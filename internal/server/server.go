// SPDX-License-Identifier: GPL-3.0-only

package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AkinoKaede/yori/internal/inbound"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
	Listen          string
	Rename          map[string]string
	CertificatePath string
	KeyPath         string
	TLSOptions      *option.InboundTLSOptions
	Users           []HTTPUser
}

// HTTPUser for Basic Auth and filtering
type HTTPUser struct {
	Username string
	Password string
}

// State holds the server state information
type State struct {
	Users                    []inbound.User
	LocalOnlyTags            map[string]bool     // Tags of local-only outbounds (not available to users)
	HTTPUserToHysteria2Users map[string][]string // HTTP username -> Hysteria2 usernames mapping
	PublicAddr               string
	PublicPorts              []string // Port list, supports ranges like "443:453"
	SNI                      string
	Obfs                     string
	ObfsPassword             string
}

// renamePattern holds compiled regex and replacement string
type renamePattern struct {
	regex *regexp.Regexp
	repl  string
}

// Server represents the HTTP subscription server
type Server struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         log.ContextLogger
	config         *ServerConfig
	server         *http.Server
	state          *State
	stateMu        sync.RWMutex
	renamePatterns []renamePattern
	users          []HTTPUser
	started        bool
	startMu        sync.Mutex
}

// NewServer creates a new subscription server instance
func NewServer(ctx context.Context, logger log.ContextLogger, cfg *ServerConfig) *Server {
	serverCtx, cancel := context.WithCancel(ctx)

	// Compile rename patterns
	var renamePatterns []renamePattern
	for pattern, repl := range cfg.Rename {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			logger.Warn("invalid rename pattern: ", pattern, ": ", err)
			continue
		}
		renamePatterns = append(renamePatterns, renamePattern{
			regex: regex,
			repl:  repl,
		})
	}

	// Copy user list (no patterns to compile anymore)
	users := append([]HTTPUser{}, cfg.Users...)

	return &Server{
		ctx:            serverCtx,
		cancel:         cancel,
		logger:         logger,
		config:         cfg,
		state:          &State{},
		renamePatterns: renamePatterns,
		users:          users,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.startMu.Lock()
	defer s.startMu.Unlock()

	if s.started {
		return E.New("server already started")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sub/base64", s.handleBase64)
	mux.HandleFunc("/sub/singbox", s.handleSingbox)
	mux.HandleFunc("/sub/sing-box", s.handleSingbox)
	mux.HandleFunc("/sub", s.handleSub)
	mux.HandleFunc("/", s.handleIndex)

	s.server = &http.Server{
		Addr:    s.config.Listen,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return E.Cause(err, "failed to listen")
	}

	// Check if TLS is configured
	useTLS := s.config.TLSOptions != nil && s.config.TLSOptions.Enabled
	if !useTLS {
		// Fallback to legacy certificate path config
		useTLS = s.config.CertificatePath != "" && s.config.KeyPath != ""
	}

	if useTLS {
		s.logger.Info("HTTPS server listening on ", s.config.Listen)
	} else {
		s.logger.Info("HTTP server listening on ", s.config.Listen)
	}
	s.started = true

	go func() {
		var err error
		if useTLS {
			if s.config.TLSOptions != nil {
				// Use sing-box TLS implementation (supports ACME)
				tlsServerConfig, err := tls.NewServer(s.ctx, s.logger, *s.config.TLSOptions)
				if err != nil {
					s.logger.Error("failed to create TLS config: ", err)
					return
				}
				// Start ACME if configured
				if err := tlsServerConfig.Start(); err != nil {
					s.logger.Error("failed to start TLS: ", err)
					return
				}
				defer func() {
					if closeErr := tlsServerConfig.Close(); closeErr != nil {
						s.logger.Error("failed to close TLS config: ", closeErr)
					}
				}()

				// Convert to standard TLS config
				stdTLSConfig, err := tlsServerConfig.STDConfig()
				if err != nil {
					s.logger.Error("failed to get standard TLS config: ", err)
					return
				}
				s.server.TLSConfig = stdTLSConfig
				if err := s.server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
					s.logger.Error("server error: ", err)
				}
			} else {
				// Legacy certificate path
				err = s.server.ServeTLS(listener, s.config.CertificatePath, s.config.KeyPath)
			}
		} else {
			err = s.server.Serve(listener)
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("server error: ", err)
		}
	}()

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop() error {
	s.startMu.Lock()
	defer s.startMu.Unlock()

	if !s.started {
		return nil
	}

	s.logger.Info("shutting down HTTP server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return E.Cause(err, "failed to shutdown server")
	}

	s.cancel()
	s.started = false
	s.logger.Info("HTTP server stopped")
	return nil
}

// UpdateState updates the server state in a thread-safe manner
func (s *Server) UpdateState(state *State) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.state = state
}

// UpdateUsers updates the HTTP users configuration
func (s *Server) UpdateUsers(users []HTTPUser) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.users = users
	s.logger.Info("updated HTTP users: ", len(users), " user(s)")
}

// UpdateRenamePatterns updates the rename patterns
func (s *Server) UpdateRenamePatterns(rename map[string]string) {
	var renamePatterns []renamePattern
	for pattern, repl := range rename {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			s.logger.Warn("invalid rename pattern: ", pattern, ": ", err)
			continue
		}
		renamePatterns = append(renamePatterns, renamePattern{
			regex: regex,
			repl:  repl,
		})
	}

	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.renamePatterns = renamePatterns
	s.logger.Info("updated rename patterns: ", len(renamePatterns), " pattern(s)")
}

// authenticate checks HTTP Basic Auth and returns the authenticated user's username
// If no users configured, returns "user" as default
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) string {
	s.stateMu.RLock()
	users := s.users
	s.stateMu.RUnlock()

	// If no users configured, allow access as default "user"
	if len(users) == 0 {
		return "user"
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Subscription"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return ""
	}

	// Find matching user with constant-time comparison
	for i := range users {
		user := &users[i]
		usernameMatch := subtle.ConstantTimeCompare([]byte(user.Username), []byte(username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) == 1
		if usernameMatch && passwordMatch {
			return username
		}
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="Subscription"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return ""
}

// filterUsers filters Hysteria2 users based on HTTP username mapping and local-only tags
func (s *Server) filterUsers(allUsers []inbound.User, httpUsername string) []inbound.User {
	if httpUsername == "" {
		return nil
	}

	// Get the list of Hysteria2 usernames this HTTP user can access
	allowedH2Users, exists := s.state.HTTPUserToHysteria2Users[httpUsername]
	if !exists || len(allowedH2Users) == 0 {
		return nil
	}

	// Create a set for fast lookup
	allowedSet := make(map[string]bool)
	for _, h2Username := range allowedH2Users {
		allowedSet[h2Username] = true
	}

	var filtered []inbound.User
	for _, user := range allUsers {
		// Skip local-only outbounds
		if s.state.LocalOnlyTags[user.Outbound] {
			continue
		}

		// Check if this user is in the allowed list
		if allowedSet[user.Name] {
			filtered = append(filtered, user)
		}
	}
	return filtered
}

// applyRename applies rename patterns to a tag
func (s *Server) applyRename(tag string) string {
	for _, pattern := range s.renamePatterns {
		tag = pattern.regex.ReplaceAllString(tag, pattern.repl)
	}
	return strings.TrimSpace(tag)
}

// detectFormat determines subscription format based on User-Agent
func detectFormat(userAgent string) string {
	// Check for sing-box family apps
	if strings.Contains(userAgent, "sing-box") ||
		strings.HasPrefix(userAgent, "SF") { // SFA/SFI/SFM/SFT
		return "singbox"
	}
	// Default to base64 for Clash and other clients
	return "base64"
}

// handleBase64 generates hysteria2:// links and returns them base64 encoded
func (s *Server) handleBase64(w http.ResponseWriter, r *http.Request) {
	// Authenticate user
	httpUsername := s.authenticate(w, r)
	if httpUsername == "" {
		return // Authentication failed
	}

	s.stateMu.RLock()
	defer s.stateMu.RUnlock()

	if len(s.state.Users) == 0 {
		http.Error(w, "no users configured", http.StatusInternalServerError)
		return
	}

	// Filter users based on HTTP username mapping
	filteredUsers := s.filterUsers(s.state.Users, httpUsername)
	if len(filteredUsers) == 0 {
		http.Error(w, "no users matched filter", http.StatusNotFound)
		return
	}

	var links []string
	for _, user := range filteredUsers {
		// Convert port ranges from colon format (sing-box) to hyphen format (hysteria2 link)
		portList := convertPortsForLink(s.state.PublicPorts)
		link := s.buildHysteria2Link(user, portList)
		links = append(links, link)
	}

	content := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(encoded)); err != nil {
		s.logger.Error("write response: ", err)
	}
}

// handleSub auto-detects format based on User-Agent and returns appropriate subscription
func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	format := detectFormat(userAgent)

	if format == "singbox" {
		s.handleSingbox(w, r)
	} else {
		s.handleBase64(w, r)
	}
}

// handleSingbox returns JSON with outbounds array
func (s *Server) handleSingbox(w http.ResponseWriter, r *http.Request) {
	// Authenticate user
	httpUsername := s.authenticate(w, r)
	if httpUsername == "" {
		return // Authentication failed
	}

	s.stateMu.RLock()
	defer s.stateMu.RUnlock()

	if len(s.state.Users) == 0 {
		http.Error(w, "no users configured", http.StatusInternalServerError)
		return
	}

	// Filter users based on HTTP username mapping
	filteredUsers := s.filterUsers(s.state.Users, httpUsername)
	if len(filteredUsers) == 0 {
		http.Error(w, "no users matched filter", http.StatusNotFound)
		return
	}

	var outbounds []option.Outbound
	for _, user := range filteredUsers {
		outbound := s.buildHysteria2Outbound(user)
		// Apply rename patterns
		if len(s.renamePatterns) > 0 {
			outbound.Tag = s.applyRename(outbound.Tag)
		}
		outbounds = append(outbounds, outbound)
	}

	response := map[string]interface{}{
		"outbounds": outbounds,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		s.logger.Error("failed to encode response: ", err)
	}
}

// handleIndex serves a simple HTML page listing endpoints
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>YORI Subscription Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            margin-top: 0;
        }
        .endpoint {
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        .endpoint-title {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }
        .endpoint-url {
            font-family: monospace;
            color: #666;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
		<h1>YORI Subscription Server</h1>
        <p>Available subscription endpoints:</p>
        
        <div class="endpoint">
            <div class="endpoint-title">Base64 Subscription</div>
            <div class="endpoint-url">/sub/base64</div>
            <p>Returns base64 encoded hysteria2:// links</p>
        </div>
        
        <div class="endpoint">
            <div class="endpoint-title">SingBox Subscription</div>
			<div class="endpoint-url">/sub/sing-box</div>
			<p>Returns JSON format with outbounds array for sing-box (compatible: /sub/singbox)</p>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(html)); err != nil {
		s.logger.Error("write response: ", err)
	}
}

// buildHysteria2Link creates a hysteria2:// URL format
// portList is a comma-separated list of ports and ranges (e.g., "443,1000-1100,8443")
func (s *Server) buildHysteria2Link(user inbound.User, portList string) string {
	// Use PublicAddr, fallback to SNI if not set
	addr := s.state.PublicAddr
	if addr == "" {
		addr = s.state.SNI
	}
	if addr == "" {
		addr = "127.0.0.1"
	}

	// hysteria2://password@host:port1,port2,range1-range2/?sni=example.com&obfs=salamander&obfs-password=secret#name
	link := fmt.Sprintf("hysteria2://%s@%s:%s/", user.Password, addr, portList)

	var params []string
	if s.state.SNI != "" {
		params = append(params, fmt.Sprintf("sni=%s", s.state.SNI))
	}
	if s.state.Obfs != "" {
		params = append(params, fmt.Sprintf("obfs=%s", s.state.Obfs))
		if s.state.ObfsPassword != "" {
			params = append(params, fmt.Sprintf("obfs-password=%s", s.state.ObfsPassword))
		}
	}

	if len(params) > 0 {
		link += "?" + strings.Join(params, "&")
	}

	name := user.Outbound
	if name != "" {
		// Apply rename patterns
		if len(s.renamePatterns) > 0 {
			name = s.applyRename(name)
		}
		link += "#" + name
	}

	return link
}

// buildHysteria2Outbound creates a sing-box Hysteria2 outbound config
func (s *Server) buildHysteria2Outbound(user inbound.User) option.Outbound {
	// Use PublicAddr, fallback to SNI if not set
	addr := s.state.PublicAddr
	if addr == "" {
		addr = s.state.SNI
	}
	if addr == "" {
		addr = "127.0.0.1"
	}

	displayName := user.Outbound
	tag := ""
	if displayName == "" {
		tag = "hysteria2"
	} else {
		tag = displayName
	}

	hysteria2Opts := &option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server: addr,
		},
		Password: user.Password,
	}

	// Prefer server_port when there is exactly one non-range port.
	if len(s.state.PublicPorts) == 1 && !strings.Contains(s.state.PublicPorts[0], ":") {
		var singlePort uint16
		if _, err := fmt.Sscanf(s.state.PublicPorts[0], "%d", &singlePort); err == nil {
			hysteria2Opts.ServerPort = singlePort
		}
	} else if len(s.state.PublicPorts) > 0 {
		hysteria2Opts.ServerPorts = s.state.PublicPorts
	}

	if s.state.SNI != "" {
		hysteria2Opts.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: s.state.SNI,
		}
	}

	if s.state.Obfs != "" {
		obfsPassword := s.state.ObfsPassword
		hysteria2Opts.Obfs = &option.Hysteria2Obfs{
			Type:     s.state.Obfs,
			Password: obfsPassword,
		}
	}

	outbound := option.Outbound{
		Type:    "hysteria2",
		Tag:     tag,
		Options: hysteria2Opts,
	}

	return outbound
}

// convertPortsForLink converts port list from sing-box format (colon ranges) to hysteria2 link format (hyphen ranges)
// Input: ["443", "1000:1100", "8443"]
// Output: "443,1000-1100,8443"
func convertPortsForLink(portSpecs []string) string {
	converted := make([]string, len(portSpecs))
	for i, spec := range portSpecs {
		// Replace colon with hyphen for ranges
		converted[i] = strings.ReplaceAll(spec, ":", "-")
	}
	return strings.Join(converted, ",")
}

// expandPortRanges expands port ranges like "443:453" to individual port strings
// Input: ["443", "1000:1002", "8443"]
// Output: ["443", "1000", "1001", "1002", "8443"]
