// SPDX-License-Identifier: GPL-3.0-only

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
	Listen string
}

// State holds the server state information
type State struct {
	Users       []option.Hysteria2User
	PublicAddr  string
	PublicPorts []uint16
	SNI         string
	Obfs        string
}

// Server represents the HTTP subscription server
type Server struct {
	ctx     context.Context
	cancel  context.CancelFunc
	logger  logger.Logger
	config  *ServerConfig
	server  *http.Server
	state   *State
	stateMu sync.RWMutex
	started bool
	startMu sync.Mutex
}

// NewServer creates a new subscription server instance
func NewServer(ctx context.Context, logger logger.Logger, cfg *ServerConfig) *Server {
	serverCtx, cancel := context.WithCancel(ctx)
	return &Server{
		ctx:    serverCtx,
		cancel: cancel,
		logger: logger,
		config: cfg,
		state:  &State{},
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
	mux.HandleFunc("/", s.handleIndex)

	s.server = &http.Server{
		Addr:    s.config.Listen,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return E.Cause(err, "failed to listen")
	}

	s.logger.Info("HTTP server listening on ", s.config.Listen)
	s.started = true

	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
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

// handleBase64 generates hysteria2:// links and returns them base64 encoded
func (s *Server) handleBase64(w http.ResponseWriter, r *http.Request) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()

	if len(s.state.Users) == 0 {
		http.Error(w, "no users configured", http.StatusInternalServerError)
		return
	}

	var links []string
	for _, user := range s.state.Users {
		for _, port := range s.state.PublicPorts {
			link := s.buildHysteria2Link(user, port)
			links = append(links, link)
		}
	}

	content := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(encoded))
}

// handleSingbox returns JSON with outbounds array
func (s *Server) handleSingbox(w http.ResponseWriter, r *http.Request) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()

	if len(s.state.Users) == 0 {
		http.Error(w, "no users configured", http.StatusInternalServerError)
		return
	}

	var outbounds []option.Outbound
	for _, user := range s.state.Users {
		for _, port := range s.state.PublicPorts {
			outbound := s.buildHysteria2Outbound(user, port)
			outbounds = append(outbounds, outbound)
		}
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
    <title>Proxy Relay Subscription Server</title>
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
        <h1>Proxy Relay Subscription Server</h1>
        <p>Available subscription endpoints:</p>
        
        <div class="endpoint">
            <div class="endpoint-title">Base64 Subscription</div>
            <div class="endpoint-url">/sub/base64</div>
            <p>Returns base64 encoded hysteria2:// links</p>
        </div>
        
        <div class="endpoint">
            <div class="endpoint-title">SingBox Subscription</div>
            <div class="endpoint-url">/sub/singbox</div>
            <p>Returns JSON format with outbounds array for sing-box</p>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// buildHysteria2Link creates a hysteria2:// URL format
func (s *Server) buildHysteria2Link(user option.Hysteria2User, port uint16) string {
	addr := s.state.PublicAddr
	if addr == "" {
		addr = "127.0.0.1"
	}

	// hysteria2://password@host:port/?sni=example.com&obfs=salamander&obfs-password=secret#name
	link := fmt.Sprintf("hysteria2://%s@%s:%d/", user.Password, addr, port)

	var params []string
	if s.state.SNI != "" {
		params = append(params, fmt.Sprintf("sni=%s", s.state.SNI))
	}
	if s.state.Obfs != "" {
		params = append(params, fmt.Sprintf("obfs=%s", s.state.Obfs))
		if user.Password != "" {
			params = append(params, fmt.Sprintf("obfs-password=%s", user.Password))
		}
	}

	if len(params) > 0 {
		link += "?" + strings.Join(params, "&")
	}

	if user.Name != "" {
		link += "#" + user.Name
	}

	return link
}

// buildHysteria2Outbound creates a sing-box Hysteria2 outbound config
func (s *Server) buildHysteria2Outbound(user option.Hysteria2User, port uint16) option.Outbound {
	addr := s.state.PublicAddr
	if addr == "" {
		addr = "127.0.0.1"
	}

	tag := fmt.Sprintf("hysteria2-%s-%d", user.Name, port)
	if user.Name == "" {
		tag = fmt.Sprintf("hysteria2-%d", port)
	}

	hysteria2Opts := &option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     addr,
			ServerPort: port,
		},
		Password: user.Password,
	}

	if s.state.SNI != "" {
		hysteria2Opts.OutboundTLSOptionsContainer.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: s.state.SNI,
		}
	}

	if s.state.Obfs != "" {
		obfsPassword := user.Password
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
