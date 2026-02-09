// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AkinoKaede/yori/internal/config"
	"github.com/AkinoKaede/yori/internal/datafile"
	"github.com/AkinoKaede/yori/internal/inbound"
	"github.com/AkinoKaede/yori/internal/outbound"
	"github.com/AkinoKaede/yori/internal/server"
	"github.com/AkinoKaede/yori/internal/subscription"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
)

// Engine wires inbound, outbound, subscriptions, and HTTP server with hot-reload.
type Engine struct {
	ctx      context.Context
	logger   log.ContextLogger
	dataFile *datafile.DataFile

	mu         sync.Mutex
	cfg        *config.Config
	subManager *subscription.Manager

	connMgr  *route.ConnectionManager
	outbound *outbound.Manager
	inbound  inbound.Inbound

	httpServer *server.Server
}

// New creates a new engine with the given config.
func New(ctx context.Context, logger log.ContextLogger, cfg *config.Config, dataFile *datafile.DataFile) *Engine {
	return &Engine{
		ctx:      ctx,
		logger:   logger,
		cfg:      cfg,
		dataFile: dataFile,
	}
}

// Start initializes all components and starts services.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	subManager, err := subscription.NewManager(e.ctx, e.logger, e.cfg)
	if err != nil {
		return E.Cause(err, "initialize subscription manager")
	}
	if err := subManager.FetchAll(); err != nil {
		e.logger.Warn("Some subscriptions failed to fetch: ", err)
	}
	e.subManager = subManager

	outbounds := appendDirectOutbound(subManager.MergeAll(), e.cfg.Direct)
	if len(outbounds) == 0 {
		return E.New("no outbounds available, check subscription configuration")
	}

	httpUsers := buildHTTPUserSubscriptions(e.cfg)
	subManagerWithDirect := &subscriptionManagerWithDirect{manager: subManager, directCfg: e.cfg.Direct}
	users, httpUserMapping, outboundToSubscription := GenerateUsers(e.ctx, subManagerWithDirect, httpUsers, e.dataFile)

	e.connMgr = route.NewConnectionManager(e.logger)
	e.outbound = outbound.NewManager(e.ctx, e.logger, e.connMgr)
	if err := e.outbound.Reload(outbounds); err != nil {
		return E.Cause(err, "load outbounds")
	}

	hysteriaInbound, err := inbound.NewHysteria2Inbound(e.ctx, e.logger, e.cfg.Hysteria2, e, users)
	if err != nil {
		return E.Cause(err, "initialize hysteria2 inbound")
	}
	if err := hysteriaInbound.Start(); err != nil {
		return E.Cause(err, "start hysteria2 inbound")
	}
	e.inbound = hysteriaInbound

	httpServer, err := e.startHTTPServer(users, httpUserMapping, outboundToSubscription)
	if err != nil {
		return err
	}
	e.httpServer = httpServer

	return nil
}

// Close stops all components.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var err error
	if e.httpServer != nil {
		err = E.Append(err, e.httpServer.Stop(), func(err error) error { return E.Cause(err, "stop http server") })
	}
	if e.inbound != nil {
		err = E.Append(err, e.inbound.Close(), func(err error) error { return E.Cause(err, "close inbound") })
	}
	if e.outbound != nil {
		err = E.Append(err, e.outbound.Close(), func(err error) error { return E.Cause(err, "close outbounds") })
	}
	if e.subManager != nil {
		err = E.Append(err, e.subManager.Close(), func(err error) error { return E.Cause(err, "close subscription manager") })
	}
	return err
}

// Reload re-fetches subscriptions and hot-reloads inbounds/outbounds/state.
func (e *Engine) Reload(newCfg *config.Config) error {
	startTime := time.Now()
	e.logger.Debug("starting engine reload")
	e.mu.Lock()
	defer e.mu.Unlock()

	if newCfg == nil {
		newCfg = e.cfg
	}

	rebuildManager := !sameSubscriptions(e.cfg.Subscriptions, newCfg.Subscriptions)
	if rebuildManager {
		e.logger.Info("subscription list changed, rebuilding manager")
		if e.subManager != nil {
			_ = e.subManager.Close()
		}
		subManager, err := subscription.NewManager(e.ctx, e.logger, newCfg)
		if err != nil {
			return E.Cause(err, "rebuild subscription manager")
		}
		e.subManager = subManager
	} else if !sameSubscriptionProcesses(e.cfg.Subscriptions, newCfg.Subscriptions) {
		e.logger.Info("subscription process changed, recompiling pipeline")
		if err := e.subManager.UpdateProcesses(newCfg.Subscriptions); err != nil {
			return E.Cause(err, "update subscription process")
		}
	}

	fetchStart := time.Now()
	if err := e.subManager.FetchAll(); err != nil {
		e.logger.Warn("Some subscriptions failed to fetch: ", err)
	}
	e.logger.Debug("subscription fetch completed in ", time.Since(fetchStart))

	outbounds := appendDirectOutbound(e.subManager.MergeAll(), newCfg.Direct)
	if len(outbounds) == 0 {
		return E.New("no outbounds after reload")
	}
	e.logger.Debug("merged ", len(outbounds), " total outbounds")

	userGenStart := time.Now()
	httpUsers := buildHTTPUserSubscriptions(newCfg)
	subManagerWithDirect := &subscriptionManagerWithDirect{manager: e.subManager, directCfg: newCfg.Direct}
	users, httpUserMapping, outboundToSubscription := GenerateUsers(e.ctx, subManagerWithDirect, httpUsers, e.dataFile)
	e.logger.Debug("generated ", len(users), " users in ", time.Since(userGenStart))

	outboundReloadStart := time.Now()
	if err := e.outbound.Reload(outbounds); err != nil {
		return E.Cause(err, "reload outbounds")
	}
	e.logger.Debug("outbound reload completed in ", time.Since(outboundReloadStart))

	if !sameHysteria2Config(e.cfg.Hysteria2, newCfg.Hysteria2) {
		e.logger.Info("hysteria2 config changed, restarting inbound")
		if e.inbound != nil {
			_ = e.inbound.Close()
		}
		hysteriaInbound, err := inbound.NewHysteria2Inbound(e.ctx, e.logger, newCfg.Hysteria2, e, users)
		if err != nil {
			return E.Cause(err, "initialize hysteria2 inbound")
		}
		if err := hysteriaInbound.Start(); err != nil {
			return E.Cause(err, "start hysteria2 inbound")
		}
		e.inbound = hysteriaInbound
	} else if e.inbound != nil {
		if err := e.inbound.UpdateUsers(users); err != nil {
			return E.Cause(err, "update inbound users")
		}
	}

	if err := e.reloadHTTPServer(newCfg, users, httpUserMapping, outboundToSubscription); err != nil {
		return err
	}

	e.cfg = newCfg
	e.logger.Debug("engine reload completed in ", time.Since(startTime))
	return nil
}

// DispatchConnection routes inbound TCP connections to the target outbound.
func (e *Engine) DispatchConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, user inbound.User, onClose N.CloseHandlerFunc) {
	outboundHandler, wrappedOnClose, ok := e.outbound.Acquire(user.Outbound, onClose)
	if !ok {
		err := E.New("outbound not found: ", user.Outbound)
		if closeErr := N.CloseOnHandshakeFailure(conn, onClose, err); closeErr != nil {
			e.logger.WarnContext(ctx, "close failed: ", closeErr)
		}
		e.logger.WarnContext(ctx, err)
		return
	}
	metadata.Outbound = outboundHandler.Tag()
	httpUser := resolveHTTPUser(user)
	e.logger.InfoContext(ctx, "inbound connection user=", httpUser, " outbound=", metadata.Outbound, " target=", metadata.Destination, " source=", metadata.Source)
	e.connMgr.NewConnection(ctx, outboundHandler, conn, metadata, wrappedOnClose)
}

// DispatchPacketConnection routes inbound UDP connections to the target outbound.
func (e *Engine) DispatchPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, user inbound.User, onClose N.CloseHandlerFunc) {
	outboundHandler, wrappedOnClose, ok := e.outbound.Acquire(user.Outbound, onClose)
	if !ok {
		err := E.New("outbound not found: ", user.Outbound)
		if closeErr := N.CloseOnHandshakeFailure(conn, onClose, err); closeErr != nil {
			e.logger.WarnContext(ctx, "close failed: ", closeErr)
		}
		e.logger.WarnContext(ctx, err)
		return
	}
	metadata.Outbound = outboundHandler.Tag()
	httpUser := resolveHTTPUser(user)
	e.logger.InfoContext(ctx, "inbound packet user=", httpUser, " outbound=", metadata.Outbound, " target=", metadata.Destination, " source=", metadata.Source)
	e.connMgr.NewPacketConnection(ctx, outboundHandler, conn, metadata, wrappedOnClose)
}

func resolveHTTPUser(user inbound.User) string {
	decoded, err := base64.StdEncoding.DecodeString(user.Name)
	if err != nil {
		return user.Name
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return user.Name
	}
	return parts[0]
}

func (e *Engine) startHTTPServer(users []inbound.User, httpUserMapping map[string][]string, outboundToSubscription map[string]string) (*server.Server, error) {
	serverCfg := buildServerConfig(e.cfg)
	for _, user := range e.cfg.HTTP.Users {
		serverCfg.Users = append(serverCfg.Users, server.HTTPUser{
			Username: user.Username,
			Password: user.Password,
		})
	}

	httpServer := server.NewServer(e.ctx, e.logger, serverCfg)
	httpServer.UpdateState(buildServerState(e.cfg, e.subManager, users, httpUserMapping, outboundToSubscription))

	if err := httpServer.Start(); err != nil {
		return nil, E.Cause(err, "start HTTP server")
	}
	return httpServer, nil
}

func (e *Engine) reloadHTTPServer(newCfg *config.Config, users []inbound.User, httpUserMapping map[string][]string, outboundToSubscription map[string]string) error {
	if e.httpServer == nil {
		return nil
	}

	if !sameHTTPServerConfig(e.cfg.HTTP, newCfg.HTTP) {
		e.logger.Info("HTTP server config changed, restarting")
		_ = e.httpServer.Stop()
		serverCfg := buildServerConfig(newCfg)
		for _, user := range newCfg.HTTP.Users {
			serverCfg.Users = append(serverCfg.Users, server.HTTPUser{
				Username: user.Username,
				Password: user.Password,
			})
		}
		e.httpServer = server.NewServer(e.ctx, e.logger, serverCfg)
		if err := e.httpServer.Start(); err != nil {
			return E.Cause(err, "start HTTP server")
		}
	} else {
		var httpUsers []server.HTTPUser
		for _, user := range newCfg.HTTP.Users {
			httpUsers = append(httpUsers, server.HTTPUser{
				Username: user.Username,
				Password: user.Password,
			})
		}
		e.httpServer.UpdateUsers(httpUsers)

		// Convert config.RenameRule to server.RenameRule
		var renameRules []server.RenameRule
		for _, rule := range newCfg.HTTP.Rename {
			renameRules = append(renameRules, server.RenameRule{
				Pattern:       rule.Pattern,
				Replace:       rule.Replace,
				Subscriptions: rule.Subscriptions,
			})
		}
		e.httpServer.UpdateRenamePatterns(renameRules)
	}

	e.httpServer.UpdateState(buildServerState(newCfg, e.subManager, users, httpUserMapping, outboundToSubscription))
	return nil
}

func buildHTTPUserSubscriptions(cfg *config.Config) map[string][]string {
	httpUsers := make(map[string][]string)
	for _, user := range cfg.HTTP.Users {
		httpUsers[user.Username] = user.Subscriptions
	}
	return httpUsers
}

func appendDirectOutbound(outbounds []option.Outbound, directCfg *config.DirectConfig) []option.Outbound {
	if directCfg == nil || !directCfg.Enabled || directCfg.Tag == "" {
		return outbounds
	}
	for _, outbound := range outbounds {
		if outbound.Tag == directCfg.Tag {
			return outbounds
		}
	}
	// Prepend direct outbound to the beginning
	directOutbound := option.Outbound{
		Type:    C.TypeDirect,
		Tag:     directCfg.Tag,
		Options: &option.DirectOutboundOptions{},
	}
	return append([]option.Outbound{directOutbound}, outbounds...)
}

func buildServerConfig(cfg *config.Config) *server.ServerConfig {
	// Convert config.RenameRule to server.RenameRule
	var renameRules []server.RenameRule
	for _, rule := range cfg.HTTP.Rename {
		renameRules = append(renameRules, server.RenameRule{
			Pattern:       rule.Pattern,
			Replace:       rule.Replace,
			Subscriptions: rule.Subscriptions,
		})
	}

	serverCfg := &server.ServerConfig{
		Listen: fmt.Sprintf("%s:%d", cfg.HTTP.Listen, cfg.HTTP.Port),
		Rename: renameRules,
	}
	if cfg.HTTP.TLS != nil {
		// Build TLS options (supports ACME)
		tlsOptions, err := buildHTTPTLSOptions(*cfg.HTTP.TLS)
		if err == nil && tlsOptions != nil {
			serverCfg.TLSOptions = tlsOptions
		}
		// Keep legacy certificate path for backward compatibility
		serverCfg.CertificatePath = cfg.HTTP.TLS.CertificatePath
		serverCfg.KeyPath = cfg.HTTP.TLS.KeyPath
	}
	return serverCfg
}

func buildServerState(cfg *config.Config, subManager *subscription.Manager, users []inbound.User, httpUserMapping map[string][]string, outboundToSubscription map[string]string) *server.State {
	var sni string
	if cfg.Hysteria2.Public.SNI != "" {
		sni = cfg.Hysteria2.Public.SNI
	} else if cfg.Hysteria2.TLS.ACME != nil && len(cfg.Hysteria2.TLS.ACME.Domain) > 0 {
		sni = cfg.Hysteria2.TLS.ACME.Domain[0]
	}

	obfsType := ""
	obfsPassword := ""
	if cfg.Hysteria2.Obfs != nil {
		obfsType = cfg.Hysteria2.Obfs.Type
		obfsPassword = cfg.Hysteria2.Obfs.Password
	}

	var directTag string
	if cfg.Direct != nil && cfg.Direct.Enabled {
		directTag = cfg.Direct.Tag
	}

	return &server.State{
		Users:                    users,
		LocalOnlyTags:            subManager.GetLocalOnlyTags(),
		HTTPUserToHysteria2Users: httpUserMapping,
		OutboundToSubscription:   outboundToSubscription,
		PublicAddr:               cfg.Hysteria2.Public.Server,
		PublicPorts:              cfg.Hysteria2.Public.GetPorts(),
		SNI:                      sni,
		Obfs:                     obfsType,
		ObfsPassword:             obfsPassword,
		DirectTag:                directTag,
	}
}

func sameSubscriptions(a, b []config.Subscription) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].URL != b[i].URL || a[i].UserAgent != b[i].UserAgent {
			return false
		}
	}
	return true
}

func sameSubscriptionProcesses(a, b []config.Subscription) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return false
		}
		if hashValue(a[i].Process) != hashValue(b[i].Process) {
			return false
		}
	}
	return true
}

func sameHysteria2Config(a, b config.Hysteria2Config) bool {
	payloadA := struct {
		Listen   string
		Port     uint16
		UpMbps   int
		DownMbps int
		TLS      config.TLSConfig
		Obfs     *config.Hysteria2Obfs
	}{
		Listen:   a.Listen,
		Port:     a.Port,
		UpMbps:   a.UpMbps,
		DownMbps: a.DownMbps,
		TLS:      a.TLS,
		Obfs:     a.Obfs,
	}
	payloadB := struct {
		Listen   string
		Port     uint16
		UpMbps   int
		DownMbps int
		TLS      config.TLSConfig
		Obfs     *config.Hysteria2Obfs
	}{
		Listen:   b.Listen,
		Port:     b.Port,
		UpMbps:   b.UpMbps,
		DownMbps: b.DownMbps,
		TLS:      b.TLS,
		Obfs:     b.Obfs,
	}
	return hashValue(payloadA) == hashValue(payloadB)
}

func sameHTTPServerConfig(a, b config.HTTPConfig) bool {
	payloadA := struct {
		Listen string
		Port   uint16
		TLS    *config.TLSConfig
	}{
		Listen: a.Listen,
		Port:   a.Port,
		TLS:    a.TLS,
	}
	payloadB := struct {
		Listen string
		Port   uint16
		TLS    *config.TLSConfig
	}{
		Listen: b.Listen,
		Port:   b.Port,
		TLS:    b.TLS,
	}
	return hashValue(payloadA) == hashValue(payloadB)
}

func hashValue(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func buildHTTPTLSOptions(tlsCfg config.TLSConfig) (*option.InboundTLSOptions, error) {
	tlsOptions := &option.InboundTLSOptions{Enabled: true}

	if tlsCfg.ACME != nil {
		acme := tlsCfg.ACME
		tlsOptions.ACME = &option.InboundACMEOptions{
			Domain:                  acme.Domain,
			Email:                   acme.Email,
			Provider:                acme.Provider,
			DataDirectory:           acme.DataDirectory,
			DisableHTTPChallenge:    acme.DisableHTTPChallenge,
			DisableTLSALPNChallenge: acme.DisableTLSALPNChallenge,
		}

		if acme.DNS01 != nil {
			tlsOptions.ACME.DNS01Challenge = &option.ACMEDNS01ChallengeOptions{
				Provider: acme.DNS01.Provider,
			}
			switch acme.DNS01.Provider {
			case "cloudflare":
				tlsOptions.ACME.DNS01Challenge.CloudflareOptions = option.ACMEDNS01CloudflareOptions{
					APIToken:  acme.DNS01.APIToken,
					ZoneToken: acme.DNS01.ZoneToken,
				}
			case "alidns":
				tlsOptions.ACME.DNS01Challenge.AliDNSOptions = option.ACMEDNS01AliDNSOptions{
					AccessKeyID:     acme.DNS01.AccessKey,
					AccessKeySecret: acme.DNS01.SecretKey,
				}
			}
		}
	} else {
		if tlsCfg.Certificate != "" {
			tlsOptions.Certificate = []string{tlsCfg.Certificate}
		} else if tlsCfg.CertificatePath != "" {
			tlsOptions.CertificatePath = tlsCfg.CertificatePath
		} else {
			return nil, nil
		}
		if tlsCfg.Key != "" {
			tlsOptions.Key = []string{tlsCfg.Key}
		} else if tlsCfg.KeyPath != "" {
			tlsOptions.KeyPath = tlsCfg.KeyPath
		}
	}

	if len(tlsCfg.ALPN) > 0 {
		tlsOptions.ALPN = tlsCfg.ALPN
	}

	return tlsOptions, nil
}
