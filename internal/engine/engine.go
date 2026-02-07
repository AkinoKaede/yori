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

	"github.com/AkinoKaede/proxy-relay/internal/config"
	"github.com/AkinoKaede/proxy-relay/internal/datafile"
	"github.com/AkinoKaede/proxy-relay/internal/inbound"
	"github.com/AkinoKaede/proxy-relay/internal/outbound"
	"github.com/AkinoKaede/proxy-relay/internal/server"
	"github.com/AkinoKaede/proxy-relay/internal/subscription"
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

	outboundsBySubscription := appendDirectSubscription(subManager.GetOutboundsBySubscription(), e.cfg.Direct)
	outbounds := appendDirectOutbound(subManager.MergeAll(), e.cfg.Direct)
	if len(outbounds) == 0 {
		return E.New("no outbounds available, check subscription configuration")
	}

	httpUsers := buildHTTPUserSubscriptions(e.cfg)
	users, httpUserMapping := GenerateUsers(e.ctx, outboundsBySubscription, httpUsers, e.dataFile)

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

	httpServer, err := e.startHTTPServer(users, httpUserMapping)
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
	e.mu.Lock()
	defer e.mu.Unlock()

	if newCfg == nil {
		newCfg = e.cfg
	}

	if !sameSubscriptions(e.cfg.Subscriptions, newCfg.Subscriptions) {
		e.logger.Info("subscription list changed, rebuilding manager")
		if e.subManager != nil {
			_ = e.subManager.Close()
		}
		subManager, err := subscription.NewManager(e.ctx, e.logger, newCfg)
		if err != nil {
			return E.Cause(err, "rebuild subscription manager")
		}
		e.subManager = subManager
	}

	if err := e.subManager.FetchAll(); err != nil {
		e.logger.Warn("Some subscriptions failed to fetch: ", err)
	}

	outboundsBySubscription := appendDirectSubscription(e.subManager.GetOutboundsBySubscription(), newCfg.Direct)
	outbounds := appendDirectOutbound(e.subManager.MergeAll(), newCfg.Direct)
	if len(outbounds) == 0 {
		return E.New("no outbounds after reload")
	}

	httpUsers := buildHTTPUserSubscriptions(newCfg)
	users, httpUserMapping := GenerateUsers(e.ctx, outboundsBySubscription, httpUsers, e.dataFile)

	if err := e.outbound.Reload(outbounds); err != nil {
		return E.Cause(err, "reload outbounds")
	}

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

	if err := e.reloadHTTPServer(newCfg, users, httpUserMapping); err != nil {
		return err
	}

	e.cfg = newCfg
	return nil
}

// DispatchConnection routes inbound TCP connections to the target outbound.
func (e *Engine) DispatchConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, user inbound.User, onClose N.CloseHandlerFunc) {
	outboundHandler, wrappedOnClose, ok := e.outbound.Acquire(user.Outbound, onClose)
	if !ok {
		err := E.New("outbound not found: ", user.Outbound)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		e.logger.WarnContext(ctx, err)
		return
	}
	metadata.Outbound = outboundHandler.Tag()
	httpUser := resolveHTTPUser(user)
	e.logger.InfoContext(ctx, "inbound connection user=", httpUser, " outbound=", metadata.Outbound, " target=", metadata.Destination)
	e.connMgr.NewConnection(ctx, outboundHandler, conn, metadata, wrappedOnClose)
}

// DispatchPacketConnection routes inbound UDP connections to the target outbound.
func (e *Engine) DispatchPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, user inbound.User, onClose N.CloseHandlerFunc) {
	outboundHandler, wrappedOnClose, ok := e.outbound.Acquire(user.Outbound, onClose)
	if !ok {
		err := E.New("outbound not found: ", user.Outbound)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		e.logger.WarnContext(ctx, err)
		return
	}
	metadata.Outbound = outboundHandler.Tag()
	httpUser := resolveHTTPUser(user)
	e.logger.InfoContext(ctx, "inbound packet user=", httpUser, " outbound=", metadata.Outbound, " target=", metadata.Destination)
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

func (e *Engine) startHTTPServer(users []inbound.User, httpUserMapping map[string][]string) (*server.Server, error) {
	serverCfg := buildServerConfig(e.cfg)
	for _, user := range e.cfg.HTTP.Users {
		serverCfg.Users = append(serverCfg.Users, server.HTTPUser{
			Username: user.Username,
			Password: user.Password,
		})
	}

	httpServer := server.NewServer(e.ctx, e.logger, serverCfg)
	httpServer.UpdateState(buildServerState(e.cfg, e.subManager, users, httpUserMapping))

	if err := httpServer.Start(); err != nil {
		return nil, E.Cause(err, "start HTTP server")
	}
	return httpServer, nil
}

func (e *Engine) reloadHTTPServer(newCfg *config.Config, users []inbound.User, httpUserMapping map[string][]string) error {
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
		e.httpServer.UpdateRenamePatterns(newCfg.HTTP.Rename)
	}

	e.httpServer.UpdateState(buildServerState(newCfg, e.subManager, users, httpUserMapping))
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
	return append(outbounds, option.Outbound{
		Type:    C.TypeDirect,
		Tag:     directCfg.Tag,
		Options: &option.DirectOutboundOptions{},
	})
}

func appendDirectSubscription(outboundsBySubscription map[string][]option.Outbound, directCfg *config.DirectConfig) map[string][]option.Outbound {
	if directCfg == nil || !directCfg.Enabled || directCfg.Tag == "" {
		return outboundsBySubscription
	}
	if _, exists := outboundsBySubscription["direct"]; exists {
		return outboundsBySubscription
	}
	for _, outbounds := range outboundsBySubscription {
		for _, outbound := range outbounds {
			if outbound.Tag == directCfg.Tag {
				return outboundsBySubscription
			}
		}
	}
	outboundsBySubscription["direct"] = []option.Outbound{
		{
			Type:    C.TypeDirect,
			Tag:     directCfg.Tag,
			Options: &option.DirectOutboundOptions{},
		},
	}
	return outboundsBySubscription
}

func buildServerConfig(cfg *config.Config) *server.ServerConfig {
	serverCfg := &server.ServerConfig{
		Listen: fmt.Sprintf("%s:%d", cfg.HTTP.Listen, cfg.HTTP.Port),
		Rename: cfg.HTTP.Rename,
	}
	if cfg.HTTP.TLS != nil {
		serverCfg.CertificatePath = cfg.HTTP.TLS.CertificatePath
		serverCfg.KeyPath = cfg.HTTP.TLS.KeyPath
	}
	return serverCfg
}

func buildServerState(cfg *config.Config, subManager *subscription.Manager, users []inbound.User, httpUserMapping map[string][]string) *server.State {
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

	return &server.State{
		Users:                    users,
		LocalOnlyTags:            subManager.GetLocalOnlyTags(),
		HTTPUserToHysteria2Users: httpUserMapping,
		PublicAddr:               cfg.Hysteria2.Public.Server,
		PublicPorts:              cfg.Hysteria2.Public.GetPorts(),
		SNI:                      sni,
		Obfs:                     obfsType,
		ObfsPassword:             obfsPassword,
	}
}

func sameSubscriptions(a, b []config.Subscription) bool {
	return hashValue(a) == hashValue(b)
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
