// SPDX-License-Identifier: GPL-3.0-only

package inbound

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/AkinoKaede/proxy-relay/internal/config"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const hysteria2InboundTag = "hy2-in"

// Hysteria2Inbound implements a hot-reloadable Hysteria2 inbound.
type Hysteria2Inbound struct {
	ctx        context.Context
	logger     log.ContextLogger
	dispatcher ConnectionDispatcher
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	service    *hysteria2.Service[int]

	usersMu sync.RWMutex
	users   []User
}

// NewHysteria2Inbound creates a new Hysteria2 inbound and registers the initial users.
func NewHysteria2Inbound(ctx context.Context, logger log.ContextLogger, cfg config.Hysteria2Config, dispatcher ConnectionDispatcher, users []User) (*Hysteria2Inbound, error) {
	listenAddr, err := netip.ParseAddr(cfg.Listen)
	if err != nil {
		return nil, E.Cause(err, "parse hysteria2.listen")
	}

	tlsOptions, err := buildTLSOptions(cfg)
	if err != nil {
		return nil, err
	}
	if tlsOptions == nil || !tlsOptions.Enabled {
		return nil, C.ErrTLSRequired
	}

	options := option.Hysteria2InboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     (*badoption.Addr)(&listenAddr),
			ListenPort: cfg.Port,
		},
		UpMbps:   cfg.UpMbps,
		DownMbps: cfg.DownMbps,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: tlsOptions,
		},
	}

	var salamanderPassword string
	if cfg.Obfs != nil {
		if cfg.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch cfg.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = cfg.Obfs.Password
			options.Obfs = &option.Hysteria2Obfs{
				Type:     cfg.Obfs.Type,
				Password: cfg.Obfs.Password,
			}
		default:
			return nil, E.New("unknown obfs type: ", cfg.Obfs.Type)
		}
	}

	listenerInstance := listener.New(listener.Options{
		Context: ctx,
		Logger:  logger,
		Listen:  options.ListenOptions,
	})

	inbound := &Hysteria2Inbound{
		ctx:        ctx,
		logger:     logger,
		dispatcher: dispatcher,
		listener:   listenerInstance,
		users:      append([]User{}, users...),
	}

	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	inbound.tlsConfig = tlsConfig

	service, err := hysteria2.NewService[int](hysteria2.ServiceOptions{
		Context:               ctx,
		Logger:                logger,
		SendBPS:               uint64(cfg.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:            uint64(cfg.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword:    salamanderPassword,
		TLSConfig:             tlsConfig,
		IgnoreClientBandwidth: options.IgnoreClientBandwidth,
		UDPTimeout:            defaultUDPTimeout(options.ListenOptions),
		Handler:               inbound,
	})
	if err != nil {
		return nil, err
	}

	inbound.service = service
	if err := inbound.UpdateUsers(users); err != nil {
		return nil, err
	}

	return inbound, nil
}

// Start starts the inbound listener and service.
func (h *Hysteria2Inbound) Start() error {
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
	}
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	return h.service.Start(packetConn)
}

// Close stops the inbound service.
func (h *Hysteria2Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		common.PtrOrNil(h.service),
	)
}

// UpdateUsers hot-reloads the user list without restarting the service.
func (h *Hysteria2Inbound) UpdateUsers(users []User) error {
	h.usersMu.Lock()
	h.users = append(h.users[:0], users...)
	h.usersMu.Unlock()

	userList := make([]int, 0, len(users))
	passwordList := make([]string, 0, len(users))
	for index, user := range users {
		userList = append(userList, index)
		passwordList = append(passwordList, user.Password)
	}

	if h.service != nil {
		h.service.UpdateUsers(userList, passwordList)
	}

	return nil
}

// NewConnectionEx handles a new TCP connection.
func (h *Hysteria2Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	metadata := buildInboundMetadata(source, destination)
	user, ok := h.lookupUser(ctx)
	if !ok {
		h.logger.WarnContext(ctx, "unknown user for inbound connection")
		if closeErr := N.CloseOnHandshakeFailure(conn, onClose, E.New("unknown user")); closeErr != nil {
			h.logger.WarnContext(ctx, "close failed: ", closeErr)
		}
		return
	}
	metadata.User = user.Name
	if h.dispatcher != nil {
		h.dispatcher.DispatchConnection(ctx, conn, metadata, user, onClose)
	}
}

// NewPacketConnectionEx handles a new UDP packet connection.
func (h *Hysteria2Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	metadata := buildInboundMetadata(source, destination)
	user, ok := h.lookupUser(ctx)
	if !ok {
		h.logger.WarnContext(ctx, "unknown user for inbound packet connection")
		if closeErr := N.CloseOnHandshakeFailure(conn, onClose, E.New("unknown user")); closeErr != nil {
			h.logger.WarnContext(ctx, "close failed: ", closeErr)
		}
		return
	}
	metadata.User = user.Name
	if h.dispatcher != nil {
		h.dispatcher.DispatchPacketConnection(ctx, conn, metadata, user, onClose)
	}
}

func (h *Hysteria2Inbound) lookupUser(ctx context.Context) (User, bool) {
	userID, ok := auth.UserFromContext[int](ctx)
	if !ok {
		return User{}, false
	}
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	if userID < 0 || userID >= len(h.users) {
		return User{}, false
	}
	return h.users[userID], true
}

func buildInboundMetadata(source M.Socksaddr, destination M.Socksaddr) adapter.InboundContext {
	return adapter.InboundContext{
		Inbound:     hysteria2InboundTag,
		InboundType: C.TypeHysteria2,
		Source:      source,
		Destination: destination,
	}
}

func defaultUDPTimeout(listen option.ListenOptions) time.Duration {
	if listen.UDPTimeout != 0 {
		return time.Duration(listen.UDPTimeout)
	}
	return C.UDPTimeout
}

func buildTLSOptions(cfg config.Hysteria2Config) (*option.InboundTLSOptions, error) {
	tlsOptions := &option.InboundTLSOptions{Enabled: true}

	if cfg.TLS.ACME != nil {
		acme := cfg.TLS.ACME
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
		if cfg.TLS.Certificate != "" {
			tlsOptions.Certificate = []string{cfg.TLS.Certificate}
		} else {
			tlsOptions.CertificatePath = cfg.TLS.CertificatePath
		}
		if cfg.TLS.Key != "" {
			tlsOptions.Key = []string{cfg.TLS.Key}
		} else {
			tlsOptions.KeyPath = cfg.TLS.KeyPath
		}
	}

	if len(cfg.TLS.ALPN) > 0 {
		tlsOptions.ALPN = cfg.TLS.ALPN
	}

	return tlsOptions, nil
}
