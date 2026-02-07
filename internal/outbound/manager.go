// SPDX-License-Identifier: GPL-3.0-only

package outbound

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Manager provides hot-reloadable outbound management.
type Manager struct {
	ctx       context.Context
	logger    log.ContextLogger
	registry  *outbound.Registry
	connMgr   *route.ConnectionManager
	dnsMgr    *dns.TransportManager
	dnsRouter adapter.DNSRouter

	mu        sync.RWMutex
	outbounds map[string]adapter.Outbound
	ordered   []adapter.Outbound
	hashes    map[string]string
	tracked   map[adapter.Outbound]*trackedOutbound
}

type trackedOutbound struct {
	active   int
	draining bool
}

type noopInboundManager struct{}

func (m *noopInboundManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *noopInboundManager) Close() error {
	return nil
}

func (m *noopInboundManager) Inbounds() []adapter.Inbound {
	return nil
}

func (m *noopInboundManager) Get(tag string) (adapter.Inbound, bool) {
	return nil, false
}

func (m *noopInboundManager) Remove(tag string) error {
	return nil
}

func (m *noopInboundManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	return E.New("inbound manager is not available")
}

// NewManager creates a new outbound manager with sing-box registries.
func NewManager(ctx context.Context, logger log.ContextLogger, connMgr *route.ConnectionManager) *Manager {
	baseCtx := include.Context(ctx)
	m := &Manager{
		ctx:       baseCtx,
		logger:    logger,
		registry:  include.OutboundRegistry(),
		connMgr:   connMgr,
		outbounds: make(map[string]adapter.Outbound),
		ordered:   nil,
		hashes:    make(map[string]string),
		tracked:   make(map[adapter.Outbound]*trackedOutbound),
	}

	baseCtx = service.ContextWith[adapter.ConnectionManager](baseCtx, connMgr)
	baseCtx = service.ContextWith[adapter.OutboundManager](baseCtx, m)
	baseCtx = m.withDNSManager(baseCtx)
	m.ctx = baseCtx

	return m
}

func (m *Manager) withDNSManager(ctx context.Context) context.Context {
	if m.dnsMgr != nil {
		ctx = service.ContextWith[adapter.DNSTransportManager](ctx, m.dnsMgr)
		if m.dnsRouter != nil {
			ctx = service.ContextWith[adapter.DNSRouter](ctx, m.dnsRouter)
		}
		return ctx
	}
	if service.FromContext[adapter.InboundManager](ctx) == nil {
		ctx = service.ContextWith[adapter.InboundManager](ctx, &noopInboundManager{})
	}
	manager := dns.NewTransportManager(m.logger, include.DNSTransportRegistry(), m, "")
	manager.Initialize(func() (adapter.DNSTransport, error) {
		return local.NewTransport(ctx, m.logger, "default", option.LocalDNSServerOptions{})
	})
	for _, stage := range adapter.ListStartStages {
		if err := adapter.LegacyStart(manager, stage); err != nil {
			m.logger.Warn("start dns manager: ", err)
			break
		}
	}
	m.dnsMgr = manager
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, manager)

	router := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{})
	if err := router.Initialize(nil); err != nil {
		m.logger.Warn("init dns router: ", err)
	}
	for _, stage := range adapter.ListStartStages {
		if err := adapter.LegacyStart(router, stage); err != nil {
			m.logger.Warn("start dns router: ", err)
			break
		}
	}
	m.dnsRouter = router
	ctx = service.ContextWith[adapter.DNSRouter](ctx, router)
	return ctx
}

// Start is a no-op for the custom manager.
func (m *Manager) Start(stage adapter.StartStage) error {
	return nil
}

// Outbounds returns the current outbound list.
func (m *Manager) Outbounds() []adapter.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]adapter.Outbound{}, m.ordered...)
}

// Default returns the first outbound as default.
func (m *Manager) Default() adapter.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.ordered) == 0 {
		return nil
	}
	return m.ordered[0]
}

// Outbound returns the outbound by tag.
func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	outbound, ok := m.outbounds[tag]
	return outbound, ok
}

// Acquire returns the outbound for tag and a wrapped onClose handler that tracks drain state.
func (m *Manager) Acquire(tag string, onClose N.CloseHandlerFunc) (adapter.Outbound, N.CloseHandlerFunc, bool) {
	m.mu.Lock()
	outbound, ok := m.outbounds[tag]
	if !ok {
		m.mu.Unlock()
		return nil, onClose, false
	}
	state := m.ensureTrackedLocked(outbound)
	state.active++
	m.mu.Unlock()

	var once sync.Once
	wrapped := func(err error) {
		once.Do(func() {
			m.release(outbound)
		})
		if onClose != nil {
			onClose(err)
		}
	}

	return outbound, wrapped, true
}

// Close stops and removes all outbounds.
func (m *Manager) Close() error {
	m.mu.Lock()
	toClose := make([]adapter.Outbound, 0, len(m.outbounds))
	for _, ob := range m.outbounds {
		toClose = append(toClose, ob)
	}
	dnsMgr := m.dnsMgr
	dnsRouter := m.dnsRouter
	m.outbounds = make(map[string]adapter.Outbound)
	m.ordered = nil
	m.hashes = make(map[string]string)
	m.tracked = make(map[adapter.Outbound]*trackedOutbound)
	m.dnsMgr = nil
	m.dnsRouter = nil
	m.mu.Unlock()

	var err error
	if dnsMgr != nil {
		err = E.Append(err, dnsMgr.Close(), func(err error) error {
			return E.Cause(err, "close dns manager")
		})
	}
	if dnsRouter != nil {
		err = E.Append(err, dnsRouter.Close(), func(err error) error {
			return E.Cause(err, "close dns router")
		})
	}
	for _, ob := range toClose {
		err = E.Append(err, common.Close(ob), func(err error) error {
			return E.Cause(err, "close outbound")
		})
	}
	return err
}

// Reload diffs the outbound set and applies changes without restarting unchanged outbounds.
func (m *Manager) Reload(outboundOptions []option.Outbound) error {
	m.mu.Lock()

	nextHashes := make(map[string]string, len(outboundOptions))
	nextOutbounds := make(map[string]adapter.Outbound, len(outboundOptions))
	nextOrdered := make([]adapter.Outbound, 0, len(outboundOptions))
	createdOutbounds := make(map[string]adapter.Outbound)
	toClose := make([]adapter.Outbound, 0)

	for _, outboundOption := range outboundOptions {
		if outboundOption.Tag == "" {
			m.mu.Unlock()
			return E.New("outbound tag is required")
		}

		hash := hashOutbound(outboundOption)
		nextHashes[outboundOption.Tag] = hash

		if existing, ok := m.outbounds[outboundOption.Tag]; ok {
			if m.hashes[outboundOption.Tag] == hash {
				nextOutbounds[outboundOption.Tag] = existing
				nextOrdered = append(nextOrdered, existing)
				continue
			}
		}

		created, err := m.registry.CreateOutbound(m.ctx, nil, m.logger, outboundOption.Tag, outboundOption.Type, outboundOption.Options)
		if err != nil {
			m.mu.Unlock()
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "create outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStateInitialize); err != nil {
			m.mu.Unlock()
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStateStart); err != nil {
			m.mu.Unlock()
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStatePostStart); err != nil {
			m.mu.Unlock()
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStateStarted); err != nil {
			m.mu.Unlock()
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}

		createdOutbounds[outboundOption.Tag] = created
		nextOutbounds[outboundOption.Tag] = created
		nextOrdered = append(nextOrdered, created)
	}

	for _, existing := range m.outbounds {
		if next, ok := nextOutbounds[existing.Tag()]; ok && next == existing {
			continue
		}
		if m.drainOutboundLocked(existing) {
			toClose = append(toClose, existing)
		}
	}

	m.outbounds = nextOutbounds
	m.ordered = nextOrdered
	m.hashes = nextHashes
	m.mu.Unlock()

	for _, ob := range toClose {
		if err := common.Close(ob); err != nil {
			m.logger.Warn("close outbound: ", err)
		}
	}

	return nil
}

func (m *Manager) closeCreated(created map[string]adapter.Outbound) {
	for tag, ob := range created {
		if err := common.Close(ob); err != nil {
			m.logger.Warn("close outbound[", tag, "]: ", err)
		}
	}
}

// Remove removes an outbound by tag.
func (m *Manager) Remove(tag string) error {
	m.mu.Lock()
	existing, ok := m.outbounds[tag]
	if !ok {
		m.mu.Unlock()
		return E.New("outbound not found: ", tag)
	}
	delete(m.outbounds, tag)
	delete(m.hashes, tag)
	for i, ob := range m.ordered {
		if ob == existing {
			m.ordered = append(m.ordered[:i], m.ordered[i+1:]...)
			break
		}
	}
	closeNow := m.drainOutboundLocked(existing)
	m.mu.Unlock()
	if closeNow {
		return common.Close(existing)
	}
	return nil
}

// Create adds or replaces an outbound by tag.
func (m *Manager) Create(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	if tag == "" {
		return E.New("outbound tag is required")
	}
	created, err := m.registry.CreateOutbound(m.ctx, nil, logger, tag, outboundType, options)
	if err != nil {
		return E.Cause(err, "create outbound[", tag, "]")
	}
	for _, stage := range adapter.ListStartStages {
		if err := adapter.LegacyStart(created, stage); err != nil {
			return E.Cause(err, "start outbound[", tag, "]")
		}
	}

	m.mu.Lock()
	var toClose []adapter.Outbound
	if existing, ok := m.outbounds[tag]; ok {
		for i, ob := range m.ordered {
			if ob == existing {
				m.ordered = append(m.ordered[:i], m.ordered[i+1:]...)
				break
			}
		}
		delete(m.outbounds, tag)
		delete(m.hashes, tag)
		if m.drainOutboundLocked(existing) {
			toClose = append(toClose, existing)
		}
	}
	m.outbounds[tag] = created
	m.ordered = append(m.ordered, created)
	m.hashes[tag] = hashOutbound(option.Outbound{Type: outboundType, Tag: tag, Options: options})
	m.mu.Unlock()

	for _, ob := range toClose {
		if err := common.Close(ob); err != nil {
			m.logger.Warn("close outbound: ", err)
		}
	}
	return nil
}

func (m *Manager) release(outbound adapter.Outbound) {
	var closeNow bool
	m.mu.Lock()
	state, ok := m.tracked[outbound]
	if !ok {
		m.mu.Unlock()
		return
	}
	if state.active > 0 {
		state.active--
	}
	if state.draining && state.active == 0 {
		delete(m.tracked, outbound)
		closeNow = true
	}
	m.mu.Unlock()

	if closeNow {
		if err := common.Close(outbound); err != nil {
			m.logger.Warn("close outbound: ", err)
		}
	}
}

func (m *Manager) ensureTrackedLocked(outbound adapter.Outbound) *trackedOutbound {
	state, ok := m.tracked[outbound]
	if ok {
		return state
	}
	state = &trackedOutbound{}
	m.tracked[outbound] = state
	return state
}

func (m *Manager) drainOutboundLocked(outbound adapter.Outbound) bool {
	state := m.ensureTrackedLocked(outbound)
	state.draining = true
	if state.active == 0 {
		delete(m.tracked, outbound)
		return true
	}
	return false
}

func hashOutbound(outboundOption option.Outbound) string {
	payload := struct {
		Type    string      `json:"type"`
		Tag     string      `json:"tag"`
		Options interface{} `json:"options"`
	}{
		Type:    outboundOption.Type,
		Tag:     outboundOption.Tag,
		Options: outboundOption.Options,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
