// SPDX-License-Identifier: GPL-3.0-only

package outbound

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Manager provides hot-reloadable outbound management.
type Manager struct {
	ctx      context.Context
	logger   log.ContextLogger
	registry *outbound.Registry
	connMgr  *route.ConnectionManager

	mu        sync.RWMutex
	outbounds map[string]adapter.Outbound
	ordered   []adapter.Outbound
	hashes    map[string]string
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
	}

	baseCtx = service.ContextWith[adapter.ConnectionManager](baseCtx, connMgr)
	baseCtx = service.ContextWith[adapter.OutboundManager](baseCtx, m)
	m.ctx = baseCtx

	return m
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

// Close stops and removes all outbounds.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var err error
	for tag, ob := range m.outbounds {
		err = E.Append(err, common.Close(ob), func(err error) error {
			return E.Cause(err, "close outbound[", tag, "]")
		})
	}
	m.outbounds = make(map[string]adapter.Outbound)
	m.ordered = nil
	m.hashes = make(map[string]string)
	return err
}

// Reload diffs the outbound set and applies changes without restarting unchanged outbounds.
func (m *Manager) Reload(outboundOptions []option.Outbound) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	nextHashes := make(map[string]string, len(outboundOptions))
	nextOutbounds := make(map[string]adapter.Outbound, len(outboundOptions))
	nextOrdered := make([]adapter.Outbound, 0, len(outboundOptions))
	createdOutbounds := make(map[string]adapter.Outbound)

	for _, outboundOption := range outboundOptions {
		if outboundOption.Tag == "" {
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
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "create outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStateInitialize); err != nil {
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStateStart); err != nil {
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStatePostStart); err != nil {
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}
		if err := adapter.LegacyStart(created, adapter.StartStateStarted); err != nil {
			m.closeCreated(createdOutbounds)
			return E.Cause(err, "start outbound[", outboundOption.Tag, "]")
		}

		createdOutbounds[outboundOption.Tag] = created
		nextOutbounds[outboundOption.Tag] = created
		nextOrdered = append(nextOrdered, created)
	}

	for tag, existing := range m.outbounds {
		if next, ok := nextOutbounds[tag]; ok && next == existing {
			continue
		}
		if err := common.Close(existing); err != nil {
			m.logger.Warn("close outbound[", tag, "]: ", err)
		}
	}

	m.outbounds = nextOutbounds
	m.ordered = nextOrdered
	m.hashes = nextHashes

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
	defer m.mu.Unlock()
	existing, ok := m.outbounds[tag]
	if !ok {
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
	return common.Close(existing)
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
	defer m.mu.Unlock()
	if existing, ok := m.outbounds[tag]; ok {
		_ = common.Close(existing)
		for i, ob := range m.ordered {
			if ob == existing {
				m.ordered = append(m.ordered[:i], m.ordered[i+1:]...)
				break
			}
		}
	}
	m.outbounds[tag] = created
	m.ordered = append(m.ordered, created)
	m.hashes[tag] = hashOutbound(option.Outbound{Type: outboundType, Tag: tag, Options: options})
	return nil
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
