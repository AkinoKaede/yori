// SPDX-License-Identifier: GPL-3.0-only

package generator

import (
	"context"
	"sync"
	"time"

	"github.com/AkinoKaede/proxy-relay/internal"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// BoxManager manages the sing-box instance lifecycle
type BoxManager struct {
	box        *box.Box
	ctx        context.Context
	cancel     context.CancelFunc
	configHash string
	mu         sync.Mutex
}

// NewBoxManager creates a new sing-box manager
func NewBoxManager() *BoxManager {
	return &BoxManager{}
}

// Start starts sing-box with the given configuration
func (m *BoxManager) Start(opts *option.Options) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing instance if running
	if m.box != nil {
		if err := m.stopLocked(); err != nil {
			return E.Cause(err, "stop existing instance")
		}
	}

	// Create new context
	m.ctx, m.cancel = context.WithCancel(context.Background())

	// Create sing-box instance
	instance, err := box.New(box.Options{
		Context: m.ctx,
		Options: *opts,
	})
	if err != nil {
		m.cancel()
		return E.Cause(err, "create sing-box instance")
	}

	// Start sing-box
	if err := instance.Start(); err != nil {
		m.cancel()
		return E.Cause(err, "start sing-box")
	}

	m.box = instance
	// Store config hash for change detection
	m.configHash = internal.HashConfig(opts)
	return nil
}

// Stop gracefully stops the sing-box instance
func (m *BoxManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stopLocked()
}

// stopLocked stops the instance (must be called with lock held)
func (m *BoxManager) stopLocked() error {
	if m.box == nil {
		return nil
	}

	// Cancel context
	if m.cancel != nil {
		m.cancel()
	}

	// Create timeout context for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Close sing-box
	errChan := make(chan error, 1)
	go func() {
		errChan <- m.box.Close()
	}()

	select {
	case err := <-errChan:
		m.box = nil
		return err
	case <-ctx.Done():
		m.box = nil
		return E.New("shutdown timeout")
	}
}

// IsRunning checks if sing-box is currently running
func (m *BoxManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.box != nil
}

// ConfigHash returns the hash of the current configuration
func (m *BoxManager) ConfigHash() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.configHash
}
