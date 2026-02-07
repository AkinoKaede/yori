// SPDX-License-Identifier: GPL-3.0-only

package subscription

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AkinoKaede/proxy-relay/config"
	"github.com/AkinoKaede/proxy-relay/subscription/parser"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// Manager manages multiple subscription sources
type Manager struct {
	ctx           context.Context
	logger        logger.Logger
	subscriptions []*Subscription
	httpClient    *http.Client
	mu            sync.RWMutex
}

// Subscription represents a single subscription with its state
type Subscription struct {
	Name           string
	URL            string
	UserAgent      string
	UpdateInterval time.Duration
	processes      []*ProcessOptions

	rawOutbounds []option.Outbound // Fetched from source
	Outbounds    []option.Outbound // After processing
	LastUpdated  time.Time
	LastEtag     string
}

// NewManager creates a new subscription manager
func NewManager(ctx context.Context, logger logger.Logger, cfg *config.Config) (*Manager, error) {
	subscriptions := make([]*Subscription, 0, len(cfg.Subscriptions))

	for i, subCfg := range cfg.Subscriptions {
		// Compile process options
		processes := make([]*ProcessOptions, 0, len(subCfg.Process))
		for j, procCfg := range subCfg.Process {
			proc, err := NewProcessOptions(procCfg)
			if err != nil {
				return nil, E.Cause(err, "subscription[", subCfg.Name, "]: compile process[", j, "]")
			}
			processes = append(processes, proc)
		}

		subscriptions = append(subscriptions, &Subscription{
			Name:           subCfg.Name,
			URL:            subCfg.URL,
			UserAgent:      subCfg.UserAgent,
			UpdateInterval: subCfg.UpdateInterval.Duration(),
			processes:      processes,
		})

		logger.Info("loaded subscription[", i, "]: ", subCfg.Name, " (", subCfg.URL, ")")
	}

	return &Manager{
		ctx:           ctx,
		logger:        logger,
		subscriptions: subscriptions,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// FetchAll fetches all subscriptions that need updating
func (m *Manager) FetchAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error

	for _, sub := range m.subscriptions {
		// Check if update is needed
		if !sub.LastUpdated.IsZero() && time.Since(sub.LastUpdated) < sub.UpdateInterval {
			continue
		}

		if err := m.fetchSubscription(sub); err != nil {
			m.logger.Error("fetch subscription ", sub.Name, ": ", err)
			errors = append(errors, E.Cause(err, "fetch ", sub.Name))
			// Continue with other subscriptions
			continue
		}
	}

	if len(errors) > 0 {
		return E.Errors(errors...)
	}

	return nil
}

// fetchSubscription fetches and processes a single subscription
func (m *Manager) fetchSubscription(sub *Subscription) error {
	// Check if it's a local file
	if isLocalFile(sub.URL) {
		return m.fetchFromFile(sub)
	}

	return m.fetchFromHTTP(sub)
}

// fetchFromHTTP fetches subscription from HTTP URL
func (m *Manager) fetchFromHTTP(sub *Subscription) error {
	req, err := http.NewRequestWithContext(m.ctx, "GET", sub.URL, nil)
	if err != nil {
		return E.Cause(err, "create request")
	}

	// Set User-Agent
	if sub.UserAgent != "" {
		req.Header.Set("User-Agent", sub.UserAgent)
	} else {
		req.Header.Set("User-Agent", "proxy-relay/1.0")
	}

	// Set ETag for conditional request
	if sub.LastEtag != "" {
		req.Header.Set("If-None-Match", sub.LastEtag)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return E.Cause(err, "http request")
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		sub.LastUpdated = time.Now()
		m.logger.Info("subscription ", sub.Name, ": not modified")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return E.New("unexpected status: ", resp.Status)
	}

	// Read response body
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return E.Cause(err, "read response")
	}

	// Parse subscription
	outbounds, err := parser.ParseSubscription(m.ctx, string(content))
	if err != nil {
		return E.Cause(err, "parse subscription")
	}

	// Store raw outbounds
	sub.rawOutbounds = outbounds

	// Process outbounds
	m.processSubscription(sub)

	// Update metadata
	if etag := resp.Header.Get("ETag"); etag != "" {
		sub.LastEtag = etag
	}
	sub.LastUpdated = time.Now()

	m.logger.Info("fetched subscription ", sub.Name, ": ", len(sub.rawOutbounds), " raw → ", len(sub.Outbounds), " processed")

	return nil
}

// fetchFromFile fetches subscription from local file
func (m *Manager) fetchFromFile(sub *Subscription) error {
	filePath := strings.TrimPrefix(sub.URL, "file://")

	// Resolve absolute path
	if !filepath.IsAbs(filePath) {
		var err error
		filePath, err = filepath.Abs(filePath)
		if err != nil {
			return E.Cause(err, "resolve path")
		}
	}

	// Read file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return E.Cause(err, "read file")
	}

	// Parse subscription
	outbounds, err := parser.ParseSubscription(m.ctx, string(content))
	if err != nil {
		return E.Cause(err, "parse subscription")
	}

	// Store raw outbounds
	sub.rawOutbounds = outbounds

	// Process outbounds
	m.processSubscription(sub)

	// Update metadata
	sub.LastUpdated = time.Now()

	m.logger.Info("fetched subscription ", sub.Name, " from file: ", len(sub.rawOutbounds), " raw → ", len(sub.Outbounds), " processed")

	return nil
}

// processSubscription applies process pipeline to a subscription
func (m *Manager) processSubscription(sub *Subscription) {
	outbounds := sub.rawOutbounds

	// Apply each process step
	for _, proc := range sub.processes {
		outbounds = proc.Process(outbounds)
	}

	sub.Outbounds = outbounds
}

// MergeAll merges all processed outbounds from all subscriptions
func (m *Manager) MergeAll() []option.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var merged []option.Outbound

	for _, sub := range m.subscriptions {
		merged = append(merged, sub.Outbounds...)
	}

	// Deduplicate tags to avoid conflicts
	merged = deduplicateOutboundTags(merged)

	return merged
}

// GetSubscriptions returns a copy of all subscriptions for inspection
func (m *Manager) GetSubscriptions() []*Subscription {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return append([]*Subscription{}, m.subscriptions...)
}

// Close cleans up the manager
func (m *Manager) Close() error {
	m.httpClient.CloseIdleConnections()
	return nil
}

// isLocalFile checks if URL is a local file path
func isLocalFile(url string) bool {
	return strings.HasPrefix(url, "file://") ||
		(!strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://"))
}

// deduplicateOutboundTags ensures all outbound tags are unique
func deduplicateOutboundTags(outbounds []option.Outbound) []option.Outbound {
	seen := make(map[string]int)
	result := make([]option.Outbound, len(outbounds))

	for i, outbound := range outbounds {
		tag := outbound.Tag
		if count, exists := seen[tag]; exists {
			// Tag collision, append suffix
			count++
			seen[tag] = count
			outbound.Tag = tag + "-" + strings.Repeat("x", count)
		} else {
			seen[tag] = 0
		}
		result[i] = outbound
	}

	return result
}
