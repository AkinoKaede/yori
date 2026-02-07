// SPDX-License-Identifier: GPL-3.0-only

package subscription

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AkinoKaede/yori/internal/cachefile"
	"github.com/AkinoKaede/yori/internal/config"
	"github.com/AkinoKaede/yori/internal/subscription/parser"
	"github.com/AkinoKaede/yori/pkg/constant"

	"github.com/sagernet/sing-box/include"
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
	cacheFile     *cachefile.CacheFile
	mu            sync.RWMutex
}

// Subscription represents a single subscription with its state
type Subscription struct {
	Name      string
	URL       string
	UserAgent string
	processes []*ProcessOptions

	rawOutbounds  []option.Outbound // Fetched from source
	Outbounds     []option.Outbound // After processing
	LocalOnlyTags map[string]bool   // Tags of outbounds marked as local-only
	LastUpdated   time.Time
	LastEtag      string
}

// NewManager creates a new subscription manager
func NewManager(ctx context.Context, logger logger.Logger, cfg *config.Config) (*Manager, error) {
	ctx = include.Context(ctx)
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
			Name:          subCfg.Name,
			URL:           subCfg.URL,
			UserAgent:     subCfg.UserAgent,
			processes:     processes,
			LocalOnlyTags: make(map[string]bool),
		})

		logger.Info("loaded subscription[", i, "]: ", subCfg.Name, " (", subCfg.URL, ")")
	}

	// Initialize cache file
	var cache *cachefile.CacheFile
	if cfg.CacheFile != "" {
		cache = cachefile.New(ctx, cfg.CacheFile)
		if err := cache.PreStart(); err != nil {
			return nil, E.Cause(err, "prepare cache file")
		}
		if err := cache.Start(); err != nil {
			return nil, E.Cause(err, "start cache file")
		}
		logger.Info("cache file initialized: ", cfg.CacheFile)

		// Load cached subscriptions
		for _, sub := range subscriptions {
			sub.LocalOnlyTags = make(map[string]bool)
			cached := cache.LoadSubscription(ctx, sub.Name)
			if cached != nil {
				sub.rawOutbounds = cached.Content
				sub.LastUpdated = cached.LastUpdated
				sub.LastEtag = cached.LastEtag
				// Process cached outbounds
				outbounds := sub.rawOutbounds
				for _, proc := range sub.processes {
					var localTags map[string]bool
					outbounds, localTags = proc.Process(outbounds)
					// Merge local-only tags
					for tag := range localTags {
						sub.LocalOnlyTags[tag] = true
					}
				}
				sub.Outbounds = outbounds
				logger.Info("loaded ", len(sub.Outbounds), " cached outbounds for ", sub.Name)
			}
		}
	}

	return &Manager{
		ctx:           ctx,
		logger:        logger,
		subscriptions: subscriptions,
		cacheFile:     cache,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// FetchAll fetches all subscriptions
// If a subscription fetch fails, it will keep using cached data and continue with other subscriptions
func (m *Manager) FetchAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error
	successCount := 0
	cachedCount := 0

	for _, sub := range m.subscriptions {
		if err := m.fetchSubscription(sub); err != nil {
			m.logger.Error("fetch subscription ", sub.Name, ": ", err)
			errors = append(errors, E.Cause(err, "fetch ", sub.Name))

			// Check if we have cached data to fall back on
			if len(sub.Outbounds) > 0 {
				m.logger.Warn("using cached data for ", sub.Name, ": ", len(sub.Outbounds), " outbounds (last updated: ", sub.LastUpdated.Format(time.RFC3339), ")")
				cachedCount++
			} else {
				m.logger.Error("no cached data available for ", sub.Name)
			}
			// Continue with other subscriptions
			continue
		}
		successCount++
	}

	m.logger.Info("fetch summary: ", successCount, " succeeded, ", cachedCount, " using cache, ", len(errors)-cachedCount, " failed with no cache")

	// Only return error if we have no data at all
	if len(errors) > 0 {
		// Check if we have at least some data
		hasData := false
		for _, sub := range m.subscriptions {
			if len(sub.Outbounds) > 0 {
				hasData = true
				break
			}
		}

		if !hasData {
			return E.New("all subscriptions failed and no cached data available")
		}

		// Return errors but don't fail - we have some data to work with
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
		version := constant.Version
		if version == "" {
			version = "unknown"
		}
		req.Header.Set("User-Agent", fmt.Sprintf("yori/%s (sing-box %s; Clash compatible; like serenity/%s)", version, constant.CoreVersion(), constant.LikeSerenityVersion))
	}

	// Set ETag for conditional request
	if sub.LastEtag != "" {
		req.Header.Set("If-None-Match", sub.LastEtag)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return E.Cause(err, "http request")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			m.logger.Warn("close response body: ", err)
		}
	}()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		sub.LastUpdated = time.Now()
		m.logger.Info("subscription ", sub.Name, ": not modified")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		// Don't clear existing data on error
		return E.New("unexpected status: ", resp.Status)
	}

	// Read response body
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		// Don't clear existing data on error
		return E.Cause(err, "read response")
	}

	// Parse subscription
	outbounds, err := parser.ParseSubscription(m.ctx, string(content))
	if err != nil {
		// Don't clear existing data on parse error
		return E.Cause(err, "parse subscription")
	}

	// Validate we have at least some outbounds
	if len(outbounds) == 0 {
		m.logger.Warn("subscription ", sub.Name, " returned 0 outbounds, keeping existing data")
		if len(sub.Outbounds) > 0 {
			return E.New("subscription returned empty data")
		}
	}

	// Store raw outbounds (only update if we got valid data)
	sub.rawOutbounds = outbounds

	// Process outbounds
	m.processSubscription(sub)

	// Update metadata
	if etag := resp.Header.Get("ETag"); etag != "" {
		sub.LastEtag = etag
	}
	sub.LastUpdated = time.Now()

	m.logger.Info("fetched subscription ", sub.Name, ": ", len(sub.rawOutbounds), " raw → ", len(sub.Outbounds), " processed")

	// Save to cache
	if m.cacheFile != nil {
		if err := m.cacheFile.StoreSubscription(m.ctx, sub.Name, &cachefile.Subscription{
			Content:     sub.rawOutbounds,
			LastUpdated: sub.LastUpdated,
			LastEtag:    sub.LastEtag,
		}); err != nil {
			m.logger.Warn("failed to cache subscription ", sub.Name, ": ", err)
		}
	}

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
		// Don't clear existing data on error
		return E.Cause(err, "read file")
	}

	// Parse subscription
	outbounds, err := parser.ParseSubscription(m.ctx, string(content))
	if err != nil {
		// Don't clear existing data on parse error
		return E.Cause(err, "parse subscription")
	}

	// Validate we have at least some outbounds
	if len(outbounds) == 0 {
		m.logger.Warn("subscription file ", sub.Name, " returned 0 outbounds, keeping existing data")
		if len(sub.Outbounds) > 0 {
			return E.New("subscription file returned empty data")
		}
	}

	// Store raw outbounds (only update if we got valid data)
	sub.rawOutbounds = outbounds

	// Process outbounds
	m.processSubscription(sub)

	// Update metadata
	sub.LastUpdated = time.Now()

	m.logger.Info("fetched subscription ", sub.Name, " from file: ", len(sub.rawOutbounds), " raw → ", len(sub.Outbounds), " processed")

	// Save to cache
	if m.cacheFile != nil {
		if err := m.cacheFile.StoreSubscription(m.ctx, sub.Name, &cachefile.Subscription{
			Content:     sub.rawOutbounds,
			LastUpdated: sub.LastUpdated,
			LastEtag:    sub.LastEtag,
		}); err != nil {
			m.logger.Warn("failed to cache subscription ", sub.Name, ": ", err)
		}
	}

	return nil
}

// processSubscription applies process pipeline to a subscription
func (m *Manager) processSubscription(sub *Subscription) {
	outbounds := sub.rawOutbounds
	sub.LocalOnlyTags = make(map[string]bool)

	// Apply each process step
	for _, proc := range sub.processes {
		var localTags map[string]bool
		outbounds, localTags = proc.Process(outbounds)
		// Merge local-only tags
		for tag := range localTags {
			sub.LocalOnlyTags[tag] = true
		}
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

// MergeAllNonLocal merges all non-local-only outbounds for user subscriptions
func (m *Manager) MergeAllNonLocal() []option.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var merged []option.Outbound

	for _, sub := range m.subscriptions {
		for _, outbound := range sub.Outbounds {
			// Skip if marked as local-only
			if !sub.LocalOnlyTags[outbound.Tag] {
				merged = append(merged, outbound)
			}
		}
	}

	// Deduplicate tags to avoid conflicts
	merged = deduplicateOutboundTags(merged)

	return merged
}

// GetLocalOnlyTags returns a merged map of all local-only tags from all subscriptions
func (m *Manager) GetLocalOnlyTags() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	localTags := make(map[string]bool)
	for _, sub := range m.subscriptions {
		for tag := range sub.LocalOnlyTags {
			localTags[tag] = true
		}
	}
	return localTags
}

// GetSubscriptions returns a copy of all subscriptions for inspection
func (m *Manager) GetSubscriptions() []*Subscription {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return append([]*Subscription{}, m.subscriptions...)
}

// GetOutboundsBySubscription returns outbounds grouped by subscription name
func (m *Manager) GetOutboundsBySubscription() map[string][]option.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]option.Outbound)
	for _, sub := range m.subscriptions {
		result[sub.Name] = append([]option.Outbound{}, sub.Outbounds...)
	}
	return result
}

// MergeBySubscriptionNames merges outbounds from specified subscriptions
// If subscriptionNames is empty, returns all outbounds
func (m *Manager) MergeBySubscriptionNames(subscriptionNames []string) []option.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var merged []option.Outbound

	// If no specific subscriptions requested, return all
	if len(subscriptionNames) == 0 {
		for _, sub := range m.subscriptions {
			merged = append(merged, sub.Outbounds...)
		}
	} else {
		// Build a set of requested subscription names
		requested := make(map[string]bool)
		for _, name := range subscriptionNames {
			requested[name] = true
		}

		// Only merge from requested subscriptions
		for _, sub := range m.subscriptions {
			if requested[sub.Name] {
				merged = append(merged, sub.Outbounds...)
			}
		}
	}

	// Deduplicate tags to avoid conflicts
	merged = deduplicateOutboundTags(merged)

	return merged
}

// Close cleans up the manager
func (m *Manager) Close() error {
	m.httpClient.CloseIdleConnections()
	if m.cacheFile != nil {
		return m.cacheFile.Close()
	}
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
