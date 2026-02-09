// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"testing"

	"github.com/AkinoKaede/yori/internal/config"
)

func TestSubscriptionChangeDetection(t *testing.T) {
	base := []config.Subscription{
		{
			Name:      "sub",
			URL:       "https://example.com/sub",
			UserAgent: "agent",
			Process: []config.OutboundProcessOptions{
				{Filter: []string{"a"}},
			},
		},
	}

	changedProcess := []config.Subscription{
		{
			Name:      "sub",
			URL:       "https://example.com/sub",
			UserAgent: "agent",
			Process: []config.OutboundProcessOptions{
				{Filter: []string{"b"}},
			},
		},
	}

	if !sameSubscriptions(base, changedProcess) {
		t.Fatalf("expected sameSubscriptions to ignore process changes")
	}
	if sameSubscriptionProcesses(base, changedProcess) {
		t.Fatalf("expected sameSubscriptionProcesses to detect process changes")
	}

	changedURL := []config.Subscription{
		{
			Name:      "sub",
			URL:       "https://example.com/other",
			UserAgent: "agent",
		},
	}
	if sameSubscriptions(base, changedURL) {
		t.Fatalf("expected sameSubscriptions to detect URL changes")
	}
}
