// SPDX-License-Identifier: GPL-3.0-only

package subscription

import (
	"context"
	"testing"

	"github.com/AkinoKaede/yori/internal/config"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestManagerUpdateProcesses(t *testing.T) {
	ctx := context.Background()
	log := logger.NOP()

	rawOutbounds := []option.Outbound{
		{
			Type: C.TypeShadowsocks,
			Tag:  "node-a",
			Options: &option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "example.com"},
			},
		},
	}

	initialProc, err := NewProcessOptions(config.OutboundProcessOptions{
		Filter:    []string{"node"},
		LocalOnly: true,
		Rename: map[string]string{
			"node": "old",
		},
	})
	if err != nil {
		t.Fatalf("NewProcessOptions: %v", err)
	}

	sub := &Subscription{
		Name:          "sub",
		rawOutbounds:  rawOutbounds,
		processes:     []*ProcessOptions{initialProc},
		LocalOnlyTags: make(map[string]bool),
	}

	manager := &Manager{
		ctx:           ctx,
		logger:        log,
		subscriptions: []*Subscription{sub},
	}

	manager.processSubscription(sub)

	if got := sub.Outbounds[0].Tag; got != "old-a" {
		t.Fatalf("expected initial rename to be applied, got %q", got)
	}
	if !sub.LocalOnlyTags["old-a"] {
		t.Fatalf("expected local-only tag to be updated after rename")
	}

	updateCfg := []config.Subscription{
		{
			Name: "sub",
			Process: []config.OutboundProcessOptions{
				{
					Filter: []string{"node"},
					Rename: map[string]string{
						"node": "new",
					},
				},
			},
		},
	}

	if err := manager.UpdateProcesses(updateCfg); err != nil {
		t.Fatalf("UpdateProcesses: %v", err)
	}

	if got := sub.Outbounds[0].Tag; got != "new-a" {
		t.Fatalf("expected updated rename to be applied, got %q", got)
	}
	if len(sub.LocalOnlyTags) != 0 {
		t.Fatalf("expected local-only tags to be cleared, got %v", sub.LocalOnlyTags)
	}
}
