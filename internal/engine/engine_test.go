// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"testing"

	"github.com/AkinoKaede/yori/internal/config"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
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
	logger := log.NewNOPFactory().Logger()
	if sameSubscriptionProcesses(logger, base, changedProcess) {
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

func TestAppendDirectOutboundAppliesDialerOptions(t *testing.T) {
	outbounds := []option.Outbound{
		{
			Type: "shadowsocks",
			Tag:  "upstream",
		},
	}

	outbounds = appendDirectOutbound(outbounds, &config.DirectConfig{
		Enabled: true,
		Tag:     "direct",
		DialerOptions: option.DialerOptions{
			TCPFastOpen: true,
		},
	})

	if len(outbounds) != 2 {
		t.Fatalf("unexpected outbound count: %d", len(outbounds))
	}
	if outbounds[0].Tag != "direct" {
		t.Fatalf("unexpected direct outbound tag: %s", outbounds[0].Tag)
	}

	directOptions, ok := outbounds[0].Options.(*option.DirectOutboundOptions)
	if !ok {
		t.Fatalf("unexpected direct outbound options type: %T", outbounds[0].Options)
	}
	if !directOptions.TCPFastOpen {
		t.Fatalf("expected direct outbound TCPFastOpen to be true")
	}
}

func TestAppendDirectSubscriptionMapAppliesDialerOptions(t *testing.T) {
	result := appendDirectSubscriptionMap(map[string][]option.Outbound{
		"main": {
			{
				Type: "shadowsocks",
				Tag:  "upstream",
			},
		},
	}, &config.DirectConfig{
		Enabled: true,
		Tag:     "direct",
		DialerOptions: option.DialerOptions{
			TCPFastOpen: true,
		},
	})

	directOutbounds, exists := result["direct"]
	if !exists {
		t.Fatalf("expected direct subscription to be added")
	}
	if len(directOutbounds) != 1 {
		t.Fatalf("unexpected direct outbound count: %d", len(directOutbounds))
	}

	directOptions, ok := directOutbounds[0].Options.(*option.DirectOutboundOptions)
	if !ok {
		t.Fatalf("unexpected direct outbound options type: %T", directOutbounds[0].Options)
	}
	if !directOptions.TCPFastOpen {
		t.Fatalf("expected direct outbound TCPFastOpen to be true")
	}
}
