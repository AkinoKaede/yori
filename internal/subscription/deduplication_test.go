// SPDX-License-Identifier: GPL-3.0-only

package subscription

import (
	"testing"

	"github.com/AkinoKaede/yori/pkg/constant"

	"github.com/sagernet/sing-box/option"
)

func Test_getAddressType(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{name: "empty", address: "", want: ""},
		{name: "domain", address: "example.com", want: constant.AddressTypeDomain},
		{name: "IPv4", address: "192.168.1.1", want: constant.AddressTypeIPv4},
		{name: "IPv6", address: "2001:db8::1", want: constant.AddressTypeIPv6},
		{name: "IPv6 short", address: "::1", want: constant.AddressTypeIPv6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAddressType(tt.address); got != tt.want {
				t.Errorf("getAddressType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getAddressPriority(t *testing.T) {
	// Test prefer_ipv4 strategy
	if got := getAddressPriority(constant.AddressTypeIPv4, constant.DeduplicationPreferIPv4); got != 3 {
		t.Errorf("prefer_ipv4 IPv4 priority = %v, want 3", got)
	}
	if got := getAddressPriority(constant.AddressTypeDomain, constant.DeduplicationPreferIPv4); got != 2 {
		t.Errorf("prefer_ipv4 Domain priority = %v, want 2", got)
	}
	if got := getAddressPriority(constant.AddressTypeIPv6, constant.DeduplicationPreferIPv4); got != 1 {
		t.Errorf("prefer_ipv4 IPv6 priority = %v, want 1", got)
	}
}

func Test_getOutboundServer(t *testing.T) {
	// Test Shadowsocks
	ss := option.Outbound{
		Tag: "test",
		Options: &option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "ss.example.com"},
		},
	}
	if got := getOutboundServer(ss); got != "ss.example.com" {
		t.Errorf("getOutboundServer(shadowsocks) = %v, want ss.example.com", got)
	}

	// Test VMess
	vmess := option.Outbound{
		Tag: "test",
		Options: &option.VMessOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "192.168.1.1"},
		},
	}
	if got := getOutboundServer(vmess); got != "192.168.1.1" {
		t.Errorf("getOutboundServer(vmess) = %v, want 192.168.1.1", got)
	}

	// Test unsupported type
	direct := option.Outbound{
		Tag:     "direct",
		Options: &option.DirectOutboundOptions{},
	}
	if got := getOutboundServer(direct); got != "" {
		t.Errorf("getOutboundServer(direct) = %v, want empty", got)
	}
}

func Test_deduplicateOutboundTags_rename(t *testing.T) {
	outbounds := []option.Outbound{
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "1.1.1.1"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "2.2.2.2"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "3.3.3.3"}}},
	}

	got := DeduplicateOutboundTags(outbounds, constant.DeduplicationRename)

	if len(got) != 3 {
		t.Fatalf("Expected 3 outbounds, got %d", len(got))
	}

	if got[0].Tag != "node" || got[1].Tag != "node (1)" || got[2].Tag != "node (2)" {
		t.Errorf("Unexpected tags: %v, %v, %v", got[0].Tag, got[1].Tag, got[2].Tag)
	}
}

func Test_deduplicateOutboundTags_first(t *testing.T) {
	outbounds := []option.Outbound{
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "1.1.1.1"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "2.2.2.2"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "3.3.3.3"}}},
	}

	got := DeduplicateOutboundTags(outbounds, constant.DeduplicationFirst)

	if len(got) != 1 {
		t.Fatalf("Expected 1 outbound, got %d", len(got))
	}

	server := getOutboundServer(got[0])
	if server != "1.1.1.1" {
		t.Errorf("Expected first server 1.1.1.1, got %v", server)
	}
}

func Test_deduplicateOutboundTags_last(t *testing.T) {
	outbounds := []option.Outbound{
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "1.1.1.1"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "2.2.2.2"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "3.3.3.3"}}},
	}

	got := DeduplicateOutboundTags(outbounds, constant.DeduplicationLast)

	if len(got) != 1 {
		t.Fatalf("Expected 1 outbound, got %d", len(got))
	}

	server := getOutboundServer(got[0])
	if server != "3.3.3.3" {
		t.Errorf("Expected last server 3.3.3.3, got %v", server)
	}
}

func Test_deduplicateOutboundTags_preferIPv4(t *testing.T) {
	outbounds := []option.Outbound{
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "example.com"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.168.1.1"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "2001:db8::1"}}},
	}

	got := DeduplicateOutboundTags(outbounds, constant.DeduplicationPreferIPv4)

	if len(got) != 1 {
		t.Fatalf("Expected 1 outbound, got %d", len(got))
	}

	server := getOutboundServer(got[0])
	if server != "192.168.1.1" {
		t.Errorf("Expected IPv4 server, got %v", server)
	}
}

func Test_deduplicateOutboundTags_preferIPv6(t *testing.T) {
	outbounds := []option.Outbound{
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.168.1.1"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "example.com"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "2001:db8::1"}}},
	}

	got := DeduplicateOutboundTags(outbounds, constant.DeduplicationPreferIPv6)

	if len(got) != 1 {
		t.Fatalf("Expected 1 outbound, got %d", len(got))
	}

	server := getOutboundServer(got[0])
	if server != "2001:db8::1" {
		t.Errorf("Expected IPv6 server, got %v", server)
	}
}

func Test_deduplicateOutboundTags_preferDomain(t *testing.T) {
	outbounds := []option.Outbound{
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.168.1.1"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "2001:db8::1"}}},
		{Tag: "node", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "example.com"}}},
	}

	got := DeduplicateOutboundTags(outbounds, constant.DeduplicationPreferDomainThenIPv4)

	if len(got) != 1 {
		t.Fatalf("Expected 1 outbound, got %d", len(got))
	}

	server := getOutboundServer(got[0])
	if server != "example.com" {
		t.Errorf("Expected domain server, got %v", server)
	}
}

func Test_deduplicateOutboundTags_mixedTags(t *testing.T) {
	outbounds := []option.Outbound{
		{Tag: "node1", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "1.1.1.1"}}},
		{Tag: "node2", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "2.2.2.2"}}},
		{Tag: "node1", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: "example.com"}}},
	}

	got := DeduplicateOutboundTags(outbounds, constant.DeduplicationFirst)

	if len(got) != 2 {
		t.Fatalf("Expected 2 outbounds, got %d", len(got))
	}

	// Should keep first occurrence of each tag
	hasNode1 := false
	hasNode2 := false
	for _, o := range got {
		if o.Tag == "node1" {
			hasNode1 = true
			if server := getOutboundServer(o); server != "1.1.1.1" {
				t.Errorf("node1 should have first server 1.1.1.1, got %v", server)
			}
		}
		if o.Tag == "node2" {
			hasNode2 = true
		}
	}

	if !hasNode1 || !hasNode2 {
		t.Errorf("Missing expected tags, hasNode1=%v, hasNode2=%v", hasNode1, hasNode2)
	}
}
