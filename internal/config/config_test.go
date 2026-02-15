// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDirectConfigUnmarshalYAMLInlineDialerOptions(t *testing.T) {
	var cfg struct {
		Direct *DirectConfig `yaml:"direct"`
	}

	content := []byte(`
direct:
  enabled: true
  tag: "direct"
  tcp_fast_open: true
`)

	if err := yaml.Unmarshal(content, &cfg); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if cfg.Direct == nil {
		t.Fatalf("expected direct config")
	}
	if !cfg.Direct.Enabled {
		t.Fatalf("expected direct enabled")
	}
	if cfg.Direct.Tag != "direct" {
		t.Fatalf("unexpected direct tag: %s", cfg.Direct.Tag)
	}
	if !cfg.Direct.TCPFastOpen {
		t.Fatalf("expected tcp_fast_open to be true")
	}
}
