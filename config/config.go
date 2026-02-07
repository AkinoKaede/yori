// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"os"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"gopkg.in/yaml.v3"
)

// Config is the main configuration structure
type Config struct {
	Subscriptions  []Subscription  `yaml:"subscriptions"`
	ReloadInterval Duration        `yaml:"reload_interval"`
	HTTP           HTTPConfig      `yaml:"http"`
	Hysteria2      Hysteria2Config `yaml:"hysteria2"`
}

// Subscription represents a single subscription source
type Subscription struct {
	Name           string                   `yaml:"name"`
	URL            string                   `yaml:"url"`
	UserAgent      string                   `yaml:"user_agent"`
	UpdateInterval Duration                 `yaml:"update_interval"`
	Process        []OutboundProcessOptions `yaml:"process"`
}

// OutboundProcessOptions defines filters and rewrites for outbounds
type OutboundProcessOptions struct {
	Filter                []string                         `yaml:"filter"`
	Exclude               []string                         `yaml:"exclude"`
	FilterType            []string                         `yaml:"filter_type"`
	ExcludeType           []string                         `yaml:"exclude_type"`
	Invert                bool                             `yaml:"invert"`
	Remove                bool                             `yaml:"remove"`
	Rename                map[string]string                `yaml:"rename"`
	RemoveEmoji           bool                             `yaml:"remove_emoji"`
	RewriteMultiplex      *option.OutboundMultiplexOptions `yaml:"rewrite_multiplex"`
	RewriteDialerOptions  *option.DialerOptions            `yaml:"rewrite_dialer_options"`
	RewritePacketEncoding string                           `yaml:"rewrite_packet_encoding"`
	RewriteUTLS           *RewriteUTLSOptions              `yaml:"rewrite_utls"`
}

// RewriteUTLSOptions for uTLS configuration rewriting
type RewriteUTLSOptions struct {
	Enabled     bool   `yaml:"enabled"`
	Fingerprint string `yaml:"fingerprint"`
}

// HTTPConfig for the HTTP subscription server
type HTTPConfig struct {
	Listen string `yaml:"listen"`
	Port   uint16 `yaml:"port"`
}

// Hysteria2Config for Hysteria2 inbound configuration
type Hysteria2Config struct {
	Listen   string         `yaml:"listen"`
	Ports    []uint16       `yaml:"ports"`
	UpMbps   int            `yaml:"up_mbps"`
	DownMbps int            `yaml:"down_mbps"`
	Public   PublicConfig   `yaml:"public"`
	TLS      TLSConfig      `yaml:"tls"`
	Obfs     *Hysteria2Obfs `yaml:"obfs"`
}

// PublicConfig for public-facing server information
type PublicConfig struct {
	Server string   `yaml:"server"`
	Ports  []uint16 `yaml:"ports"`
}

// TLSConfig supports both ACME and manual certificates
type TLSConfig struct {
	ACME            *ACMEConfig `yaml:"acme"`
	CertificatePath string      `yaml:"certificate_path"`
	KeyPath         string      `yaml:"key_path"`
}

// ACMEConfig for automatic certificate management
type ACMEConfig struct {
	Domain        []string              `yaml:"domain"`
	Email         string                `yaml:"email"`
	Provider      string                `yaml:"provider"`
	DataDirectory string                `yaml:"data_directory"`
	DNS01         *DNS01ChallengeConfig `yaml:"dns01_challenge"`
}

// DNS01ChallengeConfig for DNS-01 ACME challenge
type DNS01ChallengeConfig struct {
	Provider  string `yaml:"provider"`
	APIToken  string `yaml:"api_token"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
}

// Hysteria2Obfs configuration
type Hysteria2Obfs struct {
	Type     string `yaml:"type"`
	Password string `yaml:"password"`
}

// Duration is a wrapper for time.Duration that supports YAML parsing
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var v string
	if err := node.Decode(&v); err != nil {
		return err
	}
	duration, err := time.ParseDuration(v)
	if err != nil {
		return E.Cause(err, "parse duration")
	}
	*d = Duration(duration)
	return nil
}

// Duration returns the time.Duration value
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// LoadConfig loads and validates configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, E.Cause(err, "read config file")
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, E.Cause(err, "parse config")
	}

	if err := cfg.Validate(); err != nil {
		return nil, E.Cause(err, "validate config")
	}

	return &cfg, nil
}

// Validate checks the configuration for errors and applies defaults
func (c *Config) Validate() error {
	// Validate subscriptions
	if len(c.Subscriptions) == 0 {
		return E.New("at least one subscription is required")
	}

	for i, sub := range c.Subscriptions {
		if sub.Name == "" {
			return E.New("subscription[", i, "]: name is required")
		}
		if sub.URL == "" {
			return E.New("subscription[", sub.Name, "]: URL is required")
		}
		// Default update interval
		if sub.UpdateInterval == 0 {
			c.Subscriptions[i].UpdateInterval = Duration(30 * time.Minute)
		}
	}

	// Default reload interval
	if c.ReloadInterval == 0 {
		c.ReloadInterval = Duration(30 * time.Minute)
	}

	// Validate HTTP config
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = "0.0.0.0"
	}
	if c.HTTP.Port == 0 {
		c.HTTP.Port = 8080
	}

	// Validate Hysteria2 config
	if c.Hysteria2.Listen == "" {
		c.Hysteria2.Listen = "::"
	}
	if len(c.Hysteria2.Ports) == 0 {
		return E.New("hysteria2: at least one port is required")
	}
	if c.Hysteria2.UpMbps == 0 {
		c.Hysteria2.UpMbps = 100
	}
	if c.Hysteria2.DownMbps == 0 {
		c.Hysteria2.DownMbps = 100
	}

	// Validate TLS configuration
	if c.Hysteria2.TLS.ACME == nil && (c.Hysteria2.TLS.CertificatePath == "" || c.Hysteria2.TLS.KeyPath == "") {
		return E.New("hysteria2.tls: either ACME or manual certificate configuration is required")
	}

	// Validate ACME config
	if c.Hysteria2.TLS.ACME != nil {
		acme := c.Hysteria2.TLS.ACME
		if len(acme.Domain) == 0 {
			return E.New("hysteria2.tls.acme: at least one domain is required")
		}
		if acme.Email == "" {
			return E.New("hysteria2.tls.acme: email is required")
		}
		if acme.Provider == "" {
			acme.Provider = "letsencrypt"
		}
		if acme.DataDirectory == "" {
			acme.DataDirectory = "./data/acme"
		}
	}

	// Validate public config
	if c.Hysteria2.Public.Server == "" {
		return E.New("hysteria2.public.server is required for generating share links")
	}
	// Default to all listen ports
	if len(c.Hysteria2.Public.Ports) == 0 {
		c.Hysteria2.Public.Ports = c.Hysteria2.Ports
	}

	return nil
}
