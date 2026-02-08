// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"gopkg.in/yaml.v3"
)

// Config is the main configuration structure
type Config struct {
	LogLevel              string          `yaml:"log_level"`
	CacheFile             string          `yaml:"cache_file"`
	DataFile              string          `yaml:"data_file"`
	DeduplicationStrategy string          `yaml:"deduplication_strategy"`
	Subscriptions         []Subscription  `yaml:"subscriptions"`
	Direct                *DirectConfig   `yaml:"direct"`
	ReloadInterval        Duration        `yaml:"reload_interval"`
	HTTP                  HTTPConfig      `yaml:"http"`
	Hysteria2             Hysteria2Config `yaml:"hysteria2"`

	// BaseDir is the directory containing the config file (used for resolving relative paths)
	BaseDir string `yaml:"-"`
}

// Subscription represents a single subscription source
type Subscription struct {
	Name      string                   `yaml:"name"`
	URL       string                   `yaml:"url"`
	UserAgent string                   `yaml:"user_agent"`
	Process   []OutboundProcessOptions `yaml:"process"`
}

// OutboundProcessOptions defines filters and rewrites for outbounds
type OutboundProcessOptions struct {
	Filter                []string                         `yaml:"filter"`
	Exclude               []string                         `yaml:"exclude"`
	FilterType            []string                         `yaml:"filter_type"`
	ExcludeType           []string                         `yaml:"exclude_type"`
	Invert                bool                             `yaml:"invert"`
	Remove                bool                             `yaml:"remove"`
	LocalOnly             bool                             `yaml:"local_only"` // Mark matched outbounds as local-only (not relayed to users)
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

// RenameRule defines a single rename pattern with optional subscription filter
type RenameRule struct {
	Pattern       string   `yaml:"pattern"`       // Regex pattern to match
	Replace       string   `yaml:"replace"`       // Replacement string
	Subscriptions []string `yaml:"subscriptions"` // Subscriptions to apply (nil = all except direct, empty = none, list = specified)
}

// HTTPConfig for the HTTP subscription server
type HTTPConfig struct {
	Listen string       `yaml:"listen"`
	Port   uint16       `yaml:"port"`
	Rename []RenameRule `yaml:"rename"`
	TLS    *TLSConfig   `yaml:"tls"`
	Users  []HTTPUser   `yaml:"users"`
}

// DirectConfig defines a direct outbound entry exposed as a virtual subscription.
type DirectConfig struct {
	Enabled bool   `yaml:"enabled"`
	Tag     string `yaml:"tag"`
}

// HTTPUser for Basic Auth and user filtering
type HTTPUser struct {
	Username      string   `yaml:"username"`
	Password      string   `yaml:"password"`
	Subscriptions []string `yaml:"subscriptions"` // Subscription names to filter (unset = all, empty = none)
}

// Hysteria2Config for Hysteria2 inbound configuration
type Hysteria2Config struct {
	Listen                string         `yaml:"listen"`
	Port                  uint16         `yaml:"port"`
	UpMbps                int            `yaml:"up_mbps"`
	DownMbps              int            `yaml:"down_mbps"`
	IgnoreClientBandwidth bool           `yaml:"ignore_client_bandwidth"`
	Public                PublicConfig   `yaml:"public"`
	TLS                   TLSConfig      `yaml:"tls"`
	Obfs                  *Hysteria2Obfs `yaml:"obfs"`
}

// PublicConfig for public-facing server information
// Supports both Port and Ports. If both are set, they will be merged.
// Ports supports port ranges like "443:453" (colon format for sing-box)
// Port ranges are automatically converted to hyphen format (443-453) in hysteria2:// links
type PublicConfig struct {
	Server string   `yaml:"server"`
	SNI    string   `yaml:"sni"`
	Port   uint16   `yaml:"port,omitempty"`  // Single port
	Ports  []string `yaml:"ports,omitempty"` // Multiple ports or ranges (e.g., ["443", "1000:1100"])
}

// TLSConfig supports both ACME and manual certificates
type TLSConfig struct {
	ACME            *ACMEConfig `yaml:"acme"`
	CertificatePath string      `yaml:"certificate_path"`
	KeyPath         string      `yaml:"key_path"`
	Certificate     string      `yaml:"certificate"`
	Key             string      `yaml:"key"`
	ALPN            []string    `yaml:"alpn"`
}

// ACMEConfig for automatic certificate management
type ACMEConfig struct {
	Domain                  []string              `yaml:"domain"`
	Email                   string                `yaml:"email"`
	Provider                string                `yaml:"provider"`
	DataDirectory           string                `yaml:"data_directory"`
	DisableHTTPChallenge    bool                  `yaml:"disable_http_challenge"`
	DisableTLSALPNChallenge bool                  `yaml:"disable_tls_alpn_challenge"`
	DNS01                   *DNS01ChallengeConfig `yaml:"dns01_challenge"`
}

// DNS01ChallengeConfig for DNS-01 ACME challenge
type DNS01ChallengeConfig struct {
	Provider  string `yaml:"provider"`
	APIToken  string `yaml:"api_token"`
	ZoneToken string `yaml:"zone_token"`
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

	// Resolve config file's directory for relative path resolution
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, E.Cause(err, "resolve config path")
	}
	cfg.BaseDir = filepath.Dir(absPath)

	if err := cfg.Validate(); err != nil {
		return nil, E.Cause(err, "validate config")
	}

	return &cfg, nil
}

// Validate checks the configuration for errors and applies defaults
func (c *Config) Validate() error {
	// Validate subscriptions
	if len(c.Subscriptions) == 0 && (c.Direct == nil || !c.Direct.Enabled) {
		return E.New("at least one subscription is required (or enable direct)")
	}

	for i, sub := range c.Subscriptions {
		if sub.Name == "" {
			return E.New("subscription[", i, "]: name is required")
		}
		if sub.URL == "" {
			return E.New("subscription[", sub.Name, "]: URL is required")
		}
	}
	if c.Direct != nil && c.Direct.Enabled {
		if c.Direct.Tag == "" {
			c.Direct.Tag = "direct"
		}
		for _, sub := range c.Subscriptions {
			if sub.Name == "direct" {
				return E.New("subscription name 'direct' is reserved for direct outbound")
			}
		}
	}

	// Reload interval defaults to disabled (0)

	// Validate deduplication strategy
	if c.DeduplicationStrategy == "" {
		c.DeduplicationStrategy = "rename" // Default to rename for backward compatibility
	} else {
		// Validate strategy value
		validStrategies := []string{"rename", "first", "last", "prefer_ipv4", "prefer_ipv6", "prefer_domain_then_ipv4", "prefer_domain_then_ipv6"}
		valid := false
		for _, s := range validStrategies {
			if c.DeduplicationStrategy == s {
				valid = true
				break
			}
		}
		if !valid {
			return E.New("deduplication_strategy must be one of: rename, first, last, prefer_ipv4, prefer_ipv6, prefer_domain_then_ipv4, prefer_domain_then_ipv6")
		}
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
	if c.Hysteria2.Port == 0 {
		return E.New("hysteria2: port is required")
	}
	if c.Hysteria2.UpMbps == 0 {
		c.Hysteria2.UpMbps = 100
	}
	if c.Hysteria2.DownMbps == 0 {
		c.Hysteria2.DownMbps = 100
	}

	// Validate TLS configuration
	if c.Hysteria2.TLS.ACME == nil {
		if c.Hysteria2.TLS.Certificate == "" && c.Hysteria2.TLS.CertificatePath == "" {
			return E.New("hysteria2.tls: certificate or certificate_path is required when ACME is disabled")
		}
		if c.Hysteria2.TLS.Key == "" && c.Hysteria2.TLS.KeyPath == "" {
			return E.New("hysteria2.tls: key or key_path is required when ACME is disabled")
		}
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
	// public.server is optional - if not set, will use public.sni or ACME domain
	if c.Hysteria2.Public.Server == "" {
		if c.Hysteria2.Public.SNI != "" {
			c.Hysteria2.Public.Server = c.Hysteria2.Public.SNI
		} else if c.Hysteria2.TLS.ACME != nil && len(c.Hysteria2.TLS.ACME.Domain) > 0 {
			c.Hysteria2.Public.Server = c.Hysteria2.TLS.ACME.Domain[0]
		} else {
			return E.New("hysteria2.public.server is required (or use public.sni or ACME with domain)")
		}
	}
	// Merge port and ports, default to listen port if neither specified
	ports := c.Hysteria2.Public.GetPorts()
	if len(ports) == 0 {
		// Default to listen port
		c.Hysteria2.Public.Ports = []string{fmt.Sprintf("%d", c.Hysteria2.Port)}
	}

	return nil
}

// GetPorts returns the merged list of ports from Port and Ports
// If both are set, Port is prepended to Ports
// Result format is string to support port ranges like "443:453"
func (p *PublicConfig) GetPorts() []string {
	var result []string

	// Add single port if specified
	if p.Port != 0 {
		result = append(result, fmt.Sprintf("%d", p.Port))
	}

	// Add ports list if specified
	if len(p.Ports) > 0 {
		result = append(result, p.Ports...)
	}

	return result
}
