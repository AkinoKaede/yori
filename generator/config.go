// SPDX-License-Identifier: GPL-3.0-only

package generator

import (
	"fmt"

	"github.com/AkinoKaede/proxy-relay/config"
	"github.com/sagernet/sing-box/option"
)

// GenerateConfig builds a complete sing-box configuration
func GenerateConfig(
	cfg *config.Config,
	outbounds []option.Outbound,
	users []option.Hysteria2User,
	userToOutbound map[string]string,
) (*option.Options, error) {
	opts := &option.Options{
		Log: &option.LogOptions{
			Level: "info",
		},
	}

	// Build inbounds (one per port)
	inbounds := make([]option.Inbound, 0, len(cfg.Hysteria2.Ports))
	for _, port := range cfg.Hysteria2.Ports {
		inbound, err := buildHysteria2Inbound(cfg, port, users)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, inbound)
	}

	// Set outbounds
	opts.Outbounds = outbounds

	// Set inbounds
	opts.Inbounds = inbounds

	// Build route
	opts.Route = buildRoute(userToOutbound)

	return opts, nil
}

// buildHysteria2Inbound creates a Hysteria2 inbound configuration
func buildHysteria2Inbound(cfg *config.Config, port uint16, users []option.Hysteria2User) (option.Inbound, error) {
	// Configure TLS
	tlsOpts, err := buildTLSOptions(cfg)
	if err != nil {
		return option.Inbound{}, err
	}

	// Build Hysteria2 options
	hysteria2Opts := &option.Hysteria2InboundOptions{
		ListenOptions: option.ListenOptions{
			ListenPort: port,
		},
		UpMbps:   cfg.Hysteria2.UpMbps,
		DownMbps: cfg.Hysteria2.DownMbps,
		Users:    users,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: tlsOpts,
		},
	}

	// Configure obfuscation
	if cfg.Hysteria2.Obfs != nil {
		hysteria2Opts.Obfs = &option.Hysteria2Obfs{
			Type:     cfg.Hysteria2.Obfs.Type,
			Password: cfg.Hysteria2.Obfs.Password,
		}
	}

	inbound := option.Inbound{
		Type: "hysteria2",
		Tag:  fmt.Sprintf("hy2-in-%d", port),
	}
	inbound.Options = hysteria2Opts

	return inbound, nil
}

// buildTLSOptions creates TLS configuration (ACME or manual)
func buildTLSOptions(cfg *config.Config) (*option.InboundTLSOptions, error) {
	tls := &option.InboundTLSOptions{
		Enabled: true,
	}

	// ACME configuration
	if cfg.Hysteria2.TLS.ACME != nil {
		acme := cfg.Hysteria2.TLS.ACME
		tls.ACME = &option.InboundACMEOptions{
			Domain:        acme.Domain,
			Email:         acme.Email,
			Provider:      acme.Provider,
			DataDirectory: acme.DataDirectory,
		}

		// DNS-01 challenge if configured
		if acme.DNS01 != nil {
			tls.ACME.DNS01Challenge = &option.ACMEDNS01ChallengeOptions{
				Provider: acme.DNS01.Provider,
			}

			// Configure provider-specific options
			switch acme.DNS01.Provider {
			case "cloudflare":
				tls.ACME.DNS01Challenge.CloudflareOptions = option.ACMEDNS01CloudflareOptions{
					APIToken: acme.DNS01.APIToken,
				}
			case "alidns":
				tls.ACME.DNS01Challenge.AliDNSOptions = option.ACMEDNS01AliDNSOptions{
					AccessKeyID:     acme.DNS01.AccessKey,
					AccessKeySecret: acme.DNS01.SecretKey,
				}
			}
		}
	} else {
		// Manual certificate configuration
		tls.CertificatePath = cfg.Hysteria2.TLS.CertificatePath
		tls.KeyPath = cfg.Hysteria2.TLS.KeyPath
	}

	return tls, nil
}

// buildRoute creates routing rules for user-based routing
func buildRoute(userToOutbound map[string]string) *option.RouteOptions {
	rules := make([]option.Rule, 0, len(userToOutbound)+1)

	// Create a rule for each user
	for username, outboundTag := range userToOutbound {
		rules = append(rules, option.Rule{
			Type: "default",
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					AuthUser: []string{username},
				},
				RuleAction: option.RuleAction{
					RouteOptions: option.RouteActionOptions{
						Outbound: outboundTag,
					},
				},
			},
		})
	}

	// Add default rule (block or first outbound)
	rules = append(rules, option.Rule{
		Type: "default",
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				RouteOptions: option.RouteActionOptions{
					Outbound: "block",
				},
			},
		},
	})

	return &option.RouteOptions{
		Rules: rules,
	}
}
