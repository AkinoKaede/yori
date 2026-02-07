// SPDX-License-Identifier: GPL-3.0-only

package subscription

import (
	"regexp"
	"strings"

	"github.com/AkinoKaede/proxy-relay/config"
	"github.com/AkinoKaede/proxy-relay/internal"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// ProcessOptions holds compiled regex and configuration for outbound processing
type ProcessOptions struct {
	config.OutboundProcessOptions
	filter  []*regexp.Regexp
	exclude []*regexp.Regexp
	rename  []*RenameRule
}

// RenameRule represents a compiled rename pattern
type RenameRule struct {
	From *regexp.Regexp
	To   string
}

// NewProcessOptions creates a new ProcessOptions with compiled regex patterns
func NewProcessOptions(opts config.OutboundProcessOptions) (*ProcessOptions, error) {
	var (
		filter  []*regexp.Regexp
		exclude []*regexp.Regexp
		rename  []*RenameRule
	)

	// Compile filter patterns
	for i, pattern := range opts.Filter {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, E.Cause(err, "parse filter[", i, "]")
		}
		filter = append(filter, re)
	}

	// Compile exclude patterns
	for i, pattern := range opts.Exclude {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, E.Cause(err, "parse exclude[", i, "]")
		}
		exclude = append(exclude, re)
	}

	// Compile rename patterns
	for pattern, replacement := range opts.Rename {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, E.Cause(err, "parse rename pattern: ", pattern)
		}
		rename = append(rename, &RenameRule{
			From: re,
			To:   replacement,
		})
	}

	return &ProcessOptions{
		OutboundProcessOptions: opts,
		filter:                 filter,
		exclude:                exclude,
		rename:                 rename,
	}, nil
}

// Process applies filtering, renaming, and rewriting to outbounds
// Returns processed outbounds and a set of local-only tags
func (p *ProcessOptions) Process(outbounds []option.Outbound) ([]option.Outbound, map[string]bool) {
	var result []option.Outbound
	localOnlyTags := make(map[string]bool)
	tagChanges := make(map[string]string) // Track tag changes for updating references

	for _, outbound := range outbounds {
		// Determine if this outbound should be processed
		if !p.shouldProcess(outbound) {
			result = append(result, outbound)
			continue
		}

		// If remove is set, skip this outbound
		if p.Remove {
			continue
		}

		// If local_only is set, mark this outbound
		if p.LocalOnly {
			localOnlyTags[outbound.Tag] = true
		}

		originalTag := outbound.Tag

		// Apply rename rules
		for _, rule := range p.rename {
			outbound.Tag = rule.From.ReplaceAllString(outbound.Tag, rule.To)
		}

		// Remove emoji if requested
		if p.RemoveEmoji {
			outbound.Tag = internal.RemoveEmoji(outbound.Tag)
		}

		// Trim whitespace
		outbound.Tag = strings.TrimSpace(outbound.Tag)

		// Track tag changes
		if originalTag != outbound.Tag {
			tagChanges[originalTag] = outbound.Tag
			// Update local-only tags if tag changed
			if localOnlyTags[originalTag] {
				delete(localOnlyTags, originalTag)
				localOnlyTags[outbound.Tag] = true
			}
		}

		// Apply rewrites based on outbound type
		p.applyRewrites(&outbound)

		result = append(result, outbound)
	}

	// Update tag references in selector/urltest outbounds
	if len(tagChanges) > 0 {
		result = updateTagReferences(result, tagChanges)
	}

	return result, localOnlyTags
}

// shouldProcess determines if an outbound matches the filter criteria
func (p *ProcessOptions) shouldProcess(outbound option.Outbound) bool {
	// If no filters are specified, all outbounds are in scope
	if len(p.filter) == 0 && len(p.FilterType) == 0 && len(p.exclude) == 0 && len(p.ExcludeType) == 0 {
		return !p.Invert
	}

	var matched bool

	// Check filter patterns
	if len(p.filter) > 0 {
		if common.Any(p.filter, func(re *regexp.Regexp) bool {
			return re.MatchString(outbound.Tag)
		}) {
			matched = true
		}
	}

	// Check filter types
	if !matched && len(p.FilterType) > 0 {
		if common.Contains(p.FilterType, outbound.Type) {
			matched = true
		}
	}

	// Check exclude patterns (inverse match)
	if !matched && len(p.exclude) > 0 {
		if !common.Any(p.exclude, func(re *regexp.Regexp) bool {
			return re.MatchString(outbound.Tag)
		}) {
			matched = true
		}
	}

	// Check exclude types (inverse match)
	if !matched && len(p.ExcludeType) > 0 {
		if !common.Contains(p.ExcludeType, outbound.Type) {
			matched = true
		}
	}

	// Apply invert if specified
	if p.Invert {
		matched = !matched
	}

	return matched
}

// applyRewrites applies protocol-specific rewrites to an outbound
func (p *ProcessOptions) applyRewrites(outbound *option.Outbound) {
	switch opts := outbound.Options.(type) {
	case *option.ShadowsocksOutboundOptions:
		if p.RewriteMultiplex != nil {
			opts.Multiplex = p.RewriteMultiplex
		}
		if p.RewriteDialerOptions != nil {
			opts.DialerOptions = *p.RewriteDialerOptions
		}
	case *option.VMessOutboundOptions:
		if p.RewriteMultiplex != nil {
			opts.Multiplex = p.RewriteMultiplex
		}
		if p.RewriteDialerOptions != nil {
			opts.DialerOptions = *p.RewriteDialerOptions
		}
		if p.RewritePacketEncoding != "" {
			opts.PacketEncoding = p.RewritePacketEncoding
		}
		if p.RewriteUTLS != nil {
			p.applyUTLSRewrite(&opts.TLS, p.RewriteUTLS)
		}
	case *option.VLESSOutboundOptions:
		if p.RewriteMultiplex != nil {
			opts.Multiplex = p.RewriteMultiplex
		}
		if p.RewriteDialerOptions != nil {
			opts.DialerOptions = *p.RewriteDialerOptions
		}
		if p.RewritePacketEncoding != "" {
			opts.PacketEncoding = &p.RewritePacketEncoding
		}
		if p.RewriteUTLS != nil {
			p.applyUTLSRewrite(&opts.TLS, p.RewriteUTLS)
		}
	case *option.TrojanOutboundOptions:
		if p.RewriteMultiplex != nil {
			opts.Multiplex = p.RewriteMultiplex
		}
		if p.RewriteDialerOptions != nil {
			opts.DialerOptions = *p.RewriteDialerOptions
		}
		if p.RewriteUTLS != nil {
			p.applyUTLSRewrite(&opts.TLS, p.RewriteUTLS)
		}
	}
}

// applyUTLSRewrite applies uTLS configuration to outbound TLS settings
func (p *ProcessOptions) applyUTLSRewrite(tls **option.OutboundTLSOptions, utlsCfg *config.RewriteUTLSOptions) {
	if *tls == nil {
		*tls = &option.OutboundTLSOptions{}
	}
	if utlsCfg.Enabled {
		(*tls).UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: utlsCfg.Fingerprint,
		}
	} else {
		(*tls).UTLS = nil
	}
}

// updateTagReferences updates tag references in selector and urltest outbounds
func updateTagReferences(outbounds []option.Outbound, tagChanges map[string]string) []option.Outbound {
	for i := range outbounds {
		switch opts := outbounds[i].Options.(type) {
		case *option.SelectorOutboundOptions:
			for j, tag := range opts.Outbounds {
				if newTag, changed := tagChanges[tag]; changed {
					opts.Outbounds[j] = newTag
				}
			}
		case *option.URLTestOutboundOptions:
			for j, tag := range opts.Outbounds {
				if newTag, changed := tagChanges[tag]; changed {
					opts.Outbounds[j] = newTag
				}
			}
		}
	}
	return outbounds
}
