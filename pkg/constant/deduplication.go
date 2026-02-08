// SPDX-License-Identifier: GPL-3.0-only

package constant

// Deduplication strategies for handling duplicate outbound tags
const (
	// DeduplicationRename appends suffix to duplicate tags (default behavior)
	// Example: "node", "node-x", "node-xx"
	DeduplicationRename = "rename"

	// DeduplicationFirst keeps the first occurrence, discards subsequent duplicates
	DeduplicationFirst = "first"

	// DeduplicationLast keeps the last occurrence, discards previous duplicates
	DeduplicationLast = "last"

	// DeduplicationPreferIPv4 prioritizes IPv4 > Domain > IPv6
	DeduplicationPreferIPv4 = "prefer_ipv4"

	// DeduplicationPreferIPv6 prioritizes IPv6 > Domain > IPv4
	DeduplicationPreferIPv6 = "prefer_ipv6"

	// DeduplicationPreferDomainThenIPv4 prioritizes Domain > IPv4 > IPv6
	DeduplicationPreferDomainThenIPv4 = "prefer_domain_then_ipv4"

	// DeduplicationPreferDomainThenIPv6 prioritizes Domain > IPv6 > IPv4
	DeduplicationPreferDomainThenIPv6 = "prefer_domain_then_ipv6"
)

// Address types for deduplication strategies
const (
	AddressTypeDomain = "domain"
	AddressTypeIPv4   = "ipv4"
	AddressTypeIPv6   = "ipv6"
)
