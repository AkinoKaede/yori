// SPDX-License-Identifier: GPL-3.0-only

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"

	"github.com/sagernet/sing-box/option"
)

// GeneratePassword generates a stable password from a tag using SHA256
func GeneratePassword(tag, salt string) string {
	h := sha256.New()
	h.Write([]byte(tag + salt))
	hash := h.Sum(nil)
	return hex.EncodeToString(hash)[:32]
}

// GenerateRandomPassword generates a random password of specified length
func GenerateRandomPassword(length int) string {
	if length <= 0 {
		length = 16
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a hash-based approach if random fails
		h := sha256.New()
		h.Write([]byte("fallback"))
		hash := h.Sum(nil)
		return hex.EncodeToString(hash)[:length]
	}

	return hex.EncodeToString(b)[:length]
}

// RemoveEmoji removes emoji characters from a string
func RemoveEmoji(s string) string {
	var result strings.Builder
	for _, r := range s {
		if !isEmoji(r) {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// isEmoji checks if a rune is an emoji
func isEmoji(r rune) bool {
	// Common emoji ranges
	return (r >= 0x1F600 && r <= 0x1F64F) || // Emoticons
		(r >= 0x1F300 && r <= 0x1F5FF) || // Misc Symbols and Pictographs
		(r >= 0x1F680 && r <= 0x1F6FF) || // Transport and Map
		(r >= 0x1F1E0 && r <= 0x1F1FF) || // Regional indicators (flags)
		(r >= 0x2600 && r <= 0x26FF) || // Misc symbols
		(r >= 0x2700 && r <= 0x27BF) || // Dingbats
		(r >= 0xFE00 && r <= 0xFE0F) || // Variation Selectors
		(r >= 0x1F900 && r <= 0x1F9FF) || // Supplemental Symbols and Pictographs
		(r >= 0x1FA70 && r <= 0x1FAFF) // Symbols and Pictographs Extended-A
}

// DeduplicateTags ensures all tags are unique by appending suffixes
func DeduplicateTags(tags []string) []string {
	seen := make(map[string]int)
	result := make([]string, len(tags))
	for i, tag := range tags {
		if count, exists := seen[tag]; exists {
			// Tag already exists, append counter
			count++
			seen[tag] = count
			result[i] = tag + "-" + string(rune('0'+count))
		} else {
			seen[tag] = 0
			result[i] = tag
		}
	}
	return result
}

// ReplaceWithCaptures performs regex replacement supporting capture groups
func ReplaceWithCaptures(pattern, replacement, text string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", err
	}
	return re.ReplaceAllString(text, replacement), nil
}

// IsASCII checks if a string contains only ASCII characters
func IsASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// HashConfig generates a SHA256 hash of a sing-box configuration
// Used to detect if configuration has actually changed before reloading
func HashConfig(opts *option.Options) string {
	if opts == nil {
		return ""
	}

	// Marshal to JSON for consistent hashing
	data, err := json.Marshal(opts)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
