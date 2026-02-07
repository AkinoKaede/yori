// SPDX-License-Identifier: GPL-3.0-only

package generator

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/AkinoKaede/proxy-relay/internal/datafile"
	"github.com/sagernet/sing-box/option"
)

// GenerateUsers creates Hysteria2 users from outbounds and HTTP user configurations
// For each username and its allowed outbounds, it generates unique Hysteria2 users
// Username format: base64(httpUsername:outboundTag)
// Password format: base64Username:base64(32randomBytes)
// Returns: users, userToOutbound mapping, httpUserToHysteria2Users mapping
func GenerateUsers(
	ctx context.Context,
	outboundsBySubscription map[string][]option.Outbound,
	httpUsers map[string][]string, // HTTP username -> allowed subscription names (empty = all)
	dataFile *datafile.DataFile,
) ([]option.Hysteria2User, map[string]string, map[string][]string) {
	// If no users configured, use default "user" with access to all subscriptions
	if len(httpUsers) == 0 {
		httpUsers = map[string][]string{"user": nil}
	}

	// Build list of all outbounds for each user
	userOutbounds := make(map[string][]option.Outbound)
	for username, subscriptionNames := range httpUsers {
		var outbounds []option.Outbound

		// If no specific subscriptions, grant access to all
		if len(subscriptionNames) == 0 {
			for _, subs := range outboundsBySubscription {
				outbounds = append(outbounds, subs...)
			}
		} else {
			// Only include outbounds from specified subscriptions
			for _, subName := range subscriptionNames {
				if subs, exists := outboundsBySubscription[subName]; exists {
					outbounds = append(outbounds, subs...)
				}
			}
		}

		userOutbounds[username] = outbounds
	}

	// Calculate total capacity
	totalCapacity := 0
	for _, outbounds := range userOutbounds {
		totalCapacity += len(outbounds)
	}

	users := make([]option.Hysteria2User, 0, totalCapacity)
	userToOutbound := make(map[string]string, totalCapacity)
	httpUserToHysteria2Users := make(map[string][]string) // HTTP username -> Hysteria2 usernames

	for username, outbounds := range userOutbounds {
		httpUserToHysteria2Users[username] = make([]string, 0, len(outbounds))

		for _, outbound := range outbounds {
			// Generate unique Hysteria2 username: base64(httpUsername:outboundTag)
			usernameRaw := fmt.Sprintf("%s:%s", username, outbound.Tag)
			hysteria2Username := base64.StdEncoding.EncodeToString([]byte(usernameRaw))

			// Try to load password from database
			var fullPassword string
			if dataFile != nil {
				fullPassword = dataFile.LoadPassword(ctx, hysteria2Username)
			}

			// If not in database or database unavailable, generate new password
			if fullPassword == "" {
				// Generate 32 random bytes for password
				randomBytes := make([]byte, 32)
				if _, err := rand.Read(randomBytes); err != nil {
					// Fallback: use hysteria2Username as entropy
					copy(randomBytes, []byte(hysteria2Username))
				}
				randomPass := base64.StdEncoding.EncodeToString(randomBytes)

				// Password format: base64Username:base64(32bytes)
				fullPassword = fmt.Sprintf("%s:%s", hysteria2Username, randomPass)

				// Store in database for future use
				if dataFile != nil {
					_ = dataFile.StorePassword(ctx, hysteria2Username, fullPassword)
				}
			}

			users = append(users, option.Hysteria2User{
				Name:     hysteria2Username,
				Password: fullPassword,
			})
			userToOutbound[hysteria2Username] = outbound.Tag
			httpUserToHysteria2Users[username] = append(httpUserToHysteria2Users[username], hysteria2Username)
		}
	}

	return users, userToOutbound, httpUserToHysteria2Users
}
