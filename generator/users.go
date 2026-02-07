// SPDX-License-Identifier: GPL-3.0-only

package generator

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/AkinoKaede/proxy-relay/datafile"
	"github.com/sagernet/sing-box/option"
)

// GenerateUsers creates Hysteria2 users from outbounds and HTTP usernames
// For each username and outbound combination, it generates a unique Hysteria2 user
// Username format: base64(httpUsername:outboundTag)
// Password format: base64Username:base64(32randomBytes)
// Returns: users, userToOutbound mapping, httpUserToHysteria2Users mapping
func GenerateUsers(
	ctx context.Context,
	outbounds []option.Outbound,
	usernames []string,
	dataFile *datafile.DataFile,
) ([]option.Hysteria2User, map[string]string, map[string][]string) {
	// If no usernames configured, use default "user"
	if len(usernames) == 0 {
		usernames = []string{"user"}
	}

	// Calculate capacity: each outbound × each HTTP username
	capacity := len(outbounds) * len(usernames)
	users := make([]option.Hysteria2User, 0, capacity)
	userToOutbound := make(map[string]string, capacity)
	httpUserToHysteria2Users := make(map[string][]string) // HTTP username -> Hysteria2 usernames

	for _, username := range usernames {
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

// UserMapping represents the mapping between users and outbounds
type UserMapping struct {
	Users          []option.Hysteria2User
	UserToOutbound map[string]string
}

// NewUserMapping creates a new user mapping from outbounds and HTTP usernames
func NewUserMapping(
	ctx context.Context,
	outbounds []option.Outbound,
	usernames []string,
	dataFile *datafile.DataFile,
) *UserMapping {
	users, mapping, _ := GenerateUsers(ctx, outbounds, usernames, dataFile)
	return &UserMapping{
		Users:          users,
		UserToOutbound: mapping,
	}
}
