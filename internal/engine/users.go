// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/AkinoKaede/yori/internal/datafile"
	"github.com/AkinoKaede/yori/internal/inbound"

	"github.com/sagernet/sing-box/option"
)

// GenerateUsers creates inbound users and mappings for HTTP subscriptions.
// Returns: users, httpUserToHysteria2Users mapping, outboundToSubscription mapping
func GenerateUsers(
	ctx context.Context,
	outboundsBySubscription map[string][]option.Outbound,
	httpUsers map[string][]string,
	dataFile *datafile.DataFile,
) ([]inbound.User, map[string][]string, map[string]string) {
	if len(httpUsers) == 0 {
		httpUsers = map[string][]string{"user": nil}
	}

	users := make([]inbound.User, 0)
	httpUserToHysteria2Users := make(map[string][]string)
	outboundToSubscription := make(map[string]string)

	for username, subscriptionNames := range httpUsers {
		var outbounds []option.Outbound
		if subscriptionNames == nil {
			for subName, subs := range outboundsBySubscription {
				for _, ob := range subs {
					outbounds = append(outbounds, ob)
					// Build reverse mapping
					outboundToSubscription[ob.Tag] = subName
				}
			}
		} else if len(subscriptionNames) > 0 {
			for _, subName := range subscriptionNames {
				if subs, exists := outboundsBySubscription[subName]; exists {
					for _, ob := range subs {
						outbounds = append(outbounds, ob)
						// Build reverse mapping
						outboundToSubscription[ob.Tag] = subName
					}
				}
			}
		}
		httpUserToHysteria2Users[username] = make([]string, 0, len(outbounds))
		for _, outboundConfig := range outbounds {
			user, hysteria2Username := buildUser(ctx, username, outboundConfig.Tag, dataFile)
			users = append(users, user)
			httpUserToHysteria2Users[username] = append(httpUserToHysteria2Users[username], hysteria2Username)
		}
	}

	return users, httpUserToHysteria2Users, outboundToSubscription
}

func buildUser(ctx context.Context, httpUsername string, outboundTag string, dataFile *datafile.DataFile) (inbound.User, string) {
	usernameRaw := fmt.Sprintf("%s:%s", httpUsername, outboundTag)
	hysteria2Username := base64.StdEncoding.EncodeToString([]byte(usernameRaw))

	var fullPassword string
	if dataFile != nil {
		fullPassword = dataFile.LoadPassword(ctx, hysteria2Username)
	}

	if fullPassword == "" {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			copy(randomBytes, []byte(hysteria2Username))
		}
		randomPass := base64.StdEncoding.EncodeToString(randomBytes)
		fullPassword = fmt.Sprintf("%s:%s", hysteria2Username, randomPass)
		if dataFile != nil {
			_ = dataFile.StorePassword(ctx, hysteria2Username, fullPassword)
		}
	}

	return inbound.User{
		Name:     hysteria2Username,
		Password: fullPassword,
		Outbound: outboundTag,
	}, hysteria2Username
}
