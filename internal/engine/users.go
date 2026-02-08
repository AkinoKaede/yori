// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/AkinoKaede/yori/internal/config"
	"github.com/AkinoKaede/yori/internal/datafile"
	"github.com/AkinoKaede/yori/internal/inbound"

	"github.com/sagernet/sing-box/option"
)

// SubscriptionManager defines the interface for merging outbounds from subscriptions
type SubscriptionManager interface {
	MergeBySubscriptionNames(subscriptionNames []string) []option.Outbound
	GetOutboundsBySubscription() map[string][]option.Outbound
}

// subscriptionManagerWithDirect wraps a SubscriptionManager and injects direct outbound
type subscriptionManagerWithDirect struct {
	manager   SubscriptionManager
	directCfg *config.DirectConfig
}

func (s *subscriptionManagerWithDirect) MergeBySubscriptionNames(subscriptionNames []string) []option.Outbound {
	return s.manager.MergeBySubscriptionNames(subscriptionNames)
}

func (s *subscriptionManagerWithDirect) GetOutboundsBySubscription() map[string][]option.Outbound {
	result := s.manager.GetOutboundsBySubscription()
	return appendDirectSubscriptionMap(result, s.directCfg)
}

func appendDirectSubscriptionMap(outboundsBySubscription map[string][]option.Outbound, directCfg *config.DirectConfig) map[string][]option.Outbound {
	if directCfg == nil || !directCfg.Enabled || directCfg.Tag == "" {
		return outboundsBySubscription
	}

	// Check if "direct" subscription already exists
	if _, exists := outboundsBySubscription["direct"]; exists {
		return outboundsBySubscription
	}

	// Check if tag already exists in other subscriptions
	for _, outbounds := range outboundsBySubscription {
		for _, outbound := range outbounds {
			if outbound.Tag == directCfg.Tag {
				return outboundsBySubscription
			}
		}
	}

	// Add direct subscription
	outboundsBySubscription["direct"] = []option.Outbound{
		{
			Type:    "direct",
			Tag:     directCfg.Tag,
			Options: &option.DirectOutboundOptions{},
		},
	}
	return outboundsBySubscription
}

// GenerateUsers creates inbound users and mappings for HTTP subscriptions.
// Returns: users, httpUserToHysteria2Users mapping, outboundToSubscription mapping
func GenerateUsers(
	ctx context.Context,
	subManager SubscriptionManager,
	httpUsers map[string][]string,
	dataFile *datafile.DataFile,
) ([]inbound.User, map[string][]string, map[string]string) {
	if len(httpUsers) == 0 {
		httpUsers = map[string][]string{"user": nil}
	}

	users := make([]inbound.User, 0)
	httpUserToHysteria2Users := make(map[string][]string)
	outboundToSubscription := make(map[string]string)

	// Build reverse mapping: tag -> subscription name
	outboundsBySubscription := subManager.GetOutboundsBySubscription()
	tagToSub := make(map[string]string)
	for subName, outbounds := range outboundsBySubscription {
		for _, ob := range outbounds {
			tagToSub[ob.Tag] = subName
		}
	}

	for username, subscriptionNames := range httpUsers {
		// Use Manager's merge method to get deduplicated outbounds
		outbounds := subManager.MergeBySubscriptionNames(subscriptionNames)

		// Build reverse mapping for this user's outbounds
		for _, ob := range outbounds {
			if source, exists := tagToSub[ob.Tag]; exists {
				outboundToSubscription[ob.Tag] = source
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
