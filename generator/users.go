// SPDX-License-Identifier: GPL-3.0-only

package generator

import (
	"github.com/AkinoKaede/proxy-relay/internal"
	"github.com/sagernet/sing-box/option"
)

const defaultSalt = "proxy-relay-default-salt"

// GenerateUsers creates Hysteria2 users from outbounds
func GenerateUsers(outbounds []option.Outbound, salt string) ([]option.Hysteria2User, map[string]string) {
	if salt == "" {
		salt = defaultSalt
	}
	users := make([]option.Hysteria2User, 0, len(outbounds))
	userToOutbound := make(map[string]string, len(outbounds))
	for _, outbound := range outbounds {
		username := outbound.Tag
		password := internal.GeneratePassword(outbound.Tag, salt)
		users = append(users, option.Hysteria2User{
			Name:     username,
			Password: password,
		})
		userToOutbound[username] = outbound.Tag
	}
	return users, userToOutbound
}

// UserMapping represents the mapping between users and outbounds
type UserMapping struct {
	Users          []option.Hysteria2User
	UserToOutbound map[string]string
}

// NewUserMapping creates a new user mapping from outbounds
func NewUserMapping(outbounds []option.Outbound) *UserMapping {
	users, mapping := GenerateUsers(outbounds, "")
	return &UserMapping{
		Users:          users,
		UserToOutbound: mapping,
	}
}
