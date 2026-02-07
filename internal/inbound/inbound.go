// SPDX-License-Identifier: GPL-3.0-only

package inbound

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// User is an authenticated inbound user mapped to a target outbound.
type User struct {
	Name     string
	Password string
	Outbound string
}

// ConnectionDispatcher routes inbound connections to outbounds.
type ConnectionDispatcher interface {
	DispatchConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, user User, onClose N.CloseHandlerFunc)
	DispatchPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, user User, onClose N.CloseHandlerFunc)
}

// Inbound defines a hot-reloadable inbound implementation.
type Inbound interface {
	Start() error
	Close() error
	UpdateUsers(users []User) error
}
