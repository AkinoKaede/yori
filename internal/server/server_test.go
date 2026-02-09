// SPDX-License-Identifier: GPL-3.0-only

package server

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
)

func TestUpdateRenamePatterns(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	cfg := &ServerConfig{
		Listen: "127.0.0.1:0",
		Rename: []RenameRule{
			{Pattern: "old", Replace: "first"},
		},
	}
	server := NewServer(context.Background(), logger, cfg)

	if got := server.applyRename("node-old", "sub"); got != "node-first" {
		t.Fatalf("expected initial rename to apply, got %q", got)
	}

	server.UpdateRenamePatterns([]RenameRule{
		{Pattern: "old", Replace: "second", Subscriptions: []string{"sub"}},
	})

	if got := server.applyRename("node-old", "other"); got != "node-old" {
		t.Fatalf("expected subscription filter to skip rename, got %q", got)
	}
	if got := server.applyRename("node-old", "sub"); got != "node-second" {
		t.Fatalf("expected updated rename to apply, got %q", got)
	}
}
