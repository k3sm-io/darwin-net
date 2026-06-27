package podnet

import (
	"context"
	"net/netip"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// netdAliasManager is the helper-backed aliasManager: it dials the root netd
// daemon and sends EnsureAlias/RemoveAlias so an unprivileged process can plumb
// the pod's /32 lo0 alias it could not create itself. It satisfies aliasManager;
// the daemon re-validates that the IP is a /32 inside this node's podCIDR before
// touching lo0.
type netdAliasManager struct {
	client *wire.Client
}

// newNetdAliasManager returns an aliasManager dialing the netd daemon at
// socketPath (empty uses the default socket).
func newNetdAliasManager(socketPath string) *netdAliasManager {
	return &netdAliasManager{client: wire.NewClient(socketPath)}
}

// Ensure plumbs the /32 lo0 alias for ip via the daemon.
func (m *netdAliasManager) Ensure(ctx context.Context, ip netip.Addr) error {
	return m.client.EnsureAlias(ctx, ip)
}

// Remove tears the /32 lo0 alias for ip down via the daemon.
func (m *netdAliasManager) Remove(ctx context.Context, ip netip.Addr) error {
	return m.client.RemoveAlias(ctx, ip)
}
