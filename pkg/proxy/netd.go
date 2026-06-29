/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// netdAliasManager is the helper-backed aliasManager: it dials the root netd
// daemon and sends EnsureAlias/RemoveAlias so the unprivileged proxy can plumb the
// VIP's /32 lo0 alias. It satisfies aliasManager.
type netdAliasManager struct {
	client *wire.Client
}

// Ensure plumbs the /32 lo0 alias for ip via the daemon.
func (m *netdAliasManager) Ensure(ctx context.Context, ip netip.Addr) error {
	return m.client.EnsureAlias(ctx, ip)
}

// Remove tears the /32 lo0 alias for ip down via the daemon.
func (m *netdAliasManager) Remove(ctx context.Context, ip netip.Addr) error {
	return m.client.RemoveAlias(ctx, ip)
}

// binder opens the proxy's listening sockets. It is the consumer seam between the
// proxy and the privilege model: the direct binder calls net.Listen (the proxy
// binds its own sockets, an explicit run-as-root or unprivileged-≥1024 mode); the
// netd binder asks the root daemon to bind a privileged (<1024) Service port and
// passes the listening socket back over SCM_RIGHTS, so the unprivileged proxy can
// serve a VIP:port it could not bind itself.
type binder interface {
	// Listen returns a listening socket on the SPECIFIC addr (never the wildcard).
	Listen(ctx context.Context, network string, addr netip.AddrPort) (net.Listener, error)
}

// directBinder binds the proxy's own sockets with net.Listen. It is the default
// and the run-as-root path.
type directBinder struct{}

// Listen binds addr directly.
func (directBinder) Listen(_ context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	return net.Listen(network, addr.String())
}

// netdBinder binds privileged ports through the root netd daemon. A port the proxy
// can bind itself (>=1024) is bound locally to avoid a needless helper round-trip;
// a privileged port (<1024) is requested from the daemon, which authorizes it and
// returns the listening socket over SCM_RIGHTS. This is the one selection of the
// bind backend (paired with the alias backend by WithNetdHelper), not a per-call
// fork of policy: the <1024 split is a transport optimization, the daemon remains
// the sole authority for the privileged bind.
type netdBinder struct {
	client *wire.Client
}

// Listen binds addr, routing a privileged (<1024) port through the daemon.
func (b *netdBinder) Listen(ctx context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	if addr.Port() >= 1024 {
		return net.Listen(network, addr.String())
	}
	f, err := b.client.BindPort(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("netd bind %s %s: %w", network, addr, err)
	}
	defer f.Close()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("adopt netd socket for %s: %w", addr, err)
	}
	return ln, nil
}
