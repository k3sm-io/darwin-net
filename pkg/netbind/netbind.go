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

package netbind

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// Binder opens a listening socket. It is the seam between a socket-owning
// consumer and the privilege model: Direct binds in-process (run-as-root or
// unprivileged->=1024); Netd asks the root daemon to bind and adopts the socket
// over SCM_RIGHTS.
type Binder interface {
	// Listen returns a listening socket on addr. An implementation MAY refuse
	// an address it is not authorized to bind — Netd's root daemon refuses a
	// wildcard on a non-privileged (>=1024) port, and admits a privileged
	// wildcard only for a port its authorizer confirms (the canonical ingress
	// ports) — so every caller must handle the error. Legality is a property of
	// the binder in hand, NOT a precondition callers can discharge by knowing
	// the concrete type: a seam whose contract depends on which implementation
	// is behind it is a hidden type dependency, not a seam.
	Listen(ctx context.Context, network string, addr netip.AddrPort) (net.Listener, error)
}

// Direct binds the consumer's own sockets with net.Listen. It is the default
// and the run-as-root path.
type Direct struct{}

// Listen binds addr directly.
func (Direct) Listen(_ context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	return net.Listen(network, addr.String())
}

// Netd binds every requested port through the root netd daemon: the daemon
// authorizes the bind and returns the listening socket over SCM_RIGHTS, which
// Listen adopts. Netd forwards every address unchanged and does not pre-refuse
// the wildcard client-side: the daemon is the one authority, and it refuses a
// wildcard on a >=1024 port (the caller can bind that itself) while admitting a
// <1024 wildcard its authorizer confirms. This is the ONE
// SCM_RIGHTS fd-adoption path in the module — consumers wanting a local-bind
// fast path for unprivileged ports wrap it (see pkg/proxy) rather than copying it.
//
// The wire names only "tcp" and "udp"; Listen maps a family-specific network
// ("tcp4", "udp6", ...) to its wire name, and the daemon picks the family from
// the address itself (an IPv4 address binds IPv4-only there too).
type Netd struct {
	// Client is the netd wire client the bind is requested through.
	Client *wire.Client

	// bindPort is the wire call; nil means Client.BindPort. It is the seam the
	// unit test fakes.
	bindPort func(ctx context.Context, network string, addr netip.AddrPort) (*os.File, error)
}

// Listen requests the bind for addr from the daemon and adopts the returned fd.
func (b *Netd) Listen(ctx context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	bind := b.bindPort
	if bind == nil {
		bind = b.Client.BindPort
	}
	f, err := bind(ctx, wireNetwork(network), addr)
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

// Family returns the network to bind addr on: network+"4" ("tcp4", "udp4") for
// an IPv4 or IPv4-mapped address, else network unchanged. On macOS Go binds an
// IPv4 address under "tcp"/"udp" on a dual-stack AF_INET6 socket (0.0.0.0 becomes
// [::]), and that socket binds beside an IPv4-only process already holding the
// port, so the conflict goes unseen; an AF_INET socket is refused with
// EADDRINUSE. network is "tcp" or "udp".
func Family(network string, addr netip.Addr) string {
	if addr.Unmap().Is4() {
		return network + "4"
	}
	return network
}

// wireNetwork maps a family-specific network to the name the netd wire carries:
// "tcp4"/"tcp6" to "tcp", "udp4"/"udp6" to "udp". Any other name passes
// unchanged, for the daemon to refuse.
func wireNetwork(network string) string {
	switch network {
	case "tcp4", "tcp6":
		return "tcp"
	case "udp4", "udp6":
		return "udp"
	}
	return network
}
