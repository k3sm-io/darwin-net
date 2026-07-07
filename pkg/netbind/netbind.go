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

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// Binder opens a listening socket. It is the seam between a socket-owning
// consumer and the privilege model: Direct binds in-process (run-as-root or
// unprivileged->=1024); Netd asks the root daemon to bind and adopts the socket
// over SCM_RIGHTS.
type Binder interface {
	// Listen returns a listening socket on the SPECIFIC addr (never the wildcard).
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
// authorizes the SPECIFIC-address bind (it rejects a wildcard) and returns the
// listening socket over SCM_RIGHTS, which Listen adopts. This is the ONE
// SCM_RIGHTS fd-adoption path in the module — consumers wanting a local-bind
// fast path for unprivileged ports wrap it (see pkg/proxy) rather than copying it.
type Netd struct {
	// Client is the netd wire client the bind is requested through.
	Client *wire.Client
}

// Listen requests the bind for addr from the daemon and adopts the returned fd.
func (b *Netd) Listen(ctx context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	f, err := b.Client.BindPort(ctx, network, addr)
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
