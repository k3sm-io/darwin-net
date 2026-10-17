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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
)

// TestDirectListensSpecificAddr proves the Direct binder opens a listener on
// the SPECIFIC requested address (the loopback ephemeral case tests cover).
// The Netd binder's SCM_RIGHTS adoption path is proven end-to-end by
// pkg/netd's TestProxyClientRoundTrip against an in-process daemon.
func TestDirectListensSpecificAddr(t *testing.T) {
	ln, err := Direct{}.Listen(context.Background(), "tcp", netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("Direct.Listen: %v", err)
	}
	defer ln.Close()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("bound %q, want a 127.0.0.1 listener (err=%v)", ln.Addr(), err)
	}
}

// TestFamily proves an IPv4 address (unmapped, IPv4-mapped, or the wildcard)
// binds on the IPv4-only network and an IPv6 address keeps the network as given.
func TestFamily(t *testing.T) {
	for _, tc := range []struct {
		network, addr, want string
	}{
		{"tcp", "0.0.0.0", "tcp4"},
		{"tcp", "127.0.0.1", "tcp4"},
		{"tcp", "::ffff:10.43.0.10", "tcp4"},
		{"udp", "10.43.0.10", "udp4"},
		{"udp", "::ffff:0.0.0.0", "udp4"},
		{"tcp", "::", "tcp"},
		{"tcp", "::1", "tcp"},
		{"udp", "fd00::1", "udp"},
	} {
		t.Run(tc.network+" "+tc.addr, func(t *testing.T) {
			if got := Family(tc.network, netip.MustParseAddr(tc.addr)); got != tc.want {
				t.Fatalf("Family(%q, %s) = %q, want %q", tc.network, tc.addr, got, tc.want)
			}
		})
	}
}

// errFakeAccepted stops the fake wire call after it accepts a protocol, so the
// test needs no real socket to adopt.
var errFakeAccepted = errors.New("fake wire: accepted")

// TestNetdListenSendsTheWireProtocol proves Netd.Listen maps a family-specific
// network to the wire's "tcp"/"udp" before the request: the fake wire client,
// like the daemon, refuses any other protocol.
func TestNetdListenSendsTheWireProtocol(t *testing.T) {
	for _, tc := range []struct {
		network, want string
	}{
		{"tcp", "tcp"},
		{"tcp4", "tcp"},
		{"tcp6", "tcp"},
		{"udp", "udp"},
		{"udp4", "udp"},
		{"udp6", "udp"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			var sent string
			b := &Netd{bindPort: func(_ context.Context, network string, _ netip.AddrPort) (*os.File, error) {
				sent = network
				if network != "tcp" && network != "udp" {
					return nil, fmt.Errorf("fake wire: unsupported protocol %q", network)
				}
				return nil, errFakeAccepted
			}}
			_, err := b.Listen(context.Background(), tc.network, netip.MustParseAddrPort("0.0.0.0:80"))
			if !errors.Is(err, errFakeAccepted) {
				t.Fatalf("Listen(%q) = %v, want the wire call to accept it", tc.network, err)
			}
			if sent != tc.want {
				t.Fatalf("Listen(%q) sent protocol %q, want %q", tc.network, sent, tc.want)
			}
		})
	}
}
