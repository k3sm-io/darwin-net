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
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// These tests pin the bind family at each specific-address listener: an IPv4
// address reaches the binder or listen call as "tcp4"/"udp4" (IPv4-only, so an
// IPv4-only holder of the port is seen), an IPv6 address keeps "tcp"/"udp".
// They run on in-memory listeners and fake bind calls; no socket is opened.

// TestClusterIPListenerBindsIPv4Only proves the ClusterIP stream listener of an
// IPv4 VIP reaches the binder as "tcp4".
func TestClusterIPListenerBindsIPv4Only(t *testing.T) {
	t.Parallel()
	b := newRecordingBinder()
	p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(newNoopAliasManager()), withBinder(b),
		WithLogger(slog.New(slog.DiscardHandler)))
	key := PortKey{ClusterIP: "10.43.0.80", Port: 80, Protocol: netv1.ProtocolTCP}
	l, err := p.openListener(key, &netv1.ServicePort{Port: 80, Protocol: netv1.ProtocolTCP})
	if err != nil {
		t.Fatalf("open ClusterIP listener: %v", err)
	}
	defer l.Close()
	if b.count() != 1 {
		t.Fatalf("bound %d listeners, want 1", b.count())
	}
	b.mu.Lock()
	got := b.ls[0]
	b.mu.Unlock()
	if got.network != "tcp4" || got.address != "10.43.0.80:80" {
		t.Fatalf("ClusterIP listener = %s %s, want tcp4 10.43.0.80:80", got.network, got.address)
	}
}

// errFakeUDPBind stops the fake datagram bind after it records the network.
var errFakeUDPBind = errors.New("fake udp bind")

// TestUDPVIPListenerBindsIPv4Only proves the ClusterIP datagram bind of an IPv4
// VIP uses "udp4" and of an IPv6 address "udp", and that a failed bind returns
// a nil interface.
func TestUDPVIPListenerBindsIPv4Only(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ addr, want string }{
		{"10.43.0.10:53", "udp4"},
		{"[::ffff:10.43.0.10]:53", "udp4"},
		{"[fd00::10]:53", "udp"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			t.Parallel()
			var sent string
			listen := func(network string, _ *net.UDPAddr) (*net.UDPConn, error) {
				sent = network
				return nil, errFakeUDPBind
			}
			c, err := listenUDPVIPWith(listen, netip.MustParseAddrPort(tc.addr))
			if !errors.Is(err, errFakeUDPBind) || c != nil {
				t.Fatalf("listenUDPVIPWith(%s) = %v, %v; want nil, the fake's error", tc.addr, c, err)
			}
			if sent != tc.want {
				t.Fatalf("listenUDPVIPWith(%s) bound on %q, want %q", tc.addr, sent, tc.want)
			}
		})
	}
}

// TestPodRelayListenerBindsByFamily proves the vm pod relay binds an IPv4
// published address as "tcp4" and an IPv6 one as "tcp".
func TestPodRelayListenerBindsByFamily(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ published, live, want string }{
		{"10.42.0.30", "192.168.64.5", "tcp4"},
		{"fd00:42::30", "fd00:64::5", "tcp"},
	} {
		t.Run(tc.published, func(t *testing.T) {
			t.Parallel()
			b := newRecordingBinder()
			p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(newNoopAliasManager()), withBinder(b),
				WithLogger(slog.New(slog.DiscardHandler)))
			r := &podRelay{
				published: netip.MustParseAddr(tc.published),
				live:      netip.MustParseAddr(tc.live),
				listeners: make(map[uint16]net.Listener),
				conns:     make(map[net.Conn]struct{}),
			}
			if err := p.relays.open(context.Background(), r, 8080); err != nil {
				t.Fatalf("open relay port: %v", err)
			}
			r.close()
			p.relays.wg.Wait()
			b.mu.Lock()
			defer b.mu.Unlock()
			if len(b.ls) != 1 {
				t.Fatalf("bound %d listeners, want 1", len(b.ls))
			}
			want := netip.AddrPortFrom(r.published, 8080).String()
			if got := b.ls[0]; got.network != tc.want || got.address != want {
				t.Fatalf("relay listener = %s %s, want %s %s", got.network, got.address, tc.want, want)
			}
		})
	}
}
