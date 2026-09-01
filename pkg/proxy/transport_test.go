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
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// vmPublished stands in for a vm pod's PUBLISHED identity: a /32 out of the
// cluster podCIDR that is deliberately live on NO interface (the host must never
// alias a guest's address). Nothing in this file ever dials it — that is the whole
// point of the override — so no test here depends on what the network does with it.
var vmPublished = netip.MustParseAddr("100.64.0.7")

// TestTransportOverrideResolution is the pure table over RoutingTable's
// published-to-live transport map (M11.3-d2): the resolution itself, the
// port-preservation contract, normalization, and the wholesale-swap lifecycle that
// keeps a stale override from surviving a generation.
func TestTransportOverrideResolution(t *testing.T) {
	t.Parallel()

	live := netip.MustParseAddr("192.168.64.5")
	hostPod := netip.MustParseAddr("100.64.0.3")

	t.Run("a: no overrides installed — every backend resolves to itself", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		for _, ap := range []netip.AddrPort{
			netip.AddrPortFrom(hostPod, 8080),
			netip.AddrPortFrom(vmPublished, 8080),
			netip.MustParseAddrPort("127.0.0.1:80"),
		} {
			if got := tbl.transportAddr(ap); got != ap {
				t.Errorf("transportAddr(%s) = %s, want the published address unchanged", ap, got)
			}
		}
	})

	t.Run("b: an override redirects the address and PRESERVES the published port", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: live})

		// The port is the guest's real listening port; a DHCP lease never changes it.
		for _, port := range []uint16{80, 8080, 65535} {
			got := tbl.transportAddr(netip.AddrPortFrom(vmPublished, port))
			want := netip.AddrPortFrom(live, port)
			if got != want {
				t.Errorf("transportAddr(%s:%d) = %s, want %s", vmPublished, port, got, want)
			}
		}
		// A backend with no override is untouched by the presence of others.
		unrelated := netip.AddrPortFrom(hostPod, 8080)
		if got := tbl.transportAddr(unrelated); got != unrelated {
			t.Errorf("transportAddr(%s) = %s, want unchanged (a populated map must not disturb other backends)", unrelated, got)
		}
	})

	t.Run("c: a later swap DROPS the previous generation — no stale override leaks", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		otherVM := netip.MustParseAddr("100.64.0.8")
		tbl.SetTransportOverrides(map[netip.Addr]netip.Addr{
			vmPublished: live,
			otherVM:     netip.MustParseAddr("192.168.64.6"),
		})

		// Generation 2 re-leases vmPublished and no longer mentions otherVM (its pod
		// died). Wholesale replacement must apply BOTH facts.
		relive := netip.MustParseAddr("192.168.64.9")
		tbl.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: relive})

		if got, want := tbl.transportAddr(netip.AddrPortFrom(vmPublished, 80)), netip.AddrPortFrom(relive, 80); got != want {
			t.Errorf("after re-lease: transportAddr = %s, want %s", got, want)
		}
		stale := netip.AddrPortFrom(otherVM, 80)
		if got := tbl.transportAddr(stale); got != stale {
			t.Errorf("dropped override still resolves: transportAddr(%s) = %s — a stale lease would misdeliver to another guest", stale, got)
		}
	})

	t.Run("d: an emptied or nil map reverts every backend to its published address", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name  string
			clear map[netip.Addr]netip.Addr
		}{
			{"nil", nil},
			{"empty", map[netip.Addr]netip.Addr{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tbl := NewRoutingTable(netip.Prefix{})
				tbl.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: live})
				tbl.SetTransportOverrides(tc.clear)
				ap := netip.AddrPortFrom(vmPublished, 80)
				if got := tbl.transportAddr(ap); got != ap {
					t.Errorf("transportAddr(%s) = %s, want the published address (the override was cleared)", ap, got)
				}
			})
		}
	})

	t.Run("e: invalid entries are skipped and v4-mapped addresses normalize", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		mappedKey := netip.AddrFrom16(netip.MustParseAddr("100.64.0.9").As16())
		mappedLive := netip.AddrFrom16(live.As16())
		tbl.SetTransportOverrides(map[netip.Addr]netip.Addr{
			vmPublished:                        {},         // invalid value: skipped, not installed as a black hole
			{}:                                 live,       // invalid key: skipped
			mappedKey:                          live,       // v4-in-v6 key: normalized to its v4 form
			netip.MustParseAddr("100.64.0.10"): mappedLive, // v4-in-v6 value: likewise
		})
		ap := netip.AddrPortFrom(vmPublished, 80)
		if got := tbl.transportAddr(ap); got != ap {
			t.Errorf("an invalid override VALUE must be skipped: transportAddr(%s) = %s, want unchanged", ap, got)
		}
		want := netip.AddrPortFrom(live, 80)
		if got := tbl.transportAddr(netip.AddrPortFrom(netip.MustParseAddr("100.64.0.9"), 80)); got != want {
			t.Errorf("v4-mapped key: transportAddr = %s, want %s", got, want)
		}
		if got := tbl.transportAddr(netip.AddrPortFrom(netip.MustParseAddr("100.64.0.10"), 80)); got != want {
			t.Errorf("v4-mapped value: transportAddr = %s, want %s (unmapped)", got, want)
		}
	})

	t.Run("f: the caller may reuse its map — SetTransportOverrides copies", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		feed := map[netip.Addr]netip.Addr{vmPublished: live}
		tbl.SetTransportOverrides(feed)
		feed[vmPublished] = netip.MustParseAddr("192.168.64.99") // the feeder reuses its buffer
		want := netip.AddrPortFrom(live, 80)
		if got := tbl.transportAddr(netip.AddrPortFrom(vmPublished, 80)); got != want {
			t.Errorf("transportAddr = %s, want %s (a retained caller map must not mutate the table)", got, want)
		}
	})

	t.Run("g: concurrent swaps and resolutions are race-free", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				tbl.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: live})
				tbl.SetTransportOverrides(nil)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				// Either generation is a correct answer; only a race is not.
				got := tbl.transportAddr(netip.AddrPortFrom(vmPublished, 80))
				if got.Port() != 80 {
					t.Errorf("resolved port = %d, want 80 under concurrent swaps", got.Port())
					return
				}
			}
		}()
		wg.Wait()
	})
}

// TestTransportOverrideDialTarget proves the seam at the DIAL, on both accept
// paths: with an override installed the proxy dials the live transport address
// (reaching a backend that is NOT at the published identity), and with none it is
// byte-identical to today for a host-process pod. Loopback only — no test here
// dials an off-loopback address.
func TestTransportOverrideDialTarget(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("10.42.0.10")

	t.Run("a: TCP — the dial follows the override to the live address", func(t *testing.T) {
		t.Parallel()
		// The backend LISTENS on loopback; the routing table PUBLISHES it at the vm
		// /32 with that same port. Only the override can bridge the two, so reaching
		// the banner is proof the dial used it.
		be := newTCPBanner(t, "127.0.0.1:0")
		port := be.addrPort().Port()

		p, table := newPolicyProxy(nil)
		table.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: be.addrPort().Addr()})
		key := PortKey{ClusterIP: "10.43.2.1", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{{IP: vmPublished.String(), Port: int32(port), Ready: true}})

		if !handleVIP(t, p, key, src) {
			t.Fatalf("connection did not reach the backend: the dial must follow the transport override")
		}
		if got := be.accepts.Load(); got != 1 {
			t.Errorf("backend accepts = %d, want 1", got)
		}
	})

	t.Run("b: TCP — a host-process backend is unchanged, with an empty AND a populated map", func(t *testing.T) {
		t.Parallel()
		be := newTCPBanner(t, "127.0.0.1:0")
		p, table := newPolicyProxy(nil)
		key := PortKey{ClusterIP: "10.43.2.2", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{be.endpoint()})

		// No override map has ever been installed: the pre-M11.3 shape exactly.
		if !handleVIP(t, p, key, src) {
			t.Errorf("host-process backend must be reached with no overrides installed")
		}
		// A populated map that does not name this backend must not disturb it.
		table.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: netip.MustParseAddr("192.168.64.5")})
		if !handleVIP(t, p, key, src) {
			t.Errorf("host-process backend must be reached while OTHER backends carry overrides")
		}
		// And an explicitly emptied map is the same thing again.
		table.SetTransportOverrides(nil)
		if !handleVIP(t, p, key, src) {
			t.Errorf("host-process backend must be reached after the override map is cleared")
		}
		if got := be.accepts.Load(); got != 3 {
			t.Errorf("backend accepts = %d, want 3 (every host-process dial unchanged)", got)
		}
	})

	t.Run("c: UDP — the relay's per-flow dial follows the same override", func(t *testing.T) {
		t.Parallel()
		bp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp backend: %v", err)
		}
		defer bp.Close()
		beAP := bp.LocalAddr().(*net.UDPAddr).AddrPort()

		table := NewRoutingTable(netip.Prefix{})
		table.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: beAP.Addr()})
		key := PortKey{ClusterIP: "10.43.2.3", Port: 53, Protocol: netv1.ProtocolUDP}
		table.SetEndpoints(key, []netv1.Endpoint{{IP: vmPublished.String(), Port: int32(beAP.Port()), Ready: true}})

		vip, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen vip socket: %v", err)
		}
		r := newUDPRelay(vip, key, table, egressScope{}, time.Minute, maxUDPFlowsPerSource, nil, slog.New(slog.DiscardHandler))
		defer func() { _ = r.Close() }()

		var lastWarn time.Time
		up := r.upstreamFor(&net.UDPAddr{IP: src.AsSlice(), Port: 5001}, &lastWarn)
		if up == nil {
			t.Fatalf("flow admission failed")
		}
		if _, err := up.Write([]byte("ping")); err != nil {
			t.Fatalf("write via admitted flow: %v", err)
		}
		_ = bp.SetReadDeadline(time.Now().Add(policyTestTimeout))
		buf := make([]byte, 16)
		n, _, err := bp.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "ping" {
			t.Fatalf("backend must receive the datagram at the OVERRIDE address (read %q, err %v)", buf[:n], err)
		}
	})
}
