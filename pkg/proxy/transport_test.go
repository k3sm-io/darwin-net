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
	"net/netip"
	"slices"
	"sync"
	"testing"
)

// vmPublished stands in for a vm pod's PUBLISHED identity: a /32 out of the
// cluster podCIDR that the pod's node aliases on lo0 and serves through the
// per-pod relay (podrelay.go), never the address a VIP backend dial targets.
// Nothing in this file ever dials it — the override is what these tests resolve —
// so no test here depends on what the network does with it.
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
		tbl.SetTransportOverrides(liveOnly(map[netip.Addr]netip.Addr{vmPublished: live}))

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
		tbl.SetTransportOverrides(liveOnly(map[netip.Addr]netip.Addr{
			vmPublished: live,
			otherVM:     netip.MustParseAddr("192.168.64.6"),
		}))

		// Generation 2 re-leases vmPublished and no longer mentions otherVM (its pod
		// died). Wholesale replacement must apply BOTH facts.
		relive := netip.MustParseAddr("192.168.64.9")
		tbl.SetTransportOverrides(liveOnly(map[netip.Addr]netip.Addr{vmPublished: relive}))

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
				tbl.SetTransportOverrides(liveOnly(map[netip.Addr]netip.Addr{vmPublished: live}))
				tbl.SetTransportOverrides(liveOnly(tc.clear))
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
		tbl.SetTransportOverrides(liveOnly(map[netip.Addr]netip.Addr{
			vmPublished:                        {},         // invalid value: skipped, not installed as a black hole
			{}:                                 live,       // invalid key: skipped
			mappedKey:                          live,       // v4-in-v6 key: normalized to its v4 form
			netip.MustParseAddr("100.64.0.10"): mappedLive, // v4-in-v6 value: likewise
		}))
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

	t.Run("f: the caller may reuse its map and slices — SetTransportOverrides copies", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		ports := []uint16{8080, 0, 80, 8080}
		feed := map[netip.Addr]VMPodTransport{vmPublished: {Live: live, Ports: ports}}
		tbl.SetTransportOverrides(feed)
		feed[vmPublished] = VMPodTransport{Live: netip.MustParseAddr("192.168.64.99")} // the feeder reuses its buffer
		ports[0] = 9999
		want := netip.AddrPortFrom(live, 80)
		if got := tbl.transportAddr(netip.AddrPortFrom(vmPublished, 80)); got != want {
			t.Errorf("transportAddr = %s, want %s (a retained caller map must not mutate the table)", got, want)
		}
		if got := tbl.load().transport[vmPublished].Ports; !slices.Equal(got, []uint16{80, 8080}) {
			t.Errorf("installed ports = %v, want [80 8080] (copied, sorted, de-duplicated, zero dropped)", got)
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
				tbl.SetTransportOverrides(liveOnly(map[netip.Addr]netip.Addr{vmPublished: live}))
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

// liveOnly lifts a published-to-live address map into the override value type,
// declaring no ports, for the tests that exercise only the dial-site resolution.
// A nil map stays nil.
func liveOnly(m map[netip.Addr]netip.Addr) map[netip.Addr]VMPodTransport {
	if m == nil {
		return nil
	}
	out := make(map[netip.Addr]VMPodTransport, len(m))
	for k, v := range m {
		out[k] = VMPodTransport{Live: v}
	}
	return out
}
