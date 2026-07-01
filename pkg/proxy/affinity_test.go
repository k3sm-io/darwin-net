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
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// affinityTestTimeout is a short, finite ClientIP TTL used across the affinity gate
// so expiry is driven entirely by an INJECTED clock (now) — never a real sleep (the
// production default is 3h, untestable in wall-clock time).
const affinityTestTimeout = 30 * time.Second

// stubAddr is a net.Addr whose String() is a fixed "ip:port", so clientAddr can be
// exercised without a real socket.
type stubAddr string

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return string(a) }

// manyEndpoints returns n Ready endpoints with distinct sorted IPs (10.42.0.1..n),
// so a round-robin picker fans across a wide pool and stickiness is unmistakable.
func manyEndpoints(n int) []netv1.Endpoint {
	eps := make([]netv1.Endpoint, n)
	for i := 0; i < n; i++ {
		eps[i] = netv1.Endpoint{IP: fmt.Sprintf("10.42.0.%d", i+1), Port: 8080, Ready: true}
	}
	return eps
}

func clientIPAffinity(timeout time.Duration) affinityConfig {
	return affinityConfig{mode: affinityClientIP, timeout: timeout}
}

// TestSessionAffinityClientIPSticky is the B22 gate: the userspace proxy's TCP path
// honors ClientIP session affinity via RoutingTable.PickSticky. Each sub-case guards
// a specific failure mode the pre-build critiques flagged:
//
//  1. IP-only keying — the client key strips the ephemeral source port.
//  2. Survives endpoint churn — the binding map is TABLE-level, not on the wiped
//     portState.
//  3. iTP:Local re-pick — a stale binding is re-validated against the live pool and
//     never reused (no dead backend, no mesh spill; drop when no local remains).
//  4. Expiry — an idle binding is TTL-swept (injected clock) and re-picked.
//  5. affinity->None purge — toggling ClientIP off drops the bindings.
func TestSessionAffinityClientIPSticky(t *testing.T) {
	t.Parallel()

	// 1. IP-only keying: two connections from the same client IP on DIFFERENT source
	// ports resolve to one binding. On an IP:port key this fails.
	t.Run("ip-only keying: different source ports share one binding", func(t *testing.T) {
		t.Parallel()
		a1 := clientAddr(stubAddr("10.1.2.3:40001"))
		a2 := clientAddr(stubAddr("10.1.2.3:59999"))
		if !a1.IsValid() || a1 != a2 {
			t.Fatalf("clientAddr did not strip the ephemeral port: %v vs %v (affinity must key on IP alone)", a1, a2)
		}

		tbl := NewRoutingTable(netip.Prefix{})
		key := keyFor("10.43.0.99", 80)
		tbl.SetEndpointsPolicy(key, manyEndpoints(8), trafficCluster, clientIPAffinity(affinityTestTimeout))

		now := time.Unix(1000, 0)
		first, err := tbl.PickSticky(key, a1, now)
		if err != nil {
			t.Fatalf("PickSticky (bind): %v", err)
		}
		// The "other port" connection maps to the same key, so it sticks to the same
		// backend every time — over a pool of 8, round-robin would spread instead.
		for i := 0; i < 50; i++ {
			got, err := tbl.PickSticky(key, a2, now)
			if err != nil {
				t.Fatalf("PickSticky: %v", err)
			}
			if got.Addr() != first.Addr() {
				t.Fatalf("same client IP hit a different backend: %v != %v (key must be IP-only)", got.Addr(), first.Addr())
			}
		}
	})

	// 2. Survives endpoint churn: a reconcile replaces the portState, but a
	// table-level binding survives. A warm-up advances the cursor so the bound backend
	// is NOT pool[0] — otherwise a (buggy) per-portState map that resets the cursor to
	// 0 would coincidentally re-pick pool[0] and the test would be vacuous.
	t.Run("survives endpoint churn (bindings are table-level, not on portState)", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		key := keyFor("10.43.0.99", 80)
		eps := manyEndpoints(6)
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))

		now := time.Unix(2000, 0)
		for i := 0; i < 3; i++ {
			if _, err := tbl.PickSticky(key, netip.MustParseAddr(fmt.Sprintf("10.9.9.%d", i+1)), now); err != nil {
				t.Fatalf("warm-up PickSticky: %v", err)
			}
		}
		client := netip.MustParseAddr("10.1.2.3")
		first, err := tbl.PickSticky(key, client, now)
		if err != nil {
			t.Fatalf("PickSticky (bind): %v", err)
		}

		// A reconcile that KEEPS the bound backend Ready — this replaces the portState
		// wholesale (fresh cursor, fresh sets). The binding must survive it.
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))

		got, err := tbl.PickSticky(key, client, now)
		if err != nil {
			t.Fatalf("PickSticky after churn: %v", err)
		}
		if got.Addr() != first.Addr() {
			t.Fatalf("binding did not survive endpoint churn: %v != %v (the map must be table-level, not a portState field)", got.Addr(), first.Addr())
		}
	})

	// 3. THE CRITICAL: under iTP:Local a bound backend that LEAVES the eligible pool
	// must be re-picked (never reused → no dead backend), never spilled to a remote
	// (no mesh spill), and — when NO node-local backend remains — dropped with
	// ErrNoLocalBackends rather than reused.
	t.Run("iTP:Local re-pick: stale binding never reused (no dead backend, no mesh spill)", func(t *testing.T) {
		t.Parallel()
		cidr := netip.MustParsePrefix("100.64.0.0/24")
		key := keyFor("10.43.0.99", 80)
		client := netip.MustParseAddr("10.1.2.3")
		now := time.Unix(3000, 0)

		localA := netv1.Endpoint{IP: "100.64.0.5", Port: 8080, Ready: true} // local
		localB := netv1.Endpoint{IP: "100.64.0.6", Port: 8080, Ready: true} // local
		remote := netv1.Endpoint{IP: "100.64.1.9", Port: 8080, Ready: true} // out /24 -> remote

		tbl := NewRoutingTable(cidr)
		tbl.SetEndpointsPolicy(key, []netv1.Endpoint{localA, localB, remote}, trafficLocal, clientIPAffinity(affinityTestTimeout))

		bound, err := tbl.PickSticky(key, client, now)
		if err != nil {
			t.Fatalf("PickSticky (bind): %v", err)
		}
		boundIP := bound.Addr().Addr().String()
		if bound.Locality() != LocalityLocal || (boundIP != localA.IP && boundIP != localB.IP) {
			t.Fatalf("iTP:Local bound to a non-local backend %q (locality %v)", boundIP, bound.Locality())
		}

		// The bound backend LEAVES the pool; the OTHER local stays, plus the remote.
		remaining := localA
		if boundIP == localA.IP {
			remaining = localB
		}
		tbl.SetEndpointsPolicy(key, []netv1.Endpoint{remaining, remote}, trafficLocal, clientIPAffinity(affinityTestTimeout))

		got, err := tbl.PickSticky(key, client, now)
		if err != nil {
			t.Fatalf("PickSticky after bound backend left pool: %v", err)
		}
		gotIP := got.Addr().Addr().String()
		if gotIP == boundIP {
			t.Fatalf("stale binding reused: %q left the eligible pool but was returned again (dead backend)", boundIP)
		}
		if got.Locality() != LocalityLocal || gotIP != remaining.IP {
			t.Fatalf("re-pick = %q (locality %v), want the remaining LOCAL backend %q (no mesh spill)", gotIP, got.Locality(), remaining.IP)
		}

		// Now ALL local backends leave; only the remote remains under iTP:Local. The
		// re-pick must DROP (ErrNoLocalBackends), never reuse the stale binding or
		// spill to the remote.
		tbl.SetEndpointsPolicy(key, []netv1.Endpoint{remote}, trafficLocal, clientIPAffinity(affinityTestTimeout))
		if be, err := tbl.PickSticky(key, client, now); !errors.Is(err, ErrNoLocalBackends) {
			t.Fatalf("PickSticky with no node-local backend = (%v, %v), want ErrNoLocalBackends (drop, not spill)", be.Addr(), err)
		}
	})

	// 4. Expiry: an idle binding is evicted by SweepExpired past its TTL (injected
	// clock), and PickSticky itself re-picks a binding it finds expired inline.
	t.Run("expiry: idle bindings are swept and re-picked (injected clock)", func(t *testing.T) {
		t.Parallel()

		// (a) SweepExpired path.
		tbl := NewRoutingTable(netip.Prefix{})
		key := keyFor("10.43.0.99", 80)
		tbl.SetEndpointsPolicy(key, manyEndpoints(6), trafficCluster, clientIPAffinity(affinityTestTimeout))

		client := netip.MustParseAddr("10.1.2.3")
		t0 := time.Unix(4000, 0)
		first, err := tbl.PickSticky(key, client, t0)
		if err != nil {
			t.Fatalf("PickSticky (bind): %v", err)
		}
		// Within the window the binding holds (and refreshes lastSeen to tHold).
		tHold := t0.Add(affinityTestTimeout / 2)
		if got, _ := tbl.PickSticky(key, client, tHold); got.Addr() != first.Addr() {
			t.Fatalf("binding expired early inside the window: %v != %v", got.Addr(), first.Addr())
		}
		if n := len(tbl.affinity[key]); n != 1 {
			t.Fatalf("bound client count = %d, want 1 before sweep", n)
		}
		// Sweep well past the LAST activity (tHold): the idle binding is evicted.
		tbl.SweepExpired(tHold.Add(affinityTestTimeout + time.Second))
		if n := len(tbl.affinity[key]); n != 0 {
			t.Fatalf("SweepExpired left %d bindings, want 0 (idle past TTL)", n)
		}

		// (b) Inline expiry: a PickSticky past the timeout re-picks rather than reusing
		// the stale binding. Advance the cursor between bind and re-pick so the fresh
		// pick is observably different from the expired one.
		tbl2 := NewRoutingTable(netip.Prefix{})
		key2 := keyFor("10.43.0.98", 80)
		tbl2.SetEndpointsPolicy(key2, manyEndpoints(6), trafficCluster, clientIPAffinity(affinityTestTimeout))
		c := netip.MustParseAddr("10.5.5.5")
		tBind := time.Unix(7000, 0)
		bound, err := tbl2.PickSticky(key2, c, tBind)
		if err != nil {
			t.Fatalf("PickSticky (bind): %v", err)
		}
		for i := 0; i < 3; i++ {
			if _, err := tbl2.PickSticky(key2, netip.MustParseAddr(fmt.Sprintf("10.6.6.%d", i+1)), tBind); err != nil {
				t.Fatalf("cursor-advance PickSticky: %v", err)
			}
		}
		repick, err := tbl2.PickSticky(key2, c, tBind.Add(affinityTestTimeout+time.Second))
		if err != nil {
			t.Fatalf("PickSticky past timeout: %v", err)
		}
		if repick.Addr() == bound.Addr() {
			t.Fatalf("expired binding reused inline: %v (want a fresh round-robin pick)", repick.Addr())
		}
	})

	// 5. affinity->None purge: toggling a Service ClientIP->None purges its bindings
	// (so they cannot resurrect on re-enable), and a None Service never sticks.
	t.Run("affinity ClientIP->None purges bindings and round-robins", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		key := keyFor("10.43.0.99", 80)
		eps := manyEndpoints(6)
		now := time.Unix(5000, 0)
		client := netip.MustParseAddr("10.1.2.3")

		tbl.SetEndpointsPolicy(key, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))
		if _, err := tbl.PickSticky(key, client, now); err != nil {
			t.Fatalf("PickSticky (bind): %v", err)
		}
		if len(tbl.affinity[key]) == 0 {
			t.Fatalf("ClientIP pick recorded no binding")
		}

		// Toggle affinity OFF (mode None): the reconcile must PURGE the bindings.
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, affinityConfig{})
		if n := len(tbl.affinity[key]); n != 0 {
			t.Fatalf("toggling affinity to None left %d bindings, want 0 (must purge)", n)
		}

		// A None Service never sticks: one client spread across the pool by round-robin.
		seen := map[string]int{}
		for i := 0; i < 60; i++ {
			be, err := tbl.PickSticky(key, client, now)
			if err != nil {
				t.Fatalf("PickSticky (None): %v", err)
			}
			seen[be.Addr().Addr().String()]++
		}
		if len(seen) < 2 {
			t.Fatalf("None affinity pinned one client to a single backend (%v); want round-robin spread", seen)
		}
	})
}
