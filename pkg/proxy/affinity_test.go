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

// affinityBindings reports the live ClientIP binding total across ALL ports
// (RoutingTable.affinityCount). It is a mu-guarded test accessor (kept in _test.go so
// it is not compiled into the proxy binary), mirroring udpRelay.flowCount: the
// count-conservation invariant is that it equals the summed cardinality of the affinity
// map at all times, so an unpaired increment or decrement breaks it.
func (t *RoutingTable) affinityBindings() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.affinityCount
}

// endpointIPSet is the set of endpoint IPs, for asserting a returned backend is a
// pool member (reachability preserved) without depending on which one round-robin
// picked.
func endpointIPSet(eps []netv1.Endpoint) map[string]bool {
	s := make(map[string]bool, len(eps))
	for _, e := range eps {
		s[e.IP] = true
	}
	return s
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

// TestNodePortClientIPAffinity is the B55 gate: the *:NodePort (external) accept path
// honors ClientIP session affinity via RoutingTable.PickStickyCluster, over the CLUSTER
// pool — externalTrafficPolicy:Cluster routes to ALL Ready backends and iTP:Local is
// ignored (KEP-2086), so external stickiness is applied to the full Ready set and never
// conflated with the east-west node-local filter. Each sub-case guards a failure mode
// the pre-build critiques flagged:
//
//  1. Sticky over a >=2-backend pool — non-vacuous: distinct clients spread across the
//     pool (round-robin would otherwise rotate), yet one client sticks.
//  2. Cluster-scope, NOT iTP:Local-conflated — an iTP:Local port whose Ready backends
//     are ALL REMOTE still sticks over the full pool on the external path, while the
//     internal PickSticky DROPS (ErrNoLocalBackends) on the same port.
//  3. Re-pick on a stale binding — a bound backend that leaves the pool is re-picked to
//     a still-Ready backend, never dialed dead.
//  4. Non-affinity NodePort degrades to round-robin — PickStickyCluster is safe to call
//     unconditionally (the handle contract).
func TestNodePortClientIPAffinity(t *testing.T) {
	t.Parallel()

	// 1. Sticky over a >=2-backend pool, non-vacuously. Over a pool of 8 backends,
	// distinct client IPs fan out (>=2 backends seen), proving round-robin underneath
	// would rotate — so one client returning the SAME backend across many calls is real
	// stickiness, not a 1-backend artifact.
	t.Run("sticky over a >=2-backend cluster pool (distribution not collapsed)", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		key := keyFor("10.43.0.55", 80)
		eps := manyEndpoints(8)
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))
		pool := endpointIPSet(eps)
		now := time.Unix(1000, 0)

		// One client sticks to a single backend across many calls.
		c1 := netip.MustParseAddr("10.1.2.3")
		first, err := tbl.PickStickyCluster(key, c1, now)
		if err != nil {
			t.Fatalf("PickStickyCluster (bind c1): %v", err)
		}
		if !pool[first.Addr().Addr().String()] {
			t.Fatalf("bound backend %q not in the cluster pool", first.Addr())
		}
		for i := 0; i < 50; i++ {
			got, err := tbl.PickStickyCluster(key, c1, now)
			if err != nil {
				t.Fatalf("PickStickyCluster (sticky c1): %v", err)
			}
			if got.Addr() != first.Addr() {
				t.Fatalf("NodePort affinity broke: c1 hit %v != %v (must stick over the cluster pool)", got.Addr(), first.Addr())
			}
		}

		// A distinct second client is served (and stable); many distinct clients spread
		// across >=2 backends, so the pool is NOT collapsed to one and single-client
		// stickiness above is meaningful (a 1-backend pool would trivially pass).
		c2 := netip.MustParseAddr("10.1.2.4")
		second, err := tbl.PickStickyCluster(key, c2, now)
		if err != nil {
			t.Fatalf("PickStickyCluster (bind c2): %v", err)
		}
		if !pool[second.Addr().Addr().String()] {
			t.Fatalf("c2 backend %q not in the cluster pool", second.Addr())
		}
		seen := map[string]int{first.Addr().Addr().String(): 1, second.Addr().Addr().String(): 1}
		for i := 0; i < 40; i++ {
			c := netip.MustParseAddr(fmt.Sprintf("10.7.7.%d", i+1))
			be, err := tbl.PickStickyCluster(key, c, now)
			if err != nil {
				t.Fatalf("PickStickyCluster (distinct client): %v", err)
			}
			seen[be.Addr().Addr().String()]++
		}
		if len(seen) < 2 {
			t.Fatalf("all clients collapsed to a single backend (%v); cluster round-robin under affinity must spread", seen)
		}
	})

	// 2. THE CRITICAL: cluster-scope, NOT iTP:Local-conflated. A VALID podCIDR +
	// iTP:Local + all-REMOTE backends has ZERO node-local backends. The external path
	// must still stick over the FULL cluster pool (external forces allSet), while the
	// internal PickSticky DROPS with ErrNoLocalBackends — proving PickStickyCluster
	// re-validates against allSet, never st.localSet, so eTP:Local/B56 is not conflated.
	t.Run("cluster-scope: iTP:Local all-remote sticks externally, drops internally", func(t *testing.T) {
		t.Parallel()
		cidr := netip.MustParsePrefix("100.64.0.0/24")
		key := keyFor("10.43.0.56", 80)
		// All-REMOTE (outside the /24): ZERO node-local backends under a valid podCIDR.
		remoteEps := []netv1.Endpoint{
			{IP: "100.64.1.5", Port: 8080, Ready: true},
			{IP: "100.64.1.6", Port: 8080, Ready: true},
			{IP: "100.64.1.7", Port: 8080, Ready: true},
		}
		remoteSet := endpointIPSet(remoteEps)
		now := time.Unix(2000, 0)

		tbl := NewRoutingTable(cidr)
		tbl.SetEndpointsPolicy(key, remoteEps, trafficLocal, clientIPAffinity(affinityTestTimeout))

		// External path: binds and sticks over the full (all-remote) cluster pool.
		c1 := netip.MustParseAddr("100.64.9.9")
		bound, err := tbl.PickStickyCluster(key, c1, now)
		if err != nil {
			t.Fatalf("PickStickyCluster with all-remote iTP:Local = %v, want a remote backend (external forces the cluster pool)", err)
		}
		if !remoteSet[bound.Addr().Addr().String()] {
			t.Fatalf("external bound backend %q not in the (remote) cluster pool", bound.Addr())
		}
		for i := 0; i < 40; i++ {
			got, err := tbl.PickStickyCluster(key, c1, now)
			if err != nil {
				t.Fatalf("PickStickyCluster (sticky): %v", err)
			}
			if got.Addr() != bound.Addr() {
				t.Fatalf("external affinity broke over the cluster pool: %v != %v", got.Addr(), bound.Addr())
			}
		}

		// Contrast: the INTERNAL selector on the SAME port drops — iTP:Local with no
		// node-local backend. The external path did NOT weaken this east-west guarantee.
		if be, err := tbl.PickSticky(key, c1, now); !errors.Is(err, ErrNoLocalBackends) {
			t.Fatalf("PickSticky (internal) = (%v, %v), want ErrNoLocalBackends (iTP:Local drop preserved)", be.Addr(), err)
		}
	})

	// 3. Re-pick on a stale binding: a bound backend that leaves the Ready pool (a
	// reconcile to a set excluding it) is re-picked to a still-Ready backend on the next
	// external call, never dialed dead.
	t.Run("re-pick when the bound backend goes unready", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		key := keyFor("10.43.0.57", 80)
		eps := manyEndpoints(6)
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))
		now := time.Unix(3000, 0)

		// Warm the cursor so the bound backend is unlikely to be pool[0] (a fresh cursor
		// re-picking pool[0] would make the re-pick assertion vacuous).
		for i := 0; i < 3; i++ {
			if _, err := tbl.PickStickyCluster(key, netip.MustParseAddr(fmt.Sprintf("10.8.8.%d", i+1)), now); err != nil {
				t.Fatalf("warm-up PickStickyCluster: %v", err)
			}
		}
		client := netip.MustParseAddr("10.1.2.3")
		bound, err := tbl.PickStickyCluster(key, client, now)
		if err != nil {
			t.Fatalf("PickStickyCluster (bind): %v", err)
		}
		boundIP := bound.Addr().Addr().String()

		// Reconcile to a set that EXCLUDES the bound backend (it went unready).
		remaining := make([]netv1.Endpoint, 0, len(eps))
		for _, e := range eps {
			if e.IP != boundIP {
				remaining = append(remaining, e)
			}
		}
		tbl.SetEndpointsPolicy(key, remaining, trafficCluster, clientIPAffinity(affinityTestTimeout))

		got, err := tbl.PickStickyCluster(key, client, now)
		if err != nil {
			t.Fatalf("PickStickyCluster after bound backend left pool: %v", err)
		}
		gotIP := got.Addr().Addr().String()
		if gotIP == boundIP {
			t.Fatalf("stale binding reused: %q left the Ready pool but was returned again (dead backend)", boundIP)
		}
		if !endpointIPSet(remaining)[gotIP] {
			t.Fatalf("re-pick %q is not a Ready backend of the live pool", gotIP)
		}
	})

	// 4. Non-affinity NodePort degrades to round-robin: a port with affinityMode !=
	// ClientIP round-robins over the cluster pool, so handle can call PickStickyCluster
	// unconditionally (the same contract PickSticky honors on the internal path).
	t.Run("non-affinity NodePort round-robins over the cluster pool", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		key := keyFor("10.43.0.58", 80)
		eps := manyEndpoints(6)
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, affinityConfig{}) // affinityNone
		now := time.Unix(4000, 0)

		// A single client is NOT pinned: it spreads across the pool by round-robin.
		client := netip.MustParseAddr("10.1.2.3")
		seen := map[string]int{}
		for i := 0; i < 60; i++ {
			be, err := tbl.PickStickyCluster(key, client, now)
			if err != nil {
				t.Fatalf("PickStickyCluster (None): %v", err)
			}
			seen[be.Addr().Addr().String()]++
		}
		if len(seen) < 2 {
			t.Fatalf("non-affinity NodePort pinned one client to a single backend (%v); want round-robin spread", seen)
		}
		// No bindings recorded for a non-affinity port.
		if n := len(tbl.affinity[key]); n != 0 {
			t.Fatalf("non-affinity NodePort recorded %d bindings, want 0", n)
		}
	})
}

// TestAffinityAggregateBoundAndEviction is the B51 gate: it hardens B22's ClientIP
// affinity with a relay-GLOBAL aggregate binding ceiling and an O(1) eviction. It
// asserts INVARIANTS (count-conservation, reachability), never a specific eviction
// victim — the O(1) evict is pseudo-random (Go map iteration), so victim identity is
// non-deterministic by design. Small caps are injected via the RoutingTable fields
// directly (never by mutating the package const), so the ceilings are reachable in a
// unit test.
//
//  1. Global ceiling degrades to round-robin: at the aggregate cap a NEW client gets a
//     valid pool backend but NO binding (reachable, not sticky); affinityCount never
//     exceeds the ceiling.
//  2. Per-port O(1) eviction: a client past a port's per-port cap IS bound (an existing
//     one evicted); the sub-map never exceeds the cap and the count tracks it.
//  3. Return-to-zero after every wholesale purge (the CRITICAL backstop): binding N
//     clients across several ports then purging each wholesale — no-Ready-backends
//     reconcile, ClientIP->None reconcile, Delete — returns affinityCount to exactly 0.
//     A per-call decrement at a wholesale site (removing len(binds)>1 at once) leaves a
//     positive residue → this subtest goes red, proving the cardinality decrement is
//     load-bearing and the assertion is non-vacuous.
func TestAffinityAggregateBoundAndEviction(t *testing.T) {
	t.Parallel()

	// 1. GLOBAL CEILING: fill the aggregate binding total across MULTIPLE ports to a
	// small maxAffinityTotal, then a fresh client must still get a valid round-robin
	// backend with NO binding recorded (fail-open: reachable, not sticky).
	t.Run("global ceiling degrades new clients to round-robin (reachable, no binding)", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.maxAffinityTotal = 4 // tiny relay-global ceiling; per-port stays at the default
		now := time.Unix(1000, 0)

		keyA := keyFor("10.43.0.1", 80)
		keyB := keyFor("10.43.0.2", 80)
		eps := manyEndpoints(8) // wide pool so a round-robin spread is unmistakable
		pool := endpointIPSet(eps)
		tbl.SetEndpointsPolicy(keyA, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))
		tbl.SetEndpointsPolicy(keyB, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))

		// Two bindings on each of two ports == 4 == the ceiling.
		fill := []struct {
			key PortKey
			ip  string
		}{
			{keyA, "10.1.0.1"}, {keyA, "10.1.0.2"},
			{keyB, "10.2.0.1"}, {keyB, "10.2.0.2"},
		}
		for _, f := range fill {
			if _, err := tbl.PickSticky(f.key, netip.MustParseAddr(f.ip), now); err != nil {
				t.Fatalf("PickSticky bind %s@%s: %v", f.ip, f.key, err)
			}
		}
		if got := tbl.affinityBindings(); got != 4 {
			t.Fatalf("affinityCount after filling to the ceiling = %d, want 4", got)
		}

		// A NEW client at the ceiling: must get a valid backend (round-robin) but record
		// NO binding — never an error/reject.
		newClient := netip.MustParseAddr("10.9.9.9")
		be, err := tbl.PickSticky(keyA, newClient, now)
		if err != nil {
			t.Fatalf("PickSticky at the ceiling returned %v; affinity must fail OPEN (round-robin), never reject", err)
		}
		if !pool[be.Addr().Addr().String()] {
			t.Fatalf("degraded pick %q is not a pool backend; reachability must be preserved", be.Addr().Addr().String())
		}
		if got := tbl.affinityBindings(); got != 4 {
			t.Fatalf("affinityCount = %d after a degraded pick, want a steady 4 (no binding created at the ceiling)", got)
		}

		// The degraded client is NOT sticky: repeated picks spread across the pool, and
		// the count never drifts above the ceiling.
		seen := map[string]bool{}
		for i := 0; i < 40; i++ {
			b, err := tbl.PickSticky(keyA, newClient, now)
			if err != nil {
				t.Fatalf("PickSticky (degraded): %v", err)
			}
			seen[b.Addr().Addr().String()] = true
			if got := tbl.affinityBindings(); got > tbl.maxAffinityTotal {
				t.Fatalf("affinityCount = %d exceeded the ceiling %d during degraded picks", got, tbl.maxAffinityTotal)
			}
		}
		if len(seen) < 2 {
			t.Fatalf("degraded client pinned to a single backend %v; want a round-robin spread (no binding)", seen)
		}
	})

	// 2. PER-PORT O(1) EVICTION: past a small per-port cap the newest client is admitted
	// (an existing binding evicted); the sub-map stays bounded and the count tracks it.
	t.Run("per-port eviction bounds the sub-map and binds the newest client", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.maxAffinityPerPort = 2 // tiny per-port cap; global stays at the default
		now := time.Unix(2000, 0)
		key := keyFor("10.43.0.5", 80)
		eps := manyEndpoints(8)
		pool := endpointIPSet(eps)
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))

		c1 := netip.MustParseAddr("10.1.0.1")
		c2 := netip.MustParseAddr("10.1.0.2")
		c3 := netip.MustParseAddr("10.1.0.3")
		for _, c := range []netip.Addr{c1, c2} {
			if _, err := tbl.PickSticky(key, c, now); err != nil {
				t.Fatalf("PickSticky bind %v: %v", c, err)
			}
		}
		if n := len(tbl.affinity[key]); n != 2 {
			t.Fatalf("port bindings = %d after 2 clients, want 2 (at the cap)", n)
		}

		// A 3rd distinct client forces an O(1) eviction of one existing binding.
		be, err := tbl.PickSticky(key, c3, now)
		if err != nil {
			t.Fatalf("PickSticky bind c3: %v", err)
		}
		if !pool[be.Addr().Addr().String()] {
			t.Fatalf("c3 pick %q is not a pool backend", be.Addr().Addr().String())
		}
		if n := len(tbl.affinity[key]); n != 2 {
			t.Fatalf("port bindings = %d after the 3rd client, want exactly 2 (one evicted, c3 admitted, cap held)", n)
		}
		if got := tbl.affinityBindings(); got != 2 {
			t.Fatalf("affinityCount = %d, want 2 (the per-port evict must decrement, not leak)", got)
		}

		// c3 IS bound (not degraded): an immediate re-pick is sticky to the same backend.
		be2, err := tbl.PickSticky(key, c3, now)
		if err != nil {
			t.Fatalf("PickSticky c3 re-pick: %v", err)
		}
		if be2.Addr() != be.Addr() {
			t.Fatalf("c3 not sticky after admission: %v != %v (the newest client must be bound)", be2.Addr(), be.Addr())
		}
	})

	// STALE-REFRESH CONSERVATION (the CRITICAL both post-build critiques caught): re-picking a
	// client whose binding went STALE (idle past the timeout, or its backend left the pool)
	// drops the stale binding then re-creates — net-zero to the map, so affinityCount must NOT
	// drift up. The single-key stale-drop must route through dropBinding (decrement); an
	// unpaired delete leaks +1 per stale re-pick and eventually wedges the node at the ceiling.
	t.Run("stale-binding refresh does not leak the count", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		now := time.Unix(5000, 0)
		key := keyFor("10.43.0.5", 80)
		eps := manyEndpoints(8)
		tbl.SetEndpointsPolicy(key, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))
		c := netip.MustParseAddr("10.9.0.1")

		if _, err := tbl.PickSticky(key, c, now); err != nil {
			t.Fatalf("initial bind: %v", err)
		}
		if got := tbl.affinityBindings(); got != 1 {
			t.Fatalf("affinityCount = %d after 1 bind, want 1", got)
		}

		// Re-pick the SAME client 5×, each past the idle timeout (stale on every hit, no
		// sweep) so it hits the stale-drop-then-recreate path — net-zero each time.
		const rePicks = 5
		for i := 1; i <= rePicks; i++ {
			now = now.Add(affinityTestTimeout + time.Second)
			if _, err := tbl.PickSticky(key, c, now); err != nil {
				t.Fatalf("stale re-pick %d: %v", i, err)
			}
		}
		if n := len(tbl.affinity[key]); n != 1 {
			t.Fatalf("port bindings = %d, want 1 (one client, one live binding)", n)
		}
		if got := tbl.affinityBindings(); got != 1 {
			t.Fatalf("affinityCount = %d after %d stale re-picks, want 1 — the stale-drop must decrement (an unpaired delete leaks to %d)", got, rePicks, 1+rePicks)
		}
	})

	// 3. RETURN-TO-ZERO (the CRITICAL backstop): bind N clients across several ports,
	// then exercise all three routing.go wholesale-purge sites; affinityCount must
	// return to exactly 0. A per-call '--' at a wholesale site under-counts by
	// len(binds)-1 per site and leaves a positive residue → red, so this is non-vacuous.
	t.Run("affinityCount returns to zero after every wholesale purge", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		now := time.Unix(3000, 0)
		eps := manyEndpoints(8)

		keyDrain := keyFor("10.43.0.1", 80) // purged by a no-Ready-backends reconcile
		keyNone := keyFor("10.43.0.2", 80)  // purged by a ClientIP->None reconcile
		keyDel := keyFor("10.43.0.3", 80)   // purged by Delete
		ports := []PortKey{keyDrain, keyNone, keyDel}
		for _, k := range ports {
			tbl.SetEndpointsPolicy(k, eps, trafficCluster, clientIPAffinity(affinityTestTimeout))
		}

		// Bind several distinct clients on EACH port so len(binds) > 1 per port — that is
		// what makes a per-call decrement observably wrong (it would remove only 1).
		const perPort = 3
		total := 0
		for pi, k := range ports {
			for c := 0; c < perPort; c++ {
				ip := netip.MustParseAddr(fmt.Sprintf("10.%d.0.%d", pi+1, c+1))
				if _, err := tbl.PickSticky(k, ip, now); err != nil {
					t.Fatalf("PickSticky bind %v@%v: %v", ip, k, err)
				}
				total++
			}
		}
		if got := tbl.affinityBindings(); got != total {
			t.Fatalf("affinityCount = %d after binding %d clients, want %d", got, total, total)
		}

		// Trigger each wholesale purge site exactly once.
		tbl.SetEndpointsPolicy(keyDrain, nil, trafficCluster, clientIPAffinity(affinityTestTimeout)) // len(ready)==0 drop
		tbl.SetEndpointsPolicy(keyNone, eps, trafficCluster, affinityConfig{})                       // ClientIP->None drop
		tbl.Delete(keyDel)                                                                           // Delete drop

		if got := tbl.affinityBindings(); got != 0 {
			t.Fatalf("affinityCount = %d after three wholesale purges, want 0 "+
				"(a per-call decrement leaks len(binds)-1 per site; the drop MUST decrement by cardinality)", got)
		}
		for _, k := range ports {
			if n := len(tbl.affinity[k]); n != 0 {
				t.Fatalf("affinity[%v] still has %d bindings after purge, want 0", k, n)
			}
		}
	})
}
