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
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// fakeRelayVIP and fakeRelayBackend are the addresses the fake relays are keyed
// on. Nothing binds them: the VIP socket and the upstreams are in-memory fakes
// (fakeudp_test.go), so a privileged port and a non-loopback address cost nothing.
var (
	fakeRelayVIP     = netip.MustParseAddrPort("10.43.0.53:53")
	fakeRelayBackend = netip.MustParseAddrPort("10.42.0.9:5353")
)

// newFakeRelay builds an UNSTARTED relay on a fake VIP socket, with one Ready
// backend (fakeRelayBackend) in its routing table and be's dial as its upstream
// dial. Call start to run the dispatcher and sweeper; the fake VIP socket is
// r.conn.(*fakeVIPConn).
func newFakeRelay(be *fakeUDPBackend, idle time.Duration, perSourceCap int, budget *udpBudget) *udpRelay {
	conn := newFakeVIPConn(fakeRelayVIP)
	key := PortKey{ClusterIP: fakeRelayVIP.Addr().String(), Port: int32(fakeRelayVIP.Port()), Protocol: netv1.ProtocolUDP}
	tbl := NewRoutingTable(netip.Prefix{})
	tbl.SetEndpoints(key, []netv1.Endpoint{{IP: fakeRelayBackend.Addr().String(), Port: int32(fakeRelayBackend.Port()), Ready: true}})
	r := newUDPRelay(conn, key, tbl, egressScope{}, idle, perSourceCap, budget, slog.Default())
	r.dial = be.dial
	return r
}

// flowCount reports the number of live flows. It is a test accessor for the
// idle-flow GC assertion (defined here so it is not compiled into the proxy
// binary).
func (r *udpRelay) flowCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows)
}

// perSourceTotal reports the sum of the per-source flow counts. It is a test
// accessor for the counter-purity assertion (kept here so it is not compiled into
// the proxy binary). The invariant is perSourceTotal == flowCount at all times: an
// unpaired increment or decrement would break it.
func (r *udpRelay) perSourceTotal() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	sum := 0
	for _, c := range r.perSource {
		sum += c
	}
	return sum
}

// liveTotal reports the budget's live upstream-flow count across all VIPs, read under
// mu. It is a white-box test accessor (kept in the test file so it is not compiled
// into the proxy binary) replacing the pre-B52 budget.n.Load(): total and bySource are
// now mutex-guarded, so a test reads them under mu to stay -race clean.
func (b *udpBudget) liveTotal() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

// liveSources reports how many distinct source IPs have live flows (len(bySource)),
// read under mu. Post-teardown it MUST be zero — a positive residue is a leaked
// per-source count, the B52 counter-conservation bug shape.
func (b *udpBudget) liveSources() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.bySource)
}

// TestUDPDatagramRelayRoundTrip is the ClusterIP UDP gate, in two halves that
// together cover what one real-socket round trip did (that version survives as
// TestUDPDatagramRelayRoundTripReal under the integration tag).
//
// The reconcile half drives the full Proxy path: a ClusterIP UDP Service binds the
// relay's datagram socket through the listenUDP seam at exactly the VIP address and
// port, ensures the lo0 alias first, and ReconcileDelete closes that socket.
//
// The data-path half runs a started relay: a client datagram is forwarded to the
// picked backend and the echo comes back to that client, and a second datagram from
// the SAME client reuses the SAME flow — one dial, one upstream carrying both —
// proving the relay picks a backend once per flow rather than per datagram.
func TestUDPDatagramRelayRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("reconcile binds the VIP socket and delete closes it", func(t *testing.T) {
		t.Parallel()
		vip := fakeRelayVIP.Addr()
		bound := make(chan *fakeVIPConn, 1)
		listen := func(ap netip.AddrPort) (udpVIPConn, error) {
			c := newFakeVIPConn(ap)
			bound <- c
			return c, nil
		}
		alias := newNoopAliasManager()
		tbl := NewRoutingTable(netip.Prefix{})
		p := New(tbl, withAliasManager(alias), withListenUDP(listen))

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { defer close(runDone); _ = p.Run(ctx) }()
		defer func() { cancel(); <-runDone }()

		sp := &netv1.ServicePort{Port: int32(fakeRelayVIP.Port()), TargetPort: 5353, Protocol: netv1.ProtocolUDP}
		eps := []netv1.Endpoint{{IP: fakeRelayBackend.Addr().String(), Port: int32(fakeRelayBackend.Port()), Ready: true}}
		if err := p.Reconcile(vip.String(), sp, eps); err != nil {
			t.Fatalf("reconcile udp: %v", err)
		}

		var conn *fakeVIPConn
		select {
		case conn = <-bound:
		case <-time.After(fakeHandledTimeout):
			t.Fatal("the UDP reconcile never bound a VIP datagram socket")
		}
		if conn.local != fakeRelayVIP {
			t.Fatalf("VIP socket bound at %v, want exactly %v", conn.local, fakeRelayVIP)
		}
		// openListener ensures the alias before it binds, and the bind is ordered
		// before this read by the channel, so the count is already final.
		if alias.ensures(vip) == 0 {
			t.Fatalf("UDP relay did not ensure the lo0 alias")
		}

		p.ReconcileDelete(PortKey{ClusterIP: vip.String(), Port: int32(fakeRelayVIP.Port()), Protocol: netv1.ProtocolUDP})
		select {
		case <-conn.done:
		case <-time.After(fakeHandledTimeout):
			t.Fatal("ReconcileDelete did not close the VIP datagram socket")
		}
	})

	t.Run("one flow per client, echoed back to that client", func(t *testing.T) {
		t.Parallel()
		be := newFakeUDPBackend(true)
		relay := newFakeRelay(be, time.Hour, maxUDPFlowsPerSource, newUDPBudget(MaxUDPFlows, MaxUDPFlows))
		vip := relay.conn.(*fakeVIPConn)
		relay.start()
		defer relay.Close()

		client := netip.MustParseAddrPort("10.42.1.7:40000")
		for _, payload := range []string{"hello-udp", "world-udp"} {
			vip.deliver(t, client, payload)
			got := vip.reply(t)
			if string(got.data) != payload || got.addr != client {
				t.Fatalf("reply = %q to %v, want %q to %v", got.data, got.addr, payload, client)
			}
		}

		if d := be.dials(); d != 1 {
			t.Fatalf("relay dialed %d upstreams for one client, want 1 (flow/backend must be reused per client)", d)
		}
		if s := be.flowsSeen(); s != 1 {
			t.Fatalf("backend saw %d flows, want 1", s)
		}
		up := be.upstream(0)
		if up.remote != fakeRelayBackend {
			t.Fatalf("upstream dialed %v, want the Ready backend %v", up.remote, fakeRelayBackend)
		}
		if w := up.wrote(); w != 2 {
			t.Fatalf("upstream carried %d datagrams, want 2", w)
		}

		// Close joins the dispatcher, the sweeper, and the flow's reader (-race
		// proves the join) and closes every socket it owned.
		if err := relay.Close(); err != nil {
			t.Fatalf("relay close: %v", err)
		}
		if !vip.closed() || !up.closed() {
			t.Fatalf("after Close: vip closed=%v upstream closed=%v, want both", vip.closed(), up.closed())
		}
	})
}

// TestUDPRelayIdleFlowGC asserts the relay idle-GCs a flow that falls silent, in
// two phases that are deliberately NOT run against the same relay.
//
// Phase 1 uses a LONG idle timeout so the background sweeper cannot race the
// round trip, and forces the reap through sweepExpired, the seam factored out for
// exactly this, with a clock past the threshold — deterministic, no clock luck.
//
// Phase 2 is what phase 1 gives up: proof that the sweeper GOROUTINE performs that
// reap on its own timer with nobody calling sweepExpired. It seeds a flow
// synchronously through upstreamFor and waits for the sweeper to close that flow's
// upstream. The wait is monotone: load can delay it, never falsify it.
func TestUDPRelayIdleFlowGC(t *testing.T) {
	t.Parallel()

	t.Run("a silent flow is reaped, and its accounting with it", func(t *testing.T) {
		t.Parallel()
		const idle = time.Minute
		be := newFakeUDPBackend(true)
		budget := newUDPBudget(MaxUDPFlows, MaxUDPFlows)
		relay := newFakeRelay(be, idle, maxUDPFlowsPerSource, budget)
		vip := relay.conn.(*fakeVIPConn)
		relay.start()
		defer relay.Close()

		client := netip.MustParseAddrPort("10.42.1.8:40000")
		vip.deliver(t, client, "x")
		if got := vip.reply(t); string(got.data) != "x" {
			t.Fatalf("datagram did not round-trip: got %q", got.data)
		}
		if got := relay.flowCount(); got != 1 {
			t.Fatalf("flow count after first datagram = %d, want 1", got)
		}

		relay.sweepExpired(time.Now().Add(2 * idle))
		if got := relay.flowCount(); got != 0 {
			t.Fatalf("flow count after an expired sweep = %d, want 0", got)
		}
		if !be.upstream(0).closed() {
			t.Fatal("the reaped flow's upstream socket was not closed")
		}
		if n, s := budget.liveTotal(), budget.liveSources(); n != 0 || s != 0 {
			t.Fatalf("after the reap: budgetTotal=%d budgetSources=%d, want 0/0", n, s)
		}
	})

	t.Run("the sweeper goroutine drives the reap on its own timer", func(t *testing.T) {
		t.Parallel()
		const idle = 200 * time.Millisecond
		be := newFakeUDPBackend(true)
		relay := newFakeRelay(be, idle, maxUDPFlowsPerSource, newUDPBudget(MaxUDPFlows, MaxUDPFlows))
		relay.start()
		defer relay.Close()

		var lastWarn time.Time
		if up := relay.upstreamFor(netip.MustParseAddrPort("10.0.5.1:45000"), &lastWarn); up == nil {
			t.Fatal("upstreamFor admitted no flow, so this test would assert nothing")
		}
		// Nobody but the sweeper's timer closes this upstream before relay.Close,
		// which has not run yet.
		select {
		case <-be.upstream(0).done:
		case <-time.After(fakeHandledTimeout):
			t.Fatalf("idle flow was not GC'd by the sweeper: flow count still %d", relay.flowCount())
		}
		// The sweep closes and deletes under one hold of mu, so once the close is
		// visible the delete is too.
		if got := relay.flowCount(); got != 0 {
			t.Fatalf("flow count after the sweeper's reap = %d, want 0", got)
		}
	})
}

// TestUDPRelayPerSourceFairShare is the B48 gate: it proves the per-source
// fair-share sub-cap, the relay-GLOBAL fd budget, second-lock-authoritative
// admission, and PURE counter accounting. It drives upstreamFor DIRECTLY with
// fabricated client addresses (distinct 10.0.0.N source IPs) so the per-source
// counter is exercised without a rootless 127.0.0.2 bind (macOS refuses it). The
// VIP socket and every per-flow upstream are in-memory fakes, so no fd is opened.
//
// Non-vacuity: with the per-source check removed, PerSourceFairShare's "(cap+1)th
// dropped" assertion fails (the extra flow is admitted); with any decrement dropped,
// CounterPurityReturnsToZero leaves a non-zero residue.
func TestUDPRelayPerSourceFairShare(t *testing.T) {
	t.Parallel()

	be := newFakeUDPBackend(true)

	// newRelay builds an UNSTARTED relay (upstreamFor is driven directly, so no
	// dispatcher/sweeper goroutine runs) with the shared echo backend registered and
	// the injected caps. A long idle timeout means only an explicit sweepExpired reaps.
	newRelay := func(budget *udpBudget, perSourceCap int) *udpRelay {
		return newFakeRelay(be, time.Hour, perSourceCap, budget)
	}
	// client fabricates a distinct client address; the per-source counter keys on the
	// parsed IP, decoupled from any socket address.
	client := func(a, b, c, d byte, port int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{a, b, c, d}), uint16(port))
	}

	t.Run("PerSourceFairShare", func(t *testing.T) {
		relay := newRelay(newUDPBudget(100, 100), 2) // budget caps large so the per-VIP per-source cap is the constraint
		defer relay.Close()
		var lastWarn time.Time

		// Source 10.0.0.1 opens perSourceCap (2) flows on distinct ports — all admitted.
		if up := relay.upstreamFor(client(10, 0, 0, 1, 40000), &lastWarn); up == nil {
			t.Fatalf("10.0.0.1 flow 1 dropped, want admitted")
		}
		if up := relay.upstreamFor(client(10, 0, 0, 1, 40001), &lastWarn); up == nil {
			t.Fatalf("10.0.0.1 flow 2 dropped, want admitted")
		}
		// The (cap+1)th from 10.0.0.1 exceeds the per-source cap → DROPPED.
		if up := relay.upstreamFor(client(10, 0, 0, 1, 40002), &lastWarn); up != nil {
			t.Fatalf("10.0.0.1 flow 3 admitted past per-source cap 2 (fair-share not enforced)")
		}
		// A DIFFERENT source is NOT starved by 10.0.0.1's saturation — the core fairness.
		if up := relay.upstreamFor(client(10, 0, 0, 2, 40000), &lastWarn); up == nil {
			t.Fatalf("10.0.0.2 flow starved by 10.0.0.1's saturation (cap is not per-source)")
		}
		if fc, ps := relay.flowCount(), relay.perSourceTotal(); fc != 3 || ps != 3 {
			t.Fatalf("flowCount=%d perSourceTotal=%d, want 3/3 (2 from .1 + 1 from .2)", fc, ps)
		}
	})

	t.Run("GlobalBudgetAcrossVIPs", func(t *testing.T) {
		budget := newUDPBudget(3, 100) // shared by BOTH relays; per-source non-binding so the total is the constraint
		relayA := newRelay(budget, 100)
		defer relayA.Close()
		relayB := newRelay(budget, 100)
		defer relayB.Close()
		var warnA, warnB time.Time

		// 3 flows across the two relays exhaust the shared budget (distinct source IPs
		// so the per-source cap of 100 never interferes — the budget is the constraint).
		if up := relayA.upstreamFor(client(10, 0, 1, 1, 50000), &warnA); up == nil {
			t.Fatalf("relayA flow 1 dropped, want admitted")
		}
		if up := relayA.upstreamFor(client(10, 0, 1, 2, 50000), &warnA); up == nil {
			t.Fatalf("relayA flow 2 dropped, want admitted")
		}
		if up := relayB.upstreamFor(client(10, 0, 1, 3, 50000), &warnB); up == nil {
			t.Fatalf("relayB flow 1 dropped, want admitted")
		}
		// The 4th flow across BOTH relays exceeds the shared global budget → DROPPED.
		if up := relayB.upstreamFor(client(10, 0, 1, 4, 50000), &warnB); up != nil {
			t.Fatalf("relayB flow 2 admitted past shared global budget 3")
		}
		// And on relay A too — the budget is GLOBAL, not per-relay.
		if up := relayA.upstreamFor(client(10, 0, 1, 5, 50000), &warnA); up != nil {
			t.Fatalf("relayA flow 3 admitted past shared global budget 3")
		}
		if n := budget.liveTotal(); n != 3 {
			t.Fatalf("shared budget count = %d, want 3 (2 on A + 1 on B, no overshoot)", n)
		}
	})

	t.Run("SecondLockCounterConsistency", func(t *testing.T) {
		budget := newUDPBudget(100, 100)
		relay := newRelay(budget, 3)
		defer relay.Close()
		var lastWarn time.Time

		// 3 flows from one source (hits its per-source cap exactly), 1 rejected, then 2
		// from a second source: 5 admitted total.
		for p := 0; p < 3; p++ {
			if up := relay.upstreamFor(client(10, 0, 2, 1, 60000+p), &lastWarn); up == nil {
				t.Fatalf("10.0.2.1 flow %d dropped, want admitted", p)
			}
		}
		if up := relay.upstreamFor(client(10, 0, 2, 1, 60003), &lastWarn); up != nil {
			t.Fatalf("10.0.2.1 admitted past per-source cap 3")
		}
		for p := 0; p < 2; p++ {
			if up := relay.upstreamFor(client(10, 0, 2, 2, 60000+p), &lastWarn); up == nil {
				t.Fatalf("10.0.2.2 flow %d dropped, want admitted", p)
			}
		}
		// The three counters move in lockstep at the second-lock insert, so none can
		// diverge and none exceeds the per-VIP MaxUDPFlows.
		fc, ps, b := relay.flowCount(), relay.perSourceTotal(), budget.liveTotal()
		if fc != 5 || ps != 5 || b != 5 {
			t.Fatalf("counter divergence: flowCount=%d perSourceTotal=%d budget=%d, want 5/5/5", fc, ps, b)
		}
		if fc > MaxUDPFlows {
			t.Fatalf("per-VIP flow count %d exceeds MaxUDPFlows %d", fc, MaxUDPFlows)
		}
	})

	t.Run("CounterPurityReturnsToZero", func(t *testing.T) {
		budget := newUDPBudget(100, 100)
		relay := newRelay(budget, 10)
		defer relay.Close()
		var lastWarn time.Time

		// Admit 7 flows across two sources.
		for p := 0; p < 4; p++ {
			if up := relay.upstreamFor(client(10, 0, 3, 1, 61000+p), &lastWarn); up == nil {
				t.Fatalf("10.0.3.1 flow %d dropped, want admitted", p)
			}
		}
		for p := 0; p < 3; p++ {
			if up := relay.upstreamFor(client(10, 0, 3, 2, 61000+p), &lastWarn); up == nil {
				t.Fatalf("10.0.3.2 flow %d dropped, want admitted", p)
			}
		}
		if ps, b, s := relay.perSourceTotal(), budget.liveTotal(), budget.liveSources(); ps != 7 || b != 7 || s != 2 {
			t.Fatalf("after 7 admits: perSourceTotal=%d budgetTotal=%d budgetSources=%d, want 7/7/2", ps, b, s)
		}

		// Idle-sweep path: force every flow past the idle timeout. Symmetric release
		// must return ALL counters to zero — the budget total AND its bySource map.
		relay.sweepExpired(time.Now().Add(time.Hour))
		if fc, ps, b, s := relay.flowCount(), relay.perSourceTotal(), budget.liveTotal(), budget.liveSources(); fc != 0 || ps != 0 || b != 0 || s != 0 {
			t.Fatalf("after sweep: flowCount=%d perSourceTotal=%d budgetTotal=%d budgetSources=%d, want 0/0/0/0 (sweep release must be symmetric — total AND bySource return to zero)", fc, ps, b, s)
		}

		// Close path: admit more, then Close must ALSO return the global budget to zero.
		for p := 0; p < 5; p++ {
			if up := relay.upstreamFor(client(10, 0, 3, 3, 62000+p), &lastWarn); up == nil {
				t.Fatalf("10.0.3.3 flow %d dropped, want admitted", p)
			}
		}
		if b, s := budget.liveTotal(), budget.liveSources(); b != 5 || s != 1 {
			t.Fatalf("after 5 more admits from one source: budgetTotal=%d budgetSources=%d, want 5/1", b, s)
		}
		if err := relay.Close(); err != nil {
			t.Fatalf("relay close: %v", err)
		}
		if b, s := budget.liveTotal(), budget.liveSources(); b != 0 || s != 0 {
			t.Fatalf("after Close: budgetTotal=%d budgetSources=%d, want 0/0 (Close must release every live flow's slot — total AND bySource)", b, s)
		}
	})
}

// TestUDPRelayPerSourceGlobalCap is the B52 gate: it proves the per-source-GLOBAL
// fair share in the shared udpBudget — one source IP is bounded to maxPerSource live
// flows across ALL VIPs, not per VIP, so a pod fanning flows across N distinct UDP
// VIPs cannot consume the whole relay-global budget and starve every other pod on
// every VIP. It drives upstreamFor DIRECTLY on TWO relays (two VIPs) sharing ONE tiny
// budget (maxTotal=8, maxPerSource=2), with fabricated client source IPs, on the
// in-memory VIP and upstream fakes.
//
// Non-vacuity: B48's per-VIP-only per-source cap would let the SAME source IP hold
// maxPerSource flows on EACH VIP (2×maxPerSource across two VIPs); this gate asserts
// the source is capped at maxPerSource TOTAL across both VIPs (the 3rd flow, on either
// VIP, is dropped with rejectPerSourceGlobal), which is RED under a per-VIP-only cap.
// A missing release leaves a positive residue after teardown (return-to-zero fails).
func TestUDPRelayPerSourceGlobalCap(t *testing.T) {
	t.Parallel()

	be := newFakeUDPBackend(true)

	// newRelay builds an UNSTARTED relay (upstreamFor is driven directly) on its own
	// fake VIP socket, sharing the caller's budget, with the echo backend registered and a
	// per-VIP per-source cap (100) high enough that the per-source-GLOBAL budget cap —
	// not the per-VIP one — is the binding constraint. A long idle timeout means only
	// an explicit Close reaps.
	newRelay := func(budget *udpBudget) *udpRelay {
		return newFakeRelay(be, time.Hour, 100, budget)
	}
	client := func(a, b, c, d byte, port int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{a, b, c, d}), uint16(port))
	}

	// One budget shared by BOTH VIPs: total 8 sockets across all relays, and any ONE
	// source IP limited to 2 flows GLOBALLY (across both VIPs). 8/4 == 2, matching the
	// production /4 derivation.
	budget := newUDPBudget(8, 2)
	relayA := newRelay(budget)
	defer relayA.Close()
	relayB := newRelay(budget)
	defer relayB.Close()
	var warnA, warnB time.Time

	// (1) Per-source cap is GLOBAL across VIPs. Source S1 opens ONE flow on VIP-A and
	// ONE on VIP-B — 2 total == maxPerSource, both admitted.
	s1 := netip.MustParseAddr("10.1.0.1")
	if up := relayA.upstreamFor(client(10, 1, 0, 1, 40000), &warnA); up == nil {
		t.Fatalf("S1 flow on VIP-A dropped, want admitted")
	}
	if up := relayB.upstreamFor(client(10, 1, 0, 1, 40001), &warnB); up == nil {
		t.Fatalf("S1 flow on VIP-B dropped, want admitted")
	}
	// The 3rd S1 flow — on EITHER VIP — exceeds the per-source-GLOBAL cap and is
	// dropped, even though neither VIP's own per-source count is at the per-VIP cap
	// (100) and the global total (2) is far below maxTotal (8). Under B48's per-VIP-only
	// cap this 3rd flow would be ADMITTED (S1 has only 1 flow on VIP-A) — the red.
	if up := relayA.upstreamFor(client(10, 1, 0, 1, 40002), &warnA); up != nil {
		t.Fatalf("S1 3rd flow on VIP-A admitted past per-source-GLOBAL cap 2 (cap is per-VIP, not global)")
	}
	if up := relayB.upstreamFor(client(10, 1, 0, 1, 40003), &warnB); up != nil {
		t.Fatalf("S1 3rd flow on VIP-B admitted past per-source-GLOBAL cap 2 (cap is per-VIP, not global)")
	}
	// The reason is per-source-GLOBAL, not a global-total shortage. reserve on refusal
	// is side-effect-free (it mutates nothing before the cap check), so probing it here
	// leaves the budget unchanged.
	if ok, reason := budget.reserve(s1); ok || reason != rejectPerSourceGlobal {
		t.Fatalf("reserve(S1) = (%v, %v), want (false, rejectPerSourceGlobal)", ok, reason)
	}

	// (2) Fair share preserved: a DIFFERENT source S2 still gets its own maxPerSource
	// flows across the two VIPs — one greedy source does not starve others.
	if up := relayA.upstreamFor(client(10, 1, 0, 2, 41000), &warnA); up == nil {
		t.Fatalf("S2 flow on VIP-A starved by S1's saturation, want admitted")
	}
	if up := relayB.upstreamFor(client(10, 1, 0, 2, 41001), &warnB); up == nil {
		t.Fatalf("S2 flow on VIP-B starved by S1's saturation, want admitted")
	}

	// (3) Global-total still bites. Fill maxTotal (8) with more distinct sources: 4
	// live already (S1×2 + S2×2), so S3 and S4 add 2 each → 8 == maxTotal.
	var fillWarn time.Time
	for i, src := range [][4]byte{{10, 1, 0, 3}, {10, 1, 0, 4}} {
		r := relayA
		if i == 1 {
			r = relayB
		}
		if up := r.upstreamFor(client(src[0], src[1], src[2], src[3], 42000), &fillWarn); up == nil {
			t.Fatalf("source %v flow 1 dropped while filling budget, want admitted", src)
		}
		if up := r.upstreamFor(client(src[0], src[1], src[2], src[3], 42001), &fillWarn); up == nil {
			t.Fatalf("source %v flow 2 dropped while filling budget, want admitted", src)
		}
	}
	if n := budget.liveTotal(); n != 8 {
		t.Fatalf("budget total after filling = %d, want 8 (== maxTotal, no overshoot)", n)
	}
	// A brand-new source S5 — under its own per-source cap (0 < 2) — is refused because
	// the GLOBAL total is exhausted, with reason rejectGlobalFull (not per-source).
	if up := relayA.upstreamFor(client(10, 1, 0, 5, 43000), &warnA); up != nil {
		t.Fatalf("S5 flow admitted past exhausted global total 8")
	}
	if ok, reason := budget.reserve(netip.MustParseAddr("10.1.0.5")); ok || reason != rejectGlobalFull {
		t.Fatalf("reserve(S5) = (%v, %v), want (false, rejectGlobalFull)", ok, reason)
	}

	// (4) Return-to-zero (conservation backstop): closing both relays releases every
	// live flow's slot, so total AND bySource return to zero. A missing release-- would
	// leave a positive residue → red.
	if err := relayA.Close(); err != nil {
		t.Fatalf("relayA close: %v", err)
	}
	if err := relayB.Close(); err != nil {
		t.Fatalf("relayB close: %v", err)
	}
	if n, s := budget.liveTotal(), budget.liveSources(); n != 0 || s != 0 {
		t.Fatalf("after closing both relays: budgetTotal=%d budgetSources=%d, want 0/0 (symmetric release must empty total AND bySource)", n, s)
	}
}

// countingDialer wraps a dial func and records how many times it was invoked,
// so a test can assert the relay's first-lock early reject drops a globally-capped new
// flow BEFORE ever paying the connect(2). It is -race safe: count is mutex-guarded.
type countingDialer struct {
	inner func(laddr, raddr *net.UDPAddr) (udpUpstream, error)

	mu    sync.Mutex
	count int
}

// dial records the call then delegates to the wrapped dialer.
func (d *countingDialer) dial(laddr, raddr *net.UDPAddr) (udpUpstream, error) {
	d.mu.Lock()
	d.count++
	d.mu.Unlock()
	return d.inner(laddr, raddr)
}

// calls reports how many times dial was invoked.
func (d *countingDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.count
}

// TestUDPRelayFirstLockPerSourceGlobalReject is the B54 gate: it proves the first-lock
// early reject now PEEKS the shared budget (peekAtCap) so a new flow whose source is
// already at its per-source-GLOBAL share, OR whose budget is fd-full, is dropped BEFORE
// the Pick+dial — not after a wasted connect(2)+Close at the authoritative second lock.
// It drives upstreamFor DIRECTLY with a fabricated client source and an injected
// counting dialer, asserting the dial counter stays at ZERO for a globally-capped
// source.
//
// Non-vacuity: the "not capped" subtest reaches r.dial (count == 1), so a blanket
// reject would fail it; without the peek the two capped subtests would dial once each
// (the second lock rejects, but only AFTER the connect) — RED before B54.
func TestUDPRelayFirstLockPerSourceGlobalReject(t *testing.T) {
	t.Parallel()

	be := newFakeUDPBackend(true)

	client := func(a, b, c, d byte, port int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{a, b, c, d}), uint16(port))
	}

	// newRelay builds an UNSTARTED relay (upstreamFor is driven directly) on its own fake
	// VIP socket, sharing the caller's budget, with a per-VIP per-source cap (100) high
	// enough that ONLY the shared budget's caps bind. It injects a counting dialer that
	// wraps the fake backend's dial, so a not-capped flow dials once and a capped flow
	// never dials. A long idle timeout means only explicit Close reaps.
	newRelay := func(budget *udpBudget) (*udpRelay, *countingDialer) {
		r := newFakeRelay(be, time.Hour, 100, budget)
		cd := &countingDialer{inner: r.dial}
		r.dial = cd.dial
		return r, cd
	}

	cases := []struct {
		name string
		// budget builds the shared budget; preReserve reserves these sources directly
		// (via budget.reserve) to pre-load bySource/total to the capped state under test.
		budget     func() *udpBudget
		preReserve []netip.Addr
		src        netip.AddrPort // the NEW-flow client the subtest drives upstreamFor with
		srcIP      netip.Addr     // its parsed source IP (for the peek-reason assertion)
		wantAdmit  bool           // true → reaches r.dial (count 1, non-nil); false → early reject (count 0, nil)
		wantReason udpRejectReason
	}{
		{
			// S1 is at its per-source-GLOBAL cap (2) across VIPs but UNDER the per-VIP cap
			// (100) and the global total is far below maxTotal — only the per-source-GLOBAL
			// peek can reject it, and it must, before the dial.
			name:       "per-source-global capped → no dial",
			budget:     func() *udpBudget { return newUDPBudget(100, 2) },
			preReserve: []netip.Addr{netip.MustParseAddr("10.4.0.1"), netip.MustParseAddr("10.4.0.1")},
			src:        client(10, 4, 0, 1, 40000),
			srcIP:      netip.MustParseAddr("10.4.0.1"),
			wantAdmit:  false,
			wantReason: rejectPerSourceGlobal,
		},
		{
			// The global fd total is exhausted (2 reserved == maxTotal 2). A brand-new
			// source — under its own per-source cap — is early-rejected with rejectGlobalFull
			// before the dial.
			name:       "global-fd full → no dial",
			budget:     func() *udpBudget { return newUDPBudget(2, 100) },
			preReserve: []netip.Addr{netip.MustParseAddr("10.4.1.1"), netip.MustParseAddr("10.4.1.2")},
			src:        client(10, 4, 1, 9, 40000),
			srcIP:      netip.MustParseAddr("10.4.1.9"),
			wantAdmit:  false,
			wantReason: rejectGlobalFull,
		},
		{
			// A source under ALL caps reaches r.dial (count 1, non-nil) — the non-vacuous
			// negative proving the peek is not a blanket reject.
			name:       "not capped → dials",
			budget:     func() *udpBudget { return newUDPBudget(100, 100) },
			preReserve: nil,
			src:        client(10, 4, 2, 1, 40000),
			srcIP:      netip.MustParseAddr("10.4.2.1"),
			wantAdmit:  true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			budget := tc.budget()
			for _, s := range tc.preReserve {
				if ok, _ := budget.reserve(s); !ok {
					t.Fatalf("pre-reserve %v failed", s)
				}
			}
			relay, cd := newRelay(budget)
			defer relay.Close()
			var lastWarn time.Time

			up := relay.upstreamFor(tc.src, &lastWarn)

			if tc.wantAdmit {
				if up == nil {
					t.Fatalf("flow dropped, want admitted (peek must not blanket-reject an under-cap source)")
				}
				if n := cd.calls(); n != 1 {
					t.Fatalf("dial count = %d, want 1 (an admitted flow dials exactly once)", n)
				}
				return
			}

			// Capped: the flow is early-rejected and the dial is NEVER paid.
			if up != nil {
				t.Fatalf("flow admitted, want early-rejected at the first lock")
			}
			if n := cd.calls(); n != 0 {
				t.Fatalf("dial count = %d, want 0 (a globally-capped source must be dropped BEFORE the dial)", n)
			}
			// The two regimes are distinguished by the peek's reason, which routes the
			// throttled Warn (per-source-global vs global-fd). peekAtCap is read-only, so
			// probing it here does not perturb the budget.
			if atCap, reason := budget.peekAtCap(tc.srcIP); !atCap || reason != tc.wantReason {
				t.Fatalf("peekAtCap(%v) = (%v, %v), want (true, %v)", tc.srcIP, atCap, reason, tc.wantReason)
			}
		})
	}
}

// TestUDPRelayFlowKey pins the canonical flow key: a 4-in-6 and a plain v4 form of
// one client map to one key, so they share one flow and one fair-share bucket. The
// table covers the pure function; the subtest drives upstreamFor with both forms of
// one client through flowKey (the precondition dispatch establishes) and counts.
//
// Non-vacuity: the last subtest feeds upstreamFor the raw pair and gets two flows in
// two buckets — that split is exactly what flowKey exists to prevent.
func TestUDPRelayFlowKey(t *testing.T) {
	t.Parallel()

	v4 := netip.MustParseAddrPort("10.0.7.1:40000")
	mapped := netip.AddrPortFrom(netip.AddrFrom16(v4.Addr().As16()), v4.Port()) // ::ffff:10.0.7.1
	v6 := netip.MustParseAddrPort("[fd00::7]:40000")
	if !mapped.Addr().Is4In6() {
		t.Fatalf("fixture is not 4-in-6: %v", mapped)
	}
	for _, tc := range []struct {
		name string
		in   netip.AddrPort
		want netip.AddrPort
	}{
		{"plain v4 is already canonical", v4, v4},
		{"4-in-6 unmaps to its v4", mapped, v4},
		{"native v6 is untouched", v6, v6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := flowKey(tc.in); got != tc.want {
				t.Fatalf("flowKey(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	be := newFakeUDPBackend(true)
	newRelay := func(t *testing.T) *udpRelay {
		t.Helper()
		r := newFakeRelay(be, time.Hour, maxUDPFlowsPerSource, newUDPBudget(MaxUDPFlows, MaxUDPFlows))
		t.Cleanup(func() { _ = r.Close() })
		return r
	}

	t.Run("both forms of one client share one flow and one bucket", func(t *testing.T) {
		relay := newRelay(t)
		var lastWarn time.Time
		for _, c := range []netip.AddrPort{v4, mapped} {
			if up := relay.upstreamFor(flowKey(c), &lastWarn); up == nil {
				t.Fatalf("upstreamFor(%v) dropped, want admitted", c)
			}
		}
		if fc, ps := relay.flowCount(), relay.perSourceTotal(); fc != 1 || ps != 1 {
			t.Fatalf("flows=%d perSource=%d after both forms of one client, want 1/1", fc, ps)
		}
	})
	t.Run("the raw pair splits, so the precondition is load-bearing", func(t *testing.T) {
		relay := newRelay(t)
		var lastWarn time.Time
		for _, c := range []netip.AddrPort{v4, mapped} {
			if up := relay.upstreamFor(c, &lastWarn); up == nil {
				t.Fatalf("upstreamFor(%v) dropped, want admitted", c)
			}
		}
		if fc, ps := relay.flowCount(), relay.perSourceTotal(); fc != 2 || ps != 2 {
			t.Fatalf("flows=%d perSource=%d for the uncanonicalized pair, want 2/2", fc, ps)
		}
	})
}

// TestUDPRelayFoundFlowStampedUnderLock pins the found-flow ordering in
// upstreamFor: the activity stamp lands inside the mu critical section, so the
// sweeper — which decides under the same mu — can never reap a flow between the
// dispatcher's lookup and its stamp. With the stamp moved after Unlock, a sweep in
// that gap closes the upstream and the dispatcher writes to a dead socket.
//
// The loop provokes exactly that interleave: a sweeper spinning on mu with a clock
// that expires only a stale stamp, against a dispatcher that re-stales one flow and
// re-finds it. Every socket upstreamFor hands back must still accept a write; a
// flow the sweeper legitimately reaped while stale is simply re-dialed, so the only
// way a write fails is the gap.
func TestUDPRelayFoundFlowStampedUnderLock(t *testing.T) {
	t.Parallel()

	be := newFakeUDPBackend(true)
	const idle = time.Hour
	relay := newFakeRelay(be, idle, maxUDPFlowsPerSource, newUDPBudget(MaxUDPFlows, MaxUDPFlows))
	defer relay.Close()

	client := netip.MustParseAddrPort("10.0.8.1:40000")
	// A clock at which a stale stamp (0: the epoch) has idled past the timeout and a
	// fresh one (time.Since(epoch), microseconds at least) has not.
	expired := relay.epoch.Add(idle + 1)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				relay.sweepExpired(expired)
			}
		}
	}()
	defer wg.Wait()
	defer close(stop)

	var lastWarn time.Time
	for i := 0; i < 20000; i++ {
		relay.mu.Lock()
		if fl := relay.flows[client]; fl != nil {
			fl.lastActivity.Store(0) // stale: reapable until the dispatcher re-stamps it
		}
		relay.mu.Unlock()
		up := relay.upstreamFor(client, &lastWarn)
		if up == nil {
			t.Fatalf("iteration %d: upstreamFor dropped the datagram", i)
		}
		if _, err := up.Write([]byte("x")); err != nil {
			t.Fatalf("iteration %d: upstreamFor returned a socket the sweeper had closed: %v", i, err)
		}
	}
}

// TestUDPFlowBudgetFor pins the exported budget rule: half of
// min(soft RLIMIT_NOFILE, kern.maxfilesperproc), floored at MaxUDPFlows, with a
// zero maxfilesperproc treated as unknown.
func TestUDPFlowBudgetFor(t *testing.T) {
	cases := []struct {
		name            string
		cur, maxPerProc uint64
		want            int64
	}{
		{name: "64 GB host, rlimit binds", cur: 131072, maxPerProc: 245760, want: 65536},
		{name: "8 GB host, kernel cap binds below the floor", cur: 131072, maxPerProc: 10240, want: 8192},
		{name: "kernel cap binds above the floor", cur: 131072, maxPerProc: 32768, want: 16384},
		{name: "unknown kernel cap, rlimit alone", cur: 131072, maxPerProc: 0, want: 65536},
		{name: "floor wins at the boundary", cur: 16384, maxPerProc: 0, want: 8192},
		{name: "zero limits take the floor", cur: 0, maxPerProc: 0, want: 8192},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UDPFlowBudgetFor(tc.cur, tc.maxPerProc); got != tc.want {
				t.Fatalf("UDPFlowBudgetFor(%d, %d) = %d, want %d", tc.cur, tc.maxPerProc, got, tc.want)
			}
		})
	}
}
