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

// udpEchoBackend is a loopback UDP echo server standing in for a pod backend: it
// echoes every datagram back to its sender and records each distinct source it
// observed. Because the relay opens ONE connected upstream socket per client flow,
// the count of distinct observed sources equals the number of flows — so the test
// can assert a single client's datagrams were relayed through one flow (Pick called
// once), not re-picked per datagram.
type udpEchoBackend struct {
	conn net.PacketConn
	wg   sync.WaitGroup

	mu   sync.Mutex
	srcs map[string]int
}

// newUDPEchoBackend stands up the echo server on 127.0.0.1 and starts its read
// loop. Close stops it.
func newUDPEchoBackend(t *testing.T) *udpEchoBackend {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo backend: %v", err)
	}
	b := &udpEchoBackend{conn: pc, srcs: make(map[string]int)}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return // closed
			}
			b.mu.Lock()
			b.srcs[addr.String()]++
			b.mu.Unlock()
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return b
}

// addrPort returns the backend's listen IP and port for registration as an
// endpoint.
func (b *udpEchoBackend) addrPort() (string, int32) {
	ap := b.conn.LocalAddr().(*net.UDPAddr)
	return ap.IP.String(), int32(ap.Port)
}

// uniqueSrcs reports how many distinct upstream sources the backend observed.
func (b *udpEchoBackend) uniqueSrcs() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.srcs)
}

// close stops the echo server and joins its goroutine.
func (b *udpEchoBackend) close() {
	_ = b.conn.Close()
	b.wg.Wait()
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

// TestUDPDatagramRelayRoundTrip is the B23 gate: a ClusterIP UDP Service relays a
// client datagram to a Ready backend and the echoed payload round-trips back. It
// drives the full Proxy reconcile path (so openListener builds the relay) with the
// rootless noop alias manager and a 127.0.0.1 VIP on a free high port, exactly as
// the TCP proxy tests do. On main the UDP path opens no datagram socket, so this
// round-trip cannot complete — that is the red-before.
//
// It also asserts a second datagram from the SAME client reuses the SAME
// flow/backend (the backend observes a single upstream source), proving the relay
// picks a backend once per flow rather than per datagram.
func TestUDPDatagramRelayRoundTrip(t *testing.T) {
	t.Parallel()
	const vip = "127.0.0.1"

	be := newUDPEchoBackend(t)
	defer be.close()
	beIP, bePort := be.addrPort()

	// 127/8 is real on loopback, so the relay binds the specific VIP with no alias
	// or privilege; freePort returns an ephemeral (>=1024) port.
	port := freePort(t, vip)
	alias := newNoopAliasManager()
	tbl := NewRoutingTable(netip.Prefix{})
	p := New(tbl, withAliasManager(alias))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	sp := &netv1.ServicePort{Port: port, TargetPort: bePort, Protocol: netv1.ProtocolUDP}
	eps := []netv1.Endpoint{{IP: beIP, Port: bePort, Ready: true}}
	if err := p.Reconcile(vip, sp, eps); err != nil {
		t.Fatalf("reconcile udp: %v", err)
	}

	key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolUDP}
	waitBackends(t, tbl, key, 1)

	vipAddr := &net.UDPAddr{IP: net.ParseIP(vip), Port: int(port)}
	c, err := net.DialUDP("udp", nil, vipAddr)
	if err != nil {
		t.Fatalf("dial vip udp: %v", err)
	}
	defer c.Close()

	// Phase 1: establish the flow and round-trip the first payload, tolerating the
	// brief window before the relay's datagram socket is bound (a datagram sent too
	// early is dropped / ICMP-refused). Every send is from the same client socket,
	// so they all map to one flow once the relay is up.
	const first = "hello-udp"
	if got := udpRoundTripRetry(t, c, first, 3*time.Second); got != first {
		t.Fatalf("first datagram did not round-trip: got %q, want %q", got, first)
	}

	// Phase 2: the relay is up; a second datagram from the SAME client must reuse the
	// SAME flow (one Pick, one connected upstream socket), not open a new one.
	const second = "world-udp"
	if got := udpRoundTrip(t, c, second, 2*time.Second); got != second {
		t.Fatalf("second datagram round-trip: got %q, want %q", got, second)
	}

	// The backend observed every relayed datagram from a SINGLE upstream source
	// socket — proof the relay picked a backend once per flow and reused the
	// connected upstream socket rather than re-picking per datagram.
	if u := be.uniqueSrcs(); u != 1 {
		t.Fatalf("backend saw %d distinct upstream sources, want 1 (flow/backend must be reused per client)", u)
	}

	// The relay ensured the lo0 alias for the VIP, like the TCP path.
	if alias.ensures(netip.MustParseAddr(vip)) == 0 {
		t.Fatalf("UDP relay did not ensure the lo0 alias")
	}

	// Teardown via the per-port delete (relay.Close) then full shutdown; both join
	// the relay's goroutines leak-free (-race proves it).
	p.ReconcileDelete(key)
	cancel()
	<-runDone
}

// TestUDPRelayIdleFlowGC asserts the relay idle-GCs a flow that falls silent, in
// two phases that are deliberately NOT run against the same relay.
//
// Phase 1 uses a LONG idle timeout. With a short one the background sweeper races
// the in-flight reply: it reaps the flow — closing the upstream socket, killing
// that flow's reader — before the echo comes back, and the round-trip times out
// through no fault of the relay. That is what a loaded box does to a 200ms idle
// window, and it is the failure captured under B207. A GC test must not make its
// own round-trip the thing being GC'd. The reap is then forced through
// sweepExpired, the seam factored out for exactly this, with a clock past the
// threshold — deterministic, no polling, no clock luck.
//
// Phase 2 is what phase 1 gives up: proof that the sweeper GOROUTINE performs that
// reap on its own timer with nobody calling sweepExpired. It seeds a flow
// synchronously through upstreamFor (a non-nil return IS the proof the flow
// existed) and then asserts only that the count reaches zero. That claim is
// monotone: load can delay it, never falsify it, and a reap that beats the first
// observation is a pass, not a flake.
func TestUDPRelayIdleFlowGC(t *testing.T) {
	t.Parallel()

	be := newUDPEchoBackend(t)
	defer be.close()
	beIP, bePort := be.addrPort()

	newRelay := func(t *testing.T, idle time.Duration) *udpRelay {
		t.Helper()
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen vip udp: %v", err)
		}
		vipAddr := pc.LocalAddr().(*net.UDPAddr)
		key := PortKey{ClusterIP: "127.0.0.1", Port: int32(vipAddr.Port), Protocol: netv1.ProtocolUDP}
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.SetEndpoints(key, []netv1.Endpoint{{IP: beIP, Port: bePort, Ready: true}})
		r := newUDPRelay(pc, key, tbl, netip.Addr{}, idle, maxUDPFlowsPerSource, newUDPBudget(maxUDPFlows, maxUDPFlows), slog.Default())
		r.start()
		t.Cleanup(func() { _ = r.Close() })
		return r
	}

	t.Run("a silent flow is reaped, and its accounting with it", func(t *testing.T) {
		const idle = time.Minute
		relay := newRelay(t, idle)

		c, err := net.DialUDP("udp", nil, relay.conn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatalf("dial vip udp: %v", err)
		}
		defer c.Close()

		// The VIP socket is bound before this write, so the datagram is queued rather
		// than dropped; the budget is a liveness backstop for a starved dispatcher,
		// not a performance measurement.
		if got := udpRoundTrip(t, c, "x", 10*time.Second); got != "x" {
			t.Fatalf("datagram did not round-trip: got %q", got)
		}
		if got := relay.flowCount(); got != 1 {
			t.Fatalf("flow count after first datagram = %d, want 1", got)
		}

		relay.sweepExpired(time.Now().Add(2 * idle))
		if got := relay.flowCount(); got != 0 {
			t.Fatalf("flow count after an expired sweep = %d, want 0", got)
		}
	})

	t.Run("the sweeper goroutine drives the reap on its own timer", func(t *testing.T) {
		const idle = 200 * time.Millisecond
		relay := newRelay(t, idle)

		var lastWarn time.Time
		if up := relay.upstreamFor(&net.UDPAddr{IP: net.IPv4(10, 0, 5, 1), Port: 45000}, &lastWarn); up == nil {
			t.Fatal("upstreamFor admitted no flow, so this test would assert nothing")
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if relay.flowCount() == 0 {
				return // the sweeper's own timer reaped it
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("idle flow was not GC'd by the sweeper: flow count still %d", relay.flowCount())
	})
}

// TestUDPRelayPerSourceFairShare is the B48 gate: it proves the per-source
// fair-share sub-cap, the relay-GLOBAL fd budget, second-lock-authoritative
// admission, and PURE counter accounting. It drives upstreamFor DIRECTLY with
// fabricated client addresses (distinct 10.0.0.N source IPs) so the per-source
// counter is exercised without a rootless 127.0.0.2 bind (macOS refuses it); only
// the per-flow upstream DialUDP to a real loopback echo backend is a live fd,
// bounded by the tiny injected caps.
//
// Non-vacuity: with the per-source check removed, PerSourceFairShare's "(cap+1)th
// dropped" assertion fails (the extra flow is admitted); with any decrement dropped,
// CounterPurityReturnsToZero leaves a non-zero residue.
func TestUDPRelayPerSourceFairShare(t *testing.T) {
	t.Parallel()

	be := newUDPEchoBackend(t)
	defer be.close()
	beIP, bePort := be.addrPort()

	// newRelay builds an UNSTARTED relay (upstreamFor is driven directly, so no
	// dispatcher/sweeper goroutine runs) with the shared echo backend registered and
	// the injected caps. A long idle timeout means only an explicit sweepExpired reaps.
	newRelay := func(budget *udpBudget, perSourceCap int) *udpRelay {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen vip udp: %v", err)
		}
		vipAddr := pc.LocalAddr().(*net.UDPAddr)
		key := PortKey{ClusterIP: "127.0.0.1", Port: int32(vipAddr.Port), Protocol: netv1.ProtocolUDP}
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.SetEndpoints(key, []netv1.Endpoint{{IP: beIP, Port: bePort, Ready: true}})
		return newUDPRelay(pc, key, tbl, netip.Addr{}, time.Hour, perSourceCap, budget, slog.Default())
	}
	// client fabricates a distinct client address; the per-source counter keys on the
	// parsed IP, decoupled from any real loopback bind.
	client := func(a, b, c, d byte, port int) net.Addr {
		return &net.UDPAddr{IP: net.IPv4(a, b, c, d), Port: port}
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
		// diverge and none exceeds the per-VIP maxUDPFlows.
		fc, ps, b := relay.flowCount(), relay.perSourceTotal(), budget.liveTotal()
		if fc != 5 || ps != 5 || b != 5 {
			t.Fatalf("counter divergence: flowCount=%d perSourceTotal=%d budget=%d, want 5/5/5", fc, ps, b)
		}
		if fc > maxUDPFlows {
			t.Fatalf("per-VIP flow count %d exceeds maxUDPFlows %d", fc, maxUDPFlows)
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
// budget (maxTotal=8, maxPerSource=2), with fabricated client source IPs, so only the
// per-flow upstream DialUDP to a real loopback echo backend is a live fd.
//
// Non-vacuity: B48's per-VIP-only per-source cap would let the SAME source IP hold
// maxPerSource flows on EACH VIP (2×maxPerSource across two VIPs); this gate asserts
// the source is capped at maxPerSource TOTAL across both VIPs (the 3rd flow, on either
// VIP, is dropped with rejectPerSourceGlobal), which is RED under a per-VIP-only cap.
// A missing release leaves a positive residue after teardown (return-to-zero fails).
func TestUDPRelayPerSourceGlobalCap(t *testing.T) {
	t.Parallel()

	be := newUDPEchoBackend(t)
	defer be.close()
	beIP, bePort := be.addrPort()

	// newRelay builds an UNSTARTED relay (upstreamFor is driven directly) on its own
	// VIP socket, sharing the caller's budget, with the echo backend registered and a
	// per-VIP per-source cap (100) high enough that the per-source-GLOBAL budget cap —
	// not the per-VIP one — is the binding constraint. A long idle timeout means only
	// an explicit Close reaps.
	newRelay := func(budget *udpBudget) *udpRelay {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen vip udp: %v", err)
		}
		vipAddr := pc.LocalAddr().(*net.UDPAddr)
		key := PortKey{ClusterIP: "127.0.0.1", Port: int32(vipAddr.Port), Protocol: netv1.ProtocolUDP}
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.SetEndpoints(key, []netv1.Endpoint{{IP: beIP, Port: bePort, Ready: true}})
		return newUDPRelay(pc, key, tbl, netip.Addr{}, time.Hour, 100, budget, slog.Default())
	}
	client := func(a, b, c, d byte, port int) net.Addr {
		return &net.UDPAddr{IP: net.IPv4(a, b, c, d), Port: port}
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

// countingDialer wraps a real dial func and records how many times it was invoked,
// so a test can assert the relay's first-lock early reject drops a globally-capped new
// flow BEFORE ever paying the connect(2). It is -race safe: count is mutex-guarded.
type countingDialer struct {
	inner func(laddr, raddr *net.UDPAddr) (*net.UDPConn, error)

	mu    sync.Mutex
	count int
}

// dial records the call then delegates to the wrapped dialer.
func (d *countingDialer) dial(laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
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

	be := newUDPEchoBackend(t)
	defer be.close()
	beIP, bePort := be.addrPort()

	client := func(a, b, c, d byte, port int) net.Addr {
		return &net.UDPAddr{IP: net.IPv4(a, b, c, d), Port: port}
	}

	// newRelay builds an UNSTARTED relay (upstreamFor is driven directly) on its own VIP
	// socket, sharing the caller's budget, with a per-VIP per-source cap (100) high
	// enough that ONLY the shared budget's caps bind. It injects a counting dialer that
	// wraps net.DialUDP to a real loopback echo backend, so a not-capped flow dials once
	// and a capped flow never dials. A long idle timeout means only explicit Close reaps.
	newRelay := func(budget *udpBudget) (*udpRelay, *countingDialer) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen vip udp: %v", err)
		}
		vipAddr := pc.LocalAddr().(*net.UDPAddr)
		key := PortKey{ClusterIP: "127.0.0.1", Port: int32(vipAddr.Port), Protocol: netv1.ProtocolUDP}
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.SetEndpoints(key, []netv1.Endpoint{{IP: beIP, Port: bePort, Ready: true}})
		r := newUDPRelay(pc, key, tbl, netip.Addr{}, time.Hour, 100, budget, slog.Default())
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
		src        net.Addr   // the NEW-flow client the subtest drives upstreamFor with
		srcIP      netip.Addr // its parsed source IP (for the peek-reason assertion)
		wantAdmit  bool       // true → reaches r.dial (count 1, non-nil); false → early reject (count 0, nil)
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

// udpRoundTrip sends payload on the connected UDP socket c and returns the reply
// read back within timeout. It fails the test on a write/read error.
func udpRoundTrip(t *testing.T, c *net.UDPConn, payload string, timeout time.Duration) string {
	t.Helper()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, maxUDPDatagram)
	// Skip datagrams that echo an EARLIER payload. UDP has no request/reply
	// correlation, and udpRoundTripRetry deliberately re-sends its payload until one
	// reply arrives — so a slow relay can leave extra echoes of the previous phase
	// queued on this socket. Reading the first datagram unconditionally attributes a
	// stale echo to this send (B207: "got \"hello-udp\", want \"world-udp\"").
	// A genuinely wrong reply still fails, on the deadline, naming what was seen.
	var last string
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read reply for %q: %v (last datagram %q)", payload, err, last)
		}
		last = string(buf[:n])
		if last == payload {
			return last
		}
		t.Logf("skipping stale echo %q while awaiting %q", last, payload)
	}
	t.Fatalf("no reply matching %q within %v (last datagram %q)", payload, timeout, last)
	return ""
}

// udpRoundTripRetry repeatedly sends payload until it reads a reply or the overall
// deadline expires, returning the last reply (empty on timeout). It absorbs the
// startup window in which the relay's datagram socket is not yet bound (early
// datagrams are dropped / ICMP-refused) without giving up. All sends use the same
// socket, so they map to one relay flow.
func udpRoundTripRetry(t *testing.T, c *net.UDPConn, payload string, overall time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(overall)
	buf := make([]byte, maxUDPDatagram)
	for time.Now().Before(deadline) {
		if _, err := c.Write([]byte(payload)); err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			continue // relay not up yet (timeout or ICMP refused) → retry
		}
		// NOTE: every retry that timed out may still have been relayed, so its echo
		// can be in flight behind this one. Those duplicates are the caller's problem
		// to skip — udpRoundTrip does, by matching the payload.
		return string(buf[:n])
	}
	return ""
}
