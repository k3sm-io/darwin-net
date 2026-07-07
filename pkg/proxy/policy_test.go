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
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// policyTestTimeout bounds every blocking read in the M10.4 gate so a regression
// hangs the subtest for at most this long instead of wedging the suite.
const policyTestTimeout = 5 * time.Second

// fakeSrcConn wraps a net.Conn (one end of a net.Pipe) overriding RemoteAddr, so
// p.handle sees a chosen pod source IP: unit tests cannot originate real
// connections from arbitrary pod /32s, and a real loopback dial would collapse
// every source into the always-allowed 127.0.0.1.
type fakeSrcConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeSrcConn) RemoteAddr() net.Addr { return c.remote }

// tcpBanner is a loopback TCP server standing in for a pod backend: it writes a
// one-line banner to every accepted connection and closes it, counting accepts so
// a test can assert a denied connection never reached the backend.
type tcpBanner struct {
	ln      net.Listener
	accepts atomic.Int32
	done    chan struct{}
}

// newTCPBanner listens on addr ("127.0.0.1:0" or "[::1]:0" — the two loopback
// addresses bindable on Darwin without an lo0 alias, giving tests two DISTINCT
// backend pod IPs) and serves the banner until closed.
func newTCPBanner(t *testing.T, addr string) *tcpBanner {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen banner backend %s: %v", addr, err)
	}
	b := &tcpBanner{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepts.Add(1)
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-b.done
	})
	return b
}

// addrPort returns the backend's bound address as a netip.AddrPort.
func (b *tcpBanner) addrPort() netip.AddrPort {
	return b.ln.Addr().(*net.TCPAddr).AddrPort()
}

// endpoint returns the backend as a Ready netv1.Endpoint for the routing table.
func (b *tcpBanner) endpoint() netv1.Endpoint {
	ap := b.addrPort()
	return netv1.Endpoint{IP: ap.Addr().String(), Port: int32(ap.Port()), Ready: true}
}

// handleVIP drives ONE VIP-mediated connection through the real TCP accept path
// (p.handle, internal scope) with a forged pod source IP, and reports whether it
// reached a backend (read the banner) or was refused (closed with no data — the
// deny shape AND the no-backend shape; the caller disambiguates via backend
// accept counts).
func handleVIP(t *testing.T, p *Proxy, key PortKey, src netip.Addr) bool {
	t.Helper()
	clientEnd, proxyEnd := net.Pipe()
	defer clientEnd.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handle(fakeSrcConn{Conn: proxyEnd, remote: &net.TCPAddr{IP: src.AsSlice(), Port: 34567}}, key, internalListener)
	}()
	_ = clientEnd.SetReadDeadline(time.Now().Add(policyTestTimeout))
	buf := make([]byte, 2)
	_, err := io.ReadFull(clientEnd, buf)
	got := err == nil && string(buf) == "ok"
	_ = clientEnd.Close()
	<-done
	return got
}

// newPolicyProxy builds a rootless Proxy over a fresh routing table with the
// given policy table wired (no Run, no sockets: the tests drive p.handle
// directly, so no alias manager or listener is ever touched). The logger is
// discarded — the throttled deny Info is asserted separately via a capture
// handler, not scraped from test output.
func newPolicyProxy(pt *PolicyTable) (*Proxy, *RoutingTable) {
	table := NewRoutingTable(netip.Prefix{})
	return New(table, WithPolicyTable(pt), WithLogger(slog.New(slog.DiscardHandler))), table
}

// podIPSet builds a known-pod-IP attribution set.
func podIPSet(addrs ...netip.Addr) map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		out[a] = struct{}{}
	}
	return out
}

// TestNetworkPolicyL4AllowDeny is the M10.4 acceptance gate (M10.4-a1): the
// NetworkPolicy L4 subset's allow/deny verdict is applied at the userspace-proxy
// seam AFTER the backend pick — an allowed source reaches its backend, a denied
// source is refused — per (source, picked-backend pod IP, backend port), with the
// binding's always-allow/fail-open semantics and the honest bypass ceiling
// asserted. Non-vacuous: every allow subtest is paired with a deny on the same
// mechanism.
func TestNetworkPolicyL4AllowDeny(t *testing.T) {
	t.Parallel()

	srcA := netip.MustParseAddr("10.42.0.10")
	srcB := netip.MustParseAddr("10.42.0.11")

	t.Run("a: selected backend default-denies unlisted sources; unselected backend allows", func(t *testing.T) {
		t.Parallel()
		p4 := newTCPBanner(t, "127.0.0.1:0") // backend pod P (policy-selected)
		q6 := newTCPBanner(t, "[::1]:0")     // backend pod Q (unselected)

		pt := NewPolicyTable()
		pt.Update(map[netip.Addr][]PolicyRule{
			p4.addrPort().Addr(): {{Sources: podIPSet(srcA)}}, // from: srcA only, all ports
		}, podIPSet(srcA, srcB))

		p, table := newPolicyProxy(pt)
		keyP := PortKey{ClusterIP: "10.43.1.1", Port: 80, Protocol: netv1.ProtocolTCP}
		keyQ := PortKey{ClusterIP: "10.43.1.2", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(keyP, []netv1.Endpoint{p4.endpoint()})
		table.SetEndpoints(keyQ, []netv1.Endpoint{q6.endpoint()})

		if !handleVIP(t, p, keyP, srcA) {
			t.Errorf("A->VIP(P): allowed source must reach the selected backend")
		}
		if handleVIP(t, p, keyP, srcB) {
			t.Errorf("B->VIP(P): unlisted source must be REFUSED by the selected backend's policy")
		}
		if got := p4.accepts.Load(); got != 1 {
			t.Errorf("selected backend accepts = %d, want 1 (the denied connection must never be dialed)", got)
		}
		if !handleVIP(t, p, keyQ, srcB) {
			t.Errorf("B->VIP(Q): a backend NO policy selects must default-allow")
		}
	})

	t.Run("b: one Service fronting policy-heterogeneous pods — verdict follows the PICKED backend", func(t *testing.T) {
		t.Parallel()
		q6 := newTCPBanner(t, "[::1]:0") // unselected, dialable
		// P is a selected, DENIED backend that is never dialed, so it needs no
		// listener; its v4 address sorts before Q's v6 one, fixing round-robin order.
		pAddr := netip.MustParseAddr("10.42.0.5")

		pt := NewPolicyTable()
		pt.Update(map[netip.Addr][]PolicyRule{
			pAddr: {{Sources: podIPSet(srcA)}},
		}, podIPSet(srcA, srcB))

		p, table := newPolicyProxy(pt)
		key := PortKey{ClusterIP: "10.43.1.3", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{
			{IP: pAddr.String(), Port: 9999, Ready: true},
			q6.endpoint(),
		})

		// Fresh table → cursor 0: pick 1 = P (v4 sorts first) → denied for srcB;
		// pick 2 = Q → allowed. Same source, same VIP, opposite verdicts: the
		// verdict is per PICKED backend, never per Service.
		if handleVIP(t, p, key, srcB) {
			t.Errorf("pick 1 (selected backend P): srcB must be refused")
		}
		if !handleVIP(t, p, key, srcB) {
			t.Errorf("pick 2 (unselected backend Q): srcB must pass on the SAME VIP")
		}
	})

	t.Run("c: ports — wrong backend port refused, right port passes", func(t *testing.T) {
		t.Parallel()
		b1 := newTCPBanner(t, "127.0.0.1:0")
		b2 := newTCPBanner(t, "127.0.0.1:0")

		pt := NewPolicyTable()
		pt.Update(map[netip.Addr][]PolicyRule{
			// Both banner backends share the pod IP 127.0.0.1; the policy allows srcA
			// on b1's port only.
			b1.addrPort().Addr(): {{Sources: podIPSet(srcA), Ports: map[uint16]struct{}{b1.addrPort().Port(): {}}}},
		}, podIPSet(srcA))

		p, table := newPolicyProxy(pt)
		key1 := PortKey{ClusterIP: "10.43.1.4", Port: 80, Protocol: netv1.ProtocolTCP}
		key2 := PortKey{ClusterIP: "10.43.1.5", Port: 81, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key1, []netv1.Endpoint{b1.endpoint()})
		table.SetEndpoints(key2, []netv1.Endpoint{b2.endpoint()})

		if !handleVIP(t, p, key1, srcA) {
			t.Errorf("allowed port: srcA must reach the backend on the policy's port")
		}
		if handleVIP(t, p, key2, srcA) {
			t.Errorf("wrong port: srcA must be refused on a backend port the policy does not allow")
		}
		if got := b2.accepts.Load(); got != 0 {
			t.Errorf("wrong-port backend accepts = %d, want 0", got)
		}
	})

	t.Run("d: always-allow seeds and UNKNOWN-source fail-open pass a deny-all; known source denied", func(t *testing.T) {
		t.Parallel()
		nodeIP := netip.MustParseAddr("192.168.1.20")
		meshSelf := netip.MustParseAddr("100.64.0.0")
		meshPeer := netip.MustParseAddr("100.64.1.0")
		backend := netip.MustParseAddr("10.42.0.30")
		known := netip.MustParseAddr("10.42.0.31")
		unknown := netip.MustParseAddr("198.51.100.7")

		h := &captureHandler{}
		pt := NewPolicyTable(nodeIP, meshSelf, meshPeer)
		pt.log = slog.New(h)
		// Selected with ZERO rules: deny-all ingress for backend.
		pt.Update(map[netip.Addr][]PolicyRule{backend: nil}, podIPSet(known, backend))

		for _, src := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), nodeIP, meshSelf, meshPeer} {
			if !pt.Allow(src, backend, 8080) {
				t.Errorf("always-allow source %s must pass a deny-all policy", src)
			}
		}
		if n := len(h.warns()); n != 0 {
			t.Fatalf("always-allow sources must not warn, got %d warns", n)
		}
		if !pt.Allow(unknown, backend, 8080) {
			t.Errorf("UNKNOWN source must fail OPEN (hint contract)")
		}
		warns := h.warns()
		if len(warns) != 1 {
			t.Fatalf("unknown-source fail-open must Warn once, got %d", len(warns))
		}
		if got, ok := attr(warns[0], "src"); !ok || got != unknown.String() {
			t.Errorf("warn src attr = %q (present=%v), want %s (must NAME the unattributable source)", got, ok, unknown)
		}
		// Throttle: a second unknown source inside the window does not re-warn.
		if !pt.Allow(unknown, backend, 8080) {
			t.Errorf("unknown source must still fail open on repeat")
		}
		if n := len(h.warns()); n != 1 {
			t.Errorf("unknown-source warn must be throttled, got %d warns", n)
		}
		// Non-vacuity control: an ATTRIBUTABLE source is denied by deny-all.
		if pt.Allow(known, backend, 8080) {
			t.Errorf("known pod source must be DENIED by a deny-all policy")
		}
	})

	t.Run("e: asserted bypass — direct pod-IP traffic never consults the table (the honest ceiling)", func(t *testing.T) {
		t.Parallel()
		be := newTCPBanner(t, "127.0.0.1:0")

		pt := NewPolicyTable()
		// Deny-all on the backend: if ANY seam consulted the table for the direct
		// path, this is the policy that would deny it.
		pt.Update(map[netip.Addr][]PolicyRule{be.addrPort().Addr(): nil}, podIPSet(srcA))

		p, table := newPolicyProxy(pt)
		key := PortKey{ClusterIP: "10.43.1.6", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{be.endpoint()})

		// Direct pod-IP dial (per-pod /32 path, no VIP): succeeds DESPITE deny-all,
		// and consults the verdict table zero times — M10.4 is a VIP-mediated hint,
		// not isolation (the M10.1 causal link: per-pod /32s bypass the proxy).
		conn, err := net.DialTimeout("tcp", be.addrPort().String(), policyTestTimeout)
		if err != nil {
			t.Fatalf("direct pod-IP dial: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(policyTestTimeout))
		buf := make([]byte, 2)
		if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ok" {
			t.Fatalf("direct pod-IP path must BYPASS the deny-all policy (read %q, err %v)", buf[:n], err)
		}
		_ = conn.Close()
		if got := pt.evalCount.Load(); got != 0 {
			t.Fatalf("direct path consulted the policy table %d times, want 0 (only VIP paths are hooked)", got)
		}
		// Control: the VIP-mediated path DOES consult it (and denies).
		if handleVIP(t, p, key, srcA) {
			t.Errorf("VIP-mediated path must be denied by the same deny-all policy")
		}
		if got := pt.evalCount.Load(); got == 0 {
			t.Errorf("VIP path must consult the policy table")
		}
	})

	t.Run("f: UDP flow admission — denied flow never created, allowed flow relays", func(t *testing.T) {
		t.Parallel()
		bp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp backend: %v", err)
		}
		defer bp.Close()
		beAP := bp.LocalAddr().(*net.UDPAddr).AddrPort()

		pt := NewPolicyTable()
		pt.log = slog.New(slog.DiscardHandler)
		pt.Update(map[netip.Addr][]PolicyRule{
			beAP.Addr(): {{Sources: podIPSet(srcA)}},
		}, podIPSet(srcA, srcB))

		table := NewRoutingTable(netip.Prefix{})
		key := PortKey{ClusterIP: "10.43.1.7", Port: 53, Protocol: netv1.ProtocolUDP}
		table.SetEndpoints(key, []netv1.Endpoint{{IP: beAP.Addr().String(), Port: int32(beAP.Port()), Ready: true}})

		vip, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen vip socket: %v", err)
		}
		r := newUDPRelay(vip, key, table, netip.Addr{}, time.Minute, maxUDPFlowsPerSource, nil, slog.New(slog.DiscardHandler))
		r.policy = pt
		defer func() { _ = r.Close() }()

		var lastWarn time.Time
		// Denied source at flow admission: no upstream socket, no flow entry.
		if up := r.upstreamFor(&net.UDPAddr{IP: srcB.AsSlice(), Port: 5001}, &lastWarn); up != nil {
			t.Fatalf("denied source must not be admitted a flow")
		}
		if got := r.flowCount(); got != 0 {
			t.Fatalf("denied flow was created: flowCount = %d, want 0", got)
		}
		// Allowed source: flow created and relays to the backend.
		up := r.upstreamFor(&net.UDPAddr{IP: srcA.AsSlice(), Port: 5002}, &lastWarn)
		if up == nil {
			t.Fatalf("allowed source must be admitted a flow")
		}
		if got := r.flowCount(); got != 1 {
			t.Fatalf("flowCount = %d, want 1", got)
		}
		if _, err := up.Write([]byte("ping")); err != nil {
			t.Fatalf("write via admitted flow: %v", err)
		}
		_ = bp.SetReadDeadline(time.Now().Add(policyTestTimeout))
		buf := make([]byte, 16)
		n, _, err := bp.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "ping" {
			t.Fatalf("backend must receive the admitted flow's datagram (read %q, err %v)", buf[:n], err)
		}
	})

	t.Run("g: pre-sync/empty table and nil table allow everything", func(t *testing.T) {
		t.Parallel()
		anySrc := netip.MustParseAddr("203.0.113.9")
		anyBackend := netip.MustParseAddr("10.42.0.40")

		empty := NewPolicyTable() // pre-informer-sync shape: no Update yet
		if !empty.Allow(anySrc, anyBackend, 80) {
			t.Errorf("empty (pre-sync) table must allow everything (fail-open)")
		}
		var nilTable *PolicyTable
		if !nilTable.Allow(anySrc, anyBackend, 80) {
			t.Errorf("nil table must allow everything (feature is additive)")
		}

		// Through the real accept path: a proxy with an empty policy table serves.
		be := newTCPBanner(t, "127.0.0.1:0")
		p, table := newPolicyProxy(empty)
		key := PortKey{ClusterIP: "10.43.1.8", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{be.endpoint()})
		if !handleVIP(t, p, key, anySrc) {
			t.Errorf("pre-sync table must not refuse VIP traffic")
		}
	})
}

// TestPolicyDenyLogThrottled proves the deny hook's shared throttled Info: a burst
// of denied connections logs once per throttle window, on both accept paths.
func TestPolicyDenyLogThrottled(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("10.42.0.50")
	backend := netip.MustParseAddr("10.42.0.51")

	h := &captureHandler{}
	pt := NewPolicyTable()
	pt.log = slog.New(h)
	pt.Update(map[netip.Addr][]PolicyRule{backend: nil}, podIPSet(src, backend))

	key := PortKey{ClusterIP: "10.43.1.10", Port: 80, Protocol: netv1.ProtocolTCP}
	for i := 0; i < 5; i++ {
		if pt.Allow(src, backend, 80) {
			t.Fatalf("deny-all must deny")
		}
		pt.logDenied("tcp", key, src, netip.AddrPortFrom(backend, 8080))
	}
	pt.logDenied("udp", key, src, netip.AddrPortFrom(backend, 8080))

	var denies int
	h.mu.Lock()
	for _, r := range h.records {
		if r.Level == slog.LevelInfo && strings.Contains(r.Message, "denied by ingress policy") {
			denies++
		}
	}
	h.mu.Unlock()
	if denies != 1 {
		t.Fatalf("deny log must be throttled to once per window, got %d", denies)
	}
	// A nil table's logDenied is a defensive no-op, never a panic.
	var nilTable *PolicyTable
	nilTable.logDenied("tcp", key, src, netip.AddrPortFrom(backend, 8080))
}
