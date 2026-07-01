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

// TestUDPRelayIdleFlowGC drives the relay directly with a short idle timeout and
// asserts the sweeper reaps an idle flow: after one datagram a flow exists, and it
// is gone once it has been silent past the idle timeout. It exercises the GC path
// under -race.
func TestUDPRelayIdleFlowGC(t *testing.T) {
	t.Parallel()

	be := newUDPEchoBackend(t)
	defer be.close()
	beIP, bePort := be.addrPort()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen vip udp: %v", err)
	}
	vipAddr := pc.LocalAddr().(*net.UDPAddr)

	key := PortKey{ClusterIP: "127.0.0.1", Port: int32(vipAddr.Port), Protocol: netv1.ProtocolUDP}
	tbl := NewRoutingTable(netip.Prefix{})
	tbl.SetEndpoints(key, []netv1.Endpoint{{IP: beIP, Port: bePort, Ready: true}})

	const idle = 200 * time.Millisecond
	relay := newUDPRelay(pc, key, tbl, netip.Addr{}, idle, slog.Default())
	relay.start()
	defer relay.Close()

	c, err := net.DialUDP("udp", nil, vipAddr)
	if err != nil {
		t.Fatalf("dial vip udp: %v", err)
	}
	defer c.Close()

	// One datagram creates a flow and round-trips (the VIP socket is already bound,
	// so no retry window).
	if got := udpRoundTrip(t, c, "x", 2*time.Second); got != "x" {
		t.Fatalf("datagram did not round-trip: got %q", got)
	}
	// The flow exists immediately after activity (idle timeout >> this check).
	if got := relay.flowCount(); got != 1 {
		t.Fatalf("flow count after first datagram = %d, want 1", got)
	}
	// The idle sweeper reaps the flow after it falls silent past the idle timeout.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if relay.flowCount() == 0 {
			return // reaped
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("idle flow was not GC'd: flow count still %d", relay.flowCount())
}

// udpRoundTrip sends payload on the connected UDP socket c and returns the reply
// read back within timeout. It fails the test on a write/read error.
func udpRoundTrip(t *testing.T, c *net.UDPConn, payload string, timeout time.Duration) string {
	t.Helper()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxUDPDatagram)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read reply for %q: %v", payload, err)
	}
	return string(buf[:n])
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
		return string(buf[:n])
	}
	return ""
}
