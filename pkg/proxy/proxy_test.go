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
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// echoBackend is a tiny TCP server that writes a fixed id then echoes; it stands
// in for a pod backend so the proxy's data path is exercised without privilege.
type echoBackend struct {
	id string
	ln net.Listener
	ip string
	wg sync.WaitGroup
}

func newEchoBackend(t *testing.T, id, listenIP string) *echoBackend {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		t.Fatalf("listen echo backend: %v", err)
	}
	b := &echoBackend{id: id, ln: ln, ip: listenIP}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, b.id)
			}(c)
		}
	}()
	return b
}

func (b *echoBackend) addrPort() (string, int32) {
	ap := b.ln.Addr().(*net.TCPAddr)
	return ap.IP.String(), int32(ap.Port)
}

func (b *echoBackend) close() {
	_ = b.ln.Close()
	b.wg.Wait()
}

// readID dials clusterIP:port and returns the backend id the proxy steered to.
func readID(t *testing.T, clusterIP string, port int32) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", hostPort(clusterIP, port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial VIP: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read from VIP: %v", err)
	}
	return string(buf)
}

// hostPort joins an IP and an int32 port for net.Dial.
func hostPort(ip string, port int32) string {
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

// TestProxyReconcileLoadBalances is the rootless rehearsal for acceptance
// M1.1-a1: a ClusterIP VIP load-balances accepted TCP connections across two
// ready backends, with the unready third backend never selected. It runs the
// full Proxy reconcile path with the noop alias manager.
//
// macOS note: only 127.0.0.1 is bindable without a root-created lo0 alias
// (unlike Linux's whole 127.0.0.0/8). So the rootless tier binds the VIP on
// 127.0.0.1 and distinguishes the VIP by port; the faithful per-VIP 127.0.0.x
// source-identity rehearsal (real lo0 alias per VIP) is the root-gated
// integration test in alias_integration_test.go.
func TestProxyReconcileLoadBalances(t *testing.T) {
	t.Parallel()
	const vip = "127.0.0.1"

	be1 := newEchoBackend(t, "backend-1", "127.0.0.1")
	be2 := newEchoBackend(t, "backend-2", "127.0.0.1")
	beUnready := newEchoBackend(t, "backend-unready", "127.0.0.1")
	defer be1.close()
	defer be2.close()
	defer beUnready.close()

	// Pick a free port for the VIP listener.
	port := freePort(t, vip)

	alias := newNoopAliasManager()
	tbl := NewRoutingTable(netip.Prefix{})
	p := New(tbl, withAliasManager(alias))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	ip1, port1 := be1.addrPort()
	ip2, port2 := be2.addrPort()
	ipU, portU := beUnready.addrPort()

	sp := &netv1.ServicePort{Port: port, TargetPort: 0, Protocol: netv1.ProtocolTCP}
	eps := []netv1.Endpoint{
		{IP: ip1, Port: port1, Ready: true},
		{IP: ip2, Port: port2, Ready: true},
		{IP: ipU, Port: portU, Ready: false},
	}
	if err := p.Reconcile(vip, sp, eps); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Wait for the listener to come up.
	waitListen(t, vip, port)

	// The noop alias manager must have been asked to ensure the VIP.
	if alias.ensures(netip.MustParseAddr(vip)) == 0 {
		t.Fatalf("alias.Ensure(%s) was never called", vip)
	}

	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		counts[readID(t, vip, port)]++
	}
	if counts["backend-unready"] != 0 {
		t.Fatalf("unready backend received %d connections, want 0", counts["backend-unready"])
	}
	if counts["backend-1"] == 0 || counts["backend-2"] == 0 {
		t.Fatalf("load not balanced: %v", counts)
	}
	if counts["backend-1"]+counts["backend-2"] != 40 {
		t.Fatalf("connections lost: %v", counts)
	}

	// Tear down: the worker must close the listener and remove the alias.
	p.ReconcileDelete(PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP})
	waitClosed(t, vip, port)
	// listener.Close closes the sockets BEFORE it calls alias.Remove, so the VIP
	// refusing connections does NOT order the alias removal — waitClosed can win the
	// race by the width of a deschedule. Wait on the fact being asserted instead.
	// ctx is still live, so the delete path is the only thing that can remove it.
	waitAliasRemoved(t, alias, netip.MustParseAddr(vip))

	cancel()
	<-runDone
}

// TestProxyPerVIPSerialization asserts a burst of concurrent reconciles for the
// SAME ClusterIP:port is serialized onto one worker (one listener), so churn
// never races two owners onto one socket. It drives many goroutines at one key
// and asserts the VIP still serves and tears down cleanly under -race.
func TestProxyPerVIPSerialization(t *testing.T) {
	t.Parallel()
	const vip = "127.0.0.1"

	be := newEchoBackend(t, "be", "127.0.0.1")
	defer be.close()
	ip, bport := be.addrPort()

	port := freePort(t, vip)
	alias := newNoopAliasManager()
	p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(alias))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	sp := &netv1.ServicePort{Port: port, TargetPort: 0, Protocol: netv1.ProtocolTCP}
	eps := []netv1.Endpoint{{IP: ip, Port: bport, Ready: true}}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Reconcile(vip, sp, eps); err != nil {
				t.Errorf("concurrent reconcile: %v", err)
			}
		}()
	}
	wg.Wait()

	waitListen(t, vip, port)
	if got := readID(t, vip, port); got != "be" {
		t.Fatalf("VIP served %q, want be", got)
	}

	// Exactly one worker exists for the key.
	p.mu.Lock()
	nworkers := len(p.workers)
	p.mu.Unlock()
	if nworkers != 1 {
		t.Fatalf("workers for one VIP:port = %d, want 1", nworkers)
	}

	cancel()
	<-runDone
	// After shutdown the alias must be removed (leak-free).
	if alias.removes(netip.MustParseAddr(vip)) == 0 {
		t.Fatalf("alias.Remove(%s) not called on shutdown", vip)
	}
	waitClosed(t, vip, port)
}

// TestNodePortBindsWildcard is the M3.2 acceptance: a NodePort Service yields a
// node-wide *:NodePort TCP listener (bound to the wildcard so every interface
// answers — dialed here via loopback) that load-balances to the same ready
// backends as the ClusterIP. For UDP (B23) the ClusterIP datagram relay IS built,
// but the UDP NodePort stays deferred — no datagram socket is bound on the
// *:NodePort (a wildcard UDP reply would re-select its source on a multi-homed
// node). The externalTrafficPolicy: Cluster semantics — the userspace L4 splice
// opens a fresh backend connection and so does NOT preserve the client source IP,
// hence Local is not honored — are documented in doc.go and the openListener
// comment; this test pins the wildcard TCP bind, the LB, and the UDP-NodePort
// deferral.
func TestNodePortBindsWildcard(t *testing.T) {
	t.Parallel()

	t.Run("tcp NodePort yields a wildcard listener and load-balances", func(t *testing.T) {
		t.Parallel()
		const vip = "127.0.0.1"

		be1 := newEchoBackend(t, "np-1", "127.0.0.1")
		be2 := newEchoBackend(t, "np-2", "127.0.0.1")
		defer be1.close()
		defer be2.close()
		ip1, p1 := be1.addrPort()
		ip2, p2 := be2.addrPort()

		clusterPort := freePort(t, vip)
		nodePort := freePort(t, "0.0.0.0")
		alias := newNoopAliasManager()
		p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(alias))

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { defer close(runDone); _ = p.Run(ctx) }()

		sp := &netv1.ServicePort{Port: clusterPort, TargetPort: 0, Protocol: netv1.ProtocolTCP, NodePort: nodePort}
		eps := []netv1.Endpoint{
			{IP: ip1, Port: p1, Ready: true},
			{IP: ip2, Port: p2, Ready: true},
		}
		if err := p.Reconcile(vip, sp, eps); err != nil {
			t.Fatalf("reconcile: %v", err)
		}

		// The *:NodePort listener answers on the wildcard (dialed via loopback) and
		// fans out across both ready backends.
		waitListen(t, "127.0.0.1", nodePort)
		counts := map[string]int{}
		for i := 0; i < 20; i++ {
			counts[readID(t, "127.0.0.1", nodePort)]++
		}
		if counts["np-1"] == 0 || counts["np-2"] == 0 {
			t.Fatalf("NodePort did not load-balance across ready backends: %v", counts)
		}
		if counts["np-1"]+counts["np-2"] != 20 {
			t.Fatalf("NodePort connections lost: %v", counts)
		}

		// Delete tears the *:NodePort listener down with the ClusterIP.
		p.ReconcileDelete(PortKey{ClusterIP: vip, Port: clusterPort, Protocol: netv1.ProtocolTCP})
		waitClosed(t, "127.0.0.1", nodePort)

		cancel()
		<-runDone
	})

	t.Run("udp NodePort deferred: clusterIP relay built, NodePort datagram socket not claimed", func(t *testing.T) {
		t.Parallel()
		const vip = "127.0.0.1"

		clusterPort := freePort(t, vip)
		nodePort := freePort(t, "0.0.0.0")
		alias := newNoopAliasManager()
		tbl := NewRoutingTable(netip.Prefix{})
		p := New(tbl, withAliasManager(alias))

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { defer close(runDone); _ = p.Run(ctx) }()

		sp := &netv1.ServicePort{Port: clusterPort, TargetPort: 53, Protocol: netv1.ProtocolUDP, NodePort: nodePort}
		eps := []netv1.Endpoint{{IP: "10.42.0.9", Port: 53, Ready: true}}
		if err := p.Reconcile(vip, sp, eps); err != nil {
			t.Fatalf("reconcile udp nodeport: %v", err)
		}

		// Let the worker process the event (the UDP key lands in the table; the
		// ClusterIP relay binds in the same openListener call).
		key := PortKey{ClusterIP: vip, Port: clusterPort, Protocol: netv1.ProtocolUDP}
		waitBackends(t, tbl, key, 1)

		// The ClusterIP UDP relay is built, but the NodePort UDP is deferred. No TCP
		// listener was opened on the NodePort...
		if c, err := net.DialTimeout("tcp", hostPort("127.0.0.1", nodePort), 200*time.Millisecond); err == nil {
			_ = c.Close()
			t.Fatalf("a TCP listener was opened for a UDP NodePort (must be deferred)")
		}
		// ...and no UDP datagram socket claimed the NodePort: the wildcard *:NodePort
		// is still bindable, proving the relay did not open a NodePort datagram socket.
		if pc, err := net.ListenPacket("udp", net.JoinHostPort("", strconv.Itoa(int(nodePort)))); err != nil {
			t.Fatalf("UDP NodePort %d was claimed (datagram relay must be deferred): %v", nodePort, err)
		} else {
			_ = pc.Close()
		}

		cancel()
		<-runDone
	})
}

// TestProxyUDPClusterIPRelay asserts a ClusterIP UDP Service now BUILDS the
// datagram relay (B23): the worker ensures the lo0 alias, records the backend in
// the routing table, and opens a UDP datagram socket on the VIP — NOT a TCP stream
// listener (a UDP port must never open a TCP socket). The end-to-end datagram
// round-trip + per-flow reuse is covered by TestUDPDatagramRelayRoundTrip; this
// test pins the plumbing and that the relay is UDP-only.
func TestProxyUDPClusterIPRelay(t *testing.T) {
	t.Parallel()
	const vip = "127.0.0.1"

	udpPort := freePort(t, vip)
	alias := newNoopAliasManager()
	tbl := NewRoutingTable(netip.Prefix{})
	p := New(tbl, withAliasManager(alias))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	sp := &netv1.ServicePort{Port: udpPort, TargetPort: 53, Protocol: netv1.ProtocolUDP}
	eps := []netv1.Endpoint{{IP: "10.42.0.7", Port: 53, Ready: true}}
	if err := p.Reconcile(vip, sp, eps); err != nil {
		t.Fatalf("reconcile udp: %v", err)
	}

	// Wait for the worker to process the event. runWorker records the backends and
	// only THEN calls openListener, so a full routing table does not imply the alias
	// was ensured — the two facts need two waits.
	key := PortKey{ClusterIP: vip, Port: udpPort, Protocol: netv1.ProtocolUDP}
	waitBackends(t, tbl, key, 1)

	// Alias ensured for the UDP VIP (openListener's first act, after the table write).
	waitAliasEnsured(t, alias, netip.MustParseAddr(vip))
	// No TCP stream listener was opened on the UDP port — the relay is a datagram
	// socket, not a stream listener.
	if c, err := net.DialTimeout("tcp", hostPort(vip, udpPort), 200*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatalf("a TCP listener was opened for a UDP service port (the relay must be UDP-only)")
	}

	cancel()
	<-runDone
}

// waitBackends blocks until the routing table records exactly want backends for
// key, or fails the test after a short deadline. It is the readiness signal for
// the per-VIP worker having applied a reconcile event.
func waitBackends(t *testing.T, tbl *RoutingTable, key PortKey, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if tbl.Len(key) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("routing table for %s never reached %d backends (have %d)", key, want, tbl.Len(key))
}

// freePort returns a TCP port currently free on ip by opening and closing a
// listener; there is an inherent TOCTOU window but it is acceptable for tests.
func freePort(t *testing.T, ip string) int32 {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := int32(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

// waitAliasEnsured blocks until the alias manager has been asked to ensure ip.
// It exists because the reconcile path writes the routing table BEFORE it opens
// the listener (runWorker), so waitBackends is not a readiness signal for the
// alias having been ensured — asserting the counter directly off waitBackends is
// a lost race under load (B207).
func waitAliasEnsured(t *testing.T, m *noopAliasManager, ip netip.Addr) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.ensures(ip) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("alias.Ensure(%s) was never called", ip)
}

// waitAliasRemoved blocks until the alias manager has been asked to remove ip.
// Its counterpart to waitAliasEnsured: listener.Close closes the sockets before
// it removes the alias, so waitClosed does not order the removal either (B207).
func waitAliasRemoved(t *testing.T, m *noopAliasManager, ip netip.Addr) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.removes(ip) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("alias.Remove(%s) was never called on delete", ip)
}

func waitListen(t *testing.T, ip string, port int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostPort(ip, port), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener on %s:%d never came up", ip, port)
}

func waitClosed(t *testing.T, ip string, port int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostPort(ip, port), 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener on %s:%d never closed", ip, port)
}
