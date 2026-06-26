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
	if alias.removes(netip.MustParseAddr(vip)) == 0 {
		t.Fatalf("alias.Remove(%s) was never called on delete", vip)
	}

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
// backends as the ClusterIP, and a UDP NodePort opens NO listener (the datagram
// relay — ClusterIP and NodePort alike — is deferred, so UDP NodePort is not
// claimed). The externalTrafficPolicy: Cluster semantics — the userspace L4
// splice opens a fresh backend connection and so does NOT preserve the client
// source IP, hence Local is not honored — are documented in doc.go and the
// openListener comment; this test pins the wildcard bind, the LB, and the UDP
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

	t.Run("udp NodePort opens no listener (relay deferred, not claimed)", func(t *testing.T) {
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

		// Let the worker process the event (the UDP key lands in the table).
		key := PortKey{ClusterIP: vip, Port: clusterPort, Protocol: netv1.ProtocolUDP}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && tbl.Len(key) == 0 {
			time.Sleep(10 * time.Millisecond)
		}

		// No TCP stream listener was opened on the UDP NodePort — UDP NodePort is
		// deferred with the datagram relay, so it is not claimed.
		if c, err := net.DialTimeout("tcp", hostPort("127.0.0.1", nodePort), 200*time.Millisecond); err == nil {
			_ = c.Close()
			t.Fatalf("a TCP listener was opened for a UDP NodePort (relay should be deferred)")
		}

		cancel()
		<-runDone
	})
}

// TestProxyUDPPortDefersRelay asserts the documented UDP decision: a UDP Service
// port ensures the lo0 alias (so the VIP is reachable once the relay lands) but
// opens NO TCP stream listener in M1, and the routing table still records the
// UDP key's backends.
func TestProxyUDPPortDefersRelay(t *testing.T) {
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

	// Give the worker a moment to process the event.
	key := PortKey{ClusterIP: vip, Port: udpPort, Protocol: netv1.ProtocolUDP}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && tbl.Len(key) == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	// Alias ensured for the UDP VIP.
	if alias.ensures(netip.MustParseAddr(vip)) == 0 {
		t.Fatalf("UDP port did not ensure the lo0 alias")
	}
	// Routing table records the UDP backend (ready for the future relay).
	if tbl.Len(key) != 1 {
		t.Fatalf("UDP routing table backends = %d, want 1", tbl.Len(key))
	}
	// No TCP stream listener was opened on the UDP port.
	if c, err := net.DialTimeout("tcp", hostPort(vip, udpPort), 200*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatalf("a TCP listener was opened for a UDP service port (relay should be deferred)")
	}

	cancel()
	<-runDone
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
