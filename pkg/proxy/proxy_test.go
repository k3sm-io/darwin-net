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

// The proxy's reconcile and accept paths run here on in-memory fakes: a
// recordingBinder stands in for the VIP stream bind, a fakeTCPNet for the
// backend dial, and fakeVIPConn for the datagram bind, with client conns that
// carry real TCP source addresses (helpers_test.go). The same paths on real
// loopback sockets are covered by the integration-tier tests, whose helpers are
// in realsocket_integration_test.go.

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// testClient is the pod source the proxy tests connect from.
var testClient = netip.MustParseAddrPort("10.42.0.99:40312")

// readIDVia connects through l from testClient and reads the n-byte id of the
// backend the proxy spliced to. It closes the client end afterwards, which ends
// the splice.
func readIDVia(t *testing.T, l *fakeListener, n int) string {
	t.Helper()
	c := l.connectFrom(t, testClient)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(fakeHandledTimeout))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read backend id: %v", err)
	}
	return string(buf)
}

// startProxy runs p's supervision loop until the test ends.
func startProxy(t *testing.T, p *Proxy) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runDone })
}

// TestProxyReconcileLoadBalances is the rootless rehearsal for acceptance
// M1.1-a1: a ClusterIP VIP load-balances accepted TCP connections across two
// ready backends, with the unready third backend never selected. It runs the
// full Proxy reconcile path with the noop alias manager: the VIP listener is
// bound through the binder seam at exactly the VIP address, and every accepted
// connection is spliced to the backend the routing table picked.
func TestProxyReconcileLoadBalances(t *testing.T) {
	t.Parallel()
	const vip = "10.43.0.31"
	const port = 80

	backends := newFakeTCPNet()
	be1 := backends.add(t, "10.42.0.11:8080", "be-1")
	be2 := backends.add(t, "10.42.0.12:8080", "be-2")
	beUnready := backends.add(t, "10.42.0.13:8080", "be-u")

	alias := newNoopAliasManager()
	binder := newRecordingBinder()
	tbl := NewRoutingTable(netip.Prefix{})
	p := New(tbl, withAliasManager(alias), withBinder(binder), withDialBackend(backends.dial))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	unready := beUnready.endpoint()
	unready.Ready = false
	sp := &netv1.ServicePort{Port: port, TargetPort: 0, Protocol: netv1.ProtocolTCP}
	eps := []netv1.Endpoint{be1.endpoint(), be2.endpoint(), unready}
	if err := p.Reconcile(vip, sp, eps); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The listener comes up at exactly the VIP address and port.
	l := binder.waitBound(t, 1)
	if want := hostPortAddr(vip, port); l.address != want {
		t.Fatalf("VIP listener bound at %s, want exactly %s", l.address, want)
	}

	// The noop alias manager must have been asked to ensure the VIP: openListener
	// ensures the alias before it binds, and the bind is ordered before this read.
	if alias.ensures(netip.MustParseAddr(vip)) == 0 {
		t.Fatalf("alias.Ensure(%s) was never called", vip)
	}

	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		counts[readIDVia(t, l, 4)]++
	}
	if counts["be-u"] != 0 {
		t.Fatalf("unready backend received %d connections, want 0", counts["be-u"])
	}
	if counts["be-1"] == 0 || counts["be-2"] == 0 {
		t.Fatalf("load not balanced: %v", counts)
	}
	if counts["be-1"]+counts["be-2"] != 40 {
		t.Fatalf("connections lost: %v", counts)
	}
	if got := beUnready.accepts.Load(); got != 0 {
		t.Fatalf("unready backend was dialed %d times, want 0", got)
	}

	// Tear down: the worker must close the listener and remove the alias.
	p.ReconcileDelete(PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP})
	waitListenerClosed(t, l)
	// listener.Close closes the sockets BEFORE it calls alias.Remove, so the
	// listener closing does NOT order the alias removal. Wait on the fact being
	// asserted instead. ctx is still live, so the delete path is the only thing
	// that can remove it.
	waitAliasRemoved(t, alias, netip.MustParseAddr(vip))

	cancel()
	<-runDone
}

// hostPortAddr formats an IP and port the way a bound listener's address reads.
func hostPortAddr(ip string, port uint16) string {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), port).String()
}

// TestProxyPerVIPSerialization asserts a burst of concurrent reconciles for the
// SAME ClusterIP:port is serialized onto one worker (one listener), so churn
// never races two owners onto one socket. It drives many goroutines at one key
// and asserts the VIP still serves and tears down cleanly under -race.
func TestProxyPerVIPSerialization(t *testing.T) {
	t.Parallel()
	const vip = "10.43.0.32"
	const port = 80

	backends := newFakeTCPNet()
	be := backends.add(t, "10.42.0.21:8080", "be")

	alias := newNoopAliasManager()
	binder := newRecordingBinder()
	p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(alias), withBinder(binder), withDialBackend(backends.dial))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	sp := &netv1.ServicePort{Port: port, TargetPort: 0, Protocol: netv1.ProtocolTCP}
	eps := []netv1.Endpoint{be.endpoint()}

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

	l := binder.waitBound(t, 1)
	if got := readIDVia(t, l, 2); got != "be" {
		t.Fatalf("VIP served %q, want be", got)
	}

	// Exactly one worker exists for the key, and it bound exactly one listener.
	p.mu.Lock()
	nworkers := len(p.workers)
	p.mu.Unlock()
	if nworkers != 1 {
		t.Fatalf("workers for one VIP:port = %d, want 1", nworkers)
	}
	if n := binder.count(); n != 1 {
		t.Fatalf("listeners bound for one VIP:port = %d (%v), want 1", n, binder.addrs())
	}

	cancel()
	<-runDone
	// After shutdown the alias must be removed (leak-free).
	if alias.removes(netip.MustParseAddr(vip)) == 0 {
		t.Fatalf("alias.Remove(%s) not called on shutdown", vip)
	}
	waitListenerClosed(t, l)
}

// waitNoWorker polls, bounded, until key has no entry in p.workers — the delete
// path removes it asynchronously (from the worker's own goroutine, on its
// delete-event exit), so a caller cannot assume it is gone the instant
// ReconcileDelete returns (ReconcileDelete only enqueues the delete event; it
// does not wait for the worker to drain and process it).
func waitNoWorker(t *testing.T, p *Proxy, key PortKey) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.mu.Lock()
		_, present := p.workers[key]
		p.mu.Unlock()
		if !present {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("workers map still holds an entry for %s after delete", key)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// boundedReconcile runs a Reconcile/ReconcileDelete-shaped call in its own
// goroutine and fails the test if it has not returned within timeout — the
// direct assertion for B208's defect: a delete that leaks its workers-map entry
// sends every later reconcile for the same key into the dead worker's unread,
// 16-buffered channel, and the 17th such send blocks the caller (the informer
// handler, in production) PERMANENTLY. A fixed timeout is the only way to assert
// "does not block forever" without actually hanging the test on a red run — this
// is a bounded-time assertion, not a sleep used as pacing logic.
func boundedReconcile(t *testing.T, timeout time.Duration, label string, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	case <-time.After(timeout):
		t.Fatalf("%s: blocked for over %s (worker map entry leaked on delete)", label, timeout)
	}
}

// TestWorkerMapCleanedOnDeleteThenRecreate is the B208 gate: runWorker's delete
// path (a nil-port portEvent) must remove its own entry from Proxy.workers
// before it exits, so that a delete-then-recreate on the SAME ClusterIP:port
// spawns a fresh worker rather than reaching the dead one via the stale map
// entry. Filed from B207's builder observation (darwin-net#56): without the
// fix, worker() keeps returning the exited worker (it is still keyed in the
// map), reconciles queue into its unread 16-buffered channel, and the 17th send
// blocks the caller forever.
func TestWorkerMapCleanedOnDeleteThenRecreate(t *testing.T) {
	t.Parallel()
	const vip = "10.43.0.33"
	const port = 80
	key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP}
	sp := &netv1.ServicePort{Port: port, TargetPort: 0, Protocol: netv1.ProtocolTCP}

	t.Run("delete then recreate serves again with a fresh worker", func(t *testing.T) {
		t.Parallel()

		backends := newFakeTCPNet()
		be1 := backends.add(t, "10.42.0.31:8080", "gen-1")
		be2 := backends.add(t, "10.42.0.32:8080", "gen-2")

		binder := newRecordingBinder()
		p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(newNoopAliasManager()), withBinder(binder), withDialBackend(backends.dial))
		startProxy(t, p)

		if err := p.Reconcile(vip, sp, []netv1.Endpoint{be1.endpoint()}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		l1 := binder.waitBound(t, 1)
		if got := readIDVia(t, l1, 5); got != "gen-1" {
			t.Fatalf("VIP served %q, want gen-1", got)
		}

		p.ReconcileDelete(key)
		waitListenerClosed(t, l1)
		waitNoWorker(t, p, key)

		// Recreate on the SAME key: worker() must spawn a fresh worker (the map
		// entry is gone), not reach the exited one.
		if err := p.Reconcile(vip, sp, []netv1.Endpoint{be2.endpoint()}); err != nil {
			t.Fatalf("recreate reconcile: %v", err)
		}
		l2 := binder.waitBound(t, 2)
		if got := readIDVia(t, l2, 5); got != "gen-2" {
			t.Fatalf("recreated VIP served %q, want gen-2", got)
		}

		p.mu.Lock()
		w, present := p.workers[key]
		nworkers := len(p.workers)
		p.mu.Unlock()
		if !present || w == nil {
			t.Fatalf("workers map has no entry for %s after recreate", key)
		}
		if nworkers != 1 {
			t.Fatalf("workers map size after recreate = %d, want 1", nworkers)
		}
	})

	t.Run(">16 reconciles after a delete never block", func(t *testing.T) {
		t.Parallel()

		backends := newFakeTCPNet()
		be := backends.add(t, "10.42.0.33:8080", "burst")
		eps := []netv1.Endpoint{be.endpoint()}

		binder := newRecordingBinder()
		p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(newNoopAliasManager()), withBinder(binder), withDialBackend(backends.dial))
		startProxy(t, p)

		if err := p.Reconcile(vip, sp, eps); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		l1 := binder.waitBound(t, 1)

		// Delete, and wait for the worker to have fully exited (not merely for
		// the delete event to have been enqueued) so every reconcile below is
		// the deterministic post-delete case: at main the stale map entry sends
		// each one into the dead worker's dead channel.
		p.ReconcileDelete(key)
		waitListenerClosed(t, l1)
		waitNoWorker(t, p, key)

		// 20 > the worker channel's 16-slot buffer: at main the map entry was
		// never removed, so all 20 reconciles route to the SAME exited worker
		// and the 17th blocks forever on its unread channel.
		for i := 0; i < 20; i++ {
			boundedReconcile(t, 2*time.Second, fmt.Sprintf("post-delete reconcile %d", i), func() error {
				return p.Reconcile(vip, sp, eps)
			})
		}

		l2 := binder.waitBound(t, 2)
		if got := readIDVia(t, l2, 5); got != "burst" {
			t.Fatalf("VIP served %q after the reconcile burst, want burst", got)
		}
	})

	t.Run("deliver-vs-dying race under concurrent delete/recreate", func(t *testing.T) {
		t.Parallel()

		backends := newFakeTCPNet()
		be := backends.add(t, "10.42.0.34:8080", "racer")
		eps := []netv1.Endpoint{be.endpoint()}

		binder := newRecordingBinder()
		p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(newNoopAliasManager()), withBinder(binder), withDialBackend(backends.dial))
		startProxy(t, p)

		if err := p.Reconcile(vip, sp, eps); err != nil {
			t.Fatalf("seed reconcile: %v", err)
		}
		binder.waitBound(t, 1)

		// Hammer ReconcileDelete concurrently with a burst of ReconcilePolicy
		// calls on the SAME key, round after round, with no synchronization
		// between the delete and the reconciles — this is the window where a
		// reconcile can obtain a reference to the dying worker (via worker())
		// a moment before removeWorker's compare-and-delete runs. Every call
		// must still return within the bound: either it lands on the dying
		// worker and is unblocked by the now-closed w.stop, or it lands on
		// (or spawns) a live one and is delivered normally.
		const rounds = 12
		const burst = 4
		for r := 0; r < rounds; r++ {
			var wg sync.WaitGroup
			wg.Add(1 + burst)
			go func() {
				defer wg.Done()
				p.ReconcileDelete(key)
			}()
			for b := 0; b < burst; b++ {
				go func() {
					defer wg.Done()
					// A reconcile error here (e.g. "worker stopped") is an
					// acceptable outcome of the race — the property under
					// test is that it returns, not that it always succeeds.
					_ = p.Reconcile(vip, sp, eps)
				}()
			}
			waitDone := make(chan struct{})
			go func() { wg.Wait(); close(waitDone) }()
			select {
			case <-waitDone:
			case <-time.After(5 * time.Second):
				t.Fatalf("round %d: delete/reconcile burst did not complete (a goroutine blocked)", r)
			}
		}

		// Reaching this point at all — after `rounds` back-to-back bursts of a
		// concurrent ReconcileDelete racing a burst of ReconcilePolicy calls,
		// under -race — is itself the assertion for this subtest: neither a
		// panic (e.g. a close-of-closed w.stop, had removeWorker's close not
		// been gated on winning the compare-and-delete) nor a permanent block
		// occurred anywhere in the loop above. Whether key currently has zero
		// or one live worker is not asserted here (both are legitimate
		// outcomes depending on which of the last round's racing goroutines
		// "won"); the final reconcile below settles it and proves the key
		// stayed servable throughout.

		// Settle to a definitively torn-down state before the final check: the
		// racy loop above may leave a live worker behind. Deleting once more and
		// waiting for the worker to fully exit means the recreate below spawns a
		// BRAND NEW worker, whose listener is the next one bound.
		p.ReconcileDelete(key)
		waitNoWorker(t, p, key)

		// Recreate once more, cleanly, and confirm the VIP still serves — the
		// race must never leave the key permanently unservable.
		bound := binder.count()
		if err := p.Reconcile(vip, sp, eps); err != nil {
			t.Fatalf("final reconcile: %v", err)
		}
		l := binder.waitBound(t, bound+1)
		if got := readIDVia(t, l, 5); got != "racer" {
			t.Fatalf("VIP served %q after the race, want racer", got)
		}
	})
}

// TestProxyUDPClusterIPRelay asserts a ClusterIP UDP Service BUILDS the datagram
// relay: the worker ensures the lo0 alias, records the backend in the routing
// table, and binds a datagram socket at exactly the VIP address and port — and
// never a TCP stream listener (a UDP port must never open a TCP socket). The
// end-to-end datagram round-trip + per-flow reuse is covered by
// TestUDPDatagramRelayRoundTrip; this test pins the plumbing and that the relay
// is UDP-only.
func TestProxyUDPClusterIPRelay(t *testing.T) {
	t.Parallel()
	vip := netip.MustParseAddrPort("10.43.0.34:53")

	udpBound := make(chan *fakeVIPConn, 1)
	listenUDP := func(ap netip.AddrPort) (udpVIPConn, error) {
		c := newFakeVIPConn(ap)
		udpBound <- c
		return c, nil
	}
	alias := newNoopAliasManager()
	binder := newRecordingBinder()
	tbl := NewRoutingTable(netip.Prefix{})
	p := New(tbl, withAliasManager(alias), withBinder(binder), withListenUDP(listenUDP))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	sp := &netv1.ServicePort{Port: int32(vip.Port()), TargetPort: 53, Protocol: netv1.ProtocolUDP}
	eps := []netv1.Endpoint{{IP: "10.42.0.7", Port: 53, Ready: true}}
	if err := p.Reconcile(vip.Addr().String(), sp, eps); err != nil {
		t.Fatalf("reconcile udp: %v", err)
	}

	// Wait for the worker to process the event. runWorker records the backends and
	// only THEN calls openListener, so a full routing table does not imply the alias
	// was ensured — the two facts need two waits.
	key := PortKey{ClusterIP: vip.Addr().String(), Port: int32(vip.Port()), Protocol: netv1.ProtocolUDP}
	waitBackends(t, tbl, key, 1)

	// Alias ensured for the UDP VIP (openListener's first act, after the table write).
	waitAliasEnsured(t, alias, vip.Addr())

	var conn *fakeVIPConn
	select {
	case conn = <-udpBound:
	case <-time.After(fakeHandledTimeout):
		t.Fatal("the UDP reconcile never bound a VIP datagram socket")
	}
	if conn.local != vip {
		t.Fatalf("VIP datagram socket bound at %v, want exactly %v", conn.local, vip)
	}
	// No TCP stream listener was opened for the UDP port: the datagram bind above
	// is openListener's last act for a UDP port, so the binder count is final.
	if n := binder.count(); n != 0 {
		t.Fatalf("a TCP listener was opened for a UDP service port (%v); the relay must be UDP-only", binder.addrs())
	}

	cancel()
	<-runDone
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
