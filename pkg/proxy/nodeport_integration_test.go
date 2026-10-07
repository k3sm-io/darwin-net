//go:build integration

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

// Real-socket twin of the NodePort unit test. TestNodePortBindsWildcard in
// nodeport_test.go runs the reconcile path on in-memory listeners and dialers;
// this runs it on real loopback sockets, so the kernel's wildcard bind and the
// real accept/dial/splice path stay covered. It needs no privilege; run with:
//
//	CGO_ENABLED=0 go test -tags integration -run 'TestNodePortBindsWildcardReal' ./pkg/proxy/

package proxy

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// TestNodePortBindsWildcardReal is the real-socket twin of
// TestNodePortBindsWildcard, the M3.2 acceptance: a NodePort Service yields a
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
func TestNodePortBindsWildcardReal(t *testing.T) {
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
