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
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// fakeListener is an in-memory net.Listener: connect hands Accept the server end
// of a net.Pipe and returns the client end. Accept blocks until a connection or
// Close, after which it returns net.ErrClosed.
type fakeListener struct {
	network string
	address string
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
}

// newFakeListener returns an open listener that reports network and address.
func newFakeListener(network, address string) *fakeListener {
	return &fakeListener{network: network, address: address, conns: make(chan net.Conn), done: make(chan struct{})}
}

// Accept blocks for the next connection or Close.
func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
}

// Close closes the listener once; later calls are no-ops that return nil.
func (l *fakeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr reports a placeholder address; nothing in the proxy reads it.
func (l *fakeListener) Addr() net.Addr { return fakeAddr{l.network, l.address} }

// connect opens one connection to the listener and returns its client end.
func (l *fakeListener) connect(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client
	case <-l.done:
		t.Fatalf("connect to %s %s: listener closed", l.network, l.address)
	case <-time.After(fakeHandledTimeout):
		t.Fatalf("connect to %s %s: never accepted", l.network, l.address)
	}
	return nil
}

// fakeAddr is a net.Addr with a fixed network and string.
type fakeAddr struct{ network, address string }

func (a fakeAddr) Network() string { return a.network }
func (a fakeAddr) String() string  { return a.address }

// fakeBinder is an in-memory binder: each Listen opens a fakeListener and
// announces it on bound.
type fakeBinder struct{ bound chan *fakeListener }

// Listen opens a fake listener at addr.
func (b fakeBinder) Listen(_ context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	l := newFakeListener(network, addr.String())
	b.bound <- l
	return l, nil
}

// fakeNodePortBackends stands in for the Service's backends behind dialBackend:
// a dial to a known address returns a pipe whose far end writes that backend's id
// and closes. It records every dial that did not use the dialer want returns, so
// the test can assert dialerFor's selection reached the dial unchanged.
//
// Locking discipline: wrongDialer is guarded by mu; ids and want are read-only
// once the first dial can happen.
type fakeNodePortBackends struct {
	ids  map[string]string // backend address → id it writes
	want func() *tcpseg.Dialer

	mu          sync.Mutex
	wrongDialer int
}

// dial matches Proxy.dialBackend.
func (b *fakeNodePortBackends) dial(d *tcpseg.Dialer, network, address string) (net.Conn, error) {
	if d != b.want() {
		b.mu.Lock()
		b.wrongDialer++
		b.mu.Unlock()
	}
	id, ok := b.ids[address]
	if !ok || network != "tcp" {
		return nil, fmt.Errorf("fake backend: no %s backend at %s", network, address)
	}
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		_, _ = io.WriteString(far, id)
	}()
	return near, nil
}

// wrongDialers reports how many dials used a dialer other than want.
func (b *fakeNodePortBackends) wrongDialers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.wrongDialer
}

// readBackendID connects through l and reads the n-byte id of the backend the
// proxy spliced to. It closes the client end afterwards, which ends the splice.
func readBackendID(t *testing.T, l *fakeListener, n int) string {
	t.Helper()
	c := l.connect(t)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(fakeHandledTimeout))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read backend id: %v", err)
	}
	return string(buf)
}

// TestNodePortBindsWildcard is the M3.2 acceptance, run on in-memory listeners
// and dialers: a NodePort Service yields a node-wide NodePort TCP listener bound to
// the WILDCARD (address ":<NodePort>", so every interface and both address
// families answer) that load-balances to the same ready backends as the ClusterIP,
// through the default (non-mesh) dialer. For UDP the ClusterIP datagram relay IS
// built on the specific VIP, but the UDP NodePort stays deferred — nothing is bound
// on the NodePort (a wildcard UDP reply would re-select its source on a
// multi-homed node). The externalTrafficPolicy: Cluster semantics — the userspace
// L4 splice opens a fresh backend connection and so does NOT preserve the client
// source IP, hence Local is not honored — are documented in doc.go and the
// openListener comment. The real-socket version is TestNodePortBindsWildcardReal
// under the integration tag.
func TestNodePortBindsWildcard(t *testing.T) {
	t.Parallel()

	const (
		clusterPort = 80
		nodePort    = 30080
	)
	vip := netip.MustParseAddr("10.43.0.80")
	wantNodeAddr := ":" + strconv.Itoa(nodePort)

	t.Run("tcp NodePort yields a wildcard listener and load-balances", func(t *testing.T) {
		t.Parallel()

		binder := fakeBinder{bound: make(chan *fakeListener, 1)}
		nodeBound := make(chan *fakeListener, 1)
		listenNodePort := func(network, address string) (net.Listener, error) {
			l := newFakeListener(network, address)
			nodeBound <- l
			return l, nil
		}
		var p *Proxy
		backends := &fakeNodePortBackends{
			ids:  map[string]string{"10.42.0.1:8080": "np-1", "10.42.0.2:8080": "np-2"},
			want: func() *tcpseg.Dialer { return p.dialer },
		}
		p = New(NewRoutingTable(netip.Prefix{}),
			withAliasManager(newNoopAliasManager()),
			withBinder(binder),
			withListenNodePort(listenNodePort),
			withDialBackend(backends.dial))

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { defer close(runDone); _ = p.Run(ctx) }()
		defer func() { cancel(); <-runDone }()

		sp := &netv1.ServicePort{Port: clusterPort, TargetPort: 8080, Protocol: netv1.ProtocolTCP, NodePort: nodePort}
		eps := []netv1.Endpoint{
			{IP: "10.42.0.1", Port: 8080, Ready: true},
			{IP: "10.42.0.2", Port: 8080, Ready: true},
		}
		if err := p.Reconcile(vip.String(), sp, eps); err != nil {
			t.Fatalf("reconcile: %v", err)
		}

		var clusterLn, nodeLn *fakeListener
		select {
		case clusterLn = <-binder.bound:
		case <-time.After(fakeHandledTimeout):
			t.Fatal("the ClusterIP listener was never bound")
		}
		select {
		case nodeLn = <-nodeBound:
		case <-time.After(fakeHandledTimeout):
			t.Fatal("the NodePort listener was never bound")
		}
		// The ClusterIP binds the specific VIP; the NodePort binds the wildcard.
		if want := netip.AddrPortFrom(vip, clusterPort).String(); clusterLn.network != "tcp" || clusterLn.address != want {
			t.Fatalf("ClusterIP listener = %s %s, want tcp %s", clusterLn.network, clusterLn.address, want)
		}
		if nodeLn.network != "tcp" || nodeLn.address != wantNodeAddr {
			t.Fatalf("NodePort listener = %s %q, want tcp %q (the wildcard)", nodeLn.network, nodeLn.address, wantNodeAddr)
		}

		// The NodePort listener fans out across both ready backends.
		counts := map[string]int{}
		for i := 0; i < 20; i++ {
			counts[readBackendID(t, nodeLn, len("np-1"))]++
		}
		if counts["np-1"] == 0 || counts["np-2"] == 0 {
			t.Fatalf("NodePort did not load-balance across ready backends: %v", counts)
		}
		if counts["np-1"]+counts["np-2"] != 20 {
			t.Fatalf("NodePort connections lost: %v", counts)
		}
		// Single node, no mesh: every backend dial used the default-source dialer.
		if n := backends.wrongDialers(); n != 0 {
			t.Fatalf("%d backend dials used a dialer other than the default", n)
		}

		// Delete tears the NodePort listener down with the ClusterIP.
		p.ReconcileDelete(PortKey{ClusterIP: vip.String(), Port: clusterPort, Protocol: netv1.ProtocolTCP})
		for name, l := range map[string]*fakeListener{"NodePort": nodeLn, "ClusterIP": clusterLn} {
			select {
			case <-l.done:
			case <-time.After(fakeHandledTimeout):
				t.Fatalf("ReconcileDelete did not close the %s listener", name)
			}
		}
	})

	t.Run("udp NodePort deferred: clusterIP relay built, NodePort not bound", func(t *testing.T) {
		t.Parallel()

		udpBound := make(chan *fakeVIPConn, 1)
		listenUDP := func(ap netip.AddrPort) (udpVIPConn, error) {
			c := newFakeVIPConn(ap)
			udpBound <- c
			return c, nil
		}
		var (
			mu          sync.Mutex
			streamBinds []string
		)
		recordStream := func(what string) {
			mu.Lock()
			defer mu.Unlock()
			streamBinds = append(streamBinds, what)
		}
		listenNodePort := func(network, address string) (net.Listener, error) {
			recordStream("nodePort " + network + " " + address)
			return newFakeListener(network, address), nil
		}
		binder := fakeBinder{bound: make(chan *fakeListener, 1)}
		p := New(NewRoutingTable(netip.Prefix{}),
			withAliasManager(newNoopAliasManager()),
			withBinder(binder),
			withListenUDP(listenUDP),
			withListenNodePort(listenNodePort))

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { defer close(runDone); _ = p.Run(ctx) }()
		defer func() { cancel(); <-runDone }()

		sp := &netv1.ServicePort{Port: 53, TargetPort: 53, Protocol: netv1.ProtocolUDP, NodePort: nodePort}
		eps := []netv1.Endpoint{{IP: "10.42.0.9", Port: 53, Ready: true}}
		if err := p.Reconcile(vip.String(), sp, eps); err != nil {
			t.Fatalf("reconcile udp nodeport: %v", err)
		}

		var conn *fakeVIPConn
		select {
		case conn = <-udpBound:
		case <-time.After(fakeHandledTimeout):
			t.Fatal("the ClusterIP UDP relay was never bound")
		}
		// The relay binds the SPECIFIC VIP, never the wildcard.
		if want := netip.AddrPortFrom(vip, 53); conn.local != want {
			t.Fatalf("UDP relay bound at %v, want exactly %v", conn.local, want)
		}

		// Delete, and wait for the VIP socket to close: openListener has returned and
		// the worker has torn the port down, so every bind it was going to make for
		// this port has been made.
		p.ReconcileDelete(PortKey{ClusterIP: vip.String(), Port: 53, Protocol: netv1.ProtocolUDP})
		select {
		case <-conn.done:
		case <-time.After(fakeHandledTimeout):
			t.Fatal("ReconcileDelete did not close the UDP relay's VIP socket")
		}
		select {
		case l := <-binder.bound:
			recordStream("clusterIP " + l.network + " " + l.address)
		default:
		}
		mu.Lock()
		defer mu.Unlock()
		if len(streamBinds) != 0 {
			t.Fatalf("a UDP NodePort Service opened stream listeners %v (the NodePort must be deferred, and a UDP port never opens TCP)", streamBinds)
		}
	})
}
