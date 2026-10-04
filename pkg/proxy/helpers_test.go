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
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// withAliasManager overrides the alias manager (tests inject the rootless fake).
func withAliasManager(a aliasManager) Option {
	return func(p *Proxy) { p.alias = a }
}

// withListenUDP overrides the ClusterIP datagram bind (tests inject an in-memory
// VIP socket).
func withListenUDP(f func(netip.AddrPort) (udpVIPConn, error)) Option {
	return func(p *Proxy) { p.listenUDP = f }
}

// withBinder overrides the ClusterIP stream binder (tests inject an in-memory
// listener).
func withBinder(b binder) Option {
	return func(p *Proxy) { p.binder = b }
}

// withListenNodePort overrides the wildcard NodePort listen (tests inject an
// in-memory listener).
func withListenNodePort(f func(network, address string) (net.Listener, error)) Option {
	return func(p *Proxy) { p.listenNodePort = f }
}

// withDialBackend overrides the backend dial (tests inject an in-memory backend).
func withDialBackend(f func(d *tcpseg.Dialer, network, address string) (net.Conn, error)) Option {
	return func(p *Proxy) { p.dialBackend = f }
}

// noopAliasManager is the rootless aliasManager unit tests inject: it performs no
// syscalls and records the Ensure/Remove calls so a test can assert the reconcile
// drove the expected sequence without touching lo0. In production the proxy
// aliases VIPs for real (the netd daemon under WithNetdHelper, or the direct lo0
// manager run as root); the rootless tests bind their VIP on 127.0.0.1 — the one
// loopback address bindable without an alias on Darwin — and distinguish VIPs by
// port.
//
// Locking discipline: ensured is guarded by mu; Ensure/Remove and the test
// accessors all take it.
type noopAliasManager struct {
	mu      sync.Mutex
	ensured map[netip.Addr]int
	removed map[netip.Addr]int
}

// newNoopAliasManager returns a rootless aliasManager that performs no syscalls.
func newNoopAliasManager() *noopAliasManager {
	return &noopAliasManager{
		ensured: make(map[netip.Addr]int),
		removed: make(map[netip.Addr]int),
	}
}

// Ensure records the call and succeeds without touching the interface.
func (m *noopAliasManager) Ensure(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensured[ip]++
	return nil
}

// Remove records the call and succeeds without touching the interface.
func (m *noopAliasManager) Remove(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed[ip]++
	return nil
}

// ensures reports how many times Ensure was called for ip (test accessor).
func (m *noopAliasManager) ensures(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensured[ip]
}

// removes reports how many times Remove was called for ip (test accessor).
func (m *noopAliasManager) removes(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removed[ip]
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

// tcpPipeConn is one end of a net.Pipe that reports TCP addresses. The accept
// path reads the client's source from RemoteAddr (clientAddr feeds ClientIP
// affinity and the NetworkPolicy verdict), and a bare pipe reports "pipe", which
// parses to the zero Addr and would test a different source than the one named.
type tcpPipeConn struct {
	net.Conn
	local, remote *net.TCPAddr
}

func (c tcpPipeConn) LocalAddr() net.Addr  { return c.local }
func (c tcpPipeConn) RemoteAddr() net.Addr { return c.remote }

// connectFrom opens one connection to the listener from src and returns its
// client end. The end the proxy accepts reports src as its RemoteAddr and the
// listener's address as its LocalAddr, as an accepted TCP conn does.
func (l *fakeListener) connectFrom(t *testing.T, src netip.AddrPort) net.Conn {
	t.Helper()
	local, err := netip.ParseAddrPort(l.address)
	if err != nil {
		t.Fatalf("fake listener address %q: %v", l.address, err)
	}
	client, server := net.Pipe()
	accepted := tcpPipeConn{Conn: server, local: net.TCPAddrFromAddrPort(local), remote: net.TCPAddrFromAddrPort(src)}
	select {
	case l.conns <- accepted:
		return client
	case <-l.done:
		t.Fatalf("connect to %s %s: listener closed", l.network, l.address)
	case <-time.After(fakeHandledTimeout):
		t.Fatalf("connect to %s %s: never accepted", l.network, l.address)
	}
	return nil
}

// recordingBinder is an in-memory binder that never blocks a reconcile: each
// Listen opens a fakeListener at the requested address and records it, and
// waitBound hands the test the n-th listener once it exists.
//
// Locking discipline: ls is guarded by mu; notify is a 1-slot wake-up channel
// that Listen signals without blocking.
type recordingBinder struct {
	mu     sync.Mutex
	ls     []*fakeListener
	notify chan struct{}
}

func newRecordingBinder() *recordingBinder {
	return &recordingBinder{notify: make(chan struct{}, 1)}
}

// Listen opens and records a fake listener at addr.
func (b *recordingBinder) Listen(_ context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	l := newFakeListener(network, addr.String())
	b.mu.Lock()
	b.ls = append(b.ls, l)
	b.mu.Unlock()
	select {
	case b.notify <- struct{}{}:
	default:
	}
	return l, nil
}

// count reports how many listeners have been bound.
func (b *recordingBinder) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.ls)
}

// addrs reports the address of every listener bound, in order.
func (b *recordingBinder) addrs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.ls))
	for i, l := range b.ls {
		out[i] = l.address
	}
	return out
}

// waitBound blocks until at least n listeners have been bound and returns the
// n-th (1-based).
func (b *recordingBinder) waitBound(t *testing.T, n int) *fakeListener {
	t.Helper()
	timeout := time.After(fakeHandledTimeout)
	for {
		b.mu.Lock()
		if len(b.ls) >= n {
			l := b.ls[n-1]
			b.mu.Unlock()
			return l
		}
		b.mu.Unlock()
		select {
		case <-b.notify:
		case <-timeout:
			t.Fatalf("listener %d was never bound (have %d)", n, b.count())
		}
	}
}

// waitListenerClosed blocks until the proxy has closed l.
func waitListenerClosed(t *testing.T, l *fakeListener) {
	t.Helper()
	select {
	case <-l.done:
	case <-time.After(fakeHandledTimeout):
		t.Fatalf("listener %s %s was never closed", l.network, l.address)
	}
}

// fakeTCPNet stands in for the backends behind dialBackend: a dial to a
// registered address returns a pipe whose far end writes that backend's id and
// closes; a dial anywhere else is refused, as a closed port is. Pass its dial to
// withDialBackend.
//
// Locking discipline: backends is written only by add, before the proxy can
// dial; the per-backend accept counters are atomics.
type fakeTCPNet struct {
	backends map[netip.AddrPort]*fakeTCPBackend
}

func newFakeTCPNet() *fakeTCPNet {
	return &fakeTCPNet{backends: map[netip.AddrPort]*fakeTCPBackend{}}
}

// fakeTCPBackend is one registered backend.
type fakeTCPBackend struct {
	ap      netip.AddrPort
	id      string
	accepts atomic.Int32
}

// add registers a backend at addr ("ip:port") that writes id to every
// connection.
func (n *fakeTCPNet) add(t *testing.T, addr, id string) *fakeTCPBackend {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("fake backend address %q: %v", addr, err)
	}
	b := &fakeTCPBackend{ap: ap, id: id}
	n.backends[ap] = b
	return b
}

// dial matches Proxy.dialBackend.
func (n *fakeTCPNet) dial(_ *tcpseg.Dialer, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	b, ok := n.backends[ap]
	if err != nil || !ok || network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	b.accepts.Add(1)
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		_, _ = io.WriteString(far, b.id)
	}()
	return near, nil
}

// addrPort returns the backend's address.
func (b *fakeTCPBackend) addrPort() netip.AddrPort { return b.ap }

// endpoint returns the backend as a Ready netv1.Endpoint for the routing table.
func (b *fakeTCPBackend) endpoint() netv1.Endpoint {
	return netv1.Endpoint{IP: b.ap.Addr().String(), Port: int32(b.ap.Port()), Ready: true}
}
