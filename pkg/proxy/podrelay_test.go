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
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// relayBackends stands in for the guests behind the relay's live-side dial: a dial
// to a registered address returns a pipe whose far end writes that backend's
// banner and then HOLDS the connection open until either side closes it, so a test
// can observe the relay closing an established connection. A dial anywhere else is
// refused, as a closed port is.
//
// Locking discipline: backends is written only by add, before the proxy can dial;
// the counters and the closed channels are safe for concurrent use.
type relayBackends struct {
	backends map[netip.AddrPort]*relayBackend
}

// relayBackend is one registered guest listener.
type relayBackend struct {
	banner  string
	accepts atomic.Int32
	// closed receives once per accepted connection when its far end sees the
	// relay close the connection.
	closed chan struct{}
}

func newRelayBackends() *relayBackends {
	return &relayBackends{backends: map[netip.AddrPort]*relayBackend{}}
}

// add registers a backend at addr ("ip:port") that greets with banner.
func (n *relayBackends) add(t *testing.T, addr, banner string) *relayBackend {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("backend address %q: %v", addr, err)
	}
	b := &relayBackend{banner: banner, closed: make(chan struct{}, 16)}
	n.backends[ap] = b
	return b
}

// dial matches Proxy.dialBackend.
func (n *relayBackends) dial(_ *tcpseg.Dialer, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	b, ok := n.backends[ap]
	if err != nil || !ok || network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	b.accepts.Add(1)
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		if _, err := io.WriteString(far, b.banner); err != nil {
			b.closed <- struct{}{}
			return
		}
		_, _ = io.Copy(io.Discard, far)
		b.closed <- struct{}{}
	}()
	return near, nil
}

// relayHarness is a running Proxy over in-memory sockets.
type relayHarness struct {
	p   *Proxy
	tbl *RoutingTable
	b   *recordingBinder
}

// newRelayHarness builds and runs a Proxy whose relay binds through an in-memory
// binder and dials through dial; Run is stopped and joined at cleanup.
func newRelayHarness(t *testing.T, vmnet netip.Prefix, dial func(*tcpseg.Dialer, string, string) (net.Conn, error), opts ...Option) *relayHarness {
	t.Helper()
	tbl := NewRoutingTable(netip.Prefix{})
	b := newRecordingBinder()
	base := []Option{
		withAliasManager(newNoopAliasManager()),
		withBinder(b),
		withDialBackend(dial),
		WithVMNetPrefix(vmnet),
		WithLogger(slog.New(slog.DiscardHandler)),
	}
	p := New(tbl, append(base, opts...)...)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &relayHarness{p: p, tbl: tbl, b: b}
}

// settle runs one reconcile pass synchronously over the current generation, so a
// test can assert what the relay did NOT open without sleeping.
func (h *relayHarness) settle(t *testing.T) {
	t.Helper()
	h.p.relays.reconcile(context.Background(), h.tbl.load())
}

// boundAt waits for a listener at addr and returns the newest one there.
func (b *recordingBinder) boundAt(t *testing.T, addr string) *fakeListener {
	t.Helper()
	deadline := time.After(fakeHandledTimeout)
	for {
		b.mu.Lock()
		for i := len(b.ls) - 1; i >= 0; i-- {
			if l := b.ls[i]; l.address == addr && !l.isClosed() {
				b.mu.Unlock()
				return l
			}
		}
		b.mu.Unlock()
		select {
		case <-b.notify:
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatalf("no open listener at %s was bound (bound: %v)", addr, b.addrs())
		}
	}
}

// isClosed reports whether the proxy has closed l.
func (l *fakeListener) isClosed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// readBanner reads want's length from c and reports what arrived.
func readBanner(t *testing.T, c net.Conn, want string) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(fakeHandledTimeout))
	buf := make([]byte, len(want))
	n, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("read banner: got %q: %v", buf[:n], err)
	}
	return string(buf)
}

// expectClosed asserts the relay closed c without sending anything.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(fakeHandledTimeout))
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if err == nil || n != 0 {
		t.Fatalf("read on a refused connection = %d bytes, err %v; want the relay to close it", n, err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		t.Fatalf("refused connection was never closed: %v", err)
	}
}

// TestPublishedVMPodAddressRelaysToLive is the B440 gate: a vm pod's PUBLISHED
// address (::1 here) is served on the pod's node and every accepted connection is
// relayed to its LIVE lease address (127.0.0.1) on the same port. Before B440 the
// published address was live on no interface and nothing listened on it, so a
// dial was refused.
func TestPublishedVMPodAddressRelaysToLive(t *testing.T) {
	published := netip.MustParseAddr("::1")
	live := netip.MustParseAddr("127.0.0.1")
	const port = 8080

	backends := newRelayBackends()
	guest := backends.add(t, "127.0.0.1:8080", "hello from the guest")
	h := newRelayHarness(t, netip.MustParsePrefix("127.0.0.1/32"), backends.dial)

	h.tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{published: {Live: live, Ports: []uint16{port}}})
	ln := h.b.boundAt(t, netip.AddrPortFrom(published, port).String())

	c := ln.connectFrom(t, netip.MustParseAddrPort("[::1]:50000"))
	defer c.Close()
	if got := readBanner(t, c, guest.banner); got != guest.banner {
		t.Fatalf("relayed banner = %q, want %q", got, guest.banner)
	}
	if got := guest.accepts.Load(); got != 1 {
		t.Fatalf("live backend accepted %d connections, want 1", got)
	}
}

// TestPodRelayPortSet proves the relay listens on exactly the pod's declared
// ports plus the ports a TCP Service targets at its published address, and on
// nothing else: an undeclared non-Service port gets no listener (a dial is
// refused), and a UDP Service port is not relayed.
func TestPodRelayPortSet(t *testing.T) {
	published := netip.MustParseAddr("100.64.0.7")
	live := netip.MustParseAddr("192.168.64.5")
	h := newRelayHarness(t, netip.MustParsePrefix("192.168.64.0/24"), newRelayBackends().dial)

	h.tbl.SetEndpoints(PortKey{ClusterIP: "10.43.0.20", Port: 80, Protocol: netv1.ProtocolTCP},
		[]netv1.Endpoint{{IP: published.String(), Port: 9090, Ready: true}})
	h.tbl.SetEndpoints(PortKey{ClusterIP: "10.43.0.21", Port: 53, Protocol: netv1.ProtocolUDP},
		[]netv1.Endpoint{{IP: published.String(), Port: 5353, Ready: true}})
	h.tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{published: {Live: live, Ports: []uint16{8080}}})
	h.b.boundAt(t, "100.64.0.7:8080")
	h.b.boundAt(t, "100.64.0.7:9090")
	h.settle(t)

	got := slices.Sorted(slices.Values(h.b.addrs()))
	got = slices.Compact(got)
	if want := []string{"100.64.0.7:8080", "100.64.0.7:9090"}; !slices.Equal(got, want) {
		t.Fatalf("relay bound %v, want exactly %v (declared + Service-targeted TCP; not 5353/udp, not an undeclared port)", got, want)
	}

	// A Service port that goes away takes its listener with it.
	h.tbl.Delete(PortKey{ClusterIP: "10.43.0.20", Port: 80, Protocol: netv1.ProtocolTCP})
	h.settle(t)
	for _, l := range h.b.ls {
		if l.address == "100.64.0.7:9090" && !l.isClosed() {
			t.Fatal("the Service-targeted listener stayed open after its Service port was deleted")
		}
	}
}

// TestPodRelayRefusesClients proves the two per-connection refusals: a client
// inside the vmnet segment (a guest reaching a sibling, or itself, through the
// host) and a client the NetworkPolicy verdict denies. Both close the connection
// before any live-side dial.
func TestPodRelayRefusesClients(t *testing.T) {
	published := netip.MustParseAddr("100.64.0.7")
	live := netip.MustParseAddr("192.168.64.5")
	denied := netip.MustParseAddr("100.64.1.7")

	policy := NewPolicyTable()
	policy.Update(map[netip.Addr][]PolicyRule{published: {}}, map[netip.Addr]struct{}{denied: {}})

	backends := newRelayBackends()
	guest := backends.add(t, "192.168.64.5:8080", "guest")
	h := newRelayHarness(t, netip.MustParsePrefix("192.168.64.0/24"), backends.dial, WithPolicyTable(policy))
	h.tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{published: {Live: live, Ports: []uint16{8080}}})
	ln := h.b.boundAt(t, "100.64.0.7:8080")

	for _, tc := range []struct {
		name string
		src  string
	}{
		{"a guest on the vmnet segment", "192.168.64.9:40000"},
		{"the pod's own lease", "192.168.64.5:40000"},
		{"a source the policy denies", "100.64.1.7:40000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ln.connectFrom(t, netip.MustParseAddrPort(tc.src))
			defer c.Close()
			expectClosed(t, c)
		})
	}
	if got := guest.accepts.Load(); got != 0 {
		t.Fatalf("live backend accepted %d connections from refused clients, want 0", got)
	}

	// The relay still serves an admitted client after the refusals.
	c := ln.connectFrom(t, netip.MustParseAddrPort("100.64.0.1:40000"))
	defer c.Close()
	if got := readBanner(t, c, guest.banner); got != guest.banner {
		t.Fatalf("admitted client banner = %q, want %q", got, guest.banner)
	}
}

// TestPodRelayRefusesOverrides proves an override the node must not act on
// installs no relay at all: the guest reports its own lease, so the node never
// becomes a dialer to an address outside its vmnet segment, to the segment's
// gateway or broadcast, to the pod's own published address, or to a lease two
// pods claim — and a node with no vmnet segment relays nothing.
func TestPodRelayRefusesOverrides(t *testing.T) {
	vmnet := netip.MustParsePrefix("192.168.64.0/24")
	pubA := netip.MustParseAddr("100.64.0.7")
	pubB := netip.MustParseAddr("100.64.0.8")
	for _, tc := range []struct {
		name      string
		vmnet     netip.Prefix
		overrides map[netip.Addr]VMPodTransport
	}{
		{"live outside the vmnet segment", vmnet, map[netip.Addr]VMPodTransport{pubA: {Live: netip.MustParseAddr("10.0.0.5"), Ports: []uint16{80}}}},
		{"live is the vmnet gateway", vmnet, map[netip.Addr]VMPodTransport{pubA: {Live: netip.MustParseAddr("192.168.64.1"), Ports: []uint16{80}}}},
		{"live is the vmnet broadcast", vmnet, map[netip.Addr]VMPodTransport{pubA: {Live: netip.MustParseAddr("192.168.64.255"), Ports: []uint16{80}}}},
		{"live is the vmnet network address", vmnet, map[netip.Addr]VMPodTransport{pubA: {Live: netip.MustParseAddr("192.168.64.0"), Ports: []uint16{80}}}},
		{"live equals published", netip.MustParsePrefix("127.0.0.1/32"), map[netip.Addr]VMPodTransport{netip.MustParseAddr("127.0.0.1"): {Live: netip.MustParseAddr("127.0.0.1"), Ports: []uint16{80}}}},
		{"two pods claim one lease", vmnet, map[netip.Addr]VMPodTransport{
			pubA: {Live: netip.MustParseAddr("192.168.64.5"), Ports: []uint16{80}},
			pubB: {Live: netip.MustParseAddr("192.168.64.5"), Ports: []uint16{80}},
		}},
		{"no vmnet segment configured", netip.Prefix{}, map[netip.Addr]VMPodTransport{pubA: {Live: netip.MustParseAddr("192.168.64.5"), Ports: []uint16{80}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRelayHarness(t, tc.vmnet, newRelayBackends().dial)
			h.tbl.SetTransportOverrides(tc.overrides)
			h.settle(t)
			if n := h.b.count(); n != 0 {
				t.Fatalf("refused override bound %d listener(s): %v", n, h.b.addrs())
			}
		})
	}
}

// TestPodRelayFollowsReplaceAndDrop proves the relay's lifetime is the override's:
// a re-lease is relayed to the NEW live address (distinct banners), and both a
// replace and a drop close the old listener and every connection it was relaying
// before SetTransportOverrides returns — the ordering that lets the caller remove
// the pod's alias next.
func TestPodRelayFollowsReplaceAndDrop(t *testing.T) {
	published := netip.MustParseAddr("100.64.0.7")
	backends := newRelayBackends()
	first := backends.add(t, "192.168.64.5:8080", "first lease")
	second := backends.add(t, "192.168.64.6:8080", "second lease")
	h := newRelayHarness(t, netip.MustParsePrefix("192.168.64.0/24"), backends.dial)

	h.tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{published: {Live: netip.MustParseAddr("192.168.64.5"), Ports: []uint16{8080}}})
	ln1 := h.b.boundAt(t, "100.64.0.7:8080")
	c1 := ln1.connectFrom(t, netip.MustParseAddrPort("100.64.0.1:40000"))
	defer c1.Close()
	if got := readBanner(t, c1, first.banner); got != first.banner {
		t.Fatalf("banner = %q, want %q", got, first.banner)
	}

	h.tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{published: {Live: netip.MustParseAddr("192.168.64.6"), Ports: []uint16{8080}}})
	if !ln1.isClosed() {
		t.Fatal("the old lease's listener was still open when SetTransportOverrides returned")
	}
	expectClosed(t, c1)
	waitBackendClosed(t, first)

	ln2 := h.b.boundAt(t, "100.64.0.7:8080")
	c2 := ln2.connectFrom(t, netip.MustParseAddrPort("100.64.0.1:40001"))
	defer c2.Close()
	if got := readBanner(t, c2, second.banner); got != second.banner {
		t.Fatalf("after re-lease banner = %q, want %q", got, second.banner)
	}

	h.tbl.SetTransportOverrides(nil)
	if !ln2.isClosed() {
		t.Fatal("the dropped pod's listener was still open when SetTransportOverrides returned")
	}
	expectClosed(t, c2)
	waitBackendClosed(t, second)
	h.settle(t)
	for _, l := range h.b.ls {
		if !l.isClosed() {
			t.Fatalf("listener %s open after the drop", l.address)
		}
	}
}

// waitBackendClosed waits for the live side of one relayed connection to close.
func waitBackendClosed(t *testing.T, b *relayBackend) {
	t.Helper()
	select {
	case <-b.closed:
	case <-time.After(fakeHandledTimeout):
		t.Fatalf("the live-side connection to %q was never closed", b.banner)
	}
}

// TestPodRelayNoLeak proves a relay that served connections leaves no goroutine
// and no listener behind once its pod is dropped and the proxy stops.
func TestPodRelayNoLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	func() {
		backends := newRelayBackends()
		guest := backends.add(t, "192.168.64.5:8080", "guest")
		tbl := NewRoutingTable(netip.Prefix{})
		b := newRecordingBinder()
		p := New(tbl, withAliasManager(newNoopAliasManager()), withBinder(b), withDialBackend(backends.dial),
			WithVMNetPrefix(netip.MustParsePrefix("192.168.64.0/24")), WithLogger(slog.New(slog.DiscardHandler)))
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Run(ctx)
		}()
		tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{netip.MustParseAddr("100.64.0.7"): {Live: netip.MustParseAddr("192.168.64.5"), Ports: []uint16{8080, 8081}}})
		ln := b.boundAt(t, "100.64.0.7:8080")
		b.boundAt(t, "100.64.0.7:8081")
		var conns []net.Conn
		for i := range 3 {
			c := ln.connectFrom(t, netip.AddrPortFrom(netip.MustParseAddr("100.64.0.1"), uint16(40000+i)))
			readBanner(t, c, guest.banner)
			conns = append(conns, c)
		}
		// One connection stays open across the stop: shutdown must close it.
		tbl.SetTransportOverrides(nil)
		for _, c := range conns {
			expectClosed(t, c)
			_ = c.Close()
		}
		tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{netip.MustParseAddr("100.64.0.8"): {Live: netip.MustParseAddr("192.168.64.6"), Ports: []uint16{80}}})
		b.boundAt(t, "100.64.0.8:80")
		cancel()
		wg.Wait()
		for _, l := range b.ls {
			if !l.isClosed() {
				t.Fatalf("listener %s open after the proxy stopped", l.address)
			}
		}
		if n := len(p.relays.relays); n != 0 {
			t.Fatalf("%d relays still registered after the proxy stopped", n)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines: %d before, %d after — the relay leaked", before, after)
	}
}

// TestPodRelayStaleGenerationInstallsNothing proves a reconcile pass that loaded a
// generation the caller has since replaced installs nothing from it: the dropped
// pod's relay must not be resurrected after SetTransportOverrides(nil) returned.
func TestPodRelayStaleGenerationInstallsNothing(t *testing.T) {
	tbl := NewRoutingTable(netip.Prefix{})
	b := newRecordingBinder()
	p := New(tbl, withAliasManager(newNoopAliasManager()), withBinder(b), withDialBackend(newRelayBackends().dial),
		WithVMNetPrefix(netip.MustParsePrefix("192.168.64.0/24")), WithLogger(slog.New(slog.DiscardHandler)))
	tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{netip.MustParseAddr("100.64.0.7"): {Live: netip.MustParseAddr("192.168.64.5"), Ports: []uint16{8080}}})
	stale := tbl.load()
	tbl.SetTransportOverrides(nil)
	p.relays.reconcile(context.Background(), stale)
	if n := b.count(); n != 0 {
		t.Fatalf("a stale generation bound %d listener(s): %v", n, b.addrs())
	}
	p.relays.shutdown()
}

// TestVMNetPrefixFallsBackToPolicySeed proves an assembler that seeded the policy
// table with the vmnet segment gets the same segment on the relay without saying
// it twice, and that an explicit WithVMNetPrefix wins.
func TestVMNetPrefixFallsBackToPolicySeed(t *testing.T) {
	seed := netip.MustParsePrefix("192.168.64.0/24")
	p := New(NewRoutingTable(netip.Prefix{}), WithPolicyTable(NewPolicyTableVMNet(seed)))
	if p.relays.vmnet != seed {
		t.Fatalf("relay vmnet = %s, want the policy seed %s", p.relays.vmnet, seed)
	}
	explicit := netip.MustParsePrefix("192.168.65.0/24")
	p = New(NewRoutingTable(netip.Prefix{}), WithPolicyTable(NewPolicyTableVMNet(seed)), WithVMNetPrefix(explicit))
	if p.relays.vmnet != explicit {
		t.Fatalf("relay vmnet = %s, want the explicit %s", p.relays.vmnet, explicit)
	}
	if p.relays.gateway != netip.MustParseAddr("192.168.65.1") || p.relays.broadcast != netip.MustParseAddr("192.168.65.255") {
		t.Fatalf("derived gateway/broadcast = %s/%s, want 192.168.65.1/192.168.65.255", p.relays.gateway, p.relays.broadcast)
	}
}
