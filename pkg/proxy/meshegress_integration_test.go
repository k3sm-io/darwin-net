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

// The mesh-egress test that needs real conns: the splice signals end-of-stream
// with CloseWrite, which a pipe does not implement, so concurrent scoped dials
// are driven through real loopback VIP listeners and backends. The scoping
// decision itself is table-tested in meshegress_test.go. It needs no privilege;
// run with:
//
//	CGO_ENABLED=0 go test -tags integration -run '^TestProxyConcurrentScopedDialsShareNoDialerState$' ./pkg/proxy/

package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// TestProxyConcurrentScopedDialsShareNoDialerState is the -race leg the plan's
// gate paragraph requires: local- and remote-destination dials IN FLIGHT together
// through one shared Proxy. The containment being proven is a per-connection
// shared-state property — a sequential round trip cannot exercise it, and the
// pre-M14.2 shape (one dialer whose LocalAddr is written per destination) would
// both trip the race detector here and non-deterministically apply one
// connection's source to another's dial.
//
// macOS note: only 127.0.0.1 is bindable without a root-created lo0 alias, so
// both backends listen there and the two localities are produced by the
// classifier rather than by distinct real addresses — the node /24 is 127.1.0.0/24
// inside a 127.0.0.0/8 aggregate, which makes the real 127.0.0.1 listener
// LocalityRemote (bound path), while the local backend is published inside the
// node /24 and reaches the same loopback via a transport override (unbound path).
func TestProxyConcurrentScopedDialsShareNoDialerState(t *testing.T) {
	t.Parallel()
	var (
		aggregate = netip.MustParsePrefix("127.0.0.0/8")
		nodeCIDR  = netip.MustParsePrefix("127.1.0.0/24")
		egressIP  = netip.MustParseAddr("127.0.0.1")
		published = netip.MustParseAddr("127.1.0.5")
	)

	localBE := newEchoBackend(t, "local-backend", "127.0.0.1")
	defer localBE.close()
	remoteBE := newEchoBackend(t, "remote-backend", "127.0.0.1")
	defer remoteBE.close()
	_, localPort := localBE.addrPort()
	remoteIP, remotePort := remoteBE.addrPort()

	table := NewRoutingTable(nodeCIDR)
	localKey := PortKey{ClusterIP: "127.1.0.1", Port: 8080, Protocol: netv1.ProtocolTCP}
	remoteKey := PortKey{ClusterIP: "127.1.0.1", Port: 8081, Protocol: netv1.ProtocolTCP}
	// The local backend is published inside the node /24 (LocalityLocal) and its
	// packets follow a transport override to the real loopback listener; the remote
	// backend is published at a real loopback address that the classifier sees as
	// outside the node /24 but inside the aggregate (LocalityRemote).
	table.SetEndpoints(localKey, []netv1.Endpoint{{IP: published.String(), Port: localPort, Ready: true}})
	table.SetEndpoints(remoteKey, []netv1.Endpoint{{IP: remoteIP, Port: remotePort, Ready: true}})
	table.SetTransportOverrides(map[netip.Addr]netip.Addr{published: netip.MustParseAddr("127.0.0.1")})

	p := New(table,
		WithMeshEgressSource(egressIP),
		WithClusterPodCIDR(aggregate),
		withAliasManager(newNoopAliasManager()),
		WithLogger(slog.New(slog.DiscardHandler)),
	)
	// Premise check: the two keys really do land on opposite sides of the scoping
	// decision, so the concurrent run below mixes a bound and an unbound dial.
	if be, err := table.PickAt(localKey, 0); err != nil {
		t.Fatalf("pick local: %v", err)
	} else if got := p.egress.sourceFor(be.Locality(), netip.MustParseAddr("127.0.0.1")); got.IsValid() {
		t.Fatalf("local backend elected source %s, want kernel default", got)
	}
	if be, err := table.PickAt(remoteKey, 0); err != nil {
		t.Fatalf("pick remote: %v", err)
	} else if got := p.egress.sourceFor(be.Locality(), netip.MustParseAddr(remoteIP)); got != egressIP {
		t.Fatalf("remote backend elected source %v, want %s", got, egressIP)
	}

	// Real VIP listeners, not net.Pipe: the splice signals end-of-stream with
	// CloseWrite, which a pipe does not implement, so only a real conn lets a
	// client read to EOF the way a pod does.
	localVIP := servePort(t, p, localKey)
	remoteVIP := servePort(t, p, remoteKey)

	const iterations = 24
	errCh := make(chan error, 2*iterations)
	var wg sync.WaitGroup
	fetch := func(vip string, key PortKey, wantID string) {
		defer wg.Done()
		c, err := net.DialTimeout("tcp", vip, 10*time.Second)
		if err != nil {
			errCh <- fmt.Errorf("%s: dial vip: %w", key, err)
			return
		}
		defer c.Close()
		if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			errCh <- err
			return
		}
		got, err := io.ReadAll(c)
		if err != nil {
			errCh <- fmt.Errorf("%s: read: %w", key, err)
			return
		}
		if string(got) != wantID {
			errCh <- fmt.Errorf("%s: steered to %q, want %q", key, got, wantID)
		}
	}
	for range iterations {
		wg.Add(2)
		go fetch(localVIP, localKey, "local-backend")
		go fetch(remoteVIP, remoteKey, "remote-backend")
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Neither dialer was mutated by any of the concurrent dials: the default one
	// still selects the kernel source, the mesh one still carries exactly the
	// mesh-egress /32.
	if p.dialer.LocalAddr != nil {
		t.Fatalf("p.dialer.LocalAddr = %#v after concurrent dials, want nil", p.dialer.LocalAddr)
	}
	la, ok := p.meshDialer.LocalAddr.(*net.TCPAddr)
	if !ok || !la.IP.Equal(net.IP(egressIP.AsSlice())) {
		t.Fatalf("p.meshDialer.LocalAddr = %#v after concurrent dials, want %s", p.meshDialer.LocalAddr, egressIP)
	}
}

// servePort binds a loopback VIP listener for key and runs the proxy's TCP accept
// loop on it, returning the host:port a client dials. The listener is closed at
// test cleanup, which is what stops the serve goroutine.
func servePort(t *testing.T, p *Proxy, key PortKey) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen vip: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go p.serve(ln, key, internalListener)
	return ln.Addr().String()
}
