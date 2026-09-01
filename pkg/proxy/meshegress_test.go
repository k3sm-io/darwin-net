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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/darwin-net/pkg/podnet"
)

// nodePodCIDR is the node /24 the scoping tests classify against (node index 3 of
// the default cluster aggregate), and meshSource is the mesh-egress /32 derived
// from it — the same podnet.MeshEgressIP derivation production uses.
var (
	nodePodCIDR = netip.MustParsePrefix("100.64.3.0/24")
	meshSource  = netip.MustParseAddr("100.64.3.1")
)

// scopeCase is one destination-scoping decision: a picked backend's precomputed
// locality plus the address the dial actually uses, against the source the dial
// must bind (the zero Addr meaning kernel default selection).
type scopeCase struct {
	name string
	loc  Locality
	dst  netip.Addr
	// scope overrides the default scope (mesh source set, default cluster
	// aggregate) for the cases that vary it; the zero value uses the default.
	scope *egressScope
	want  netip.Addr
}

// defaultScope is the production posture on a mesh node: this node's mesh-egress
// /32 plus the default cluster pod aggregate.
func defaultScope() egressScope {
	return egressScope{src: meshSource, clusterCIDR: podnet.ClusterPodCIDR}
}

// scopeCases is the shared decision table: the SAME cases drive the pure
// predicate, the TCP dialer selection, and the UDP relay's per-flow source, so
// the two protocols cannot be proven to different standards (M14.2-d1 requires
// identical scoping for both).
func scopeCases() []scopeCase {
	return []scopeCase{
		{
			name: "pod on another node binds the mesh source",
			loc:  LocalityRemote,
			dst:  netip.MustParseAddr("100.64.7.5"),
			want: meshSource,
		},
		{
			name: "v4-mapped pod on another node binds the mesh source",
			loc:  LocalityRemote,
			dst:  netip.MustParseAddr("::ffff:100.64.7.5"),
			want: meshSource,
		},
		{
			name: "same-node pod keeps kernel default selection",
			loc:  LocalityLocal,
			dst:  netip.MustParseAddr("100.64.3.9"),
		},
		{
			name: "loopback backend keeps kernel default selection",
			loc:  LocalityRemote,
			dst:  netip.MustParseAddr("127.0.0.1"),
		},
		{
			// A hostNetwork pod reports podIP == nodeIP: the reply would route back
			// over the peer's utun and wireguard would drop it as outside the
			// sender's AllowedIPs. This is the latent worker-side blackhole the
			// unconditional construction-time bind carried.
			name: "node LAN destination keeps kernel default selection",
			loc:  LocalityRemote,
			dst:  netip.MustParseAddr("192.168.1.50"),
		},
		{
			// The ClusterIP VIP itself is never a dial destination (the proxy dials
			// the picked backend), but a Service VIP handed to the proxy as a
			// backend address must not be bound either: it is outside the pod
			// aggregate.
			name: "ClusterIP VIP keeps kernel default selection",
			loc:  LocalityRemote,
			dst:  netip.MustParseAddr("10.43.0.42"),
		},
		{
			name: "upstream address keeps kernel default selection",
			loc:  LocalityRemote,
			dst:  netip.MustParseAddr("1.1.1.1"),
		},
		{
			// R6: the zero/invalid node-podCIDR state fails to the kernel default,
			// never to a bind — a node that cannot classify its own backends must
			// not assert a source for them.
			name: "unknown locality never binds even for a cluster pod IP",
			loc:  LocalityUnknown,
			dst:  netip.MustParseAddr("100.64.7.5"),
		},
		{
			name: "unknown locality never binds for an own-CIDR address",
			loc:  LocalityUnknown,
			dst:  netip.MustParseAddr("100.64.3.9"),
		},
		{
			name:  "single node (no mesh source) never binds",
			loc:   LocalityRemote,
			dst:   netip.MustParseAddr("100.64.7.5"),
			scope: &egressScope{clusterCIDR: podnet.ClusterPodCIDR},
		},
		{
			name:  "invalid cluster aggregate never binds",
			loc:   LocalityRemote,
			dst:   netip.MustParseAddr("100.64.7.5"),
			scope: &egressScope{src: meshSource},
		},
		{
			name:  "non-default cluster aggregate binds inside itself",
			loc:   LocalityRemote,
			dst:   netip.MustParseAddr("10.42.5.5"),
			scope: &egressScope{src: meshSource, clusterCIDR: netip.MustParsePrefix("10.42.0.0/16")},
			want:  meshSource,
		},
		{
			name:  "non-default cluster aggregate does not bind outside itself",
			loc:   LocalityRemote,
			dst:   netip.MustParseAddr("100.64.7.5"),
			scope: &egressScope{src: meshSource, clusterCIDR: netip.MustParsePrefix("10.42.0.0/16")},
		},
		{
			name: "IPv6 destination keeps kernel default selection",
			loc:  LocalityRemote,
			dst:  netip.MustParseAddr("2001:db8::1"),
		},
		{
			name: "invalid destination keeps kernel default selection",
			loc:  LocalityRemote,
			dst:  netip.Addr{},
		},
	}
}

// scope returns the case's scope, defaulting to the production mesh posture.
func (c scopeCase) resolved() egressScope {
	if c.scope != nil {
		return *c.scope
	}
	return defaultScope()
}

// TestEgressScopeSourceFor is the central scoping table (M14.2-d1): the
// mesh-egress source is bound ONLY for a destination inside the cluster pod
// aggregate that is outside this node's own /24 (LocalityRemote). Every other
// destination — same-node pod, loopback, node LAN, a Service VIP, upstream — and
// every LocalityUnknown backend keeps the kernel's default source selection, as
// does a single node with no mesh source at all.
//
// It is the predicate both protocols share, so a regression here is a regression
// in the TCP dial and in every UDP relay at once.
func TestEgressScopeSourceFor(t *testing.T) {
	t.Parallel()
	for _, tc := range scopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.resolved().sourceFor(tc.loc, tc.dst)
			if got != tc.want {
				t.Fatalf("sourceFor(%v, %s) = %v, want %v", tc.loc, tc.dst, got, tc.want)
			}
		})
	}
}

// TestProxyDialerForAppliesEgressScope proves the TCP dial path applies the
// scoping table by SELECTING between two immutable dialers — the mesh-bound one
// only when the scope elects a bind — and that the shared default dialer's
// LocalAddr is never written, which is the property that makes the shared dialer
// safe across the per-connection handle goroutines.
func TestProxyDialerForAppliesEgressScope(t *testing.T) {
	t.Parallel()
	for _, tc := range scopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sc := tc.resolved()
			opts := []Option{withAliasManager(newNoopAliasManager()), WithLogger(slog.New(slog.DiscardHandler))}
			opts = append(opts, WithMeshEgressSource(sc.src), WithClusterPodCIDR(sc.clusterCIDR))
			p := New(NewRoutingTable(nodePodCIDR), opts...)
			// WithClusterPodCIDR ignores an invalid prefix (New re-defaults), so the
			// "invalid cluster aggregate" case is expressed on the proxy by pointing
			// the aggregate somewhere the destination cannot fall.
			if !sc.clusterCIDR.IsValid() {
				p.egress.clusterCIDR = netip.Prefix{}
			}

			d := p.dialerFor(tc.loc, tc.dst)
			if tc.want.IsValid() {
				if d != p.meshDialer {
					t.Fatalf("dialerFor(%v, %s) returned the default dialer, want the mesh-bound dialer", tc.loc, tc.dst)
				}
				la, ok := d.LocalAddr.(*net.TCPAddr)
				if !ok {
					t.Fatalf("mesh dialer LocalAddr = %#v, want *net.TCPAddr", d.LocalAddr)
				}
				if !la.IP.Equal(net.IP(tc.want.AsSlice())) {
					t.Fatalf("mesh dialer LocalAddr IP = %s, want %s", la.IP, tc.want)
				}
				if la.Port != 0 {
					t.Fatalf("mesh dialer LocalAddr port = %d, want 0 (ephemeral)", la.Port)
				}
			} else {
				if d != p.dialer {
					t.Fatalf("dialerFor(%v, %s) returned the mesh-bound dialer, want the default dialer", tc.loc, tc.dst)
				}
				if d.LocalAddr != nil {
					t.Fatalf("default dialer LocalAddr = %#v, want nil (kernel default source selection)", d.LocalAddr)
				}
			}
			// The shared default dialer is never mutated by a dial decision.
			if p.dialer.LocalAddr != nil {
				t.Fatalf("p.dialer.LocalAddr = %#v after dialerFor, want nil (never mutated)", p.dialer.LocalAddr)
			}
		})
	}
}

// TestUDPRelayAppliesEgressScope proves the datagram path applies the SAME table:
// a per-flow upstream socket is source-bound only for a cross-node pod backend.
// It drives upstreamFor through the relay's dial seam, capturing the local
// address the relay would bind, so the assertion needs no privilege and no
// reachable peer.
//
// The UDP half is exactly the half a TCP-only functional test cannot see, which
// is why it is asserted here rather than inferred from the shared predicate.
func TestUDPRelayAppliesEgressScope(t *testing.T) {
	t.Parallel()
	for _, tc := range scopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !tc.dst.IsValid() {
				t.Skip("an invalid address is not a routable endpoint; covered by the predicate table")
			}
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen vip udp: %v", err)
			}
			defer pc.Close()

			// A zero podCIDR yields LocalityUnknown for every backend; the node /24
			// yields Local for its own addresses and Remote for the rest — the same
			// classify() the reconcile path runs.
			cidr := nodePodCIDR
			if tc.loc == LocalityUnknown {
				cidr = netip.Prefix{}
			}
			vip := pc.LocalAddr().(*net.UDPAddr)
			key := PortKey{ClusterIP: "127.0.0.1", Port: int32(vip.Port), Protocol: netv1.ProtocolUDP}
			tbl := NewRoutingTable(cidr)
			if n := tbl.SetEndpoints(key, []netv1.Endpoint{{IP: tc.dst.String(), Port: 9000, Ready: true}}); n != 1 {
				t.Fatalf("installed %d backends, want 1", n)
			}
			if be, err := tbl.Pick(key); err != nil {
				t.Fatalf("pick: %v", err)
			} else if be.Locality() != tc.loc {
				t.Fatalf("backend locality = %v, want %v (the case's premise)", be.Locality(), tc.loc)
			}

			r := newUDPRelay(pc, key, tbl, tc.resolved(), time.Hour, maxUDPFlowsPerSource, nil, slog.New(slog.DiscardHandler))
			defer r.Close()
			var (
				mu    sync.Mutex
				laddr *net.UDPAddr
				dials int
			)
			r.dial = func(l, _ *net.UDPAddr) (*net.UDPConn, error) {
				mu.Lock()
				defer mu.Unlock()
				laddr, dials = l, dials+1
				// Refusing the dial keeps the case hermetic: no upstream socket, no
				// flow entry, no reachable peer required. The source decision has
				// already been made by the time the seam is called.
				return nil, errors.New("test seam: no upstream socket")
			}
			var lastWarn time.Time
			_ = r.upstreamFor(&net.UDPAddr{IP: net.IPv4(10, 1, 0, 1), Port: 40000}, &lastWarn)

			mu.Lock()
			defer mu.Unlock()
			if dials != 1 {
				t.Fatalf("relay dialed %d times, want 1", dials)
			}
			if !tc.want.IsValid() {
				if laddr != nil {
					t.Fatalf("relay bound laddr = %v, want nil (kernel default source selection)", laddr)
				}
				return
			}
			if laddr == nil {
				t.Fatalf("relay bound laddr = nil, want %s", tc.want)
			}
			if !laddr.IP.Equal(net.IP(tc.want.AsSlice())) {
				t.Fatalf("relay bound laddr IP = %s, want %s", laddr.IP, tc.want)
			}
			if laddr.Port != 0 {
				t.Fatalf("relay bound laddr port = %d, want 0 (ephemeral)", laddr.Port)
			}
		})
	}
}

// TestWithMeshEgressSourceBuildsSeparateBoundDialer pins the CONSTRUCTION
// contract that replaced the retired construction-time bind: WithMeshEgressSource
// builds a second, immutable mesh-bound dialer and leaves the shared default
// dialer's source selection untouched, so no dial is bound merely because the
// option was passed. Binding is a per-dial decision (see
// TestProxyDialerForAppliesEgressScope); this test proves only that the two
// dialers exist in the right shape and that the option is inert on the default one.
func TestWithMeshEgressSourceBuildsSeparateBoundDialer(t *testing.T) {
	t.Parallel()
	// A fresh table per subtest: New copies the proxy's logger into the routing
	// table it is given, so two parallel New calls on one shared table would race
	// on that write rather than on anything this test is about.

	t.Run("valid source builds a bound sibling dialer", func(t *testing.T) {
		t.Parallel()
		p := New(NewRoutingTable(nodePodCIDR), WithMeshEgressSource(meshSource), withAliasManager(newNoopAliasManager()))
		if p.meshDialer == nil {
			t.Fatal("p.meshDialer = nil, want a mesh-source-bound dialer")
		}
		la, ok := p.meshDialer.LocalAddr.(*net.TCPAddr)
		if !ok {
			t.Fatalf("meshDialer.LocalAddr = %#v, want *net.TCPAddr", p.meshDialer.LocalAddr)
		}
		if !la.IP.Equal(net.IP(meshSource.AsSlice())) {
			t.Fatalf("meshDialer LocalAddr IP = %s, want %s", la.IP, meshSource)
		}
		if p.dialer.LocalAddr != nil {
			t.Fatalf("p.dialer.LocalAddr = %#v, want nil — the option must NOT bind every dial", p.dialer.LocalAddr)
		}
		if p.egress.src != meshSource {
			t.Fatalf("p.egress.src = %s, want %s (shared with the UDP relays)", p.egress.src, meshSource)
		}
		if p.egress.clusterCIDR != podnet.ClusterPodCIDR {
			t.Fatalf("p.egress.clusterCIDR = %s, want the podnet default %s", p.egress.clusterCIDR, podnet.ClusterPodCIDR)
		}
	})

	t.Run("zero source builds no mesh dialer", func(t *testing.T) {
		t.Parallel()
		p := New(NewRoutingTable(nodePodCIDR), WithMeshEgressSource(netip.Addr{}), withAliasManager(newNoopAliasManager()))
		if p.meshDialer != nil {
			t.Fatalf("p.meshDialer = %#v, want nil (no mesh source on a single node)", p.meshDialer)
		}
		if p.dialer.LocalAddr != nil {
			t.Fatalf("p.dialer.LocalAddr = %#v, want nil", p.dialer.LocalAddr)
		}
		if p.egress.src.IsValid() {
			t.Fatalf("p.egress.src = %s, want invalid (single-node default source)", p.egress.src)
		}
	})

	t.Run("cluster aggregate defaults and overrides", func(t *testing.T) {
		t.Parallel()
		custom := netip.MustParsePrefix("10.42.0.0/16")
		p := New(NewRoutingTable(nodePodCIDR), WithMeshEgressSource(meshSource), WithClusterPodCIDR(custom), withAliasManager(newNoopAliasManager()))
		if p.egress.clusterCIDR != custom {
			t.Fatalf("p.egress.clusterCIDR = %s, want %s", p.egress.clusterCIDR, custom)
		}
		// An invalid override is ignored, leaving the podnet default in place: a
		// mesh node must never silently degrade to "never bind".
		q := New(NewRoutingTable(nodePodCIDR), WithMeshEgressSource(meshSource), WithClusterPodCIDR(netip.Prefix{}), withAliasManager(newNoopAliasManager()))
		if q.egress.clusterCIDR != podnet.ClusterPodCIDR {
			t.Fatalf("q.egress.clusterCIDR = %s, want the podnet default %s", q.egress.clusterCIDR, podnet.ClusterPodCIDR)
		}
	})
}

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
