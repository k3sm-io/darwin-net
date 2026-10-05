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
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// relayRefusalThrottle bounds how often the refusal of one pod's override is
// logged: a refused override is re-evaluated on every routing generation, and an
// endpoint churn must not turn one misreport into a log flood.
const relayRefusalThrottle = time.Minute

// maxRelayPorts caps one pod's relay port set (declared container ports together
// with the Service-targeted ports at its published address). Every relayed port is
// a daemon file descriptor, a bind (a root-helper round-trip below 1024) and a
// retry log line on failure, and a pod spec may declare tens of thousands of
// container ports. A pod over the cap gets no relay at all — fail closed, never a
// silently truncated subset — and a throttled Warn naming the pod and the count.
const maxRelayPorts = 32

// podRelays is the Proxy's per-pod TCP relay manager: for every vm pod in the
// routing table's transport overrides it listens on the pod's PUBLISHED address
// (the lo0 alias pkg/podnet holds for the pod's lifetime) and relays each accepted
// connection to the pod's LIVE lease address. It is what makes a vm pod's
// status.podIP reachable at all — by a direct dial, from its own host, and from
// another node, whose traffic to this node's /24 the mesh already delivers here.
//
// # Reconcile
//
// The desired relay set is derived from ONE routing generation: the transport
// overrides (live address and declared ports) and the backend ports the same
// generation's Service ports list for each published address. Two paths apply it:
//
//   - retire runs synchronously from the table's observer, under the table's
//     writer lock, whenever a generation replaces the transport overrides. It closes
//     every relay whose pod was dropped or whose live address changed — listeners and
//     every relayed connection — so by the time SetTransportOverrides returns no
//     relay serves a pod the caller has let go. That ordering is what lets the caller
//     drop the override and then remove the pod's alias safely.
//   - reconcile runs on the relay goroutine (Run), kicked by every generation and
//     by a retry timer. It opens what is missing, closes listeners for ports that
//     left the set, and retries a failed bind with backoff (the alias may not be up
//     yet, or the bind may lose a race). Binds happen outside the lock, so a slow
//     netd round-trip never stalls retire.
//
// # Refusals (fail closed)
//
// The guest reports its own lease, so the node must not become a dialer to an
// arbitrary host on a guest's say-so. An override is refused — no relay, a
// throttled Warn naming the pod — when its live address is outside the node's
// vmnet segment, is that segment's gateway or broadcast address, equals the
// published address, or is claimed by another pod in the same generation, and when
// its port set exceeds maxRelayPorts. With no vmnet segment configured every
// override is refused. retire applies the same admission check, so a relay that
// becomes refused while its lease is unchanged (a second pod claims the lease)
// closes synchronously too.
//
// Locking discipline: mu guards relays, warned, retryAt and closed. A podRelay has
// its own leaf lock (podRelay.mu) for its listeners and connections, taken with or
// without mu held, never the reverse. mu is a leaf with respect to the routing
// table: retire is called with the table's writer lock held and never calls back
// into the table. wg counts every serve and handle goroutine.
type podRelays struct {
	p *Proxy
	// vmnet is the node's vmnet segment (the guest NAT subnet). gateway and
	// broadcast are derived from it once at construction and are invalid for a
	// prefix too small to have them (/31, /32, and IPv6 has no broadcast).
	vmnet     netip.Prefix
	gateway   netip.Addr
	broadcast netip.Addr

	kick chan struct{}
	wg   sync.WaitGroup

	mu     sync.Mutex
	relays map[netip.Addr]*podRelay
	warned map[netip.Addr]time.Time
	closed bool
}

// podRelay is one vm pod's relay: the listeners on its published address, one per
// port, and every connection (client and backend side) it is relaying.
type podRelay struct {
	published netip.Addr
	live      netip.Addr

	mu        sync.Mutex
	listeners map[uint16]net.Listener
	conns     map[net.Conn]struct{}
	closed    bool
}

// relayPlan is the validated desired state for one pod.
type relayPlan struct {
	live  netip.Addr
	ports []uint16
}

// newPodRelays returns a relay manager for p over the vmnet segment vmnet.
func newPodRelays(p *Proxy, vmnet netip.Prefix) *podRelays {
	m := &podRelays{
		p:      p,
		vmnet:  vmnet.Masked(),
		kick:   make(chan struct{}, 1),
		relays: make(map[netip.Addr]*podRelay),
		warned: make(map[netip.Addr]time.Time),
	}
	if m.vmnet.IsValid() && m.vmnet.Addr().Is4() && m.vmnet.Bits() <= 30 {
		m.gateway = m.vmnet.Addr().Next()
		a := m.vmnet.Addr().As4()
		host := uint32(1)<<(32-m.vmnet.Bits()) - 1
		v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		v |= host
		m.broadcast = netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	} else if m.vmnet.IsValid() && m.vmnet.Addr().Is6() && m.vmnet.Bits() <= 126 {
		m.gateway = m.vmnet.Addr().Next()
	}
	return m
}

// observe is the routing table's generation observer. It runs under the table's
// writer lock: it retires what a transport generation dropped, synchronously, and
// kicks the reconcile goroutine for everything else.
func (m *podRelays) observe(s *routingSnapshot, transport bool) {
	if transport {
		m.retire(s)
	}
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// retire closes every relay whose pod is absent from s's overrides, whose live
// address changed, or whose override s no longer admits. It does not log a
// refusal; the reconcile pass the same generation kicks does that.
func (m *podRelays) retire(s *routingSnapshot) {
	claims := liveClaims(s)
	svc := s.relayBackendPorts()
	m.mu.Lock()
	var gone []*podRelay
	for pub, r := range m.relays {
		if tr, ok := s.transport[pub]; ok && tr.Live == r.live {
			if _, reason := m.admit(pub, tr, svc[pub], claims[tr.Live]); reason == "" {
				continue
			}
		}
		gone = append(gone, r)
		delete(m.relays, pub)
	}
	m.mu.Unlock()
	for _, r := range gone {
		r.close()
		m.p.logger().Info("vm pod relay closed", "pod", r.published.String(), "live", r.live.String())
	}
}

// run is the reconcile goroutine. It returns when ctx is cancelled; the caller then
// calls shutdown.
func (m *podRelays) run(ctx context.Context) {
	retry := time.NewTimer(openRetryInitial)
	retry.Stop()
	defer retry.Stop()
	backoff := openRetryInitial
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
		case <-retry.C:
		}
		if m.reconcile(ctx, m.p.table.load()) {
			backoff = openRetryInitial
			retry.Stop()
			continue
		}
		retry.Reset(backoff)
		backoff = min(2*backoff, openRetryMax)
	}
}

// reconcile drives the relay set to the one generation s describes and reports
// whether every listener it wanted is open.
func (m *podRelays) reconcile(ctx context.Context, s *routingSnapshot) bool {
	want := m.plan(s)

	type bindJob struct {
		r    *podRelay
		port uint16
	}
	var (
		gone []*podRelay
		jobs []bindJob
	)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return true
	}
	if m.p.table.load().transportGen != s.transportGen {
		// A newer transport generation was stored after s was loaded, and its
		// retire may already have run: installing s's relays now could resurrect
		// a pod the caller has dropped. The newer generation kicked this goroutine,
		// so the next pass applies it.
		m.mu.Unlock()
		return true
	}
	for pub, r := range m.relays {
		if pl, ok := want[pub]; !ok || pl.live != r.live {
			gone = append(gone, r)
			delete(m.relays, pub)
		}
	}
	for pub, pl := range want {
		r, ok := m.relays[pub]
		if !ok {
			r = &podRelay{published: pub, live: pl.live, listeners: make(map[uint16]net.Listener), conns: make(map[net.Conn]struct{})}
			m.relays[pub] = r
			m.p.logger().Info("vm pod relay installed", "pod", pub.String(), "live", pl.live.String(), "ports", pl.ports)
		}
		for _, port := range r.trimPorts(pl.ports) {
			jobs = append(jobs, bindJob{r: r, port: port})
		}
	}
	m.mu.Unlock()
	for _, r := range gone {
		r.close()
		m.p.logger().Info("vm pod relay closed", "pod", r.published.String(), "live", r.live.String())
	}

	ok := true
	for _, j := range jobs {
		if err := m.open(ctx, j.r, j.port); err != nil {
			ok = false
			m.p.logger().Warn("vm pod relay: bind the published address; retrying", "pod", j.r.published.String(), "port", j.port, "err", err)
		}
	}
	return ok
}

// plan validates s's overrides and returns the relay each admitted pod should
// have. A refused pod is logged (throttled) and left out.
func (m *podRelays) plan(s *routingSnapshot) map[netip.Addr]relayPlan {
	claims := liveClaims(s)
	svc := s.relayBackendPorts()
	want := make(map[netip.Addr]relayPlan, len(s.transport))
	for pub, tr := range s.transport {
		ports, reason := m.admit(pub, tr, svc[pub], claims[tr.Live])
		if reason != "" {
			m.warnRefused(pub, tr.Live, reason)
			continue
		}
		want[pub] = relayPlan{live: tr.Live, ports: ports}
	}
	m.mu.Lock()
	for pub := range m.warned {
		if _, ok := s.transport[pub]; !ok {
			delete(m.warned, pub)
		}
	}
	m.mu.Unlock()
	return want
}

// liveClaims counts, per live address, how many pods in s report it.
func liveClaims(s *routingSnapshot) map[netip.Addr]int {
	claims := make(map[netip.Addr]int, len(s.transport))
	for _, tr := range s.transport {
		claims[tr.Live]++
	}
	return claims
}

// admit returns the sorted port set the override published→tr is relayed on, or
// why it must not be relayed at all. svcPorts are the TCP backend ports the
// generation lists at published (relayBackendPorts) and claims is how many pods in
// the generation report tr.Live. It reads only its arguments and m's immutable
// fields, so it is safe under either lock.
func (m *podRelays) admit(published netip.Addr, tr VMPodTransport, svcPorts []uint16, claims int) ([]uint16, string) {
	if reason := m.refusal(published, tr.Live, claims); reason != "" {
		return nil, reason
	}
	ports := slices.Concat(tr.Ports, svcPorts)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	if len(ports) > maxRelayPorts {
		return nil, fmt.Sprintf("port set has %d ports, over the per-pod relay cap of %d", len(ports), maxRelayPorts)
	}
	return ports, ""
}

// refusal returns why the override published→live must not get a relay, or "".
// claims is how many pods in the generation report live.
func (m *podRelays) refusal(published, live netip.Addr, claims int) string {
	switch {
	case !m.vmnet.IsValid():
		return "no vmnet segment is configured on this node"
	case !m.vmnet.Contains(live):
		return "live address is outside the node's vmnet segment " + m.vmnet.String()
	case live == m.vmnet.Addr() && m.vmnet.Bits() <= 30:
		return "live address is the vmnet segment's network address"
	case live == m.gateway:
		return "live address is the vmnet gateway"
	case live == m.broadcast:
		return "live address is the vmnet broadcast address"
	case live == published:
		return "live address equals the published address"
	case claims > 1:
		return "live address is reported by more than one pod"
	}
	return ""
}

// warnRefused logs a refused override at most once per relayRefusalThrottle per pod.
func (m *podRelays) warnRefused(published, live netip.Addr, reason string) {
	now := time.Now()
	m.mu.Lock()
	last, seen := m.warned[published]
	quiet := seen && now.Sub(last) < relayRefusalThrottle
	if !quiet {
		m.warned[published] = now
	}
	m.mu.Unlock()
	if quiet {
		return
	}
	m.p.logger().Warn("vm pod relay refused: the pod's published address is not relayed", "pod", published.String(), "live", live.String(), "reason", reason)
}

// open binds one port of r's published address (never a wildcard) through the
// proxy's binder and starts serving it. A relay closed or already serving the port
// by the time the bind returns gets the new listener closed.
func (m *podRelays) open(ctx context.Context, r *podRelay, port uint16) error {
	bctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	ap := netip.AddrPortFrom(r.published, port)
	raw, err := m.p.binder.Listen(bctx, "tcp", ap)
	if err != nil {
		return fmt.Errorf("listen %s: %w", ap, err)
	}
	ln := tcpseg.WrapListener(raw)
	if !r.addListener(port, ln) {
		_ = ln.Close()
		return nil
	}
	m.wg.Add(1)
	go m.serve(r, ln, port)
	return nil
}

// serve accepts on one relay listener until it is closed.
func (m *podRelays) serve(r *podRelay, ln net.Listener, port uint16) {
	defer m.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !r.track(c) {
			_ = c.Close()
			continue
		}
		m.wg.Add(1)
		go m.handle(r, c, port)
	}
}

// handle relays one accepted connection to the pod's live address. It refuses a
// client inside the vmnet segment (a guest must never reach a sibling, or itself,
// through the host), then applies the same NetworkPolicy verdict the VIP path does
// against the published identity, then dials the live address through the clamped
// default-source dialer and splices.
func (m *podRelays) handle(r *podRelay, client net.Conn, port uint16) {
	defer m.wg.Done()
	defer r.release(client)
	p := m.p
	src := clientAddr(client.RemoteAddr())
	if m.vmnet.Contains(src) {
		p.logger().Debug("vm pod relay: refused a client inside the vmnet segment", "pod", r.published.String(), "port", port, "src", src.String())
		return
	}
	if !p.policy.Allow(src, r.published, port) {
		key := PortKey{ClusterIP: r.published.String(), Port: int32(port), Protocol: netv1.ProtocolTCP}
		p.policy.logDenied("tcp", key, src, netip.AddrPortFrom(r.published, port))
		return
	}
	dst := netip.AddrPortFrom(r.live, port)
	backendConn, err := p.dialBackend(p.dialerFor(LocalityLocal, r.live), "tcp", dst.String())
	if err != nil {
		p.logger().Debug("vm pod relay: dial the live address", "pod", r.published.String(), "live", dst.String(), "err", err)
		return
	}
	if !r.track(backendConn) {
		_ = backendConn.Close()
		return
	}
	defer r.release(backendConn)
	splice(client, backendConn)
}

// shutdown closes every relay and waits for every relay goroutine to return. No
// relay is opened afterwards.
func (m *podRelays) shutdown() {
	m.mu.Lock()
	m.closed = true
	rs := slices.Collect(maps.Values(m.relays))
	m.relays = make(map[netip.Addr]*podRelay)
	m.mu.Unlock()
	for _, r := range rs {
		r.close()
	}
	m.wg.Wait()
}

// trimPorts closes the listeners for ports not in want and returns the ports of
// want that have no listener yet.
func (r *podRelay) trimPorts(want []uint16) []uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	for port, ln := range r.listeners {
		if !slices.Contains(want, port) {
			_ = ln.Close()
			delete(r.listeners, port)
		}
	}
	var missing []uint16
	for _, port := range want {
		if _, ok := r.listeners[port]; !ok {
			missing = append(missing, port)
		}
	}
	return missing
}

// addListener records ln for port, reporting false (the caller closes ln) when the
// relay is closed or the port is already served.
func (r *podRelay) addListener(port uint16, ln net.Listener) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	if _, ok := r.listeners[port]; ok {
		return false
	}
	r.listeners[port] = ln
	return true
}

// track records c as relayed, reporting false (the caller closes c) once the relay
// is closed.
func (r *podRelay) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

// release closes c and forgets it.
func (r *podRelay) release(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
	_ = c.Close()
}

// close closes the relay's listeners and every connection it is relaying. It is
// idempotent.
func (r *podRelay) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for port, ln := range r.listeners {
		_ = ln.Close()
		delete(r.listeners, port)
	}
	for c := range r.conns {
		_ = c.Close()
	}
}
