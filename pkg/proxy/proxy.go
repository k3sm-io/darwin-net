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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// dialTimeout bounds how long the proxy waits to connect to a chosen backend
// before giving up on that connection. Kept short because backends are local
// (loopback) or one mesh hop away.
const dialTimeout = 5 * time.Second

// udpFlowIdleTimeout is the idle-flow GC timeout for the UDP datagram relay: a
// flow (a client 5-tuple bound to a connected upstream socket and the backend
// picked once for it) is reaped after this much two-way silence, so a cached
// socket and backend selection do not pin to a dead client. It mirrors Linux
// conntrack-UDP (30s) and kube-proxy's userspace udpIdleTimeout. It is
// deliberately distinct in MAGNITUDE from a future sessionAffinity: ClientIP
// timeout: a session-affinity TTL outlives many idle gaps, so the two must not be
// collapsed into one constant. B22 reuses the named-const + idle-sweeper PATTERN
// (and may share this GC cadence), NOT this flow map itself: ClientIP affinity keys
// on the client IP alone — not the 5-tuple this relay keys on — and spans TCP
// Services too (which never enter this UDP relay), so it needs its own IP-keyed
// affinity table at the Pick layer.
const udpFlowIdleTimeout = 30 * time.Second

// Proxy is the userspace Service proxy: it owns one listening socket per bound
// Service port (a ClusterIP:port on an lo0 alias, plus *:NodePort when set) and
// L4-load-balances accepted connections to the Ready backends in its
// RoutingTable.
//
// It yields ownership of infra VIPs registered via WithInfraVIPExemptions (the
// kube-dns VIP, which per-node resolver binds directly): for an exempt VIP the
// proxy creates no worker, no lo0 alias, and no listener, so it never contends
// with the per-node resolver for 10.43.0.10:53 (EADDRINUSE).
//
// Concurrency / locking discipline:
//   - Each ClusterIP:port (a PortKey) is reconciled by exactly one per-key worker
//     goroutine, fed by a per-key event channel. Serializing per VIP means a
//     Service event and an EndpointSlice event for the same port can never race
//     two owners onto one socket or close a live listener: the single worker
//     opens, updates, and closes that port's listener in order.
//   - workers (the map of per-key workers) is guarded by mu. Only the run loop
//     mutates it; reconcile callers send on a worker's channel without holding mu
//     beyond the lookup.
//   - The RoutingTable has its own internal lock and is shared read-only by the
//     accept paths and written by the workers.
type Proxy struct {
	table  *RoutingTable
	alias  aliasManager
	binder binder
	log    *slog.Logger
	dialer *net.Dialer
	// meshEgress is the node's reserved mesh-egress /32, retained from
	// WithMeshEgressSource for the UDP relay's per-flow upstream source-bind. The TCP
	// path source-binds via p.dialer.LocalAddr, but the UDP path cannot reuse it: a
	// net.Dialer whose LocalAddr is a *net.TCPAddr fails to dial "udp" (mismatched
	// local address type), so the datagram path builds a *net.UDPAddr from this Addr
	// instead. The zero Addr (single node, no utun) means the kernel default source.
	// Set once at construction, read-only thereafter.
	meshEgress netip.Addr
	// exemptVIPs are infra VIPs owned by a node-local binder (per-node resolver on
	// the kube-dns VIP) rather than by the proxy: the proxy never aliases, binds,
	// or routes them. It is set once by WithInfraVIPExemptions and read-only
	// thereafter, so it needs no lock.
	exemptVIPs map[netip.Addr]struct{}

	mu      sync.Mutex
	workers map[PortKey]*portWorker
	// done is closed when the proxy is shutting down so workers stop accepting.
	done chan struct{}
}

// Option configures a Proxy.
type Option func(*Proxy)

// WithLogger sets the structured logger; the default is slog.Default.
func WithLogger(l *slog.Logger) Option {
	return func(p *Proxy) { p.log = l }
}

// WithMeshEgressSource binds the backend dialer's source address (LocalAddr) to
// the node's reserved mesh-egress /32 (podnet.MeshEgressIP). It is REQUIRED on a
// multi-node mesh and MUST be left unset on a single node:
//
// wireguard accepts an inbound packet only when its source falls within some
// peer's AllowedIPs (= the sending node's podCIDR). A backend on another node is
// reached by a dial that egresses the utun, so that dial must be sourced from this
// node's mesh-egress address (which is inside this node's podCIDR by construction)
// or the peer drops the return packet — a one-way blackhole. Same-node backends
// stay on loopback and are unaffected because the mesh-egress address is a local
// lo0 alias. When src is the zero Addr the dialer keeps the kernel's default
// source selection (the single-node path, where no utun exists to bind to).
func WithMeshEgressSource(src netip.Addr) Option {
	return func(p *Proxy) {
		// Retain the address for the UDP relay's per-flow upstream source-bind (it
		// builds a *net.UDPAddr from this, since a *net.TCPAddr LocalAddr cannot dial
		// "udp"). The zero Addr stays invalid, so the relay keeps the kernel default
		// source on a single node — matching the TCP dialer below.
		p.meshEgress = src
		if src.IsValid() {
			p.dialer.LocalAddr = &net.TCPAddr{IP: src.AsSlice()}
		}
	}
}

// WithInfraVIPExemptions marks one or more infra VIPs as owned by a node-local
// binder rather than the Service proxy, so the proxy never takes ownership of
// them: no lo0 alias, no listening socket, no routing-table entry.
//
// It is the fix for the per-node resolver collision (M3.3). k3sm runs a per-node
// resolver (the in-process k3sm/pkg/netserve resolver) on every node bound
// directly to the kube-dns VIP (10.43.0.10) for 53/TCP and 53/UDP, so cluster DNS
// is always answered node-locally over loopback and never
// steered over the wireguard mesh (which carries only pod /24s — a mesh-steered
// DNS VIP would blackhole). Without this exemption the proxy's kube-dns Service
// reconcile would try to bind 10.43.0.10:53 and fail with EADDRINUSE — for TCP and,
// since B23 built the ClusterIP UDP datagram relay, for 53/UDP too (it no longer
// dodges the collision by opening no datagram socket). The exemption is keyed on the
// VIP address, so it covers every port and protocol on that VIP, and that
// address-keyed seam is what keeps cluster DNS node-local while a legitimate USER
// UDP Service on a different (non-exempt) VIP is still claimed and relayed.
//
// The node-local kubernetes (10.43.0.1) endpoint uses the same step-aside
// mechanism, but its endpoint rewrite is k3sm-owned (k3sm:M3.3); darwin-net
// supplies the per-node resolver (pkg/dns.PerNodeDNS) and this exemption seam.
func WithInfraVIPExemptions(vips ...netip.Addr) Option {
	return func(p *Proxy) {
		for _, v := range vips {
			if v.IsValid() {
				p.exemptVIPs[v] = struct{}{}
			}
		}
	}
}

// withAliasManager overrides the alias manager (tests inject the rootless fake).
func withAliasManager(a aliasManager) Option {
	return func(p *Proxy) { p.alias = a }
}

// WithNetdHelper routes both privileged proxy operations — the lo0 VIP alias and
// the privileged-port (<1024) ClusterIP bind — through the root netd daemon at
// socketPath (empty uses the default socket), so the Service proxy runs
// unprivileged. It is the one construction-time selection wiring both seams to the
// helper; the direct ifconfig/net.Listen path remains the default for an explicit
// run-as-root mode. The node-wide *:NodePort listener is always bound directly (it
// is >=1024 and needs no privilege).
func WithNetdHelper(socketPath string) Option {
	return func(p *Proxy) {
		c := wire.NewClient(socketPath)
		p.alias = &netdAliasManager{client: c}
		p.binder = &netdBinder{client: c}
	}
}

// New constructs a Proxy steering to the backends in table. By default it uses
// the root-gated lo0 alias manager; pass options to override (e.g. a logger).
func New(table *RoutingTable, opts ...Option) *Proxy {
	p := &Proxy{
		table:      table,
		alias:      newLo0AliasManager(),
		binder:     directBinder{},
		log:        slog.Default(),
		dialer:     &net.Dialer{Timeout: dialTimeout},
		exemptVIPs: make(map[netip.Addr]struct{}),
		workers:    make(map[PortKey]*portWorker),
		done:       make(chan struct{}),
	}
	for _, o := range opts {
		o(p)
	}
	// Propagate the (possibly WithLogger-overridden) logger to the routing table so
	// its fail-open Warn (internalTrafficPolicy: Local under an unknown podCIDR)
	// shares the proxy's sink. Set before Run starts any worker, so Pick's read of
	// table.log is safe under the goroutine-start happens-before.
	if p.table != nil {
		p.table.log = p.log
	}
	return p
}

// portWorker owns one ClusterIP:port. It is the single goroutine that may open
// or close that port's listeners, guaranteeing per-VIP serialization. Events
// (Service add/update/delete; EndpointSlice changes for the port) arrive on ch
// and are applied in order.
type portWorker struct {
	key  PortKey
	ch   chan portEvent
	stop chan struct{}
	done chan struct{}
}

// portEvent is a desired-state update for one ClusterIP:port delivered to its
// worker. A nil port means the port (or its Service) was deleted and the worker
// should tear its listeners down. policy is the Service's internalTrafficPolicy,
// applied to the routing table atomically with endpoints so Pick never observes a
// stale (policy, backends) pairing.
type portEvent struct {
	port      *netv1.ServicePort
	policy    trafficPolicy
	endpoints []netv1.Endpoint
}

// Run starts the proxy's worker supervision loop and blocks until ctx is
// cancelled, at which point it stops every worker (closing all listeners and
// removing every lo0 alias it created) and returns. Run is the single owner of
// the workers map mutation lifecycle.
func (p *Proxy) Run(ctx context.Context) error {
	<-ctx.Done()
	p.shutdown()
	return ctx.Err()
}

// shutdown stops all workers and waits for them to release their sockets.
func (p *Proxy) shutdown() {
	p.mu.Lock()
	close(p.done)
	ws := make([]*portWorker, 0, len(p.workers))
	for _, w := range p.workers {
		ws = append(ws, w)
	}
	p.workers = make(map[PortKey]*portWorker)
	p.mu.Unlock()

	for _, w := range ws {
		close(w.stop)
	}
	for _, w := range ws {
		<-w.done
	}
}

// Reconcile delivers the desired state for one Service port to its dedicated
// worker under the default internalTrafficPolicy: Cluster (round-robin over all
// backends). It is ReconcilePolicy with trafficCluster; the production watch path
// calls ReconcilePolicy to carry a Service's actual policy.
//
// Reconcile is safe for concurrent callers (the informer event handlers).
func (p *Proxy) Reconcile(clusterIP string, port *netv1.ServicePort, endpoints []netv1.Endpoint) error {
	return p.ReconcilePolicy(clusterIP, port, trafficCluster, endpoints)
}

// ReconcilePolicy delivers the desired state for one Service port — including its
// internalTrafficPolicy — to its dedicated worker, creating the worker on first
// sight. Passing port == nil signals deletion. Because every event for a given
// ClusterIP:port routes to the same worker channel, Service and EndpointSlice
// updates for that port are applied in a single serialized stream — no two
// goroutines ever touch one listener, and (policy, endpoints) reach the routing
// table together.
//
// ReconcilePolicy is safe for concurrent callers (the informer event handlers).
func (p *Proxy) ReconcilePolicy(clusterIP string, port *netv1.ServicePort, policy trafficPolicy, endpoints []netv1.Endpoint) error {
	if port == nil {
		return errors.New("proxy: reconcile requires a port (use ReconcileDelete to remove)")
	}
	// Validate the clusterIP early so a malformed VIP fails fast at the caller
	// rather than later in the worker's openListener.
	addr, err := netip.ParseAddr(clusterIP)
	if err != nil {
		return fmt.Errorf("proxy: parse clusterIP %q: %w", clusterIP, err)
	}
	key := PortKey{ClusterIP: clusterIP, Port: port.Port, Protocol: defaultProto(port.Protocol)}
	if p.isExemptVIP(addr) {
		// An infra VIP a node-local binder owns (per-node resolver on the kube-dns
		// VIP, the rewritten kubernetes endpoint). Step aside entirely — no worker,
		// no lo0 alias, no listener, no routing entry — so the proxy never contends
		// for the socket (EADDRINUSE). The exemption covers every port/protocol on
		// the VIP, so this fires for both 53/TCP and 53/UDP on the kube-dns VIP.
		p.log.Debug("infra VIP exempt from proxy ownership (node-local binder owns it)", "vip", key.String())
		return nil
	}
	w := p.worker(key)
	if w == nil {
		return errors.New("proxy: shutting down")
	}
	select {
	case w.ch <- portEvent{port: port, policy: policy, endpoints: endpoints}:
		return nil
	case <-w.stop:
		return errors.New("proxy: worker stopped")
	}
}

// ReconcileDelete tells the worker for clusterIP:port/proto to tear down its
// listeners and exit.
func (p *Proxy) ReconcileDelete(key PortKey) {
	p.mu.Lock()
	w := p.workers[key]
	p.mu.Unlock()
	if w == nil {
		return
	}
	select {
	case w.ch <- portEvent{port: nil}:
	case <-w.stop:
	}
}

// worker returns the worker for key, starting it if necessary. It returns nil if
// the proxy is shutting down.
func (p *Proxy) worker(key PortKey) *portWorker {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		return nil
	default:
	}
	if w, ok := p.workers[key]; ok {
		return w
	}
	w := &portWorker{
		key:  key,
		ch:   make(chan portEvent, 16),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	p.workers[key] = w
	go p.runWorker(w)
	return w
}

// runWorker is the per-VIP serialized reconcile loop. It is the only goroutine
// permitted to open or close key's listeners.
func (p *Proxy) runWorker(w *portWorker) {
	defer close(w.done)
	var ln *listener
	defer func() {
		if ln != nil {
			ln.Close()
		}
	}()

	for {
		select {
		case <-w.stop:
			return
		case ev := <-w.ch:
			if ev.port == nil {
				if ln != nil {
					ln.Close()
					ln = nil
				}
				p.table.Delete(w.key)
				return
			}
			p.table.SetEndpointsPolicy(w.key, ev.endpoints, ev.policy)
			if ln == nil {
				l, err := p.openListener(w.key, ev.port)
				if err != nil {
					p.log.Error("open service listener", "vip", w.key.String(), "err", err)
					continue
				}
				ln = l
			}
		}
	}
}

// openListener binds the sockets for one Service port. For TCP it opens the
// ClusterIP stream listener on the specific lo0 alias address (net.Listen on
// clusterIP:port, never :port, so the bound source identity is the VIP) and, when
// NodePort is set, a node-wide *:NodePort stream listener. For UDP it opens the
// ClusterIP datagram relay (net.ListenPacket on the specific clusterIP:port,
// mirroring the TCP specific-bind) and runs its dispatcher + idle-flow sweeper. It
// ensures the lo0 alias exists first.
//
// NodePort semantics (TCP): the *:NodePort listener accepts on every node interface
// and L4-load-balances to the SAME Ready backend set as the ClusterIP — i.e.
// externalTrafficPolicy: Cluster. externalTrafficPolicy: Local is NOT honored,
// because the userspace splice (see splice) opens a fresh backend connection and
// therefore does NOT preserve the external client's source IP (the backend sees
// the proxy/mesh-egress source, not the client) — the precondition Local relies on.
//
// UDP: the ClusterIP datagram relay IS built (connectionless — a dispatcher reads
// the VIP socket, picks a backend ONCE per client flow, opens a connected upstream
// socket, relays both ways, and idle-GCs the flow; see udprelay.go and doc.go).
// Like the TCP splice it re-originates traffic (Cluster policy: the upstream socket
// is source-bound to the node's mesh-egress /32 on a multi-node mesh, never the
// client pod IP), and a flow stays pinned to its picked backend until idle GC reaps
// it (no conntrack-style flush in B23). UDP NodePort is DEFERRED: a wildcard-bound
// *:NodePort UDP reply re-selects its source by route lookup on a multi-homed node,
// so the client would see the reply from the wrong source IP and drop it; honoring
// it needs IP_RECVDSTADDR/IP_SENDSRCADDR, out of scope for B23. Privileged (<1024)
// UDP binds directly via net.ListenPacket (the binder seam is stream-only — a
// net.Listener/FileListener cannot adopt a datagram fd), so a <1024 UDP ClusterIP
// without root surfaces an honest net.ListenPacket EACCES; a netd FilePacketConn
// path is deferred, not dead-ended.
func (p *Proxy) openListener(key PortKey, port *netv1.ServicePort) (*listener, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	ip, err := netip.ParseAddr(key.ClusterIP)
	if err != nil {
		return nil, fmt.Errorf("parse clusterIP %q: %w", key.ClusterIP, err)
	}
	if err := p.alias.Ensure(ctx, ip); err != nil {
		return nil, fmt.Errorf("ensure lo0 alias %s: %w", ip, err)
	}

	l := &listener{key: key, alias: p.alias, aliasIP: ip, log: p.log}

	if key.Protocol == netv1.ProtocolUDP {
		// ClusterIP UDP: bind the SPECIFIC alias-address datagram socket (mirroring
		// the TCP specific-bind below) and run the connectionless relay — a dispatcher
		// reads the VIP socket, picks a backend once per client flow, opens a connected
		// per-flow upstream socket, and idle-GCs the flow (see udprelay.go). The relay
		// binds directly via net.ListenPacket, NOT through p.binder: that seam is
		// stream-only (net.Listener/FileListener), so a privileged (<1024) UDP VIP
		// without root surfaces an honest EACCES here; the netd datagram path is
		// deferred. NodePort UDP is deferred too: a wildcard *:NodePort UDP reply
		// re-selects its source on a multi-homed node (wrong src IP → client drops it),
		// needing IP_RECVDSTADDR/IP_SENDSRCADDR — out of scope for B23.
		clusterAP := netip.AddrPortFrom(ip, uint16(port.Port))
		pc, err := net.ListenPacket("udp", clusterAP.String())
		if err != nil {
			_ = p.alias.Remove(ctx, ip)
			return nil, fmt.Errorf("listen udp clusterIP %s: %w", clusterAP, err)
		}
		relay := newUDPRelay(pc, key, p.table, p.meshEgress, udpFlowIdleTimeout, p.log)
		relay.start()
		l.udp = relay
		if port.NodePort != 0 {
			p.log.Info("udp nodePort deferred (wildcard datagram reply re-selects source IP on a multi-homed node); clusterIP relay built", "vip", key.String())
		}
		return l, nil
	}

	// ClusterIP listener: bind the SPECIFIC alias address, not the wildcard, so
	// loopback stamps the VIP as the source identity. The binder is direct by
	// default; under WithNetdHelper a privileged (<1024) VIP port is bound by the
	// root daemon and the socket is passed back over SCM_RIGHTS.
	clusterAP := netip.AddrPortFrom(ip, uint16(port.Port))
	cl, err := p.binder.Listen(ctx, "tcp", clusterAP)
	if err != nil {
		_ = p.alias.Remove(ctx, ip)
		return nil, fmt.Errorf("listen clusterIP %s: %w", clusterAP, err)
	}
	l.clusterIP = cl
	go p.serve(cl, key)

	// NodePort listener: bind the wildcard (*:NodePort) so every node interface
	// answers, load-balancing to the same backends as the ClusterIP
	// (externalTrafficPolicy: Cluster — the splice does not preserve client src IP).
	if port.NodePort != 0 {
		nodeAddr := net.JoinHostPort("", strconv.Itoa(int(port.NodePort)))
		nl, err := net.Listen("tcp", nodeAddr)
		if err != nil {
			_ = cl.Close()
			_ = p.alias.Remove(ctx, ip)
			return nil, fmt.Errorf("listen nodePort %s: %w", nodeAddr, err)
		}
		l.nodePort = nl
		go p.serve(nl, key)
	}
	return l, nil
}

// serve accepts TCP connections on ln and proxies each to a backend chosen by
// the routing table. It returns when ln is closed (Accept errors).
func (p *Proxy) serve(ln net.Listener, key PortKey) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go p.handle(conn, key)
	}
}

// handle proxies one accepted client connection to a Ready backend.
func (p *Proxy) handle(client net.Conn, key PortKey) {
	defer client.Close()
	be, err := p.table.Pick(key)
	if err != nil {
		p.log.Debug("no backend for connection", "vip", key.String(), "err", err)
		return
	}
	backendConn, err := p.dialer.Dial("tcp", be.Addr().String())
	if err != nil {
		p.log.Debug("dial backend", "vip", key.String(), "backend", be.Addr().String(), "err", err)
		return
	}
	defer backendConn.Close()
	splice(client, backendConn)
}

// splice copies bytes in both directions between client and backend until either
// side closes, then returns. It is the L4 data path.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// listener bundles the sockets and lo0 alias owned by one Service port so the
// worker can tear them down atomically.
type listener struct {
	key       PortKey
	clusterIP net.Listener
	nodePort  net.Listener
	// udp is the ClusterIP UDP datagram relay; it is non-nil only for a UDP port
	// (nil for TCP). Close reaps it, joining its dispatcher, sweeper, and per-flow
	// reader goroutines.
	udp     *udpRelay
	alias   aliasManager
	aliasIP netip.Addr
	log     *slog.Logger
}

// Close shuts the listeners and removes the lo0 alias, leak-free. It tolerates a
// partially-open listener (nil sockets) so failed opens clean up correctly.
func (l *listener) Close() {
	if l.clusterIP != nil {
		_ = l.clusterIP.Close()
	}
	if l.nodePort != nil {
		_ = l.nodePort.Close()
	}
	if l.udp != nil {
		// Tears down the VIP datagram socket, the sweeper, and every per-flow upstream
		// socket + reader, joining them all before returning (no stranded goroutine).
		_ = l.udp.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := l.alias.Remove(ctx, l.aliasIP); err != nil {
		l.log.Warn("remove lo0 alias", "vip", l.key.String(), "ip", l.aliasIP.String(), "err", err)
	}
}

// isExemptVIP reports whether addr is an infra VIP a node-local binder owns (set
// via WithInfraVIPExemptions), in which case the proxy yields ownership of every
// port on it. The map is immutable after construction so this needs no lock.
func (p *Proxy) isExemptVIP(addr netip.Addr) bool {
	_, ok := p.exemptVIPs[addr]
	return ok
}

// defaultProto returns p, defaulting the empty protocol to TCP (Kubernetes
// convention) so a PortKey is never built with an empty protocol.
func defaultProto(p netv1.Protocol) netv1.Protocol {
	if p == "" {
		return netv1.ProtocolTCP
	}
	return p
}
