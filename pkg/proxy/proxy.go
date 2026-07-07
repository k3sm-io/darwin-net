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

	"golang.org/x/sys/unix"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/netbind"
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
	// policy is the optional NetworkPolicy L4-subset verdict table (M10.4),
	// consulted on the accept paths AFTER the backend pick. Nil (the default)
	// allows everything — PolicyTable.Allow is nil-receiver-safe, so the hooks are
	// unconditional. Set once by WithPolicyTable and read-only thereafter.
	policy *PolicyTable
	// udpBudget is the relay-GLOBAL admission budget shared by every per-VIP UDP relay:
	// it caps concurrent upstream sockets across ALL relays (so the datagram relays
	// cannot jointly exhaust the process fd table the co-resident control plane spends
	// from) AND caps any one source IP's flows across ALL VIPs (the per-source-GLOBAL
	// fair share, B52). Constructed once in New (RLIMIT_NOFILE-derived total, floored at
	// maxUDPFlows) or overridden by WithUDPFlowBudget; its maxTotal/maxPerSource are
	// read-only after construction, and it is a mutex-guarded LEAF that mutates its own
	// total/bySource under its OWN lock and never calls back into a relay, so it needs
	// no proxy lock.
	udpBudget *udpBudget

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

// WithUDPFlowBudget overrides the relay-GLOBAL cap on concurrent UDP upstream
// sockets shared by every per-VIP UDP relay. The default is derived from
// RLIMIT_NOFILE (see New); the k3sm assembler — which alone sees the whole process
// fd table (the TCP proxy, kine, and the apiserver client all spend from it) — passes
// this to partition the relay subsystem's fd slice deliberately, since a leaf
// subsystem must not unilaterally claim a process-global resource. A non-positive
// max is ignored, so the RLIMIT-derived default stands.
func WithUDPFlowBudget(max int64) Option {
	return func(p *Proxy) {
		if max > 0 {
			p.udpBudget = newUDPBudget(max, udpPerSourceGlobalCap(max))
		}
	}
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

// WithPolicyTable wires the NetworkPolicy L4-subset verdict table (M10.4): the
// accept paths consult it per (source, PICKED backend pod IP, backend port) —
// TCP in handle after the pick, UDP at relay flow admission — and refuse a denied
// connection/flow. Unset (nil) the proxy is policy-free: everything is allowed.
// The k3sm assembler constructs the table (NewPolicyTable with the node's
// always-allow seeds) and feeds it from a PolicyWatcher.
func WithPolicyTable(t *PolicyTable) Option {
	return func(p *Proxy) { p.policy = t }
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
		p.binder = &netdBinder{netd: &netbind.Netd{Client: c}}
	}
}

// New constructs a Proxy steering to the backends in table. By default it uses
// the root-gated lo0 alias manager; pass options to override (e.g. a logger).
//
// The relay-global UDP fd budget defaults to half the process's enforced soft fd
// limit (RLIMIT_NOFILE.Cur), floored at maxUDPFlows so a low launchd soft limit
// never regresses a single VIP below its B23 per-VIP capacity; WithUDPFlowBudget
// lets the k3sm assembler size the relay subsystem's fd slice against the whole
// process (the TCP proxy + control plane spend from the same table).
func New(table *RoutingTable, opts ...Option) *Proxy {
	maxTotal := defaultUDPFlowBudget()
	p := &Proxy{
		table:      table,
		alias:      newLo0AliasManager(),
		binder:     directBinder{},
		log:        slog.Default(),
		dialer:     &net.Dialer{Timeout: dialTimeout},
		exemptVIPs: make(map[netip.Addr]struct{}),
		udpBudget:  newUDPBudget(maxTotal, udpPerSourceGlobalCap(maxTotal)),
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
	// Same propagation for the policy table's two throttled data-path signals (the
	// unknown-source fail-open Warn and the deny Info); its logger() accessor
	// nil-guards a WithLogger(nil) override, like the routing table's.
	if p.policy != nil {
		p.policy.log = p.log
	}
	return p
}

// defaultUDPFlowBudget is the relay-global UDP upstream-socket budget when the
// assembler sets none (WithUDPFlowBudget). It is half the process's ENFORCED soft fd
// limit (RLIMIT_NOFILE.Cur — not Max, which may be unlimited), leaving the other half
// for the TCP proxy, the listeners, and the co-resident control plane, but floored at
// maxUDPFlows so a low launchd soft limit never regresses a single VIP's capacity
// below the B23 per-VIP bound. A Getrlimit error falls back to the floor.
//
// NOTE (deployment): the reservation only leaves REAL headroom for the co-resident
// control plane when the daemon's soft RLIMIT_NOFILE is provisioned above 2*maxUDPFlows
// (the launchd plist NumberOfFiles) OR the k3sm assembler passes WithUDPFlowBudget.
// Below that the floor dominates and the budget bounds only a single VIP — tracked in B52.
func defaultUDPFlowBudget() int64 {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		return maxUDPFlows
	}
	return max(int64(maxUDPFlows), int64(rl.Cur)/2)
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
// should tear its listeners down. policy is the Service's internalTrafficPolicy and
// affinity its ClientIP session-affinity config; both are applied to the routing
// table atomically with endpoints so a pick never observes a stale (policy,
// affinity, backends) pairing.
type portEvent struct {
	port      *netv1.ServicePort
	policy    trafficPolicy
	affinity  affinityConfig
	endpoints []netv1.Endpoint
}

// affinitySweepInterval is how often the Proxy evicts idle ClientIP session-affinity
// bindings from the routing table. It is a coarse backstop: PickSticky already
// re-validates and TTL-checks a binding inline on every connection, so the sweep only
// reclaims bindings of clients that have gone completely silent (and never redialed).
const affinitySweepInterval = 60 * time.Second

// Run starts the proxy's worker supervision loop and the ClientIP affinity idle
// sweeper, and blocks until ctx is cancelled, at which point it stops every worker
// (closing all listeners and removing every lo0 alias it created), joins the sweeper,
// and returns. Run is the single owner of the workers map mutation lifecycle and of
// the affinity sweeper goroutine.
func (p *Proxy) Run(ctx context.Context) error {
	sweeperDone := make(chan struct{})
	go func() {
		defer close(sweeperDone)
		if p.table != nil {
			p.sweepAffinity(ctx)
		}
	}()
	<-ctx.Done()
	p.shutdown()
	<-sweeperDone
	return ctx.Err()
}

// sweepAffinity is the single owner of the routing table's ClientIP affinity idle
// GC: every affinitySweepInterval it calls RoutingTable.SweepExpired(now). The table
// itself is deliberately clock-injected and goroutine-free (SweepExpired is pure), so
// this proxy-owned ticker is where the TTL's lifetime lives. It returns when ctx is
// cancelled; Run joins it after shutdown so it never outlives the Proxy.
func (p *Proxy) sweepAffinity(ctx context.Context) {
	ticker := time.NewTicker(affinitySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			p.table.SweepExpired(now)
		}
	}
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
	return p.ReconcilePolicy(clusterIP, port, trafficCluster, affinityConfig{}, endpoints)
}

// ReconcilePolicy delivers the desired state for one Service port — including its
// internalTrafficPolicy and ClientIP session-affinity config — to its dedicated
// worker, creating the worker on first sight. Passing port == nil signals deletion.
// Because every event for a given ClusterIP:port routes to the same worker channel,
// Service and EndpointSlice updates for that port are applied in a single serialized
// stream — no two goroutines ever touch one listener, and (policy, affinity,
// endpoints) reach the routing table together.
//
// ReconcilePolicy is safe for concurrent callers (the informer event handlers).
func (p *Proxy) ReconcilePolicy(clusterIP string, port *netv1.ServicePort, policy trafficPolicy, affinity affinityConfig, endpoints []netv1.Endpoint) error {
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
	case w.ch <- portEvent{port: port, policy: policy, affinity: affinity, endpoints: endpoints}:
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
			p.table.SetEndpointsPolicy(w.key, ev.endpoints, ev.policy, ev.affinity)
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
// and L4-load-balances to ALL Ready backends (the Cluster pool via PickStickyCluster,
// which also applies ClientIP session affinity over that pool) —
// externalTrafficPolicy: Cluster. internalTrafficPolicy:Local is IGNORED on the
// NodePort path: iTP governs the ClusterIP (east-west) path only (KEP-2086), so an
// iTP:Local Service still serves its NodePort to every backend rather than dropping
// when no backend is node-local — the *:NodePort listener no longer shares the
// ClusterIP's iTP:Local filter. externalTrafficPolicy: Local is NOT honored either,
// because the userspace splice (see splice) opens a fresh backend connection and
// therefore does NOT preserve the external client's source IP (the backend sees
// the proxy/mesh-egress source, not the client) — the precondition Local relies on —
// so an eTP:Local Service gets Cluster behavior on its NodePort (a documented divergence).
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
		relay := newUDPRelay(pc, key, p.table, p.meshEgress, udpFlowIdleTimeout, maxUDPFlowsPerSource, p.udpBudget, p.log)
		// NetworkPolicy L4 subset (M10.4): the relay consults the shared verdict
		// table at flow admission (upstreamFor, after its once-per-flow Pick). Set
		// before start so the dispatcher's read is covered by the goroutine-start
		// happens-before; nil means policy-free.
		relay.policy = p.policy
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
	go p.serve(cl, key, internalListener)

	// NodePort listener: bind the wildcard (*:NodePort) so every node interface
	// answers, load-balancing to ALL Ready backends via the external scope
	// (externalTrafficPolicy: Cluster — PickStickyCluster ignores internalTrafficPolicy:
	// Local while applying ClientIP session affinity over the Cluster pool; the splice
	// does not preserve client src IP, so eTP:Local is not honored either).
	if port.NodePort != 0 {
		nodeAddr := net.JoinHostPort("", strconv.Itoa(int(port.NodePort)))
		nl, err := net.Listen("tcp", nodeAddr)
		if err != nil {
			_ = cl.Close()
			_ = p.alias.Remove(ctx, ip)
			return nil, fmt.Errorf("listen nodePort %s: %w", nodeAddr, err)
		}
		l.nodePort = nl
		go p.serve(nl, key, externalListener)
	}
	return l, nil
}

// internalListener and externalListener name the accept-path scope threaded through
// serve/handle, so a call site reads its intent rather than a bare bool (matching the
// file's Locality/trafficPolicy enum idiom). The ClusterIP (east-west) listener is
// internal — it honors internalTrafficPolicy:Local and ClientIP affinity (PickSticky);
// the *:NodePort listener is external — externalTrafficPolicy governs it, so it routes
// to ALL Ready backends with ClientIP affinity over that Cluster pool
// (PickStickyCluster), ignoring iTP:Local.
const (
	internalListener = false
	externalListener = true
)

// serve accepts TCP connections on ln and proxies each to a backend chosen by the
// routing table. external selects the accept-path scope: the ClusterIP listener
// passes internalListener (iTP:Local + ClientIP affinity honored); the *:NodePort
// listener passes externalListener (externalTrafficPolicy:Cluster — route to ALL
// Ready backends). It returns when ln is closed (Accept errors).
func (p *Proxy) serve(ln net.Listener, key PortKey, external bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go p.handle(conn, key, external)
	}
}

// handle proxies one accepted client connection to a Ready backend. external selects
// the picker: the external (*:NodePort) path uses PickStickyCluster
// (externalTrafficPolicy:Cluster — ClientIP session affinity over ALL Ready backends,
// ignoring iTP:Local); the internal (ClusterIP) path uses PickSticky, honoring
// iTP:Local and ClientIP session affinity. BOTH paths extract the client IP with its
// ephemeral source port stripped (clientAddr), because affinity keys on the source IP
// alone; both pickers degrade to plain round-robin over their scope's pool for a
// non-affinity port, so either path is unconditional.
func (p *Proxy) handle(client net.Conn, key PortKey, external bool) {
	defer client.Close()
	src := clientAddr(client.RemoteAddr())
	var (
		be  backend
		err error
	)
	if external {
		be, err = p.table.PickStickyCluster(key, src, time.Now())
	} else {
		be, err = p.table.PickSticky(key, src, time.Now())
	}
	if err != nil {
		// Distinct messages so the two drop reasons are greppable, but BOTH stay at
		// Debug: handle logs per-connection, so Info here would FLOOD a steady-state
		// iTP:Local-starved Service; the throttled activePool Warn (once per backend
		// set) is the observable signal. The ErrNoLocalBackends arm is ClusterIP-only —
		// PickStickyCluster (external) forces the Cluster pool and never returns it.
		if errors.Is(err, ErrNoLocalBackends) {
			p.logger().Debug("no node-local backend for internalTrafficPolicy:Local connection", "vip", key.String(), "err", err)
		} else {
			p.logger().Debug("no backend for connection", "vip", key.String(), "external", external, "err", err)
		}
		return
	}
	// NetworkPolicy L4-subset verdict (M10.4), AFTER the pick — per (source,
	// picked-backend pod IP, backend port), never per VIP, because one Service can
	// front policy-heterogeneous pods. A deny closes the accepted connection
	// (deferred Close → client sees RST/EOF) before any backend dial; nil p.policy
	// allows unconditionally (Allow is nil-receiver-safe).
	if !p.policy.Allow(src, be.Addr().Addr(), be.Addr().Port()) {
		p.policy.logDenied("tcp", key, src, be.Addr())
		return
	}
	backendConn, err := p.dialer.Dial("tcp", be.Addr().String())
	if err != nil {
		p.logger().Debug("dial backend", "vip", key.String(), "backend", be.Addr().String(), "err", err)
		return
	}
	defer backendConn.Close()
	splice(client, backendConn)
}

// logger returns p.log, or slog.Default() when it is nil. New copies the (possibly nil)
// option-supplied logger into p.log AFTER the options run, so WithLogger(nil) would
// otherwise nil-deref on the per-connection handle drop/dial-fail path — a bare
// `go p.handle` goroutine with no recover, i.e. a daemon crash on the exact no-backend
// input this path handles. Mirrors RoutingTable.logger (the table's fail-open Warn), so
// BOTH nil-log sinks on the no-backend data path are guarded (go-standards: never panic
// in library code).
func (p *Proxy) logger() *slog.Logger {
	if p.log == nil {
		return slog.Default()
	}
	return p.log
}

// clientAddr extracts the client's IP — with the ephemeral source port stripped —
// from a connection's remote address, for ClientIP session affinity: affinity keys
// on the source IP ALONE, so keying on the full IP:port would silently degrade
// stickiness to per-connection (no stickiness at all). A remote address that is nil
// or does not parse yields the zero Addr, which is harmless: that client just shares
// one affinity bucket (and for a non-affinity port the IP is ignored entirely).
//
// Cross-node fidelity caveat: this is the source IP THIS proxy sees. Same-node
// ClusterIP traffic arrives on loopback carrying the real pod lo0 IP (faithful), but
// cross-node / NodePort traffic is re-originated from the peer node's mesh-egress /32
// (the splice does not preserve the client src IP — DESIGN §5b), so all cross-node
// clients behind one peer collapse to a single affinity binding — a userspace-L4
// limitation, not a bug.
func clientAddr(remote net.Addr) netip.Addr {
	if remote == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
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
