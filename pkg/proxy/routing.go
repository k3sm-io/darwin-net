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
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// Locality classifies a backend as local to this node or remote (reachable only
// over the wireguard mesh). It is computed proxy-side from the node podCIDR with
// a cheap CIDR Contains, avoiding a getifaddrs scan per connection.
type Locality uint8

const (
	// LocalityUnknown is the zero value: locality has not been computed (no node
	// podCIDR was configured on the table).
	LocalityUnknown Locality = iota
	// LocalityLocal means the backend IP falls inside the node podCIDR, so it is a
	// same-node lo0 pod IP reachable over loopback with no mesh hop.
	LocalityLocal
	// LocalityRemote means the backend IP is outside the node podCIDR, so it is a
	// pod on another node reachable over the wireguard mesh.
	LocalityRemote
)

// String renders the locality for logs.
func (l Locality) String() string {
	switch l {
	case LocalityLocal:
		return "local"
	case LocalityRemote:
		return "remote"
	default:
		return "unknown"
	}
}

// trafficPolicy is the proxy-internal analog of corev1.ServiceInternalTrafficPolicy:
// it selects which backends Pick may steer a Service port's connections to. It is
// consumed only by this proxy — the Watcher reads svc.Spec.InternalTrafficPolicy in
// serviceToVIP and threads it to the routing table — so it is not a field on the
// apis netv1 contract: no cross-repo type carries internalTrafficPolicy.
type trafficPolicy uint8

const (
	// trafficCluster is the zero value and default: Pick round-robins over all
	// Ready backends regardless of locality. It is kube-proxy's standard behavior
	// and the mapping for a nil or "Cluster" internalTrafficPolicy.
	trafficCluster trafficPolicy = iota
	// trafficLocal honors internalTrafficPolicy: Local. Under a valid node podCIDR
	// (locality is known) Pick steers only to node-local backends and drops the
	// connection when none are local (the faithful upstream no-fallback). Under a
	// zero/invalid podCIDR (locality is unknowable) Pick fails open to all backends
	// rather than blackhole the Service — see Pick.
	trafficLocal
)

// backend is one dialable endpoint plus its precomputed locality. It is the
// routing table's internal view of a netv1.Endpoint: only Ready endpoints are
// admitted, so a backend in the table is always selectable.
type backend struct {
	addr     netip.AddrPort
	locality Locality
}

// Addr returns the dial target for this backend.
func (b backend) Addr() netip.AddrPort { return b.addr }

// Locality reports whether the backend is local (loopback) or remote (mesh).
func (b backend) Locality() Locality { return b.locality }

// RoutingTable is the pure-logic core of the Service proxy: it maps a
// ClusterIP:port to the ordered set of Ready backends and picks one per
// connection. It carries no sockets, no informers, and no I/O, so its load-
// balancing behavior is fully table-testable.
//
// Locking discipline: all state is guarded by mu. The table is written by the
// reconcile path (SetEndpointsPolicy, one call per Service port key) and read by
// the accept path (Pick). Pick takes the write lock because it advances a per-key
// round-robin cursor; the read-only inspectors (Backends, Len, PickAt) take the
// read lock. The table is independent of socket ownership — per-VIP reconcile
// serialization (one worker per ClusterIP:port) lives in the proxy server, not
// here.
type RoutingTable struct {
	// podCIDR, when valid, classifies backend locality. The zero Prefix means
	// locality is unknown (every backend is LocalityUnknown). It is load-bearing
	// for one decision only: internalTrafficPolicy: Local backend selection (see
	// Pick). For every other path locality stays a hint/metric — cross-node
	// steering is by the mesh's per-peer kernel routes, not this classifier.
	podCIDR netip.Prefix

	mu     sync.RWMutex
	states map[PortKey]*portState
	// affinity holds ClientIP session-affinity bindings: PortKey -> client IP -> the
	// backend that client is stuck to. It is table-level (guarded by the same mu, so
	// the affinity and routing locks are folded into one — no two-lock ordering
	// hazard) and not a portState field, so a binding survives endpoint churn:
	// SetEndpointsPolicy replaces the portState on every reconcile, which would wipe
	// a per-portState map. Bindings are re-validated against the live pool on every
	// PickSticky hit and idle-swept by the owning Proxy (SweepExpired); only
	// ClientIP ports have entries here (a None or deleted port is purged).
	affinity map[PortKey]map[netip.Addr]*affinityBinding
	// affinityCount is the live-binding total across all PortKeys — the sum of
	// len(binds) over the affinity map — guarded by mu. It is a plain int under the
	// single table lock, not an atomic: unlike B48's cross-lock udpBudget it never
	// leaves mu. It backs the relay-global aggregate ceiling (maxAffinityTotal) and
	// must stay an exact function of the affinity map's cardinality — +1 at the one
	// create in PickSticky, -1 at each single-key delete (routed through
	// dropBinding: the stale-binding refresh, the per-port evict, and the idle
	// sweep), and -len(binds) at each wholesale delete (routed through
	// dropAffinity) — or it would leak upward until the ceiling wedged every
	// Service on the node to round-robin.
	affinityCount int
	// maxAffinityPerPort bounds any single PortKey's binding sub-map (default
	// maxAffinityBindingsPerPort). Read via max(1, …) in PickSticky so a non-positive
	// override cannot break the evict-removes-exactly-one accounting.
	maxAffinityPerPort int
	// maxAffinityTotal bounds affinityCount across all PortKeys (default
	// maxAffinityBindingsTotal) — the relay-global memory bound. On saturation PickSticky
	// degrades a new client to round-robin (no binding recorded), never rejecting it.
	// Read via max(1, …) in PickSticky so a non-positive override still admits one.
	maxAffinityTotal int
	// affinityWarned throttles the aggregate-ceiling degradation Warn to fire once per
	// saturation episode (mirroring portState.warned for the iTP:Local fail-open): it is
	// set when the global ceiling first engages and cleared by PickSticky once the count
	// falls back below the cap, so a later re-saturation is logged again, not silent.
	affinityWarned bool
	// transport maps a backend's published address (the identity in the routing
	// table, the EndpointSlice, DNS and status.podIP) to the live transport address
	// the dial must actually use. It is empty on every node that hosts no vm pod, so
	// the resolution is a single map miss on the ordinary path. Guarded by mu and
	// replaced wholesale by SetTransportOverrides (the same atomic-swap lifecycle
	// SetEndpointsPolicy and PolicyTable.Update use), so a generation of overrides can
	// never leak into the next one. See SetTransportOverrides for the full contract.
	transport map[netip.Addr]netip.Addr

	// log records the fail-open degradation when internalTrafficPolicy: Local meets
	// an unknown podCIDR (a loud, throttled Warn so the misconfig is observable). It
	// defaults to slog.Default() in NewRoutingTable and is overridden by the owning
	// Proxy's logger in proxy.New. It is set before any worker starts, so reads in
	// Pick need no extra synchronization beyond the goroutine-start happens-before.
	log *slog.Logger
}

// portState is the per-PortKey routing state for one bound Service port. Every
// field is written together under the table write lock in SetEndpointsPolicy, so
// Pick always observes a consistent (policy, all, locals) snapshot: a connection
// can never see a freshly installed backend set paired with a stale policy, and
// the node-local subset is precomputed once per reconcile rather than rescanned
// per connection.
type portState struct {
	// all is every Ready backend for the key, sorted by IP then port. It is the
	// trafficCluster pool and the fail-open pool.
	all []backend
	// locals is the LocalityLocal subset of all (same sorted order), precomputed at
	// reconcile time. It is the trafficLocal pool under a valid podCIDR.
	locals []backend
	// policy is the internalTrafficPolicy of the owning Service, applied to this
	// port. It selects the pool Pick round-robins over.
	policy trafficPolicy
	// cursor is the round-robin cursor over the active pool. SetEndpointsPolicy
	// installs a fresh state (cursor 0) on any change so distribution restarts
	// deterministically.
	cursor uint64
	// warned records that the fail-open Warn has already fired for this state, so
	// an unknown-podCIDR iTP: Local port logs once per backend set, not per
	// connection. A new state (a reconcile) clears it.
	warned bool
	// affinityMode is the port's session-affinity mode (affinityClientIP or
	// affinityNone), installed from the Service's SessionAffinity each reconcile. It
	// is config, not bindings — the bindings live table-level in RoutingTable.affinity
	// so they survive this portState being replaced.
	affinityMode affinityMode
	// affinityTimeout is the ClientIP idle TTL (from SessionAffinityConfig, defaulted
	// by the translate layer / clamped in SetEndpointsPolicy). Meaningful only when
	// affinityMode is affinityClientIP.
	affinityTimeout time.Duration
	// allSet and localSet are membership sets over all and locals (same contents,
	// O(1) lookup), precomputed in SetEndpointsPolicy so PickSticky can re-validate a
	// cached binding against the active pool without an O(N) slice scan. localSet is
	// nil when there are no node-local backends.
	allSet   map[netip.AddrPort]struct{}
	localSet map[netip.AddrPort]struct{}
}

// PortKey identifies one bound Service port: the ClusterIP plus the Service Port
// (not the TargetPort). It is the per-VIP reconcile key and the routing-table
// key, so a Service vs EndpointSlice event for the same port always lands on one
// owner.
type PortKey struct {
	// ClusterIP is the VIP the proxy binds (an lo0 alias address).
	ClusterIP string
	// Port is the Service port exposed on ClusterIP (the listener port).
	Port int32
	// Protocol is the L4 transport, so a TCP and a UDP port that share a number
	// are distinct keys.
	Protocol netv1.Protocol
}

// String renders the key as clusterIP:port/proto for logs and worker names.
func (k PortKey) String() string {
	return fmt.Sprintf("%s:%d/%s", k.ClusterIP, k.Port, k.Protocol)
}

// NewRoutingTable returns an empty table. podCIDR may be the zero Prefix, in
// which case backend locality is reported as LocalityUnknown and an
// internalTrafficPolicy: Local Service fails open (routes to all backends) rather
// than drop; pass the node's podCIDR (e.g. netip.MustParsePrefix("100.64.0.0/24"))
// to enable local/remote classification and node-local filtering.
func NewRoutingTable(podCIDR netip.Prefix) *RoutingTable {
	return &RoutingTable{
		podCIDR:            podCIDR,
		states:             make(map[PortKey]*portState),
		transport:          make(map[netip.Addr]netip.Addr),
		affinity:           make(map[PortKey]map[netip.Addr]*affinityBinding),
		maxAffinityPerPort: maxAffinityBindingsPerPort,
		maxAffinityTotal:   maxAffinityBindingsTotal,
		log:                slog.Default(),
	}
}

// SetEndpoints replaces the backend set for key with the Ready endpoints in eps
// under the default trafficCluster policy (round-robin over all backends). It is
// SetEndpointsPolicy with internalTrafficPolicy: Cluster; the reconcile path calls
// SetEndpointsPolicy directly to carry a Service's actual policy.
func (t *RoutingTable) SetEndpoints(key PortKey, eps []netv1.Endpoint) int {
	return t.SetEndpointsPolicy(key, eps, trafficCluster, affinityConfig{})
}

// SetEndpointsPolicy replaces the backend set and the traffic policy for key in a
// single locked write, so (policy, backends, node-local subset) is always a
// consistent snapshot for Pick. Unready endpoints are dropped here, at the single
// admission point, so the accept path can never select one: there is no readiness
// check in Pick because an unready endpoint is never in the table. Endpoints are
// sorted by IP then port for deterministic ordering, and the LocalityLocal subset
// is precomputed once (not rescanned per connection) for trafficLocal selection.
// The per-key pick cursor and fail-open warn-throttle are reset so distribution
// and observability restart predictably whenever the set changes.
// SetEndpointsPolicy returns the number of Ready backends installed.
//
// Endpoints that fail netv1.Endpoint.Validate (empty IP, out-of-range port) or
// whose IP does not parse are skipped; they are not dialable.
//
// aff carries the port's ClientIP session-affinity config (installed onto the new
// portState alongside policy). The ClientIP bindings themselves live table-level and
// are not touched here when affinity stays on — they survive the portState swap and
// PickSticky re-validates them against the fresh backend set. They are purged when
// affinity is off (aff.mode != ClientIP) or the port has no Ready backends, so a
// Service toggled ClientIP->None (or drained) leaves no stale bindings to resurrect.
// Membership sets over the full and node-local pools are precomputed here (the O(N)
// slice build is already paid) so PickSticky re-validation is O(1).
func (t *RoutingTable) SetEndpointsPolicy(key PortKey, eps []netv1.Endpoint, policy trafficPolicy, aff affinityConfig) int {
	ready := make([]backend, 0, len(eps))
	for _, ep := range eps {
		if !ep.Ready {
			continue
		}
		if err := ep.Validate(); err != nil {
			continue
		}
		addr, err := netip.ParseAddr(ep.IP)
		if err != nil {
			continue
		}
		ready = append(ready, backend{
			addr:     netip.AddrPortFrom(addr, uint16(ep.Port)),
			locality: t.classify(addr),
		})
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].addr.Addr() != ready[j].addr.Addr() {
			return ready[i].addr.Addr().Less(ready[j].addr.Addr())
		}
		return ready[i].addr.Port() < ready[j].addr.Port()
	})

	// Precompute the node-local subset (preserving the sorted order) so a
	// trafficLocal Pick round-robins picks%len(locals) over a ready-made slice
	// instead of indexing the full set and filtering — or rescanning O(N) — per
	// connection.
	var locals []backend
	for _, b := range ready {
		if b.locality == LocalityLocal {
			locals = append(locals, b)
		}
	}

	// Precompute membership sets over the full set and the node-local subset so
	// PickSticky can re-validate a ClientIP binding against the active pool in O(1)
	// instead of an O(N) slice scan. localSet stays nil when there are no locals.
	allSet := make(map[netip.AddrPort]struct{}, len(ready))
	for _, b := range ready {
		allSet[b.addr] = struct{}{}
	}
	var localSet map[netip.AddrPort]struct{}
	if len(locals) > 0 {
		localSet = make(map[netip.AddrPort]struct{}, len(locals))
		for _, b := range locals {
			localSet[b.addr] = struct{}{}
		}
	}

	// A ClientIP port always carries a positive TTL (the translate layer defaults an
	// absent/zero timeout to affinityDefaultTimeout); clamp defensively so no caller
	// can install an instantly-expiring binding.
	if aff.mode == affinityClientIP && aff.timeout <= 0 {
		aff.timeout = affinityDefaultTimeout
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(ready) == 0 {
		delete(t.states, key)
		t.dropAffinity(key) // no backends: any bindings are meaningless
		return 0
	}
	if aff.mode != affinityClientIP {
		// Affinity off for this port: purge bindings so a Service toggled
		// ClientIP->None (or never sticky) leaves nothing to resurrect on re-enable.
		t.dropAffinity(key)
	}
	t.states[key] = &portState{
		all:             ready,
		locals:          locals,
		policy:          policy,
		affinityMode:    aff.mode,
		affinityTimeout: aff.timeout,
		allSet:          allSet,
		localSet:        localSet,
	}
	return len(ready)
}

// Delete removes all backends for key (e.g. when a Service or port is deleted),
// including any ClientIP affinity bindings so a re-created port never resurrects a
// stale stickiness.
func (t *RoutingTable) Delete(key PortKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, key)
	t.dropAffinity(key)
}

// SetTransportOverrides atomically replaces the published-to-live transport
// address map, the seam the two-address vm-pod identity model needs (M11.3-d2).
//
// # The two addresses
//
// A vm-RuntimeClass pod has two addresses and they are never the same one. The /32
// carved from the node podCIDR is its published identity — what EndpointSlices,
// cluster DNS and status.podIP carry, and the address every NetworkPolicy names.
// It is live on no interface for a vm pod: the host must not alias the guest's
// identity on lo0 or it would answer for it. The address that actually carries
// bytes is the guest's macOS-assigned vmnet DHCP lease, which is never published.
// This map is the only place the two meet: keys are published addresses, values
// are the live lease addresses to dial instead. The port is not overridden — a
// backend's port is the guest's real listening port, which the lease does not
// change.
//
// # Who feeds it (nobody yet — stated honestly)
//
// The feeder is the k3sm assembler, from the guest agent's Health lease report: it
// is the only component that may hold both the runtimed-side guest view and this
// darwin-net table (darwin-net cannot reach for a runtimed type — see the repo DAG),
// so darwin-net exposes the seam and holds no opinion about the source. That
// host-side consumer does not exist yet. Until it is built, no override is ever
// installed and every backend is dialed exactly as it is today.
//
// # The liveness contract (the feeder's obligation, not this table's)
//
// A DHCP lease is not an identity. The feeder must replace an override when the
// pod's lease changes and must drop it when the pod dies — a stale override dials a
// live address that now belongs to a different guest, which is a cross-pod
// misdelivery, not a failed dial. This table cannot detect that: it has no lease
// watch and no liveness signal, and does not invent one. Wholesale replacement is
// what makes the obligation cheap to discharge: pass the full current map on every
// lease report and the previous generation is dropped entire.
//
// # No fallback, by design
//
// A backend with no override is dialed at its published address — byte-identical to
// today's behavior, which is what keeps every host-process pod untouched. For a vm
// pod that is the /32 that is live on no interface, so the dial fails the way any
// unreachable backend's dial fails today (a refusal or a dialTimeout, logged at
// Debug). That is the intended outcome: an absent override means undialable. The
// table never substitutes some other address to paper over a missing override,
// because the only candidates are wrong — the published /32 XNU will blackhole, or a
// stale lease pointing at another tenant's guest.
//
// overrides is defensively copied and normalized (v4-mapped-v6 unmapped on both
// sides; entries with an invalid key or value skipped, mirroring NewPolicyTable's
// invalid-seed skip), so the caller may retain and reuse its map. A nil or empty map
// clears every override.
func (t *RoutingTable) SetTransportOverrides(overrides map[netip.Addr]netip.Addr) {
	next := make(map[netip.Addr]netip.Addr, len(overrides))
	for published, live := range overrides {
		if !published.IsValid() || !live.IsValid() {
			continue
		}
		next[published.Unmap()] = live.Unmap()
	}
	t.mu.Lock()
	t.transport = next
	t.mu.Unlock()
}

// transportAddr resolves a picked backend's published address to the address the
// dial must use: the live transport override when one is installed for it (keeping
// the published port), otherwise the published address unchanged.
//
// It is called at the dial sites only — proxy.handle for TCP and udpRelay.upstreamFor
// for UDP — never at pick, policy, or affinity time. That split is load-bearing: the
// NetworkPolicy verdict, the deny log, the ClientIP affinity binding and the
// endpoint-set membership all key on the published identity, which is the address
// policies and Services name and the one that survives a lease change. Only the
// packet needs the lease.
func (t *RoutingTable) transportAddr(published netip.AddrPort) netip.AddrPort {
	t.mu.RLock()
	live, ok := t.transport[published.Addr().Unmap()]
	t.mu.RUnlock()
	if !ok {
		return published
	}
	return netip.AddrPortFrom(live, published.Port())
}

// classify computes a backend's locality from the node podCIDR. A zero podCIDR
// yields LocalityUnknown. It does not lock; callers hold no lock requirement
// because podCIDR is immutable after construction.
func (t *RoutingTable) classify(addr netip.Addr) Locality {
	if !t.podCIDR.IsValid() {
		return LocalityUnknown
	}
	if t.podCIDR.Contains(addr) {
		return LocalityLocal
	}
	return LocalityRemote
}

// logger returns the table's structured logger, defaulting to slog.Default() when
// unset — never a nil pointer. It guards the table's nil-log vector (the fail-open
// Warn in activePool): proxy.New copies p.table.log = p.log unconditionally after
// options run, so proxy.New(table, WithLogger(nil)) leaves this table's log nil;
// routing that Warn through this accessor keeps the path from a nil-pointer deref
// (never panic in library code — GO-STANDARDS.md §Errors). Proxy.logger is the
// sibling accessor guarding handle's per-connection Debug sinks.
func (t *RoutingTable) logger() *slog.Logger {
	if t.log == nil {
		return slog.Default()
	}
	return t.log
}

// ErrNoBackends is returned by Pick when a key has no Ready backends. The proxy
// translates it into a refused/timed-out connection (there is nowhere to steer).
var ErrNoBackends = fmt.Errorf("proxy: no ready backends for service port")

// ErrNoLocalBackends is returned by Pick for an internalTrafficPolicy: Local port
// whose Ready backends are all known-remote (the node has no local endpoint) under
// a valid node podCIDR. It is the faithful upstream drop: the proxy closes the
// accepted connection rather than spilling node-local traffic across the mesh, so a
// pod that requested same-node endpoints never silently reaches another node. It is
// distinct from ErrNoBackends (no Ready endpoints at all) and never occurs under an
// unknown podCIDR — that path fails open to all backends (see Pick).
var ErrNoLocalBackends = fmt.Errorf("proxy: no node-local backends for internalTrafficPolicy:Local service port")

// activePool returns the policy-correct backend pool for st together with a
// membership set over that exact pool, or an error that must be surfaced (never
// masked by a fallback). It is the single selector, parametrized by a scope rather
// than forked: activePool is not bypassed for NodePort — PickStickyCluster calls it
// with external=true — so the Ready-set selection can never drift between the
// ClusterIP and NodePort paths.
//
//   - external (the *:NodePort accept path, PickStickyCluster): the full Ready set
//     (all / allSet), unconditionally. externalTrafficPolicy governs NodePort and
//     its default (Cluster) routes to all backends; internalTrafficPolicy:Local
//     governs the ClusterIP (east-west) path only (KEP-2086), so it is ignored
//     here — a NodePort connection is never dropped for lack of a node-local
//     backend.
//   - internal + trafficCluster (Pick/PickSticky): the full Ready set (all / allSet).
//   - internal + trafficLocal under a valid podCIDR: the node-local subset (locals /
//     localSet), or ErrNoLocalBackends when that subset is empty — the faithful
//     upstream drop, never a spill to a remote backend.
//   - internal + trafficLocal under a zero/invalid podCIDR: locality is unknowable, so
//     it fails open to the full set and warns once per backend set (degrade-to-Cluster,
//     never a blackhole). The fail-open is on !podCIDR.IsValid() only — a valid but
//     wrong prefix still drops, since podCIDR drives lo0 alias allocation.
//
// The set is returned so PickSticky can re-validate a cached binding against the live
// pool in O(1). The caller must hold t.mu (activePool may flip st.warned and log).
func (t *RoutingTable) activePool(key PortKey, st *portState, external bool) ([]backend, map[netip.AddrPort]struct{}, error) {
	pool, set := st.all, st.allSet
	if external {
		// External (NodePort) scope: externalTrafficPolicy governs, and its default
		// (Cluster) routes to all Ready backends. Return the full pool before the
		// iTP:Local branch so an iTP:Local Service with no node-local backend still
		// serves its NodePort — iTP governs the ClusterIP path only (KEP-2086).
		return st.all, st.allSet, nil
	}
	if st.policy == trafficLocal {
		if t.podCIDR.IsValid() {
			// Locality is known: steer only to node-local backends, dropping when none
			// are local rather than spilling across the mesh.
			if len(st.locals) == 0 {
				return nil, nil, ErrNoLocalBackends
			}
			pool, set = st.locals, st.localSet
		} else if !st.warned {
			// Locality is unknowable (zero/invalid podCIDR): fail open to all backends
			// and warn once per backend set, so an unset/malformed podCIDR degrades
			// iTP: Local to Cluster loudly instead of blackholing it.
			st.warned = true
			t.logger().Warn("internalTrafficPolicy:Local routing degraded to Cluster: node podCIDR is unset/invalid so backend locality is unknown; routing to ALL backends instead of dropping",
				"key", key.String(), "backends", len(st.all))
		}
	}
	return pool, set, nil
}

// roundRobin returns the next backend in pool and advances st's per-key cursor so
// successive calls fan out. pool must be non-empty (activePool guarantees it for a
// non-error return). The caller holds t.mu.
func (t *RoutingTable) roundRobin(st *portState, pool []backend) backend {
	i := st.cursor % uint64(len(pool))
	st.cursor++
	return pool[i]
}

// Pick selects the next backend for key using round-robin, advancing a per-key
// cursor so successive calls fan out across the active pool. It is the ClusterIP
// (internal / east-west) accept-path selector: deterministic given a known call
// count, which is what makes the distribution table-assertable. Pick is round-robin
// only; ClientIP session affinity layers on top via PickSticky (affinity.go). Both
// ClusterIP selectors call activePool with the internal scope (external=false), so
// round-robin and sticky selection can never diverge on which backends are eligible;
// the NodePort path is PickStickyCluster, which calls the same activePool with the
// external scope (forcing the Cluster pool, ignoring internalTrafficPolicy:Local).
//
// The active pool depends on the key's traffic policy:
//
//   - trafficCluster (the default): round-robin over all Ready backends.
//   - trafficLocal under a valid podCIDR (locality is known): round-robin over the
//     precomputed node-local subset; if it is empty (every backend is known-remote)
//     return ErrNoLocalBackends so the proxy drops the connection — the faithful
//     upstream no-fallback, not a spill to a remote backend.
//   - trafficLocal under a zero/invalid podCIDR (locality is unknowable — every
//     backend is LocalityUnknown): fail open to all backends and emit a loud,
//     throttled Warn. LocalityUnknown is not the same as no-local; dropping here
//     would blackhole every internalTrafficPolicy: Local Service on a node with
//     an unset/malformed/mismatched podCIDR. Degrading to Cluster keeps the Service
//     reachable and makes the misconfiguration observable.
//
// Pick returns ErrNoBackends when the key has no Ready backends at all.
func (t *RoutingTable) Pick(key PortKey) (backend, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.states[key]
	if st == nil || len(st.all) == 0 {
		return backend{}, ErrNoBackends
	}
	pool, _, err := t.activePool(key, st, false)
	if err != nil {
		return backend{}, err
	}
	return t.roundRobin(st, pool), nil
}

// PickAt selects the backend at index i modulo the Ready-set size, without
// touching the round-robin cursor or applying the traffic policy. It is the
// explicit-index picker the unit tests use to assert the exact backend for a given
// index over the full set, decoupling distribution assertions from call ordering.
// It returns ErrNoBackends when the key has no Ready backends.
func (t *RoutingTable) PickAt(key PortKey, i uint64) (backend, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	st := t.states[key]
	if st == nil || len(st.all) == 0 {
		return backend{}, ErrNoBackends
	}
	return st.all[i%uint64(len(st.all))], nil
}

// Backends returns a copy of the Ready backend set for key, in deterministic
// (sorted) order. It is used by tests and diagnostics; the returned slice is
// owned by the caller.
func (t *RoutingTable) Backends(key PortKey) []backend {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var bes []backend
	if st := t.states[key]; st != nil {
		bes = st.all
	}
	out := make([]backend, len(bes))
	copy(out, bes)
	return out
}

// Len reports the number of Ready backends for key.
func (t *RoutingTable) Len(key PortKey) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if st := t.states[key]; st != nil {
		return len(st.all)
	}
	return 0
}
