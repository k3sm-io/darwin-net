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
// serviceToVIP and threads it to the routing table — so it is deliberately NOT a
// field on the apis netv1 contract: no cross-repo type carries internalTrafficPolicy.
type trafficPolicy uint8

const (
	// trafficCluster is the zero value and default: Pick round-robins over ALL
	// Ready backends regardless of locality. It is kube-proxy's standard behavior
	// and the mapping for a nil or "Cluster" internalTrafficPolicy.
	trafficCluster trafficPolicy = iota
	// trafficLocal honors internalTrafficPolicy: Local. Under a valid node podCIDR
	// (locality is known) Pick steers ONLY to node-local backends and drops the
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
		podCIDR: podCIDR,
		states:  make(map[PortKey]*portState),
		log:     slog.Default(),
	}
}

// SetEndpoints replaces the backend set for key with the Ready endpoints in eps
// under the default trafficCluster policy (round-robin over all backends). It is
// SetEndpointsPolicy with internalTrafficPolicy: Cluster; the reconcile path calls
// SetEndpointsPolicy directly to carry a Service's actual policy.
func (t *RoutingTable) SetEndpoints(key PortKey, eps []netv1.Endpoint) int {
	return t.SetEndpointsPolicy(key, eps, trafficCluster)
}

// SetEndpointsPolicy replaces the backend set AND the traffic policy for key in a
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
func (t *RoutingTable) SetEndpointsPolicy(key PortKey, eps []netv1.Endpoint, policy trafficPolicy) int {
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

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(ready) == 0 {
		delete(t.states, key)
		return 0
	}
	t.states[key] = &portState{
		all:    ready,
		locals: locals,
		policy: policy,
	}
	return len(ready)
}

// Delete removes all backends for key (e.g. when a Service or port is deleted).
func (t *RoutingTable) Delete(key PortKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, key)
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

// ErrNoBackends is returned by Pick when a key has no Ready backends. The proxy
// translates it into a refused/timed-out connection (there is nowhere to steer).
var ErrNoBackends = fmt.Errorf("proxy: no ready backends for service port")

// ErrNoLocalBackends is returned by Pick for an internalTrafficPolicy: Local port
// whose Ready backends are ALL known-remote (the node has no local endpoint) under
// a VALID node podCIDR. It is the faithful upstream drop: the proxy closes the
// accepted connection rather than spilling node-local traffic across the mesh, so a
// pod that requested same-node endpoints never silently reaches another node. It is
// distinct from ErrNoBackends (no Ready endpoints at all) and never occurs under an
// unknown podCIDR — that path fails open to all backends (see Pick).
var ErrNoLocalBackends = fmt.Errorf("proxy: no node-local backends for internalTrafficPolicy:Local service port")

// Pick selects the next backend for key using round-robin, advancing a per-key
// cursor so successive calls fan out across the active pool. It is the accept-path
// selector: deterministic given a known call count, which is what makes the
// distribution table-assertable. SessionAffinity is out of scope for M1 — this is
// round-robin only.
//
// The active pool depends on the key's traffic policy:
//
//   - trafficCluster (the default): round-robin over ALL Ready backends.
//   - trafficLocal under a VALID podCIDR (locality is known): round-robin over the
//     precomputed node-local subset; if it is empty (every backend is known-remote)
//     return ErrNoLocalBackends so the proxy DROPS the connection — the faithful
//     upstream no-fallback, not a spill to a remote backend.
//   - trafficLocal under a ZERO/INVALID podCIDR (locality is unknowable — every
//     backend is LocalityUnknown): FAIL OPEN to all backends and emit a loud,
//     throttled Warn. LocalityUnknown is NOT the same as no-local; dropping here
//     would blackhole 100% of internalTrafficPolicy: Local Services on a node with
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

	pool := st.all
	if st.policy == trafficLocal {
		if t.podCIDR.IsValid() {
			// Locality is KNOWN: steer only to node-local backends, dropping when
			// none are local rather than spilling across the mesh.
			if len(st.locals) == 0 {
				return backend{}, ErrNoLocalBackends
			}
			pool = st.locals
		} else if !st.warned {
			// Locality is UNKNOWABLE (zero/invalid podCIDR): fail open to all
			// backends and warn once per backend set, so an unset/malformed podCIDR
			// degrades iTP: Local to Cluster loudly instead of blackholing it.
			st.warned = true
			t.log.Warn("internalTrafficPolicy:Local routing degraded to Cluster: node podCIDR is unset/invalid so backend locality is unknown; routing to ALL backends instead of dropping",
				"key", key.String(), "backends", len(st.all))
		}
	}

	i := st.cursor % uint64(len(pool))
	st.cursor++
	return pool[i], nil
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
