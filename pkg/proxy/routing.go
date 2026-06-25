package proxy

import (
	"fmt"
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
// reconcile path (SetEndpoints, one call per Service port key) and read by the
// accept path (Pick). Reads take the read lock; writes take the write lock.
// The table is independent of socket ownership — per-VIP reconcile serialization
// (one worker per ClusterIP:port) lives in the proxy server, not here.
type RoutingTable struct {
	// podCIDR, when valid, classifies backend locality. The zero Prefix means
	// locality is unknown (every backend is LocalityUnknown) — correctness of
	// steering does not depend on it; it is an optimization hint and a metric.
	podCIDR netip.Prefix

	mu       sync.RWMutex
	backends map[PortKey][]backend
	// picks counts Pick calls per key, giving the round-robin its deterministic,
	// monotonic cursor. It is reset when a key's backend set changes so the
	// distribution restarts predictably.
	picks map[PortKey]uint64
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
// which case backend locality is reported as LocalityUnknown; pass the node's
// podCIDR (e.g. netip.MustParsePrefix("100.64.0.0/24")) to enable local/remote
// classification.
func NewRoutingTable(podCIDR netip.Prefix) *RoutingTable {
	return &RoutingTable{
		podCIDR:  podCIDR,
		backends: make(map[PortKey][]backend),
		picks:    make(map[PortKey]uint64),
	}
}

// SetEndpoints replaces the backend set for key with the Ready endpoints in eps.
// Unready endpoints are dropped here, at the single admission point, so the
// accept path can never select one: there is no readiness check in Pick because
// an unready endpoint is never in the table. Endpoints are sorted by IP then
// port for deterministic ordering across reconciles. The per-key pick cursor is
// reset so the round-robin distribution restarts predictably whenever the set
// changes. SetEndpoints returns the number of Ready backends installed.
//
// Endpoints that fail netv1.Endpoint.Validate (empty IP, out-of-range port) or
// whose IP does not parse are skipped; they are not dialable.
func (t *RoutingTable) SetEndpoints(key PortKey, eps []netv1.Endpoint) int {
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

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(ready) == 0 {
		delete(t.backends, key)
	} else {
		t.backends[key] = ready
	}
	// Reset the cursor so distribution restarts deterministically on any change.
	delete(t.picks, key)
	return len(ready)
}

// Delete removes all backends for key (e.g. when a Service or port is deleted).
func (t *RoutingTable) Delete(key PortKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.backends, key)
	delete(t.picks, key)
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

// Pick selects the next backend for key using round-robin over the Ready set,
// advancing a per-key cursor so successive calls fan out across all backends.
// It is the accept-path selector: deterministic given a known call count, which
// is what makes the distribution table-assertable. SessionAffinity is out of
// scope for M1 — this is round-robin only. Pick returns ErrNoBackends when the
// key has no Ready backends.
func (t *RoutingTable) Pick(key PortKey) (backend, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	bes := t.backends[key]
	if len(bes) == 0 {
		return backend{}, ErrNoBackends
	}
	i := t.picks[key] % uint64(len(bes))
	t.picks[key]++
	return bes[i], nil
}

// PickAt selects the backend at index i modulo the Ready-set size, without
// touching the round-robin cursor. It is the explicit-index picker the unit
// tests use to assert the exact backend for a given index, decoupling
// distribution assertions from call ordering. It returns ErrNoBackends when the
// key has no Ready backends.
func (t *RoutingTable) PickAt(key PortKey, i uint64) (backend, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	bes := t.backends[key]
	if len(bes) == 0 {
		return backend{}, ErrNoBackends
	}
	return bes[i%uint64(len(bes))], nil
}

// Backends returns a copy of the Ready backend set for key, in deterministic
// (sorted) order. It is used by tests and diagnostics; the returned slice is
// owned by the caller.
func (t *RoutingTable) Backends(key PortKey) []backend {
	t.mu.RLock()
	defer t.mu.RUnlock()
	bes := t.backends[key]
	out := make([]backend, len(bes))
	copy(out, bes)
	return out
}

// Len reports the number of Ready backends for key.
func (t *RoutingTable) Len(key PortKey) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.backends[key])
}
