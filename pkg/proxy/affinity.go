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
	"net/netip"
	"time"
)

// affinityDefaultTimeout is the ClientIP session-affinity idle TTL used when a
// Service requests ClientIP affinity without a SessionAffinityConfig timeout (or
// with a non-positive one). It mirrors Kubernetes'
// DefaultClientIPServiceAffinitySeconds (3h): a binding is always TTL-bounded and
// never infinite, so a client that goes silent eventually releases its backend.
const affinityDefaultTimeout = 3 * time.Hour

// maxAffinityBindingsPerPort bounds a single Service port's ClientIP binding table
// so a peer churning source IPs cannot grow it without limit. Same-node pods share
// one trust domain with no per-pod uid isolation, so this is a hard safety bound on
// top of the TTL sweep. It is generous, and an evicted binding pins no live resource
// (unlike the ClusterIP UDP datagram relay's per-flow socket), so over-cap eviction only degrades that client
// to a fresh round-robin pick; on saturation one existing binding is evicted in O(1)
// — a pseudo-random victim (Go map iteration is randomized), since a best-effort
// affinity overlay needs no true-LRU victim and this avoids an O(cap) scan under the
// table write lock. The relay-global aggregate ceiling (maxAffinityBindingsTotal)
// bounds the sum across all ports on top of this per-port cap.
const maxAffinityBindingsPerPort = 8192

// maxAffinityBindingsTotal is the relay-global ceiling on live ClientIP bindings
// summed across all Service ports (RoutingTable.affinityCount). The per-port cap bounds
// any single port, but a peer fanning source-IP churn across many Services could still
// grow the aggregate map unbounded; this caps node-wide affinity memory. It is 8x the
// per-port cap — sized well above a legitimate multi-Service steady state, so only
// pathological churn reaches it. On saturation PickSticky degrades a new client to
// round-robin (a valid backend, no binding recorded), never rejecting the connection:
// affinity is a fail-open overlay, so the worst realized effect is loss of stickiness,
// never a reachability break.
const maxAffinityBindingsTotal = 8 * maxAffinityBindingsPerPort

// affinityMode is the proxy-internal analog of corev1.ServiceAffinity for the one
// mode the userspace proxy implements: ClientIP. Like trafficPolicy it is consumed
// only by this proxy (the Watcher reads svc.Spec.SessionAffinity in serviceToVIP and
// threads it to the routing table), so it is not a field on the apis netv1
// contract — no cross-repo type carries session affinity.
type affinityMode uint8

const (
	// affinityNone is the zero value and default: no session affinity, so PickSticky
	// behaves exactly like Pick (round-robin). It is the mapping for a nil/None/
	// unrecognized SessionAffinity.
	affinityNone affinityMode = iota
	// affinityClientIP steers every connection from one client IP to the same
	// backend until the binding expires (idle past the port timeout) or the backend
	// leaves the eligible pool (unready, or under iTP:Local no longer node-local).
	affinityClientIP
)

// affinityConfig is the per-port session-affinity configuration threaded from the
// Service spec (serviceToVIP) through the reconcile path to SetEndpointsPolicy,
// which unpacks it onto the portState. The zero value is affinityNone (no affinity).
type affinityConfig struct {
	// mode is affinityClientIP or affinityNone.
	mode affinityMode
	// timeout is the ClientIP idle TTL; meaningful only when mode is affinityClientIP.
	timeout time.Duration
}

// affinityBinding is one client IP's sticky backend plus the last time it was
// selected. lastSeen drives idle expiry (refreshed on a PickSticky hit, evicted by
// SweepExpired).
type affinityBinding struct {
	backend  backend
	lastSeen time.Time
}

// PickSticky selects a backend for key honoring ClientIP session affinity on the
// INTERNAL (ClusterIP / east-west) accept path. It is a thin wrapper over
// pickStickyScoped with the internal scope (external=false), so the ClusterIP path
// gets the Ready + internalTrafficPolicy:Local-filtered pool (ErrNoLocalBackends when
// no node-local backend remains). See pickStickyScoped for the affinity mechanics.
func (t *RoutingTable) PickSticky(key PortKey, client netip.Addr, now time.Time) (backend, error) {
	return t.pickStickyScoped(key, client, now, false)
}

// PickStickyCluster selects a backend for key honoring ClientIP session affinity on
// the external (*:NodePort) accept path. It is a thin wrapper over pickStickyScoped
// with the external scope (external=true), so affinity is applied over the full Ready
// (Cluster) pool: externalTrafficPolicy governs NodePort and its default (Cluster)
// routes to all backends, and internalTrafficPolicy:Local is ignored here (KEP-2086) —
// a NodePort connection is never dropped for lack of a node-local backend, and a
// binding is always re-validated against the full Ready set (allSet), never the
// iTP:Local subset. It replaces the old non-sticky PickCluster: NodePort now honors
// ClientIP affinity over the Cluster pool. See pickStickyScoped for the mechanics.
func (t *RoutingTable) PickStickyCluster(key PortKey, client netip.Addr, now time.Time) (backend, error) {
	return t.pickStickyScoped(key, client, now, true)
}

// pickStickyScoped is the scope-parametrized core shared by PickSticky (internal /
// ClusterIP) and PickStickyCluster (external / NodePort). client is the connecting
// pod's IP with the ephemeral source port already stripped (see clientAddr) —
// affinity keys on the IP alone — and now is injected so expiry is testable without a
// real clock. external selects the pool scope by driving activePool: false yields the
// internalTrafficPolicy-filtered pool (with the iTP:Local drop/fail-open), true forces
// the full Ready (Cluster) pool.
//
// The pool and its membership set are consumed from the single activePool call, so
// every downstream step is scope-agnostic: the cached binding is re-validated against
// the set returned by activePool (for external=true that is allSet, not st.localSet),
// so the iTP:Local filter can never spill onto the NodePort surface, and the round-
// robin/evict/ceiling/record steps operate on whichever pool the scope selected.
//
// When the port's affinity mode is not ClientIP, pickStickyScoped is exactly Pick over
// the scope's pool: round-robin (so handle can call either wrapper unconditionally).
// Under ClientIP it reuses a client's existing binding only when that backend is still
// in the current active pool (O(1) membership in the returned set) and the binding is
// within the port's idle timeout; otherwise it round-robins a fresh backend and
// (re)binds. Re-validating against the live pool on every hit is load-bearing: a
// backend that went unready, or (internal scope) under iTP:Local left the node-local
// subset, is re-picked, never reused — so affinity never dials a dead backend nor (on
// the internal path) spills node-local traffic across the mesh. An internal-scope
// iTP:Local port with no node-local backend propagates ErrNoLocalBackends (a drop),
// never a stale/remote fallback; the external scope never returns it.
//
// The round-robin cursor is advanced only on a miss/expiry/invalidation, so a steady
// sticky client does not perturb the fan-out of new clients. pickStickyScoped takes
// the table write lock (it may create or refresh a binding, and shares Pick's
// locking).
//
// Trust model: the binding key is the client's source IP alone. On the internal
// (ClusterIP) surface, stickiness integrity inherits the same substrate anti-spoofing
// the TCP splice and iTP:Local locality already assume — a pod that could forge
// another's lo0 source IP could share, or (by churning IPs to the cap) evict, that
// client's binding. On the external (*:NodePort) surface, there is no such
// substrate: an off-cluster client presents an arbitrary, unauthenticated source IP
// (it is not a mesh pod and is not confined to the pod CIDR), so it can collide with
// an internal client's key (share a binding) or churn source IPs to consume the
// shared per-port/global budget (see "Shared budget" below). This opens no new
// isolation boundary: there is no path to observe another client's binding, every
// reuse is re-validated against the live Ready set (backends behind one Service are
// fungible endpoints of that Service), and the worst realized effect is loss of
// stickiness — a fresh, still-revalidated round-robin pick, never a routing,
// reachability, or observation break. It is fail-open by construction, not a
// containment control.
//
// Cross-scope couplings of the shared table-level t.affinity[key] map. The ClusterIP
// and *:NodePort listeners are opened with the same PortKey (proxy.go:562 and :577),
// so the binding sub-map for a port is shared across both scopes — the sub-map is
// intentionally not namespaced by scope — with three self-correcting consequences:
//
//   - Shared binding across surfaces: a client IP that hits both the ClusterIP and the
//     NodePort surface of one Service shares one binding, re-validated against each
//     scope's set on every hit. If a backend is eligible under one scope but not the
//     other (an iTP:Local Service whose bound backend is node-local: eligible on the
//     internal path, and still eligible on the external path since external uses the
//     full set), the mismatch only ever forces a drop-and-re-pick — never a wrong route.
//     Worst case is stickiness thrash between the two surfaces, never a reachability or
//     isolation break.
//   - Shared budget: external NodePort source-IP churn consumes the same
//     maxAffinityPerPort and relay-global affinityCount budget as east-west ClusterIP
//     bindings, so internet-facing churn on a port can evict on-node ClusterIP
//     stickiness for that same port (per-port cap) or, at the global ceiling, degrade
//     new ClusterIP clients to round-robin. This is fail-open: eviction/degradation
//     only loses stickiness, never reachability.
//   - Mesh-egress /32 collapse: cross-node mesh-forwarded NodePort traffic is
//     re-originated from the peer node's mesh-egress /32 (the userspace splice does not
//     preserve the external client's source IP — DESIGN §5b), so all such clients
//     behind one peer collapse to a single binding — coarse stickiness. But that one
//     binding is still re-validated against the live Cluster pool on every hit, so it
//     always resolves to a Ready backend — coarse, never wrong-routing.
func (t *RoutingTable) pickStickyScoped(key PortKey, client netip.Addr, now time.Time, external bool) (backend, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.states[key]
	if st == nil || len(st.all) == 0 {
		return backend{}, ErrNoBackends
	}
	pool, set, err := t.activePool(key, st, external)
	if err != nil {
		// e.g. internal-scope iTP:Local with no node-local backend: propagate the drop;
		// never fall back to a stale binding (that would spill node-local traffic to a
		// remote). The external scope is error-free today, but propagate rather than
		// discard so a future eTP:Local drop surfaces as an error, not a silent spill.
		return backend{}, err
	}
	// Defensive empty-pool guard (folded in from the old PickCluster): activePool's
	// non-error return is non-empty today, but a future subset scope could empty the
	// pool — guard roundRobin's cursor%len from a divide-by-zero.
	if len(pool) == 0 {
		return backend{}, ErrNoBackends
	}
	if st.affinityMode != affinityClientIP {
		return t.roundRobin(st, pool), nil
	}

	binds := t.affinity[key]
	if b := binds[client]; b != nil {
		// A hit is reused only if the bound backend is STILL eligible (O(1) membership
		// in the active pool's set) AND not idle past the timeout. Otherwise it is a
		// stale binding: drop it and re-pick below.
		if _, ok := set[b.backend.addr]; ok && now.Sub(b.lastSeen) < st.affinityTimeout {
			b.lastSeen = now
			return b.backend, nil
		}
		// Stale binding (backend left the pool, or idled past the timeout): drop it —
		// counter-aware, so a stale-refresh never leaks affinityCount (the client is
		// re-bound below at ++, or degraded at the ceiling; either way the map lost one).
		t.dropBinding(binds, client)
	}

	be := t.roundRobin(st, pool)
	perPortCap := max(1, t.maxAffinityPerPort)
	totalCap := max(1, t.maxAffinityTotal)

	// Per-port eviction runs before the global ceiling check: evicting one of this
	// port's own bindings to admit another is net-zero to affinityCount, so a port at
	// its per-port cap keeps rotating its bindings even under global saturation.
	if len(binds) >= perPortCap {
		// O(1) pseudo-random eviction: Go map iteration is randomized and a best-effort
		// affinity overlay needs no true-LRU victim, so evict the first entry range
		// visits. This replaces the affinity table's earlier O(cap) least-recently-seen scan under the lock.
		for k := range binds {
			t.dropBinding(binds, k)
			break
		}
	}

	// Relay-global aggregate ceiling. When the live-binding total across all ports is at
	// the cap, degrade this new client to round-robin: return the picked backend but
	// record no binding, so reachability is preserved and only stickiness is lost — this
	// is a fail-open overlay, never a reject or a closed connection. Warn once (throttled
	// by affinityWarned) so node-wide stickiness degradation is observable, not silent.
	if t.affinityCount >= totalCap {
		if !t.affinityWarned {
			t.affinityWarned = true
			t.log.Warn("ClientIP session affinity degraded to round-robin: relay-global binding ceiling reached; new clients stay reachable but lose stickiness",
				"bindings", t.affinityCount, "max", totalCap)
		}
		return be, nil
	}
	// Below the ceiling: clear the throttle so a later re-saturation warns again.
	t.affinityWarned = false

	if binds == nil {
		binds = make(map[netip.Addr]*affinityBinding)
		t.affinity[key] = binds
	}
	binds[client] = &affinityBinding{backend: be, lastSeen: now}
	t.affinityCount++
	return be, nil
}

// SweepExpired evicts every ClientIP affinity binding idle at least its port's
// timeout as of now. It is a pure, clock-injected method — no time.Now, no ticker,
// no goroutine inside the RoutingTable — so the table stays hermetic and
// table-testable; the owning Proxy drives it from a single sweeper goroutine
// (proxy.sweepAffinity), the affinity TTL's lifetime owner. An expired binding pins
// no live resource, so eviction only means that client round-robins a fresh backend
// on its next connection. Bindings whose port has vanished (no portState) are dropped
// wholesale.
func (t *RoutingTable) SweepExpired(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, binds := range t.affinity {
		st := t.states[key]
		if st == nil {
			// Orphaned port (its state vanished): drop wholesale, decrementing
			// affinityCount by the sub-map's cardinality so the total stays exact.
			t.dropAffinity(key)
			continue
		}
		for client, b := range binds {
			if now.Sub(b.lastSeen) >= st.affinityTimeout {
				t.dropBinding(binds, client) // single-key idle eviction
			}
		}
		if len(binds) == 0 {
			// The single-key deletes above already decremented; dropAffinity on the now-
			// empty sub-map subtracts 0 and removes the key (no double-count).
			t.dropAffinity(key)
		}
	}
}

// dropBinding removes one client's binding from binds and decrements the global
// affinityCount by one, keeping affinityCount an exact function of the affinity map. It
// is the single counter-aware single-key removal site: the stale-binding refresh drop,
// the per-port O(1) eviction, and the idle sweep all route through it, so a single-key
// delete can never leak the count (the wholesale sibling is dropAffinity). The caller
// holds t.mu and guarantees client is present in binds.
func (t *RoutingTable) dropBinding(binds map[netip.Addr]*affinityBinding, client netip.Addr) {
	delete(binds, client)
	t.affinityCount--
}

// dropAffinity removes key's entire ClientIP binding sub-map and decrements the global
// affinityCount by that sub-map's cardinality, keeping affinityCount an exact function
// of the affinity map. It is the single counter-aware wholesale-purge site: every place
// that drops a whole port's bindings — SetEndpointsPolicy (no Ready backends, or
// ClientIP toggled off), Delete, and SweepExpired's orphaned/empty-state drops — routes
// through it, so a wholesale delete can never leak the count (a per-call decrement would
// under-count by len(binds)-1 and drift the total up to the ceiling). A missing or
// already-empty sub-map decrements 0 (len(nil) == 0), so there is no special case. The
// caller holds t.mu.
func (t *RoutingTable) dropAffinity(key PortKey) {
	t.affinityCount -= len(t.affinity[key])
	delete(t.affinity, key)
}
