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
// top of the TTL sweep. It is generous, and an evicted binding pins NO live resource
// (unlike B23's per-flow UDP socket), so over-cap eviction only degrades that client
// to a fresh round-robin pick; on saturation the OLDEST binding is evicted to admit
// the newest.
const maxAffinityBindingsPerPort = 8192

// affinityMode is the proxy-internal analog of corev1.ServiceAffinity for the one
// mode the userspace proxy implements: ClientIP. Like trafficPolicy it is consumed
// ONLY by this proxy (the Watcher reads svc.Spec.SessionAffinity in serviceToVIP and
// threads it to the routing table), so it is deliberately NOT a field on the apis
// netv1 contract — no cross-repo type carries session affinity.
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

// PickSticky selects a backend for key honoring ClientIP session affinity. It is the
// TCP accept path's selector (proxy.handle): client is the connecting pod's IP with
// the ephemeral source port already stripped (see clientAddr) — affinity keys on the
// IP alone — and now is injected so expiry is testable without a real clock.
//
// When the port's affinity mode is not ClientIP, PickSticky is EXACTLY Pick:
// round-robin over the active pool (so handle can call it unconditionally). Under
// ClientIP it reuses a client's existing binding ONLY when that backend is still in
// the current active pool (Ready + internalTrafficPolicy:Local-filtered, via the
// shared activePool) AND the binding is within the port's idle timeout; otherwise it
// round-robins a fresh backend and (re)binds. Re-validating against the LIVE pool on
// every hit is load-bearing: a backend that went unready, or under iTP:Local left the
// node-local subset, is re-picked, never reused — so affinity never dials a dead
// backend nor spills node-local traffic across the mesh. An iTP:Local port with no
// node-local backend propagates ErrNoLocalBackends (a drop), never a stale/remote
// fallback.
//
// The round-robin cursor is advanced ONLY on a miss/expiry/invalidation, so a steady
// sticky client does not perturb the fan-out of new clients. PickSticky takes the
// table write lock (it may create or refresh a binding, and shares Pick's locking).
//
// Trust model: the binding key is the client's source IP alone, so stickiness integrity
// inherits the SAME substrate anti-spoofing the TCP splice and iTP:Local locality
// already assume — a pod that could forge another's lo0 source IP could share, or (by
// churning IPs to the cap) evict, that client's binding. This opens NO new isolation
// boundary: there is no path to OBSERVE another client's binding, and the worst realized
// effect is loss of stickiness → a fresh, still-revalidated round-robin pick, never a
// routing or security break.
func (t *RoutingTable) PickSticky(key PortKey, client netip.Addr, now time.Time) (backend, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.states[key]
	if st == nil || len(st.all) == 0 {
		return backend{}, ErrNoBackends
	}
	pool, set, err := t.activePool(key, st)
	if err != nil {
		// e.g. iTP:Local with no node-local backend: propagate the drop; never fall
		// back to a stale binding (that would spill node-local traffic to a remote).
		return backend{}, err
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
		delete(binds, client)
	}

	be := t.roundRobin(st, pool)
	if binds == nil {
		binds = make(map[netip.Addr]*affinityBinding)
		t.affinity[key] = binds
	}
	if len(binds) >= maxAffinityBindingsPerPort {
		evictOldestBinding(binds)
	}
	binds[client] = &affinityBinding{backend: be, lastSeen: now}
	return be, nil
}

// SweepExpired evicts every ClientIP affinity binding idle at least its port's
// timeout as of now. It is a PURE, clock-injected method — no time.Now, no ticker,
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
			delete(t.affinity, key)
			continue
		}
		for client, b := range binds {
			if now.Sub(b.lastSeen) >= st.affinityTimeout {
				delete(binds, client)
			}
		}
		if len(binds) == 0 {
			delete(t.affinity, key)
		}
	}
}

// evictOldestBinding removes the least-recently-seen entry from binds to make room
// under maxAffinityBindingsPerPort. It is a linear scan, but runs only when a single
// port is already at the (generous) cap — a pathological client-IP-churn case — so it
// is a defensive bound, not the hot path. The caller holds t.mu and guarantees binds
// is non-empty.
func evictOldestBinding(binds map[netip.Addr]*affinityBinding) {
	var oldest netip.Addr
	var oldestSeen time.Time
	first := true
	for client, b := range binds {
		if first || b.lastSeen.Before(oldestSeen) {
			oldest, oldestSeen, first = client, b.lastSeen, false
		}
	}
	delete(binds, oldest)
}
