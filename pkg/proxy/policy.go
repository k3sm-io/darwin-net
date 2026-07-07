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
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// policyLogThrottle bounds how often the PolicyTable emits its two data-path log
// signals — the unknown-source fail-open Warn and the connection-denied Info — so
// a steady stream of denied or unattributable traffic logs once per interval, not
// once per connection/datagram.
const policyLogThrottle = 10 * time.Second

// PolicyRule is ONE fully resolved NetworkPolicy ingress allow clause for a
// selected backend pod: the concrete source /32 set its `from` peers resolved to,
// plus the concrete backend (container) port set. The PolicyTable never sees a
// selector — resolution (label matching, namespace lookup) happens upstream in the
// PolicyWatcher, so the table stays a pure O(1)-lookup verdict core.
//
// Upstream-faithful widening: a nil Sources allows ANY source (an empty `from`
// list), and a nil Ports allows ANY backend port (an empty `ports` list). The
// resolver also uses nil for any clause the v0.2 subset cannot express (ipBlock
// peers, named/ranged ports, a selector that fails to parse) — an inexpressible
// clause may only WIDEN allows, never manufacture a deny.
type PolicyRule struct {
	// Sources is the resolved set of allowed source pod IPs; nil allows any source.
	Sources map[netip.Addr]struct{}
	// Ports is the set of allowed backend (target/container) ports; nil allows any
	// port. Matching is against the PICKED backend's dial port, which for k3sm's
	// pod-backed Services is the pod's container port.
	Ports map[uint16]struct{}
}

// PolicyTable is the pure-logic core of the M10.4 NetworkPolicy L4 subset: it maps
// a POLICY-SELECTED backend pod IP to its resolved union-of-allows ingress rules
// and answers one question — Allow(src, backend, port) — per accepted connection
// (TCP) or admitted flow (UDP), AFTER the routing table has picked the backend.
// The verdict is per (source, picked-backend pod IP, backend port), never per
// VIP/Service: one Service can front policy-heterogeneous pods, so the verdict
// must follow the pick.
//
// Semantics (upstream-faithful RESTRICTION, documented in doc.go):
//
//   - Default-allow-unless-selected: a backend no policy selects is allowed.
//   - A selected backend admits a source iff ANY resolved rule matches both the
//     source and the port (union of allows); zero matching rules → deny.
//   - Always-allow (fail-open, availability-critical): loopback sources
//     (127.0.0.0/8, ::1) and the constructor-seeded /32s (the node's InternalIP,
//     this node's and every peer's mesh-egress /32) always pass — node-origin
//     dialers (the in-process Ingress, apiserver webhooks, hostNetwork clients)
//     must never be locked out by a pod policy.
//   - UNKNOWN source (not in the resolved known-pod-IP set and not always-allowed)
//     → ALLOW with a throttled Warn naming the unattributable source. This is the
//     hint contract: the subset restricts attributable pod traffic and fails open
//     on anything it cannot attribute.
//   - An empty table (pre-informer-sync, or no policies) allows everything, and a
//     nil *PolicyTable allows everything — the feature is strictly additive.
//
// Locking discipline: selected and known are replaced wholesale under mu by
// Update (the watcher's debounced recompute) and read under RLock by Allow (the
// accept paths). alwaysAllow is set once at construction and read lock-free.
// The log-throttle state has its own leaf mutex (warnMu) so the hot-path RLock is
// never upgraded; evalCount is an atomic counter of Allow evaluations that backs
// the gate's asserted-bypass subtest (a non-VIP path never consults the table)
// and is otherwise unobserved.
type PolicyTable struct {
	// alwaysAllow is the constructor-seeded never-deny source set (node InternalIP,
	// mesh-egress /32s). Read-only after construction, so no lock.
	alwaysAllow map[netip.Addr]struct{}

	mu sync.RWMutex
	// selected maps a policy-selected backend pod IP to its resolved ingress rules.
	// A present key with ZERO rules is a selected-but-nothing-allowed backend
	// (deny-all); an absent key is an unselected backend (default-allow).
	selected map[netip.Addr][]PolicyRule
	// known is the set of all resolved pod IPs in the cluster. A source in it is
	// attributable (a deny verdict is trustworthy); a source outside it is unknown
	// and fails open.
	known map[netip.Addr]struct{}

	// log records the fail-open Warn and the throttled deny Info. Defaulted in
	// NewPolicyTable and overwritten by the owning Proxy's logger in proxy.New
	// (before any worker starts, so the goroutine-start happens-before covers it).
	log *slog.Logger

	// warnMu guards the two throttle timestamps below (a leaf: taken with no other
	// lock held, never inverted with mu — Allow releases mu before warning).
	warnMu          sync.Mutex
	lastUnknownWarn time.Time
	lastDenyLog     time.Time

	// evalCount counts Allow evaluations (atomically). It exists for the M10.4
	// gate's asserted-bypass subtest: a direct pod-IP→pod-IP connection never
	// transits a VIP accept path, so it must never bump this counter.
	evalCount atomic.Uint64
}

// NewPolicyTable returns an empty (allow-everything) table seeded with the
// always-allow source /32s: the node's own InternalIP, this node's mesh-egress
// /32, and every peer's mesh-egress /32. Loopback (127.0.0.0/8, ::1) is always
// allowed implicitly and needs no seed. Invalid (zero) addresses are skipped so a
// single-node caller can pass its unset mesh-egress Addr unconditionally.
func NewPolicyTable(alwaysAllow ...netip.Addr) *PolicyTable {
	aa := make(map[netip.Addr]struct{}, len(alwaysAllow))
	for _, a := range alwaysAllow {
		if a.IsValid() {
			aa[a.Unmap()] = struct{}{}
		}
	}
	return &PolicyTable{
		alwaysAllow: aa,
		selected:    make(map[netip.Addr][]PolicyRule),
		known:       make(map[netip.Addr]struct{}),
		log:         slog.Default(),
	}
}

// Update atomically replaces the table's resolved state: selected maps each
// policy-selected backend pod IP to its union-of-allows ingress rules (a present
// key with zero rules is deny-all for that backend), and knownPodIPs is the set of
// every resolved pod IP (the source-attribution set — a source outside it fails
// open). Both maps are FULLY RESOLVED by the caller (the PolicyWatcher's debounced
// recompute); the table never sees a selector. Ownership of both maps transfers to
// the table — the caller must not mutate them after the call. Nil maps install the
// empty (allow-everything) state.
func (t *PolicyTable) Update(selected map[netip.Addr][]PolicyRule, knownPodIPs map[netip.Addr]struct{}) {
	if selected == nil {
		selected = make(map[netip.Addr][]PolicyRule)
	}
	if knownPodIPs == nil {
		knownPodIPs = make(map[netip.Addr]struct{})
	}
	t.mu.Lock()
	t.selected = selected
	t.known = knownPodIPs
	t.mu.Unlock()
}

// Allow reports whether a connection/flow from src to the PICKED backend pod IP on
// backend port port passes the NetworkPolicy L4 subset. It is called on the accept
// paths AFTER the routing table picked the backend (proxy.handle for TCP,
// udpRelay.upstreamFor at UDP flow admission) — never per VIP, because one Service
// can front policy-heterogeneous pods. It is O(1) map lookups plus a scan of the
// picked backend's resolved rules.
//
// A nil receiver allows everything (the proxy runs policy-free unless the
// assembler wires a table via WithPolicyTable), as does an empty table
// (pre-informer-sync fail-open). See the type comment for the full verdict order:
// loopback/always-allow → unselected-backend allow → rule match → unknown-source
// fail-open (throttled Warn) → deny.
func (t *PolicyTable) Allow(src, backend netip.Addr, port uint16) bool {
	if t == nil {
		return true
	}
	t.evalCount.Add(1)
	src = src.Unmap()
	if src.IsLoopback() {
		return true
	}
	if _, ok := t.alwaysAllow[src]; ok {
		return true
	}

	t.mu.RLock()
	rules, isSelected := t.selected[backend.Unmap()]
	_, srcKnown := t.known[src]
	t.mu.RUnlock()

	if !isSelected {
		return true // default-allow-unless-selected
	}
	for _, r := range rules {
		if r.Sources != nil {
			if _, ok := r.Sources[src]; !ok {
				continue
			}
		}
		if r.Ports != nil {
			if _, ok := r.Ports[port]; !ok {
				continue
			}
		}
		return true // union of allows: any matching rule admits
	}
	if !srcKnown {
		// The source is unattributable (not a resolved pod IP, not always-allowed):
		// fail open per the hint contract, but say so loudly (throttled) — a silent
		// allow here would masquerade as enforcement.
		t.warnUnknownSource(src, backend, port)
		return true
	}
	return false
}

// warnUnknownSource emits the throttled unknown-source fail-open Warn, naming the
// unattributable source so an operator can seed it (node/mesh /32s) or trace it.
func (t *PolicyTable) warnUnknownSource(src, backend netip.Addr, port uint16) {
	t.warnMu.Lock()
	throttled := time.Since(t.lastUnknownWarn) < policyLogThrottle
	if !throttled {
		t.lastUnknownWarn = time.Now()
	}
	t.warnMu.Unlock()
	if throttled {
		return
	}
	t.logger().Warn("networkpolicy: allowing connection from UNKNOWN source (not a resolved pod IP, not always-allowed) — fail-open per the VIP-mediated hint contract",
		"src", src.String(), "backend", backend.String(), "port", port)
}

// logDenied emits the throttled connection-denied Info shared by both accept
// paths (proto is "tcp" or "udp"). Info, not Warn: a deny is the policy WORKING
// as configured; and throttled, because handle/upstreamFor run per connection/
// datagram and a scanner must not flood the log. A nil receiver is a no-op (only
// reachable defensively — a nil table never returns a deny verdict).
func (t *PolicyTable) logDenied(proto string, key PortKey, src netip.Addr, backend netip.AddrPort) {
	if t == nil {
		return
	}
	t.warnMu.Lock()
	throttled := time.Since(t.lastDenyLog) < policyLogThrottle
	if !throttled {
		t.lastDenyLog = time.Now()
	}
	t.warnMu.Unlock()
	if throttled {
		return
	}
	t.logger().Info("networkpolicy: denied by ingress policy (VIP-mediated L4 subset)",
		"proto", proto, "vip", key.String(), "src", src.String(), "backend", backend.String())
}

// logger returns the table's structured logger, defaulting to slog.Default() when
// unset — never a nil pointer (proxy.New copies a possibly-nil WithLogger(nil)
// logger in; mirrors RoutingTable.logger and Proxy.logger, the sibling nil-log
// guards on the data path).
func (t *PolicyTable) logger() *slog.Logger {
	if t.log == nil {
		return slog.Default()
	}
	return t.log
}
