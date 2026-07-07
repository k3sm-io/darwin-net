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

package ingress

import (
	"net/netip"
	"strings"
	"sync/atomic"
)

// PathType is how a Rule's Path matches a request path. It mirrors the
// networking/v1 pathType semantics k3sm implements: Exact and Prefix.
// ImplementationSpecific is normalized to Prefix by the Watcher (documented
// there) and never appears in a Rule.
type PathType string

const (
	// PathTypeExact matches the request path literally (case-sensitive, no
	// trailing-slash forgiveness).
	PathTypeExact PathType = "Exact"
	// PathTypePrefix matches element-wise on /-separated path segments: /foo
	// matches /foo, /foo/, and /foo/bar, but never /foobar.
	PathTypePrefix PathType = "Prefix"
)

// Backend is the L7 routing target: a Service ClusterIP VIP and Service port.
// The ingress dials the VIP (the L4 proxy owns EndpointSlices, affinity, and
// mesh egress behind it), never a pod IP.
type Backend struct {
	// VIP is the Service ClusterIP.
	VIP netip.Addr
	// Port is the Service port on the VIP.
	Port uint16
}

// AddrPort returns the dialable VIP:port.
func (b Backend) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(b.VIP, b.Port)
}

// Rule routes one host+path to a Backend.
//
// Host is an EXACT lowercase host (no port). Wildcard hosts (*.example.com)
// are DEFERRED — the Watcher skips them — so a Rule never carries one. An empty
// Host matches any host, but only after every host-specific rule has been
// tried (the hostless tier).
type Rule struct {
	Host     string
	Path     string
	PathType PathType
	Backend  Backend
}

// routeState is one immutable rule snapshot; RouteTable swaps it atomically so
// the per-request Match path never takes a lock.
type routeState struct {
	rules          []Rule
	defaultBackend *Backend
}

// RouteTable is the pure L7 routing core: an atomically-swapped snapshot of
// Rules plus an optional default backend. It holds no HTTP server types — rules
// in, Backend out — so the precedence matrix is fully table-testable.
//
// Concurrency: Update replaces the whole snapshot via atomic pointer swap;
// Match loads it lock-free. Callers therefore always observe a consistent
// (rules, defaultBackend) pair, never a torn mix.
type RouteTable struct {
	state atomic.Pointer[routeState]
}

// NewRouteTable returns an empty table (no rules, no default backend).
func NewRouteTable() *RouteTable {
	t := &RouteTable{}
	t.state.Store(&routeState{})
	return t
}

// Update atomically replaces the table's rules and default backend. Rule hosts
// are normalized to lowercase; the slice and backend are copied so the caller
// cannot mutate the live snapshot.
func (t *RouteTable) Update(rules []Rule, defaultBackend *Backend) {
	st := &routeState{rules: make([]Rule, len(rules))}
	copy(st.rules, rules)
	for i := range st.rules {
		st.rules[i].Host = strings.ToLower(st.rules[i].Host)
	}
	if defaultBackend != nil {
		db := *defaultBackend
		st.defaultBackend = &db
	}
	t.state.Store(st)
}

// Match resolves the Backend for a request host+path. host must be the bare
// lowercase host (no port). Precedence:
//
//  1. Rules whose Host equals host (the host-specific tier).
//  2. Rules with an empty Host (the hostless any-host tier).
//  3. The table's default backend, if set.
//
// Within a tier the best match is the rule with the LONGEST matching Path;
// at equal path length Exact beats Prefix. No match at all returns ok=false —
// the router-level 404.
func (t *RouteTable) Match(host, path string) (Backend, bool) {
	st := t.state.Load()
	if be, ok := bestMatch(st.rules, host, path); ok {
		return be, true
	}
	if be, ok := bestMatch(st.rules, "", path); ok {
		return be, true
	}
	if st.defaultBackend != nil {
		return *st.defaultBackend, true
	}
	return Backend{}, false
}

// bestMatch picks the winning rule for path among the rules whose Host equals
// host: longest matching Path wins; Exact beats Prefix at equal length.
func bestMatch(rules []Rule, host, path string) (Backend, bool) {
	var (
		found    bool
		best     Backend
		bestLen  = -1
		bestType PathType
	)
	for _, r := range rules {
		if r.Host != host || !ruleMatches(r, path) {
			continue
		}
		l := len(r.Path)
		if l > bestLen || (l == bestLen && r.PathType == PathTypeExact && bestType != PathTypeExact) {
			found, best, bestLen, bestType = true, r.Backend, l, r.PathType
		}
	}
	return best, found
}

// ruleMatches reports whether path satisfies r's Path under r's PathType.
func ruleMatches(r Rule, path string) bool {
	switch r.PathType {
	case PathTypeExact:
		return path == r.Path
	case PathTypePrefix:
		return segmentPrefixMatch(r.Path, path)
	default:
		return false
	}
}

// segmentPrefixMatch implements the networking/v1 Prefix semantics: the rule
// path's /-separated segments must equal the leading segments of the request
// path, element-wise. "/" (zero segments) matches everything; "/foo" matches
// "/foo", "/foo/", and "/foo/bar" but NOT "/foobar".
func segmentPrefixMatch(rulePath, reqPath string) bool {
	rs := pathSegments(rulePath)
	ps := pathSegments(reqPath)
	if len(rs) > len(ps) {
		return false
	}
	for i := range rs {
		if rs[i] != ps[i] {
			return false
		}
	}
	return true
}

// pathSegments splits a path into its non-empty /-separated segments, so a
// trailing slash does not manufacture a phantom segment ("/foo/" -> ["foo"]).
func pathSegments(p string) []string {
	var segs []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}
