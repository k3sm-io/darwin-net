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

package dns

import (
	netv1 "k3sm.io/apis/net/v1"
)

// MaxSearchDomains is the effective in-pod DNS search-list cap MergeDNSConfig
// enforces. It mirrors the C shim's K3SM_MAX_SEARCH (shim/getaddrinfo_shim.c),
// which stores at most that many search entries (char
// search[K3SM_MAX_SEARCH][...]) and silently drops any beyond it. Capping on the
// Go side keeps three views in lockstep: the K3SM_DNS_SEARCH env ConfigToEnv
// emits, the shim's effective in-pod search list, and the Go reference resolver's
// expansion (expand.go) — emitted env == shim-effective == Go-resolver mirror.
// This is a DELIBERATE divergence from upstream Kubernetes' cap of 32: a
// ClusterFirst pod's 6th-and-later added search beyond the three cluster defaults
// is silently dropped. TestShimMaxSearchMatchesC binds this const to the .c so a
// future edit to either side fails the build.
const MaxSearchDomains = 8

// MergeDNSConfig returns base augmented with a ClusterFirst pod's additive
// dnsConfig. It is the pure darwin-net merge primitive (k3sm wave 2 extracts the
// pod-spec fields and calls it); it takes DISCRETE searches/ndots rather than a
// full netv1.DNSConfig "extra" so it can only ever augment the search list and
// ndots and can NEVER override the cluster server VIP (ClusterDNSIP) or domain.
// That type-enforces B18's infra-wins invariant — a ClusterFirst pod always
// points at the cluster resolver; dnsConfig may add to its search/ndots, never
// preempt the cluster server.
//
// Merge rules:
//   - SearchDomains: the cluster searches (base.SearchDomains) FIRST, then the pod
//     searches, then deduped first-seen (so the cluster WINS a collision — a pod
//     search equal to a cluster one is dropped), then capped at MaxSearchDomains.
//     A pod can ADD search domains but never PREEMPT a cluster one, and the tail
//     beyond MaxSearchDomains is truncated (cluster 3 + at most 5 pod survive).
//   - NDots: ndots > 0 overrides base.NDots (the pod's ndots wins); ndots <= 0
//     keeps base.NDots. An explicit `ndots: 0` is INDISTINGUISHABLE from unset in
//     the int32 field, so it is treated as unset (→ cluster default); honoring an
//     explicit 0 is deferred to B20b.
//   - ClusterDNSIP and ClusterDomain are carried from base UNCHANGED.
//
// base is not mutated: out starts as a copy of base and is given a FRESH
// SearchDomains slice that never aliases the caller's. dnsConfig.nameservers and
// non-ndots dnsConfig.options are NOT honored here (the single-server shim ABI;
// deferred to B20b).
func MergeDNSConfig(base netv1.DNSConfig, searches []string, ndots int32) netv1.DNSConfig {
	out := base

	// Cluster searches first, then the pod's; dedupe first-seen so the cluster
	// wins a collision; cap at MaxSearchDomains. The slice is freshly allocated, so
	// dedupe's in-place compaction never touches base's backing array.
	merged := make([]string, 0, len(base.SearchDomains)+len(searches))
	merged = append(merged, base.SearchDomains...)
	merged = append(merged, searches...)
	merged = dedupe(merged)
	if len(merged) > MaxSearchDomains {
		merged = merged[:MaxSearchDomains]
	}
	out.SearchDomains = merged

	// A positive pod ndots overrides the cluster default. ndots <= 0 — which an
	// explicit `ndots: 0` is indistinguishable from in the int32 field — keeps
	// base.NDots; honoring an explicit 0 is deferred to B20b.
	if ndots > 0 {
		out.NDots = ndots
	}
	return out
}
