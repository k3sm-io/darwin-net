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
// Go side (via the shared capSearch, applied by normalizeSearch) keeps four views
// in lockstep: the K3SM_DNS_SEARCH env ConfigToEnv emits, the shim's effective
// in-pod search list, the vm-guest /etc/resolv.conf GuestResolvConf renders, and
// the Go reference resolver's expansion (expand.go) — emitted env == shim-effective
// == guest resolv.conf == Go-resolver mirror.
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
// It returns the merged config plus the number of valid search domains DROPPED BY
// THE CAP (0 when nothing was truncated) — i.e. max(0, len(sanitized-deduped) -
// MaxSearchDomains). The count is the cap's doing ONLY, not the sanitize step's; the
// k3sm caller (wave 2) logs a Warn with pod identity when it is non-zero.
// MergeDNSConfig itself stays a PURE primitive with no logging side effect (see
// TestMergeDNSConfigDoesNotMutateBase).
//
// Merge rules:
//   - SearchDomains: the cluster searches (base.SearchDomains) FIRST, then the pod
//     searches, then deduped first-seen (so the cluster WINS a collision — a pod
//     search equal to a cluster one is dropped), then SANITIZED (interior-whitespace
//     domains dropped, empties dropped) via the shared normalization helper, then
//     capped at MaxSearchDomains. A pod can ADD search domains but never PREEMPT a
//     cluster one; a malformed pod search is dropped BEFORE the cap (matching the
//     shim's skip-empty behavior), and the tail beyond MaxSearchDomains is truncated.
//   - NDots: ndots > 0 overrides base.NDots (the pod's ndots wins); ndots <= 0
//     keeps base.NDots. An explicit `ndots: 0` is INDISTINGUISHABLE from unset in
//     the int32 field, so it is treated as unset (→ cluster default); honoring an
//     explicit 0 is deferred to B20b.
//   - ClusterDNSIP and ClusterDomain are carried from base UNCHANGED.
//
// Sanitize+cap go through the same sanitizeSearch/capSearch helpers ConfigToEnv,
// GuestResolvConf, and candidateNames use (via normalizeSearch), so all four
// SearchDomains views drop the same malformed domain and truncate at the same cap.
//
// base is not mutated: out starts as a copy of base and is given a FRESH
// SearchDomains slice that never aliases the caller's. dnsConfig.nameservers and
// non-ndots dnsConfig.options are NOT honored here (the single-server shim ABI;
// deferred to B20b).
func MergeDNSConfig(base netv1.DNSConfig, searches []string, ndots int32) (netv1.DNSConfig, int) {
	out := base

	// Cluster searches first, then the pod's; dedupe first-seen so the cluster wins
	// a collision. The slice is freshly allocated, so dedupe's in-place compaction
	// never touches base's backing array.
	merged := make([]string, 0, len(base.SearchDomains)+len(searches))
	merged = append(merged, base.SearchDomains...)
	merged = append(merged, searches...)

	// Sanitize BEFORE the cap so a malformed pod search is dropped rather than
	// counted against (and truncating) a valid one; then the cap-drop count is the
	// number of valid searches the MaxSearchDomains prefix-cut removed.
	sanitized := sanitizeSearch(dedupe(merged))
	dropped := max(0, len(sanitized)-MaxSearchDomains)
	out.SearchDomains = capSearch(sanitized)

	// A positive pod ndots overrides the cluster default. ndots <= 0 — which an
	// explicit `ndots: 0` is indistinguishable from in the int32 field — keeps
	// base.NDots; honoring an explicit 0 is deferred to B20b.
	if ndots > 0 {
		out.NDots = ndots
	}
	return out, dropped
}
