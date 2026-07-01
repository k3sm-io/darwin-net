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
	"strings"
	"unicode"
)

// normalizeSearch returns searches trimmed, with malformed (interior whitespace/control)
// domains DROPPED, then prefix-capped to MaxSearchDomains. It is the single home of
// the search-list normalization every SearchDomains consumer applies, so the
// emitted shim env (ConfigToEnv), the vm-guest resolv.conf (GuestResolvConf), and
// the Go reference resolver (candidateNames) stay in lockstep by construction —
// each drops the SAME malformed domain and truncates at the SAME cap.
//
// DROP (not strip, not split) a domain with interior whitespace: the C shim splits
// K3SM_DNS_SEARCH on " \t" via strtok_r, so "a b" would fork into two in-pod search
// tokens; stripping ("a b" -> "ab") silently fuses two RFC-1123 labels, and
// splitting fabricates a domain admission never authorized. A trailing dot is
// shim-tolerated and is NOT malformed. The cap is a PREFIX cut (not tail) so the
// cluster-first survivors — MergeDNSConfig appends the cluster base first — are the
// ones kept.
//
// This is defense-in-depth: admission (k3sm's validatePodDNSConfig) already rejects
// interior whitespace and over-cap lists, so normalizeSearch is a no-op for every
// admission-valid config and the live cluster-DNS keystone stays byte-identical. The
// returned slice never aliases the caller's input (sanitizeSearch always allocates).
func normalizeSearch(searches []string) []string {
	return capSearch(sanitizeSearch(searches))
}

// sanitizeSearch returns a freshly-allocated copy of searches with each entry
// strings.TrimSpace'd, entries empty after the trim dropped, and any entry that
// still holds an interior whitespace or control byte (which TrimSpace leaves) DROPPED
// as malformed. It never lowercases or otherwise rewrites a valid domain — a trailing
// dot is preserved (the shim tolerates it). The returned slice never aliases the
// input, so callers may compact or prefix-cap it in place.
func sanitizeSearch(searches []string) []string {
	out := make([]string, 0, len(searches))
	for _, s := range searches {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			// Any interior whitespace or control byte that survived the trim → DROP the
			// entry whole (never fuse via strip, never fabricate via split). The predicate
			// is deliberately WIDER than the host shim's strtok_r " \t": GuestResolvConf
			// renders a LINE-structured /etc/resolv.conf, where an interior '\n' is a
			// directive-injection primitive — a crafted "\nnameserver 6.6.6.6" split across
			// two entries (neither holding a literal space) would, once the entries are
			// space-joined, MITM the untrusted vm-guest's DNS. Dropping on all whitespace +
			// control (incl '\n' and NUL) keeps the untrusted guest path at least as
			// hardened as the trusted host path, and is still a no-op for every
			// admission-valid RFC-1123 domain (whose charset is [a-z0-9.-] only).
			continue
		}
		out = append(out, s)
	}
	return out
}

// capSearch prefix-caps searches to MaxSearchDomains, returning searches unchanged
// when it is already within the cap. It cuts the tail (keeps the PREFIX) so a
// cluster-first list retains the cluster searches MergeDNSConfig placed first.
func capSearch(searches []string) []string {
	if len(searches) > MaxSearchDomains {
		return searches[:MaxSearchDomains]
	}
	return searches
}
