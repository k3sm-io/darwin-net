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
)

// normalizeSearch returns searches trimmed, with malformed domains DROPPED — any
// entry holding a byte OUTSIDE the RFC-1123 subdomain charset [a-zA-Z0-9.-] — then
// prefix-capped to MaxSearchDomains. It is the single home of the search-list
// normalization every SearchDomains consumer applies, so the emitted shim env
// (ConfigToEnv), the vm-guest resolv.conf (GuestResolvConf), and the Go reference
// resolver (candidateNames) stay in lockstep by construction — each drops the SAME
// malformed domain and truncates at the SAME cap.
//
// DROP (not strip, not split) a domain carrying an out-of-charset byte: the C shim
// splits K3SM_DNS_SEARCH on " \t" via strtok_r, so "a b" would fork into two in-pod
// search tokens; stripping ("a b" -> "ab") silently fuses two RFC-1123 labels, and
// splitting fabricates a domain admission never authorized. The allowlist is a FLAT
// per-rune charset scan, NOT a label-grammar decomposition — the '.' is in the
// charset, so a trailing-dot FQDN like "svc.cluster.local." survives (it is not
// mistaken for an empty trailing label); a trailing dot is shim-tolerated and is NOT
// malformed. The cap is a PREFIX cut (not tail) so the cluster-first survivors —
// MergeDNSConfig appends the cluster base first — are the ones kept.
//
// This is defense-in-depth: admission (k3sm's validatePodDNSConfig) already rejects
// out-of-charset and over-cap lists (its IsDNS1123Subdomain charset [a-z0-9.-] is a
// subset of this allowlist), so normalizeSearch is a no-op for every admission-valid
// config and the live cluster-DNS keystone stays byte-identical. The returned slice
// never aliases the caller's input (sanitizeSearch always allocates).
func normalizeSearch(searches []string) []string {
	return capSearch(sanitizeSearch(searches))
}

// sanitizeSearch returns a freshly-allocated copy of searches with each entry
// strings.TrimSpace'd, entries empty after the trim dropped, and any entry holding a
// byte OUTSIDE the RFC-1123 subdomain charset [a-zA-Z0-9.-] DROPPED as malformed (a
// positive-charset allowlist — see hasOnlyRFC1123Chars). It never lowercases or
// otherwise rewrites a valid domain — a trailing dot is in the allowlist and is
// preserved (the shim tolerates it). The returned slice never aliases the input, so
// callers may compact or prefix-cap it in place.
func sanitizeSearch(searches []string) []string {
	out := make([]string, 0, len(searches))
	for _, s := range searches {
		s = strings.TrimSpace(s)
		if s == "" {
			// Load-bearing: the allowlist below is a per-rune universal ("every rune in
			// set"), which is VACUOUSLY true over "" (zero runes) and would otherwise KEEP
			// an empty token. Drop it explicitly here.
			continue
		}
		if !hasOnlyRFC1123Chars(s) {
			// Any byte outside the RFC-1123 subdomain charset [a-zA-Z0-9.-] → DROP the
			// entry whole (never fuse via strip, never fabricate via split). This positive
			// allowlist is a strict SUPERSET of admission's IsDNS1123Subdomain charset
			// [a-z0-9.-], so it is a no-op for every admission-valid search domain, yet
			// strictly STRONGER than a whitespace+control blocklist: it also drops the
			// non-whitespace separators a blocklist misses (':' '/' '@' and the resolv.conf
			// comment chars ';' '#'). Both matter on the untrusted vm-guest path: the C
			// shim splits K3SM_DNS_SEARCH on " \t" via strtok_r (whitespace would fork one
			// entry into two fabricated in-pod tokens), and GuestResolvConf renders a
			// LINE-structured /etc/resolv.conf where an interior '\n' injects a directive
			// and ';'/'#' inject a directive or fabricate an unauthorized search token
			// (mid-line ';'/'#' handling is resolver-specific — glibc/musl/systemd-resolved
			// differ). Dropping every out-of-charset entry keeps the untrusted guest
			// path at least as hardened as the trusted host path.
			continue
		}
		out = append(out, s)
	}
	return out
}

// hasOnlyRFC1123Chars reports whether every rune of s lies in the RFC-1123 subdomain
// CHARSET [a-zA-Z0-9.-]. It is a flat per-rune charset scan, NOT an RFC-1123 label
// grammar check: it accepts structurally-invalid strings like "-foo",
// "a..b", a trailing-dot FQDN, or uppercase — validating label length, hyphen
// position, and non-empty labels is the apiserver's admission job (k3sm's
// validatePodDNSConfig / IsDNS1123Subdomain). sanitizeSearch uses it only to DROP a
// search entry that carries a byte outside that charset (a separator or injection
// byte), never to assert domain structure. A non-ASCII or invalid-UTF-8 rune is
// outside the charset and so causes a drop.
func hasOnlyRFC1123Chars(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
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
