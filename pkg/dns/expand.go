package dns

import (
	"strings"

	netv1 "k3sm.io/apis/net/v1"
)

// candidateNames returns the ordered list of fully-qualified names a resolver
// should try for the query name under cfg, implementing resolv.conf ndots/search
// semantics — the exact logic the getaddrinfo shim runs before querying CoreDNS.
//
// Rules (matching glibc/musl and Kubernetes pod resolv.conf behavior):
//   - An already-absolute name (a trailing dot) is tried as-is only, with the dot
//     stripped; the search list is skipped.
//   - A name with at least cfg.NDots dots (counting interior dots, not a trailing
//     one) is tried as absolute FIRST, then against the search domains.
//   - A name with fewer than NDots dots is tried against the search domains
//     FIRST, then as absolute. This is why a SHORT name like "web" (0 dots)
//     resolves via search expansion (web.<ns>.svc.cluster.local …) before being
//     attempted as a bare absolute name — the tell for a correct ndots loop.
//
// NDots defaults to netv1.DefaultNDots when cfg.NDots is zero (via WithDefaults).
// Duplicate candidates are removed while preserving order.
func candidateNames(cfg netv1.DNSConfig, name string) []string {
	cfg = cfg.WithDefaults()
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	// Absolute name (FQDN with trailing dot): try exactly once, no search.
	if strings.HasSuffix(name, ".") {
		return []string{strings.TrimSuffix(name, ".")}
	}

	dots := strings.Count(name, ".")
	searched := make([]string, 0, len(cfg.SearchDomains))
	for _, d := range cfg.SearchDomains {
		d = strings.TrimSuffix(strings.TrimSpace(d), ".")
		if d == "" {
			continue
		}
		searched = append(searched, name+"."+d)
	}

	var ordered []string
	if int32(dots) >= cfg.NDots {
		// Enough dots: absolute first, then search.
		ordered = append(ordered, name)
		ordered = append(ordered, searched...)
	} else {
		// Too few dots: search first, then absolute.
		ordered = append(ordered, searched...)
		ordered = append(ordered, name)
	}
	return dedupe(ordered)
}

// dedupe removes duplicate strings while preserving first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
