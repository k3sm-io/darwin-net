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
	"slices"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// TestSearchNormalizationLockstep pins the invariant B47 is justified by: the three
// SearchDomains encoders that go through normalizeSearch — the host-process shim env
// (ConfigToEnv), the vm-guest /etc/resolv.conf (GuestResolvConf), and the Go
// reference resolver (candidateNames) — agree EXACTLY on the effective search list
// for a malformed+over-cap config. They drop the same interior-whitespace domain and
// truncate at the same MaxSearchDomains cap, so "emitted env == guest resolv.conf ==
// Go-resolver mirror" holds by construction, not by three parallel hand-rolled loops.
func TestSearchNormalizationLockstep(t *testing.T) {
	t.Parallel()

	// A config that bypassed admission: one malformed (interior-whitespace) domain
	// plus more valid domains than the cap. No trailing dots — those are handled
	// differently by the resolver (a candidate name must not carry one), so the
	// invariant under test is the shared DROP + CAP, isolated from that resolver-
	// local detail.
	cfg := netv1.DNSConfig{
		ClusterDNSIP:  "10.43.0.10",
		ClusterDomain: "cluster.local",
		SearchDomains: []string{
			"ns.svc.cluster.local", "svc.cluster.local", "cluster.local",
			"bad domain", // malformed: dropped by all three views
			"e1.internal", "e2.internal", "e3.internal", "e4.internal",
			"e5.internal", "e6.internal", "e7.internal", // e6/e7 truncated by the cap
		},
		NDots: 5,
	}

	// The one effective list every view must converge on: the malformed domain
	// removed, then the first MaxSearchDomains(8) kept (cluster-first prefix).
	want := []string{
		"ns.svc.cluster.local", "svc.cluster.local", "cluster.local",
		"e1.internal", "e2.internal", "e3.internal", "e4.internal", "e5.internal",
	}

	// View 1 — the host-process shim env (space-joined K3SM_DNS_SEARCH).
	fromEnv := strings.Split(ConfigToEnv(cfg)[EnvDNSSearch], " ")

	// View 2 — the vm-guest /etc/resolv.conf `search` line.
	guest, err := GuestResolvConf(cfg)
	if err != nil {
		t.Fatalf("GuestResolvConf: %v", err)
	}
	fromGuest := searchLine(t, guest)

	// View 3 — the Go reference resolver. A 0-dot query expands search-first, so
	// every candidate but the trailing bare name is "<query>.<domain>"; strip the
	// prefix to recover the effective domain list in order.
	const q = "q"
	var fromResolver []string
	for _, c := range candidateNames(cfg, q) {
		if c == q {
			continue
		}
		fromResolver = append(fromResolver, strings.TrimPrefix(c, q+"."))
	}

	for _, v := range []struct {
		name string
		got  []string
	}{
		{"shim env", fromEnv},
		{"guest resolv.conf", fromGuest},
		{"Go resolver", fromResolver},
	} {
		if !slices.Equal(v.got, want) {
			t.Errorf("%s view = %v, want %v (same drop + same cap as the others)", v.name, v.got, want)
		}
		// Make the DROP explicit: no fragment of the malformed domain may survive in
		// any view (split into "bad"/"domain" or fused into "baddomain").
		for _, d := range v.got {
			if strings.Contains(d, "bad") || strings.Contains(d, "domain") {
				t.Errorf("%s view leaked malformed-domain fragment %q", v.name, d)
			}
		}
	}
}

// TestSanitizeSearchRFC1123Allowlist is the B50 gate: sanitizeSearch drops any entry
// holding a byte outside the RFC-1123 subdomain charset [a-zA-Z0-9.-] (a positive
// allowlist), which is strictly STRONGER than B47's whitespace+control blocklist. The
// separator cases below (';' '#' ':' '/' '@') are the proof of "stronger, not just
// equal": B47's blocklist ADMITS them (none is whitespace or control), so on main
// those assertions fail — this gate is non-vacuous. The trailing-dot case proves the
// scan is a FLAT charset scan, not a label decomposition (the '.' is in the charset,
// so an FQDN's trailing dot is kept, not treated as an empty trailing label).
func TestSanitizeSearchRFC1123Allowlist(t *testing.T) {
	t.Parallel()

	// Each case passes ONE domain through sanitizeSearch; want is nil when the entry
	// is dropped, else the single surviving (possibly trimmed) token.
	tests := []struct {
		name string
		in   string
		want []string
	}{
		// Non-whitespace separators the B47 blocklist ADMITTED are now DROPPED. On main
		// (whitespace+control blocklist) each of these is KEPT, so the assertion FAILS
		// there — this is what makes the gate non-vacuous and proves subsume-and-exceed.
		{"semicolon (resolv.conf comment) dropped", "evil;comment", nil},
		{"hash (resolv.conf comment) dropped", "a#b", nil},
		{"colon dropped", "x:1", nil},
		{"slash dropped", "a/b", nil},
		{"at-sign dropped", "u@h", nil},

		// Whitespace / control still dropped — regression parity with B47's blocklist.
		{"interior space dropped", "foo bar", nil},
		{"interior tab dropped", "a\tb", nil},
		{"interior newline dropped", "x\ny", nil},
		{"interior NUL dropped", "n\x00", nil},

		// Trailing-dot FQDN SURVIVES: the '.' is in the charset and the scan is flat
		// (not a label decomposition), so the trailing dot is not an empty trailing label.
		{"trailing-dot FQDN kept", "svc.cluster.local.", []string{"svc.cluster.local."}},

		// Valid domains kept — the allowlist is a superset of admission's [a-z0-9.-].
		{"cluster service kept", "svc.cluster.local", []string{"svc.cluster.local"}},
		{"namespaced service kept", "default.svc.cluster.local", []string{"default.svc.cluster.local"}},
		{"uppercase kept (charset superset of [a-z0-9.-])", "Foo.Example", []string{"Foo.Example"}},

		// Empty / padded — the load-bearing empty-guard survives the predicate swap.
		{"empty dropped", "", nil},
		{"padded-but-valid trimmed and kept", " cluster.local ", []string{"cluster.local"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// slices.Equal treats a fresh len-0 slice and nil as equal, so a dropped
			// entry (sanitizeSearch returns an empty slice) matches want == nil.
			if got := sanitizeSearch([]string{tt.in}); !slices.Equal(got, tt.want) {
				t.Errorf("sanitizeSearch([%q]) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// searchLine returns the tokens of the single `search` line in resolv.conf content,
// or fails the test if there is not exactly one.
func searchLine(t *testing.T, resolvConf string) []string {
	t.Helper()
	var found []string
	seen := 0
	for _, line := range strings.Split(resolvConf, "\n") {
		if rest, ok := strings.CutPrefix(line, "search "); ok {
			found = strings.Fields(rest)
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("want exactly one `search` line in resolv.conf, found %d:\n%s", seen, resolvConf)
	}
	return found
}
