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
