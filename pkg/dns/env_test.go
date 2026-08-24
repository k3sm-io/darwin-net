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
	"context"
	"maps"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

func TestConfigToEnv(t *testing.T) {
	tests := []struct {
		name string
		cfg  netv1.DNSConfig
		want map[string]string
	}{
		{
			name: "valid config serializes server, domain, space-joined search, ndots",
			cfg: netv1.DNSConfig{
				ClusterDNSIP:  "10.43.0.10",
				ClusterDomain: "cluster.local",
				SearchDomains: []string{"team.svc.cluster.local", "svc.cluster.local", "cluster.local"},
				NDots:         5,
			},
			want: map[string]string{
				EnvDNSServer: "10.43.0.10",
				EnvDNSDomain: "cluster.local",
				// Space-separated — the C shim splits on " \t" via strtok_r.
				EnvDNSSearch: "team.svc.cluster.local svc.cluster.local cluster.local",
				EnvDNSNdots:  "5",
			},
		},
		{
			name: "zero ndots defaults to 5 (never serializes \"0\")",
			cfg: netv1.DNSConfig{
				ClusterDNSIP:  "10.43.0.10",
				ClusterDomain: "cluster.local",
				SearchDomains: []string{"svc.cluster.local"},
				NDots:         0,
			},
			want: map[string]string{
				EnvDNSServer: "10.43.0.10",
				EnvDNSDomain: "cluster.local",
				EnvDNSSearch: "svc.cluster.local",
				EnvDNSNdots:  "5",
			},
		},
		{
			name: "invalid config (no cluster DNS VIP) omits all env so the shim falls back to the host resolver",
			cfg: netv1.DNSConfig{
				ClusterDNSIP:  "",
				ClusterDomain: "cluster.local",
				SearchDomains: []string{"svc.cluster.local"},
				NDots:         5,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConfigToEnv(tt.cfg)
			if !maps.Equal(got, tt.want) {
				t.Errorf("ConfigToEnv() = %v, want %v", got, tt.want)
			}
			// EnvDNSPort must never be emitted: the shim defaults the port to 53 and
			// netv1.DNSConfig carries no port field.
			if v, ok := got[EnvDNSPort]; ok {
				t.Errorf("ConfigToEnv() emitted %s=%q; the port must be omitted", EnvDNSPort, v)
			}
		})
	}
}

// TestConfigToEnvCapsAndSanitizes is the B47 gate: it proves ConfigToEnv defends the
// K3SM_DNS_SEARCH / K3SM_DNS_NDOTS wire values against a config that bypassed
// admission (k3sm's validatePodDNSConfig). Every assertion here is a no-op for an
// admission-valid config, so the live cluster-DNS keystone stays byte-identical; the
// cases below use only INVALID inputs that admission would have rejected. On main
// (no normalizeSearch, no ndots high-clamp) the interior-whitespace, over-cap, and
// ndots cases all fail.
func TestConfigToEnvCapsAndSanitizes(t *testing.T) {
	cfg := func(search []string, ndots int32) netv1.DNSConfig {
		return netv1.DNSConfig{
			ClusterDNSIP:  "10.43.0.10",
			ClusterDomain: "cluster.local",
			SearchDomains: search,
			NDots:         ndots,
		}
	}

	t.Run("interior-whitespace domain is dropped whole, not split or stripped", func(t *testing.T) {
		got := ConfigToEnv(cfg([]string{"svc.cluster.local", "foo bar", "cluster.local"}, 5))[EnvDNSSearch]
		// The C shim splits K3SM_DNS_SEARCH on " \t" via strtok_r: a leaked "foo bar"
		// would fork into two in-pod search tokens. It must be dropped whole — never
		// split into "foo"/"bar" nor fused into "foobar".
		for _, tok := range strings.Fields(got) {
			if tok == "foo" || tok == "bar" || tok == "foobar" {
				t.Fatalf("malformed domain leaked as %q into K3SM_DNS_SEARCH=%q", tok, got)
			}
		}
		if want := "svc.cluster.local cluster.local"; got != want {
			t.Fatalf("K3SM_DNS_SEARCH = %q, want %q (malformed domain dropped whole)", got, want)
		}
	})

	t.Run("over-cap list is prefix-capped to the first MaxSearchDomains, cluster-first", func(t *testing.T) {
		// 3 cluster + 7 extra = 10 valid domains; only the first MaxSearchDomains(8)
		// survive (the cluster-first prefix), the tail is truncated.
		search := []string{
			"ns.svc.cluster.local", "svc.cluster.local", "cluster.local",
			"e1.internal", "e2.internal", "e3.internal", "e4.internal",
			"e5.internal", "e6.internal", "e7.internal",
		}
		got := ConfigToEnv(cfg(search, 5))[EnvDNSSearch]
		toks := strings.Split(got, " ")
		if len(toks) != MaxSearchDomains {
			t.Fatalf("K3SM_DNS_SEARCH has %d tokens, want exactly %d", len(toks), MaxSearchDomains)
		}
		if want := search[:MaxSearchDomains]; !slices.Equal(toks, want) {
			t.Fatalf("K3SM_DNS_SEARCH = %v, want the cluster-first prefix %v", toks, want)
		}
	})

	t.Run("an out-of-range ndots is clamped high to the RES_MAXNDOTS ceiling", func(t *testing.T) {
		if got := ConfigToEnv(cfg([]string{"svc.cluster.local"}, 1000))[EnvDNSNdots]; got != "15" {
			t.Fatalf("K3SM_DNS_NDOTS = %q, want \"15\" (clamped to RES_MAXNDOTS)", got)
		}
	})

	t.Run("a trailing-dot domain is preserved, not treated as malformed", func(t *testing.T) {
		got := ConfigToEnv(cfg([]string{"svc.cluster.local.", "cluster.local."}, 5))[EnvDNSSearch]
		if want := "svc.cluster.local. cluster.local."; got != want {
			t.Fatalf("K3SM_DNS_SEARCH = %q, want %q (trailing dot is shim-tolerated, kept)", got, want)
		}
	})
}

// TestShimEnvNamesMatchC is the C<->Go drift guard. It is the one place both the
// Go env-name consts and shim/getaddrinfo_shim.c are visible, so it mechanically
// binds the unavoidable C copy of the K3SM_DNS_* names to the Go consts: it reads
// the .c as text, extracts every getenv("K3SM_DNS_…") name, and asserts that set
// exactly equals the consts ConfigToEnv and k3sm depend on. A rename on either
// side fails here instead of silently disabling cluster DNS in pods.
//
// See also: TestDNSWireClassificationDifferential
// (differential_integration_test.go) is the BEHAVIOURAL half of the same C<->Go
// contract — it runs both engines over the same wire bytes. This guard binds the
// CONSTANTS by reading the .c as text and needs no toolchain, so it is neither
// subsumed by nor redundant with the differential; keep both.
func TestShimEnvNamesMatchC(t *testing.T) {
	const shimPath = "../../shim/getaddrinfo_shim.c"
	src, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", shimPath, err)
	}
	// Match only real getenv() calls, never the K3SM_DNS_* names in the .c comments.
	re := regexp.MustCompile(`getenv\("(K3SM_DNS_[A-Z0-9_]+)"\)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatalf("no getenv(\"K3SM_DNS_*\") calls found in %s — regex or shim layout drifted", shimPath)
	}
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		seen[m[1]] = struct{}{}
	}
	got := make([]string, 0, len(seen))
	for name := range seen {
		got = append(got, name)
	}
	slices.Sort(got)

	want := []string{EnvDNSServer, EnvDNSPort, EnvDNSDomain, EnvDNSSearch, EnvDNSNdots, EnvDNSDebug}
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Errorf("getaddrinfo-shim ABI drift between %s and pkg/dns consts:\n  C shim getenv names: %v\n  Go env-name consts:  %v", shimPath, got, want)
	}
}

// TestShimMaxSearchMatchesC is the second C<->Go drift guard, a sibling of
// TestShimEnvNamesMatchC for the search-list cap. MaxSearchDomains is the Go-side
// single source of the in-pod search cap (MergeDNSConfig enforces it); the C shim
// holds the unavoidable copy as `#define K3SM_MAX_SEARCH`. This reads the .c as
// text, extracts that macro, and asserts it equals MaxSearchDomains — so the
// emitted K3SM_DNS_SEARCH list, the shim's effective in-pod list, and the Go
// resolver mirror cannot silently diverge. A future edit to either side fails the
// build here instead of truncating the search list at a different bound in pods.
//
// See also: TestDNSWireClassificationDifferential
// (differential_integration_test.go), the behavioural sibling of this whole
// family of constant-level drift guards.
func TestShimMaxSearchMatchesC(t *testing.T) {
	const shimPath = "../../shim/getaddrinfo_shim.c"
	src, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", shimPath, err)
	}
	re := regexp.MustCompile(`#define\s+K3SM_MAX_SEARCH\s+(\d+)`)
	m := re.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatalf("no `#define K3SM_MAX_SEARCH <n>` found in %s — regex or shim layout drifted", shimPath)
	}
	cMax, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse K3SM_MAX_SEARCH %q: %v", m[1], err)
	}
	if cMax != MaxSearchDomains {
		t.Errorf("getaddrinfo-shim search-cap drift: %s #define K3SM_MAX_SEARCH = %d, but pkg/dns MaxSearchDomains = %d", shimPath, cMax, MaxSearchDomains)
	}
}

// shimDefine reads the value of a `#define <name> <n>` integer macro from the C
// shim source, failing the test if it is absent — the shared machinery behind
// the numeric C<->Go drift guards below.
func shimDefine(t *testing.T, name string) int {
	t.Helper()
	const shimPath = "../../shim/getaddrinfo_shim.c"
	src, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", shimPath, err)
	}
	re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(name) + `\s+(\d+)`)
	m := re.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatalf("no `#define %s <n>` found in %s — regex or shim layout drifted", name, shimPath)
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse %s %q: %v", name, m[1], err)
	}
	return v
}

// TestShimAttemptsMatchesC binds the C shim's per-candidate transient-retry count
// to the Go resolver's queryAttempts. Both implement the resolv.conf "attempts"
// default; a drift would make a pod and the reference resolver retry a lost
// datagram a different number of times before giving up.
func TestShimAttemptsMatchesC(t *testing.T) {
	if cAttempts := shimDefine(t, "K3SM_DNS_ATTEMPTS"); cAttempts != queryAttempts {
		t.Errorf("getaddrinfo-shim attempts drift: #define K3SM_DNS_ATTEMPTS = %d, but pkg/dns queryAttempts = %d", cAttempts, queryAttempts)
	}
}

// TestShimEDNSSizeMatchesC binds the C shim's advertised EDNS0 UDP payload size
// to the Go resolver's EDNSUDPPayloadSize. Both append an OPT RR advertising this
// size; a drift would make a pod and the reference resolver ask CoreDNS to
// truncate at different thresholds, diverging their UDP-vs-TCP behavior.
func TestShimEDNSSizeMatchesC(t *testing.T) {
	if cSize := shimDefine(t, "K3SM_EDNS_UDP_SIZE"); cSize != EDNSUDPPayloadSize {
		t.Errorf("getaddrinfo-shim EDNS-size drift: #define K3SM_EDNS_UDP_SIZE = %d, but pkg/dns EDNSUDPPayloadSize = %d", cSize, EDNSUDPPayloadSize)
	}
}

// nameOfLength builds a hostname of EXACTLY total presentation bytes (no
// trailing dot) whose every label is well under the 63-byte label ceiling, so
// TOTAL length is the only property under test. It ends in ".invalid" (RFC 2606)
// so any fallthrough to a host resolver can never reach a real name. Shared with
// the wire differential's boundary cases.
func nameOfLength(t *testing.T, total int) string {
	t.Helper()
	const suffix = ".invalid"
	name := ""
	for total-len(name)-len(suffix) > 63 {
		name += strings.Repeat("a", 60) + "."
	}
	fill := total - len(name) - len(suffix)
	if fill < 1 {
		t.Fatalf("nameOfLength(%d): cannot build a name that short", total)
	}
	name += strings.Repeat("b", fill) + suffix
	if len(name) != total {
		t.Fatalf("nameOfLength(%d) produced %d bytes", total, len(name))
	}
	return name
}

// TestShimMaxNameLenMatchesGo binds the C shim's `#define K3SM_DNS_MAX_NAME_LEN`
// to the Go reference resolver's real encoding ceiling. The C side cannot import
// the Go bound, and the bound is subtle — the shim stores a candidate WITHOUT a
// trailing dot while queryA encodes ensureFQDN(candidate) WITH one, so the two
// differ by exactly the dot. Rather than restate 253 on the Go side (a second
// hand-written copy is the thing that drifts), this drives the PRODUCTION path:
// the C constant must be the largest length at which the Go resolver still puts
// bytes on the wire, and one more must produce zero exchanges.
//
// It also asserts the C buffer (K3SM_MAX_NAME) can hold a boundary-length name
// plus its NUL, so a future "bump the buffer" edit cannot quietly turn the
// boundary check into a no-op — the C side carries the same coupling as a
// _Static_assert.
//
// See also: TestDNSWireClassificationDifferential
// (differential_integration_test.go) pins the same boundary BEHAVIOURALLY
// against the real dylib, on both engines at once.
func TestShimMaxNameLenMatchesGo(t *testing.T) {
	t.Parallel()
	cMax := shimDefine(t, "K3SM_DNS_MAX_NAME_LEN")
	if buf := shimDefine(t, "K3SM_MAX_NAME"); buf < cMax+1 {
		t.Fatalf("getaddrinfo-shim buffer/boundary drift: #define K3SM_MAX_NAME = %d cannot hold a %d-byte name plus its NUL", buf, cMax)
	}

	stub := newStubDNS(t, map[string]netip.Addr{})
	defer stub.close()

	tests := []struct {
		name      string
		length    int
		wantDials int
	}{
		{
			name:      "a name at the boundary is encodable and reaches the wire",
			length:    cMax,
			wantDials: 1,
		},
		{
			name:      "one byte over the boundary is unencodable and never reaches the wire",
			length:    cMax + 1,
			wantDials: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// dials counts every exchange the resolver attempts. It is written only
			// from the synchronous dial seam on this goroutine, so it needs no lock.
			dials := 0
			counting := withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
				dials++
				d := net.Dialer{}
				return d.DialContext(ctx, network, stub.addr())
			})
			r, err := NewResolver(stdConfig(), counting, WithTimeout(time.Second))
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			// Both lengths are a definitive miss here (the stub knows no names); the
			// discriminator is whether the query reached the wire at all.
			addrs, err := r.lookupCandidate(context.Background(), nameOfLength(t, tt.length))
			if err != nil {
				t.Fatalf("lookupCandidate(%d-byte name) err = %v, want a definitive miss", tt.length, err)
			}
			if len(addrs) != 0 {
				t.Fatalf("lookupCandidate(%d-byte name) = %v, want no addresses", tt.length, addrs)
			}
			if dials != tt.wantDials {
				t.Fatalf("getaddrinfo-shim name-length drift: the Go reference made %d exchange(s) for a %d-byte name, want %d — #define K3SM_DNS_MAX_NAME_LEN = %d is not the Go encoder's ceiling",
					dials, tt.length, tt.wantDials, cMax)
			}
		})
	}
}
