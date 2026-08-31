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

package podnet

import (
	"maps"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

// bindShimPath is the C shim the drift guards below read as text. It is the same
// dylib source pkg/dns's guards read; the two ABIs share a file and nothing else.
const bindShimPath = "../../shim/getaddrinfo_shim.c"

func TestBindDisciplineEnv(t *testing.T) {
	tests := []struct {
		name  string
		podIP netip.Addr
		want  map[string]string
	}{
		{
			name:  "an allocated pod /32 serializes as a dotted quad",
			podIP: netip.MustParseAddr("100.64.0.7"),
			want:  map[string]string{EnvPodIP: "100.64.0.7"},
		},
		{
			name: "a 4-in-6 mapped address is unmapped, never emitted as ::ffff:…",
			// inet_pton(AF_INET, "::ffff:100.64.0.7") fails, which would silently
			// disable the discipline in-pod.
			podIP: netip.AddrFrom16(netip.MustParseAddr("100.64.0.7").As16()),
			want:  map[string]string{EnvPodIP: "100.64.0.7"},
		},
		{
			name:  "the zero Addr injects nothing (the shim passes every bind through)",
			podIP: netip.Addr{},
			want:  nil,
		},
		{
			name:  "an IPv6 pod IP injects nothing — the shim's parser is AF_INET",
			podIP: netip.MustParseAddr("fd00::7"),
			want:  nil,
		},
		{
			name:  "the unspecified address injects nothing (it would rewrite wildcard to wildcard)",
			podIP: netip.MustParseAddr("0.0.0.0"),
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BindDisciplineEnv(tt.podIP)
			if !maps.Equal(got, tt.want) {
				t.Errorf("BindDisciplineEnv(%v) = %v, want %v", tt.podIP, got, tt.want)
			}
			// EnvBindDebug must never be emitted: it is a diagnostic the operator
			// sets on a pod under investigation, not part of the injected config.
			if v, ok := got[EnvBindDebug]; ok {
				t.Errorf("BindDisciplineEnv() emitted %s=%q; the debug flag must never be injected", EnvBindDebug, v)
			}
		})
	}
}

// TestShimBindEnvNamesMatchC is the C<->Go drift guard for the BIND half of the
// shim ABI — the sibling of pkg/dns's TestShimEnvNamesMatchC, which guards the
// resolver half of the same .c. It is the one place both the Go env-name consts
// and shim/getaddrinfo_shim.c are visible, so it mechanically binds the
// unavoidable C copy of the names to the Go consts: it reads the .c as text,
// extracts every getenv("K3SM_POD_*"/"K3SM_BIND_*") name, and asserts that set
// exactly equals the consts BindDisciplineEnv and k3sm depend on.
//
// A rename on either side fails here instead of silently disabling the bind
// discipline in pods — a failure whose only symptom is two Pods colliding on a
// port again, attributed to whichever one happened to bind second.
func TestShimBindEnvNamesMatchC(t *testing.T) {
	src, err := os.ReadFile(bindShimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", bindShimPath, err)
	}
	// Match only real getenv() calls, never the K3SM_* names in the .c comments.
	// The K3SM_DNS_* names are the resolver ABI and are guarded separately by
	// pkg/dns; this pattern deliberately does not see them.
	re := regexp.MustCompile(`getenv\("(K3SM_(?:POD|BIND|CLUSTER)_[A-Z0-9_]+)"\)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatalf("no getenv(\"K3SM_POD_*\"/\"K3SM_BIND_*\"/\"K3SM_CLUSTER_*\") calls found in %s — regex or shim layout drifted", bindShimPath)
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

	want := []string{EnvPodIP, EnvBindDebug, EnvClusterCIDRs}
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Errorf("bind-shim ABI drift between %s and pkg/podnet consts:\n  C shim getenv names: %v\n  Go env-name consts:  %v", bindShimPath, got, want)
	}
}

// TestShimMinRewritablePortMatchesC binds the C shim's low-port carve to the Go
// side's MinRewritablePort, the same way pkg/dns's TestShimMaxSearchMatchesC
// binds the search cap. The carve is a BINDING resolution of the bind-discipline
// plan (a specific-address bind below 1024 is EACCES for a non-root uid on
// Darwin, so rewriting a low-port wildcard breaks a working workload); a drift
// between the two copies would either reintroduce that breakage or silently
// widen the shared-wildcard residual the docs describe.
func TestShimMinRewritablePortMatchesC(t *testing.T) {
	src, err := os.ReadFile(bindShimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", bindShimPath, err)
	}
	re := regexp.MustCompile(`#define\s+K3SM_BIND_MIN_PORT\s+(\d+)`)
	m := re.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatalf("no `#define K3SM_BIND_MIN_PORT <n>` found in %s — regex or shim layout drifted", bindShimPath)
	}
	cMin, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse K3SM_BIND_MIN_PORT %q: %v", m[1], err)
	}
	if cMin != MinRewritablePort {
		t.Errorf("bind-shim low-port drift: %s #define K3SM_BIND_MIN_PORT = %d, but pkg/podnet MinRewritablePort = %d", bindShimPath, cMin, MinRewritablePort)
	}
}

func TestBindDisciplineEnvWithCIDRs(t *testing.T) {
	podIP := netip.MustParseAddr("100.64.0.7")
	pfx := func(ss ...string) []netip.Prefix {
		out := make([]netip.Prefix, 0, len(ss))
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	tests := []struct {
		name  string
		podIP netip.Addr
		cidrs []netip.Prefix
		want  map[string]string
	}{
		{
			name:  "the pod CIDR and the Service CIDR serialize comma-separated, in caller order",
			podIP: podIP,
			cidrs: pfx("10.42.0.0/16", "10.43.0.0/16"),
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.42.0.0/16,10.43.0.0/16",
			},
		},
		{
			name:  "nil cidrs produce exactly BindDisciplineEnv's output (the additive contract)",
			podIP: podIP,
			cidrs: nil,
			want:  map[string]string{EnvPodIP: "100.64.0.7"},
		},
		{
			name:  "an empty slice is the same as nil — no key, not an empty value",
			podIP: podIP,
			cidrs: []netip.Prefix{},
			want:  map[string]string{EnvPodIP: "100.64.0.7"},
		},
		{
			// The C side masks nothing: it parses the address with inet_pton and
			// applies the prefix length itself, so an unmasked spelling would match
			// the same destinations — but the two sides must AGREE on the text, and
			// the shim's trace prints the masked form.
			name:  "an unmasked prefix is canonicalised to its network address",
			podIP: podIP,
			cidrs: []netip.Prefix{netip.MustParsePrefix("10.42.7.9/16")},
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.42.0.0/16",
			},
		},
		{
			name:  "a 4-in-6 mapped prefix serializes as a dotted quad, never ::ffff:…",
			podIP: podIP,
			cidrs: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom16(netip.MustParseAddr("10.42.0.0").As16()), 16)},
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.42.0.0/16",
			},
		},
		{
			name:  "exact duplicates collapse, order preserved",
			podIP: podIP,
			cidrs: pfx("10.43.0.0/16", "10.42.0.0/16", "10.43.0.0/16"),
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.43.0.0/16,10.42.0.0/16",
			},
		},
		{
			// A /0 names every destination, so emitting it would source-pin
			// en0-routed external egress onto a lo0 /32 — the hazard the whole
			// destination scoping exists to prevent.
			name:  "a /0 is dropped; the surviving prefixes still ship",
			podIP: podIP,
			cidrs: pfx("0.0.0.0/0", "10.42.0.0/16"),
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.42.0.0/16",
			},
		},
		{
			name:  "a /0 alone leaves no usable scope, so the key is omitted entirely",
			podIP: podIP,
			cidrs: pfx("0.0.0.0/0"),
			want:  map[string]string{EnvPodIP: "100.64.0.7"},
		},
		{
			name:  "an IPv6 prefix is skipped — the shim's parser and the IPAM are both v4",
			podIP: podIP,
			cidrs: pfx("fd00::/48", "10.42.0.0/16"),
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.42.0.0/16",
			},
		},
		{
			name:  "the zero Prefix is skipped",
			podIP: podIP,
			cidrs: []netip.Prefix{{}, netip.MustParsePrefix("10.42.0.0/16")},
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.42.0.0/16",
			},
		},
		{
			name:  "a single-address /32 scope is legal (one Service VIP)",
			podIP: podIP,
			cidrs: pfx("10.43.0.10/32"),
			want: map[string]string{
				EnvPodIP:        "100.64.0.7",
				EnvClusterCIDRs: "10.43.0.10/32",
			},
		},
		{
			// Deterministically OFF beats silently narrowed: the C shim treats an
			// over-long list as unparseable, so shipping a truncated one would mean
			// the two sides disagree about which destinations are in scope.
			name:  "more than MaxClusterCIDRs usable prefixes omits the key entirely",
			podIP: podIP,
			cidrs: pfx("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",
				"10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24", "10.0.7.0/24", "10.0.8.0/24"),
			want: map[string]string{EnvPodIP: "100.64.0.7"},
		},
		{
			name:  "exactly MaxClusterCIDRs prefixes still ship (the boundary is inclusive)",
			podIP: podIP,
			cidrs: pfx("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",
				"10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24", "10.0.7.0/24"),
			want: map[string]string{
				EnvPodIP: "100.64.0.7",
				EnvClusterCIDRs: "10.0.0.0/24,10.0.1.0/24,10.0.2.0/24,10.0.3.0/24," +
					"10.0.4.0/24,10.0.5.0/24,10.0.6.0/24,10.0.7.0/24",
			},
		},
		{
			name:  "a rejected pod IP injects nothing, however good the CIDRs are",
			podIP: netip.MustParseAddr("0.0.0.0"),
			cidrs: pfx("10.42.0.0/16"),
			want:  nil,
		},
		{
			name:  "the zero Addr injects nothing (no source to pin to)",
			podIP: netip.Addr{},
			cidrs: pfx("10.42.0.0/16"),
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BindDisciplineEnvWithCIDRs(tt.podIP, tt.cidrs)
			if !maps.Equal(got, tt.want) {
				t.Errorf("BindDisciplineEnvWithCIDRs(%v, %v) = %v, want %v", tt.podIP, tt.cidrs, got, tt.want)
			}
			if v, ok := got[EnvBindDebug]; ok {
				t.Errorf("BindDisciplineEnvWithCIDRs() emitted %s=%q; the debug flag must never be injected", EnvBindDebug, v)
			}
		})
	}
}

// TestBindDisciplineEnvUnchangedByCIDRs pins the ADDITIVE half of the B218 ABI
// extension: BindDisciplineEnv must keep its exact signature AND its exact
// output, because k3sm's provider calls it directly (pkg/provider/translate.go)
// and an existing caller that declares no cluster scope must keep getting the
// pre-B218 behaviour — the shim pins no dial at all.
func TestBindDisciplineEnvUnchangedByCIDRs(t *testing.T) {
	addr := netip.MustParseAddr("100.64.0.7")
	base := BindDisciplineEnv(addr)
	if !maps.Equal(base, map[string]string{EnvPodIP: "100.64.0.7"}) {
		t.Fatalf("BindDisciplineEnv(%v) = %v; the pre-B218 output must not change", addr, base)
	}
	if _, ok := base[EnvClusterCIDRs]; ok {
		t.Errorf("BindDisciplineEnv emitted %s; the connect rung must stay off for callers that did not ask for it", EnvClusterCIDRs)
	}
	if withNil := BindDisciplineEnvWithCIDRs(addr, nil); !maps.Equal(withNil, base) {
		t.Errorf("BindDisciplineEnvWithCIDRs(%v, nil) = %v, want the BindDisciplineEnv output %v", addr, withNil, base)
	}
}

// TestShimMaxClusterCIDRsMatchesC binds the C shim's fixed-size cluster-CIDR
// table to the Go side's MaxClusterCIDRs, the sibling of
// TestShimMinRewritablePortMatchesC. The two copies must agree in BOTH
// directions: a Go cap ABOVE the C one would ship a list the shim rejects as
// unparseable (the connect rung silently off for every pod), and a Go cap BELOW
// it would refuse a scope the shim could have honoured.
func TestShimMaxClusterCIDRsMatchesC(t *testing.T) {
	src, err := os.ReadFile(bindShimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", bindShimPath, err)
	}
	re := regexp.MustCompile(`#define\s+K3SM_MAX_CLUSTER_CIDRS\s+(\d+)`)
	m := re.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatalf("no `#define K3SM_MAX_CLUSTER_CIDRS <n>` found in %s — regex or shim layout drifted", bindShimPath)
	}
	cMax, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse K3SM_MAX_CLUSTER_CIDRS %q: %v", m[1], err)
	}
	if cMax != MaxClusterCIDRs {
		t.Errorf("cluster-CIDR cap drift: %s #define K3SM_MAX_CLUSTER_CIDRS = %d, but pkg/podnet MaxClusterCIDRs = %d", bindShimPath, cMax, MaxClusterCIDRs)
	}
}
