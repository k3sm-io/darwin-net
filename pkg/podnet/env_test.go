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
	re := regexp.MustCompile(`getenv\("(K3SM_(?:POD|BIND)_[A-Z0-9_]+)"\)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatalf("no getenv(\"K3SM_POD_*\"/\"K3SM_BIND_*\") calls found in %s — regex or shim layout drifted", bindShimPath)
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

	want := []string{EnvPodIP, EnvBindDebug}
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
