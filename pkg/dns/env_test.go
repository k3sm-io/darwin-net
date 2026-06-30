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
	"maps"
	"os"
	"regexp"
	"slices"
	"testing"

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

// TestShimEnvNamesMatchC is the C<->Go drift guard. It is the one place both the
// Go env-name consts and shim/getaddrinfo_shim.c are visible, so it mechanically
// binds the unavoidable C copy of the K3SM_DNS_* names to the Go consts: it reads
// the .c as text, extracts every getenv("K3SM_DNS_…") name, and asserts that set
// exactly equals the consts ConfigToEnv and k3sm depend on. A rename on either
// side fails here instead of silently disabling cluster DNS in pods.
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

	want := []string{EnvDNSServer, EnvDNSPort, EnvDNSDomain, EnvDNSSearch, EnvDNSNdots}
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Errorf("getaddrinfo-shim ABI drift between %s and pkg/dns consts:\n  C shim getenv names: %v\n  Go env-name consts:  %v", shimPath, got, want)
	}
}
