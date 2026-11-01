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

package netd

import (
	"os"
	"strings"
	"testing"
)

// longVersion returns a valid release version name of exactly n characters.
func longVersion(n int) string {
	const base = "v1.0.0-"
	return base + strings.Repeat("a", n-len(base))
}

// TestValidInstalledVersionBoundaries pins validInstalledVersion at the edges
// of the installer's rule (k3sm pkg/updater/layout ValidateVersion).
func TestValidInstalledVersionBoundaries(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"release", "v0.3.0", true},
		{"no v prefix", "0.3.0", true},
		{"prerelease", "v1.2.3-rc.1", true},
		{"prerelease with empty identifier", "v1.2.3-rc..1", false},
		{"dangling prerelease dash", "v1.2.3-", false},
		{"build suffix", "v1.2.3+build.7", true},
		{"prerelease and build suffix", "v1.2.3-rc.1+build.5", true},
		{"unknown form", "unknown-0123456789ab", true},
		{"unknown form one hex short", "unknown-0123456789a", false},
		{"unknown form one hex long", "unknown-0123456789abc", false},
		{"unknown form uppercase hex", "unknown-0123456789AB", false},
		{"bare v prefix", "v", false},
		{"v with one number", "v1", false},
		{"leading zero", "v01.2.3", false},
		{"uppercase V", "V1.2.3", false},
		{"empty", "", false},
		{"path separator", "v1.2.3/x", false},
		{"127 characters", longVersion(127), true},
		{"128 characters", longVersion(128), true},
		{"129 characters", longVersion(129), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validInstalledVersion(tc.in); got != tc.want {
				t.Fatalf("validInstalledVersion(%.40q, len %d) = %v, want %v", tc.in, len(tc.in), got, tc.want)
			}
		})
	}
}

// TestValidInstalledVersionCorpus checks the committed seed corpus, derived
// from the installer's rule, against validInstalledVersion.
func TestValidInstalledVersionCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/installed-versions.txt")
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, verdict, ok := strings.Cut(line, " ")
		if !ok || (verdict != "valid" && verdict != "invalid") {
			t.Fatalf("malformed corpus line %.60q", line)
		}
		rows++
		if got := validInstalledVersion(name); got != (verdict == "valid") {
			t.Errorf("validInstalledVersion(%.40q, len %d) = %v, corpus says %s", name, len(name), got, verdict)
		}
	}
	if rows < 20 {
		t.Fatalf("corpus holds %d rows, want at least 20", rows)
	}
}
