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

package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const pin = "2026.2.2"

// ciCandidateLoop returns the staticcheck candidate lookup of the shipped
// hack/ci.sh, from the `sc=""` initialiser up to (not including) the line that
// announces the chosen binary, so the test runs the real text, not a copy.
func ciCandidateLoop(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "ci.sh"))
	if err != nil {
		t.Fatalf("read ci.sh: %v", err)
	}
	ci := string(raw)
	start := strings.Index(ci, "\tsc=\"\"; sc_seen=\"\"")
	end := strings.Index(ci, "\techo \"==> [darwin-net] staticcheck ${STATICCHECK_VERSION}")
	if start < 0 || end < start {
		t.Fatalf("staticcheck candidate loop not found in ci.sh")
	}
	return ci[start:end]
}

// TestStaticcheckCandidateOrder pins the lookup order of the staticcheck stage
// in hack/ci.sh: $GOPATH/bin/staticcheck-<pin>, then PATH, then
// $GOPATH/bin/staticcheck, each accepted only when it reports the pin, and no
// candidate at the pin is a named red. The fakes only print a version line.
func TestStaticcheckCandidateOrder(t *testing.T) {
	loop := ciCandidateLoop(t)
	// The real home: go env writes telemetry under it, which a temp dir cannot clean.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	pinned := "staticcheck " + pin + " (0.8.1)"
	other := "staticcheck 2025.1 (0.6.0)"

	cases := []struct {
		name      string
		path      string // PATH fake's -version output; "" = none
		versioned string // $GOPATH/bin/staticcheck-<pin>; "" = none
		plain     string // $GOPATH/bin/staticcheck; "" = none
		want      string // "path", "versioned", "plain"; "" = red
		wantOut   []string
	}{
		{name: "versioned_binary_wins", path: pinned, versioned: pinned, plain: pinned, want: "versioned"},
		{name: "versioned_wrong_version_falls_back", path: pinned, versioned: other, want: "path"},
		{name: "path_before_plain_gopath", path: pinned, plain: pinned, want: "path"},
		{name: "plain_gopath_last_resort", path: other, plain: pinned, want: "plain"},
		{name: "absent_is_red", wantOut: []string{"not installed", "staticcheck@" + pin, "staticcheck-" + pin}},
		{name: "no_candidate_at_pin_is_red", path: other, versioned: other, wantOut: []string{"the gate needs " + pin, "2025.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, gopath := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Join(gopath, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"go", "awk"} {
				p, err := exec.LookPath(tool)
				if err != nil {
					t.Fatalf("need %s: %v", tool, err)
				}
				if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
					t.Fatal(err)
				}
			}
			fake := func(path, who, line string) {
				if line == "" {
					return
				}
				body := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo '" + line + "'; fi\n" + "# " + who + "\n"
				if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			fake(filepath.Join(bin, "staticcheck"), "path", tc.path)
			fake(filepath.Join(gopath, "bin", "staticcheck-"+pin), "versioned", tc.versioned)
			fake(filepath.Join(gopath, "bin", "staticcheck"), "plain", tc.plain)

			script := "set -euo pipefail\nSTATICCHECK_VERSION=" + pin + "\n" + loop +
				"\nprintf 'CHOSEN=%s\\n' \"$sc\"\n"
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = []string{
				"PATH=" + bin + ":/bin:/usr/bin",
				"GOPATH=" + gopath,
				"GOFLAGS=",
				"GOTOOLCHAIN=local",
				"GOWORK=off",
				"HOME=" + home,
			}
			outb, err := cmd.CombinedOutput()
			out := string(outb)

			if tc.want == "" {
				if err == nil {
					t.Fatalf("want RED, exited zero:\n%s", out)
				}
				for _, w := range tc.wantOut {
					if !strings.Contains(out, w) {
						t.Errorf("output lacks %q:\n%s", w, out)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("want a pick, got %v:\n%s", err, out)
			}
			want := map[string]string{
				"versioned": filepath.Join(gopath, "bin", "staticcheck-"+pin),
				"path":      filepath.Join(bin, "staticcheck"),
				"plain":     filepath.Join(gopath, "bin", "staticcheck"),
			}[tc.want]
			if !strings.Contains(out, "CHOSEN="+want+"\n") {
				t.Errorf("chose wrong binary, want %s (%s):\n%s", tc.want, want, out)
			}
		})
	}
}
