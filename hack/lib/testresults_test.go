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

// Package testresults_test drives hack/lib/testresults.go (a //go:build ignore
// program) as a built binary over planted go test -json streams and registries.
package testresults_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
	buildOut  []byte
)

func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "testresults-bin-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "testresults")
		cmd := exec.Command("go", "build", "-o", binPath, "testresults.go")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		buildOut, buildErr = cmd.CombinedOutput()
	})
	if buildErr != nil {
		t.Fatalf("build testresults.go: %v\n%s", buildErr, buildOut)
	}
	return binPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binPath != "" {
		_ = os.RemoveAll(filepath.Dir(binPath)) // best-effort cleanup of the temp build dir
	}
	os.Exit(code)
}

const (
	pkg   = "k3sm.io/darwin-net/pkg/dns"
	other = "k3sm.io/darwin-net/pkg/proxy"
	sig   = "read udp 127.0.0.1: i/o timeout"
	today = "2026-10-30"
)

func ev(action, pkg, test, output string) string {
	m := map[string]string{"Action": action, "Package": pkg}
	if test != "" {
		m["Test"] = test
	}
	if output != "" {
		m["Output"] = output
	}
	b, _ := json.Marshal(m) // a map of strings always marshals
	return string(b)
}

func stream(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func entryFor(test string) string {
	return test + `  sig="` + sig + `"  owner=maintainers  filed=2026-10-20  deadline=2026-11-20  fix=#1  reason="port collision"` + "\n"
}

var (
	green = stream(
		ev("run", pkg, "TestOK", ""),
		ev("pass", pkg, "TestOK", ""),
		ev("output", pkg, "", "ok  \t"+pkg+"\t0.1s\n"),
		ev("pass", pkg, "", ""))
	flake = stream(
		ev("run", pkg, "TestFlake", ""),
		ev("output", pkg, "TestFlake", "    x_test.go:9: "+sig+"\n"),
		ev("output", pkg, "TestFlake", "--- FAIL: TestFlake (0.01s)\n"),
		ev("fail", pkg, "TestFlake", ""),
		ev("output", pkg, "", "FAIL\t"+pkg+"\t0.1s\n"),
		ev("fail", pkg, "", ""))
	race = stream(
		ev("run", pkg, "TestFlake", ""),
		ev("output", pkg, "TestFlake", "WARNING: DATA RACE\n"+sig+"\n"),
		ev("fail", pkg, "TestFlake", ""),
		ev("fail", pkg, "", ""))
	subFlake = stream(
		ev("run", pkg, "TestParent", ""),
		ev("run", pkg, "TestParent/a", ""),
		ev("output", pkg, "TestParent/a", sig+"\n"),
		ev("fail", pkg, "TestParent/a", ""),
		ev("pass", pkg, "TestParent/b", ""),
		ev("fail", pkg, "TestParent", ""),
		ev("fail", pkg, "", ""))
	nestedFlake = stream(
		ev("output", pkg, "TestTop/mid/leaf", sig+"\n"),
		ev("fail", pkg, "TestTop/mid/leaf", ""),
		ev("fail", pkg, "TestTop/mid", ""),
		ev("fail", pkg, "TestTop", ""),
		ev("fail", pkg, "", ""))
	parentOnly = stream(
		ev("output", pkg, "TestParent", sig+"\n"),
		ev("pass", pkg, "TestParent/a", ""),
		ev("fail", pkg, "TestParent", ""),
		ev("fail", pkg, "", ""))
	pkgFail = stream(
		ev("output", pkg, "", "panic: init\n"),
		ev("fail", pkg, "", ""))
	noResult = stream(
		ev("run", pkg, "TestHang", ""),
		ev("output", pkg, "TestHang", "=== RUN TestHang\n"))
	buildFail = `{"ImportPath":"k3sm.io/darwin-net/pkg/dns [k3sm.io/darwin-net/pkg/dns.test]","Action":"build-output","Output":"x.go:1: syntax error\n"}` + "\n" +
		`{"ImportPath":"k3sm.io/darwin-net/pkg/dns [k3sm.io/darwin-net/pkg/dns.test]","Action":"build-fail"}` + "\n" +
		ev("fail", pkg, "", "") + "\n"
)

func TestTestResults(t *testing.T) {
	bin := binary(t)
	cases := []struct {
		name     string
		registry string // "" writes an empty file; "-" writes none
		input    string
		args     []string
		want     int
		wantOut  string
	}{
		{name: "green run, empty registry", input: green, args: []string{"-tier", "fast"}, want: 0, wantOut: "ok"},
		{name: "missing registry is empty", registry: "-", input: green, args: []string{"-tier", "full"}, want: 0},
		{name: "unlisted failure reds", input: flake, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED " + pkg + "::TestFlake: failed"},
		{name: "failing-test summary names the test", input: flake, args: []string{"-tier", "fast"}, want: 1, wantOut: "--- FAIL: TestFlake"},
		{name: "quarantined flake is excused in the fast tier", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast"}, want: 3, wantOut: "QUARANTINED " + pkg + "::TestFlake"},
		{name: "affected is the fast tier", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "affected"}, want: 3},
		{name: "quarantined flake reds in the full tier", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "full"}, want: 1, wantOut: "the full tier reds on it"},
		{name: "quarantined flake in an edited package reds", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast", pkg}, want: 1, wantOut: "edits " + pkg + " directly"},
		{name: "another edited package does not matter", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast", other}, want: 3},
		{name: "signature mismatch reds", registry: strings.Replace(entryFor(pkg+"::TestFlake"), sig, "connection reset by peer", 1), input: flake, args: []string{"-tier", "fast"}, want: 1, wantOut: "does not match the recorded signature"},
		{name: "race reds even when listed", registry: entryFor(pkg + "::TestFlake"), input: race, args: []string{"-tier", "fast"}, want: 1, wantOut: "race or sanitizer report"},
		{name: "expired entry reds", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast", "-today", "2026-11-21"}, want: 1, wantOut: "quarantine expired"},
		{name: "expired entry reds a green run", registry: entryFor(pkg + "::TestFlake"), input: green, args: []string{"-tier", "fast", "-today", "2026-11-21"}, want: 1},
		{name: "malformed line reds a green run", registry: pkg + "::TestX sig=\"x\"\n", input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED registry: line 1"},
		{name: "unclosed quote reds", registry: pkg + "::TestX sig=\"" + sig + "\n", input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "unparseable"},
		{name: "unknown key reds", registry: strings.TrimSuffix(entryFor(pkg+"::TestX"), "\n") + " extra=1\n", input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "unknown key"},
		{name: "short signature reds", registry: strings.Replace(entryFor(pkg+"::TestX"), sig, "timeout", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "shorter than 12"},
		{name: "race signature is refused", registry: strings.Replace(entryFor(pkg+"::TestX"), sig, "WARNING: DATA RACE here", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "refused"},
		{name: "trust surface is refused", registry: entryFor("k3sm.io/k3sm/pkg/certs::TestRotate"), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "can never be quarantined"},
		{name: "deadline before filed reds", registry: strings.Replace(entryFor(pkg+"::TestX"), "deadline=2026-11-20", "deadline=2026-10-01", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "before filed"},
		{name: "duplicate id reds", registry: entryFor(pkg+"::TestX") + entryFor(pkg+"::TestX"), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "already listed"},
		{name: "eleven entries red", registry: elevenEntries(), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "at most 10"},
		{name: "comments and blank lines are ignored", registry: "# header\n\n" + strings.TrimSuffix(entryFor(pkg+"::TestFlake"), "\n") + "  # trailing\n", input: flake, args: []string{"-tier", "fast"}, want: 3},
		{name: "unlisted parent of a quarantined subtest is excused", registry: entryFor(pkg + "::TestParent/a"), input: subFlake, args: []string{"-tier", "fast"}, want: 3, wantOut: "failed only through quarantined subtests"},
		{name: "nested unlisted parents are excused", registry: entryFor(pkg + "::TestTop/mid/leaf"), input: nestedFlake, args: []string{"-tier", "fast"}, want: 3},
		{name: "a listed parent covers no subtest", registry: entryFor(pkg + "::TestParent"), input: subFlake, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED " + pkg + "::TestParent/a: failed"},
		{name: "a parent failing with no failing subtest reds", registry: entryFor(pkg + "::TestParent/a"), input: parentOnly, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED " + pkg + "::TestParent: failed"},
		{name: "parent rule does not apply in the full tier", registry: entryFor(pkg + "::TestParent/a"), input: subFlake, args: []string{"-tier", "full"}, want: 1},
		{name: "package failure outside a test reds", input: pkgFail, args: []string{"-tier", "fast"}, want: 1, wantOut: pkg + "::(package)"},
		{name: "a build failure reds", input: buildFail, args: []string{"-tier", "fast"}, want: 1, wantOut: "::(build)"},
		{name: "a test with no result reds", input: noResult, args: []string{"-tier", "fast"}, want: 1, wantOut: "no result"},
		{name: "a non-JSON line reds", input: green + "FAIL something\n", args: []string{"-tier", "fast"}, want: 1, wantOut: "not JSON"},
		{name: "an empty stream reds", input: "", args: []string{"-tier", "fast"}, want: 1, wantOut: "holds no results"},
		{name: "no tier is a usage error", input: green, want: 2},
		{name: "an unknown tier is a usage error", input: green, args: []string{"-tier", "medium"}, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			reg := filepath.Join(dir, "quarantine.txt")
			if tc.registry != "-" {
				if err := os.WriteFile(reg, []byte(tc.registry), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{"-registry", reg, "-today", today}, tc.args...)
			cmd := exec.Command(bin, args...)
			cmd.Stdin = strings.NewReader(tc.input)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			got := 0
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("run: %v", err)
				}
				got = ee.ExitCode()
			}
			if got != tc.want {
				t.Fatalf("exit %d, want %d\n%s", got, tc.want, out.String())
			}
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Fatalf("output lacks %q\n%s", tc.wantOut, out.String())
			}
		})
	}
}

func elevenEntries() string {
	var b strings.Builder
	for i := 0; i < 11; i++ {
		b.WriteString(entryFor(pkg + "::TestN" + string(rune('A'+i))))
	}
	return b.String()
}

// TestCommittedRegistryIsValid keeps the repository's own registry parseable.
func TestCommittedRegistryIsValid(t *testing.T) {
	cmd := exec.Command(binary(t), "-registry", "../quarantine.txt", "-tier", "full")
	cmd.Stdin = strings.NewReader(green)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("committed registry: %v\n%s", err, out)
	}
}
