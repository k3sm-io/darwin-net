//go:build darwin

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
	"debug/macho"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// shimArchRepoRoot returns the darwin-net repo root from this file's location.
// It is deliberately separate from the integration-tagged helper of the same
// purpose: this test runs in the DEFAULT build, where that file is absent.
func shimArchRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	// .../darwin-net/pkg/dns/shim_arch_test.go -> .../darwin-net
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// requireX86_64Capable skips the test when this toolchain cannot emit an x86_64
// slice at all (no clang, or no x86_64 SDK support). It compiles a throwaway
// dylib rather than assuming, so the difference between "the environment cannot
// build the slice" (legible skip) and "the build script did not ask for the
// slice" (failure) is decided by evidence, not by inference.
func requireX86_64Capable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("SKIP: clang not on PATH, cannot build the shim at all: %v", err)
	}
	src := filepath.Join(t.TempDir(), "probe.c")
	if err := os.WriteFile(src, []byte("int k3sm_arch_probe(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatalf("write arch probe source: %v", err)
	}
	out := filepath.Join(filepath.Dir(src), "probe.dylib")
	cmd := exec.Command("clang", "-arch", "x86_64", "-dynamiclib", "-o", out, src)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("SKIP: this toolchain cannot emit an x86_64 slice (no x86_64 SDK support?), "+
			"so the universal-shim assertion is untestable here: %v\n%s", err, combined)
	}
}

// machoArches returns the CPU architectures present in the Mach-O at path,
// whether it is a fat (universal) file or a single-arch one.
func machoArches(t *testing.T, path string) []macho.Cpu {
	t.Helper()
	fat, err := macho.OpenFat(path)
	if err == nil {
		defer func() { _ = fat.Close() }()
		arches := make([]macho.Cpu, 0, len(fat.Arches))
		for _, a := range fat.Arches {
			arches = append(arches, a.Cpu)
		}
		return arches
	}
	if !errors.Is(err, macho.ErrNotFat) {
		t.Fatalf("read %s as a fat Mach-O: %v", path, err)
	}
	thin, err := macho.Open(path)
	if err != nil {
		t.Fatalf("read %s as a Mach-O: %v", path, err)
	}
	defer func() { _ = thin.Close() }()
	return []macho.Cpu{thin.Cpu}
}

// TestShimIsUniversalBinary asserts the BUILT getaddrinfo shim carries both an
// arm64 and an x86_64 slice, by reading the Mach-O headers of the artifact
// hack/build-shim.sh actually produces.
//
// It reads the artifact and never greps the build script, on purpose: the bug
// this gate fixes (B166) was the script's comment promising "arm64 + x86_64 fat
// dylib" while its flags passed only -arch arm64. A script-grep gate would have
// passed for the whole life of that bug, and would pass again the moment someone
// edits the comment back. The artifact cannot lie.
//
// Why it matters: dyld HARD-TERMINATES a process whose DYLD_INSERT_LIBRARIES
// library has no slice for that process's architecture, so an arm64-only shim
// kills a darwin/amd64 pod payload under Rosetta rather than merely dropping
// cluster DNS.
func TestShimIsUniversalBinary(t *testing.T) {
	requireX86_64Capable(t)

	root := shimArchRepoRoot(t)
	outDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "hack", "build-shim.sh"), outDir)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-shim.sh failed: %v\n%s", err, out)
	}
	dylib := filepath.Join(outDir, "libk3sm_getaddrinfo_shim.dylib")
	if _, err := os.Stat(dylib); err != nil {
		t.Fatalf("shim dylib not produced: %v", err)
	}

	arches := machoArches(t, dylib)
	want := map[macho.Cpu]bool{macho.CpuArm64: false, macho.CpuAmd64: false}
	for _, a := range arches {
		if _, ok := want[a]; ok {
			want[a] = true
		}
	}
	for cpu, found := range want {
		if !found {
			t.Errorf("built shim %s is missing the %s slice; it has %v. "+
				"dyld hard-terminates a process whose inserted library lacks its arch — "+
				"hack/build-shim.sh must pass both -arch arm64 and -arch x86_64",
				filepath.Base(dylib), cpu, arches)
		}
	}
}
