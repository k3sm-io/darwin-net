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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// arm64eHostSource is a tiny host executable that reports whether the
// getaddrinfo shim is among its loaded images.
const arm64eHostSource = `#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>
int main(void) {
	for (unsigned i = 0; i < _dyld_image_count(); i++) {
		if (strstr(_dyld_get_image_name(i), "libk3sm_getaddrinfo_shim")) {
			puts("K3SM_SHIM_LOADED");
			return 0;
		}
	}
	puts("K3SM_SHIM_ABSENT");
	return 3;
}
`

// TestShimLoadsIntoArm64eHost is the arm64e canary: it LIVE-loads the built
// shim into an arm64e process with DYLD_INSERT_LIBRARIES and requires the shim
// to be present in the process's image list.
//
// Why live: the re-signed copies of Apple's shells that keep the shim alive
// across a wrapper are arm64e, and dyld aborts any process whose inserted
// library lacks its slice ("missing compatible architecture ... need
// 'arm64e'"), turning a silent DNS gap into a SIGABRT of every shell exec.
// Header parsing cannot prove the slice: debug/macho reports arm64e as
// CpuArm64 (the difference is the CPU subtype), and Apple does not promise
// arm64e ABI stability for third-party code, so only a load is evidence.
//
// It skips, with the reason, only when the environment cannot run the check
// at all (not darwin, no clang, no codesign, a toolchain that cannot emit or
// execute arm64e); a shim that fails to build, or an arm64e process that
// dies loading it, fails.
func TestShimLoadsIntoArm64eHost(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("SKIP: arm64e and DYLD_INSERT_LIBRARIES are darwin-only (GOOS=%s)", runtime.GOOS)
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("SKIP: clang not on PATH, cannot build the shim or an arm64e host: %v", err)
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skipf("SKIP: codesign not on PATH, cannot ad-hoc sign the arm64e host: %v", err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "host.c")
	if err := os.WriteFile(src, []byte(arm64eHostSource), 0o644); err != nil {
		t.Fatalf("write arm64e host source: %v", err)
	}
	host := filepath.Join(dir, "host")
	if out, err := exec.Command("clang", "-arch", "arm64e", "-o", host, src).CombinedOutput(); err != nil {
		t.Skipf("SKIP: this toolchain cannot emit an arm64e executable: %v\n%s", err, out)
	}
	if out, err := exec.Command("codesign", "-s", "-", "-f", host).CombinedOutput(); err != nil {
		t.Fatalf("ad-hoc sign the arm64e host: %v\n%s", err, out)
	}
	// Baseline without the shim: proves this machine can run arm64e at all, so
	// a later failure is the shim's, not the host's.
	base, err := exec.Command(host).CombinedOutput()
	if !strings.Contains(string(base), "K3SM_SHIM_ABSENT") {
		t.Skipf("SKIP: this machine cannot execute an ad-hoc arm64e binary (not Apple silicon?): %v\n%s", err, base)
	}

	root := shimArchRepoRoot(t)
	outDir := filepath.Join(dir, "shim")
	build := exec.Command("bash", filepath.Join(root, "hack", "build-shim.sh"), outDir)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build-shim.sh failed: %v\n%s", err, out)
	}
	dylib := filepath.Join(outDir, "libk3sm_getaddrinfo_shim.dylib")
	if _, err := os.Stat(dylib); err != nil {
		t.Skipf("SKIP: build-shim.sh produced no shim at %s: %v", dylib, err)
	}

	cmd := exec.Command(host)
	cmd.Env = append(os.Environ(), "DYLD_INSERT_LIBRARIES="+dylib)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "incompatible architecture") || strings.Contains(string(out), "missing compatible architecture") {
		t.Fatalf("dyld refused the shim in an arm64e process (no arm64e slice); "+
			"hack/build-shim.sh must pass -arch arm64e: %v\n%s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "K3SM_SHIM_LOADED") {
		t.Fatalf("arm64e host did not load the shim: %v\n%s", err, out)
	}
}
