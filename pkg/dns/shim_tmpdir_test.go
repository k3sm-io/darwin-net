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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestShimBuildLeavesNoTempDirs asserts hack/build-shim.sh leaves nothing
// behind in the caller's TMPDIR. Apple clang's driver creates one
// <source>-<hex> directory per arch for a multi-arch compile and does not
// remove it, so without a private TMPDIR every shim build leaks empty
// getaddrinfo_shim-* directories into the user's temp dir.
func TestShimBuildLeavesNoTempDirs(t *testing.T) {
	requireX86_64Capable(t)

	root := shimArchRepoRoot(t)
	tmp := t.TempDir()
	outDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "hack", "build-shim.sh"), outDir)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-shim.sh failed: %v\n%s", err, out)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read TMPDIR %s: %v", tmp, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("build-shim.sh left %d entries in TMPDIR: %v; "+
			"the clang driver's per-arch temp dirs must be removed", len(names), names)
	}
}
