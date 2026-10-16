//go:build integration

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
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestCodesignToolDeveloperIDAnchor runs the real /usr/bin/codesign: an
// Apple-signed system binary (/usr/bin/true) and this test binary's own
// ad-hoc linker signature both verify, neither satisfies the Developer ID
// requirement, so neither counts as a team and signature: required refuses
// both.
func TestCodesignToolDeveloperIDAnchor(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	adhoc := filepath.Join(t.TempDir(), "adhoc")
	copyFile(t, self, adhoc)
	ctx := context.Background()
	for name, p := range map[string]string{"apple-signed /usr/bin/true": "/usr/bin/true", "ad-hoc test binary": adhoc} {
		t.Run(name, func(t *testing.T) {
			sig, err := codesignTool{}.Inspect(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			if !sig.Valid || sig.DeveloperID || sig.team() != "" {
				t.Fatalf("Inspect(%s) = %+v, want valid with no Developer ID team", p, sig)
			}
			ok, _, err := runCodesign(ctx, "--verify", "--strict", "-R="+developerIDAnchor, p)
			if err != nil || ok {
				t.Fatalf("the Developer ID anchor on %s = %v, %v; want unsatisfied", p, ok, err)
			}
			if err := checkCodeSigning(sig, map[string]codeSignature{"k3sm": sig}, true); err == nil {
				t.Fatalf("signature: required accepted %s", p)
			}
		})
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
