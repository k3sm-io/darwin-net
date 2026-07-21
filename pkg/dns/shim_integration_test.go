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

// Integration test for the getaddrinfo DYLD shim. It builds the C dylib (via
// hack/build-shim.sh), injects it into a plain probe process with
// DYLD_INSERT_LIBRARIES, and resolves a name through a LOCAL stub DNS server —
// proving the interpose path works in isolation, without runtimed or a real
// CoreDNS binary. Run with:
//
//	CGO_ENABLED=0 go test -tags integration -run TestGetaddrinfoShim ./pkg/dns/
//
// macOS / runtimed caveat (see doc.go): the shim only takes effect end-to-end in
// a pod when runtimed spawns it via its NON-platform exec-shim, because Apple's
// sandbox-exec strips DYLD_* from the environment. That true pod-under-Seatbelt
// path is an integration test in the runtimed slice; here we prove the dylib's
// interpose in isolation.
package dns

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// repoRoot returns the darwin-net repo root from this test file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	// .../darwin-net/pkg/dns/shim_integration_test.go -> .../darwin-net
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// buildShim runs hack/build-shim.sh and returns the dylib path.
func buildShim(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
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
	return dylib
}

// buildProbe compiles testdata/probe.c with clang and returns the binary path.
func buildProbe(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	src := filepath.Join(root, "pkg", "dns", "testdata", "probe.c")
	bin := filepath.Join(t.TempDir(), "probe")
	cmd := exec.Command("clang", "-arch", "arm64", "-O2", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile probe.c: %v\n%s", err, out)
	}
	return bin
}

// TestGetaddrinfoShimResolvesViaStub maps to acceptance M1.2-a1 (proven in
// isolation): with the shim injected and pointed at a local stub CoreDNS, a
// probe process resolves a SHORT Service name via search expansion; without the
// shim, the same probe does NOT resolve it. This is the in-repo proof the DYLD
// interpose path works.
func TestGetaddrinfoShimResolvesViaStub(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}

	want := netip.MustParseAddr("10.43.0.42")
	stub := newStubDNS(t, map[string]netip.Addr{
		"web.default.svc.cluster.local": want,
	})
	defer stub.close()

	dylib := buildShim(t)
	probe := buildProbe(t)

	env := append(os.Environ(),
		"K3SM_DNS_SERVER=127.0.0.1",
		"K3SM_DNS_PORT="+strconv.Itoa(stub.port()),
		"K3SM_DNS_DOMAIN=cluster.local",
		"K3SM_DNS_SEARCH=default.svc.cluster.local svc.cluster.local cluster.local",
		"K3SM_DNS_NDOTS=5",
	)

	t.Run("with shim resolves short name via search", func(t *testing.T) {
		cmd := exec.Command(probe, "web")
		cmd.Env = append(env, "DYLD_INSERT_LIBRARIES="+dylib)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("probe with shim failed: %v\n%s", err, out)
		}
		got := strings.TrimSpace(string(out))
		if got != want.String() {
			t.Fatalf("probe resolved %q, want %q (shim search-expansion path)", got, want)
		}
		if !stub.asked("web.default.svc.cluster.local") {
			t.Fatalf("stub never received the search-expanded query")
		}
	})

	t.Run("without shim does not resolve the cluster name", func(t *testing.T) {
		cmd := exec.Command(probe, "web")
		cmd.Env = env // no DYLD_INSERT_LIBRARIES
		out, err := cmd.CombinedOutput()
		// The system resolver should not know "web"; either it errors or it
		// returns something other than the cluster address. Both prove the shim
		// is what made resolution work.
		got := strings.TrimSpace(string(out))
		if err == nil && got == want.String() {
			t.Fatalf("probe resolved cluster name WITHOUT the shim: %q", got)
		}
	})
}

// TestGetaddrinfoShimNamedService pins the named-service ("http") contract: a
// named service must never hard-fail up front — it DEFERS to the system
// resolver for external names (the behavior an up-front EAI_SERVICE once
// regressed) and is refused with EAI_SERVICE only on a cluster HIT, where the
// shim itself would have to fabricate the port. A numeric service still rides
// the cluster path into the returned sockaddr.
func TestGetaddrinfoShimNamedService(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}

	want := netip.MustParseAddr("10.43.0.42")
	stub := newStubDNS(t, map[string]netip.Addr{
		"web.default.svc.cluster.local": want,
	})
	defer stub.close()

	dylib := buildShim(t)
	probe := buildProbe(t)

	env := append(os.Environ(),
		"K3SM_DNS_SERVER=127.0.0.1",
		"K3SM_DNS_PORT="+strconv.Itoa(stub.port()),
		"K3SM_DNS_DOMAIN=cluster.local",
		"K3SM_DNS_SEARCH=default.svc.cluster.local svc.cluster.local cluster.local",
		"K3SM_DNS_NDOTS=5",
		"DYLD_INSERT_LIBRARIES="+dylib,
	)

	t.Run("numeric service rides the cluster path into the sockaddr", func(t *testing.T) {
		cmd := exec.Command(probe, "web", "8080")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("probe web 8080 failed: %v\n%s", err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want.String()+":8080" {
			t.Fatalf("probe resolved %q, want %q", got, want.String()+":8080")
		}
	})

	t.Run("named service on a cluster HIT is EAI_SERVICE, not port 0", func(t *testing.T) {
		cmd := exec.Command(probe, "web", "http")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("probe web http succeeded, want EAI_SERVICE; out=%s", out)
		}
		if !strings.Contains(string(out), "EAI_SERVICE") {
			t.Fatalf("probe web http failed without EAI_SERVICE: %s", out)
		}
		if !stub.asked("web.default.svc.cluster.local") {
			t.Fatalf("cluster candidate was never queried — EAI_SERVICE fired up front again")
		}
	})

	t.Run("named service on an external name defers to the system resolver", func(t *testing.T) {
		cmd := exec.Command(probe, "name.invalid", "http")
		cmd.Env = env
		out, _ := cmd.CombinedOutput()
		// .invalid never resolves (RFC 2606), so the DEFERRED system call fails
		// with a name error — but never with EAI_SERVICE, which is the pre-walk
		// hard-fail regression signature for external name + named service.
		if strings.Contains(string(out), "EAI_SERVICE") {
			t.Fatalf("external name + named service returned EAI_SERVICE (up-front hard fail regressed): %s", out)
		}
		if !stub.asked("name.invalid.default.svc.cluster.local") {
			t.Fatalf("search-expanded cluster candidate was never queried — shim not active?")
		}
		if stub.asked("name.invalid") {
			t.Fatalf("absolute external candidate was queried in-shim; want defer-before-query")
		}
	})
}
