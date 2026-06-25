//go:build integration

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
