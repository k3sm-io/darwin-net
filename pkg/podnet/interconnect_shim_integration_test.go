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

package podnet

import (
	"bytes"
	"context"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// The addresses the interconnect gate uses. The pod IP is 127.0.0.1, which
// exists on every host, exactly as the bind and connect acceptance gates use it. The interconnect
// address is a lo0 /32 alias inside the interconnect range at a host octet
// InterconnectSlotAddress never derives (it stops at 248), so it cannot collide
// with a real slot on a cabled node. No packet is sent to any destination: every
// dial case is SOCK_DGRAM, where connect(2) only fills in the pcb.
const (
	icTestPodIP      = "127.0.0.1"
	icTestClusterNet = "192.0.2.0/24" // RFC 5737 TEST-NET-1
	icTestClusterDst = "192.0.2.7"
	icTestIP         = "169.254.0.253"
	icTestDst        = "169.254.0.250"
	icTestOutDst     = "198.51.100.7" // RFC 5737 TEST-NET-2
	icTestBasePort   = "18522"

	// icScopeAccepted is the trace line the shim prints when it accepts the
	// interconnect scope.
	icScopeAccepted = "interconnect: source-pin scope"
)

// icRepoRoot returns the darwin-net repo root from this file's location.
func icRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// icArm is one run of the case harness: its parsed case lines and its stderr
// (the K3SM_BIND_DEBUG trace).
type icArm struct {
	cases map[string]map[string]string
	trace string
}

// local returns the address half of a case's LOCAL field; every dial port is
// kernel-assigned, so the ADDRESS is the verdict.
func (a icArm) local(c string) string {
	v := a.cases[c]["LOCAL"]
	if i := strings.LastIndex(v, ":"); i >= 0 {
		return v[:i]
	}
	return v
}

// TestInterconnectEnvPinsSourceInScope is the gate. It injects the REAL
// shim (built by hack/build-shim.sh) into the bindcases harness's interconnect
// table and reads every verdict from the socket (getsockname), asserting the
// K3SM_BIND_DEBUG trace in addition, the connect-pinning discipline.
//
// It needs root for one thing only: the interconnect address must exist on the
// host to be bound, so the test adds it as a lo0 alias and removes it after.
// Run it with:
//
//	CGO_ENABLED=0 go test -c -tags integration -o podnet.test ./pkg/podnet/
//	sudo ./podnet.test -test.run TestInterconnectEnvPinsSourceInScope -test.v
func TestInterconnectEnvPinsSourceInScope(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("clang not on PATH, cannot build the shim or the harness: %v", err)
	}
	icRange := netv1alpha1.InterconnectCIDR
	icPrefix := netip.MustParsePrefix(icRange)
	if !icPrefix.Contains(netip.MustParseAddr(icTestIP)) || !icPrefix.Contains(netip.MustParseAddr(icTestDst)) {
		t.Fatalf("test addresses %s/%s are not inside apis InterconnectCIDR %s", icTestIP, icTestDst, icRange)
	}

	root := icRepoRoot(t)
	work := t.TempDir()
	if out, err := exec.Command("bash", filepath.Join(root, "hack", "build-shim.sh"), work).CombinedOutput(); err != nil {
		t.Fatalf("build-shim.sh: %v\n%s", err, out)
	}
	dylib := filepath.Join(work, "libk3sm_getaddrinfo_shim.dylib")
	harness := filepath.Join(work, "bindcases")
	if out, err := exec.Command("clang", "-O2", "-Wall", "-Wextra", "-o", harness,
		filepath.Join(root, "pkg", "podnet", "testdata", "bindcases.c")).CombinedOutput(); err != nil {
		t.Fatalf("compile bindcases.c: %v\n%s", err, out)
	}

	ctx := context.Background()
	alias := netip.MustParseAddr(icTestIP)
	if lo0HasAddr(t, alias) {
		t.Fatalf("precondition: %s is already on lo0; refusing to touch an address this test did not add", alias)
	}
	mgr := newLo0AliasManager(netip.Prefix{})
	if err := mgr.Ensure(ctx, alias); err != nil {
		t.Fatalf("add lo0 alias %s: %v", alias, err)
	}
	t.Cleanup(func() { _ = mgr.Remove(ctx, alias) })

	run := func(t *testing.T, withShim bool, env ...string) icArm {
		t.Helper()
		cmd := exec.Command(harness, icTestBasePort, "1000", work, "interconnect",
			icTestClusterDst, icTestDst, icTestOutDst, icTestIP)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		if withShim {
			cmd.Env = append(cmd.Env, "DYLD_INSERT_LIBRARIES="+dylib, "K3SM_BIND_DEBUG=1")
		}
		cmd.Env = append(cmd.Env, env...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("harness %v: %v\nstdout:\n%s\nstderr:\n%s", env, err, stdout.String(), stderr.String())
		}
		arm := icArm{cases: map[string]map[string]string{}, trace: stderr.String()}
		for _, line := range strings.Split(stdout.String(), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || !strings.HasPrefix(fields[0], "CASE=") {
				continue
			}
			kv := map[string]string{}
			for _, f := range fields[1:] {
				if k, v, ok := strings.Cut(f, "="); ok {
					kv[k] = v
				}
			}
			arm.cases[strings.TrimPrefix(fields[0], "CASE=")] = kv
		}
		if len(arm.cases) != 6 {
			t.Fatalf("harness printed %d cases, want 6:\n%s", len(arm.cases), stdout.String())
		}
		return arm
	}

	podEnv := []string{"K3SM_POD_IP=" + icTestPodIP, "K3SM_CLUSTER_CIDRS=" + icTestClusterNet}
	icEnv := []string{EnvInterconnectIP + "=" + icTestIP, EnvInterconnectCIDRs + "=" + icRange}

	control := run(t, false)
	clusterOnly := run(t, true, podEnv...)
	enabled := run(t, true, append(cloneEnv(podEnv), icEnv...)...)

	// Preconditions: the kernel's own source for the interconnect destination is
	// neither address under test, so a pin is visible. A host with no route for
	// 169.254.0.0/24 (no bridge0 link-local, no default route) fails here.
	if c := control.cases["ic_dial_interconnect"]; c["RC"] != "0" {
		t.Fatalf("precondition: the un-shimmed dial to %s failed (RC=%s ERRNO=%s); the host needs a route for it", icTestDst, c["RC"], c["ERRNO"])
	}
	if got := control.local("ic_dial_interconnect"); got == icTestIP || got == icTestPodIP {
		t.Fatalf("precondition: the kernel already sources %s from %s, so the gate cannot discriminate", icTestDst, got)
	}

	t.Run("interconnect dial sources the interconnect address", func(t *testing.T) {
		if c := enabled.cases["ic_dial_interconnect"]; c["RC"] != "0" {
			t.Fatalf("dial failed: %v", c)
		}
		if got := enabled.local("ic_dial_interconnect"); got != icTestIP {
			t.Errorf("unbound dial to %s sourced %s, want %s", icTestDst, got, icTestIP)
		}
		if want := "-> PIN-INTERCONNECT source " + icTestIP; !strings.Contains(enabled.trace, want) {
			t.Errorf("trace lacks %q:\n%s", want, enabled.trace)
		}
	})
	t.Run("cluster dial still sources the pod IP", func(t *testing.T) {
		if got := enabled.local("ic_dial_cluster"); got != icTestPodIP {
			t.Errorf("unbound dial to %s sourced %s, want the pod IP %s", icTestClusterDst, got, icTestPodIP)
		}
		if want := "dst " + icTestClusterDst + ":9999 -> PIN source " + icTestPodIP; !strings.Contains(enabled.trace, want) {
			t.Errorf("trace lacks %q:\n%s", want, enabled.trace)
		}
	})
	t.Run("a dial elsewhere is unchanged", func(t *testing.T) {
		if got, want := enabled.local("ic_dial_elsewhere"), control.local("ic_dial_elsewhere"); got != want {
			t.Errorf("dial to %s sourced %s, want the kernel's own %s", icTestOutDst, got, want)
		}
		if want := "dst " + icTestOutDst + ":9999 -> PASSTHROUGH-NOTCLUSTER"; !strings.Contains(enabled.trace, want) {
			t.Errorf("trace lacks %q:\n%s", want, enabled.trace)
		}
	})
	t.Run("an already-bound socket is left alone", func(t *testing.T) {
		if got, want := enabled.local("ic_dial_interconnect_prebound"), control.local("ic_dial_interconnect_prebound"); got != want {
			t.Errorf("pre-bound dial to %s sourced %s, want the kernel's own %s", icTestDst, got, want)
		}
	})
	t.Run("a wildcard bind still lands on the pod IP", func(t *testing.T) {
		c := enabled.cases["ic_bind_wildcard"]
		if want := icTestPodIP + ":" + icTestBasePort; c["RC"] != "0" || c["LOCAL"] != want {
			t.Errorf("wildcard bind = %v, want RC=0 LOCAL=%s", c, want)
		}
	})
	t.Run("an explicit bind to the interconnect address is left alone", func(t *testing.T) {
		c := enabled.cases["ic_bind_interconnect"]
		if want := icTestIP + ":18523"; c["RC"] != "0" || c["LOCAL"] != want || c["REUSE"] != "0" {
			t.Errorf("explicit bind = %v, want RC=0 LOCAL=%s REUSE=0 (passthrough)", c, want)
		}
	})

	// Fail-safe polarity: every defective interconnect env reproduces the
	// cluster-only arm address for address, and the configured arm differs from
	// it (the non-vacuity check for this table).
	if clusterOnly.local("ic_dial_interconnect") == enabled.local("ic_dial_interconnect") {
		t.Fatalf("the cluster-only and configured arms agree on the interconnect dial; the inert checks below would prove nothing")
	}
	inert := []struct {
		name string
		env  []string
	}{
		{"unset", nil},
		{"ip only", []string{EnvInterconnectIP + "=" + icTestIP}},
		{"cidrs only", []string{EnvInterconnectCIDRs + "=" + icRange}},
		{"empty ip", []string{EnvInterconnectIP + "=", EnvInterconnectCIDRs + "=" + icRange}},
		{"garbage ip", []string{EnvInterconnectIP + "=not-an-ip", EnvInterconnectCIDRs + "=" + icRange}},
		{"garbage cidrs", []string{EnvInterconnectIP + "=" + icTestIP, EnvInterconnectCIDRs + "=" + icRange + ",bogus"}},
		{"ip outside the cidrs", []string{EnvInterconnectIP + "=" + icTestPodIP, EnvInterconnectCIDRs + "=" + icRange}},
		{"cidr outside link-local", []string{EnvInterconnectIP + "=" + icTestIP, EnvInterconnectCIDRs + "=" + icRange + ",198.51.100.0/24"}},
		{"/0", []string{EnvInterconnectIP + "=" + icTestIP, EnvInterconnectCIDRs + "=0.0.0.0/0"}},
		{"network address", []string{EnvInterconnectIP + "=169.254.0.0", EnvInterconnectCIDRs + "=" + icRange}},
		{"broadcast address", []string{EnvInterconnectIP + "=169.254.0.255", EnvInterconnectCIDRs + "=" + icRange}},
	}
	for _, tc := range inert {
		t.Run("inert/"+tc.name, func(t *testing.T) {
			arm := run(t, true, append(cloneEnv(podEnv), tc.env...)...)
			for c := range clusterOnly.cases {
				if got, want := arm.local(c), clusterOnly.local(c); got != want {
					t.Errorf("case %s sourced %s, want the cluster-only %s", c, got, want)
				}
			}
			if strings.Contains(arm.trace, "PIN-INTERCONNECT") || strings.Contains(arm.trace, icScopeAccepted) {
				t.Errorf("the shim accepted the interconnect scope or pinned a dial:\n%s", arm.trace)
			}
		})
	}
	// A valid interconnect address that is not on the host: the pin's bind
	// fails, the dial still goes out (unpinned, with the kernel's own source),
	// and the failure is traced. The one-shot unified-log line is not read
	// here; reading the log store is slow and needs no extra coverage beyond
	// the trace, which proves the branch ran.
	t.Run("a failed pin falls through unpinned", func(t *testing.T) {
		missing := "169.254.0.252"
		arm := run(t, true, append(cloneEnv(podEnv), EnvInterconnectIP+"="+missing, EnvInterconnectCIDRs+"="+icRange)...)
		c := arm.cases["ic_dial_interconnect"]
		if c["RC"] != "0" {
			t.Fatalf("dial failed after a failed pin: %v", c)
		}
		if got, want := arm.local("ic_dial_interconnect"), clusterOnly.local("ic_dial_interconnect"); got != want {
			t.Errorf("dial sourced %s, want the unpinned %s", got, want)
		}
		if want := "dst " + icTestDst + ":9999 -> PIN-FAILED errno=49"; !strings.Contains(arm.trace, want) {
			t.Errorf("trace lacks %q (EADDRNOTAVAIL):\n%s", want, arm.trace)
		}
	})

	// The C and Go sides must agree on which (address, range) pairs are
	// usable. Every input here is canonical (masked, inside 169.254.0.0/16),
	// the only shape InterconnectEnv emits, so Go's verdict on it and the
	// shim's verdict on the same strings must match exactly.
	t.Run("the shim and InterconnectEnv agree", func(t *testing.T) {
		pairs := []struct{ ip, cidrs string }{
			{icTestIP, icRange},
			{"169.254.0.1", icRange},
			{"169.254.0.254", icRange},
			{"169.254.0.0", icRange},
			{"169.254.0.255", icRange},
			{"169.254.0.255", "169.254.0.0/16,169.254.0.0/24"},
			{"169.254.0.11", "169.254.0.8/29,169.254.0.0/24"},
			{"169.254.0.11", "169.254.0.11/32"},
			{"169.254.0.10", "169.254.0.10/31"},
			{"169.254.9.209", icRange},
		}
		for _, pr := range pairs {
			var cidrs []netip.Prefix
			for _, c := range strings.Split(pr.cidrs, ",") {
				cidrs = append(cidrs, netip.MustParsePrefix(c))
			}
			goOK := InterconnectEnv(netip.MustParseAddr(pr.ip), cidrs) != nil
			arm := run(t, true, append(cloneEnv(podEnv), EnvInterconnectIP+"="+pr.ip, EnvInterconnectCIDRs+"="+pr.cidrs)...)
			cOK := strings.Contains(arm.trace, icScopeAccepted)
			if goOK != cOK {
				t.Errorf("%s in %s: InterconnectEnv accepts=%v, shim accepts=%v\n%s", pr.ip, pr.cidrs, goOK, cOK, arm.trace)
			}
		}
	})

	t.Run("inert/no pod IP", func(t *testing.T) {
		arm := run(t, true, append([]string{"K3SM_CLUSTER_CIDRS=" + icTestClusterNet}, icEnv...)...)
		for c := range control.cases {
			if got, want := arm.local(c), control.local(c); got != want {
				t.Errorf("case %s sourced %s, want the un-shimmed %s", c, got, want)
			}
		}
	})
}

// cloneEnv returns a copy of s so an append onto it never aliases the original.
func cloneEnv(s []string) []string { return append([]string(nil), s...) }
