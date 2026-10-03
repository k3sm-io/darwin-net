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

// The pod-alias blackhole against the live routing table. It mutates lo0 and the
// kernel routing table and therefore requires root; run with:
//
//	sudo CGO_ENABLED=0 go test -tags integration -run '^TestAliasTeardownBlackholeLive$' ./pkg/podnet/

package podnet

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

// routeGetFlags returns the flags line `route -n get <ip>` prints. The test reads
// the table through route(8), independently of the routing-socket code under test.
func routeGetFlags(t *testing.T, ip netip.Addr) string {
	t.Helper()
	out, err := exec.Command("route", "-n", "get", ip.String()).CombinedOutput()
	if err != nil {
		// No route at all (no default route on the host) is reported as an error.
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f, ok := strings.CutPrefix(strings.TrimSpace(line), "flags:"); ok {
			return strings.TrimSpace(f)
		}
	}
	return ""
}

// TestAliasTeardownBlackholeLive drives the real lo0 alias manager on a TEST-NET
// address standing in for a pod of the node /24: Remove leaves a blackhole host
// route behind the alias, the next Ensure clears it before re-aliasing, and the
// final teardown's blackhole is cleared by the cleanup.
func TestAliasTeardownBlackholeLive(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	node := netip.MustParsePrefix("192.0.2.0/24")
	ip := netip.MustParseAddr("192.0.2.77")
	mgr := newLo0AliasManager(node)
	t.Cleanup(func() {
		_ = mgr.Remove(ctx, ip)
		if err := (BlackholeRoutes{}).Clear(ctx, ip); err != nil {
			t.Errorf("cleanup: clear blackhole: %v", err)
		}
	})

	if lo0HasAddr(t, ip) {
		t.Fatalf("precondition: %s already on lo0", ip)
	}
	if err := mgr.Ensure(ctx, ip); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !lo0HasAddr(t, ip) {
		t.Fatalf("%s not on lo0 after Ensure", ip)
	}
	if err := mgr.Remove(ctx, ip); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if lo0HasAddr(t, ip) {
		t.Fatalf("%s still on lo0 after Remove", ip)
	}
	if f := routeGetFlags(t, ip); !strings.Contains(f, "BLACKHOLE") || !strings.Contains(f, "HOST") {
		t.Fatalf("route -n get %s flags = %q after Remove, want a BLACKHOLE host route", ip, f)
	}
	if err := mgr.Remove(ctx, ip); err != nil {
		t.Fatalf("re-Remove: %v (must be idempotent)", err)
	}

	if err := mgr.Ensure(ctx, ip); err != nil {
		t.Fatalf("re-Ensure: %v", err)
	}
	if !lo0HasAddr(t, ip) {
		t.Fatalf("%s not on lo0 after re-Ensure", ip)
	}
	if f := routeGetFlags(t, ip); strings.Contains(f, "BLACKHOLE") {
		t.Fatalf("route -n get %s flags = %q after re-Ensure, want the blackhole cleared", ip, f)
	}
}
