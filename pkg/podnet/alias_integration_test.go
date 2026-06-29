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

// Integration tests for the real lo0 alias manager and the PodNetwork seam against
// the live loopback interface. These touch lo0 via ifconfig and therefore require
// root; run with:
//
//	sudo CGO_ENABLED=0 go test -tags integration -run 'TestLo0|TestPodNetwork' ./pkg/podnet/
//
// They are excluded from the default (rootless) unit build, where the seam is
// exercised with the fake alias manager and the pure allocator.
package podnet

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// requireRoot skips the test when not effectively root (ifconfig alias needs it).
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to manage lo0 aliases; run under sudo with -tags integration")
	}
}

// lo0HasAddr reports whether ip is currently present on lo0.
func lo0HasAddr(t *testing.T, ip netip.Addr) bool {
	t.Helper()
	out, err := exec.Command("ifconfig", "lo0").CombinedOutput()
	if err != nil {
		t.Fatalf("ifconfig lo0: %v: %s", err, out)
	}
	return strings.Contains(string(out), "inet "+ip.String()+" ")
}

// TestLo0AliasIdempotentLeakFree maps to acceptance M2.1-a2: lo0 alias
// create/teardown is idempotent and leak-free. It Ensures the same address twice
// (idempotent create), confirms it is present on lo0, Removes it twice (idempotent
// + leak-free teardown), and confirms it is gone. Mirrors the proxy's identical
// assertion for the IPAM alias seam.
func TestLo0AliasIdempotentLeakFree(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	mgr := newLo0AliasManager()
	// An address unlikely to collide with anything real on the host.
	ip := netip.MustParseAddr("127.0.0.151")

	t.Cleanup(func() { _ = mgr.Remove(ctx, ip) })

	if lo0HasAddr(t, ip) {
		t.Fatalf("precondition: %s already on lo0", ip)
	}

	if err := mgr.Ensure(ctx, ip); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if err := mgr.Ensure(ctx, ip); err != nil {
		t.Fatalf("second Ensure (idempotent): %v", err)
	}
	if !lo0HasAddr(t, ip) {
		t.Fatalf("%s not present on lo0 after Ensure", ip)
	}

	if err := mgr.Remove(ctx, ip); err != nil {
		t.Fatalf("first Remove: %v", err)
	}
	if err := mgr.Remove(ctx, ip); err != nil {
		t.Fatalf("second Remove (idempotent): %v", err)
	}
	if lo0HasAddr(t, ip) {
		t.Fatalf("%s leaked on lo0 after Remove", ip)
	}
}

// TestLo0AliasChurn hammers create/teardown cycles and asserts no address leaks
// after the churn settles (leak-free under churn).
func TestLo0AliasChurn(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	mgr := newLo0AliasManager()
	ips := []netip.Addr{
		netip.MustParseAddr("127.0.0.161"),
		netip.MustParseAddr("127.0.0.162"),
		netip.MustParseAddr("127.0.0.163"),
	}
	t.Cleanup(func() {
		for _, ip := range ips {
			_ = mgr.Remove(ctx, ip)
		}
	})

	for cycle := 0; cycle < 25; cycle++ {
		for _, ip := range ips {
			if err := mgr.Ensure(ctx, ip); err != nil {
				t.Fatalf("cycle %d Ensure %s: %v", cycle, ip, err)
			}
		}
		for _, ip := range ips {
			if err := mgr.Remove(ctx, ip); err != nil {
				t.Fatalf("cycle %d Remove %s: %v", cycle, ip, err)
			}
		}
	}
	for _, ip := range ips {
		if lo0HasAddr(t, ip) {
			t.Fatalf("%s leaked after churn", ip)
		}
	}
}

// TestPodNetworkSetupTeardownOnRealLo0 is the seam-level integration for
// acceptance M2.1-a2: Network.Setup plumbs a real lo0 alias and returns a bindable
// IP (a process can bind it), Teardown removes it, and the whole cycle leaks no
// alias. It drives the production Network with the real lo0AliasManager over a
// loopback test CIDR (127.0.0.0/24) so the assertion does not depend on the host's
// pod CIDR; the production path is identical for a 100.64.x node CIDR.
func TestPodNetworkSetupTeardownOnRealLo0(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()

	// 127.0.0.0/24 is a safe loopback test block (hosts .1 through .254). The
	// returned IP is the first free host the allocator hands out, which we then bind
	// and assert on against the live lo0.
	n, err := New(netip.MustParsePrefix("127.0.0.0/24"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ip, err := n.Setup(ctx, "pod-int")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = n.Teardown(context.Background(), "pod-int") })

	// The returned IP must be aliased on lo0 (give the kernel a moment).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !lo0HasAddr(t, ip) {
		time.Sleep(20 * time.Millisecond)
	}
	if !lo0HasAddr(t, ip) {
		t.Fatalf("Setup did not alias %s on lo0", ip)
	}

	// The returned IP is bindable — the contract runtimed relies on (it binds the
	// pod's process to this source address via IP_BOUND_IF).
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatalf("bind returned pod IP %s: %v", ip, err)
	}
	_ = ln.Close()

	// Idempotent Setup returns the same IP without a second alias.
	again, err := n.Setup(ctx, "pod-int")
	if err != nil {
		t.Fatalf("idempotent Setup: %v", err)
	}
	if again != ip {
		t.Fatalf("idempotent Setup returned %s, want %s", again, ip)
	}

	// Teardown removes the alias (leak-free).
	if err := n.Teardown(ctx, "pod-int"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && lo0HasAddr(t, ip) {
		time.Sleep(20 * time.Millisecond)
	}
	if lo0HasAddr(t, ip) {
		t.Fatalf("%s leaked on lo0 after Teardown", ip)
	}

	// Idempotent Teardown is a no-op success.
	if err := n.Teardown(ctx, "pod-int"); err != nil {
		t.Fatalf("second Teardown (idempotent): %v", err)
	}
}
