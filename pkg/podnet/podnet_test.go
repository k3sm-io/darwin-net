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
	"context"
	"errors"
	"net/netip"
	"testing"
)

// newTestNetwork builds a Network over a fixed /24 with the rootless fake alias
// manager, returning both so tests can assert the Ensure/Remove sequence.
func newTestNetwork(t *testing.T) (*Network, *fakeAliasManager) {
	t.Helper()
	fake := newFakeAliasManager()
	n, err := New(netip.MustParsePrefix("100.64.0.0/24"), withAliasManager(fake))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return n, fake
}

// TestEnsureNodeAlias covers the node's OWN lo0 alias (the mesh-egress .1 the VK
// node advertises as its NodeInternalIP so the apiserver node-proxy can dial
// :10250 for `kubectl top node`): EnsureNodeAlias plumbs it, is idempotent, and —
// critically — it survives a full stale-sweep because .1 lies outside the swept
// pod range [.2, .254]. The sweep-survival leg is the regression guard for the
// property the kubectl-top fix relies on (a reaped node alias would make top-node
// fail intermittently moments after boot).
func TestEnsureNodeAlias(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()

	nodeIP, err := MeshEgressIP(n.CIDR())
	if err != nil {
		t.Fatalf("MeshEgressIP: %v", err)
	}
	if want := netip.MustParseAddr("100.64.0.1"); nodeIP != want {
		t.Fatalf("MeshEgressIP = %s, want %s (the node's advertised NodeInternalIP)", nodeIP, want)
	}

	if err := n.EnsureNodeAlias(ctx, nodeIP); err != nil {
		t.Fatalf("EnsureNodeAlias: %v", err)
	}
	if got := fake.ensures(nodeIP); got != 1 {
		t.Errorf("ensures(%s) = %d, want 1", nodeIP, got)
	}

	// Idempotent: a startup reconcile may re-ensure it every boot; still one live alias.
	if err := n.EnsureNodeAlias(ctx, nodeIP); err != nil {
		t.Fatalf("EnsureNodeAlias (idempotent re-ensure): %v", err)
	}
	if got := fake.liveAliases(); got != 1 {
		t.Errorf("liveAliases = %d after re-ensure, want 1", got)
	}

	// A full stale-sweep must NOT reclaim the reserved .1 (it is outside [.2, .254]).
	if err := n.SweepStale(ctx, nil); err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if got := fake.removes(nodeIP); got != 0 {
		t.Errorf("removes(%s) = %d after SweepStale, want 0 — the reserved .1 must be outside the swept range", nodeIP, got)
	}
	if got := fake.liveAliases(); got != 1 {
		t.Errorf("liveAliases = %d after SweepStale, want 1 — the node .1 alias must survive the sweep", got)
	}
}

// TestNetworkSetupAllocatesAndAliases maps to acceptance M2.1-a2 (rootless leg):
// Setup returns a bindable IP inside the node /24 and ensures exactly one lo0
// alias for it; the IP is recorded for the pod.
func TestNetworkSetupAllocatesAndAliases(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()

	ip, err := n.Setup(ctx, "pod-a")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !n.CIDR().Contains(ip) {
		t.Fatalf("Setup returned %s outside node CIDR %s", ip, n.CIDR())
	}
	if got := fake.ensures(ip); got != 1 {
		t.Fatalf("Ensure called %d times for %s, want 1", got, ip)
	}
	if recorded, ok := n.IP("pod-a"); !ok || recorded != ip {
		t.Fatalf("IP(pod-a) = %s,%v, want %s,true", recorded, ok, ip)
	}
	if got := n.Pods(); got != 1 {
		t.Fatalf("Pods = %d, want 1", got)
	}
}

// TestNetworkSetupIdempotent maps to acceptance M2.1-a2: a repeated Setup for the
// same pod returns the same IP and allocates no second address (a retried sandbox
// creation must not leak). The alias is re-ensured (idempotent) on the retry.
func TestNetworkSetupIdempotent(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()

	first, err := n.Setup(ctx, "pod-a")
	if err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	second, err := n.Setup(ctx, "pod-a")
	if err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if first != second {
		t.Fatalf("idempotent Setup returned %s then %s", first, second)
	}
	if got := n.alloc.InUse(); got != 1 {
		t.Fatalf("InUse = %d after idempotent Setup, want 1 (no second allocation)", got)
	}
	if got := fake.ensures(first); got != 2 {
		t.Fatalf("Ensure called %d times, want 2 (re-ensured on retry)", got)
	}
	if got := n.Pods(); got != 1 {
		t.Fatalf("Pods = %d, want 1", got)
	}
}

// TestNetworkDistinctPodsDistinctIPs proves two pods get two different addresses.
func TestNetworkDistinctPodsDistinctIPs(t *testing.T) {
	n, _ := newTestNetwork(t)
	ctx := context.Background()

	a, err := n.Setup(ctx, "pod-a")
	if err != nil {
		t.Fatalf("Setup pod-a: %v", err)
	}
	b, err := n.Setup(ctx, "pod-b")
	if err != nil {
		t.Fatalf("Setup pod-b: %v", err)
	}
	if a == b {
		t.Fatalf("two pods got the same IP %s", a)
	}
	if got := n.Pods(); got != 2 {
		t.Fatalf("Pods = %d, want 2", got)
	}
}

// TestNetworkTeardownReleasesAndRemoves maps to acceptance M2.1-a2: Teardown
// removes the lo0 alias, releases the IP back to the pool, and forgets the pod —
// and the released address becomes reusable.
func TestNetworkTeardownReleasesAndRemoves(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()

	ip, err := n.Setup(ctx, "pod-a")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := n.Teardown(ctx, "pod-a"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := fake.removes(ip); got != 1 {
		t.Fatalf("Remove called %d times for %s, want 1", got, ip)
	}
	if _, ok := n.IP("pod-a"); ok {
		t.Fatalf("pod-a still has an IP after Teardown")
	}
	if n.alloc.Allocated(ip) {
		t.Fatalf("%s not released to the pool after Teardown", ip)
	}
	if got := n.Pods(); got != 0 {
		t.Fatalf("Pods = %d after Teardown, want 0", got)
	}
	if got := fake.liveAliases(); got != 0 {
		t.Fatalf("alias leak: %d live aliases after Teardown", got)
	}
}

// TestNetworkTeardownIdempotentLeakFree maps to acceptance M2.1-a2 (leak-free):
// tearing down an unknown pod, or the same pod twice, is a no-op success — the
// crash-recovery reconcile path.
func TestNetworkTeardownIdempotentLeakFree(t *testing.T) {
	n, _ := newTestNetwork(t)
	ctx := context.Background()

	// Never-set-up pod: no-op success.
	if err := n.Teardown(ctx, "ghost"); err != nil {
		t.Fatalf("Teardown of unknown pod: %v", err)
	}

	if _, err := n.Setup(ctx, "pod-a"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := n.Teardown(ctx, "pod-a"); err != nil {
		t.Fatalf("first Teardown: %v", err)
	}
	if err := n.Teardown(ctx, "pod-a"); err != nil {
		t.Fatalf("second Teardown (idempotent): %v", err)
	}
}

// TestNetworkSetupTeardownChurnLeakFree maps to acceptance M2.1-a2 (leak-free
// under churn): repeated Setup/Teardown cycles never leak an IP or an alias, and
// the pool always returns to empty.
func TestNetworkSetupTeardownChurnLeakFree(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()

	for cycle := 0; cycle < 100; cycle++ {
		ids := []string{"p0", "p1", "p2", "p3"}
		for _, id := range ids {
			if _, err := n.Setup(ctx, id); err != nil {
				t.Fatalf("cycle %d Setup %s: %v", cycle, id, err)
			}
		}
		if got := n.Pods(); got != len(ids) {
			t.Fatalf("cycle %d Pods = %d, want %d", cycle, got, len(ids))
		}
		for _, id := range ids {
			if err := n.Teardown(ctx, id); err != nil {
				t.Fatalf("cycle %d Teardown %s: %v", cycle, id, err)
			}
		}
		if got := n.Pods(); got != 0 {
			t.Fatalf("cycle %d Pods after teardown = %d, want 0", cycle, got)
		}
		if got := n.alloc.InUse(); got != 0 {
			t.Fatalf("cycle %d allocator InUse = %d after teardown, want 0 — IP leak", cycle, got)
		}
	}
	if got := fake.liveAliases(); got != 0 {
		t.Fatalf("alias leak after churn: %d live aliases", got)
	}
}

// TestNetworkSetupRollsBackOnAliasFailure proves a failed alias plumb releases the
// freshly allocated IP so a failed Setup leaks nothing.
func TestNetworkSetupRollsBackOnAliasFailure(t *testing.T) {
	failer := &failingAliasManager{}
	n, err := New(netip.MustParsePrefix("100.64.0.0/24"), withAliasManager(failer))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := n.Setup(context.Background(), "pod-a"); err == nil {
		t.Fatal("Setup succeeded despite alias failure")
	}
	if got := n.alloc.InUse(); got != 0 {
		t.Fatalf("allocator InUse = %d after failed Setup, want 0 — IP leaked on alias failure", got)
	}
	if got := n.Pods(); got != 0 {
		t.Fatalf("Pods = %d after failed Setup, want 0", got)
	}
}

// TestNetworkEmptyPodID rejects an empty pod id on both Setup and Teardown.
func TestNetworkEmptyPodID(t *testing.T) {
	n, _ := newTestNetwork(t)
	ctx := context.Background()
	if _, err := n.Setup(ctx, ""); !errors.Is(err, ErrEmptyPodID) {
		t.Fatalf("Setup(\"\") err = %v, want ErrEmptyPodID", err)
	}
	if err := n.Teardown(ctx, ""); !errors.Is(err, ErrEmptyPodID) {
		t.Fatalf("Teardown(\"\") err = %v, want ErrEmptyPodID", err)
	}
}

// failingAliasManager always fails Ensure, to exercise the Setup rollback path.
type failingAliasManager struct{}

func (failingAliasManager) Ensure(context.Context, netip.Addr) error {
	return errors.New("ifconfig alias failed (test)")
}

func (failingAliasManager) Remove(context.Context, netip.Addr) error { return nil }
