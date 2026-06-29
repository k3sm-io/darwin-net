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

package mesh

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// fakeDevice is the rootless Device unit tests inject: it performs no syscalls and
// records the plans Apply received (and the Up/Down lifecycle) so a test can assert
// the controller reconciled the right state. It mirrors the proxy/podnet fake-seam
// pattern.
//
// Locking discipline: all state is guarded by mu; the Device methods and the test
// accessors take it.
type fakeDevice struct {
	mu      sync.Mutex
	ups     int
	downs   int
	applied []Plan
}

func (f *fakeDevice) Up(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ups++
	return nil
}

func (f *fakeDevice) Apply(_ context.Context, p Plan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, p)
	return nil
}

func (f *fakeDevice) Down(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downs++
	return nil
}

func (f *fakeDevice) applyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func (f *fakeDevice) last() Plan {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied[len(f.applied)-1]
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestMeshNewDerivesMeshIP proves New derives the reserved mesh-egress source from
// the node podCIDR and rejects a non-/24.
func TestMeshNewDerivesMeshIP(t *testing.T) {
	m, err := New(netip.MustParsePrefix("100.64.5.0/24"), withDevice(&fakeDevice{}), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.MeshIP().String(); got != "100.64.5.1" {
		t.Fatalf("MeshIP = %s, want 100.64.5.1", got)
	}
	if got := m.CIDR().String(); got != "100.64.5.0/24" {
		t.Fatalf("CIDR = %s, want 100.64.5.0/24", got)
	}
	for _, bad := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/25"),
		netip.MustParsePrefix("fd00::/24"),
	} {
		if _, err := New(bad, withDevice(&fakeDevice{})); err == nil {
			t.Fatalf("New(%s) succeeded, want ErrSelfCIDR", bad)
		}
	}
}

// TestMeshReconcileEndpointChange is the M3.1 acceptance for continuous reconcile:
// a peer's endpoint change is reconciled (the applied config carries the new
// endpoint), not ignored after the initial read. It drives the controller twice
// with the same peer at two endpoints and asserts the device's last-applied plan
// reflects the move — the reconcile is re-driven, not one-shot.
func TestMeshReconcileEndpointChange(t *testing.T) {
	const (
		ep1 = "192.0.2.10:51820"
		ep2 = "198.51.100.20:51820"
	)
	fake := &fakeDevice{}
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(fake), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if fake.ups != 1 {
		t.Fatalf("device Up called %d times, want 1", fake.ups)
	}

	// Initial reconcile: peer B at endpoint ep1.
	if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{peerSpec("nodeB", "100.64.1.0/24", ep1, 0x42)}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	first := fake.last()
	if len(first.Peers) != 1 || first.Peers[0].Endpoint != ep1 {
		t.Fatalf("after first reconcile, peer endpoint = %+v, want %s", first.Peers, ep1)
	}

	// The peer roams: same node, new endpoint. The reconcile must re-apply it.
	if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{peerSpec("nodeB", "100.64.1.0/24", ep2, 0x42)}); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if got := fake.applyCount(); got != 2 {
		t.Fatalf("Apply called %d times, want 2 (the endpoint change was not ignored)", got)
	}
	last := fake.last()
	if len(last.Peers) != 1 || last.Peers[0].Endpoint != ep2 {
		t.Fatalf("after endpoint change, peer endpoint = %+v, want %s (reconverged, not stuck at %s)", last.Peers, ep2, ep1)
	}
	if uapi := last.UAPI(); !strings.Contains(uapi, "endpoint="+ep2) || strings.Contains(uapi, "endpoint="+ep1) {
		t.Fatalf("applied UAPI did not move to the new endpoint:\n%s", uapi)
	}
	// The route set is unchanged by an endpoint move (still the peer's /24).
	if len(last.Routes) != 1 || last.Routes[0].String() != "100.64.1.0/24" {
		t.Fatalf("routes after endpoint change = %v, want [100.64.1.0/24]", last.Routes)
	}

	if err := m.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fake.downs != 1 {
		t.Fatalf("device Down called %d times, want 1", fake.downs)
	}
}
