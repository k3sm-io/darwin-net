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
	"maps"
	"net/netip"
	"strings"
	"sync"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// keyHex is the hex (UAPI) form of the deterministic test key for seed, the form
// AppliedEndpoints and the rendered UAPI both key peers by.
func keyHex(t *testing.T, seed byte) string {
	t.Helper()
	h, err := wgKeyHex(wgKeyB64(seed))
	if err != nil {
		t.Fatalf("wgKeyHex(seed %#x): %v", seed, err)
	}
	return h
}

// planFor builds the plan a reconcile would apply for the given peer specs, from
// the fixed test node /24.
func planFor(t *testing.T, peers ...netv1.MeshPeerSpec) Plan {
	t.Helper()
	plan, err := BuildPlan(netip.MustParsePrefix("100.64.0.0/24"), peers)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Skipped) != 0 {
		t.Fatalf("BuildPlan skipped peers the test expected to be programmable: %+v", plan.Skipped)
	}
	return plan
}

// TestPlanUAPIUpdateEndpointRoamingSemantics is the table-driven contract for the
// endpoint-roaming fix: the CR endpoint is programmed when the peer is NEW to the
// device, when its KEY changed, or when the CR endpoint itself CHANGED from the
// value the applier last wrote — and in no other case, because wireguard owns the
// endpoint once the peer has been heard from. AllowedIPs, keepalives and removals
// keep reconciling unconditionally.
func TestPlanUAPIUpdateEndpointRoamingSemantics(t *testing.T) {
	const (
		crEP    = "192.0.2.10:51820"
		movedEP = "198.51.100.20:51820"
		peerB   = "100.64.1.0/24"
		peerC   = "100.64.2.0/24"
	)
	keyB := keyHex(t, 0x42)
	keyC := keyHex(t, 0x43)
	keyBRotated := keyHex(t, 0x44)

	specB := peerSpec("nodeB", peerB, crEP, 0x42)
	specBMoved := peerSpec("nodeB", peerB, movedEP, 0x42)
	specBRotated := peerSpec("nodeB", peerB, crEP, 0x44)
	specC := peerSpec("nodeC", peerC, crEP, 0x43)
	// The CRD requires an endpoint (a MeshPeer without one is skipped by BuildPlan),
	// so the endpoint-less peer is built as a Plan directly: it exercises the
	// defensive branch that never emits an empty "endpoint=" line.
	planNoEP := Plan{Peers: []PeerConfig{{
		NodeName:         "nodeB",
		PublicKeyHex:     keyB,
		AllowedIPs:       []netip.Prefix{netip.MustParsePrefix(peerB)},
		KeepaliveSeconds: PersistentKeepaliveSeconds,
	}}}

	tests := []struct {
		name       string
		prev       AppliedEndpoints
		plan       Plan
		want       []string
		notWant    []string
		wantApplie AppliedEndpoints
	}{
		{
			name: "new peer on a fresh device is fully programmed",
			prev: nil,
			plan: planFor(t, specB),
			want: []string{
				"replace_peers=true\n",
				"public_key=" + keyB + "\n",
				"endpoint=" + crEP + "\n",
				"persistent_keepalive_interval=25\n",
				"allowed_ip=100.64.1.0/24\n",
			},
			wantApplie: AppliedEndpoints{keyB: crEP},
		},
		{
			name: "unchanged peer keeps the endpoint wireguard owns",
			prev: AppliedEndpoints{keyB: crEP},
			plan: planFor(t, specB),
			want: []string{
				"public_key=" + keyB + "\n",
				"allowed_ip=100.64.1.0/24\n",
				"persistent_keepalive_interval=25\n",
			},
			notWant:    []string{"endpoint=", "replace_peers=true", "remove=true"},
			wantApplie: AppliedEndpoints{keyB: crEP},
		},
		{
			name:       "changed CR endpoint is applied (the operator moved the node)",
			prev:       AppliedEndpoints{keyB: crEP},
			plan:       planFor(t, specBMoved),
			want:       []string{"public_key=" + keyB + "\n", "endpoint=" + movedEP + "\n"},
			notWant:    []string{"endpoint=" + crEP, "replace_peers=true"},
			wantApplie: AppliedEndpoints{keyB: movedEP},
		},
		{
			name: "key rotation removes the old peer and programs the new one",
			prev: AppliedEndpoints{keyB: crEP},
			plan: planFor(t, specBRotated),
			want: []string{
				"public_key=" + keyB + "\nremove=true\n",
				"public_key=" + keyBRotated + "\n",
				"endpoint=" + crEP + "\n",
			},
			notWant:    []string{"replace_peers=true"},
			wantApplie: AppliedEndpoints{keyBRotated: crEP},
		},
		{
			name:       "an added peer is programmed while the existing one is left alone",
			prev:       AppliedEndpoints{keyB: crEP},
			plan:       planFor(t, specB, specC),
			want:       []string{"public_key=" + keyC + "\nendpoint=" + crEP + "\n"},
			notWant:    []string{"public_key=" + keyB + "\nendpoint=", "replace_peers=true"},
			wantApplie: AppliedEndpoints{keyB: crEP, keyC: crEP},
		},
		{
			name:       "a departed peer is removed",
			prev:       AppliedEndpoints{keyB: crEP, keyC: crEP},
			plan:       planFor(t, specB),
			want:       []string{"public_key=" + keyC + "\nremove=true\n"},
			notWant:    []string{"endpoint=", "replace_peers=true"},
			wantApplie: AppliedEndpoints{keyB: crEP},
		},
		{
			name:       "a new peer with no CR endpoint gets none (it must call us first)",
			prev:       nil,
			plan:       planNoEP,
			want:       []string{"public_key=" + keyB + "\n", "allowed_ip=100.64.1.0/24\n"},
			notWant:    []string{"endpoint="},
			wantApplie: AppliedEndpoints{keyB: ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := maps.Clone(tc.prev)
			uapi, next := tc.plan.UAPIUpdate(tc.prev)
			for _, w := range tc.want {
				if !strings.Contains(uapi, w) {
					t.Errorf("UAPI missing %q in:\n%s", w, uapi)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(uapi, w) {
					t.Errorf("UAPI must not contain %q, got:\n%s", w, uapi)
				}
			}
			if !maps.Equal(next, tc.wantApplie) {
				t.Errorf("applied endpoints = %v, want %v", next, tc.wantApplie)
			}
			if !maps.Equal(tc.prev, before) {
				t.Errorf("UAPIUpdate mutated the caller's previous state: %v, want %v", tc.prev, before)
			}
		})
	}
}

// uapiDevice is the fake Device that renders each applied plan exactly as the real
// wireguard device does — through Plan.UAPIUpdate against its own memory of what
// it last programmed — and records the resulting UAPI text. It is the seam the
// stomp regression is asserted on: the Plan always carries the CR endpoint, so the
// question "was the endpoint re-stamped?" is only answerable at the render.
//
// Locking discipline: all state is guarded by mu.
type uapiDevice struct {
	mu      sync.Mutex
	applied AppliedEndpoints
	writes  []string
}

func (f *uapiDevice) Up(context.Context) error { return nil }

func (f *uapiDevice) Apply(_ context.Context, p Plan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	uapi, next := p.UAPIUpdate(f.applied)
	f.applied = next
	f.writes = append(f.writes, uapi)
	return nil
}

func (f *uapiDevice) Down(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = nil
	return nil
}

func (f *uapiDevice) lastWrite() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes[len(f.writes)-1]
}

// TestMeshReconcileDoesNotStompRoamedEndpoint is the regression gate for the
// two-Mac lab defect: the handshake completes and wireguard roams the peer's
// endpoint to its real underlay source, then the periodic reconcile re-applies the
// MeshPeer CR's (wrong, unreachable) endpoint and every reply after it blackholes.
// It drives Mesh.Reconcile twice with the SAME stale CR endpoint — exactly what
// the 30s resync does — and asserts the second write carries no endpoint at all,
// and no replace_peers (which would delete and re-create the peer, discarding the
// roam and the session just as surely).
func TestMeshReconcileDoesNotStompRoamedEndpoint(t *testing.T) {
	// The endpoint the worker publishes on its MeshPeer is its own mesh IP: routable
	// only through the very tunnel it is meant to bring up, so a reply sent there
	// after a reconcile goes nowhere.
	const staleCREndpoint = "100.64.1.1:51820"

	dev := &uapiDevice{}
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(dev), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	peer := peerSpec("nodeB", "100.64.1.0/24", staleCREndpoint, 0x42)

	// First reconcile: the peer is new to the device, so the CR endpoint is the
	// only hint available for making first contact and IS programmed.
	if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{peer}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if first := dev.lastWrite(); !strings.Contains(first, "endpoint="+staleCREndpoint+"\n") {
		t.Fatalf("first apply did not program the CR endpoint (first contact would be impossible):\n%s", first)
	}

	// The peer handshakes; wireguard roams its endpoint to the real underlay
	// source. The MeshPeer CR is unchanged and still carries the stale endpoint.
	if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{peer}); err != nil {
		t.Fatalf("resync Reconcile: %v", err)
	}
	after := dev.lastWrite()
	if strings.Contains(after, "endpoint=") {
		t.Fatalf("the resync re-stamped the stale CR endpoint over the roamed one (the blackhole):\n%s", after)
	}
	if strings.Contains(after, "replace_peers=true") {
		t.Fatalf("the resync replaced the whole peer set, discarding the roamed endpoint and the session:\n%s", after)
	}
	// The rest of the peer state still reconciles on every pass.
	for _, want := range []string{"public_key=" + keyHex(t, 0x42) + "\n", "allowed_ip=100.64.1.0/24\n"} {
		if !strings.Contains(after, want) {
			t.Fatalf("the resync stopped reconciling %q:\n%s", want, after)
		}
	}
	if err := m.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestWGDeviceForgetsAppliedEndpointsOnDown pins the lifetime coupling that makes
// the suppression safe: the endpoint memory belongs to the wireguard device, not
// to the controller, so a device that goes away (a netd restart drops the utun and
// every peer with it) forgets what it programmed and the next apply re-programs
// every CR endpoint. Were the memory held above the device, the post-restart
// resync would suppress every endpoint and the mesh would never come back up.
// Down on a never-upped device performs no privileged operation.
func TestWGDeviceForgetsAppliedEndpointsOnDown(t *testing.T) {
	d := newWGDevice(wgLink{name: "utun", mtu: MTU, mss: MSSClamp, listenPort: DefaultListenPort}, discardLogger())
	d.applied = AppliedEndpoints{keyHex(t, 0x42): "192.0.2.10:51820"}
	if err := d.Down(context.Background()); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if len(d.applied) != 0 {
		t.Fatalf("applied endpoints survived Down: %v (a re-created device would never be re-programmed)", d.applied)
	}
}
