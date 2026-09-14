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
	"errors"
	"net/netip"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// fakeWG records the UAPI writes the applier makes, standing in for the
// wireguard-go device handle behind the wgControl seam. No utun, no wireguard.
type fakeWG struct {
	sets   []string
	setErr error
}

func (f *fakeWG) IpcSet(uapi string) error {
	f.sets = append(f.sets, uapi)
	return f.setErr
}
func (f *fakeWG) Up() error { return nil }
func (f *fakeWG) Close()    {}

// applierDevice returns a WGDevice that is "up" on a fake wireguard handle and a
// fake kernel route table, so Apply can be driven end to end without privilege.
func applierDevice(t *testing.T) (*WGDevice, *fakeWG, *fakeRouteTable) {
	t.Helper()
	rt := &fakeRouteTable{}
	d := routeDevice(rt)
	wg := &fakeWG{}
	d.dev = wg
	return d, wg, rt
}

func peerPlan(t *testing.T, endpoint string) Plan {
	t.Helper()
	self := netip.MustParsePrefix("100.64.0.0/24")
	plan, err := BuildPlan(self, []netv1.MeshPeerSpec{peerSpec("nodeB", "100.64.1.0/24", endpoint, 0x42)})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Peers) != 1 || len(plan.Skipped) != 0 {
		t.Fatalf("plan = %d peers, %d skipped, want 1 and 0", len(plan.Peers), len(plan.Skipped))
	}
	return plan
}

// TestApplySkipsTheUAPIWriteWhenNothingChanged pins the IpcSet side of the
// reconcile fan-out: the periodic resync re-applies an unchanged snapshot every
// meshResyncPeriod, and that must not be a wireguard write every time. The
// endpoint-roaming contract decides what the update SAYS (Plan.UAPIUpdate,
// unchanged here); this pins whether an update that says exactly what the last
// accepted one said is written at all.
//
// Fails-before: Apply called IpcSet unconditionally, so a quiet two-node cluster
// re-programmed every peer's AllowedIPs and keepalive every 30s.
func TestApplySkipsTheUAPIWriteWhenNothingChanged(t *testing.T) {
	ctx := context.Background()
	d, wg, rt := applierDevice(t)
	plan := peerPlan(t, "192.0.2.10:51820")

	// First apply after Up: a full replace that programs the CR endpoint.
	if err := d.Apply(ctx, plan); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if len(wg.sets) != 1 || !strings.Contains(wg.sets[0], "replace_peers=true\n") || !strings.Contains(wg.sets[0], "endpoint=192.0.2.10:51820\n") {
		t.Fatalf("first Apply wrote %q, want one full replace carrying the endpoint", wg.sets)
	}

	// Second apply of the same plan: the first INCREMENTAL update, which reads
	// differently from the full replace (no replace_peers, no endpoint), so it is
	// written once more.
	if err := d.Apply(ctx, plan); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if len(wg.sets) != 2 || strings.Contains(wg.sets[1], "replace_peers") || strings.Contains(wg.sets[1], "endpoint=") {
		t.Fatalf("second Apply wrote %q, want one incremental update without replace_peers or endpoint", wg.sets[1:])
	}

	// Every further apply of the same plan renders that same incremental text, so
	// the periodic resync writes nothing to wireguard.
	for i := 0; i < 3; i++ {
		if err := d.Apply(ctx, plan); err != nil {
			t.Fatalf("resync Apply %d: %v", i, err)
		}
	}
	if got := len(wg.sets); got != 2 {
		t.Fatalf("three resyncs of an unchanged plan drove IpcSet %d times in total, want 2 (the unchanged update must be skipped)", got)
	}

	// The kernel routes are still reconciled on a skipped write: a read-back that
	// fails still fails the apply.
	rt.listErr = errors.New("sysctl: boom")
	if err := d.Apply(ctx, plan); err == nil {
		t.Fatalf("Apply with the route read-back failing returned nil, want an error (routes must be re-verified even when the UAPI write is skipped)")
	}
	rt.listErr = nil
	if got := len(wg.sets); got != 2 {
		t.Fatalf("the route-failed apply drove IpcSet, total %d, want 2", got)
	}

	// A real change — the CR endpoint moves — is written, and carries the endpoint.
	moved := peerPlan(t, "192.0.2.99:51820")
	if err := d.Apply(ctx, moved); err != nil {
		t.Fatalf("Apply after endpoint move: %v", err)
	}
	if len(wg.sets) != 3 || !strings.Contains(wg.sets[2], "endpoint=192.0.2.99:51820\n") {
		t.Fatalf("endpoint move wrote %q, want one update carrying the new endpoint", wg.sets[2:])
	}
	if err := d.Apply(ctx, moved); err != nil {
		t.Fatalf("Apply after endpoint move (resync): %v", err)
	}
	if got := len(wg.sets); got != 4 {
		t.Fatalf("first resync after the move drove IpcSet total %d, want 4 (the post-move incremental text is new once)", got)
	}
	if err := d.Apply(ctx, moved); err != nil {
		t.Fatalf("Apply after endpoint move (second resync): %v", err)
	}
	if got := len(wg.sets); got != 4 {
		t.Fatalf("second resync after the move drove IpcSet total %d, want 4", got)
	}
}

// TestApplyForgetsTheLastWriteWhenItFails: a rejected IpcSet leaves wireguard in
// an unknown state, so the next apply must be a full replace and must be
// written even if it happens to render the same text as the rejected one.
func TestApplyForgetsTheLastWriteWhenItFails(t *testing.T) {
	ctx := context.Background()
	d, wg, _ := applierDevice(t)
	plan := peerPlan(t, "192.0.2.10:51820")
	if err := d.Apply(ctx, plan); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if err := d.Apply(ctx, plan); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	wg.setErr = errors.New("ipc: boom")
	moved := peerPlan(t, "192.0.2.99:51820")
	if err := d.Apply(ctx, moved); err == nil {
		t.Fatalf("Apply with IpcSet failing returned nil, want an error")
	}
	wg.setErr = nil
	if err := d.Apply(ctx, moved); err != nil {
		t.Fatalf("Apply after the failure: %v", err)
	}
	last := wg.sets[len(wg.sets)-1]
	if !strings.Contains(last, "replace_peers=true\n") || !strings.Contains(last, "endpoint=192.0.2.99:51820\n") {
		t.Fatalf("the apply after a failed write wrote %q, want a full replace carrying the endpoint", last)
	}
	if got := len(wg.sets); got != 4 {
		t.Fatalf("IpcSet called %d times, want 4 (full, incremental, rejected, full again)", got)
	}
}
