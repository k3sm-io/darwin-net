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
	"net/netip"
	"slices"
	"testing"
)

// TestMeshEgressAliasedOntoUTUN pins B453's fix for the node's own mesh-egress
// address: bring-up aliases it on lo0 (its home, whose host route keeps a local
// dial on loopback) and then on the utun as a point-to-point /32 whose
// destination is the utun's own link address, so a reply the kernel generates
// for a packet that arrived on the utun has a source on that interface; teardown
// takes the utun alias before the lo0 one. The device issues no route operation
// for either.
func TestMeshEgressAliasedOntoUTUN(t *testing.T) {
	rec := &commandRecorder{}
	rt := &fakeRouteTable{}
	d := newWGDevice(wgLink{
		name:       "utun",
		mtu:        MTU,
		meshIP:     netip.MustParseAddr("100.64.3.1"),
		linkIP:     netip.MustParseAddr("100.64.3.255"),
		listenPort: DefaultListenPort,
	}, discardLogger())
	d.command = rec.run
	d.rt = rt
	ctx := context.Background()

	if err := d.plumb(ctx, "utun7"); err != nil {
		t.Fatalf("plumb: %v", err)
	}
	wantUp := [][]string{
		{"ifconfig", "utun7", "inet", "100.64.3.255", "100.64.3.255", "netmask", "255.255.255.255", "up"},
		{"ifconfig", "lo0", "alias", "100.64.3.1/32"},
		{"ifconfig", "utun7", "inet", "100.64.3.1", "100.64.3.255", "netmask", "255.255.255.255", "alias"},
	}
	if up := rec.take(); !slices.EqualFunc(up, wantUp, slices.Equal[[]string]) {
		t.Fatalf("bring-up commands = %q, want %q", up, wantUp)
	}

	d.iface = "utun7"
	if err := d.Down(ctx); err != nil {
		t.Fatalf("Down: %v", err)
	}
	wantDown := [][]string{
		{"pfctl", "-a", "io.k3sm.mesh", "-F", "all"},
		{"ifconfig", "utun7", "inet", "100.64.3.1", "-alias"},
		{"ifconfig", "lo0", "-alias", "100.64.3.1"},
	}
	if down := rec.take(); !slices.EqualFunc(down, wantDown, slices.Equal[[]string]) {
		t.Fatalf("teardown commands = %q, want %q", down, wantDown)
	}
	if len(rt.ops) != 0 {
		t.Fatalf("the alias plumbing made route operations %q, want none", rt.ops)
	}
}
