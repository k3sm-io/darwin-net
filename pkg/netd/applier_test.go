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

package netd

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"
)

// TestDarwinApplierDerivesBothMeshAddresses pins that the helper path programs the
// same two-address datapath the direct path does. The mesh needs BOTH: the
// mesh-egress source on lo0 (bindable by the proxy and the control plane) and the
// utun's own point-to-point link address, without which macOS refuses every
// interface-bound route and no peer route can land. A daemon that derived only the
// first would bring a tunnel up that carries no routes — the defect this pins.
func TestDarwinApplierDerivesBothMeshAddresses(t *testing.T) {
	cidr := netip.MustParsePrefix("100.64.3.0/24")
	a := newDarwinApplier(cidr, quietLogger())

	wantEgress, err := podnet.MeshEgressIP(cidr)
	if err != nil {
		t.Fatalf("MeshEgressIP: %v", err)
	}
	wantLink, err := podnet.MeshLinkIP(cidr)
	if err != nil {
		t.Fatalf("MeshLinkIP: %v", err)
	}
	if a.meshIP != wantEgress {
		t.Errorf("meshIP = %s, want %s", a.meshIP, wantEgress)
	}
	if a.linkIP != wantLink {
		t.Errorf("linkIP = %s, want %s", a.linkIP, wantLink)
	}
	if a.meshIP == a.linkIP {
		t.Errorf("the daemon derived one address for both roles (%s): an address on the utun is reached over the utun, so the mesh IP would stop being loopback-dialable", a.meshIP)
	}
}

// TestDarwinApplierRefusesMeshWithoutBothAddresses pins the fail-fast: a node whose
// podCIDR cannot yield the pair never brings a route-less tunnel up. It performs no
// privileged operation, so it runs in the unit pass.
func TestDarwinApplierRefusesMeshWithoutBothAddresses(t *testing.T) {
	a := newDarwinApplier(netip.MustParsePrefix("100.64.0.0/16"), quietLogger())
	err := a.ConfigureMesh(context.Background(), "", mesh.DefaultListenPort, mesh.Plan{})
	if err == nil {
		t.Fatal("ConfigureMesh accepted a node podCIDR that yields no mesh addresses")
	}
	if !strings.Contains(err.Error(), "100.64.0.0/16") {
		t.Errorf("error %q does not name the offending podCIDR", err)
	}
}

// quietLogger is a logger the applier tests can pass without emitting output. The
// package's other tests live in netd_test and cannot share it.
func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
