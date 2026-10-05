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

// vmTestConfig is the NAT/DNS parameters the fork test composes into a GuestNetwork.
// The NAT subnet/gateway mirror macOS's typical shared-network NAT range; the DNS
// VIP is the cluster kube-dns VIP. They are intended values runtimed reconciles
// against the live attachment (lab-gated) — the test only asserts they round-trip.
var (
	vmNATSubnet = netip.MustParsePrefix("192.168.64.0/24")
	vmGateway   = netip.MustParseAddr("192.168.64.1")
	vmDNSVIP    = netip.MustParseAddr("10.43.0.10")
)

// TestVMPodSelectsVmnetPathAndAliasesPublished asserts both branches of the
// path-selection fork: a vm guest gets a GuestNetwork (the NAT config) AND its
// published /32 aliased on lo0 for the pod's lifetime — the address the node's
// proxy relays from (B440: before it, a vm pod's status.podIP was live on no
// interface and unreachable from anywhere) — while a host-process pod still gets
// exactly one lo0 alias. Teardown removes the alias for both backends, so the
// alias manager installs the address's blackhole for a vm pod exactly as for a
// host-process pod.
func TestVMPodSelectsVmnetPathAndAliasesPublished(t *testing.T) {
	fake := newFakeAliasManager()
	n, err := New(
		netip.MustParsePrefix("100.64.0.0/24"),
		withAliasManager(fake),
		WithVMNetwork(VMNetworkConfig{NATSubnet: vmNATSubnet, Gateway: vmGateway, DNSVIP: vmDNSVIP}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	guest, err := n.SetupGuest(ctx, "vm-pod")
	if err != nil {
		t.Fatalf("SetupGuest: %v", err)
	}
	if !n.CIDR().Contains(guest.PodIP) {
		t.Fatalf("guest PodIP %s outside node CIDR %s", guest.PodIP, n.CIDR())
	}
	if got := fake.ensures(guest.PodIP); got != 1 {
		t.Fatalf("VM pod ensured its published lo0 alias %d times for %s, want 1", got, guest.PodIP)
	}
	if guest.NATSubnet != vmNATSubnet || guest.Gateway != vmGateway || guest.DNSVIP != vmDNSVIP {
		t.Fatalf("GuestNetwork NAT config = {subnet %s gw %s dns %s}, want {subnet %s gw %s dns %s}",
			guest.NATSubnet, guest.Gateway, guest.DNSVIP, vmNATSubnet, vmGateway, vmDNSVIP)
	}
	if got, ok := n.IP("vm-pod"); !ok || got != guest.PodIP {
		t.Fatalf("IP(vm-pod) = %s,%v, want %s,true", got, ok, guest.PodIP)
	}

	hostIP, err := n.Setup(ctx, "host-pod")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := fake.ensures(hostIP); got != 1 {
		t.Fatalf("host-process pod ensured a lo0 alias %d times for %s, want 1", got, hostIP)
	}
	if hostIP == guest.PodIP {
		t.Fatalf("host and vm pods got the same IP %s", hostIP)
	}
	if got := fake.liveAliases(); got != 2 {
		t.Fatalf("live lo0 aliases = %d with one vm and one host pod, want 2", got)
	}

	if err := n.Teardown(ctx, "vm-pod"); err != nil {
		t.Fatalf("Teardown vm-pod: %v", err)
	}
	if got := fake.removes(guest.PodIP); got != 1 {
		t.Fatalf("VM pod teardown removed its lo0 alias %d times for %s, want 1", got, guest.PodIP)
	}
	if n.alloc.Allocated(guest.PodIP) {
		t.Fatalf("VM pod IP %s not released on teardown — IPAM leak", guest.PodIP)
	}

	if err := n.Teardown(ctx, "host-pod"); err != nil {
		t.Fatalf("Teardown host-pod: %v", err)
	}
	if got := fake.removes(hostIP); got != 1 {
		t.Fatalf("host-process pod teardown removed a lo0 alias %d times for %s, want 1", got, hostIP)
	}
	if got := fake.liveAliases(); got != 0 {
		t.Fatalf("alias leak after teardown: %d live", got)
	}
}

// TestSetupGuestAliasFailureReleasesAddress proves a vm pod whose published alias
// cannot be plumbed leaks no address: the allocation is rolled back and a retry
// re-allocates cleanly.
func TestSetupGuestAliasFailureReleasesAddress(t *testing.T) {
	fake := newFakeAliasManager()
	n, err := New(netip.MustParsePrefix("100.64.0.0/24"), withAliasManager(fake))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	fake.failEnsure(errors.New("netd unavailable"))
	if _, err := n.SetupGuest(ctx, "vm-pod"); err == nil {
		t.Fatal("SetupGuest with a failing alias plumb succeeded, want error")
	}
	if got := n.alloc.InUse(); got != 0 {
		t.Fatalf("InUse = %d after a failed SetupGuest, want 0 (rolled back)", got)
	}
	if _, ok := n.IP("vm-pod"); ok {
		t.Fatal("a failed SetupGuest recorded a binding")
	}
	fake.failEnsure(nil)
	if _, err := n.SetupGuest(ctx, "vm-pod"); err != nil {
		t.Fatalf("retried SetupGuest: %v", err)
	}
}

// TestSetupGuestIdempotentAndBackendMismatch proves SetupGuest is idempotent per pod
// (a retried sandbox creation returns the same GuestNetwork, allocates no second IP
// and only re-ensures the same alias) and that mixing backends for one pod is
// rejected with ErrBackendMismatch.
func TestSetupGuestIdempotentAndBackendMismatch(t *testing.T) {
	fake := newFakeAliasManager()
	n, err := New(
		netip.MustParsePrefix("100.64.0.0/24"),
		withAliasManager(fake),
		WithVMNetwork(VMNetworkConfig{NATSubnet: vmNATSubnet, Gateway: vmGateway, DNSVIP: vmDNSVIP}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	first, err := n.SetupGuest(ctx, "vm-pod")
	if err != nil {
		t.Fatalf("first SetupGuest: %v", err)
	}
	second, err := n.SetupGuest(ctx, "vm-pod")
	if err != nil {
		t.Fatalf("second SetupGuest: %v", err)
	}
	if first != second {
		t.Fatalf("idempotent SetupGuest returned %+v then %+v", first, second)
	}
	if got := n.alloc.InUse(); got != 1 {
		t.Fatalf("InUse = %d after idempotent SetupGuest, want 1 (no second allocation)", got)
	}
	if got := fake.liveAliases(); got != 1 {
		t.Fatalf("live lo0 aliases = %d after idempotent SetupGuest, want 1", got)
	}

	if _, err := n.Setup(ctx, "vm-pod"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("Setup of a vm pod err = %v, want ErrBackendMismatch", err)
	}
	if _, err := n.Setup(ctx, "host-pod"); err != nil {
		t.Fatalf("Setup host-pod: %v", err)
	}
	if _, err := n.SetupGuest(ctx, "host-pod"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("SetupGuest of a host pod err = %v, want ErrBackendMismatch", err)
	}
}

// TestBackendString covers the Backend stringer used in logs and error messages.
func TestBackendString(t *testing.T) {
	cases := []struct {
		b    Backend
		want string
	}{
		{BackendHostProcess, "host-process"},
		{BackendVM, "vm"},
		{Backend(99), "Backend(99)"},
	}
	for _, tc := range cases {
		if got := tc.b.String(); got != tc.want {
			t.Errorf("Backend(%d).String() = %q, want %q", int(tc.b), got, tc.want)
		}
	}
}
