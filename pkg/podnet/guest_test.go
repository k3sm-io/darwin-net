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

// TestVMPodSelectsVmnetPathNotLo0 maps to acceptance M5.1-a2: the networking setup
// selects the VM (NAT) path — NOT the lo0-alias path — when the pod's backend is the
// VM, and the host-process path is unaffected. It asserts BOTH branches of the fork:
// a vm guest gets a GuestNetwork and NO lo0 alias (Ensure/Remove never called for
// it), while a host-process pod still gets exactly one lo0 alias and no vmnet config.
func TestVMPodSelectsVmnetPathNotLo0(t *testing.T) {
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

	// --- VM pod: the NAT path, NOT lo0 (the not-taken branch) ---
	guest, err := n.SetupGuest(ctx, "vm-pod")
	if err != nil {
		t.Fatalf("SetupGuest: %v", err)
	}
	if !n.CIDR().Contains(guest.PodIP) {
		t.Fatalf("guest PodIP %s outside node CIDR %s", guest.PodIP, n.CIDR())
	}
	// THE FORK, not-taken branch: a vm guest must NOT get a lo0 alias — the host
	// would otherwise own the guest's IP and blackhole same-node delivery.
	if got := fake.ensures(guest.PodIP); got != 0 {
		t.Fatalf("VM pod ensured a lo0 alias %d times for %s, want 0", got, guest.PodIP)
	}
	if got := fake.liveAliases(); got != 0 {
		t.Fatalf("VM pod left %d live lo0 aliases, want 0", got)
	}
	// The vmnet/NAT config is returned for runtimed's VZ backend to apply.
	if guest.NATSubnet != vmNATSubnet || guest.Gateway != vmGateway || guest.DNSVIP != vmDNSVIP {
		t.Fatalf("GuestNetwork NAT config = {subnet %s gw %s dns %s}, want {subnet %s gw %s dns %s}",
			guest.NATSubnet, guest.Gateway, guest.DNSVIP, vmNATSubnet, vmGateway, vmDNSVIP)
	}
	if got, ok := n.IP("vm-pod"); !ok || got != guest.PodIP {
		t.Fatalf("IP(vm-pod) = %s,%v, want %s,true", got, ok, guest.PodIP)
	}

	// --- host-process pod: the lo0 path is unaffected (the taken branch) ---
	hostIP, err := n.Setup(ctx, "host-pod")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// THE FORK, taken branch: a host-process pod DOES get exactly one lo0 alias.
	if got := fake.ensures(hostIP); got != 1 {
		t.Fatalf("host-process pod ensured a lo0 alias %d times for %s, want 1", got, hostIP)
	}
	if hostIP == guest.PodIP {
		t.Fatalf("host and vm pods got the same IP %s", hostIP)
	}

	// --- teardown branches: a vm pod removes no alias; a host pod does ---
	if err := n.Teardown(ctx, "vm-pod"); err != nil {
		t.Fatalf("Teardown vm-pod: %v", err)
	}
	if got := fake.removes(guest.PodIP); got != 0 {
		t.Fatalf("VM pod teardown removed a lo0 alias %d times for %s, want 0", got, guest.PodIP)
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

// TestSetupGuestIdempotentAndBackendMismatch proves SetupGuest is idempotent per pod
// (a retried sandbox creation returns the same GuestNetwork and allocates no second
// IP) and that mixing backends for one pod is rejected with ErrBackendMismatch.
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
	if got := fake.ensures(first.PodIP); got != 0 {
		t.Fatalf("idempotent SetupGuest ensured a lo0 alias %d times, want 0", got)
	}

	// A pod set up as a guest cannot then be set up as a host process, and vice versa.
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
