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
	"fmt"
	"net/netip"
)

// ErrBackendMismatch is returned by setup when podID is already provisioned under
// the OTHER backend. A pod has exactly one backend for its lifetime; provisioning
// the same pod as both a host process and a vm guest is a caller error, not an
// idempotent retry.
var ErrBackendMismatch = errors.New("podnet: pod already set up under a different backend")

// Backend selects how a pod's network is provisioned — the path-selection fork. A
// host-process pod lives in the host's network and binds a /32 lo0 alias
// (IP_BOUND_IF); a vm-RuntimeClass guest runs under Virtualization.framework with
// its OWN network stack and is reached over a VZNATNetworkDeviceAttachment, so it
// gets no lo0 alias. The caller (runtimed) chooses the backend from the pod's
// RuntimeClass: the empty/default handler is a host process; the "vm" handler
// (apis runtimev1.HandlerVM => SANDBOX_BACKEND_VM) is the guest.
type Backend int

const (
	// BackendHostProcess is a pod that runs as a native Darwin process and binds a
	// /32 lo0 alias. It is the zero value (the default backend).
	BackendHostProcess Backend = iota
	// BackendVM is a pod that runs as a Virtualization.framework micro-VM guest and
	// gets a GuestNetwork (NAT-attachment config), never an lo0 alias.
	BackendVM
)

// String names the backend for logs and errors.
func (b Backend) String() string {
	switch b {
	case BackendHostProcess:
		return "host-process"
	case BackendVM:
		return "vm"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// VMNetworkConfig carries the NAT parameters SetupGuest composes into a
// GuestNetwork. It is supplied once via WithVMNetwork and is optional: an unset
// config yields a GuestNetwork carrying only the allocated PodIP, leaving the NAT
// fields for runtimed to fill from the live attachment.
//
// NAT, not bridged: a VZNATNetworkDeviceAttachment needs only the
// com.apple.security.virtualization entitlement, whereas a bridged/raw-vmnet
// attachment needs the Apple-restricted com.apple.vm.networking entitlement the
// project ruled unobtainable — so the guest is always NAT-attached.
type VMNetworkConfig struct {
	// NATSubnet is the subnet the guest's interface address sits in behind the
	// VZNATNetworkDeviceAttachment. It is ADVISORY: macOS's vmnet assigns the guest's
	// actual address by its own DHCP, and that lease — reported by the guest agent's
	// Health, never derived from this value — is the single authority for the guest's
	// live transport address. This field is the expected/intended subnet, useful for
	// scoping decisions made before any guest boots (the Service proxy's fail-closed
	// vm-source predicate is one), not a statement about where a given guest landed.
	NATSubnet netip.Prefix
	// Gateway is the NAT gateway (the host side of the attachment) the guest routes
	// through. Advisory for the same reason as NATSubnet: macOS assigns it, and this
	// is the intended value carried alongside the config. Note the guest needs no
	// route beyond its ordinary default route through this gateway to reach a
	// ClusterIP VIP — see doc.go.
	Gateway netip.Addr
	// DNSVIP is the cluster DNS VIP (kube-dns, e.g. 10.43.0.10) the guest's
	// /etc/resolv.conf points at (see pkg/dns.GuestResolvConf). It is a cluster fact
	// darwin-net owns, not a macOS NAT fact.
	DNSVIP netip.Addr
}

// WithVMNetwork sets the NAT parameters SetupGuest composes into a GuestNetwork.
func WithVMNetwork(cfg VMNetworkConfig) Option {
	return func(n *Network) { n.vm = cfg }
}

// GuestNetwork is the config darwin-net hands runtimed's VZ backend to network a
// vm-RuntimeClass guest. darwin-net DECIDES and ALLOCATES (the pod's cluster IP and
// the NAT/DNS parameters) but does NOT attach: the live VZNATNetworkDeviceAttachment
// wiring is runtimed's (the DAG forbids darwin-net touching the VZ backend or the
// guest rootfs), so this flows guest-ward as data. Crucially it carries NO lo0
// alias — the host must never own the guest's address.
type GuestNetwork struct {
	// PodIP is the pod's cluster identity, allocated from the node podCIDR by the
	// same Allocator host-process pods use (unified, leak-free IPAM). It is the
	// PUBLISHED half of the two-address model (doc.go): status.podIP, the
	// EndpointSlice and cluster DNS carry it, and for a vm pod it is live on NO
	// interface — the host must never alias it. The guest's macOS-assigned vmnet
	// lease is the other half, the LIVE TRANSPORT address that host-to-guest dials
	// target; it is never published, and the two are deliberately NOT reconciled into
	// one address (the lease exists only after boot, the identity is baked before).
	// A guest pod stays same-node-scoped and is not a cross-node Service backend: its
	// lease address is in no peer's mesh AllowedIPs.
	PodIP netip.Addr
	// Gateway is the NAT gateway the guest routes through (from VMNetworkConfig).
	Gateway netip.Addr
	// NATSubnet is the NAT subnet the guest's interface address sits in (from
	// VMNetworkConfig).
	NATSubnet netip.Prefix
	// DNSVIP is the cluster DNS VIP the guest's resolv.conf points at (from
	// VMNetworkConfig).
	DNSVIP netip.Addr
}

// SetupGuest provisions the vm-RuntimeClass (guest) backend for podID: it allocates
// a pod IP from the node /24 and returns the GuestNetwork config WITHOUT plumbing a
// lo0 alias (the not-taken branch of the path-selection fork). It is idempotent per
// podID and returns ErrBackendMismatch if podID was already set up as a host
// process. The returned GuestNetwork is for runtimed's VZ backend to apply; the live
// NAT attach stays lab-gated, while guest VIP reachability is answered and needs
// nothing added (see doc.go).
func (n *Network) SetupGuest(ctx context.Context, podID string) (GuestNetwork, error) {
	ip, err := n.setup(ctx, podID, BackendVM)
	if err != nil {
		return GuestNetwork{}, err
	}
	return GuestNetwork{
		PodIP:     ip,
		Gateway:   n.vm.Gateway,
		NATSubnet: n.vm.NATSubnet,
		DNSVIP:    n.vm.DNSVIP,
	}, nil
}
