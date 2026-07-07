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

// This file is the crash-reconcile surface (M10.1): the Network's IPAM state is
// in-memory while the lo0 aliases it plumbs are durable kernel state, so a
// daemon crash (`launchctl kickstart -k`) leaves the two divergent — the new
// process would re-allocate addresses still aliased for running pods
// (collisions) and never remove aliases whose pods died with the old process
// (leaks). The k3sm caller reconciles at startup, BEFORE serving any Setup:
// ReattachPod for every still-running pod's recorded podID->IP binding (from
// PodBox.pod_ip), then one SweepStale with that same known set to clear the
// orphans. Both are no-op-clean on an empty node.

// ErrIPInUse is returned by ReattachPod when the requested address is already
// bound (to a different pod, or held by the allocator without a pod binding),
// so a corrupt restart manifest cannot silently steal a live pod's address.
var ErrIPInUse = errors.New("podnet: ip already in use")

// ReattachPod re-adopts a known podID->IP binding after a daemon restart: it
// validates ip is a usable host address in the node /24 (the reserved network,
// broadcast, and mesh-egress addresses are rejected with ErrOutOfRange),
// reserves exactly that address, records the binding, and (re-)ensures the lo0
// alias — idempotent, since the alias likely survived the crash. A subsequent
// Setup for the same podID returns the same address, and no other pod can be
// allocated it.
//
// It re-adopts the HOST-PROCESS backend (the one with durable lo0 state to
// re-own); a vm-RuntimeClass guest owns its address inside its own netstack and
// is re-provisioned via SetupGuest. Reattaching the same podID->ip twice is a
// no-op success; a conflicting binding fails — ErrIPInUse when the address is
// held elsewhere, a descriptive error for a same-pod rebind — never a silent
// overwrite. If the alias plumb fails the reservation is rolled back so a
// failed reattach leaks nothing.
func (n *Network) ReattachPod(ctx context.Context, podID string, ip netip.Addr) error {
	if podID == "" {
		return ErrEmptyPodID
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if e, ok := n.byPod[podID]; ok {
		if e.backend != BackendHostProcess {
			return fmt.Errorf("%w: pod %s is provisioned as %s, reattach re-adopts host-process pods only", ErrBackendMismatch, podID, e.backend)
		}
		if e.ip != ip {
			return fmt.Errorf("reattach pod %s: already bound to %s, refusing rebind to %s", podID, e.ip, ip)
		}
		// Idempotent re-reattach: just re-ensure the alias.
		if err := n.alias.Ensure(ctx, ip); err != nil {
			return fmt.Errorf("re-ensure lo0 alias %s for pod %s: %w", ip, podID, err)
		}
		return nil
	}
	if owner, ok := n.inverse[ip]; ok {
		return fmt.Errorf("reattach pod %s: %w: %s is bound to pod %s", podID, ErrIPInUse, ip, owner)
	}

	alreadyHeld, err := n.alloc.AllocateSpecific(ip)
	if err != nil {
		return fmt.Errorf("reattach pod %s: reserve %s: %w", podID, ip, err)
	}
	if alreadyHeld {
		// Held by the allocator but bound to no pod: internal inconsistency (only
		// setup and reattach allocate, and both record the binding under mu).
		// Refuse rather than adopt an address of unknown provenance.
		return fmt.Errorf("reattach pod %s: %w: %s is held but unbound", podID, ErrIPInUse, ip)
	}
	if err := n.alias.Ensure(ctx, ip); err != nil {
		// Roll back the reservation so a failed reattach does not leak the IP.
		_ = n.alloc.Release(ip)
		return fmt.Errorf("ensure lo0 alias %s for pod %s: %w", ip, podID, err)
	}
	n.byPod[podID] = podEntry{ip: ip, backend: BackendHostProcess}
	n.inverse[ip] = podID
	n.log.Debug("pod network reattach", "pod", podID, "ip", ip.String(), "cidr", n.alloc.CIDR().String())
	return nil
}

// SweepStale removes every k3sm-owned lo0 alias inside the node podCIDR that is
// NOT in the known podID->IP set (nor bound in this Network) — the orphans a
// crashed previous daemon left aliased on lo0 with no surviving pod. Callers
// run it once at startup, after ReattachPod-ing the still-running pods and
// before serving any Setup; on an empty node with a nil/empty known set it is a
// no-op success.
//
// The alias-manager seam has no List (netd exposes ensure/remove only), so the
// sweep walks the /24's usable host range [.2, .254] and Removes every address
// not in the keep set — correct because Remove is idempotent by contract (an
// absent alias is a no-op success) and cheap because it runs once at startup,
// never on the pod hot path. The reserved addresses (.0 network, .1
// mesh-egress, .255 broadcast) lie outside the walked range and are never
// touched. A failing removal is collected, the sweep continues (one stuck
// alias must not strand the rest), and the joined error is returned.
func (n *Network) SweepStale(ctx context.Context, known map[string]netip.Addr) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	keep := make(map[netip.Addr]struct{}, len(known)+len(n.inverse))
	for _, ip := range known {
		keep[ip] = struct{}{}
	}
	for ip := range n.inverse {
		keep[ip] = struct{}{}
	}

	var errs []error
	swept := 0
	for ip := n.alloc.first; ip.Compare(n.alloc.last) <= 0; ip = ip.Next() {
		if _, ok := keep[ip]; ok {
			continue
		}
		if err := n.alias.Remove(ctx, ip); err != nil {
			errs = append(errs, fmt.Errorf("sweep stale lo0 alias %s: %w", ip, err))
			continue
		}
		swept++
	}
	n.log.Debug("pod network sweep", "cidr", n.alloc.CIDR().String(), "kept", len(keep), "swept", swept, "errors", len(errs))
	return errors.Join(errs...)
}
