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
	"log/slog"
	"net/netip"
	"sync"
)

// PodNetwork is the CNI seam the runtime calls during pod setup and teardown. It
// is the macOS-native analog of a CNI plugin's ADD/DEL: Setup gives a pod an IP
// (a /32 lo0 alias carved from the node podCIDR) for the runtime to bind its
// processes to, and Teardown reclaims it. It is defined here, at the consumer of
// the allocator and alias manager, and is the only surface the runtime depends on.
//
// runtimed (M2) is the caller: it invokes Setup before launching the pod's
// processes, binds them to the returned IP via IP_BOUND_IF, and records the IP in
// runtime/v1 PodBox.pod_ip; it invokes Teardown when the pod is removed.
//
// PodNetwork is the host-process seam. A vm-RuntimeClass guest is provisioned via
// the concrete Network's SetupGuest instead (it returns a GuestNetwork and plumbs
// no lo0 alias — see guest.go); Teardown is shared across both backends.
type PodNetwork interface {
	// Setup allocates an IP for podID, plumbs the lo0 alias, and returns the
	// bindable address. It is idempotent per podID: calling it again for a pod that
	// already has an IP returns the same address without allocating a new one (so a
	// retried pod sandbox creation does not leak addresses).
	Setup(ctx context.Context, podID string) (netip.Addr, error)
	// Teardown removes the lo0 alias for podID and releases its IP. It is
	// idempotent and leak-free: tearing down a pod that has no IP (already torn
	// down, or never set up) is a no-op success, so a crash-recovery reconcile
	// cannot error or leak.
	Teardown(ctx context.Context, podID string) error
}

// Network implements the host-process PodNetwork seam.
var _ PodNetwork = (*Network)(nil)

// Sentinel errors for the PodNetwork seam.
var (
	// ErrEmptyPodID is returned by Setup/Teardown when podID is empty; a pod must
	// have an identity to key its IP allocation on.
	ErrEmptyPodID = errors.New("podnet: empty pod id")
)

// Network is the production PodNetwork: it pairs an Allocator (the pure IPAM core)
// with an aliasManager (the root-gated lo0 plumbing) and tracks the per-pod IP
// assignment so Setup is idempotent and Teardown is leak-free. It serves two pod
// backends from one Allocator: a host-process pod (Setup) gets a /32 lo0 alias the
// host owns and binds to; a vm-RuntimeClass guest (SetupGuest) gets NO lo0 alias
// (it owns its address inside its own netstack via a VZNATNetworkDeviceAttachment),
// only a GuestNetwork config for runtimed's VZ backend to apply — see guest.go.
//
// Locking discipline: byPod and inverse are guarded by mu and record the
// podID<->IP binding and the pod's backend (so Teardown removes a lo0 alias only
// for the host-process backend, never for a guest the host must not answer for).
// The Allocator and aliasManager have their own internal locks; mu is held across
// an Allocate+Ensure (and a Release+Remove) so a concurrent Setup and Teardown for
// the same pod cannot interleave into a leaked alias or a double allocation. The
// (root-gated) ifconfig exec happens under mu — acceptable because pod
// setup/teardown is not on a hot path and serializing it matches the proxy's
// per-VIP discipline. The vm field is set once at construction and read without the
// lock.
type Network struct {
	alloc *Allocator
	alias aliasManager
	vm    VMNetworkConfig
	log   *slog.Logger

	mu      sync.Mutex
	byPod   map[string]podEntry
	inverse map[netip.Addr]string
}

// podEntry records a pod's allocated IP and the backend that provisioned it. The
// backend governs teardown: only a host-process pod has a lo0 alias to remove.
type podEntry struct {
	ip      netip.Addr
	backend Backend
}

// Option configures a Network.
type Option func(*Network)

// WithLogger sets the structured logger; the default is slog.Default.
func WithLogger(l *slog.Logger) Option {
	return func(n *Network) { n.log = l }
}

// withAliasManager overrides the alias manager (tests inject the rootless fake).
func withAliasManager(a aliasManager) Option {
	return func(n *Network) { n.alias = a }
}

// WithNetdHelper routes lo0 alias plumbing through the root netd daemon at
// socketPath (empty uses the default socket) instead of the direct, root-gated
// ifconfig manager, so an unprivileged process can run the pod network. It is the
// one construction-time selection of the alias backend; the direct manager remains
// the default for an explicit run-as-root mode.
func WithNetdHelper(socketPath string) Option {
	return func(n *Network) { n.alias = newNetdAliasManager(socketPath) }
}

// New constructs a Network allocating pod IPs from nodeCIDR (a /24; use NodeCIDR
// to derive one from the cluster CIDR and the node index). By default it uses the
// root-gated lo0 alias manager; pass options to override (e.g. a logger). It
// returns an error if nodeCIDR is not a usable /24.
func New(nodeCIDR netip.Prefix, opts ...Option) (*Network, error) {
	alloc, err := NewAllocator(nodeCIDR)
	if err != nil {
		return nil, fmt.Errorf("new pod network: %w", err)
	}
	n := &Network{
		alloc:   alloc,
		alias:   newLo0AliasManager(),
		log:     slog.Default(),
		byPod:   make(map[string]podEntry),
		inverse: make(map[netip.Addr]string),
	}
	for _, o := range opts {
		o(n)
	}
	return n, nil
}

// CIDR returns the node /24 this network allocates pod IPs from.
func (n *Network) CIDR() netip.Prefix { return n.alloc.CIDR() }

// Setup allocates an IP for podID, ensures its lo0 alias, and returns the bindable
// address. It provisions the HOST-PROCESS backend: the returned /32 is aliased on
// lo0 for the runtime to bind the pod's processes to (IP_BOUND_IF). It is
// idempotent per podID. If the alias cannot be plumbed the freshly allocated
// address is released so a failed Setup leaks nothing. A vm-RuntimeClass guest uses
// SetupGuest instead (no lo0 alias) — see guest.go.
func (n *Network) Setup(ctx context.Context, podID string) (netip.Addr, error) {
	return n.setup(ctx, podID, BackendHostProcess)
}

// setup is the shared provisioning core for both pod backends. It allocates a
// unique IP from the node /24 and records the pod<->IP binding and its backend.
// THE PATH-SELECTION FORK lives here: a host-process pod gets a /32 lo0 alias (the
// host owns it and binds to it); a vm-RuntimeClass guest gets NONE — a
// Virtualization.framework guest has its own network stack reached over a
// VZNATNetworkDeviceAttachment, so an lo0 alias would make the host answer for the
// guest's address and blackhole same-node delivery. setup is idempotent per podID
// and, for the host-process backend, rolls back the allocation if the alias plumb
// fails, so a failed setup leaks nothing.
func (n *Network) setup(ctx context.Context, podID string, backend Backend) (netip.Addr, error) {
	if podID == "" {
		return netip.Addr{}, ErrEmptyPodID
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if e, ok := n.byPod[podID]; ok {
		if e.backend != backend {
			return netip.Addr{}, fmt.Errorf("%w: pod %s set up as %s, requested %s", ErrBackendMismatch, podID, e.backend, backend)
		}
		// Idempotent: the pod already has an IP. Re-ensure the alias for a host-
		// process pod (cheap no-op if present) so a retry after a host-side alias loss
		// reconverges; a guest pod has no lo0 alias to re-ensure.
		if backend == BackendHostProcess {
			if err := n.alias.Ensure(ctx, e.ip); err != nil {
				return netip.Addr{}, fmt.Errorf("re-ensure lo0 alias %s for pod %s: %w", e.ip, podID, err)
			}
		}
		return e.ip, nil
	}

	ip, err := n.alloc.Allocate()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("allocate pod ip for %s: %w", podID, err)
	}
	if backend == BackendHostProcess {
		if err := n.alias.Ensure(ctx, ip); err != nil {
			// Roll back the allocation so a failed alias plumb does not leak the IP.
			_ = n.alloc.Release(ip)
			return netip.Addr{}, fmt.Errorf("ensure lo0 alias %s for pod %s: %w", ip, podID, err)
		}
	}
	n.byPod[podID] = podEntry{ip: ip, backend: backend}
	n.inverse[ip] = podID
	n.log.Debug("pod network setup", "pod", podID, "ip", ip.String(), "backend", backend.String(), "cidr", n.alloc.CIDR().String())
	return ip, nil
}

// Teardown releases podID's IP and, for a host-process pod, removes its lo0 alias;
// a vm-RuntimeClass guest has no alias to remove (the host never owned its address).
// It is idempotent and leak-free: a pod with no recorded IP is a no-op success. If a
// host-process alias removal fails the IP is NOT released (so a retry can complete
// the teardown rather than orphaning a still-aliased address).
func (n *Network) Teardown(ctx context.Context, podID string) error {
	if podID == "" {
		return ErrEmptyPodID
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	e, ok := n.byPod[podID]
	if !ok {
		// Already torn down or never set up: nothing to remove, nothing to leak.
		return nil
	}
	// Remove the lo0 alias only for a host-process pod. A guest pod never had one
	// (the host must not own the guest's address), so there is nothing to remove.
	if e.backend == BackendHostProcess {
		if err := n.alias.Remove(ctx, e.ip); err != nil {
			return fmt.Errorf("remove lo0 alias %s for pod %s: %w", e.ip, podID, err)
		}
	}
	if err := n.alloc.Release(e.ip); err != nil && !errors.Is(err, ErrNotAllocated) {
		return fmt.Errorf("release pod ip %s for %s: %w", e.ip, podID, err)
	}
	delete(n.byPod, podID)
	delete(n.inverse, e.ip)
	n.log.Debug("pod network teardown", "pod", podID, "ip", e.ip.String(), "backend", e.backend.String())
	return nil
}

// IP returns the address assigned to podID and whether it has one. It is a
// read-only accessor for diagnostics and the runtime's status reporting.
func (n *Network) IP(podID string) (netip.Addr, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.byPod[podID]
	return e.ip, ok
}

// Pods returns the number of pods currently holding an IP.
func (n *Network) Pods() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.byPod)
}
