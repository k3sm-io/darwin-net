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
// runtimed is the caller: it invokes Setup before launching the pod's
// processes, binds them to the returned IP via IP_BOUND_IF, and records the IP in
// runtime/v1 PodBox.pod_ip; it invokes Teardown when the pod is removed.
//
// PodNetwork is the host-process seam. A vm-RuntimeClass guest is provisioned via
// the concrete Network's SetupGuest instead (it returns a GuestNetwork for the VZ
// backend and aliases the pod's published /32 on lo0 so the node can relay it to
// the guest — see guest.go); Teardown is shared across both backends.
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
// backends from one Allocator, and both get a /32 lo0 alias for the pod's
// lifetime: a host-process pod (Setup) binds its processes to it; a vm-RuntimeClass
// guest (SetupGuest) owns a different, live address inside its own netstack, and
// its published /32 is aliased so the node's Service proxy can listen on it and
// relay to the guest — see guest.go.
//
// Locking discipline: byPod and inverse are guarded by mu and record the
// podID<->IP binding and the pod's backend (so a re-setup or reattach under the
// other backend is refused).
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

// podEntry records a pod's allocated IP and the backend that provisioned it. Both
// backends hold a lo0 alias for the pod's lifetime; the backend is recorded so a
// pod is never re-provisioned under the other one.
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
		alias:   newLo0AliasManager(alloc.CIDR()),
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

// EnsureNodeAlias plumbs an lo0 /32 alias for the node's OWN advertised address —
// the reserved mesh-egress /32 (.1 of the node /24, see MeshEgressIP) the VK node
// advertises as its NodeInternalIP. The apiserver node-proxy dials that
// address:10250 to serve /nodes/<n>/proxy/stats/summary (kubectl top node), and a
// connect to a non-loopback address loops back to the local listener on the same
// host ONLY when the address is an lo0 alias. Unlike Setup this is NOT pod-keyed
// and lies outside the allocator's usable range ([.2, .254]), so SweepStale never
// reclaims it (the .1 is excluded — see reconcile.go). It touches only the alias
// manager (which serializes on its own lock), never the pod IPAM maps, so it needs
// no Network lock. Idempotent (ifconfig alias re-add is a no-op success), so a
// caller may re-ensure it at every startup reconcile.
func (n *Network) EnsureNodeAlias(ctx context.Context, ip netip.Addr) error {
	return n.alias.Ensure(ctx, ip)
}

// Setup allocates an IP for podID, ensures its lo0 alias, and returns the bindable
// address. It provisions the HOST-PROCESS backend: the returned /32 is aliased on
// lo0 for the runtime to bind the pod's processes to (IP_BOUND_IF). It is
// idempotent per podID. If the alias cannot be plumbed the freshly allocated
// address is released so a failed Setup leaks nothing. A vm-RuntimeClass guest uses
// SetupGuest instead — see guest.go.
func (n *Network) Setup(ctx context.Context, podID string) (netip.Addr, error) {
	return n.setup(ctx, podID, BackendHostProcess)
}

// setup is the shared provisioning core for both pod backends. It allocates a
// unique IP from the node /24, ensures its /32 lo0 alias, and records the
// pod<->IP binding and its backend. Both backends get the alias: a host-process
// pod binds its processes to it, and a vm-RuntimeClass guest's published /32 is
// where the node's proxy listens to relay to the guest's live lease address
// (pkg/proxy podrelay.go) — without it the published address would be live on no
// interface and reachable from nowhere. setup is idempotent per podID and rolls
// back the allocation if the alias plumb fails, so a failed setup leaks nothing.
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
		// Idempotent: the pod already has an IP. Re-ensure the alias (cheap no-op if
		// present) so a retry after a host-side alias loss reconverges.
		if err := n.alias.Ensure(ctx, e.ip); err != nil {
			return netip.Addr{}, fmt.Errorf("re-ensure lo0 alias %s for pod %s: %w", e.ip, podID, err)
		}
		return e.ip, nil
	}

	ip, err := n.alloc.Allocate()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("allocate pod ip for %s: %w", podID, err)
	}
	if err := n.alias.Ensure(ctx, ip); err != nil {
		// Roll back the allocation so a failed alias plumb does not leak the IP.
		_ = n.alloc.Release(ip)
		return netip.Addr{}, fmt.Errorf("ensure lo0 alias %s for pod %s: %w", ip, podID, err)
	}
	n.byPod[podID] = podEntry{ip: ip, backend: backend}
	n.inverse[ip] = podID
	n.log.Debug("pod network setup", "pod", podID, "ip", ip.String(), "backend", backend.String(), "cidr", n.alloc.CIDR().String())
	return ip, nil
}

// Teardown removes podID's lo0 alias and releases its IP, for both backends; the
// alias manager installs the address's lo0 blackhole as the alias goes (see
// BlackholeRoutes). For a vm pod the caller MUST first drop the pod's proxy
// transport override, which closes its relay (listeners and relayed connections)
// before that call returns, and only then call Teardown, so no relayed
// connection is still open when the alias goes. It is idempotent and leak-free: a pod with no recorded
// IP is a no-op success. If the alias removal fails the IP is NOT released (so a
// retry can complete the teardown rather than orphaning a still-aliased address).
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
	if err := n.alias.Remove(ctx, e.ip); err != nil {
		return fmt.Errorf("remove lo0 alias %s for pod %s: %w", e.ip, podID, err)
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
