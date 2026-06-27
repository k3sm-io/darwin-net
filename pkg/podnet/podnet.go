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

// Sentinel errors for the PodNetwork seam.
var (
	// ErrEmptyPodID is returned by Setup/Teardown when podID is empty; a pod must
	// have an identity to key its IP allocation on.
	ErrEmptyPodID = errors.New("podnet: empty pod id")
)

// Network is the production PodNetwork: it pairs an Allocator (the pure IPAM core)
// with an aliasManager (the root-gated lo0 plumbing) and tracks the per-pod IP
// assignment so Setup is idempotent and Teardown is leak-free.
//
// Locking discipline: byPod and inverse are guarded by mu and record the
// podID<->IP binding. The Allocator and aliasManager have their own internal
// locks; mu is held across an Allocate+Ensure (and a Release+Remove) so a
// concurrent Setup and Teardown for the same pod cannot interleave into a leaked
// alias or a double allocation. The (root-gated) ifconfig exec happens under mu —
// acceptable because pod setup/teardown is not on a hot path and serializing it
// matches the proxy's per-VIP discipline.
type Network struct {
	alloc *Allocator
	alias aliasManager
	log   *slog.Logger

	mu      sync.Mutex
	byPod   map[string]netip.Addr
	inverse map[netip.Addr]string
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
		byPod:   make(map[string]netip.Addr),
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
// address. It is idempotent per podID. If the alias cannot be plumbed the freshly
// allocated address is released so a failed Setup leaks nothing.
func (n *Network) Setup(ctx context.Context, podID string) (netip.Addr, error) {
	if podID == "" {
		return netip.Addr{}, ErrEmptyPodID
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if ip, ok := n.byPod[podID]; ok {
		// Idempotent: the pod already has an IP. Re-ensure the alias (cheap no-op if
		// already present) so a retry after a host-side alias loss still converges.
		if err := n.alias.Ensure(ctx, ip); err != nil {
			return netip.Addr{}, fmt.Errorf("re-ensure lo0 alias %s for pod %s: %w", ip, podID, err)
		}
		return ip, nil
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
	n.byPod[podID] = ip
	n.inverse[ip] = podID
	n.log.Debug("pod network setup", "pod", podID, "ip", ip.String(), "cidr", n.alloc.CIDR().String())
	return ip, nil
}

// Teardown removes podID's lo0 alias and releases its IP. It is idempotent and
// leak-free: a pod with no recorded IP is a no-op success. If the alias removal
// fails the IP is NOT released (so a retry can complete the teardown rather than
// orphaning a still-aliased address).
func (n *Network) Teardown(ctx context.Context, podID string) error {
	if podID == "" {
		return ErrEmptyPodID
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	ip, ok := n.byPod[podID]
	if !ok {
		// Already torn down or never set up: nothing to remove, nothing to leak.
		return nil
	}
	if err := n.alias.Remove(ctx, ip); err != nil {
		return fmt.Errorf("remove lo0 alias %s for pod %s: %w", ip, podID, err)
	}
	if err := n.alloc.Release(ip); err != nil && !errors.Is(err, ErrNotAllocated) {
		return fmt.Errorf("release pod ip %s for %s: %w", ip, podID, err)
	}
	delete(n.byPod, podID)
	delete(n.inverse, ip)
	n.log.Debug("pod network teardown", "pod", podID, "ip", ip.String())
	return nil
}

// IP returns the address assigned to podID and whether it has one. It is a
// read-only accessor for diagnostics and the runtime's status reporting.
func (n *Network) IP(podID string) (netip.Addr, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ip, ok := n.byPod[podID]
	return ip, ok
}

// Pods returns the number of pods currently holding an IP.
func (n *Network) Pods() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.byPod)
}
