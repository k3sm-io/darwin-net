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
	"os/exec"
	"sync"
)

// aliasManager creates and tears down the loopback /32 aliases a pod's IP lives
// on. It is defined at the consumer (this package) per the standards: the real
// implementation runs `ifconfig lo0 alias <ip>/32` and is root-gated, while tests
// substitute a rootless fake so unit tests need no privilege. It mirrors the
// identical seam in pkg/proxy — the two are separate so the proxy and the IPAM
// path each own their alias lifecycle, but the contract is the same.
//
// Ensure must be idempotent (aliasing an already-aliased address is a no-op
// success) and Remove must be leak-free under churn (removing an absent alias is a
// no-op success). The integration test asserts both directly against lo0.
type aliasManager interface {
	// Ensure makes ip resolvable on the loopback as a /32 so the pod's process can
	// bind it. It is idempotent: a second Ensure of the same ip succeeds.
	Ensure(ctx context.Context, ip netip.Addr) error
	// Remove tears down a previously ensured alias. It is idempotent: removing an
	// address that is not aliased succeeds (no leak, no spurious error).
	Remove(ctx context.Context, ip netip.Addr) error
}

// ErrAliasUnsupported is returned by an aliasManager that cannot operate in the
// current environment (e.g. the real lo0 manager without root). Callers fall back
// to the rootless path in tests.
var ErrAliasUnsupported = errors.New("podnet: lo0 alias management unsupported (needs root)")

// blackholer installs and clears the lo0 blackhole host route that holds a pod
// address while its alias is torn down (see BlackholeRoutes). It is the seam the
// alias managers drive, so unit tests record the calls without a routing socket.
type blackholer interface {
	// Install adds the blackhole host route for ip (idempotent).
	Install(ctx context.Context, ip netip.Addr) error
	// Clear removes ip's blackhole host route if there is one, and nothing else.
	Clear(ctx context.Context, ip netip.Addr) error
}

// lo0AliasManager is the production aliasManager: it shells out to ifconfig to add
// and remove /32 aliases on lo0. These are root-gated operations; in the real
// deployment they run inside the root netd daemon boundary. It is kept here (not
// in a cmd) so the integration test can drive it directly under sudo.
//
// A pod address of the node /24 (IsPodAddress) is blackholed on lo0 when its
// alias is removed and un-blackholed just before it is aliased again, so a
// connection still open to a departed pod cannot re-route onto the mesh utun
// (see BlackholeRoutes). Other addresses are aliased and removed plainly.
//
// The blackhole is installed only for an address that was actually aliased:
// one this manager tracks, or one whose -alias found an alias on lo0 (a pod
// alias left by a previous process, which only a root alias owner can have
// plumbed). A Remove of any other address — a sweep over the whole /24, a
// teardown of an address that never had a pod — skips it, so a caller cannot
// durably blackhole an unused address.
//
// Locking discipline: a single ifconfig invocation is atomic from our side, but
// concurrent Ensure/Remove of the same address could race the kernel's alias list,
// so all mutations — the alias change and its blackhole step together — serialize
// on mu. The set of addresses we have aliased is tracked so Remove of an unknown
// address is treated as already-gone (leak-free teardown).
type lo0AliasManager struct {
	iface    string
	nodeCIDR netip.Prefix
	// ifconfig runs `ifconfig <iface> <verb> <arg>`; routes installs and clears
	// the blackhole. Both are set by newLo0AliasManager and replaced only by unit
	// tests.
	ifconfig func(ctx context.Context, iface, verb, arg string) error
	routes   blackholer
	log      *slog.Logger

	mu      sync.Mutex
	aliased map[netip.Addr]aliasState
}

// aliasState is what an alias manager knows about an address it aliased.
type aliasState uint8

const (
	// aliasLive: the alias is plumbed on lo0.
	aliasLive aliasState = iota
	// aliasBlackholePending: the alias is gone but its blackhole install failed,
	// so the address stays tracked until a retried Remove installs it.
	aliasBlackholePending
)

// newLo0AliasManager returns an aliasManager bound to the loopback interface
// (lo0) for a node whose pod /24 is nodeCIDR, which decides the addresses that
// are blackholed on removal; an invalid nodeCIDR blackholes nothing. It manages
// /32 host aliases; addresses are tracked so teardown is leak-free across churn.
func newLo0AliasManager(nodeCIDR netip.Prefix) *lo0AliasManager {
	return &lo0AliasManager{
		iface:    "lo0",
		nodeCIDR: nodeCIDR,
		ifconfig: runIfconfig,
		routes:   BlackholeRoutes{},
		log:      slog.Default(),
		aliased:  make(map[netip.Addr]aliasState),
	}
}

// Ensure adds ip as a /32 alias on lo0 if not already present. For a pod address
// it first clears any blackhole left by the address's previous teardown — a stale
// blackhole must never shadow a new pod — and fails if that clear fails. ifconfig
// alias is itself idempotent on Darwin (re-adding an existing alias returns
// success), and we additionally short-circuit on our tracked set to avoid the exec.
func (m *lo0AliasManager) Ensure(ctx context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, ok := m.aliased[ip]; ok && state == aliasLive {
		return nil
	}
	if IsPodAddress(m.nodeCIDR, ip) {
		if err := m.routes.Clear(ctx, ip); err != nil {
			return fmt.Errorf("ensure lo0 alias %s: %w", ip, err)
		}
	}
	cidr := fmt.Sprintf("%s/32", ip.String())
	if err := m.ifconfig(ctx, m.iface, "alias", cidr); err != nil {
		return fmt.Errorf("ifconfig %s alias %s: %w", m.iface, cidr, err)
	}
	m.aliased[ip] = aliasLive
	return nil
}

// Remove deletes the lo0 alias for ip and, for a pod address that was aliased,
// installs its blackhole host route in the same critical section. It is
// idempotent: if we never aliased ip the delete is best-effort (an absent address
// is exactly the success condition, so a crash-recovery teardown does not error),
// and the blackhole install is idempotent too.
//
// The blackhole is skipped, with a Debug line, for a pod address this manager
// does not track whose -alias found nothing on lo0: there is no alias, so there
// is no departed pod whose connections could re-route, and installing it would
// let any teardown request blackhole an unused address until it is next aliased.
//
// A failed blackhole install is returned as an error even though the alias is
// gone. The address stays tracked as pending, and Network.Teardown keeps it
// allocated and retries — the retry skips the -alias and re-runs the install —
// so an address is never handed to a new pod while a departed pod's connections
// could still re-route.
func (m *lo0AliasManager) Remove(ctx context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, tracked := m.aliased[ip]
	removed := false
	switch {
	case tracked && state == aliasBlackholePending:
		// The alias went on an earlier attempt; only the blackhole is owed.
	case tracked:
		if err := m.ifconfig(ctx, m.iface, "-alias", ip.String()); err != nil {
			return fmt.Errorf("ifconfig %s -alias %s: %w", m.iface, ip.String(), err)
		}
		removed = true
	default:
		// Best-effort delete in case a previous process left it; a failure means
		// the address is absent, which is exactly the success condition.
		removed = m.ifconfig(ctx, m.iface, "-alias", ip.String()) == nil
	}
	if !IsPodAddress(m.nodeCIDR, ip) {
		delete(m.aliased, ip)
		return nil
	}
	if !tracked && !removed {
		m.log.Debug("lo0 alias was never plumbed; no blackhole installed", "ip", ip.String())
		return nil
	}
	if err := m.routes.Install(ctx, ip); err != nil {
		m.aliased[ip] = aliasBlackholePending
		return fmt.Errorf("remove lo0 alias %s: %w", ip, err)
	}
	delete(m.aliased, ip)
	return nil
}

// runIfconfig invokes ifconfig with the given verb and argument against iface.
func runIfconfig(ctx context.Context, iface, verb, arg string) error {
	cmd := exec.CommandContext(ctx, "ifconfig", iface, verb, arg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
