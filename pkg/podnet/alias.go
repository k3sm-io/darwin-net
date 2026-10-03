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

	mu      sync.Mutex
	aliased map[netip.Addr]struct{}
}

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
		aliased:  make(map[netip.Addr]struct{}),
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
	if _, ok := m.aliased[ip]; ok {
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
	m.aliased[ip] = struct{}{}
	return nil
}

// Remove deletes the lo0 alias for ip and, for a pod address, installs its
// blackhole host route in the same critical section. It is idempotent: if we
// never aliased ip the delete is best-effort (an absent address is exactly the
// success condition, so a crash-recovery teardown does not error), and the
// blackhole install is idempotent too.
//
// A failed blackhole install is returned as an error even though the alias is
// gone. Network.Teardown then keeps the address allocated and the teardown is
// retried — the retry finds the alias untracked, re-runs the tolerated delete and
// the install — so an address is never handed to a new pod while a departed
// pod's connections could still re-route.
func (m *lo0AliasManager) Remove(ctx context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.aliased[ip]; !ok {
		// Best-effort delete in case a previous process left it; ignore failure
		// because the address being absent is exactly the success condition.
		_ = m.ifconfig(ctx, m.iface, "-alias", ip.String())
	} else {
		if err := m.ifconfig(ctx, m.iface, "-alias", ip.String()); err != nil {
			return fmt.Errorf("ifconfig %s -alias %s: %w", m.iface, ip.String(), err)
		}
		delete(m.aliased, ip)
	}
	if IsPodAddress(m.nodeCIDR, ip) {
		if err := m.routes.Install(ctx, ip); err != nil {
			return fmt.Errorf("remove lo0 alias %s: %w", ip, err)
		}
	}
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
