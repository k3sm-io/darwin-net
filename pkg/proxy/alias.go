package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sync"
)

// aliasManager creates and tears down the loopback alias addresses the proxy
// binds its ClusterIP listeners on. It is defined at the consumer (the proxy)
// per the standards: the real implementation runs `ifconfig lo0 alias <ip>/32`
// and is root-gated; tests substitute a rootless fake or the 127.0.0.x rehearsal
// so unit tests need no privilege.
//
// Ensure must be idempotent (aliasing an already-aliased address is a no-op
// success) and Remove must be leak-free under churn (removing an absent alias is
// a no-op success). The integration test asserts both directly against lo0.
type aliasManager interface {
	// Ensure makes ip resolvable on the loopback so a listener can bind it. It is
	// idempotent: a second Ensure of the same ip succeeds without error.
	Ensure(ctx context.Context, ip netip.Addr) error
	// Remove tears down a previously ensured alias. It is idempotent: removing an
	// address that is not aliased succeeds (no leak, no spurious error).
	Remove(ctx context.Context, ip netip.Addr) error
}

// ErrAliasUnsupported is returned by an aliasManager that cannot operate in the
// current environment (e.g. the real lo0 manager without root). The proxy server
// surfaces it so callers fall back to the rootless rehearsal path in tests.
var ErrAliasUnsupported = errors.New("proxy: lo0 alias management unsupported (needs root)")

// lo0AliasManager is the production aliasManager: it shells out to ifconfig to
// add and remove /32 aliases on lo0. These are root-gated operations; in the
// real deployment they run inside the root netd daemon boundary. It is kept here
// (not in a cmd) so the integration test can drive it directly under sudo.
//
// Locking discipline: a single ifconfig invocation is atomic from our side, but
// concurrent Ensure/Remove of the same address could race the kernel's alias
// list, so all mutations serialize on mu. The set of addresses we have aliased
// is tracked so Remove of an unknown address is treated as already-gone.
type lo0AliasManager struct {
	iface string

	mu      sync.Mutex
	aliased map[netip.Addr]struct{}
}

// newLo0AliasManager returns an aliasManager bound to the loopback interface
// (lo0). It manages /32 host aliases; addresses are tracked so teardown is leak-
// free across churn.
func newLo0AliasManager() *lo0AliasManager {
	return &lo0AliasManager{iface: "lo0", aliased: make(map[netip.Addr]struct{})}
}

// Ensure adds ip as a /32 alias on lo0 if not already present. ifconfig alias is
// itself idempotent on Darwin (re-adding an existing alias returns success), and
// we additionally short-circuit on our tracked set to avoid the exec.
func (m *lo0AliasManager) Ensure(ctx context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.aliased[ip]; ok {
		return nil
	}
	cidr := fmt.Sprintf("%s/32", ip.String())
	if err := m.run(ctx, "alias", cidr); err != nil {
		return fmt.Errorf("ifconfig %s alias %s: %w", m.iface, cidr, err)
	}
	m.aliased[ip] = struct{}{}
	return nil
}

// Remove deletes the lo0 alias for ip. It is idempotent: if we never aliased ip
// it returns nil, and ifconfig -alias of an absent address is tolerated so a
// crash-recovery teardown does not error.
func (m *lo0AliasManager) Remove(ctx context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.aliased[ip]; !ok {
		// Best-effort delete in case a previous process left it; ignore failure
		// because the address being absent is exactly the success condition.
		_ = m.run(ctx, "-alias", ip.String())
		return nil
	}
	if err := m.run(ctx, "-alias", ip.String()); err != nil {
		return fmt.Errorf("ifconfig %s -alias %s: %w", m.iface, ip.String(), err)
	}
	delete(m.aliased, ip)
	return nil
}

// run invokes ifconfig with the given verb and argument against the interface.
func (m *lo0AliasManager) run(ctx context.Context, verb, arg string) error {
	cmd := exec.CommandContext(ctx, "ifconfig", m.iface, verb, arg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// noopAliasManager is the rootless aliasManager used when the proxy binds an
// address that is already resolvable without an alias (the 127.0.0.x rehearsal
// path: 127.0.0.0/8 is entirely loopback on Darwin, so any 127.0.0.x is
// bindable without ifconfig). It records calls so tests can assert reconcile
// drove the expected Ensure/Remove sequence.
//
// Locking discipline: ensured is guarded by mu; Ensure/Remove and the test
// accessors all take it.
type noopAliasManager struct {
	mu      sync.Mutex
	ensured map[netip.Addr]int
	removed map[netip.Addr]int
}

// newNoopAliasManager returns a rootless aliasManager that performs no syscalls.
func newNoopAliasManager() *noopAliasManager {
	return &noopAliasManager{
		ensured: make(map[netip.Addr]int),
		removed: make(map[netip.Addr]int),
	}
}

// Ensure records the call and succeeds without touching the interface.
func (m *noopAliasManager) Ensure(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensured[ip]++
	return nil
}

// Remove records the call and succeeds without touching the interface.
func (m *noopAliasManager) Remove(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed[ip]++
	return nil
}

// ensures reports how many times Ensure was called for ip (test accessor).
func (m *noopAliasManager) ensures(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensured[ip]
}

// removes reports how many times Remove was called for ip (test accessor).
func (m *noopAliasManager) removes(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removed[ip]
}
