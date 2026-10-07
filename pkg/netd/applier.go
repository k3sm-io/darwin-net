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

package netd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync"

	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"
)

// Privileged is the root-only datapath the daemon drives AFTER it has
// authenticated the peer and validated + rendered a request. It is the seam
// between netd's pure policy core (peer-auth, CIDR/route/port validation, UAPI/pf
// rendering — all unit-tested) and the irreducibly-privileged darwin operations.
// NewServer uses the production darwin implementation when Config.Privileged is
// nil; tests (and an alternate host) inject their own. The server never lets an
// unvalidated parameter reach this interface.
type Privileged interface {
	// EnsureAlias plumbs ip as a /32 lo0 alias (idempotent).
	EnsureAlias(ctx context.Context, ip netip.Addr) error
	// RemoveAlias tears ip's /32 lo0 alias down (leak-free, idempotent).
	RemoveAlias(ctx context.Context, ip netip.Addr) error
	// ConfigureMesh brings the wireguard mesh up with privKeyB64 + listenPort (once)
	// and applies the already-validated, already-rendered plan.
	ConfigureMesh(ctx context.Context, privKeyB64 string, listenPort int, plan mesh.Plan) error
	// RemoveMesh tears the wireguard mesh down (leak-free, idempotent).
	RemoveMesh(ctx context.Context) error
	// SetNodePodCIDR re-points the executor at cidr, re-deriving everything it
	// derives from the node's pod /24 (the mesh-egress source and the utun link
	// address) and retiring anything built from the old one. The server calls it
	// only when it adopts a new node identity, which it does only while nothing is
	// live; an executor that cannot serve the new CIDR returns an error and the
	// adoption is refused.
	SetNodePodCIDR(ctx context.Context, cidr netip.Prefix) error
	// BindPort binds a listening socket on the specific addr and returns it; the
	// caller passes the fd to the client and closes this copy.
	BindPort(ctx context.Context, network string, addr netip.AddrPort) (*os.File, error)
	// ConfigureLink configures a validated direct-link port (idempotent): out of
	// bridge0, its /32 address, offload off, the on-link host route to the peer
	// when one is given, all read back from the kernel before it returns nil. A
	// failure leaves no alias or host route of this call behind.
	ConfigureLink(ctx context.Context, spec LinkSpec) error
	// RemoveLink tears a direct-link port down (idempotent): the direct routes
	// over it first, then its host route and address, then bridge membership is
	// restored.
	RemoveLink(ctx context.Context, iface string) error
}

// LinkSpec is a direct-link port the server has validated: the Thunderbolt
// interface, the address the server derived for it, and the peer's address on
// the cable (invalid: no host route).
type LinkSpec struct {
	Iface      string
	LinkIP     netip.Addr
	PeerLinkIP netip.Addr
}

// linkRouter is the host-route seam the link operations drive
// (*mesh.HostRoutes in production).
type linkRouter interface {
	Ensure(ctx context.Context, peer netip.Addr, iface string) error
	Remove(ctx context.Context, peer netip.Addr, iface string) error
	List(ctx context.Context) ([]mesh.Route, error)
	Delete(ctx context.Context, r mesh.Route) error
}

// blackholer installs and clears the lo0 blackhole host route that holds a pod
// address while its alias is torn down (podnet.BlackholeRoutes in production).
type blackholer interface {
	// Install adds the blackhole host route for ip (idempotent).
	Install(ctx context.Context, ip netip.Addr) error
	// Clear removes ip's blackhole host route if there is one, and nothing else.
	Clear(ctx context.Context, ip netip.Addr) error
	// List returns the pod addresses of nodeCIDR that hold a blackhole host route.
	List(ctx context.Context, nodeCIDR netip.Prefix) ([]netip.Addr, error)
}

// meshDevice is the slice of the wireguard device (*mesh.WGDevice in production)
// the applier drives: bring-up, plan apply, teardown, the direct-route withdraw,
// and the resolved utun name. It exists so the alias plumbing around the device
// is testable without a utun.
type meshDevice interface {
	Up(ctx context.Context) error
	Apply(ctx context.Context, plan mesh.Plan) error
	Down(ctx context.Context) error
	WithdrawIface(ctx context.Context, iface string) (int, error)
	Interface() string
}

// newWGDevice builds the production meshDevice.
func newWGDevice(cfg mesh.DeviceConfig, log *slog.Logger) meshDevice {
	return mesh.NewDevice(cfg, log)
}

// aliasState is what the applier knows about a lo0 alias it plumbed.
type aliasState uint8

const (
	// aliasLive: the alias is plumbed on lo0.
	aliasLive aliasState = iota
	// aliasBlackholePending: the alias is gone but its blackhole install failed,
	// so the address stays tracked until a retried RemoveAlias installs it.
	aliasBlackholePending
)

// localPods is the set of this node's pod addresses that a pod holds — aliased on
// lo0 — as the mesh device's SYN refusal sees it (mesh.DeviceConfig.Allocated).
// The device answers a peer's SYN to a pod address OUTSIDE this set with a RST, so
// the set must never miss a live pod: until it is known (no lo0 read yet, a failed
// read, a re-pointed /24) every address counts as allocated; an address joins it
// before its lo0 alias is plumbed and leaves only once that alias is known gone.
// It is read on the receive path, so it has its own lock, never held across a
// command. In helper mode every lo0 alias in the node /24 is plumbed through this
// executor, which is what lets it be the authority.
type localPods struct {
	mu    sync.RWMutex
	known bool
	set   map[netip.Addr]struct{}
}

// allocated reports whether a pod holds ip, or the set is not known.
func (l *localPods) allocated(ip netip.Addr) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if !l.known {
		return true
	}
	_, ok := l.set[ip]
	return ok
}

// reset replaces the set with ips and marks it known.
func (l *localPods) reset(ips []netip.Addr) {
	set := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		set[ip] = struct{}{}
	}
	l.mu.Lock()
	l.known, l.set = true, set
	l.mu.Unlock()
}

// forget marks the set unknown: every address counts as allocated again.
func (l *localPods) forget() {
	l.mu.Lock()
	l.known, l.set = false, nil
	l.mu.Unlock()
}

// add puts ip in the set (a no-op while it is unknown).
func (l *localPods) add(ip netip.Addr) {
	l.mu.Lock()
	if l.known {
		l.set[ip] = struct{}{}
	}
	l.mu.Unlock()
}

// remove takes ip out of the set.
func (l *localPods) remove(ip netip.Addr) {
	l.mu.Lock()
	delete(l.set, ip)
	l.mu.Unlock()
}

// darwinApplier is the production Privileged: it shells out to ifconfig and
// binds sockets directly, and drives the real wireguard mesh device (pkg/mesh).
// It runs as root inside the daemon; unit tests inject a fake Privileged instead,
// so this code path is exercised only in the root-gated integration tier, apart
// from the alias path, whose command runner and route seam a unit test replaces.
//
// A pod address of the node /24 (podnet.IsPodAddress) is blackholed on lo0 when
// its alias is removed and un-blackholed just before it is aliased again, so a
// connection still open to a departed pod cannot re-route onto the mesh utun (see
// podnet.BlackholeRoutes). A Service VIP is aliased and removed plainly: with no
// alias it falls to the default route, never the utun. The blackhole is installed
// only for an address that was actually aliased — one this applier tracks, or one
// whose -alias found an alias on lo0 (left by a previous daemon; a lo0 alias in
// the pod /24 is plumbed by nothing but this root executor) — so a RemoveAlias
// request cannot durably blackhole an unused address. The blackholes of a /24 the
// applier stops serving are swept by SetNodePodCIDR, and stale ones in the
// current /24 by sweepStaleBlackholes at daemon start.
//
// A pod address of the node /24 is also aliased onto the mesh utun, with the
// utun's own link address as point-to-point destination (mesh.UTUNAliasArgs):
// after its lo0 alias on EnsureAlias, before it on RemoveAlias, and for the whole
// lo0 set whenever ConfigureMesh runs (reconcileUTUNAliases), which covers a utun
// (re)created under live pods. The kernel scopes a reply it generates itself (a
// RST for a closed port, an echo reply) to the interface the packet arrived on and
// drops it when its source is not an address of that interface, so without the
// utun alias a peer's dial of a closed port on a pod of this node hangs instead
// of being refused. The alias installs no route and lo0 stays the address's home.
//
// The applier also hands the mesh device the set of pod addresses a pod holds
// (localPods), so the device can answer a peer's SYN to an address of the /24 no
// pod holds, such as a deleted pod's, with a RST of its own: the kernel cannot,
// because that address is on no interface.
//
// Locking discipline: the lazily-built mesh device, its up/iface state, and the
// node CIDR the mesh addresses derive from are guarded by mu, so concurrent
// ConfigureMesh/RemoveMesh/SetNodePodCIDR calls (from different
// connections) serialize. Alias operations serialize on aliasMu, so an alias
// change and its blackhole step are one critical section; they read nodePodCIDR
// under mu briefly and never hold mu across a command (lock order: aliasMu, then
// mu). aliased is guarded by aliasMu. Port operations are independent (the kernel serializes them) and take no
// lock here. ConfigureMesh holds aliasMu (then mu) for its whole run, so the utun
// reconcile it ends with cannot interleave with an alias change.
type darwinApplier struct {
	utunName string
	log      *slog.Logger
	// command runs a root-gated command and routes installs and clears the
	// pod-address blackhole. Both are set by newDarwinApplier and replaced only by
	// unit tests.
	command func(ctx context.Context, name string, args ...string) error
	routes  blackholer
	// output runs a read-only command and returns its standard output (the
	// ifconfig read-backs of the link operations); hostRoutes is the link
	// operations' host-route seam; ifaceAddrs lists every interface's IPv4
	// addresses for the start-up reconcile. All three are set by
	// newDarwinApplier and replaced only by unit tests.
	output     func(ctx context.Context, name string, args ...string) ([]byte, error)
	hostRoutes linkRouter
	ifaceAddrs func() (map[string][]netip.Addr, error)
	// withdraw removes the mesh's direct routes over an interface before its host
	// route goes (withdrawDirect in production).
	withdraw func(ctx context.Context, iface string) error
	// newDevice builds the mesh device (newWGDevice in production).
	newDevice func(cfg mesh.DeviceConfig, log *slog.Logger) meshDevice

	// linkMu serializes the link operations; links are the ports configured,
	// guarded by linkMu. Lock order: linkMu, then mu.
	linkMu sync.Mutex
	links  map[string]LinkSpec

	aliasMu sync.Mutex
	aliased map[netip.Addr]aliasState
	pods    localPods

	mu          sync.Mutex
	nodePodCIDR netip.Prefix
	meshIP      netip.Addr // derived from nodePodCIDR; invalid if the CIDR is bad
	linkIP      netip.Addr // the mesh utun's own p2p address; same derivation contract
	dev         meshDevice
	meshUp      bool
}

// newDarwinApplier builds the production executor for a node whose pod /24 is
// nodePodCIDR. The mesh-egress source is derived once; if nodePodCIDR is not a
// usable /24 the derivation fails and mesh operations return an error (alias/port
// operations are unaffected).
func newDarwinApplier(nodePodCIDR netip.Prefix, log *slog.Logger) *darwinApplier {
	if log == nil {
		log = slog.Default()
	}
	meshIP, _ := podnet.MeshEgressIP(nodePodCIDR)
	linkIP, _ := podnet.MeshLinkIP(nodePodCIDR)
	a := &darwinApplier{
		nodePodCIDR: nodePodCIDR,
		meshIP:      meshIP,
		linkIP:      linkIP,
		utunName:    "utun",
		log:         log,
		command:     run,
		routes:      podnet.BlackholeRoutes{},
		aliased:     make(map[netip.Addr]aliasState),
		output:      runOutput,
		hostRoutes:  mesh.NewHostRoutes(),
		ifaceAddrs:  interfaceIPv4Addrs,
		links:       make(map[string]LinkSpec),
		newDevice:   newWGDevice,
	}
	a.withdraw = a.withdrawDirect
	return a
}

// isPodAddress reports whether ip is a pod address of the node /24 this applier
// currently serves, reading nodePodCIDR under mu.
func (a *darwinApplier) isPodAddress(ip netip.Addr) bool {
	a.mu.Lock()
	cidr := a.nodePodCIDR
	a.mu.Unlock()
	return podnet.IsPodAddress(cidr, ip)
}

// EnsureAlias adds ip as a /32 alias on lo0. For a pod address it first clears
// any blackhole left by the address's previous teardown — a stale blackhole must
// never shadow a new pod — and fails if that clear fails.
func (a *darwinApplier) EnsureAlias(ctx context.Context, ip netip.Addr) error {
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	if a.isPodAddress(ip) {
		// Allocated before anything is plumbed: the mesh never refuses a SYN to an
		// address that may already be live.
		a.pods.add(ip)
		if err := a.routes.Clear(ctx, ip); err != nil {
			return fmt.Errorf("ensure lo0 alias %s: %w", ip, err)
		}
	}
	if err := a.command(ctx, "ifconfig", "lo0", "alias", fmt.Sprintf("%s/32", ip)); err != nil {
		return fmt.Errorf("ifconfig lo0 alias %s/32: %w", ip, err)
	}
	a.aliased[ip] = aliasLive
	if !a.isPodAddress(ip) {
		return nil
	}
	// Then onto the mesh utun, if there is one; ConfigureMesh plumbs the set when
	// the utun comes up later. A refusal is returned, and the lo0 alias stays for
	// the client's retry (EnsureAlias is idempotent).
	if iface, link := a.meshUTUN(); iface != "" {
		if err := a.command(ctx, "ifconfig", mesh.UTUNAliasArgs(iface, ip, link)...); err != nil {
			return fmt.Errorf("alias %s onto the mesh utun %s: %w", ip, iface, err)
		}
	}
	return nil
}

// meshUTUN returns the mesh utun's name and its own link address while the mesh
// is up, or "" when there is no utun.
func (a *darwinApplier) meshUTUN() (string, netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.meshUTUNLocked()
}

// meshUTUNLocked is meshUTUN with mu held.
func (a *darwinApplier) meshUTUNLocked() (string, netip.Addr) {
	if !a.meshUp || a.dev == nil {
		return "", netip.Addr{}
	}
	return a.dev.Interface(), a.linkIP
}

// reconcileUTUNAliases converges the mesh utun's pod-address aliases on the pod
// addresses of the node /24 that are aliased on lo0, read back from the kernel:
// a utun alias whose lo0 twin is gone is removed first, then a missing one is
// added. lo0 is the truth because it is the address's home and survives a daemon
// restart, which the utun (owned by the daemon's wireguard device) does not; so
// the first ConfigureMesh after a start, or after a utun is re-created, re-plumbs
// every live pod. The mesh-egress and link addresses are not pod addresses
// (podnet.IsPodAddress) and are left to the device. It issues alias operations
// only, never a route operation. aliasMu and mu must be held.
func (a *darwinApplier) reconcileUTUNAliases(ctx context.Context) error {
	iface, link := a.meshUTUNLocked()
	if iface == "" {
		return nil
	}
	// A partial read changes nothing: an lo0 list missing an address would remove a
	// live pod's utun alias.
	addrs, err := a.ifaceAddrs()
	if err != nil {
		return fmt.Errorf("read interface addresses for the mesh utun aliases: %w", err)
	}
	want := podAddresses(a.nodePodCIDR, addrs["lo0"])
	have := podAddresses(a.nodePodCIDR, addrs[iface])
	var errs []error
	for _, ip := range have {
		if slices.Contains(want, ip) {
			continue
		}
		if err := a.command(ctx, "ifconfig", mesh.UTUNUnaliasArgs(iface, ip)...); err != nil {
			errs = append(errs, fmt.Errorf("remove stale utun alias %s from %s: %w", ip, iface, err))
			continue
		}
		a.log.Info("netd: removed a utun alias whose lo0 alias is gone", "iface", iface, "ip", ip.String())
	}
	for _, ip := range want {
		if slices.Contains(have, ip) {
			continue
		}
		if err := a.command(ctx, "ifconfig", mesh.UTUNAliasArgs(iface, ip, link)...); err != nil {
			errs = append(errs, fmt.Errorf("alias %s onto the mesh utun %s: %w", ip, iface, err))
		}
	}
	return errors.Join(errs...)
}

// seedPodsLocked replaces the allocation with the pod addresses of the node /24 on
// lo0, read back from the kernel, plus every address this executor has aliased; a
// failed read forgets it instead (every address allocated). aliasMu and mu must be
// held, so no alias change interleaves.
func (a *darwinApplier) seedPodsLocked() {
	addrs, err := a.ifaceAddrs()
	if err != nil {
		a.pods.forget()
		a.log.Warn("netd: cannot read lo0; refusing no SYN until it can be read", "err", err)
		return
	}
	ips := podAddresses(a.nodePodCIDR, addrs["lo0"])
	for ip, st := range a.aliased {
		if st == aliasLive && podnet.IsPodAddress(a.nodePodCIDR, ip) {
			ips = append(ips, ip)
		}
	}
	a.pods.reset(ips)
}

// podAddresses returns the pod addresses of cidr among ips, sorted.
func podAddresses(cidr netip.Prefix, ips []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, ip := range ips {
		if podnet.IsPodAddress(cidr, ip) && !slices.Contains(out, ip) {
			out = append(out, ip)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// RemoveAlias removes ip's lo0 alias and, for a pod address that was aliased,
// installs its blackhole host route right after. An absent alias is tolerated
// (leak-free teardown), so the ifconfig error is logged, not returned.
//
// The blackhole is skipped, with a Debug line, for a pod address this applier
// does not track whose -alias found nothing on lo0: there is no alias, so no
// departed pod whose connections could re-route, and installing it would let any
// authorized peer blackhole an unused address of the /24 until it is next aliased.
// A tracked address is blackholed even when its -alias fails, and the install
// fails closed on a live non-blackhole host route, so an alias that would not go
// is reported rather than hidden.
//
// A failed blackhole install IS returned, and the address stays tracked as
// pending: the client keeps the address allocated and retries the teardown, the
// retry skips the -alias and re-runs the install, so the address is never reused
// while a departed pod's connections could re-route.
func (a *darwinApplier) RemoveAlias(ctx context.Context, ip netip.Addr) error {
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	state, tracked := a.aliased[ip]
	// The mesh utun alias goes first, so the address is never on the utun without
	// its lo0 home. An absent one is tolerated, like the lo0 -alias below; a utun
	// alias that would not go is left to the next ConfigureMesh's reconcile.
	if a.isPodAddress(ip) {
		if iface, _ := a.meshUTUN(); iface != "" {
			if err := a.command(ctx, "ifconfig", mesh.UTUNUnaliasArgs(iface, ip)...); err != nil {
				a.log.Debug("utun -alias tolerated (address may be absent)", "iface", iface, "ip", ip.String(), "err", err)
			}
		}
	}
	removed := false
	if tracked && state == aliasBlackholePending {
		a.log.Debug("lo0 alias already removed; retrying its blackhole", "ip", ip.String())
	} else if err := a.command(ctx, "ifconfig", "lo0", "-alias", ip.String()); err != nil {
		a.log.Debug("ifconfig lo0 -alias tolerated (address may be absent)", "ip", ip.String(), "err", err)
	} else {
		removed = true
	}
	if !a.isPodAddress(ip) {
		delete(a.aliased, ip)
		return nil
	}
	if removed || (tracked && state == aliasBlackholePending) {
		// The lo0 alias is known gone: a SYN to it is now the mesh's to refuse.
		a.pods.remove(ip)
	}
	if !tracked && !removed {
		a.log.Debug("lo0 alias was never plumbed; no blackhole installed", "ip", ip.String())
		return nil
	}
	if err := a.routes.Install(ctx, ip); err != nil {
		a.aliased[ip] = aliasBlackholePending
		return fmt.Errorf("remove lo0 alias %s: %w", ip, err)
	}
	delete(a.aliased, ip)
	return nil
}

// sweepBlackholes clears every blackhole host route held for a pod address of
// cidr and returns how many it cleared. Clear deletes a host route only when it
// carries RTF_BLACKHOLE, and an address's alias and its blackhole are the same
// /32 key, so no live alias's route can be touched. aliasMu must be held.
func (a *darwinApplier) sweepBlackholes(ctx context.Context, cidr netip.Prefix) (int, error) {
	ips, err := a.routes.List(ctx, cidr)
	if err != nil {
		return 0, err
	}
	var errs []error
	n := 0
	for _, ip := range ips {
		if err := a.routes.Clear(ctx, ip); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// sweepStaleBlackholes clears, at daemon start, the blackholes left inside the
// node pod /24 the applier serves. A teardown can leave one behind for good: the
// daemon crashing between a -alias and the blackhole's later clear, or a pod that
// never came back to its address. A fresh daemon has no alias tracked and no pod
// teardown in flight, so nothing it holds is protected by those routes — a pod
// re-plumbed afterwards clears its own anyway — and they would otherwise sit in
// the table until the address is next aliased. The residual: a connection another
// process still holds to a pod torn down just before a daemon restart loses its
// blackhole here. A failure is logged, never fatal:
// a leftover blackhole is harmless, and the daemon must start.
func (a *darwinApplier) sweepStaleBlackholes(ctx context.Context) {
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	a.mu.Lock()
	cidr := a.nodePodCIDR
	a.mu.Unlock()
	n, err := a.sweepBlackholes(ctx, cidr)
	if err != nil {
		a.log.Warn("netd: sweeping stale pod-address blackholes at start", "nodePodCIDR", cidr.String(), "swept", n, "err", err)
		return
	}
	if n > 0 {
		a.log.Info("netd: swept stale pod-address blackholes at start", "nodePodCIDR", cidr.String(), "swept", n)
	}
}

// SetNodePodCIDR re-points the applier at cidr and re-derives the two addresses the
// mesh needs from it. It refuses while the mesh is UP — those addresses are already
// programmed on a live utun, so changing them behind it would leave the device
// carrying an identity the daemon no longer believes in (the server refuses such an
// adoption too; this is the executor-side backstop).
//
// With the mesh down, a device built from the OLD CIDR is torn down before it is
// dropped. Dropping the reference alone would leak: a device whose Up failed partway
// holds an open utun and possibly a lo0 mesh-egress alias, and nothing else in the
// daemon still has a handle on it. Down is idempotent and leak-free, so calling it
// on a never-upped or already-downed device is safe; its error is only logged,
// because a stale device's teardown must not fail an adoption that is otherwise
// admissible.
//
// A changed CIDR also sweeps the blackhole host routes of the OLD /24 and drops
// the applier's alias tracking for it. Those routes stood in for departed pods of
// a /24 this node no longer serves; left behind, they would blackhole another
// node's pods on this host once the old /24 is routed over the mesh. Only routes
// flagged RTF_BLACKHOLE are deleted, and a sweep failure is logged, not returned,
// for the same reason as the device teardown.
func (a *darwinApplier) SetNodePodCIDR(ctx context.Context, cidr netip.Prefix) error {
	meshIP, err := podnet.MeshEgressIP(cidr)
	if err != nil {
		return fmt.Errorf("derive mesh-egress source for %s: %w", cidr, err)
	}
	linkIP, err := podnet.MeshLinkIP(cidr)
	if err != nil {
		return fmt.Errorf("derive mesh link address for %s: %w", cidr, err)
	}
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	a.mu.Lock()
	if a.meshUp {
		old := a.nodePodCIDR
		a.mu.Unlock()
		return fmt.Errorf("mesh is up on node podCIDR %s: refusing to re-derive its addresses", old)
	}
	if a.dev != nil {
		if err := a.dev.Down(ctx); err != nil {
			a.log.Debug("tearing down the device built from the previous node podCIDR", "nodePodCIDR", a.nodePodCIDR.String(), "err", err)
		}
		a.dev = nil
	}
	old := a.nodePodCIDR
	a.nodePodCIDR, a.meshIP, a.linkIP = cidr, meshIP, linkIP
	a.mu.Unlock()
	if old == cidr {
		return nil
	}
	a.pods.forget()
	for ip := range a.aliased {
		if podnet.IsPodAddress(old, ip) {
			delete(a.aliased, ip)
		}
	}
	if n, err := a.sweepBlackholes(ctx, old); err != nil {
		a.log.Warn("netd: sweeping the previous node podCIDR's blackholes", "nodePodCIDR", old.String(), "swept", n, "err", err)
	} else if n > 0 {
		a.log.Info("netd: swept the previous node podCIDR's blackholes", "nodePodCIDR", old.String(), "swept", n)
	}
	return nil
}

// ConfigureMesh builds (once) and brings up the real wireguard device with the
// resolved private key and listen port, applies the validated plan, and then
// reconciles the pod addresses' utun aliases (reconcileUTUNAliases) — on every
// call, so a freshly created utun gets the live set and any drift is repaired by
// the next resync. A reconcile failure is returned after the plan is applied.
func (a *darwinApplier) ConfigureMesh(ctx context.Context, privKeyB64 string, listenPort int, plan mesh.Plan) error {
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	// The allocation the device's SYN refusal consults is read from lo0 BEFORE the
	// device can come up, and again on every resync.
	a.seedPodsLocked()
	if a.dev == nil {
		if !a.meshIP.IsValid() || !a.linkIP.IsValid() {
			return fmt.Errorf("configure mesh: node podCIDR %s has no mesh-egress source or utun link address", a.nodePodCIDR)
		}
		a.dev = a.newDevice(mesh.DeviceConfig{
			UTUNName:      a.utunName,
			MeshIP:        a.meshIP,
			LinkIP:        a.linkIP,
			PrivateKeyB64: privKeyB64,
			ListenPort:    listenPort,
			NodePodCIDR:   a.nodePodCIDR,
			Allocated:     a.pods.allocated,
		}, a.log)
	}
	if !a.meshUp {
		if err := a.dev.Up(ctx); err != nil {
			return fmt.Errorf("mesh up: %w", err)
		}
		a.meshUp = true
	}
	var errs []error
	if err := a.dev.Apply(ctx, plan); err != nil {
		errs = append(errs, fmt.Errorf("apply mesh plan: %w", err))
	}
	if err := a.reconcileUTUNAliases(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// RemoveMesh tears the wireguard mesh down.
func (a *darwinApplier) RemoveMesh(ctx context.Context) error {
	// Take aliasMu first, as ConfigureMesh does (lock order aliasMu, then mu), so an
	// alias operation never reads the utun name just before Down destroys it.
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dev == nil || !a.meshUp {
		return nil
	}
	if err := a.dev.Down(ctx); err != nil {
		return fmt.Errorf("mesh down: %w", err)
	}
	a.meshUp = false
	return nil
}

// BindPort binds a listening socket on addr and returns it as an *os.File so the
// server can pass the descriptor to the client over SCM_RIGHTS. The original
// listener is closed after the descriptor is duplicated; the kernel keeps the
// socket alive while the passed descriptor is open.
func (a *darwinApplier) BindPort(_ context.Context, network string, addr netip.AddrPort) (*os.File, error) {
	switch network {
	case "tcp":
		ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
		if err != nil {
			return nil, fmt.Errorf("listen tcp %s: %w", addr, err)
		}
		f, err := ln.File()
		_ = ln.Close()
		if err != nil {
			return nil, fmt.Errorf("dup tcp socket %s: %w", addr, err)
		}
		return f, nil
	case "udp":
		c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
		if err != nil {
			return nil, fmt.Errorf("listen udp %s: %w", addr, err)
		}
		f, err := c.File()
		_ = c.Close()
		if err != nil {
			return nil, fmt.Errorf("dup udp socket %s: %w", addr, err)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("bind port: unsupported network %q", network)
	}
}

// runOutput runs a command and returns its standard output.
func runOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, fmt.Errorf("%w: %s", err, bytes.TrimSpace(ee.Stderr))
		}
		return out, err
	}
	return out, nil
}

// run invokes a root-gated command, wrapping any failure with its combined output.
func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
