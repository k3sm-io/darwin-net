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

package mesh

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// PFAnchor is the pf anchor the mesh loads its MSS-clamp rule into. Wiring the
// anchor into the main ruleset (anchor "io.k3sm.mesh") is the root netd boundary's
// job — the full pf sub-anchor is not built; this minimal clamp is pulled
// forward on its own here. It is exported so the netd daemon
// (k3sm.io/darwin-net/pkg/netd) loads the standalone MSS-clamp verb into the
// same anchor.
const PFAnchor = "io.k3sm.mesh"

// wgLink is the immutable configuration of the real wireguard device.
type wgLink struct {
	name          string // requested utun name ("utun" lets the kernel pick a unit)
	mtu           int
	mss           int
	meshIP        netip.Addr
	linkIP        netip.Addr
	privateKeyB64 string
	listenPort    int
}

// DeviceConfig is the construction config for the production wireguard Device. It
// is the exported seam the netd daemon (k3sm.io/darwin-net/pkg/netd) uses to build
// the real datapath after it has authenticated the peer and validated+rendered a
// Plan; the Mesh controller builds the same device internally from its options.
// Zero fields take the package defaults (MTU, MSSClamp, DefaultListenPort, "utun").
type DeviceConfig struct {
	// UTUNName is the requested utun name; "" or "utun" lets the kernel pick the unit.
	UTUNName string
	// MTU is the tunnel MTU; 0 uses MTU.
	MTU int
	// MSS is the TCP MSS the pf scrub anchor clamps to on the utun egress; 0 uses MSSClamp.
	MSS int
	// MeshIP is the node's reserved mesh-egress /32 (podnet.MeshEgressIP), plumbed as
	// an lo0 alias so the Service proxy can bind it as the backend dialer source.
	MeshIP netip.Addr
	// LinkIP is the node's reserved mesh-link /32 (podnet.MeshLinkIP), assigned as
	// the utun's own point-to-point interface address. It is REQUIRED: macOS refuses
	// every interface-bound route on an addressless utun, so without it no peer route
	// can be installed (see Up). It is deliberately distinct from MeshIP.
	LinkIP netip.Addr
	// PrivateKeyB64 is the node's wireguard PRIVATE key (base64). It never leaves the
	// node; the device fails fast at Up if it is empty.
	PrivateKeyB64 string
	// ListenPort is the UDP port wireguard listens on; 0 uses DefaultListenPort.
	ListenPort int
}

// WGDevice is the production Device: userspace wireguard (wireguard-go) over a
// root-created utun. Construction performs no syscalls (mirroring the lo0 alias
// managers); the privileged work happens in Up/Apply/Down and fails without root.
// In deployment it runs inside the netd daemon boundary.
//
// Datapath design — two addresses, each with one job:
//
//   - The mesh-egress source (meshIP, podnet.MeshEgressIP) is an lo0 /32 alias, the
//     same proven-bindable mechanism the pod IPs use. The Service proxy binds it as
//     its backend-dialer source and the node's control plane listens on it, both of
//     which need it locally bindable AND loopback-reachable. Inbound tunnel packets
//     addressed to it are still delivered and answered, because macOS accepts a
//     packet for any local address whichever interface it arrives on.
//   - The mesh-link address (linkIP, podnet.MeshLinkIP) is the utun's own
//     point-to-point interface address. It exists because macOS will not install an
//     interface-bound route on an ADDRESSLESS utun, so it is what makes the per-peer
//     routes installable at all (see Up).
//
// The two must not be collapsed into one. An address that lives ON the utun is
// reached OVER the utun: assigning meshIP there installs a host route for it via
// the tunnel, so a same-node dial of the node's own mesh IP is encrypted and dropped
// (no peer's AllowedIPs covers this node's own address) instead of looping back.
//
// Locking discipline: all mutable state (the device handle, the actual interface
// name, and the installed-route set) is guarded by mu, so Up/Apply/Down serialize.
type WGDevice struct {
	cfg wgLink
	log *slog.Logger
	rt  routeTable

	mu    sync.Mutex
	iface string // resolved interface name after CreateTUN (e.g. "utun4")
	dev   *device.Device
	tun   tun.Device
	// routes is the set of prefixes this device has VERIFIED in the kernel table,
	// re-derived from a read-back on every apply — never a record of the route
	// commands that were issued (route(8) reports success it did not achieve).
	routes    map[netip.Prefix]struct{}
	applied   AppliedEndpoints // endpoints this device last programmed, per peer key
	pfApplied bool
}

// NewDevice constructs the production wireguard Device from cfg. It performs no
// privileged operation; call Up to bring the mesh up. It is the exported entry the
// netd daemon uses to build the real datapath; the Mesh controller uses it too.
func NewDevice(cfg DeviceConfig, log *slog.Logger) *WGDevice {
	name := cfg.UTUNName
	if name == "" {
		name = "utun"
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = MTU
	}
	mss := cfg.MSS
	if mss == 0 {
		mss = MSSClamp
	}
	port := cfg.ListenPort
	if port == 0 {
		port = DefaultListenPort
	}
	return newWGDevice(wgLink{
		name:          name,
		mtu:           mtu,
		mss:           mss,
		meshIP:        cfg.MeshIP,
		linkIP:        cfg.LinkIP,
		privateKeyB64: cfg.PrivateKeyB64,
		listenPort:    port,
	}, log)
}

// newWGDevice constructs the production Device from its internal link config,
// backed by the real kernel routing table.
func newWGDevice(cfg wgLink, log *slog.Logger) *WGDevice {
	if log == nil {
		log = slog.Default()
	}
	return &WGDevice{
		cfg:    cfg,
		log:    log,
		rt:     kernelRouteTable{},
		routes: make(map[netip.Prefix]struct{}),
	}
}

// Interface returns the resolved utun name (e.g. "utun4") once Up has run, or the
// empty string before. It lets the netd daemon scope a standalone MSS-clamp pf
// rule to the live tunnel.
func (d *WGDevice) Interface() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.iface
}

// Up creates the utun, starts wireguard with the node's private key + listen port,
// assigns the utun's own mesh-link address, plumbs the mesh-egress lo0 alias, and
// loads the MSS-clamp pf anchor. It fails fast if the private key or the mesh-link
// address is missing (hard cut — the operator provisions them; no embedded default)
// and is idempotent (a second Up is a no-op once the device is running).
func (d *WGDevice) Up(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev != nil {
		return nil
	}
	if d.cfg.privateKeyB64 == "" {
		return fmt.Errorf("%w: mesh private key not provided", ErrPeerConfig)
	}
	if !d.cfg.linkIP.IsValid() {
		return fmt.Errorf("%w: mesh utun link address not provided (no peer route can be installed without it)", ErrPeerConfig)
	}
	privHex, err := wgKeyHex(d.cfg.privateKeyB64)
	if err != nil {
		return fmt.Errorf("mesh private key: %w", err)
	}

	tunDev, err := tun.CreateTUN(d.cfg.name, d.cfg.mtu)
	if err != nil {
		return fmt.Errorf("create utun %q: %w", d.cfg.name, err)
	}
	name, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return fmt.Errorf("resolve utun name: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", name))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, d.cfg.listenPort)); err != nil {
		dev.Close()
		return fmt.Errorf("configure wireguard private key: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring wireguard device up: %w", err)
	}

	// The utun's own point-to-point address. It is what makes the per-peer routes
	// installable: macOS resolves an interface-bound route's source address from an
	// address on that interface, so RTM_ADD against an ADDRESSLESS utun is rejected
	// with ENETUNREACH — and route(8) prints "writing to routing socket: Network is
	// unreachable" while still exiting 0, so the failure is invisible to a caller
	// that trusts the exit status. Every peer route silently failed to land before
	// this address existed.
	if err := d.run(ctx, "ifconfig", name, "inet", d.cfg.linkIP.String(), d.cfg.linkIP.String(), "netmask", "255.255.255.255", "up"); err != nil {
		dev.Close()
		return fmt.Errorf("assign mesh link address %s to %s: %w", d.cfg.linkIP, name, err)
	}
	// Mesh-egress source as an lo0 /32 alias (locally bindable by the proxy dialer).
	if err := d.run(ctx, "ifconfig", "lo0", "alias", fmt.Sprintf("%s/32", d.cfg.meshIP)); err != nil {
		dev.Close()
		return fmt.Errorf("plumb mesh-egress alias %s: %w", d.cfg.meshIP, err)
	}
	// Minimal utun-scoped MSS clamp (never lo0).
	if err := d.loadPF(ctx, name); err != nil {
		_ = d.run(ctx, "ifconfig", "lo0", "-alias", d.cfg.meshIP.String())
		dev.Close()
		return fmt.Errorf("load mesh pf anchor: %w", err)
	}

	d.iface = name
	d.dev = dev
	d.tun = tunDev
	// A freshly created wireguard device has no peers, so the applier's
	// endpoint memory starts empty: the next Apply is a full resync that
	// programs every peer's CR endpoint.
	d.applied = nil
	d.pfApplied = true
	d.log.Info("mesh device up", "iface", name, "meshIP", d.cfg.meshIP.String(), "linkIP", d.cfg.linkIP.String(), "mtu", d.cfg.mtu, "mss", d.cfg.mss, "listenPort", d.cfg.listenPort)
	return nil
}

// Apply programs the wireguard peers and reconciles the kernel routes to exactly
// plan.Routes, each routed to the utun and each VERIFIED against the kernel's own
// routing table before the apply reports success (reconcileRoutes). It must be
// called after Up.
//
// The peer write honours the endpoint-roaming contract (Plan.UAPIUpdate): the
// first apply after Up is a full resync that programs every CR endpoint, and each
// later apply is an incremental update that leaves an already-configured peer's
// endpoint alone — wireguard owns it once the peer has been heard from — while
// still reconciling AllowedIPs, keepalives, additions, and removals. A failed
// IpcSet leaves the device in an unknown state, so the memory is dropped and the
// next apply is a full resync again.
func (d *WGDevice) Apply(ctx context.Context, plan Plan) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev == nil {
		return fmt.Errorf("%w: mesh device not up", ErrPeerConfig)
	}
	uapi, next := plan.UAPIUpdate(d.applied)
	if err := d.dev.IpcSet(uapi); err != nil {
		d.applied = nil
		return fmt.Errorf("apply wireguard peers: %w", err)
	}
	d.applied = next

	installed, err := d.reconcileRoutes(ctx, plan.Routes)
	if err != nil {
		return err
	}
	d.log.Info("mesh peers applied", "peers", len(plan.Peers), "routes", installed, "skipped", len(plan.Skipped))
	return nil
}

// reconcileRoutes converges the kernel routing table on exactly want — one route
// per peer podCIDR, each bound to the mesh utun — and then VERIFIES the result by
// reading the kernel table back, returning the number of routes proven present.
//
// The read-back is the whole point. route(8) exits 0 even when the kernel rejected
// its routing-socket write, so "the command succeeded" and "the route exists" are
// different claims and only the second one matters: a peer route that is missing
// sends that peer's pod traffic to the host default gateway, which fails as a
// silent cross-node blackhole rather than as an error anybody sees. So the device's
// own route set is re-derived from the table on every apply, and a route that is
// wanted but absent (or bound to another interface) fails the apply loudly with
// ErrRouteNotInstalled, quoting route(8)'s own report of what it thought it did.
//
// A stale route the delete did not remove is a warning, not a failure: the desired
// routes are all present, the lingering one stays owned so the next apply retries
// its removal. The caller holds mu.
func (d *WGDevice) reconcileRoutes(ctx context.Context, want []netip.Prefix) (int, error) {
	desired := make(map[netip.Prefix]struct{}, len(want))
	for _, r := range want {
		desired[r] = struct{}{}
	}
	reports := make(map[netip.Prefix]string, len(want))
	for _, r := range sortedPrefixes(desired) {
		if _, ok := d.routes[r]; ok {
			continue
		}
		out, err := d.rt.Add(ctx, r, d.iface)
		reports[r] = out
		if err != nil {
			// Deliberately not fatal here: the kernel table below is the verdict.
			// route(8) reports failures that did not happen (adding a route that is
			// already present) as readily as successes that did not, so an apply that
			// stopped on this error would refuse to converge a mesh that is fine.
			reports[r] = fmt.Sprintf("%s (error: %v)", out, err)
		}
	}
	for _, r := range sortedPrefixes(d.routes) {
		if _, ok := desired[r]; ok {
			continue
		}
		if _, err := d.rt.Delete(ctx, r, d.iface); err != nil {
			d.log.Warn("delete stale mesh route", "route", r.String(), "iface", d.iface, "err", err)
		}
	}

	have, err := d.rt.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("read back kernel routes for %s: %w", d.iface, err)
	}
	onIface := prefixesOn(have, d.iface)
	verified := make(map[netip.Prefix]struct{}, len(desired))
	var missing []netip.Prefix
	for _, r := range sortedPrefixes(desired) {
		if _, ok := onIface[r]; !ok {
			missing = append(missing, r)
			continue
		}
		verified[r] = struct{}{}
	}
	var lingering []netip.Prefix
	for _, r := range sortedPrefixes(d.routes) {
		if _, ok := desired[r]; ok {
			continue
		}
		if _, ok := onIface[r]; ok {
			lingering = append(lingering, r)
			verified[r] = struct{}{} // still ours to remove on the next apply
		}
	}
	d.routes = verified
	if len(missing) > 0 {
		return 0, fmt.Errorf("%w: %s absent from the kernel routing table on %s%s",
			ErrRouteNotInstalled, formatPrefixes(missing), d.iface, routeReport(reports[missing[0]]))
	}
	if len(lingering) > 0 {
		d.log.Warn("stale mesh routes still in the kernel table", "routes", formatPrefixes(lingering), "iface", d.iface)
	}
	return len(verified) - len(lingering), nil
}

// Down removes every route the device installed, unloads the pf anchor, removes
// the mesh-egress alias, and closes the wireguard device. It is leak-free and
// idempotent.
func (d *WGDevice) Down(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range sortedPrefixes(d.routes) {
		if _, err := d.rt.Delete(ctx, r, d.iface); err != nil {
			d.log.Warn("delete mesh route on teardown", "route", r.String(), "err", err)
		}
		delete(d.routes, r)
	}
	if d.pfApplied {
		if err := d.run(ctx, "pfctl", "-a", PFAnchor, "-F", "all"); err != nil {
			d.log.Warn("flush mesh pf anchor", "anchor", PFAnchor, "err", err)
		}
		d.pfApplied = false
	}
	if d.cfg.meshIP.IsValid() {
		_ = d.run(ctx, "ifconfig", "lo0", "-alias", d.cfg.meshIP.String())
	}
	if d.dev != nil {
		d.dev.Close()
		d.dev = nil
		d.tun = nil
	}
	// The peers died with the device; forget what was programmed so a later Up +
	// Apply re-programs every endpoint rather than suppressing them all.
	d.applied = nil
	d.log.Info("mesh device down", "iface", d.iface)
	return nil
}

// loadPF loads the utun-scoped MSS-clamp rule into the mesh pf anchor.
func (d *WGDevice) loadPF(ctx context.Context, iface string) error {
	cmd := exec.CommandContext(ctx, "pfctl", "-a", PFAnchor, "-f", "-")
	cmd.Stdin = bytes.NewBufferString(PFMSSClampRule(iface, d.cfg.mss))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// run invokes a root-gated command, wrapping any failure with its combined output.
func (d *WGDevice) run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, bytes.TrimSpace(out))
	}
	return nil
}
