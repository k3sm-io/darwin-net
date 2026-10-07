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
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// PFAnchor is the pf anchor name older releases loaded a TCP MSS-clamp rule into.
// Nothing loads it now: the main pf ruleset never referenced it, so the rule was
// never evaluated, and k3sm does not own pf. The name is kept only so teardown
// (WGDevice.Down) and the k3sm uninstall can flush an anchor an older release left
// behind.
const PFAnchor = "io.k3sm.mesh"

// commandFunc runs one host command and returns its combined output. It is the
// single seam every command the WGDevice spawns goes through, so the full set of
// host mutations bring-up and teardown make is observable in an unprivileged test.
type commandFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// execCommand is the production commandFunc.
func execCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// wgLink is the immutable configuration of the real wireguard device.
type wgLink struct {
	name          string // requested utun name ("utun" lets the kernel pick a unit)
	mtu           int
	meshIP        netip.Addr
	linkIP        netip.Addr
	privateKeyB64 string
	listenPort    int
	// nodePodCIDR and allocated drive the SYN refusal (refuser); a nil allocated
	// leaves the utun unwrapped.
	nodePodCIDR netip.Prefix
	allocated   func(netip.Addr) bool
}

// DeviceConfig is the construction config for the production wireguard Device. It
// is the exported seam the netd daemon (k3sm.io/darwin-net/pkg/netd) uses to build
// the real datapath after it has authenticated the peer and validated+rendered a
// Plan; the Mesh controller builds the same device internally from its options.
// Zero fields take the package defaults (MTU, DefaultListenPort, "utun").
type DeviceConfig struct {
	// UTUNName is the requested utun name; "" or "utun" lets the kernel pick the unit.
	UTUNName string
	// MTU is the tunnel MTU; 0 uses MTU.
	MTU int
	// MeshIP is the node's reserved mesh-egress /32 (podnet.MeshEgressIP), plumbed as
	// an lo0 alias so the Service proxy can bind it as the backend dialer source, and
	// aliased onto the utun too so the kernel can answer for it over the mesh.
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
	// NodePodCIDR is the node's pod /24 and Allocated reports whether a pod of this
	// node holds an address of it. With both set, a TCP SYN a peer sends over the
	// tunnel to an address of the /24 no pod holds is answered with a RST instead
	// of being dropped by the kernel (see refuser), so a dial of a deleted pod's
	// address is refused at once. Allocated is called on the receive path and must
	// be cheap and safe for concurrent use; it must answer true whenever it is
	// unsure. A nil Allocated turns the refusal off.
	NodePodCIDR netip.Prefix
	Allocated   func(netip.Addr) bool
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
// reached OVER the utun: making meshIP the utun's own address installs a host route
// for it via the tunnel, so a same-node dial of the node's own mesh IP is encrypted
// and dropped (no peer's AllowedIPs covers this node's own address) instead of
// looping back.
//
// Every node-local address that lives on lo0 (meshIP here, the pod addresses in
// the netd executor) is ALSO aliased onto the utun, with UTUNAliasArgs. A packet
// that arrives on the utun is delivered to such an address, but a reply the kernel
// generates itself (a TCP RST for a closed port, an ICMP echo reply) is scoped to
// the arrival interface, and ip_output drops it with EADDRNOTAVAIL when its source
// is not an address of that interface: the peer's dial hangs instead of being
// refused. The utun alias is point-to-point with the utun's own link address as
// destination, so it installs no route (the host route to the link address is
// already there) and lo0 stays the address's home: its lo0 host route still
// carries every local dial.
//
// Locking discipline: all mutable state (the device handle, the actual interface
// name, and the installed-route set) is guarded by mu, so Up/Apply/Down serialize.
type WGDevice struct {
	cfg     wgLink
	log     *slog.Logger
	rt      routeTable
	command commandFunc // every spawned host command (ifconfig, pfctl) goes through it

	mu    sync.Mutex
	iface string // resolved interface name after CreateTUN (e.g. "utun4")
	dev   wgControl
	tun   tun.Device
	// routes is the set of routes this device has VERIFIED in the kernel table,
	// keyed by prefix (a plan never wants two routes for one prefix) and
	// re-derived from a read-back on every apply — never a record of the route
	// requests that were made (an accepted write is not a route in the table).
	routes   map[netip.Prefix]RouteSpec
	applied  AppliedEndpoints // endpoints this device last programmed, per peer key
	lastUAPI string           // the peer update IpcSet last accepted; "" once the device is gone
}

// wgControl is the slice of *device.Device the applier drives: the UAPI write,
// the bring-up, and the close. It exists so the Apply path — in particular the
// decision to write or skip a peer update — is testable against a recorder with no
// utun and no wireguard in play; Up always installs the real device.
//
// Apply's IpcSet-skip rests on an invariant this interface does not enforce:
// nothing else in this process, and no other UAPI listener on the host (there is
// none in this tree), writes this device's peer table. lastUAPI is the applier's
// own memory of what it last wrote, not a read-back, so a second writer would
// make that memory wrong; introducing one would have to clear it on every write
// that isn't the applier's own.
type wgControl interface {
	IpcSet(uapi string) error
	Up() error
	Close()
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
	port := cfg.ListenPort
	if port == 0 {
		port = DefaultListenPort
	}
	return newWGDevice(wgLink{
		name:          name,
		mtu:           mtu,
		meshIP:        cfg.MeshIP,
		linkIP:        cfg.LinkIP,
		privateKeyB64: cfg.PrivateKeyB64,
		listenPort:    port,
		nodePodCIDR:   cfg.NodePodCIDR,
		allocated:     cfg.Allocated,
	}, log)
}

// newWGDevice constructs the production Device from its internal link config,
// backed by the real kernel routing table.
func newWGDevice(cfg wgLink, log *slog.Logger) *WGDevice {
	if log == nil {
		log = slog.Default()
	}
	return &WGDevice{
		cfg:     cfg,
		log:     log,
		rt:      kernelRouteTable{},
		command: execCommand,
		routes:  make(map[netip.Prefix]RouteSpec),
	}
}

// Interface returns the resolved utun name (e.g. "utun4") once Up has run, or the
// empty string before.
func (d *WGDevice) Interface() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.iface
}

// Up creates the utun, starts wireguard with the node's private key + listen port,
// and plumbs the host side (plumb: the utun's own mesh-link address and the
// mesh-egress lo0 alias). It loads no pf rule: XNU takes a connection's TCP MSS
// from the route to the destination, which for a peer pod CIDR is the utun at
// MTU. It fails fast if the private key or the mesh-link
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
	dev := device.NewDevice(d.wrapTUN(tunDev, name), conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, d.cfg.listenPort)); err != nil {
		dev.Close()
		return fmt.Errorf("configure wireguard private key: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring wireguard device up: %w", err)
	}

	if err := d.plumb(ctx, name); err != nil {
		dev.Close()
		return err
	}

	d.iface = name
	d.dev = dev
	d.tun = tunDev
	// A freshly created wireguard device has no peers, so the applier's
	// endpoint memory starts empty: the next Apply is a full resync that
	// programs every peer's CR endpoint.
	d.applied = nil
	d.lastUAPI = ""
	d.log.Info("mesh device up", "iface", name, "meshIP", d.cfg.meshIP.String(), "linkIP", d.cfg.linkIP.String(), "mtu", d.cfg.mtu, "listenPort", d.cfg.listenPort)
	return nil
}

// wrapTUN returns the tun.Device wireguard drives: tunDev itself, or the refuser
// over it when the config carries an allocation (see DeviceConfig.Allocated).
func (d *WGDevice) wrapTUN(tunDev tun.Device, name string) tun.Device {
	if d.cfg.allocated == nil || !d.cfg.nodePodCIDR.IsValid() {
		return tunDev
	}
	node, allocated := d.cfg.nodePodCIDR, d.cfg.allocated
	wake, rearm := utunWake(tunDev)
	r := newRefuser(tunDev, func(pkt []byte) bool { return refuseSYN(pkt, node, allocated) }, wake, rearm)
	r.onWakeErr = func(err error) {
		d.log.Warn("mesh: cannot wake the utun reader; a refusal waits for the next outbound packet", "iface", name, "err", err)
	}
	return r
}

// plumb performs the host-side bring-up on the created utun name: it assigns the
// utun's own point-to-point mesh-link address, plumbs the mesh-egress source as an
// lo0 /32 alias, and then aliases it onto the utun (UTUNAliasArgs). Every command goes through d.command, so it is driven without
// privilege in tests. The caller holds mu and closes the device on error.
func (d *WGDevice) plumb(ctx context.Context, name string) error {
	// The utun's own point-to-point address. It is what makes the per-peer routes
	// installable: macOS resolves an interface-bound route's source address from an
	// address on that interface, so RTM_ADD against an ADDRESSLESS utun is rejected
	// with ENETUNREACH. Every peer route silently failed to land before this
	// address existed (the applier then drove route(8), which prints that refusal
	// and still exits 0, so a caller that trusted the exit status never saw it).
	if err := d.run(ctx, "ifconfig", name, "inet", d.cfg.linkIP.String(), d.cfg.linkIP.String(), "netmask", "255.255.255.255", "up"); err != nil {
		return fmt.Errorf("assign mesh link address %s to %s: %w", d.cfg.linkIP, name, err)
	}
	// Mesh-egress source as an lo0 /32 alias (locally bindable by the proxy dialer).
	if err := d.run(ctx, "ifconfig", "lo0", "alias", fmt.Sprintf("%s/32", d.cfg.meshIP)); err != nil {
		return fmt.Errorf("plumb mesh-egress alias %s: %w", d.cfg.meshIP, err)
	}
	// And onto the utun, after lo0, so the kernel can answer a packet for it that
	// arrived over the mesh (see WGDevice).
	if err := d.run(ctx, "ifconfig", UTUNAliasArgs(name, d.cfg.meshIP, d.cfg.linkIP)...); err != nil {
		return fmt.Errorf("alias mesh-egress address %s onto %s: %w", d.cfg.meshIP, name, err)
	}
	return nil
}

// UTUNAliasArgs is the ifconfig argv that aliases ip onto the mesh utun iface as a
// point-to-point /32 whose destination is the utun's own link address link. The
// destination is what keeps the alias route-free: the kernel's host route to link
// already exists, so the alias adds none, and ip keeps its lo0 host route. It is
// the one home of that argv; the netd executor uses it for the pod addresses.
func UTUNAliasArgs(iface string, ip, link netip.Addr) []string {
	return []string{iface, "inet", ip.String(), link.String(), "netmask", "255.255.255.255", "alias"}
}

// UTUNUnaliasArgs is the ifconfig argv that removes ip's alias from the mesh utun
// iface. The alias never owned a route, so its removal deletes none.
func UTUNUnaliasArgs(iface string, ip netip.Addr) []string {
	return []string{iface, "inet", ip.String(), "-alias"}
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
//
// An update whose UAPI text is byte-identical to the one this device last wrote
// is not written again. UAPIUpdate never renders an empty update — an incremental
// update re-states every peer's AllowedIPs and keepalive — so "unchanged" is the
// only empty there is: identical text means the same peer set, the same
// AllowedIPs and keepalives, and no endpoint the roaming contract would re-stamp,
// which is exactly the periodic resync on a quiet cluster. The skip is a pure
// no-op elimination: IpcSet with that text would program what wireguard already
// holds. The route reconcile below is NOT skipped — the kernel table is outside
// this process and is re-verified on every apply regardless. The memory is
// cleared with the endpoint memory (Up, a failed IpcSet, Down), so a re-created
// device is always written in full.
//
// The settle after an endpoint transition costs two writes, not one: the
// transition's own render carries the endpoint= line, and the next incremental
// render — the roaming contract has now recorded the new endpoint, so it does
// not re-stamp it — differs textually and is written once more before the two
// converge. This recurs on every endpoint transition a peer makes over the
// device's life, not once per device lifetime.
func (d *WGDevice) Apply(ctx context.Context, plan Plan) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev == nil {
		return fmt.Errorf("%w: mesh device not up", ErrPeerConfig)
	}
	uapi, next := plan.UAPIUpdate(d.applied)
	written := uapi != d.lastUAPI
	if written {
		if err := d.dev.IpcSet(uapi); err != nil {
			d.applied = nil
			d.lastUAPI = ""
			return fmt.Errorf("apply wireguard peers: %w", err)
		}
		d.lastUAPI = uapi
	}
	d.applied = next

	installed, err := d.reconcileRoutes(ctx, plan.Routes)
	if err != nil {
		return err
	}
	d.log.Info("mesh peers applied", "peers", len(plan.Peers), "written", written, "routes", installed, "direct", len(plan.Direct), "skipped", len(plan.Skipped))
	return nil
}

// reconcileRoutes converges the kernel routing table on exactly want — one utun
// route per peer podCIDR, plus the two /25 gateway routes of each direct peer —
// and then VERIFIES the result by reading the kernel table back, returning the
// number of routes proven present.
//
// The read-back is the whole point. The routing-socket write's verdict is on the
// REQUEST, so "the kernel accepted the add" and "the route exists on our utun" are
// different claims and only the second one matters: a peer route that is missing
// sends that peer's pod traffic to the host default gateway, which fails as a
// silent cross-node blackhole rather than as an error anybody sees. So the device's
// own route set is re-derived from the table on every apply, and a route that is
// wanted but absent (or bound to another interface, through another gateway, or in
// the other form) fails the apply loudly with ErrRouteNotInstalled, quoting the
// routing socket's own report of the request.
//
// Ordering is what keeps a direct peer's traffic off the floor. Removals run
// first, gateway routes before utun routes; additions run after, utun routes
// before gateway routes. So a direct peer's /25s go before anything else of that
// peer does, and come only once its utun /24 is in place: there is never a moment
// with neither. A peer that stays never loses its utun /24 — only a departed peer's
// is removed. A route whose spec changed (a /25 that moved to another cable) is
// removed and re-added, which is safe for the same reason: the /24 carries the
// peer meanwhile.
//
// A stale route the delete did not remove is a warning, not a failure: the desired
// routes are all present, the lingering one stays owned so the next apply retries
// its removal. The caller holds mu.
func (d *WGDevice) reconcileRoutes(ctx context.Context, want []RouteSpec) (int, error) {
	desired := make(map[netip.Prefix]RouteSpec, len(want))
	for _, r := range want {
		desired[r.Prefix] = r
	}
	// Removals: routes owned but no longer wanted in that exact form.
	var stale []netip.Prefix
	for _, p := range sortedPrefixes(d.routes) {
		if w, ok := desired[p]; !ok || w != d.routes[p] {
			stale = append(stale, p)
		}
	}
	for _, direct := range []bool{true, false} {
		for _, p := range stale {
			r := d.routes[p]
			if r.Direct() != direct {
				continue
			}
			if _, err := d.rt.Delete(ctx, d.kernelRoute(r)); err != nil {
				d.log.Warn("delete stale mesh route", "route", r.String(), "iface", d.ifaceOf(r), "err", err)
			}
		}
	}
	// Additions: routes wanted and not owned in that exact form.
	reports := make(map[netip.Prefix]string, len(want))
	for _, direct := range []bool{false, true} {
		for _, p := range sortedPrefixes(desired) {
			r := desired[p]
			if r.Direct() != direct {
				continue
			}
			if have, ok := d.routes[p]; ok && have == r {
				continue
			}
			out, err := d.rt.Add(ctx, d.kernelRoute(r))
			reports[p] = out
			if err != nil {
				// Deliberately not fatal here: the kernel table below is the verdict.
				// EEXIST for a route the table already holds in this form is a mesh
				// that is fine, so an apply that stopped on this error would refuse to
				// converge it; the read-back tells that case from a route bound elsewhere.
				reports[p] = fmt.Sprintf("%s (error: %v)", out, err)
			}
		}
	}

	have, err := d.rt.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("read back kernel routes for %s: %w", d.iface, err)
	}
	verified := make(map[netip.Prefix]RouteSpec, len(desired))
	var missing []netip.Prefix
	for _, p := range sortedPrefixes(desired) {
		if !d.inKernel(have, desired[p]) {
			missing = append(missing, p)
			continue
		}
		verified[p] = desired[p]
	}
	var lingering []netip.Prefix
	for _, p := range stale {
		r := d.routes[p]
		if _, wanted := verified[p]; wanted {
			continue
		}
		if d.inKernel(have, r) {
			lingering = append(lingering, p)
			verified[p] = r // still ours to remove on the next apply
		}
	}
	d.routes = verified
	if len(missing) > 0 {
		return 0, fmt.Errorf("%w: %s absent from the kernel routing table%s",
			ErrRouteNotInstalled, d.formatSpecs(desired, missing), routeReport(reports[missing[0]]))
	}
	if len(lingering) > 0 {
		d.log.Warn("stale mesh routes still in the kernel table", "routes", formatPrefixes(lingering), "iface", d.iface)
	}
	return len(verified) - len(lingering), nil
}

// kernelRoute is the routing request for r: a utun route is a link route on the
// device's utun; a direct route is a gateway route bound to its cable interface
// and sourced from the node's mesh-egress address, so a host dial the kernel
// sources itself still leaves from inside this node's AllowedIPs when the cable
// goes and the packet falls back to the tunnel.
func (d *WGDevice) kernelRoute(r RouteSpec) Route {
	if r.Direct() {
		return Route{Prefix: r.Prefix, Interface: r.Iface, Gateway: r.Gateway, Source: d.cfg.meshIP}
	}
	return Route{Prefix: r.Prefix, Interface: d.iface}
}

// ifaceOf is the interface a route spec is bound to.
func (d *WGDevice) ifaceOf(r RouteSpec) string {
	if r.Direct() {
		return r.Iface
	}
	return d.iface
}

// inKernel reports whether the kernel table have holds r in its exact form.
func (d *WGDevice) inKernel(have []Route, r RouteSpec) bool {
	want := d.kernelRoute(r)
	for _, k := range have {
		if holds(k, want) {
			return true
		}
	}
	return false
}

// formatSpecs renders the named routes of set for an error message.
func (d *WGDevice) formatSpecs(set map[netip.Prefix]RouteSpec, ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = d.kernelRoute(set[p]).String()
	}
	return strings.Join(s, ", ")
}

// WithdrawIface removes every direct route this device holds on iface and returns
// how many it removed. The root helper calls it before it tears a cable down
// (RemoveLink) or re-points it at another peer, so the /25s always leave before
// the on-link host route they depend on. The utun routes are untouched. A route
// the read-back still finds is kept owned and reported, like a lingering stale
// route in reconcileRoutes.
func (d *WGDevice) WithdrawIface(ctx context.Context, iface string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var gone []netip.Prefix
	for _, p := range sortedPrefixes(d.routes) {
		r := d.routes[p]
		if !r.Direct() || r.Iface != iface {
			continue
		}
		if _, err := d.rt.Delete(ctx, d.kernelRoute(r)); err != nil {
			d.log.Warn("withdraw direct mesh route", "route", r.String(), "err", err)
		}
		gone = append(gone, p)
	}
	if len(gone) == 0 {
		return 0, nil
	}
	have, err := d.rt.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("read back kernel routes after withdrawing %s: %w", iface, err)
	}
	var left []netip.Prefix
	for _, p := range gone {
		if d.inKernel(have, d.routes[p]) {
			left = append(left, p)
			continue
		}
		delete(d.routes, p)
	}
	if len(left) > 0 {
		return len(gone) - len(left), fmt.Errorf("%w: direct routes %s on %s are still in the kernel table after their removal",
			ErrRouteNotInstalled, formatPrefixes(left), iface)
	}
	d.log.Warn("direct mesh routes withdrawn", "iface", iface, "routes", formatPrefixes(gone))
	return len(gone), nil
}

// Down removes every route the device installed, flushes the legacy PFAnchor,
// removes the mesh-egress aliases (the utun one, then lo0), and closes the wireguard device. It is leak-free
// and idempotent.
func (d *WGDevice) Down(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, direct := range []bool{true, false} {
		for _, p := range sortedPrefixes(d.routes) {
			r := d.routes[p]
			if r.Direct() != direct {
				continue
			}
			if _, err := d.rt.Delete(ctx, d.kernelRoute(r)); err != nil {
				d.log.Warn("delete mesh route on teardown", "route", r.String(), "err", err)
			}
			delete(d.routes, p)
		}
	}
	// Backstop, not a feature: this release loads nothing into PFAnchor, but an
	// older one loaded an MSS-clamp rule there. Flushing it unconditionally on every
	// teardown means an upgraded node self-cleans on its first Down. Best-effort and
	// warn-only: an empty or absent anchor, or no privilege, must not fail teardown.
	if err := d.run(ctx, "pfctl", "-a", PFAnchor, "-F", "all"); err != nil {
		d.log.Warn("flush legacy mesh pf anchor", "anchor", PFAnchor, "err", err)
	}
	if d.cfg.meshIP.IsValid() {
		// The utun alias goes before the lo0 one, so the address is never on the
		// utun alone. Both are best-effort: either may already be gone.
		if d.iface != "" {
			_ = d.run(ctx, "ifconfig", UTUNUnaliasArgs(d.iface, d.cfg.meshIP)...)
		}
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
	d.lastUAPI = ""
	d.log.Info("mesh device down", "iface", d.iface)
	return nil
}

// run invokes a root-gated command through the command seam, wrapping any failure
// with its combined output.
func (d *WGDevice) run(ctx context.Context, name string, args ...string) error {
	out, err := d.command(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, bytes.TrimSpace(out))
	}
	return nil
}
