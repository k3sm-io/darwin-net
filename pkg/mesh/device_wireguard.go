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
// job — the full pf sub-anchor is M4; M3 pulls only this minimal clamp forward. It
// is exported so the netd daemon (k3sm.io/darwin-net/pkg/netd) loads the standalone
// MSS-clamp verb into the same anchor.
const PFAnchor = "io.k3sm.mesh"

// wgLink is the immutable configuration of the real wireguard device.
type wgLink struct {
	name          string // requested utun name ("utun" lets the kernel pick a unit)
	mtu           int
	mss           int
	meshIP        netip.Addr
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
// Datapath design: the mesh-egress source (meshIP, podnet.MeshEgressIP) is plumbed
// as an lo0 /32 alias — the same proven-bindable mechanism the pod IPs use — so the
// Service proxy can bind it as the dialer source, while the utun itself is brought
// up addressless and carries only the per-peer /24 kernel routes. Inbound packets
// destined to meshIP are delivered locally (it is an lo0 address); outbound packets
// to a peer /24 match the per-peer route to the utun and egress with meshIP as the
// source (inside the node's own AllowedIPs).
//
// Locking discipline: all mutable state (the device handle, the actual interface
// name, and the installed-route set) is guarded by mu, so Up/Apply/Down serialize.
type WGDevice struct {
	cfg wgLink
	log *slog.Logger

	mu        sync.Mutex
	iface     string // resolved interface name after CreateTUN (e.g. "utun4")
	dev       *device.Device
	tun       tun.Device
	routes    map[netip.Prefix]struct{}
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
		privateKeyB64: cfg.PrivateKeyB64,
		listenPort:    port,
	}, log)
}

// newWGDevice constructs the production Device from its internal link config.
func newWGDevice(cfg wgLink, log *slog.Logger) *WGDevice {
	if log == nil {
		log = slog.Default()
	}
	return &WGDevice{cfg: cfg, log: log, routes: make(map[netip.Prefix]struct{})}
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
// plumbs the mesh-egress lo0 alias, and loads the MSS-clamp pf anchor. It fails
// fast if the private key is missing (hard cut — the operator provisions it; no
// embedded default) and is idempotent (a second Up is a no-op once the device is
// running).
func (d *WGDevice) Up(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev != nil {
		return nil
	}
	if d.cfg.privateKeyB64 == "" {
		return fmt.Errorf("%w: mesh private key not provided", ErrPeerConfig)
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
	d.pfApplied = true
	d.log.Info("mesh device up", "iface", name, "meshIP", d.cfg.meshIP.String(), "mtu", d.cfg.mtu, "mss", d.cfg.mss, "listenPort", d.cfg.listenPort)
	return nil
}

// Apply sets the wireguard peers (full replacement) and reconciles the kernel
// routes to exactly plan.Routes, each routed to the utun. It must be called after
// Up.
func (d *WGDevice) Apply(ctx context.Context, plan Plan) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev == nil {
		return fmt.Errorf("%w: mesh device not up", ErrPeerConfig)
	}
	if err := d.dev.IpcSet(plan.UAPI()); err != nil {
		return fmt.Errorf("apply wireguard peers: %w", err)
	}

	want := make(map[netip.Prefix]struct{}, len(plan.Routes))
	for _, r := range plan.Routes {
		want[r] = struct{}{}
	}
	// Add missing peer routes.
	for r := range want {
		if _, ok := d.routes[r]; ok {
			continue
		}
		if err := d.run(ctx, "route", "-n", "add", "-net", r.String(), "-interface", d.iface); err != nil {
			return fmt.Errorf("add mesh route %s -> %s: %w", r, d.iface, err)
		}
		d.routes[r] = struct{}{}
	}
	// Remove stale routes (a departed peer or a changed podCIDR).
	for r := range d.routes {
		if _, ok := want[r]; ok {
			continue
		}
		if err := d.run(ctx, "route", "-n", "delete", "-net", r.String(), "-interface", d.iface); err != nil {
			d.log.Warn("delete stale mesh route", "route", r.String(), "iface", d.iface, "err", err)
			continue
		}
		delete(d.routes, r)
	}
	d.log.Info("mesh peers applied", "peers", len(plan.Peers), "routes", len(d.routes), "skipped", len(plan.Skipped))
	return nil
}

// Down removes every route the device installed, unloads the pf anchor, removes
// the mesh-egress alias, and closes the wireguard device. It is leak-free and
// idempotent.
func (d *WGDevice) Down(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for r := range d.routes {
		if err := d.run(ctx, "route", "-n", "delete", "-net", r.String(), "-interface", d.iface); err != nil {
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
