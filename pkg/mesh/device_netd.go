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
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// helperClient is the slice of the netd wire client the helper-backed device
// drives. It is defined here, at the consumer, so the version gate is tested
// against a scripted helper with no socket; *wire.Client is the production one.
type helperClient interface {
	ConfigureMesh(ctx context.Context, privKeyRef string, listenPort int, nodePodCIDR netip.Prefix, peers []wire.MeshPeerArg, direct []wire.DirectRouteArg) error
	RemoveMesh(ctx context.Context) error
	ConfigureLink(ctx context.Context, args wire.ConfigureLinkArgs) (netip.Addr, error)
	RemoveLink(ctx context.Context, iface string) error
	HelperVersion() (wire.Version, bool)
}

// netdDevice is the helper-backed Device: instead of creating a utun and driving
// wireguard itself, it sends the typed peer set to the root netd daemon over a
// unix socket and the daemon renders the UAPI and installs the routes. It lets an unprivileged process run the mesh controller while
// the irreducibly-root datapath stays behind the daemon boundary.
//
// It satisfies Device. The daemon's ConfigureMesh is the combined bring-up + apply
// (it creates the utun and sets the key on first call, then programs peers), so Up
// sends an empty-peer ConfigureMesh and Apply sends the rendered peer set. The
// private key never crosses the socket — only privKeyRef does, which the daemon
// resolves root-side.
//
// # The direct-link gate
//
// It also satisfies the direct-link extension (ConfigureLink/RemoveLink), and it
// is where the protocol's one compatibility promise is kept: DirectRoutes go ONLY
// to a helper whose own reply reported minor >= 1 (wire.Version.SupportsDirectLinks)
// and only for an interface on which that helper has accepted a ConfigureLink. A
// helper that predates minor 1 does not decode strictly, so it would accept the
// field and silently drop it — reporting success for routes it never installed.
// Against such a helper ConfigureLink answers "unknown verb", the device reports
// ErrLinksUnsupported, logs one Info line, and the mesh runs over the tunnel.
//
// Locking discipline: mu guards linked and oldLogged; no RPC runs under it.
type netdDevice struct {
	client     helperClient
	privKeyRef string
	listenPort int
	self       netip.Prefix
	log        *slog.Logger

	mu sync.Mutex
	// linked are the interfaces the CURRENT helper accepted a ConfigureLink for,
	// with the peer address it was configured toward. A failed ConfigureLink
	// clears the entry; so does RemoveLink.
	linked    map[string]netip.Addr
	oldLogged bool
}

// newNetdDevice constructs a helper-backed Device dialing socketPath. privKeyRef
// is the opaque reference the daemon resolves to the node's private key root-side;
// self is the node's own pod /24, which every ConfigureMesh carries so a daemon
// still holding its pre-join default can adopt the node's real identity.
func newNetdDevice(socketPath, privKeyRef string, listenPort int, self netip.Prefix, log *slog.Logger) *netdDevice {
	return newNetdDeviceWith(wire.NewClient(socketPath), privKeyRef, listenPort, self, log)
}

func newNetdDeviceWith(c helperClient, privKeyRef string, listenPort int, self netip.Prefix, log *slog.Logger) *netdDevice {
	if log == nil {
		log = slog.Default()
	}
	return &netdDevice{
		client:     c,
		privKeyRef: privKeyRef,
		listenPort: listenPort,
		self:       self,
		log:        log,
		linked:     make(map[string]netip.Addr),
	}
}

// Up brings the mesh tunnel up via the daemon with no peers yet (the daemon
// creates the utun and sets the resolved private key + listen port). It is
// idempotent: the daemon's ConfigureMesh is.
func (d *netdDevice) Up(ctx context.Context) error {
	return d.client.ConfigureMesh(ctx, d.privKeyRef, d.listenPort, d.self, nil, nil)
}

// Apply sends the plan's peer set to the daemon as typed scalars; the daemon
// re-validates and re-renders the UAPI + routes from them (it never accepts the
// rendered text). plan.Routes/plan.UAPI are recomputed daemon-side and so are not
// transmitted. The plan's direct peers ride as DirectRoutes only past the gate
// (directArgs); a direct peer the gate holds back stays on the tunnel.
func (d *netdDevice) Apply(ctx context.Context, plan Plan) error {
	peers := make([]wire.MeshPeerArg, 0, len(plan.Peers))
	for _, pc := range plan.Peers {
		pub, err := hexToBase64(pc.PublicKeyHex)
		if err != nil {
			return fmt.Errorf("mesh peer %q: %w", pc.NodeName, err)
		}
		allowed := make([]string, len(pc.AllowedIPs))
		for i, a := range pc.AllowedIPs {
			allowed[i] = a.String()
		}
		peers = append(peers, wire.MeshPeerArg{PubKey: pub, Endpoint: pc.Endpoint, AllowedIPs: allowed})
	}
	return d.client.ConfigureMesh(ctx, d.privKeyRef, d.listenPort, d.self, peers, d.directArgs(plan.Direct))
}

// directArgs renders the direct peers the gate admits: the helper reported minor
// >= 1, and accepted a ConfigureLink on the peer's interface toward this gateway.
func (d *netdDevice) directArgs(direct []DirectPeer) []wire.DirectRouteArg {
	if len(direct) == 0 {
		return nil
	}
	v, seen := d.client.HelperVersion()
	if !seen || !v.SupportsDirectLinks() {
		d.logOldHelper(v, seen)
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []wire.DirectRouteArg
	for _, dp := range direct {
		peer, ok := d.linked[dp.Route.Iface]
		if !ok || peer != dp.Route.Gateway {
			d.log.Warn("direct route held back: the helper has not configured this link toward the peer", "iface", dp.Route.Iface, "peer", dp.NodeName)
			continue
		}
		out = append(out, wire.DirectRouteArg{PeerPodCIDR: dp.PodCIDR.String(), Gateway: dp.Route.Gateway.String(), Iface: dp.Route.Iface})
	}
	return out
}

// ConfigureLink asks the helper to configure a direct-link port. A helper that
// does not support direct links (it answered with minor 0, which is how it
// answers the unknown verb) yields ErrLinksUnsupported and one Info line per
// device; the mesh then stays tunnel-only.
func (d *netdDevice) ConfigureLink(ctx context.Context, cfg LinkConfig) (netip.Addr, error) {
	args := wire.ConfigureLinkArgs{Iface: cfg.Iface, PortOrdinal: cfg.PortOrdinal}
	if cfg.LinkIP.IsValid() {
		args.LinkIP = cfg.LinkIP.String()
	}
	if cfg.PeerLinkIP.IsValid() {
		args.PeerLinkIP = cfg.PeerLinkIP.String()
	}
	addr, err := d.client.ConfigureLink(ctx, args)
	v, seen := d.client.HelperVersion()
	if !seen || !v.SupportsDirectLinks() {
		d.mu.Lock()
		delete(d.linked, cfg.Iface)
		d.mu.Unlock()
		d.logOldHelper(v, seen)
		return netip.Addr{}, fmt.Errorf("%w: netd helper speaks %d.%d", ErrLinksUnsupported, v.Major, v.Minor)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		delete(d.linked, cfg.Iface)
		return netip.Addr{}, err
	}
	d.linked[cfg.Iface] = cfg.PeerLinkIP
	return addr, nil
}

// RemoveLink asks the helper to tear a direct-link port down and forgets it.
func (d *netdDevice) RemoveLink(ctx context.Context, iface string) error {
	d.mu.Lock()
	delete(d.linked, iface)
	d.mu.Unlock()
	if v, seen := d.client.HelperVersion(); seen && !v.SupportsDirectLinks() {
		return nil // a helper that never configured a link has none to remove
	}
	return d.client.RemoveLink(ctx, iface)
}

// logOldHelper writes the one Info line a helper without direct links earns. A
// helper that has not replied yet is no verdict and logs nothing.
func (d *netdDevice) logOldHelper(v wire.Version, seen bool) {
	if !seen {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.oldLogged {
		return
	}
	d.oldLogged = true
	d.log.Info("netd helper predates direct links; the mesh runs over the tunnel only", "helperVersion", fmt.Sprintf("%d.%d", v.Major, v.Minor))
}

// Down tears the mesh down via the daemon.
func (d *netdDevice) Down(ctx context.Context) error {
	return d.client.RemoveMesh(ctx)
}

// hexToBase64 re-encodes a hex wireguard key (the UAPI form a PeerConfig carries)
// into the base64 form the wire MeshPeerArg uses, so the daemon decodes it with
// the same wgKeyHex path a MeshPeerSpec takes.
func hexToBase64(h string) (string, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", fmt.Errorf("decode hex wireguard key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
