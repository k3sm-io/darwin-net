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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"

	netv1 "k3sm.io/apis/net/v1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkwatch"
	"k3sm.io/darwin-net/pkg/podnet"
)

// ErrLinksUnsupported reports that the mesh's device cannot configure direct
// links: the direct (run-as-root) device has no link verbs, and a root network
// helper that predates them answers "unknown verb". The mesh then runs over the
// tunnel only; compare with errors.Is.
var ErrLinksUnsupported = errors.New("mesh: direct links are not supported by this device")

// LinkConfig is one direct-link port as the node wants it configured: the
// Thunderbolt interface, its port ordinal (receptacle − 1), the node's own link
// address on it (a cross-check: the root helper derives the address itself), and,
// optionally, the peer's link address for the on-link host route.
type LinkConfig struct {
	Iface       string
	PortOrdinal int
	LinkIP      netip.Addr
	PeerLinkIP  netip.Addr
}

// linkDevice is the optional Device extension for direct links. The helper-backed
// device implements it; a device that does not runs the mesh tunnel-only.
type linkDevice interface {
	// ConfigureLink configures (idempotently) the link and reports the address the
	// helper configured. A device that cannot returns ErrLinksUnsupported.
	ConfigureLink(ctx context.Context, cfg LinkConfig) (netip.Addr, error)
	// RemoveLink tears the link down (idempotent).
	RemoveLink(ctx context.Context, iface string) error
}

// Mesh is the node's wireguard mesh controller. It owns the node's reserved
// mesh-egress source (podnet.MeshEgressIP), brings the privileged Device up, and
// reconciles the wireguard peer set + kernel routes from MeshPeer snapshots. It is
// the consumer of the Device seam and of the pure Plan logic.
//
// Locking discipline: mu serializes Start/Reconcile/Close so the device is brought
// up once and reconciles never interleave. The Device has its own internal lock;
// mu is held across an Apply, which is acceptable because the peer set is small
// (cluster nodes) and reconcile is not on a per-connection hot path.
type Mesh struct {
	self   netip.Prefix
	meshIP netip.Addr
	dev    Device
	log    *slog.Logger

	// Construction-only config for the default wireguard device; ignored when a
	// device is injected via withDevice (tests).
	utunName      string
	listenPort    int
	privateKeyB64 string

	// netd helper selection (WithNetdHelper). When netdSocket is set, New builds a
	// netd-backed device that drives the root daemon over the unix socket instead of
	// the direct wireguard device; netdPrivKeyRef is the opaque reference the daemon
	// resolves to the private key root-side (the key itself never crosses the socket).
	netdSocket     string
	netdPrivKeyRef string

	mu      sync.Mutex
	started bool
	applied Plan

	// Direct-link state, guarded by mu. links are the ports the node asked for
	// (ConfigureLink), by interface; vanished are links whose interface went away
	// and are re-configured when it returns; linkUp is the local link state from
	// link events; status is this node's resolved DirectLink status.
	links      map[string]LinkConfig
	vanished   map[string]bool
	linkUp     map[string]bool
	status     netv1alpha1.DirectLinkStatus
	prober     *Prober
	onLiveness func(iface string, peer netip.Addr, alive bool)
	// notify asks the owner of the reconcile loop for a pass (the Watcher's
	// trigger). It never blocks. Read under mu, called outside it.
	notify func()
}

// Option configures a Mesh.
type Option func(*Mesh)

// WithLogger sets the structured logger; the default is slog.Default.
func WithLogger(l *slog.Logger) Option {
	return func(m *Mesh) {
		if l != nil {
			m.log = l
		}
	}
}

// WithListenPort sets the UDP port the node's wireguard listens on (default
// DefaultListenPort). It must match the port advertised in this node's MeshPeer
// endpoint.
func WithListenPort(port int) Option {
	return func(m *Mesh) {
		if port > 0 {
			m.listenPort = port
		}
	}
}

// WithPrivateKey sets the node's wireguard PRIVATE key (base64). It never leaves
// the node and never appears on a MeshPeer; the mesh fails fast at Start if it is
// unset (hard cut — the operator provisions it; there is no embedded default).
func WithPrivateKey(base64Key string) Option {
	return func(m *Mesh) { m.privateKeyB64 = base64Key }
}

// WithUTUNName sets the requested utun interface name; "utun" (the default) lets
// the kernel pick the next free unit.
func WithUTUNName(name string) Option {
	return func(m *Mesh) {
		if name != "" {
			m.utunName = name
		}
	}
}

// WithNetdHelper routes the privileged mesh datapath through the root netd daemon
// at socketPath: the device sends ConfigureMesh/RemoveMesh and the daemon (which
// holds the private key, resolved from privKeyRef) creates the utun, programs
// wireguard, and installs the per-peer routes. It is
// the one construction-time selection of the mesh backend — the direct wireguard
// device (WithPrivateKey) remains for an explicit run-as-root mode. The base64
// private key never crosses the socket; only privKeyRef does, which the daemon
// resolves root-side. An empty socketPath uses the netd default socket.
func WithNetdHelper(socketPath, privKeyRef string) Option {
	return func(m *Mesh) {
		m.netdSocket = socketPath
		m.netdPrivKeyRef = privKeyRef
	}
}

// WithLivenessCallback registers cb to hear every direct-link liveness
// transition the probe observes: alive=false after ProbeMisses unanswered echoes
// (the node clears the port's routeReady), alive=true when the peer answers again.
// cb runs on the probe's goroutine, outside the mesh lock, and must not block.
func WithLivenessCallback(cb func(iface string, peer netip.Addr, alive bool)) Option {
	return func(m *Mesh) { m.onLiveness = cb }
}

// New constructs a Mesh for the node whose pod /24 is self. It derives the node's
// mesh-egress source (podnet.MeshEgressIP) and, unless a device is injected,
// builds the production wireguard device. It returns ErrSelfCIDR if self is not a
// usable IPv4 /24.
func New(self netip.Prefix, opts ...Option) (*Mesh, error) {
	s := self.Masked()
	if !s.Addr().Is4() || s.Bits() != nodeCIDRBits {
		return nil, fmt.Errorf("%w: got %s", ErrSelfCIDR, self)
	}
	meshIP, err := podnet.MeshEgressIP(s)
	if err != nil {
		return nil, fmt.Errorf("derive mesh-egress source: %w", err)
	}
	linkIP, err := podnet.MeshLinkIP(s)
	if err != nil {
		return nil, fmt.Errorf("derive mesh link address: %w", err)
	}
	m := &Mesh{
		self:       s,
		meshIP:     meshIP,
		log:        slog.Default(),
		utunName:   "utun",
		listenPort: DefaultListenPort,
		links:      make(map[string]LinkConfig),
		vanished:   make(map[string]bool),
		linkUp:     make(map[string]bool),
	}
	for _, o := range opts {
		o(m)
	}
	if m.prober == nil {
		m.prober = newProber(nil, m.probeChanged)
	}
	if m.dev == nil {
		if m.netdSocket != "" {
			m.dev = newNetdDevice(m.netdSocket, m.netdPrivKeyRef, m.listenPort, s, m.log)
		} else {
			m.dev = NewDevice(DeviceConfig{
				UTUNName:      m.utunName,
				MTU:           MTU,
				MeshIP:        meshIP,
				LinkIP:        linkIP,
				PrivateKeyB64: m.privateKeyB64,
				ListenPort:    m.listenPort,
			}, m.log)
		}
	}
	return m, nil
}

// CIDR returns the node's pod /24 (the single source of truth: == the podnet IPAM
// CIDR == node.spec.podCIDR).
func (m *Mesh) CIDR() netip.Prefix { return m.self }

// MeshIP returns the node's reserved mesh-egress /32 (the proxy binds its backend
// dialer to this via proxy.WithMeshEgressSource).
func (m *Mesh) MeshIP() netip.Addr { return m.meshIP }

// Start brings the mesh device up: the utun, wireguard, the mesh-link address, and
// the mesh-egress alias. It is idempotent (a second Start is a no-op).
func (m *Mesh) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}
	if err := m.dev.Up(ctx); err != nil {
		return fmt.Errorf("start mesh: %w", err)
	}
	m.started = true
	m.log.Info("mesh started", "cidr", m.self.String(), "meshIP", m.meshIP.String())
	return nil
}

// Reconcile programs the full mesh state from the current MeshPeer snapshot. It is
// the continuous reconcile entry point the watcher calls on every MeshPeer change,
// every link event, every liveness transition and on its periodic resync, so a CR
// endpoint move, a key rotation or a cable pull reconverges without a restart
// rather than being read once at startup. The Plan carries the selected endpoint
// for every peer; whether that endpoint is actually (re)written is the applier's
// endpoint-roaming decision (Plan.UAPIUpdate), so a periodic resync re-asserts the
// mesh without stomping an endpoint wireguard has roamed, while a change of the
// SELECTED candidate (the cable died, so the underlay is chosen) is re-programmed.
//
// The direct routes are re-derived here every time (directRoutesLocked): a peer
// is routed over its cable only while the resolver reports the port up, the link
// is up locally, the probe hears the peer, and the device re-confirms the link.
// Per-peer problems are logged (Plan.Skipped) but do not fail the reconcile. It is
// idempotent.
func (m *Mesh) Reconcile(ctx context.Context, peers []netv1.MeshPeerSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	direct := m.directRoutesLocked(ctx)
	plan, err := BuildPlan(m.self, peers, direct)
	if err != nil {
		return fmt.Errorf("build mesh plan: %w", err)
	}
	for _, s := range plan.Skipped {
		m.log.Warn("mesh peer skipped", "node", s.NodeName, "podCIDR", s.PodCIDR, "reason", s.Reason)
	}
	for _, s := range plan.DirectRejected {
		m.log.Warn("direct route ignored", "node", s.NodeName, "reason", s.Reason)
	}
	if err := m.dev.Apply(ctx, plan); err != nil {
		return fmt.Errorf("apply mesh plan: %w", err)
	}
	m.logDirectTransitions(m.applied.Direct, plan.Direct)
	m.applied = plan
	m.log.Info("mesh reconciled", "peers", len(plan.Peers), "routes", len(plan.Routes), "direct", len(plan.Direct), "skipped", len(plan.Skipped))
	return nil
}

// directRoutesLocked derives the direct routes for the next plan: the eligible
// set (EligibleDirectRoutes over the resolved status, the local link state and the
// probe), restricted to links this node configured, each re-confirmed with the
// device — an idempotent ConfigureLink carrying the peer's link address, which is
// also what re-installs the link after a helper restart and re-removes a port the
// system put back into the bridge. A link the device will not confirm is dropped
// from this plan (the peer keeps its tunnel). m.mu must be held.
func (m *Mesh) directRoutesLocked(ctx context.Context) DirectRoutes {
	eligible := EligibleDirectRoutes(m.status, m.isLinkUpLocked, m.prober.Alive)
	if len(eligible) == 0 {
		return nil
	}
	ld, ok := m.dev.(linkDevice)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(eligible))
	for name := range eligible {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make(DirectRoutes, len(eligible))
	for _, name := range names {
		r := eligible[name]
		cfg, ok := m.links[r.Iface]
		if !ok || m.vanished[r.Iface] {
			continue
		}
		cfg.PeerLinkIP = r.Gateway
		if _, err := ld.ConfigureLink(ctx, cfg); err != nil {
			if !errors.Is(err, ErrLinksUnsupported) {
				m.log.Warn("direct link not confirmed; the peer stays on the tunnel", "iface", r.Iface, "peer", name, "err", err)
			}
			continue
		}
		m.links[r.Iface] = cfg
		out[name] = r
	}
	return out
}

// logDirectTransitions writes one Warn line per peer whose path changed between
// two applied plans: onto a cable, off it, or onto another cable.
func (m *Mesh) logDirectTransitions(prev, next []DirectPeer) {
	was := make(map[string]DirectPeer, len(prev))
	for _, d := range prev {
		was[d.NodeName] = d
	}
	now := make(map[string]DirectPeer, len(next))
	for _, d := range next {
		now[d.NodeName] = d
		old, ok := was[d.NodeName]
		switch {
		case !ok:
			m.log.Warn("direct link up: peer pods now route over the cable", "iface", d.Route.Iface, "peer", d.NodeName, "gateway", d.Route.Gateway.String(), "reason", "port up, link up locally, peer answers")
		case old.Route != d.Route:
			m.log.Warn("direct link moved: peer pods now route over another cable", "iface", d.Route.Iface, "peer", d.NodeName, "from", old.Route.Iface, "reason", "the resolved port changed")
		}
	}
	for _, d := range prev {
		if _, ok := now[d.NodeName]; !ok {
			m.log.Warn("direct link down: peer pods fall back to the tunnel", "iface", d.Route.Iface, "peer", d.NodeName, "reason", m.downReason(d.Route))
		}
	}
}

// downReason names which input withdrew a direct route. m.mu must be held.
func (m *Mesh) downReason(r DirectRoute) string {
	switch {
	case m.vanished[r.Iface]:
		return "interface vanished"
	case !m.linkUp[r.Iface]:
		return "link down locally"
	case !m.prober.Alive(r.Iface, r.Gateway):
		return "peer does not answer the probe"
	default:
		return "port no longer up in the resolved status, or the link was not confirmed"
	}
}

// isLinkUpLocked reports the local link state of iface from link events.
func (m *Mesh) isLinkUpLocked(iface string) bool { return m.linkUp[iface] }

// ConfigureLink asks the device to configure a direct-link port and records it as
// one this node wants, so a reconcile can route over it once the resolver reports
// it up and so the link is re-configured if its interface vanishes and returns. It
// returns the link address the device configured. On a device without link verbs
// (or a helper that predates them) it returns ErrLinksUnsupported and the mesh
// stays tunnel-only.
func (m *Mesh) ConfigureLink(ctx context.Context, cfg LinkConfig) (netip.Addr, error) {
	ld, ok := m.dev.(linkDevice)
	if !ok {
		return netip.Addr{}, ErrLinksUnsupported
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	addr, err := ld.ConfigureLink(ctx, cfg)
	if err != nil {
		return netip.Addr{}, err
	}
	m.links[cfg.Iface] = cfg
	delete(m.vanished, cfg.Iface)
	m.refreshProbesLocked()
	m.kickLocked()
	return addr, nil
}

// RemoveLink forgets a direct-link port and asks the device to tear it down (its
// direct routes leave first, then its host route and address). The next reconcile
// routes the peer over the tunnel.
func (m *Mesh) RemoveLink(ctx context.Context, iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, iface)
	delete(m.vanished, iface)
	m.refreshProbesLocked()
	m.kickLocked()
	ld, ok := m.dev.(linkDevice)
	if !ok {
		return nil
	}
	return ld.RemoveLink(ctx, iface)
}

// SetDirectLinkStatus records this node's resolved DirectLink status (from the
// node's DirectLink informer) and asks for a reconcile.
func (m *Mesh) SetDirectLinkStatus(status netv1alpha1.DirectLinkStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = *status.DeepCopy()
	m.refreshProbesLocked()
	m.kickLocked()
}

// HandleLinkEvent folds one link event into the local link state and asks for a
// reconcile. An interface that VANISHES while it carries a configured link is
// torn down through the device (RemoveLink) and re-configured, with the same
// config, when an interface of that name comes back — a removal and a re-add,
// never a flag flip, because the system may have destroyed and recreated it.
func (m *Mesh) HandleLinkEvent(ctx context.Context, ev linkwatch.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, configured := m.links[ev.Iface]
	ld, hasLinks := m.dev.(linkDevice)
	switch {
	case ev.Gone:
		delete(m.linkUp, ev.Iface)
		if configured && hasLinks && !m.vanished[ev.Iface] {
			m.vanished[ev.Iface] = true
			if err := ld.RemoveLink(ctx, ev.Iface); err != nil {
				m.log.Warn("removing the link of a vanished interface", "iface", ev.Iface, "err", err)
			}
		}
	default:
		m.linkUp[ev.Iface] = ev.Up
		if configured && hasLinks && m.vanished[ev.Iface] {
			if _, err := ld.ConfigureLink(ctx, cfg); err != nil {
				m.log.Warn("re-configuring the link of a returned interface", "iface", ev.Iface, "err", err)
			} else {
				delete(m.vanished, ev.Iface)
			}
		}
	}
	m.kickLocked()
}

// RunProbes runs the direct-link liveness probe until ctx ends. The Watcher runs
// it; a caller driving Reconcile without a Watcher runs it itself, or no peer is
// ever routed over a cable (a new target starts dead).
func (m *Mesh) RunProbes(ctx context.Context) { m.prober.Run(ctx) }

// refreshProbesLocked points the probe at every configured link the resolver
// reports up. m.mu must be held.
func (m *Mesh) refreshProbesLocked() {
	var targets []ProbeTarget
	for _, p := range m.status.Ports {
		gw, ok := directTarget(p)
		if !ok {
			continue
		}
		if _, configured := m.links[p.Iface]; !configured {
			continue
		}
		targets = append(targets, ProbeTarget{Iface: p.Iface, Peer: gw})
	}
	m.prober.SetTargets(targets)
}

// probeChanged is the probe's transition callback: it asks for a reconcile (which
// withdraws or restores the /25s) and tells the registered callback.
func (m *Mesh) probeChanged(t ProbeTarget, alive bool) {
	if alive {
		m.log.Info("direct link peer answers the probe", "iface", t.Iface, "peer", t.Peer.String())
	} else {
		m.log.Warn("direct link peer stopped answering the probe", "iface", t.Iface, "peer", t.Peer.String(), "misses", ProbeMisses)
	}
	m.mu.Lock()
	notify, cb := m.notify, m.onLiveness
	m.mu.Unlock()
	if notify != nil {
		notify()
	}
	if cb != nil {
		cb(t.Iface, t.Peer, alive)
	}
}

// kickLocked asks for a reconcile pass. m.mu must be held; notify never blocks.
func (m *Mesh) kickLocked() {
	if m.notify != nil {
		m.notify()
	}
}

// setNotify registers the reconcile trigger (the Watcher's).
func (m *Mesh) setNotify(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notify = f
}

// Close tears the mesh down (routes, legacy pf anchor flush, mesh-egress alias, wireguard
// device), leak-free. It is idempotent.
func (m *Mesh) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return nil
	}
	m.started = false
	return m.dev.Down(ctx)
}

// Applied returns the last plan Reconcile applied. The returned Plan shares its
// slices with the controller; it is a diagnostics/test accessor and must not be
// mutated.
func (m *Mesh) Applied() Plan {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied
}
