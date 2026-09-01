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
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/podnet"
)

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

// withDevice injects a Device, bypassing the default wireguard device (tests use
// it to drive the reconcile logic without privilege).
func withDevice(d Device) Option {
	return func(m *Mesh) { m.dev = d }
}

// WithNetdHelper routes the privileged mesh datapath through the root netd daemon
// at socketPath: the device sends ConfigureMesh/RemoveMesh and the daemon (which
// holds the private key, resolved from privKeyRef) creates the utun, programs
// wireguard, installs the per-peer routes, and loads the MSS-clamp anchor. It is
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
	}
	for _, o := range opts {
		o(m)
	}
	if m.dev == nil {
		if m.netdSocket != "" {
			m.dev = newNetdDevice(m.netdSocket, m.netdPrivKeyRef, m.listenPort, m.log)
		} else {
			m.dev = NewDevice(DeviceConfig{
				UTUNName:      m.utunName,
				MTU:           MTU,
				MSS:           MSSClamp,
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

// Start brings the mesh device up: the utun, wireguard, the mesh-egress alias, and
// the MSS-clamp pf anchor. It is idempotent (a second Start is a no-op).
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
// the continuous reconcile entry point the watcher calls on every MeshPeer change
// and on its periodic resync, so a CR endpoint move or a key rotation reconverges
// without a restart rather than being read once at startup. The Plan carries the
// CR endpoint for every peer; whether that endpoint is actually (re)written is the
// applier's endpoint-roaming decision (Plan.UAPIUpdate), so a periodic resync
// re-asserts the mesh without stomping an endpoint wireguard has roamed. Per-peer
// problems are logged (Plan.Skipped) but do not fail the reconcile. It is
// idempotent.
func (m *Mesh) Reconcile(ctx context.Context, peers []netv1.MeshPeerSpec) error {
	plan, err := BuildPlan(m.self, peers)
	if err != nil {
		return fmt.Errorf("build mesh plan: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range plan.Skipped {
		m.log.Warn("mesh peer skipped", "node", s.NodeName, "podCIDR", s.PodCIDR, "reason", s.Reason)
	}
	if err := m.dev.Apply(ctx, plan); err != nil {
		return fmt.Errorf("apply mesh plan: %w", err)
	}
	m.applied = plan
	m.log.Info("mesh reconciled", "peers", len(plan.Peers), "routes", len(plan.Routes), "skipped", len(plan.Skipped))
	return nil
}

// Close tears the mesh down (routes, pf anchor, mesh-egress alias, wireguard
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
