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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	netv1 "k3sm.io/apis/net/v1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// directHalfBits is the prefix length of each of the two gateway routes a direct
// peer's /24 gets over the cable: two /25s are more specific than the utun /24, so
// they win while they exist and the /24 carries the traffic the moment they go.
const directHalfBits = 25

// nodeCIDRBits is the prefix length of a per-node pod CIDR. The mesh routes and
// AllowedIPs are per-node /24s; requiring /24 is what excludes the 100.64.0.0/10
// cluster aggregate (and any supernet) from the kernel route set.
const nodeCIDRBits = 24

// ethernetIfaceRE is the interface-name shape a direct route may name (en0, en12,
// ...): the same shape a DirectLink port carries.
var ethernetIfaceRE = regexp.MustCompile(`^en[0-9]+$`)

// wgKeyBytes is the length of a Curve25519 wireguard key. A MeshPeer carries the
// PUBLIC key base64-encoded (44 chars); the wireguard UAPI wants it hex-encoded.
const wgKeyBytes = 32

// Sentinel errors. Compare with errors.Is, never by string match.
var (
	// ErrSelfCIDR is returned when the node's own podCIDR is not a usable IPv4 /24
	// (the mesh cannot compute routes or a mesh-egress source without it).
	ErrSelfCIDR = errors.New("mesh: node podCIDR must be an IPv4 /24")
	// ErrPeerConfig is returned for a MeshPeer that cannot be programmed (bad key,
	// malformed CIDR, or AllowedIPs that do not equal the peer podCIDR).
	ErrPeerConfig = errors.New("mesh: invalid mesh peer config")
	// ErrDirectRoute is returned by ValidatePlan for a direct route the strict
	// form refuses (a gateway outside the reserved direct-link halves, a malformed
	// interface, or a route for no programmable peer).
	ErrDirectRoute = errors.New("mesh: invalid direct route")
)

// DirectRoute is the cable path to one peer: the local interface the cable is on
// and the peer's direct-link address on that cable, the next hop for the peer's
// pods.
type DirectRoute struct {
	// Iface is the local interface the cable presents as (e.g. "en5").
	Iface string
	// Gateway is the peer's direct-link address (netv1alpha1.LinkIP of the peer's
	// node index and port).
	Gateway netip.Addr
}

// DirectRoutes are the peers to reach over a cable, keyed by peer node name
// (MeshPeerSpec.NodeName). The caller derives it from local link state ANDed with
// the resolved DirectLink status and the liveness probe (EligibleDirectRoutes);
// BuildPlan trusts it and never derives one from a MeshPeer alone.
type DirectRoutes map[string]DirectRoute

// RouteSpec is one kernel route the plan wants. A zero Gateway is the utun link
// route of a peer's /24 (Iface is empty: the device knows its own utun); a set
// Gateway is a direct /25 through the peer's link address on Iface.
type RouteSpec struct {
	// Prefix is the destination.
	Prefix netip.Prefix
	// Iface is the interface of a direct route; empty for a utun route.
	Iface string
	// Gateway is the next hop of a direct route; zero for a utun route.
	Gateway netip.Addr
}

// Direct reports whether the route is a direct (gateway) route over a cable.
func (r RouteSpec) Direct() bool { return r.Gateway.IsValid() }

// String renders a utun route as its prefix and a direct route with its next hop.
func (r RouteSpec) String() string {
	if r.Direct() {
		return fmt.Sprintf("%s via %s on %s", r.Prefix, r.Gateway, r.Iface)
	}
	return r.Prefix.String()
}

// DirectPeer records a peer the plan routes over a cable: the peer, its pod /24,
// and the route. The netd client sends these to the helper as typed values.
type DirectPeer struct {
	// NodeName is the peer node.
	NodeName string
	// PodCIDR is the peer's pod /24.
	PodCIDR netip.Prefix
	// Route is the cable path.
	Route DirectRoute
}

// PeerConfig is the resolved, programmable form of one MeshPeer: the wireguard
// public key hex-encoded for the UAPI, the reachable endpoint, the AllowedIPs
// (each equal to the peer podCIDR), and the keepalive. It is derived from a
// netv1.MeshPeerSpec by BuildPlan and carries no private material.
type PeerConfig struct {
	// NodeName is the peer node this config programs (for logs and diagnostics).
	NodeName string
	// PublicKeyHex is the peer's wireguard PUBLIC key, hex-encoded for the UAPI.
	PublicKeyHex string
	// Endpoint is the host:port the peer's wireguard is reachable at.
	Endpoint string
	// AllowedIPs are the symmetric wireguard routes for this peer (== its podCIDR).
	AllowedIPs []netip.Prefix
	// KeepaliveSeconds is the wireguard PersistentKeepalive for this peer.
	KeepaliveSeconds int
}

// PeerSkip records a MeshPeer that BuildPlan dropped and why, so the reconcile
// loop can log non-convergence (a skipped peer blackholes that node's pods). It
// is observability, not control flow — one bad peer never fails the whole plan.
type PeerSkip struct {
	NodeName string
	PodCIDR  string
	Reason   string
}

// Plan is the full desired mesh state computed from a MeshPeer snapshot: the
// wireguard peer set and the kernel route set to install on the utun. The Device
// applies it (IpcSet of UAPI + route reconcile). It is a value type with no I/O so
// it is fully table-tested.
type Plan struct {
	// Peers is the desired wireguard peer set (see UAPI/UAPIUpdate for how it is
	// programmed: a full replacement on the first apply, an incremental update
	// afterwards so roamed endpoints and live sessions survive a reconcile).
	Peers []PeerConfig
	// Routes is the kernel route set: one utun route per peer podCIDR, ALWAYS,
	// plus, for a direct peer, two /25 gateway routes over its cable. It NEVER
	// contains this node's own /24 or the cluster aggregate, and a direct peer's
	// utun /24 is never dropped (the kernel's own deletion of the /25s on unplug
	// is the fallback to it).
	Routes []RouteSpec
	// Direct lists the peers routed over a cable, sorted by pod CIDR.
	Direct []DirectPeer
	// Skipped lists MeshPeers omitted from the plan, with reasons, for logging.
	Skipped []PeerSkip
	// DirectRejected lists direct routes BuildPlan ignored (the peer still gets
	// its utun route), with reasons. ValidatePlan refuses a plan with any.
	DirectRejected []PeerSkip
}

// EqualCIDR reports whether two prefixes denote the same network (masked equal).
// It is the equality the node /24 single-source-of-truth relies on: a symmetric
// but unequal AllowedIPs still blackholes, so the mesh checks equality, not just
// symmetry.
func EqualCIDR(a, b netip.Prefix) bool { return a.Masked() == b.Masked() }

// RouteSet computes the kernel routes to install on the utun from a MeshPeer
// snapshot: exactly one route per peer podCIDR. It NEVER includes this node's own
// /24 or the 100.64.0.0/10 cluster aggregate — routing either to the utun would
// steal same-node lo0 loopback traffic (the wireguard-go library over a raw utun
// installs no routes of its own, so this is the sole route authority). Entries are
// admitted only if they are an IPv4 /24 (which excludes the aggregate and any
// supernet) disjoint from self; malformed and duplicate entries are dropped. The
// result is deduplicated and sorted for deterministic reconcile. self must be an
// IPv4 /24 or RouteSet returns ErrSelfCIDR.
func RouteSet(self netip.Prefix, peers []netv1.MeshPeerSpec) ([]netip.Prefix, error) {
	self = self.Masked()
	if !self.Addr().Is4() || self.Bits() != nodeCIDRBits {
		return nil, fmt.Errorf("%w: got %s", ErrSelfCIDR, self)
	}
	seen := make(map[netip.Prefix]struct{})
	out := make([]netip.Prefix, 0, len(peers))
	for _, p := range peers {
		c, err := netip.ParsePrefix(p.PodCIDR)
		if err != nil {
			continue
		}
		c = c.Masked()
		if !c.Addr().Is4() || c.Bits() != nodeCIDRBits {
			// Not a per-node /24: excludes the 100.64.0.0/10 aggregate and any
			// supernet that would capture same-node traffic.
			continue
		}
		if c.Overlaps(self) {
			// Never route this node's own range to the utun (loopback theft).
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out, nil
}

// AllowedIPsMatchCIDR asserts the node /24 single source of truth for one peer:
// every AllowedIPs entry equals the peer podCIDR, and there is at least one. The
// mesh checks equality (not mere symmetry) because two nodes can agree on an
// AllowedIPs that does not match the real podCIDR and still blackhole. Errors wrap
// ErrPeerConfig.
func AllowedIPsMatchCIDR(spec netv1.MeshPeerSpec) error {
	pc, err := netip.ParsePrefix(spec.PodCIDR)
	if err != nil {
		return fmt.Errorf("%w: peer %q podCIDR %q: %w", ErrPeerConfig, spec.NodeName, spec.PodCIDR, err)
	}
	pc = pc.Masked()
	if len(spec.AllowedIPs) == 0 {
		return fmt.Errorf("%w: peer %q has no allowedIPs (want exactly %s)", ErrPeerConfig, spec.NodeName, pc)
	}
	for _, s := range spec.AllowedIPs {
		a, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("%w: peer %q allowedIP %q: %w", ErrPeerConfig, spec.NodeName, s, err)
		}
		if a.Masked() != pc {
			return fmt.Errorf("%w: peer %q allowedIP %s != podCIDR %s (equality required, not just symmetry)", ErrPeerConfig, spec.NodeName, a.Masked(), pc)
		}
	}
	return nil
}

// BuildPlan turns a MeshPeer snapshot into the desired mesh state for the node
// whose podCIDR is self. It drops the node's own MeshPeer (a node is not its own
// wireguard peer, and its /24 is never routed to the utun), gates each peer on the
// schema version, validates the spec and the AllowedIPs==podCIDR equality, and
// resolves the wireguard config. Per-peer problems are recorded in Plan.Skipped
// (logged by the reconcile loop) rather than failing the whole plan, so one bad
// MeshPeer cannot wedge the mesh. self must be an IPv4 /24 (ErrSelfCIDR otherwise).
//
// direct names the peers to route over a cable (nil: none). For each programmable
// peer it names, the plan adds two /25 gateway routes through the peer's link
// address on top of — never instead of — the peer's utun /24, and selects the
// peer's wireguard endpoint from its candidates: the direct candidate whose host
// is the route's gateway, else the first underlay candidate, else Endpoint. A peer
// not in direct gets the first underlay candidate, else Endpoint. Candidates with
// a Link this reader does not know are ignored, never a reason to skip the peer.
// A direct route that is unusable (no interface, a gateway that is not an IPv4
// address) is recorded in Plan.DirectRejected and the peer keeps its tunnel.
func BuildPlan(self netip.Prefix, peers []netv1.MeshPeerSpec, direct DirectRoutes) (Plan, error) {
	self = self.Masked()
	if !self.Addr().Is4() || self.Bits() != nodeCIDRBits {
		return Plan{}, fmt.Errorf("%w: got %s", ErrSelfCIDR, self)
	}
	var plan Plan
	included := make([]netv1.MeshPeerSpec, 0, len(peers))
	directByCIDR := make(map[netip.Prefix]DirectPeer)
	for _, raw := range peers {
		spec := knownCandidates(raw.WithDefaults())
		skip := func(reason string) {
			plan.Skipped = append(plan.Skipped, PeerSkip{NodeName: spec.NodeName, PodCIDR: spec.PodCIDR, Reason: reason})
		}
		if err := spec.Validate(); err != nil {
			skip(err.Error())
			continue
		}
		if spec.SchemaVersion != netv1.MeshPeerSchemaVersion {
			skip(fmt.Sprintf("unsupported schemaVersion %d (want %d)", spec.SchemaVersion, netv1.MeshPeerSchemaVersion))
			continue
		}
		peerCIDR, err := netip.ParsePrefix(spec.PodCIDR)
		if err != nil {
			skip(fmt.Sprintf("malformed podCIDR %q: %v", spec.PodCIDR, err))
			continue
		}
		peerCIDR = peerCIDR.Masked()
		if EqualCIDR(peerCIDR, self) {
			// The node's own MeshPeer: not a peer of itself; never routed.
			continue
		}
		if err := AllowedIPsMatchCIDR(spec); err != nil {
			skip(err.Error())
			continue
		}
		pc, err := peerConfigFromSpec(spec)
		if err != nil {
			skip(err.Error())
			continue
		}
		route, isDirect := direct[spec.NodeName]
		if isDirect {
			if reason := directRouteProblem(route); reason != "" {
				plan.DirectRejected = append(plan.DirectRejected, PeerSkip{NodeName: spec.NodeName, PodCIDR: spec.PodCIDR, Reason: reason})
				isDirect = false
			} else if peerCIDR.Bits() == nodeCIDRBits && peerCIDR.Addr().Is4() && !peerCIDR.Overlaps(self) {
				directByCIDR[peerCIDR] = DirectPeer{NodeName: spec.NodeName, PodCIDR: peerCIDR, Route: route}
			} else {
				// RouteSet will not route this peer at all; neither will the cable.
				isDirect = false
			}
		}
		pc.Endpoint = selectEndpoint(spec, route, isDirect)
		plan.Peers = append(plan.Peers, pc)
		included = append(included, spec)
	}
	for name := range direct {
		if !containsNode(included, name) {
			plan.DirectRejected = append(plan.DirectRejected, PeerSkip{NodeName: name, Reason: "no programmable mesh peer of that name"})
		}
	}
	sort.Slice(plan.DirectRejected, func(i, j int) bool { return plan.DirectRejected[i].NodeName < plan.DirectRejected[j].NodeName })
	utun, err := RouteSet(self, included)
	if err != nil {
		return Plan{}, err
	}
	for _, p := range utun {
		plan.Routes = append(plan.Routes, RouteSpec{Prefix: p})
		dp, ok := directByCIDR[p]
		if !ok {
			continue
		}
		lo, hi := halves(p)
		plan.Routes = append(plan.Routes,
			RouteSpec{Prefix: lo, Iface: dp.Route.Iface, Gateway: dp.Route.Gateway},
			RouteSpec{Prefix: hi, Iface: dp.Route.Iface, Gateway: dp.Route.Gateway})
		plan.Direct = append(plan.Direct, dp)
	}
	return plan, nil
}

// halves splits a /24 into its two /25s.
func halves(p netip.Prefix) (lo, hi netip.Prefix) {
	b := p.Masked().Addr().As4()
	lo = netip.PrefixFrom(netip.AddrFrom4(b), directHalfBits)
	b[3] = 128
	hi = netip.PrefixFrom(netip.AddrFrom4(b), directHalfBits)
	return lo, hi
}

// directRouteProblem returns why a direct route cannot be used, or "".
func directRouteProblem(r DirectRoute) string {
	if r.Iface == "" {
		return "direct route has no interface"
	}
	if !r.Gateway.IsValid() || !r.Gateway.Unmap().Is4() {
		return fmt.Sprintf("direct route gateway %v is not an IPv4 address", r.Gateway)
	}
	return ""
}

// containsNode reports whether specs holds a peer named name.
func containsNode(specs []netv1.MeshPeerSpec, name string) bool {
	for _, s := range specs {
		if s.NodeName == name {
			return true
		}
	}
	return false
}

// knownCandidates returns spec with every Endpoints candidate whose Link this
// reader does not recognise removed. A reader ignores such a candidate rather than
// failing the peer, so a future link kind never blackholes a node from an older
// reader; removing it before Validate is what keeps Validate's writer-side rule
// (every candidate carries a known Link) from skipping the peer.
func knownCandidates(spec netv1.MeshPeerSpec) netv1.MeshPeerSpec {
	if len(spec.Endpoints) == 0 {
		return spec
	}
	kept := make([]netv1.EndpointCandidate, 0, len(spec.Endpoints))
	for _, c := range spec.Endpoints {
		switch c.Link {
		case netv1.EndpointLinkUnderlay, netv1.EndpointLinkDirect:
			kept = append(kept, c)
		}
	}
	spec.Endpoints = kept
	return spec
}

// selectEndpoint chooses the peer's wireguard endpoint: when the peer is routed
// over a cable, the direct candidate whose host is that cable's gateway; else the
// first underlay candidate; else Endpoint. The choice is local, so when the direct
// path dies the selection moves to the underlay and the applier re-programs the
// endpoint (wireguard-go roams only on a received packet, which a dead cable never
// delivers).
func selectEndpoint(spec netv1.MeshPeerSpec, route DirectRoute, direct bool) string {
	if direct {
		for _, c := range spec.Endpoints {
			if c.Link != netv1.EndpointLinkDirect {
				continue
			}
			if host, ok := endpointHost(c.Address); ok && host == route.Gateway.Unmap() {
				return c.Address
			}
		}
	}
	for _, c := range spec.Endpoints {
		if c.Link == netv1.EndpointLinkUnderlay {
			return c.Address
		}
	}
	return spec.Endpoint
}

// endpointHost parses the IP host of a host:port endpoint.
func endpointHost(endpoint string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// ValidatePlan is the strict form of BuildPlan: it returns a Plan only if EVERY
// peer is programmable, turning a peer BuildPlan would silently skip (bad key,
// malformed or non-/24 podCIDR, AllowedIPs != podCIDR, unsupported schemaVersion)
// into an error instead. The netd daemon uses it to REJECT an out-of-policy
// ConfigureMesh at the privilege boundary, where a skipped peer is a client bug or
// an attack rather than the benign cluster churn BuildPlan tolerates for the
// in-process reconcile loop. self must be an IPv4 /24 (ErrSelfCIDR otherwise);
// per-peer problems wrap ErrPeerConfig.
//
// Every direct route must be usable, name a programmable peer, sit on an
// Ethernet-class interface, and have its gateway in one of the two reserved
// direct-link halves (netv1alpha1.IsLinkAddress); a violation wraps
// ErrDirectRoute. That the gateway is exactly the address derived for the node
// that owns the peer's /24 needs the cluster aggregate, so the daemon checks it
// before calling here.
func ValidatePlan(self netip.Prefix, peers []netv1.MeshPeerSpec, direct DirectRoutes) (Plan, error) {
	plan, err := BuildPlan(self, peers, direct)
	if err != nil {
		return Plan{}, err
	}
	if len(plan.Skipped) > 0 {
		s := plan.Skipped[0]
		return Plan{}, fmt.Errorf("%w: peer %q (podCIDR %s): %s", ErrPeerConfig, s.NodeName, s.PodCIDR, s.Reason)
	}
	// Strict: BuildPlan admits a peer whose AllowedIPs equals its podCIDR even when
	// that CIDR is not a per-node /24 (RouteSet then drops the non-/24, leaving a
	// routeless peer). For the privilege boundary that is a misconfiguration to
	// reject, not silently program — a non-/24 AllowedIPs would also widen the
	// wireguard cryptokey-routing source range.
	for _, pc := range plan.Peers {
		for _, a := range pc.AllowedIPs {
			if !a.Addr().Is4() || a.Bits() != nodeCIDRBits {
				return Plan{}, fmt.Errorf("%w: peer %q AllowedIPs %s is not a per-node /%d", ErrPeerConfig, pc.NodeName, a, nodeCIDRBits)
			}
		}
	}
	if len(plan.DirectRejected) > 0 {
		s := plan.DirectRejected[0]
		return Plan{}, fmt.Errorf("%w: peer %q: %s", ErrDirectRoute, s.NodeName, s.Reason)
	}
	for _, r := range plan.Routes {
		if !r.Direct() {
			continue
		}
		if !ethernetIfaceRE.MatchString(r.Iface) {
			return Plan{}, fmt.Errorf("%w: route %s: interface %q is not an Ethernet-class interface", ErrDirectRoute, r, r.Iface)
		}
		if !netv1alpha1.IsLinkAddress(r.Gateway) {
			return Plan{}, fmt.Errorf("%w: route %s: gateway %s is outside the reserved direct-link halves 169.254.0.0/24 and 169.254.255.0/24", ErrDirectRoute, r, r.Gateway)
		}
	}
	return plan, nil
}

// AppliedEndpoints is the applier's memory of the endpoint it last programmed for
// each peer, keyed by the peer's hex public key — the state UAPIUpdate diffs the
// next Plan against. It is deliberately the applier's OWN record of what it wrote,
// never a read-back of the device: wireguard roams a peer's endpoint to whatever
// source its last authenticated packet came from, so device state answers "where
// is the peer now", which is exactly the answer a reconcile must not overwrite.
// Its lifetime is the wireguard device's: a device that is (re)created has no
// peers, so its applier starts from an empty map and programs every endpoint.
type AppliedEndpoints map[string]string

// UAPI renders the wireguard userspace-API configuration that programs this plan's
// peer set as a FULL replacement (replace_peers=true), the form IpcSet consumes.
// It is the first-apply form — the one an applier with no prior state uses, where
// replacing peers loses nothing — and is UAPIUpdate(nil). Use UAPIUpdate for every
// subsequent reconcile: replace_peers tears down and re-creates every peer, which
// discards both the live session and the roamed endpoint.
func (p Plan) UAPI() string {
	uapi, _ := p.UAPIUpdate(nil)
	return uapi
}

// UAPIUpdate renders the wireguard UAPI that moves the device from the peer set
// the applier last programmed (prev, keyed by hex public key) to this plan, and
// returns the applier's new memory. It is the endpoint-roaming contract in code:
// a peer whose public key is already configured keeps the endpoint wireguard
// itself roamed onto, and the CR endpoint is (re)programmed only when the peer is
// new to the device, when its key changed (a fresh peer needs a first endpoint),
// or when the CR endpoint differs from the value this applier last wrote (an
// operator deliberately moved the node). AllowedIPs, the keepalive, and peer
// removal reconcile on every call as before.
//
// With no prior state (len(prev) == 0) it emits the full-replacement form: there
// is no live peer state to protect, and a clean slate is the safe first write.
// Otherwise it emits an incremental update — never replace_peers, which would
// delete and re-create every peer and so discard the very roamed endpoints and
// handshakes this contract exists to preserve — plus an explicit remove=true for
// each key the plan no longer carries (a departed peer, or the old half of a key
// rotation). It excludes private material entirely.
func (p Plan) UAPIUpdate(prev AppliedEndpoints) (string, AppliedEndpoints) {
	var b strings.Builder
	if len(prev) == 0 {
		b.WriteString("replace_peers=true\n")
	} else {
		keep := make(map[string]struct{}, len(p.Peers))
		for _, pc := range p.Peers {
			keep[pc.PublicKeyHex] = struct{}{}
		}
		gone := make([]string, 0, len(prev))
		for k := range prev {
			if _, ok := keep[k]; !ok {
				gone = append(gone, k)
			}
		}
		sort.Strings(gone) // deterministic output for the table tests
		for _, k := range gone {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k)
		}
	}
	next := make(AppliedEndpoints, len(p.Peers))
	for _, pc := range p.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", pc.PublicKeyHex)
		last, configured := prev[pc.PublicKeyHex]
		if pc.Endpoint != "" && (!configured || last != pc.Endpoint) {
			fmt.Fprintf(&b, "endpoint=%s\n", pc.Endpoint)
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", pc.KeepaliveSeconds)
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range pc.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
		}
		next[pc.PublicKeyHex] = pc.Endpoint
	}
	return b.String(), next
}

// peerConfigFromSpec resolves a validated MeshPeerSpec into a PeerConfig: it
// hex-encodes the public key for the UAPI, parses and masks the AllowedIPs, and
// defaults the keepalive. The caller has already checked Validate, the schema
// version, and AllowedIPsMatchCIDR.
func peerConfigFromSpec(spec netv1.MeshPeerSpec) (PeerConfig, error) {
	keyHex, err := wgKeyHex(spec.PublicKey)
	if err != nil {
		return PeerConfig{}, fmt.Errorf("%w: peer %q publicKey: %w", ErrPeerConfig, spec.NodeName, err)
	}
	allowed := make([]netip.Prefix, 0, len(spec.AllowedIPs))
	for _, s := range spec.AllowedIPs {
		a, err := netip.ParsePrefix(s)
		if err != nil {
			return PeerConfig{}, fmt.Errorf("%w: peer %q allowedIP %q: %w", ErrPeerConfig, spec.NodeName, s, err)
		}
		allowed = append(allowed, a.Masked())
	}
	keepalive := int(spec.PersistentKeepaliveSeconds)
	if keepalive == 0 {
		keepalive = PersistentKeepaliveSeconds
	}
	return PeerConfig{
		NodeName:         spec.NodeName,
		PublicKeyHex:     keyHex,
		Endpoint:         spec.Endpoint,
		AllowedIPs:       allowed,
		KeepaliveSeconds: keepalive,
	}, nil
}

// wgKeyHex converts a base64-encoded 32-byte wireguard key (the form a MeshPeer
// carries its public key, and the form a node stores its private key) into the hex
// encoding the wireguard UAPI expects. The conversion is identical for public and
// private keys; private material is handled only by the device, never logged.
func wgKeyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode base64 wireguard key: %w", err)
	}
	if len(raw) != wgKeyBytes {
		return "", fmt.Errorf("wireguard key is %d bytes, want %d", len(raw), wgKeyBytes)
	}
	return hex.EncodeToString(raw), nil
}
