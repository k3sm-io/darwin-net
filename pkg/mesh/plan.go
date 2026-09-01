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
	"sort"
	"strings"

	netv1 "k3sm.io/apis/net/v1"
)

// nodeCIDRBits is the prefix length of a per-node pod CIDR. The mesh routes and
// AllowedIPs are per-node /24s; requiring /24 is what excludes the 100.64.0.0/10
// cluster aggregate (and any supernet) from the kernel route set.
const nodeCIDRBits = 24

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
)

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
	// Peers is the wireguard peer set (a full replacement — see UAPI).
	Peers []PeerConfig
	// Routes is the kernel route set: one prefix per peer podCIDR, each routed to
	// the utun. It NEVER contains this node's own /24 or the cluster aggregate.
	Routes []netip.Prefix
	// Skipped lists MeshPeers omitted from the plan, with reasons, for logging.
	Skipped []PeerSkip
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
func BuildPlan(self netip.Prefix, peers []netv1.MeshPeerSpec) (Plan, error) {
	self = self.Masked()
	if !self.Addr().Is4() || self.Bits() != nodeCIDRBits {
		return Plan{}, fmt.Errorf("%w: got %s", ErrSelfCIDR, self)
	}
	var plan Plan
	included := make([]netv1.MeshPeerSpec, 0, len(peers))
	for _, raw := range peers {
		spec := raw.WithDefaults()
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
		plan.Peers = append(plan.Peers, pc)
		included = append(included, spec)
	}
	routes, err := RouteSet(self, included)
	if err != nil {
		return Plan{}, err
	}
	plan.Routes = routes
	return plan, nil
}

// ValidatePlan is the strict form of BuildPlan: it returns a Plan only if EVERY
// peer is programmable, turning a peer BuildPlan would silently skip (bad key,
// malformed or non-/24 podCIDR, AllowedIPs != podCIDR, unsupported schemaVersion)
// into an error instead. The netd daemon uses it to REJECT an out-of-policy
// ConfigureMesh at the privilege boundary, where a skipped peer is a client bug or
// an attack rather than the benign cluster churn BuildPlan tolerates for the
// in-process reconcile loop. self must be an IPv4 /24 (ErrSelfCIDR otherwise);
// per-peer problems wrap ErrPeerConfig.
func ValidatePlan(self netip.Prefix, peers []netv1.MeshPeerSpec) (Plan, error) {
	plan, err := BuildPlan(self, peers)
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
	return plan, nil
}

// UAPI renders the wireguard userspace-API configuration that programs this plan's
// peer set as a FULL replacement (replace_peers=true), the form IpcSet consumes.
// A full resync is idempotent and naturally handles an endpoint move, a key
// rotation, or a peer removal between reconciles — the next snapshot simply
// replaces the set. Per peer it sets the endpoint, the keepalive, and the
// AllowedIPs (also as a replacement). It excludes private material entirely.
func (p Plan) UAPI() string {
	var b strings.Builder
	b.WriteString("replace_peers=true\n")
	for _, pc := range p.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", pc.PublicKeyHex)
		if pc.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", pc.Endpoint)
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", pc.KeepaliveSeconds)
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range pc.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
		}
	}
	return b.String()
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
