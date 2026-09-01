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

package proxy

import (
	"net"
	"net/netip"
)

// egressScope is the destination-scoped mesh-egress source decision: given a
// backend's precomputed locality and the address a dial is actually about to use,
// it answers which local source that dial binds — this node's reserved mesh-egress
// /32, or nothing at all (kernel default source selection).
//
// # Why the decision is per dial and not per proxy
//
// wireguard admits an inbound packet only when its source falls inside some peer's
// AllowedIPs (= the sending node's pod /24), so a dial that egresses the utun to a
// pod on another node must be sourced from this node's mesh-egress /32 or the reply
// is silently dropped. Binding that source on EVERY dial — the construction-time
// contract this type replaces — buys that one case and breaks every other one: a
// loopback backend, a node LAN destination (a hostNetwork pod reports podIP ==
// nodeIP, and its reply would route back over the peer's utun and be dropped as
// outside the sender's AllowedIPs), and any upstream address all get a source that
// does not belong on their route. That is why a mesh server could not previously
// set a mesh-egress source at all without breaking its own backend dials.
//
// # The predicate
//
// A dial binds the mesh-egress source if and only if all three hold:
//
//   - a mesh-egress source is configured at all (WithMeshEgressSource; the zero
//     Addr is the single-node path, where no utun exists to bind to);
//   - the backend is LocalityRemote — outside this node's own pod /24. Locality is
//     precomputed per backend at reconcile time (routing.go), so the accept path
//     pays a comparison, not a classification;
//   - the dial destination is inside the cluster pod aggregate (WithClusterPodCIDR,
//     default podnet.ClusterPodCIDR).
//
// LocalityUnknown — the zero/invalid node-podCIDR state that the routing decision
// already fails open for — NEVER binds. It fails to the kernel default, not to a
// bind: a node that cannot classify its own backends must not assert a source
// address for them.
//
// # Which address the containment test reads
//
// It reads the address the packet is actually sent to (the transport-resolved
// destination), not the published backend identity, because the source bind must
// match the route the kernel picks and the route follows the packet. Only the
// two-address vm-pod model (RoutingTable.SetTransportOverrides) can make the two
// differ, and there the packet leaves over vmnet rather than the utun — where a
// mesh-egress lo0 source would be wrong. Every identity-keyed decision (the
// NetworkPolicy verdict, the deny log, ClientIP affinity) keeps reading the
// published address; only the source bind follows the packet.
//
// The value is immutable: it is built once by New (options) and read by every
// per-connection handle goroutine and every UDP relay with no lock, which is the
// property that makes the shared *net.Dialer safe (see Proxy.dialerFor).
type egressScope struct {
	// src is this node's reserved mesh-egress /32 (podnet.MeshEgressIP), or the
	// zero Addr on a single node. The zero Addr disables binding entirely.
	src netip.Addr
	// clusterCIDR is the pod aggregate a destination must fall inside for a bind:
	// every pod IP in the cluster is carved from it, so "inside it and outside this
	// node's /24" is exactly "a pod on another node". The zero Prefix disables
	// binding (fail to the kernel default), though New always defaults it.
	clusterCIDR netip.Prefix
}

// sourceFor returns the local source address a dial to dst must bind, or the zero
// Addr when the dial keeps the kernel's default source selection. loc is the picked
// backend's precomputed Locality and dst is the address the dial will actually use
// (transport-resolved). It is the single home of the scoping predicate — both the
// TCP dial (Proxy.dialerFor) and the UDP relay's per-flow upstream socket call it,
// so the two protocols cannot drift apart.
func (s egressScope) sourceFor(loc Locality, dst netip.Addr) netip.Addr {
	if !s.src.IsValid() || !s.clusterCIDR.IsValid() {
		return netip.Addr{}
	}
	// LocalityUnknown and LocalityLocal both fail to the kernel default: an
	// unclassifiable node must not assert a source, and a same-node backend is
	// reached over loopback with no mesh hop.
	if loc != LocalityRemote {
		return netip.Addr{}
	}
	// Remote-but-not-a-pod-IP (a node LAN address, an upstream host, loopback)
	// keeps the kernel default: its reply never comes back over the utun.
	if !s.clusterCIDR.Contains(dst.Unmap()) {
		return netip.Addr{}
	}
	return s.src
}

// dialerFor returns the *net.Dialer a TCP backend dial must use for a backend with
// locality loc at transport address dst: the mesh-source-bound dialer when
// egressScope.sourceFor elects a bind, otherwise the default-source dialer.
//
// Both dialers are built once in New and are never mutated afterwards, so the
// per-connection handle goroutines only ever read them. Selecting between two
// immutable dialers is the whole point: setting p.dialer.LocalAddr per connection
// would be a data race across those goroutines and would non-deterministically
// apply one connection's source to another's dial — the wrong-source blackhole,
// intermittently.
func (p *Proxy) dialerFor(loc Locality, dst netip.Addr) *net.Dialer {
	if p.meshDialer != nil && p.egress.sourceFor(loc, dst).IsValid() {
		return p.meshDialer
	}
	return p.dialer
}
