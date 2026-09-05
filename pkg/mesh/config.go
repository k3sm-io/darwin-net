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
	"fmt"

	netv1 "k3sm.io/apis/net/v1"
)

// MTU is the wireguard tunnel MTU (DESIGN §5b: 1380, leaving headroom for the wg
// overhead under the lo0 MTU). It is the apis cross-repo constant rendered as an
// int for the tun device and the route/link setup.
const MTU = int(netv1.DefaultMeshMTU)

// PersistentKeepaliveSeconds is the wireguard PersistentKeepalive each peer uses
// to keep a NAT/roam path warm. It is the apis cross-repo default (25s).
const PersistentKeepaliveSeconds = int(netv1.DefaultPersistentKeepaliveSeconds)

// DefaultListenPort is the default UDP port the node's wireguard listens on. The
// MeshPeer endpoint a node advertises is host:port; k3sm overrides this when the
// node advertises a different port.
const DefaultListenPort = 51820

// tcpIPv4HeaderBytes is the combined IPv4 (20) + TCP (20) header size subtracted
// from the link MTU to derive the largest TCP payload (MSS) that fits without
// fragmentation across the tunnel.
const tcpIPv4HeaderBytes = 40

// MSSClamp is the TCP MSS the pf scrub anchor clamps to on the utun egress: the
// mesh MTU minus the IPv4+TCP headers. A pod socket bound to an lo0 alias sees the
// loopback MTU (16384) and would otherwise advertise an MSS too large for the 1380
// utun, blackholing large-payload cross-node TCP.
const MSSClamp = MTU - tcpIPv4HeaderBytes

// MaxMSS returns the largest TCP MSS (payload) that fits in an IPv4 segment on a
// link of the given MTU. It is the derivation behind MSSClamp, exposed so the
// clamp value is table-tested rather than asserted as a bare literal.
func MaxMSS(mtu int) int { return mtu - tcpIPv4HeaderBytes }

// PFMSSClampRule renders the minimal pf scrub rule that clamps TCP MSS on the
// mesh utun egress. It is scoped `on <utun>` to the tunnel only — clamping lo0
// (MTU 16384) would needlessly shrink same-node loopback segments. This is the
// rule text loaded into the io.k3sm.mesh pf anchor; wiring the anchor into the
// main ruleset is the root netd boundary's job — only this minimal MSS clamp is
// wired here; the full pf sub-anchor is not built. It is exported so the netd
// daemon renders the same rule for the standalone MSS-clamp verb, never
// accepting pf text over the wire.
func PFMSSClampRule(utun string, mss int) string {
	return fmt.Sprintf("scrub out on %s proto tcp from any to any max-mss %d\n", utun, mss)
}
