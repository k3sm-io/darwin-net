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

// TunnelMSS is the TCP MSS the kernel derives for a connection across the mesh:
// the tunnel MTU minus the IPv4+TCP headers (1380 - 40 = 1340). XNU sizes a
// connection's MSS from the route to the destination, and every peer pod CIDR
// routes to the utun at MTU, so a pod socket bound to an lo0 alias (loopback MTU
// 16384) still advertises this value toward a peer. It is documentation of the
// expected on-wire MSS, not a value the mesh programs; no pf rule clamps it.
const TunnelMSS = MTU - tcpIPv4HeaderBytes

// MaxMSS returns the largest TCP MSS (payload) that fits in an IPv4 segment on a
// link of the given MTU. It is the derivation behind TunnelMSS, exposed so the
// value is table-tested rather than asserted as a bare literal.
func MaxMSS(mtu int) int { return mtu - tcpIPv4HeaderBytes }
