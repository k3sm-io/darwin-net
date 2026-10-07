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
	"net/netip"
	"sort"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// EligibleDirectRoutes derives the peers to route over a cable from three inputs
// that must ALL agree, keyed by peer node name:
//
//   - status, this node's resolved DirectLink status: the port's State is
//     DirectLinkStateUp (both ends list each other, report link and ready routes,
//     neither opts out, the peer is live) and it names the peer node and the
//     peer's direct-link address (an address in a reserved half);
//   - localUp(iface): this node sees link on the interface right now;
//   - probeAlive(iface, peer): the liveness probe hears the peer over the cable.
//
// Server status alone is never enough: in a cable-only cluster the update that
// says the cable died would have to arrive over the cable that died, so the local
// link state and the probe are what withdraw the route in time. When two cables
// reach the same peer the lowest interface name wins, so the choice is stable.
func EligibleDirectRoutes(status netv1alpha1.DirectLinkStatus, localUp func(iface string) bool, probeAlive func(iface string, peer netip.Addr) bool) DirectRoutes {
	ports := make([]netv1alpha1.DirectLinkPortStatus, len(status.Ports))
	copy(ports, status.Ports)
	sort.Slice(ports, func(i, j int) bool { return ports[i].Iface < ports[j].Iface })
	out := make(DirectRoutes)
	for _, p := range ports {
		gw, ok := directTarget(p)
		if !ok {
			continue
		}
		if _, taken := out[p.PeerNodeName]; taken {
			continue
		}
		if localUp == nil || !localUp(p.Iface) {
			continue
		}
		if probeAlive == nil || !probeAlive(p.Iface, gw) {
			continue
		}
		out[p.PeerNodeName] = DirectRoute{Iface: p.Iface, Gateway: gw}
	}
	return out
}

// directTarget returns the peer's link address for a port the resolver reports
// up, or false when the port is not a usable direct path by its status alone.
func directTarget(p netv1alpha1.DirectLinkPortStatus) (netip.Addr, bool) {
	if p.State != netv1alpha1.DirectLinkStateUp || p.PeerNodeName == "" || p.Iface == "" {
		return netip.Addr{}, false
	}
	gw, err := netip.ParseAddr(p.PeerLinkIP)
	if err != nil || !netv1alpha1.IsLinkAddress(gw) {
		return netip.Addr{}, false
	}
	return gw.Unmap(), true
}
