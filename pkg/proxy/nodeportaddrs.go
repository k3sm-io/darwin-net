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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// NodePortPresetLocal is the preset entry of a NodePort address spec that
// names loopback (127.0.0.1) plus this node's own address (its InternalIP: the
// mesh address on a joined node, the lo0-aliased pod-range address on a single
// node). It is the untrusted-network setting: NodePorts answer on the node
// itself and over the mesh, and on no LAN or Wi-Fi address.
const NodePortPresetLocal = "local"

// ErrNodePortAddresses is the named error of a NodePort address spec that
// cannot be used: an entry that is neither a CIDR nor a preset, an IPv6 CIDR,
// or a spec that resolves to no address on this host.
var ErrNodePortAddresses = errors.New("invalid nodeport addresses")

// loopbackV4 is the loopback address the preset and a 127.0.0.0/8 CIDR resolve to.
var loopbackV4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// nodePortSpec is a parsed NodePort address spec: its CIDRs and whether the
// preset appears.
type nodePortSpec struct {
	prefixes []netip.Prefix
	local    bool
}

// parseNodePortSpec parses a non-empty spec, refusing an empty entry, an entry
// that is neither a CIDR nor the preset, and an IPv6 CIDR.
func parseNodePortSpec(spec string) (nodePortSpec, error) {
	var out nodePortSpec
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "":
			return nodePortSpec{}, fmt.Errorf("%w: %q has an empty entry", ErrNodePortAddresses, spec)
		case entry == NodePortPresetLocal:
			out.local = true
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nodePortSpec{}, fmt.Errorf("%w: %q is neither a CIDR nor the preset %q", ErrNodePortAddresses, entry, NodePortPresetLocal)
		}
		if !prefix.Addr().Is4() {
			return nodePortSpec{}, fmt.Errorf("%w: %q is an IPv6 range; NodePort listeners are IPv4 only", ErrNodePortAddresses, entry)
		}
		out.prefixes = append(out.prefixes, prefix.Masked())
	}
	return out, nil
}

// ValidateNodePortAddresses checks a NodePort address spec's syntax without
// resolving it against a host: an empty spec (the wildcard default), or a
// comma-separated list of IPv4 CIDRs and the NodePortPresetLocal preset. It is
// for a caller that records the spec for a daemon to resolve later (an
// installer), so a typo is refused before it is written down.
func ValidateNodePortAddresses(spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	_, err := parseNodePortSpec(strings.TrimSpace(spec))
	return err
}

// ResolveNodePortAddresses turns a NodePort address spec into the addresses
// every NodePort listener binds.
//
// The spec is the kube-proxy --nodeport-addresses shape: a comma-separated list
// of CIDRs, each selecting the host addresses inside it. One preset entry may
// appear among them, NodePortPresetLocal. An empty spec returns nil, which the
// proxy reads as the wildcard (the upstream default: every address).
//
// Candidates are host (this host's interface addresses, as HostAddrs reports
// them), loopback, and node (this node's own address) even when node is not
// yet on an interface: the node address is aliased by the pod network during
// startup, after the spec is resolved. The result is IPv4 only, deduplicated
// and sorted. It is a snapshot of the host at the call: an address that
// appears on the host later is not picked up until the caller resolves the
// spec again and swaps the result in (Proxy.PrepareNodePortAddresses).
//
// An IPv6 CIDR is refused rather than skipped, and so is a spec that selects
// no address: either would leave every NodePort unbound with nothing saying why.
func ResolveNodePortAddresses(spec string, node netip.Addr, host []netip.Addr) ([]netip.Addr, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	parsed, err := parseNodePortSpec(spec)
	if err != nil {
		return nil, err
	}
	node = node.Unmap()
	nodeUsable := node.Is4() && !node.IsUnspecified()
	candidates := []netip.Addr{loopbackV4}
	if nodeUsable {
		candidates = append(candidates, node)
	}
	for _, a := range host {
		if a = a.Unmap(); a.Is4() && !a.IsUnspecified() {
			candidates = append(candidates, a)
		}
	}

	var out []netip.Addr
	if parsed.local {
		out = append(out, loopbackV4)
		if nodeUsable && !node.IsLoopback() {
			out = append(out, node)
		}
	}
	for _, prefix := range parsed.prefixes {
		for _, c := range candidates {
			if prefix.Contains(c) {
				out = append(out, c)
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %q selects no address on this host", ErrNodePortAddresses, spec)
	}
	return out, nil
}

// HostAddrs reports the addresses ResolveNodePortAddresses resolves CIDRs
// against: every address of this host's up, non-loopback interfaces, plus
// 127.0.0.1. The lo0 aliases are deliberately left out (they are pod addresses
// and Service VIPs, which come and go, and a NodePort must never bind one); the
// node's own address reaches the resolver as its own argument instead.
func HostAddrs() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := []netip.Addr{loopbackV4}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			// One unreadable interface must not hide the rest.
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out, nil
}
