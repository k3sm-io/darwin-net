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

package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// This file is the pure record-synthesis library the in-process cluster
// resolver (k3sm/pkg/netserve) consumes for headless / StatefulSet-identity /
// SRV / PTR answers. It is watch-free and
// dependency-light: the INPUTS are already-fetched Service/EndpointSlice-shaped
// values (SynthService / SynthEndpoint — small consumer-side structs, NOT
// k8s.io/api types, so the layer stays table-testable and import-cheap), and
// the OUTPUT is a RecordSet of synthesized record sets keyed by fully
// qualified owner name. The dashed-IP pod form (<a-b-c-d>.<ns>.pod.<domain>)
// is not synthesized into a set at all — the name encodes the answer, so
// PodAddrFromName decodes it statelessly and the server needs no Pod watch.
//
// Record semantics follow the upstream kube-dns/CoreDNS specification
// (kubernetes/dns: DNS-Based Service Discovery), with the cluster domain a
// parameter. All owner names in a RecordSet are lower-case and carry NO
// trailing dot; callers compare queries after the same normalization.

// Sentinel errors for record synthesis and pod-name decoding. Compare with
// errors.Is, never by string match.
var (
	// ErrSynthInput is returned by Synthesize when the service, endpoints, or
	// domain are malformed (empty names, a normal service without a ClusterIP,
	// an invalid endpoint address, ...).
	ErrSynthInput = errors.New("dns: invalid record synthesis input")
	// ErrNotPodName is returned by PodAddrFromName when the queried name is not
	// a well-formed <ip-with-dashes>.<ns>.pod.<domain> pod name.
	ErrNotPodName = errors.New("dns: not a dashed-ip pod name")
)

// SynthService is the Service-shaped synthesis input: the handful of fields
// record synthesis needs, extracted by the caller from its Service watch.
type SynthService struct {
	// Name and Namespace identify the Service (RFC 1123 labels).
	Name      string
	Namespace string
	// ClusterIP is the Service VIP. Required for a normal (ClusterIP) service;
	// ignored when Headless (a headless service has none).
	ClusterIP netip.Addr
	// Headless marks a clusterIP: None service: its A set is the backend pod
	// IPs, and SRV records target the individual endpoints.
	Headless bool
	// PublishNotReadyAddresses mirrors spec.publishNotReadyAddresses: when set,
	// not-ready endpoints are included in every synthesized set.
	PublishNotReadyAddresses bool
	// Ports are the service's ports. Only NAMED ports get SRV records, per
	// upstream semantics. For a headless service the caller supplies the
	// endpoint (target) ports as published in the EndpointSlice.
	Ports []SynthPort
}

// SynthPort is one service port for SRV synthesis.
type SynthPort struct {
	// Name is the port name; an unnamed port synthesizes no SRV record.
	Name string
	// Port is the port number the SRV record carries.
	Port uint16
	// Protocol is "tcp", "udp", or "sctp" (any case); empty defaults to "tcp".
	Protocol string
}

// SynthEndpoint is one EndpointSlice-endpoint-shaped synthesis input.
type SynthEndpoint struct {
	// IP is the endpoint's pod IP (IPv4 in k3sm's 100.64.0.0/10 space).
	IP netip.Addr
	// Hostname is the endpoint's hostname field — set for StatefulSet pods
	// (spec.hostname + a matching headless serviceName), empty otherwise. A
	// hostname-carrying endpoint gets the per-pod identity A record
	// <hostname>.<svc>.<ns>.svc.<domain>; the rest are named by dashed IP.
	Hostname string
	// Ready is the endpoint's serving readiness. Not-ready endpoints are
	// excluded from every set unless PublishNotReadyAddresses is set.
	Ready bool
}

// SRVRecord is one synthesized SRV answer.
type SRVRecord struct {
	// Target is the owner name the SRV points at (no trailing dot); it is
	// always also present as a key in the same RecordSet's A map.
	Target string
	// Port is the SRV port.
	Port uint16
	// Priority is always 0, per the kube-dns specification.
	Priority uint16
	// Weight is 100/n for n records under one SRV name (minimum 1), per the
	// kube-dns specification's equal-weight split.
	Weight uint16
}

// RecordSet is the synthesized record output, keyed by fully qualified owner
// name (lower-case, no trailing dot). Slices are sorted deterministically
// (A by address, SRV by target) so outputs are directly comparable.
type RecordSet struct {
	// A maps <name> -> A record addresses.
	A map[string][]netip.Addr
	// SRV maps _<port>._<proto>.<svc>.<ns>.svc.<domain> -> SRV records.
	SRV map[string][]SRVRecord
	// PTR maps <reversed>.in-addr.arpa -> the owning name (the service name
	// for a ClusterIP, the hostname-qualified or dashed-IP endpoint name for
	// a pod IP).
	PTR map[string]string
}

// Synthesize builds the DNS record sets for one Service and its endpoints,
// per upstream kube-dns/CoreDNS semantics with clusterDomain a parameter
// (e.g. "cluster.local"):
//
//   - Normal (ClusterIP) service: A <svc>.<ns>.svc.<domain> -> ClusterIP; one
//     SRV per named port targeting that service name with the service port;
//     PTR for the ClusterIP.
//   - Headless service: A <svc>.<ns>.svc.<domain> -> every included backend
//     IP; a per-endpoint identity A record (<hostname>.<svc>... when the
//     endpoint carries a Hostname, <ip-with-dashes>.<svc>... otherwise, so
//     every SRV target resolves); per named port, one SRV per included
//     endpoint targeting the endpoint's name; PTR per included endpoint IP.
//
// An endpoint is included iff it is Ready or the service publishes not-ready
// addresses — the readiness filter is load-bearing for rollout correctness.
// endpoints is ignored for a normal service (the proxy owns VIP->backend
// routing; DNS answers only the VIP).
func Synthesize(clusterDomain string, svc SynthService, endpoints []SynthEndpoint) (RecordSet, error) {
	domain, err := normalizeDomain(clusterDomain)
	if err != nil {
		return RecordSet{}, err
	}
	if !isDNSLabel(strings.ToLower(svc.Name)) || !isDNSLabel(strings.ToLower(svc.Namespace)) {
		return RecordSet{}, fmt.Errorf("%w: service name %q / namespace %q must be RFC 1123 labels", ErrSynthInput, svc.Name, svc.Namespace)
	}
	rs := RecordSet{
		A:   make(map[string][]netip.Addr),
		SRV: make(map[string][]SRVRecord),
		PTR: make(map[string]string),
	}
	svcName := strings.ToLower(svc.Name) + "." + strings.ToLower(svc.Namespace) + ".svc." + domain

	if !svc.Headless {
		return rs, synthesizeClusterIP(&rs, svc, svcName)
	}
	return rs, synthesizeHeadless(&rs, svc, svcName, endpoints)
}

// synthesizeClusterIP fills rs for a normal (ClusterIP) service: a single VIP
// A record, a single SRV per named port targeting the service name, and the
// VIP's PTR.
func synthesizeClusterIP(rs *RecordSet, svc SynthService, svcName string) error {
	if !svc.ClusterIP.Is4() {
		return fmt.Errorf("%w: service %s: a normal service needs an IPv4 ClusterIP", ErrSynthInput, svcName)
	}
	rs.A[svcName] = []netip.Addr{svc.ClusterIP}
	rev, err := ReverseName(svc.ClusterIP)
	if err != nil {
		return fmt.Errorf("service %s: %w", svcName, err)
	}
	rs.PTR[rev] = svcName
	for _, p := range svc.Ports {
		srvName, err := srvOwnerName(p, svcName)
		if err != nil {
			return err
		}
		if srvName == "" {
			continue // unnamed port: no SRV record
		}
		rs.SRV[srvName] = append(rs.SRV[srvName], SRVRecord{Target: svcName, Port: p.Port})
	}
	finalizeSRVWeights(rs.SRV)
	return nil
}

// synthesizeHeadless fills rs for a headless service: the all-backends A set,
// per-endpoint identity A records, per-endpoint SRV records, and per-IP PTRs.
func synthesizeHeadless(rs *RecordSet, svc SynthService, svcName string, endpoints []SynthEndpoint) error {
	included := make([]SynthEndpoint, 0, len(endpoints))
	seen := make(map[netip.Addr]struct{}, len(endpoints))
	for _, e := range endpoints {
		if !e.Ready && !svc.PublishNotReadyAddresses {
			continue // readiness filter: not-ready backends must not resolve
		}
		if !e.IP.Is4() {
			return fmt.Errorf("%w: service %s: endpoint address %s must be IPv4", ErrSynthInput, svcName, e.IP)
		}
		if e.Hostname != "" && !isDNSLabel(strings.ToLower(e.Hostname)) {
			return fmt.Errorf("%w: service %s: endpoint hostname %q must be an RFC 1123 label", ErrSynthInput, svcName, e.Hostname)
		}
		if _, dup := seen[e.IP]; dup {
			continue // one record per address
		}
		seen[e.IP] = struct{}{}
		included = append(included, e)
	}
	sort.Slice(included, func(i, j int) bool { return included[i].IP.Compare(included[j].IP) < 0 })

	for _, e := range included {
		name := endpointOwnerName(e, svcName)
		rs.A[svcName] = append(rs.A[svcName], e.IP)
		rs.A[name] = append(rs.A[name], e.IP)
		rev, err := ReverseName(e.IP)
		if err != nil {
			return fmt.Errorf("service %s: %w", svcName, err)
		}
		rs.PTR[rev] = name
	}
	for _, p := range svc.Ports {
		srvName, err := srvOwnerName(p, svcName)
		if err != nil {
			return err
		}
		if srvName == "" {
			continue // unnamed port: no SRV record
		}
		for _, e := range included {
			rs.SRV[srvName] = append(rs.SRV[srvName], SRVRecord{Target: endpointOwnerName(e, svcName), Port: p.Port})
		}
	}
	finalizeSRVWeights(rs.SRV)
	return nil
}

// endpointOwnerName is the DNS name owning one headless endpoint: the
// hostname-qualified StatefulSet identity when the endpoint carries a
// Hostname, else the dashed-IP name under the service — both resolvable, so
// SRV targets always have a matching A record.
func endpointOwnerName(e SynthEndpoint, svcName string) string {
	if e.Hostname != "" {
		return strings.ToLower(e.Hostname) + "." + svcName
	}
	return dashedIP(e.IP) + "." + svcName
}

// srvOwnerName builds the _<port>._<proto>. owner name for a service port. An
// unnamed port returns "" (no SRV); a malformed name or protocol errors.
func srvOwnerName(p SynthPort, svcName string) (string, error) {
	if p.Name == "" {
		return "", nil
	}
	name := strings.ToLower(p.Name)
	if !isDNSLabel(name) {
		return "", fmt.Errorf("%w: service %s: port name %q must be an RFC 1123 label", ErrSynthInput, svcName, p.Name)
	}
	proto := strings.ToLower(p.Protocol)
	if proto == "" {
		proto = "tcp"
	}
	switch proto {
	case "tcp", "udp", "sctp":
	default:
		return "", fmt.Errorf("%w: service %s: port %s: unsupported protocol %q", ErrSynthInput, svcName, p.Name, p.Protocol)
	}
	return "_" + name + "._" + proto + "." + svcName, nil
}

// finalizeSRVWeights sets each SRV group's equal-split weight (100/n, min 1,
// per the kube-dns specification) and sorts each group by target for
// deterministic output. Priority stays 0.
func finalizeSRVWeights(srv map[string][]SRVRecord) {
	for name, recs := range srv {
		w := uint16(100 / len(recs))
		if w == 0 {
			w = 1
		}
		for i := range recs {
			recs[i].Weight = w
		}
		sort.Slice(recs, func(i, j int) bool { return recs[i].Target < recs[j].Target })
		srv[name] = recs
	}
}

// PodDNSName encodes the dashed-IP pod A name <a-b-c-d>.<ns>.pod.<domain> for
// an IPv4 pod address — the inverse of PodAddrFromName. It returns an error if
// ip is not IPv4 or the namespace/domain are malformed.
func PodDNSName(ip netip.Addr, namespace, clusterDomain string) (string, error) {
	domain, err := normalizeDomain(clusterDomain)
	if err != nil {
		return "", err
	}
	ns := strings.ToLower(namespace)
	if !isDNSLabel(ns) {
		return "", fmt.Errorf("%w: namespace %q must be an RFC 1123 label", ErrSynthInput, namespace)
	}
	if !ip.Is4() {
		return "", fmt.Errorf("%w: pod address %s must be IPv4", ErrSynthInput, ip)
	}
	return dashedIP(ip) + "." + ns + ".pod." + domain, nil
}

// PodAddrFromName decodes a dashed-IP pod query <a-b-c-d>.<ns>.pod.<domain>
// into the pod address and namespace it encodes. It is a pure, stateless
// decoder — the name IS the answer — so the resolver serves pod A records
// with no Pod watch. The name may carry a trailing dot and any case. It
// returns ErrNotPodName for anything that is not a well-formed pod name under
// clusterDomain (wrong suffix, wrong label count, a dashed part that is not a
// strict dotted-quad IPv4 address).
func PodAddrFromName(name, clusterDomain string) (netip.Addr, string, error) {
	domain, err := normalizeDomain(clusterDomain)
	if err != nil {
		return netip.Addr{}, "", err
	}
	q := strings.ToLower(strings.TrimSuffix(name, "."))
	suffix := ".pod." + domain
	rest, ok := strings.CutSuffix(q, suffix)
	if !ok {
		return netip.Addr{}, "", fmt.Errorf("%w: %q not under pod.%s", ErrNotPodName, name, domain)
	}
	dashed, ns, ok := strings.Cut(rest, ".")
	if !ok || dashed == "" || ns == "" || strings.Contains(ns, ".") {
		return netip.Addr{}, "", fmt.Errorf("%w: %q must be <ip-with-dashes>.<ns>%s", ErrNotPodName, name, suffix)
	}
	if !isDNSLabel(ns) {
		return netip.Addr{}, "", fmt.Errorf("%w: %q: namespace %q is not an RFC 1123 label", ErrNotPodName, name, ns)
	}
	if strings.Count(dashed, "-") != 3 {
		return netip.Addr{}, "", fmt.Errorf("%w: %q: %q is not a dashed IPv4 address", ErrNotPodName, name, dashed)
	}
	// netip.ParseAddr is strict (no leading zeros, no empty octets, 0-255
	// range), which is exactly the rejection behavior the decoder needs.
	ip, perr := netip.ParseAddr(strings.ReplaceAll(dashed, "-", "."))
	if perr != nil || !ip.Is4() {
		return netip.Addr{}, "", fmt.Errorf("%w: %q: %q is not a dashed IPv4 address", ErrNotPodName, name, dashed)
	}
	return ip, ns, nil
}

// ReverseName returns the in-addr.arpa PTR owner name for an IPv4 address
// (e.g. 100.64.0.7 -> "7.0.64.100.in-addr.arpa"), lower-case with no trailing
// dot, matching the RecordSet.PTR key convention.
func ReverseName(ip netip.Addr) (string, error) {
	if !ip.Is4() {
		return "", fmt.Errorf("%w: reverse name needs an IPv4 address, got %s", ErrSynthInput, ip)
	}
	o := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", o[3], o[2], o[1], o[0]), nil
}

// dashedIP renders an IPv4 address as its dashed pod-name form (1.2.3.4 ->
// "1-2-3-4").
func dashedIP(ip netip.Addr) string {
	o := ip.As4()
	return strconv.Itoa(int(o[0])) + "-" + strconv.Itoa(int(o[1])) + "-" + strconv.Itoa(int(o[2])) + "-" + strconv.Itoa(int(o[3]))
}

// normalizeDomain lower-cases and strips the trailing dot from the cluster
// domain, validating it is a plausible DNS name (non-empty RFC 1123 labels).
func normalizeDomain(clusterDomain string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(clusterDomain, "."))
	if d == "" {
		return "", fmt.Errorf("%w: empty cluster domain", ErrSynthInput)
	}
	for _, label := range strings.Split(d, ".") {
		if !isDNSLabel(label) {
			return "", fmt.Errorf("%w: cluster domain %q: label %q is not an RFC 1123 label", ErrSynthInput, clusterDomain, label)
		}
	}
	return d, nil
}

// isDNSLabel reports whether s is a lower-case RFC 1123 DNS label: 1-63 chars
// of [a-z0-9-], starting and ending alphanumeric.
func isDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
