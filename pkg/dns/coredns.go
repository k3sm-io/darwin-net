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
	"fmt"
	"strings"

	netv1 "k3sm.io/apis/net/v1"
)

// CorefileOptions parameterizes a CoreDNS Corefile bound to the DNS VIP. NOTE
// (2026-06 upstream-alignment audit): this renderer is currently UNCONSUMED — the
// cluster resolver that actually runs is k3sm's in-process A-record resolver
// (k3sm/pkg/netserve), NOT CoreDNS-the-binary; this Corefile is an export kept for
// the deferred native-CoreDNS follow-up (DESIGN §5b). Pods are pointed at the DNS
// VIP via the netv1.DNSConfig the getaddrinfo shim consumes (PodDNSConfig — live).
type CorefileOptions struct {
	// ClusterDomain is the zone CoreDNS is authoritative for via the kubernetes
	// plugin, e.g. "cluster.local".
	ClusterDomain string
	// BindIP is the DNS VIP the rendered Corefile listens on (the lo0 alias the
	// proxy exempts for the kube-dns Service). Empty binds all interfaces.
	BindIP string
	// Port is the DNS port (53 by default).
	Port int32
	// UpstreamResolvers are the forwarders for non-cluster names. When empty, the
	// rendered Corefile forwards to the host resolver via /etc/resolv.conf — note
	// macOS pods never read resolv.conf themselves; this would be CoreDNS's own
	// upstream if the native-CoreDNS follow-up ships (the in-process resolver that
	// serves DNS today has its own forwarder).
	UpstreamResolvers []string
}

// DefaultDNSPort is the standard DNS port.
const DefaultDNSPort = 53

// DefaultDNSVIP is the conventional kube-dns ClusterIP in k3sm's default
// 10.43.0.0/16 service CIDR (the .10 of the range, matching k3s). The per-node
// resolver runs bound to this address (the in-process k3sm/pkg/netserve resolver;
// PerNodeDNS renders the equivalent Corefile) so cluster DNS is always answered
// node-locally over loopback — never steered over the wireguard mesh, which
// carries only pod /24s (a mesh-steered DNS VIP would blackhole, since no peer's
// AllowedIPs cover 10.43.0.10). The Service proxy exempts this VIP from ownership
// (proxy.WithInfraVIPExemptions) so the resolver and the proxy do not fight for
// 10.43.0.10:53 (EADDRINUSE). It is a darwin-net default; the authoritative value
// is the server's service-CIDR config (k3sm).
const DefaultDNSVIP = "10.43.0.10"

// PerNodeDNS returns the CorefileOptions for the per-node cluster resolver: a
// Corefile bound to the DNS VIP (dnsVIP, default DefaultDNSVIP) on the standard
// DNS port, authoritative for clusterDomain, forwarding all other names to
// upstream. The per-node resolver binds the same VIP on each node's own lo0 alias
// so a pod's DNS query resolves over loopback and never crosses the mesh; the
// Service proxy must exempt dnsVIP (proxy.WithInfraVIPExemptions) so the two do
// not contend for dnsVIP:53. NOTE: the output is currently UNCONSUMED — the
// in-process k3sm/pkg/netserve resolver serves DNS today; this renders the
// equivalent Corefile for the deferred native-CoreDNS follow-up (DESIGN §5b). An
// empty dnsVIP defaults to DefaultDNSVIP and an empty clusterDomain defaults to
// cluster.local (applied by Corefile).
func PerNodeDNS(dnsVIP, clusterDomain string, upstream []string) CorefileOptions {
	if dnsVIP == "" {
		dnsVIP = DefaultDNSVIP
	}
	return CorefileOptions{
		ClusterDomain:     clusterDomain,
		BindIP:            dnsVIP,
		Port:              DefaultDNSPort,
		UpstreamResolvers: upstream,
	}
}

// Corefile renders a CoreDNS configuration string for the cluster resolver. It
// serves the cluster domain via the kubernetes plugin, answers pod/Service
// records, caches, and forwards everything else upstream. NOTE: the output is
// currently UNCONSUMED (the in-process k3sm/pkg/netserve resolver serves cluster
// DNS, not a CoreDNS binary); it is kept as the native-CoreDNS export (DESIGN
// §5b) — a future supervised CoreDNS would consume it via -conf.
func (o CorefileOptions) Corefile() string {
	port := o.Port
	if port == 0 {
		port = DefaultDNSPort
	}
	domain := o.ClusterDomain
	if domain == "" {
		domain = "cluster.local"
	}
	upstream := "forward . /etc/resolv.conf"
	if len(o.UpstreamResolvers) > 0 {
		upstream = "forward . " + strings.Join(o.UpstreamResolvers, " ")
	}

	var b strings.Builder
	// The server block listens on the VIP:port; bind pins it to the alias so it
	// does not answer on every interface (mirrors the proxy's bind discipline).
	fmt.Fprintf(&b, ".:%d {\n", port)
	if o.BindIP != "" {
		fmt.Fprintf(&b, "    bind %s\n", o.BindIP)
	}
	fmt.Fprintf(&b, "    kubernetes %s in-addr.arpa ip6.arpa {\n", domain)
	b.WriteString("        pods insecure\n")
	b.WriteString("        fallthrough in-addr.arpa ip6.arpa\n")
	b.WriteString("    }\n")
	b.WriteString("    cache 30\n")
	b.WriteString("    loop\n")
	fmt.Fprintf(&b, "    %s\n", upstream)
	b.WriteString("    errors\n")
	b.WriteString("}\n")
	return b.String()
}

// PodDNSConfig builds the netv1.DNSConfig a pod in namespace should receive: the
// cluster DNS VIP, the cluster domain, and the standard Kubernetes search list
// (<ns>.svc.<domain>, svc.<domain>, <domain>) with the default ndots. It is the
// data the getaddrinfo shim is initialized with so a pod's unqualified Service
// lookups expand correctly. dnsVIP is the address CoreDNS is bound to (matching
// CorefileOptions.BindIP).
func PodDNSConfig(dnsVIP, clusterDomain, namespace string) netv1.DNSConfig {
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	search := []string{
		fmt.Sprintf("%s.svc.%s", namespace, clusterDomain),
		fmt.Sprintf("svc.%s", clusterDomain),
		clusterDomain,
	}
	return netv1.DNSConfig{
		ClusterDNSIP:  dnsVIP,
		ClusterDomain: clusterDomain,
		SearchDomains: search,
		NDots:         netv1.DefaultNDots,
	}
}
