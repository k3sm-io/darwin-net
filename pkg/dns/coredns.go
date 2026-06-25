package dns

import (
	"fmt"
	"strings"

	netv1 "k3sm.io/apis/net/v1"
)

// CorefileOptions parameterizes the CoreDNS configuration k3sm runs as the
// cluster resolver on the DNS VIP. It is the wiring side of pkg/dns: the server
// (k3sm) renders a Corefile from it and binds CoreDNS to the VIP; pods are
// pointed at that VIP via the netv1.DNSConfig the getaddrinfo shim consumes.
type CorefileOptions struct {
	// ClusterDomain is the zone CoreDNS is authoritative for via the kubernetes
	// plugin, e.g. "cluster.local".
	ClusterDomain string
	// BindIP is the DNS VIP CoreDNS listens on (the lo0 alias the proxy owns for
	// the kube-dns Service). Empty binds all interfaces.
	BindIP string
	// Port is the DNS port (53 by default).
	Port int32
	// UpstreamResolvers are the forwarders for non-cluster names. When empty,
	// CoreDNS forwards to the host resolver via /etc/resolv.conf — but note macOS
	// pods never read resolv.conf themselves; this is CoreDNS's own upstream, and
	// CoreDNS runs in the server process, not under the pod sandbox.
	UpstreamResolvers []string
}

// DefaultDNSPort is the standard DNS port.
const DefaultDNSPort = 53

// Corefile renders the CoreDNS configuration for the cluster resolver. It serves
// the cluster domain via the kubernetes plugin, answers pod/Service records,
// caches, and forwards everything else upstream. The output is a valid Corefile
// string the server writes to disk (or passes via -conf) when launching CoreDNS
// on the DNS VIP.
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
