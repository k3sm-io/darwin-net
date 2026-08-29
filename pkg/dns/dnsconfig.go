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

	netv1 "k3sm.io/apis/net/v1"
)

// DefaultDNSPort is the standard DNS port.
const DefaultDNSPort = 53

// DefaultDNSVIP is the conventional kube-dns ClusterIP in k3sm's default
// 10.43.0.0/16 service CIDR (the .10 of the range, matching k3s). The per-node
// resolver runs bound to this address (the in-process k3sm/pkg/netserve
// resolver) so cluster DNS is always answered node-locally over loopback — never
// steered over the wireguard mesh, which carries only pod /24s (a mesh-steered
// DNS VIP would blackhole, since no peer's AllowedIPs cover 10.43.0.10). The
// Service proxy exempts this VIP from ownership (proxy.WithInfraVIPExemptions)
// so the resolver and the proxy do not fight for 10.43.0.10:53 (EADDRINUSE). It
// is a darwin-net default; the authoritative value is the server's
// service-CIDR config (k3sm).
const DefaultDNSVIP = "10.43.0.10"

// DefaultClusterDomain is the conventional cluster DNS domain (matching k3s and
// upstream Kubernetes) that pod Service names expand under, e.g.
// <svc>.<ns>.svc.cluster.local. It is a darwin-net default; the authoritative
// value is the server's --cluster-domain config (k3sm). It lives here beside
// DefaultDNSVIP — rather than in apis — because it is a darwin-net defaulting
// value, not a shared wire contract (the apis-vs-dns placement was adjudicated to
// darwin-net, mirroring DefaultDNSVIP).
const DefaultClusterDomain = "cluster.local"

// PodDNSConfig builds the netv1.DNSConfig a pod in namespace should receive: the
// cluster DNS VIP, the cluster domain, and the standard Kubernetes search list
// (<ns>.svc.<domain>, svc.<domain>, <domain>) with the default ndots. It is the
// data the getaddrinfo shim is initialized with so a pod's unqualified Service
// lookups expand correctly. dnsVIP is the address the per-node resolver binds
// (matching DefaultDNSVIP unless overridden).
func PodDNSConfig(dnsVIP, clusterDomain, namespace string) netv1.DNSConfig {
	if clusterDomain == "" {
		clusterDomain = DefaultClusterDomain
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
