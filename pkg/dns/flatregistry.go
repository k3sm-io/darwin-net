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
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// RegistryServiceName is the name of the cluster image registry's Service.
	// k3sm's registry package publishes the Service under this same literal, so
	// the two must change together.
	RegistryServiceName = "registry-k3sm"
	// RegistryServiceNamespace is the namespace the cluster image registry's
	// Service lives in. k3sm's registry package publishes the Service in this
	// same literal namespace, so the two must change together.
	RegistryServiceNamespace = "k3sm-registry"
)

// ServiceIPv4Lookup is the consumer view of the resolver's Service set that
// ResolveFlatRegistryName reads: the IPv4 ClusterIP of the Service name in
// namespace, and ok=false when the Service is absent or has no answerable IPv4
// ClusterIP (headless, pending, IPv6, ExternalName).
type ServiceIPv4Lookup func(namespace, name string) (netip.Addr, bool)

// ResolveFlatRegistryName answers the flat registry name from every namespace.
//
// A bare Service name resolves only in its own namespace, so an image reference
// "registry-k3sm:6450/x" would resolve only for pods in RegistryServiceNamespace.
// The per-node resolver (k3sm/pkg/netserve) calls this BEFORE its partial-name
// classifier and zone switch, so the bare name and every search-suffixed form a
// pod's search list produces answer as the registry Service, from any
// namespace and from native pods and vm guests alike:
//
//   - registry-k3sm
//   - registry-k3sm.<ns>.svc.<domain>, for any namespace <ns>
//   - registry-k3sm.svc.<domain>
//   - registry-k3sm.<domain>
//
// The canonical registry-k3sm.k3sm-registry.svc.<domain> is not a flat form: it
// keeps answering through the ordinary Service path. A name that merely starts
// with the registry name (registry-k3sm-x) is not a flat form either.
//
// For a flat form whose Service lookup succeeds, handled is true: an A query
// gets the Service's ClusterIP, any other type gets an empty NOERROR (no
// records), the same as an exact Service name. The caller stamps the answer
// under the name that was asked. When qname is not a flat form, the cluster
// domain is invalid, lookup is nil, or the Service does not exist, handled is
// false and the caller answers qname exactly as it would have without this
// function (an unknown name stays NXDOMAIN or forwards, as before).
//
// The ClusterIP is read from lookup on every call, never cached or hard-coded,
// so a Service recreated with a new ClusterIP is answered with the new one.
//
// Known trade: a Service named registry-k3sm in another namespace is shadowed by
// its <ns>.svc form while the registry Service exists; the name is reserved for
// the cluster registry.
//
// qname is taken without the wire trailing dot (as netserve's normalizeDNSName
// yields it); a single trailing dot is tolerated. Matching is case-insensitive.
func ResolveFlatRegistryName(qtype dnsmessage.Type, qname, clusterDomain string, lookup ServiceIPv4Lookup) (addrs []netip.Addr, handled bool) {
	if lookup == nil || !isFlatRegistryName(qname, clusterDomain) {
		return nil, false
	}
	ip, ok := lookup(RegistryServiceNamespace, RegistryServiceName)
	if !ok || !ip.Is4() && !ip.Is4In6() {
		return nil, false
	}
	if qtype != dnsmessage.TypeA {
		return nil, true
	}
	return []netip.Addr{ip.Unmap()}, true
}

// isFlatRegistryName reports whether qname is one of the flat registry forms
// ResolveFlatRegistryName answers.
func isFlatRegistryName(qname, clusterDomain string) bool {
	domain, err := normalizeDomain(clusterDomain)
	if err != nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if name == RegistryServiceName {
		return true
	}
	rest, ok := strings.CutPrefix(name, RegistryServiceName+".")
	if !ok {
		return false
	}
	if rest == domain || rest == svcLabel+"."+domain {
		return true
	}
	ns, ok := strings.CutSuffix(rest, "."+svcLabel+"."+domain)
	return ok && ns != RegistryServiceNamespace && isDNSLabel(ns)
}
