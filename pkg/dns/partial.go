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

import "strings"

//go:generate go run gen_tlds.go

// Verdict is CompletePartialName's classification of a query name that reached
// the per-node resolver.
type Verdict int

const (
	// Passthrough: the name is already under the cluster domain, or it is an
	// absolute name (trailing dot). The caller's zone logic decides it exactly as
	// it did before completion existed.
	Passthrough Verdict = iota
	// Completed: the name is a partial cluster Service name and the returned
	// fqdn is its completion under the cluster domain. The caller answers the
	// completed name but stamps the answer under the name that was asked.
	Completed
	// Refused: the name sits under the cluster-reserved "svc" label but is not a
	// completable <name>.<ns>.svc (for example <name>.svc, which names no
	// namespace). The caller answers it authoritatively (NXDOMAIN) and never
	// forwards it upstream.
	Refused
	// Forward: the name is not cluster-shaped (a single label, <name>.<ns> for a
	// namespace that has not opted in, any other shape). The caller forwards it
	// upstream as an off-cluster name, never answers it NXDOMAIN on its own.
	Forward
)

// String returns the verdict's name.
func (v Verdict) String() string {
	switch v {
	case Passthrough:
		return "Passthrough"
	case Completed:
		return "Completed"
	case Refused:
		return "Refused"
	case Forward:
		return "Forward"
	}
	return "Verdict(unknown)"
}

// svcLabel is the label every Service name carries between namespace and
// cluster domain (<name>.<ns>.svc.<domain>).
const svcLabel = "svc"

// CompletePartialName classifies a query name for server-side completion and,
// for a partial cluster Service name, returns its fully qualified form.
//
// Why server-side: on Linux the kubelet's resolv.conf (search <ns>.svc.<domain>
// svc.<domain> <domain>, ndots:5) expands partial names in the client. macOS
// applies no ndots to a supplemental resolver's domains, so a shim-less process
// sends "kubernetes.default.svc" to the node resolver as-is. The node resolver
// therefore completes it itself, the precedent being CoreDNS's shipped
// "autopath" plugin (server-side search-path completion). k3sm's per-node
// resolver (k3sm/pkg/netserve) applies this classifier BEFORE its zone switch;
// this package only decides, it answers nothing.
//
// The rules, on the lower-cased name with every label checked by isDNSLabel:
//
//   - under the cluster domain, or ending in a dot: Passthrough, qname unchanged.
//   - <name>.<ns>.svc: Completed as <name>.<ns>.svc.<domain>.
//   - <name>.<ns>: Completed as <name>.<ns>.svc.<domain> only when optedIn(ns)
//     and ns is not a reserved suffix (IsReservedSuffix, defence in depth behind
//     the registration check); otherwise Forward.
//   - anything else ending in the "svc" label (<name>.svc, a bare "svc", deeper
//     or malformed names): Refused. "svc" is a cluster-reserved match domain, so
//     such a name stays authoritative and never leaks upstream.
//   - any other shape (a single label, three or more labels not ending in
//     "svc", an invalid label): Forward.
//
// optedIn may be nil (no namespace opted in). Callers pass the name WITHOUT the
// wire trailing dot (as netserve's normalizeDNSName yields it); a trailing dot
// is read as the caller declaring the name absolute. An empty or invalid
// clusterDomain makes every name Passthrough, so the classifier never widens
// what the caller already does.
func CompletePartialName(qname, clusterDomain string, optedIn func(ns string) bool) (string, Verdict) {
	if strings.HasSuffix(qname, ".") {
		return qname, Passthrough
	}
	domain, err := normalizeDomain(clusterDomain)
	if err != nil {
		return qname, Passthrough
	}
	name := strings.ToLower(qname)
	if name == domain || strings.HasSuffix(name, "."+domain) {
		return qname, Passthrough
	}
	labels := strings.Split(name, ".")
	valid := true
	for _, l := range labels {
		if !isDNSLabel(l) {
			valid = false
			break
		}
	}
	if labels[len(labels)-1] == svcLabel {
		if valid && len(labels) == 3 {
			return name + "." + domain, Completed
		}
		return qname, Refused
	}
	if valid && len(labels) == 2 {
		ns := labels[1]
		if optedIn != nil && !IsReservedSuffix(ns) && optedIn(ns) {
			return name + "." + svcLabel + "." + domain, Completed
		}
	}
	return qname, Forward
}

// specialUseSuffixes are the labels a cluster namespace must never capture as a
// host match domain, beyond the IANA root zone: the RFC 6761 special-use names
// (test, localhost, invalid, example), RFC 6762 mDNS (local), RFC 7686 (onion),
// RFC 9476 (alt), the reverse/infrastructure zone (arpa, which holds RFC 8375's
// home.arpa), and the de-facto private suffixes networks already route
// (internal, corp, home, lan, localdomain, intranet, private).
var specialUseSuffixes = map[string]struct{}{
	"alt":         {},
	"arpa":        {},
	"corp":        {},
	"example":     {},
	"home":        {},
	"internal":    {},
	"intranet":    {},
	"invalid":     {},
	"lan":         {},
	"local":       {},
	"localdomain": {},
	"localhost":   {},
	"onion":       {},
	"private":     {},
	"test":        {},
}

// IsReservedSuffix reports whether label is a DNS suffix a namespace name must
// not claim as a host resolver match domain: an IANA root-zone TLD (the
// vendored, dated snapshot in tlds_iana.go) or a special-use/private suffix.
// Registering such a namespace would redirect a real suffix (com, local,
// internal, ...) for every process on the host, a host-DNS trust decision an
// in-cluster name must not make. k3sm's netd consults this before registering a
// namespace; CompletePartialName consults it again before completing <name>.<ns>.
// The comparison is case-insensitive; a trailing dot is ignored.
func IsReservedSuffix(label string) bool {
	l := strings.ToLower(strings.TrimSuffix(label, "."))
	if _, ok := specialUseSuffixes[l]; ok {
		return true
	}
	_, ok := ianaTLDs[l]
	return ok
}
