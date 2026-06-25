// Package dns is k3sm's pod DNS: it wires CoreDNS as the cluster resolver on a
// VIP and carries the pure-Go reference resolver whose algorithm the
// getaddrinfo DYLD shim mirrors inside pods.
//
// # Why a shim at all
//
// macOS getaddrinfo routes through mDNSResponder/configd and never reads
// /etc/resolv.conf (DESIGN §3), so the usual "write the pod a resolv.conf"
// approach does nothing on Darwin. k3sm instead injects a DYLD_INSERT_LIBRARIES
// shim that interposes getaddrinfo / freeaddrinfo / res_* and routes cluster
// name resolution to CoreDNS over the cluster DNS VIP, applying ndots/search
// expansion from a netv1.DNSConfig.
//
// # The pieces
//
//   - expand.go — candidateNames: the pure ndots/search expansion. A short name
//     like "web" (0 dots) is expanded through the search domains FIRST, so it
//     resolves as a Service without the caller qualifying it; an absolute name
//     (trailing dot) skips the search list. This is unit-tested directly.
//   - resolver.go — Resolver: the Go reference implementation of pod resolution
//     (candidateNames + an A-record query to CoreDNS over UDP using
//     golang.org/x/net/dns/dnsmessage, keeping darwin-net pure Go). The C shim
//     mirrors this algorithm; sharing the expansion semantics here keeps the two
//     in lockstep and lets the hard part (ndots/search) be tested in Go.
//   - coredns.go — CorefileOptions / PodDNSConfig: the wiring the server uses to
//     run CoreDNS on the DNS VIP and to hand each pod the DNSConfig the shim
//     consumes.
//
// # The C shim (built with clang, not cgo)
//
// The interposer itself is a small C dylib in ../../shim/getaddrinfo_shim.c,
// built by ../../hack/build-shim.sh with clang into
// libk3sm_getaddrinfo_shim.dylib. It is deliberately NOT Go cgo: darwin-net's Go
// stays CGO_ENABLED=0, and a DYLD interposer must be a plain C dylib with a
// __DATA,__interpose section anyway. The shim reads its DNSConfig from the
// environment (K3SM_DNS_* variables the runtime sets per pod) and talks UDP DNS
// to the VIP.
//
// # Test tiers (and the cross-repo caveat)
//
// The shim only takes effect when the pod is spawned by runtimed's NON-platform
// exec-shim: Apple's sandbox-exec strips DYLD_* from the environment, so the true
// end-to-end test (a pod under Seatbelt resolving a Service) is an integration-
// tier test that depends on runtimed and lives in that slice. For THIS repo the
// shim is proven by:
//
//   - the pure-Go resolver/ndots unit tests (expand_test.go, resolver_test.go),
//     including that a short name resolves via search expansion; and
//   - a build-tagged integration test (shim_integration_test.go) that builds the
//     dylib, DYLD_INSERT_LIBRARIES-injects it into a plain probe process, and
//     resolves a name through a local stub DNS server — proving the interpose
//     path works in isolation without needing runtimed or a real CoreDNS binary.
//
// # In-pod kube-apiserver resolution (M2.2)
//
// In-pod kubectl / client-go reach the apiserver via kubernetes.default.svc — a
// Service the apiserver auto-creates (its ClusterIP, e.g. 10.43.0.1). It needs NO
// special-casing here: it is just a Service name, so the same ndots/search
// expansion resolves it. From a pod in any namespace, the partial form
// "kubernetes.default.svc" expands through the search list to the canonical
// kubernetes.default.svc.cluster.local (the third candidate under the default
// ndots:5), and the bare/FQDN forms work the same way. Cross-namespace access
// follows the standard contract: a "<svc>.<ns>" form resolves to
// <svc>.<ns>.svc.cluster.local, while a BARE name expands only within the pod's
// OWN namespace and never crosses namespaces. This is exercised by
// resolution_test.go (TestInPodKubernetesAndCrossNamespaceResolution,
// TestCandidateNamesCrossNamespaceContract).
//
// Decision (M2.2): because resolution rides the getaddrinfo shim and Apple's
// sandbox-exec strips DYLD_* from the child environment, the in-pod-API path
// REQUIRES runtimed's NON-platform exec-shim backend — the one backend under
// which DYLD_INSERT_LIBRARIES survives into the pod. The runtime pins that
// backend for pods that need in-pod API access (coordinated with runtimed:M2);
// there is no new darwin-net component. The documented ALTERNATIVE, for a future
// platform/confined backend where DYLD_* cannot survive, is a machine-wide DNS
// proxy (an mDNSResponder resolver scoped to the cluster domain) injected via
// /etc/resolver — out of scope for M2.2, which pins the exec-shim backend.
package dns
