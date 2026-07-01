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

// Package dns is k3sm's pod DNS: it carries the pure-Go reference resolver whose
// algorithm the getaddrinfo DYLD shim mirrors inside pods, plus the per-pod
// DNSConfig that shim consumes. The cluster resolver that actually RUNS is k3sm's
// in-process A-record + upstream-forward resolver (k3sm/pkg/netserve), NOT
// CoreDNS-the-binary; the CoreDNS Corefile this package renders (CorefileOptions /
// PerNodeDNS) is an UNCONSUMED export kept for the deferred "native CoreDNS"
// follow-up (DESIGN §5b). (Corrected 2026-06 upstream-alignment audit: earlier
// prose here wrongly said k3sm runs CoreDNS per-node.)
//
// # Why a shim at all
//
// macOS getaddrinfo routes through mDNSResponder/configd and never reads
// /etc/resolv.conf (DESIGN §3), so the usual "write the pod a resolv.conf"
// approach does nothing on Darwin. k3sm instead injects a DYLD_INSERT_LIBRARIES
// shim that interposes getaddrinfo / freeaddrinfo / res_* and routes cluster
// name resolution to the in-process cluster resolver over the cluster DNS VIP,
// applying ndots/search expansion from a netv1.DNSConfig.
//
// # The pieces
//
//   - expand.go — candidateNames: the pure ndots/search expansion. A short name
//     like "web" (0 dots) is expanded through the search domains FIRST, so it
//     resolves as a Service without the caller qualifying it; an absolute name
//     (trailing dot) skips the search list. This is unit-tested directly.
//   - resolver.go — Resolver: the Go reference implementation of pod resolution
//     (candidateNames + an A-record query to the cluster resolver over UDP using
//     golang.org/x/net/dns/dnsmessage, keeping darwin-net pure Go). The C shim
//     mirrors this algorithm; sharing the expansion semantics here keeps the two
//     in lockstep and lets the hard part (ndots/search) be tested in Go.
//   - coredns.go — CorefileOptions / PodDNSConfig: PodDNSConfig hands each pod the
//     DNSConfig the shim consumes (LIVE). CorefileOptions / PerNodeDNS RENDER a
//     CoreDNS Corefile string bound to the DNS VIP (DefaultDNSVIP) that is
//     currently UNCONSUMED — an export for the deferred native-CoreDNS follow-up
//     (DESIGN §5b), not what serves DNS today (the in-process k3sm/pkg/netserve
//     resolver does). See the M3.3 section below.
//   - merge.go — MergeDNSConfig / MaxSearchDomains: the pure ClusterFirst additive
//     dnsConfig merge — a pod's search domains APPEND to the cluster search list
//     (cluster-first, deduped, capped) and its ndots overrides the cluster
//     default, never the cluster server. See the B20a section below.
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
//
// # Per-node DNS and the infra-VIP exemption (M3.3)
//
// On a multi-node mesh the kube-dns VIP (10.43.0.10) is NOT in any pod's podCIDR,
// so a podCIDR classifier would call it remote and a podCIDR router would steer
// it over the wireguard mesh — where no peer's symmetric AllowedIPs (= podCIDR)
// cover it, blackholing in-pod DNS. The fix is to keep DNS node-local: k3sm runs
// a per-node resolver bound directly to the DNS VIP (the in-process resolver in
// k3sm/pkg/netserve; PerNodeDNS here renders the equivalent Corefile, BindIP =
// DefaultDNSVIP, for the future native-CoreDNS path), so a pod's query resolves
// over loopback and never crosses the mesh. The mesh routes only peer pod /24s to
// the utun (pkg/mesh, M3.1), so the DNS VIP is never steered there — locality
// stays a hint, not a routing input.
//
// Because the per-node resolver binds 10.43.0.10:53 (TCP and UDP) directly, the
// Service proxy must NOT also try to own that VIP, or the two collide
// (EADDRINUSE). The proxy exempts the kube-dns VIP via proxy.WithInfraVIPExemptions;
// the per-node resolver launch (k3sm, root-gated netd boundary) ensures the
// 10.43.0.10/32 lo0 alias the proxy no longer creates for it.
//
// The sibling infra VIP, the kubernetes endpoint (10.43.0.1), is fixed the same
// way in spirit but is k3sm-owned (k3sm:M3.3): k3sm rewrites the kubernetes
// Service endpoint to a node-local apiserver/proxy address per node. darwin-net
// provides this half — the per-node DNS Corefile render (PerNodeDNS) + the proxy
// exemption seam — and depends on k3sm:M3.3 for the kubernetes-endpoint half.
//
// # Guest-side resolver for the vm RuntimeClass (M5.2)
//
// The DYLD getaddrinfo shim is Darwin-only: inside a Linux micro-VM guest there is
// no dyld (glibc/musl NSS instead), so cluster names are pointed at the resolver
// the standard Linux way. GuestResolvConf (resolvconf.go) renders the guest's
// /etc/resolv.conf content from the SAME netv1.DNSConfig a host-process pod uses
// (nameserver = the cluster DNS VIP, search + ndots from the config) — only the
// injection mechanism differs. It returns the content as DATA: darwin-net does not
// write into runtimed's guest rootfs (the DAG forbids it), so runtimed / the k3sm
// guest provisioner injects it. Two caveats the injector owns (flagged on
// GuestResolvConf, not solved here): a Linux guest's DHCP/systemd-resolved will
// CLOBBER resolv.conf on the NAT interface unless it is pinned static/immutable,
// and musl (Alpine) largely IGNORES `options ndots:` where glibc honors it.
//
// # Additive dnsConfig merge under ClusterFirst (B20a)
//
// A ClusterFirst pod may set spec.dnsConfig to AUGMENT — never replace — the
// cluster DNS settings: its search domains append to the cluster search list and
// its ndots overrides the cluster default. MergeDNSConfig (merge.go) is the pure
// darwin-net primitive for that merge: cluster searches FIRST, the pod's appended,
// deduped first-seen (the cluster WINS a collision, so a pod search equal to a
// cluster one is dropped), sanitized (interior-whitespace domains dropped), then
// capped at MaxSearchDomains. A strictly-positive pod ndots overrides the cluster
// default; otherwise the cluster default stays. It returns the merged config plus
// the count of valid searches DROPPED BY THE CAP (the k3sm caller logs a Warn with
// pod identity when non-zero; the primitive itself never logs).
//
// # Search-list normalization is single-homed (B47)
//
// Four consumers read a DNSConfig's SearchDomains: ConfigToEnv (the host-process
// shim env), GuestResolvConf (the vm-guest /etc/resolv.conf), candidateNames (the Go
// reference resolver), and MergeDNSConfig itself. They all normalize through ONE
// helper, normalizeSearch (normalize.go) = sanitizeSearch + capSearch: it TrimSpaces
// each entry, DROPS any with interior whitespace (the C shim's strtok_r would
// otherwise split "a b" into two fabricated in-pod tokens — dropping is safer than
// fusing or splitting), and prefix-caps at MaxSearchDomains. This is defense-in-depth
// behind k3sm's validatePodDNSConfig admission gate, so it is a no-op for every
// admission-valid config and the live cluster-DNS keystone stays byte-identical;
// single-homing it is what keeps the four views dropping the same domain and
// truncating at the same cap. ConfigToEnv additionally clamps ndots to the
// resolv.conf RES_MAXNDOTS ceiling (15).
//
// MergeDNSConfig takes DISCRETE searches/ndots rather than a full netv1.DNSConfig
// "extra" on purpose: a full extra carries ClusterDNSIP, and a later edit that
// populated it from a pod's nameservers would override the cluster VIP — inverting
// B18's infra-wins. Discrete params type-enforce "augment search + ndots, never the
// server." k3sm wave 2 (B20b) extracts the pod-spec dnsConfig fields and calls this;
// THIS repo owns the merge mechanics and the shared MaxSearchDomains cap.
//
// Honest gaps (each deferred to B20b):
//   - The search list caps at MaxSearchDomains (8), NOT upstream's 32 — a pod's
//     6th-and-later added search beyond the three cluster defaults is silently
//     dropped. The cap mirrors the C shim's K3SM_MAX_SEARCH so the emitted env, the
//     shim's effective list, and the Go resolver agree; TestShimMaxSearchMatchesC
//     binds the const to the .c.
//   - An explicit `ndots: 0` is treated as unset (→ cluster default): the int32
//     NDots field cannot distinguish an explicit 0 from absent. Honoring an explicit
//     0 is deferred to B20b.
//   - dnsConfig.nameservers and non-ndots dnsConfig.options are NOT honored under
//     ClusterFirst: the getaddrinfo shim is single-server (one cluster VIP), so a
//     pod can neither add nameservers nor set arbitrary resolver options here.
package dns
