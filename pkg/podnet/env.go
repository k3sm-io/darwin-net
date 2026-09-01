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

package podnet

import (
	"net/netip"
	"strings"
)

// The K3SM_* names below are the BIND-SHIM ABI: the exact environment keys the
// bind() interpose in shim/getaddrinfo_shim.c reads with getenv() to learn the
// pod's own /32 and rewrite the pod's wildcard binds onto it. k3sm's toPodBox
// injects them into each pod (iff podnet allocated a distinct /32 for it); the C
// shim, loaded via DYLD_INSERT_LIBRARIES, consumes them.
//
// They live in podnet rather than pkg/dns because the value is POD IDENTITY, not
// resolver configuration — pkg/dns/env.go's doc comment scopes that ABI to the
// getaddrinfo resolver, and the two shims share a dylib but nothing else. Both
// sets are single-sourced in Go so callers never re-type a name across the repo
// boundary; a silent typo here would disable the bind discipline for every pod
// and reintroduce the same-node EADDRINUSE collisions it exists to remove.
// TestShimBindEnvNamesMatchC mechanically binds this set to the .c, so a rename
// on either side fails the build instead of failing silently in production.
const (
	// EnvPodIP names the pod's own /32 (an IPv4 literal, e.g. "100.64.0.7"). The
	// C side parses it with inet_pton(AF_INET, …). Unset — or set to a value
	// inet_pton rejects — disables the interpose entirely: every bind is passed
	// through to the kernel unchanged, with no error surfaced to the workload.
	// That fail-safe polarity is deliberate and is pinned by the acceptance gate.
	EnvPodIP = "K3SM_POD_IP"
	// EnvBindDebug gates the bind shim's stderr diagnostic trace (set to any
	// value other than "0" to enable), mirroring EnvDNSDebug for the resolver.
	// BindDisciplineEnv never emits it — the acceptance harness sets it directly
	// on a pod under diagnosis — but it is part of the shim ABI, so the drift
	// guard tracks it. It is the ONLY field diagnostic for the interpose's two
	// silent-by-construction escapes (a socket that set IPV6_V6ONLY, and a pod
	// binary that never loaded the dylib at all).
	EnvBindDebug = "K3SM_BIND_DEBUG"
	// EnvClusterCIDRs names the destination scope of the connect() rung: a
	// comma-separated list of IPv4 CIDRs ("10.42.0.0/16,10.43.0.0/16") the shim
	// parses once at startup. An unbound AF_INET dial whose DESTINATION falls
	// inside one of them is bind()-pinned to K3SM_POD_IP first, so the peer sees
	// the caller's own /32; every other dial is passed through untouched.
	//
	// Scoping is the safety property here, not an optimisation. XNU source-selects
	// the DESTINATION's address for an unbound dial to a /32 lo0 alias (B215 P1d),
	// so without the pin every same-node pod-to-pod connection appears to come from
	// the callee — but with an UNSCOPED pin, an en0-routed external dial would
	// carry a loopback source and never see a reply. Unset or unparseable therefore
	// means "pin nothing", the same fail-safe polarity EnvPodIP has.
	EnvClusterCIDRs = "K3SM_CLUSTER_CIDRS"
)

// MinRewritablePort is the port floor of the bind discipline: a WILDCARD bind
// below it is passed through unrewritten. It is the Go-side single source of the
// carve, held in the C shim as `#define K3SM_BIND_MIN_PORT` and bound to it by
// TestShimMinRewritablePortMatchesC.
//
// The reason is a Darwin platform inversion, measured rather than assumed: a
// wildcard bind needs no privilege at any port, but a SPECIFIC-address bind
// below 1024 returns EACCES for a non-root uid, and k3sm pods never run as root.
// So rewriting a low-port wildcard would convert a working workload into a
// permission error. Low-port pods keep the shared wildcard port space; that is a
// named residual of the discipline, not an oversight. Port 0 (an ephemeral
// client bind, whose eventual destination this interpose cannot see) sits below
// the floor too and is likewise passed through.
const MinRewritablePort = 1024

// MaxClusterCIDRs is the ceiling on how many CIDRs the connect() rung's
// destination scope may carry, held in the C shim as
// `#define K3SM_MAX_CLUSTER_CIDRS` and bound to it by
// TestShimMaxClusterCIDRsMatchesC.
//
// The shim keeps the parsed table in a fixed-size struct member — it runs
// interposed on arbitrary application threads, where an allocation is a hazard
// and an unbounded loop over environment text is worse — and treats an
// over-length list as UNPARSEABLE rather than truncating it. The Go encoder
// takes the same view from the other side: a list longer than this emits no
// K3SM_CLUSTER_CIDRS at all (see BindDisciplineEnvWithCIDRs), so the rung is
// deterministically off instead of silently scoped to a prefix of what the
// caller asked for.
const MaxClusterCIDRs = 8

// BindDisciplineEnv serializes a pod's allocated /32 into the environment map the
// bind shim consumes. It is the single pinned encoder of that ABI, so callers
// (k3sm's toPodBox) never hand-roll the key or the value format — the C side
// parses the value with inet_pton(AF_INET, …), so anything but a dotted-quad
// IPv4 literal would disable the discipline in-pod with no visible symptom until
// two pods collided on a port.
//
// It returns nil — meaning "inject nothing" — when podIP cannot serve as a pod
// identity: the zero Addr, an IPv6 address (the lo0-alias IPAM is IPv4-only and
// the shim's parser is AF_INET), or the unspecified address 0.0.0.0 (which would
// enable the shim and then "rewrite" a wildcard bind to a wildcard). Emitting NO
// K3SM_POD_IP makes the shim take its unset path and pass every bind through,
// which is exactly the pre-discipline behaviour; emitting a sentinel would not
// be. A 4-in-6 mapped address is unmapped first, so it serializes as a dotted
// quad rather than as "::ffff:a.b.c.d", which inet_pton(AF_INET) would reject.
//
// hostNetwork pods are excluded upstream by construction — they are never
// allocated a distinct /32 — so this encoder never sees them.
func BindDisciplineEnv(podIP netip.Addr) map[string]string {
	ip := podIP.Unmap()
	if !ip.IsValid() || !ip.Is4() || ip.IsUnspecified() {
		return nil
	}
	return map[string]string{EnvPodIP: ip.String()}
}

// BindDisciplineEnvWithCIDRs is BindDisciplineEnv plus the connect() rung's
// destination scope: it emits K3SM_POD_IP exactly as BindDisciplineEnv does, and
// additionally K3SM_CLUSTER_CIDRS naming the destinations whose dials the shim
// may source-pin to that /32 — the cluster pod CIDR and the Service CIDR, i.e.
// the addresses that live on lo0 aliases and on the node's own proxy.
//
// It is ADDITIVE, never a replacement: BindDisciplineEnv keeps its signature and
// its exact output, so a caller with no CIDRs to declare (or one that
// wants the connect rung off) keeps working unchanged and gets the
// pre-B218 behaviour — the shim pins nothing.
//
// The nil-means-inject-nothing polarity governs the pod IP first: if
// BindDisciplineEnv rejects podIP, this returns nil too, because a destination
// scope with no source to pin to is meaningless.
//
// CIDR handling, in the order it matters:
//   - nil or empty cidrs => the EnvClusterCIDRs key is OMITTED and the result is
//     identical to BindDisciplineEnv's.
//   - each prefix is Unmap()ed and Masked(), so a 4-in-6 spelling and an
//     unmasked "10.42.0.1/16" both serialize to the canonical dotted-quad form
//     the C side's inet_pton + prefix-length parser accepts. Caller order is
//     preserved (a caller lists the pod CIDR before the Service CIDR for a
//     reason) and exact duplicates are dropped.
//   - an invalid, non-IPv4, or /0 prefix is SKIPPED. A /0 names every
//     destination, so it would source-pin en0-routed external egress onto a lo0
//     /32 — the precise hazard destination scoping exists to prevent — and the C
//     shim rejects one outright, which would disable the whole rung.
//   - more than MaxClusterCIDRs usable prefixes => the key is omitted entirely
//     (see MaxClusterCIDRs), so the rung goes off deterministically rather than
//     being silently scoped to the first few.
//   - if every prefix was skipped, the key is omitted — same as passing nil.
func BindDisciplineEnvWithCIDRs(podIP netip.Addr, cidrs []netip.Prefix) map[string]string {
	env := BindDisciplineEnv(podIP)
	if env == nil {
		return nil
	}
	out := make([]string, 0, len(cidrs))
	seen := make(map[string]struct{}, len(cidrs))
	for _, p := range cidrs {
		if !p.IsValid() {
			continue
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
		if !p.IsValid() || !p.Addr().Is4() || p.Bits() < 1 {
			continue
		}
		masked := p.Masked().String()
		if _, dup := seen[masked]; dup {
			continue
		}
		seen[masked] = struct{}{}
		out = append(out, masked)
	}
	if len(out) == 0 || len(out) > MaxClusterCIDRs {
		return env
	}
	env[EnvClusterCIDRs] = strings.Join(out, ",")
	return env
}
