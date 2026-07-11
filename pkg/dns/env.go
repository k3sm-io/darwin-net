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
	"strconv"
	"strings"

	netv1 "k3sm.io/apis/net/v1"
)

// The K3SM_DNS_* names below are the getaddrinfo-shim ABI: the exact environment
// keys shim/getaddrinfo_shim.c reads with getenv() to configure per-pod cluster
// DNS. k3sm's toPodBox injects them into each pod; the C shim, loaded via
// DYLD_INSERT_LIBRARIES, consumes them. They are single-sourced here so callers
// never re-type the names across the repo boundary — a silent typo would disable
// cluster DNS for every pod. TestShimEnvNamesMatchC mechanically binds this set
// to the .c so the Go consts and the unavoidable C copy cannot drift apart.
const (
	// EnvDNSServer names the cluster DNS VIP (IPv4) the shim queries. The C side
	// parses the value with inet_pton(AF_INET, …); unset disables the shim, which
	// then defers every lookup to the real getaddrinfo.
	EnvDNSServer = "K3SM_DNS_SERVER"
	// EnvDNSPort names the DNS port. Optional: the shim defaults to 53. ConfigToEnv
	// never emits it because netv1.DNSConfig carries no port field.
	EnvDNSPort = "K3SM_DNS_PORT"
	// EnvDNSDomain names the cluster domain, e.g. "cluster.local".
	EnvDNSDomain = "K3SM_DNS_DOMAIN"
	// EnvDNSSearch names the resolv.conf-style search list, SPACE-separated. The C
	// side splits it with strtok_r(buf, " \t", …), so the separator must be a space.
	EnvDNSSearch = "K3SM_DNS_SEARCH"
	// EnvDNSNdots names the ndots value in decimal. The C side reads it with atoi
	// and defaults to 5 when unset or non-positive.
	EnvDNSNdots = "K3SM_DNS_NDOTS"
	// EnvDNSDebug gates the shim's stderr diagnostic trace (set to any value to
	// enable). ConfigToEnv never emits it — the acceptance harness sets it
	// directly on a pod under diagnosis — but it is part of the shim ABI, so the
	// drift guard tracks it.
	EnvDNSDebug = "K3SM_DNS_DEBUG"
)

// MaxNDots is the resolv.conf RES_MAXNDOTS ceiling (15) — the single source of the
// ndots CEILING. ConfigToEnv and GuestResolvConf clamp ndots to it so the encoder
// self-defends against a direct caller that bypassed the k3sm-side admission clamp;
// a value above the ceiling has no resolver meaning and only risks surprising the
// shim's atoi. It is a no-op for admission-valid input.
//
// The default/ceiling split has two homes on purpose: the ndots DEFAULT
// (netv1.DefaultNDots == 5, applied when NDots is unset) lives in apis beside the
// DNSConfig it defaults, while this CEILING (RES_MAXNDOTS, the shim's atoi cap) lives
// here in darwin-net beside its sibling shim-ABI cap MaxSearchDomains. It is UNTYPED
// (like MaxSearchDomains) so it adapts with no cast to both the int32 ndots compares
// here and k3sm's int clamp — wave 2's dnsConfigOverride references dns.MaxNDots.
const MaxNDots = 15

// ConfigToEnv serializes a cluster DNSConfig into the K3SM_DNS_* environment map
// the getaddrinfo shim consumes. It is the single pinned encoder of the shim ABI,
// so callers (k3sm's toPodBox) never hand-roll the wire format — a wrong separator
// here would silently break ALL in-pod cluster DNS. The encoding is a strict C/Go
// contract that MUST stay in lockstep with shim/getaddrinfo_shim.c:
//
//   - EnvDNSServer — cfg.ClusterDNSIP as an IPv4 string (C: inet_pton, AF_INET).
//   - EnvDNSDomain — cfg.ClusterDomain verbatim.
//   - EnvDNSSearch — normalizeSearch(cfg.SearchDomains) joined with a single SPACE;
//     the C side tokenizes on " \t" via strtok_r, so a comma/newline would collapse
//     to one un-splittable token and yield zero search expansions (the keystone
//     dead). normalizeSearch DROPS any interior-whitespace domain before the join
//     (that domain would otherwise strtok_r-split into fabricated tokens) and
//     prefix-caps at MaxSearchDomains, keeping this emitted list identical to the
//     shim, guest resolv.conf, and Go-resolver views (defense-in-depth; a no-op for
//     admission-valid input).
//   - EnvDNSNdots  — cfg.NDots in decimal (C: atoi), defaulting to DefaultNDots
//     when not positive so the wire value is never "0" (a "0" would invert the
//     short-name vs. absolute candidate ordering), and clamped to MaxNDots (the
//     resolv.conf RES_MAXNDOTS ceiling) so a caller that bypassed admission cannot
//     emit a nonsensical ndots.
//
// EnvDNSPort is intentionally omitted: netv1.DNSConfig has no port field and the
// shim already defaults to 53, so emitting a port could only misconfigure it.
//
// When cfg is not usable (cfg.Validate fails — e.g. a node with no cluster DNS
// VIP), ConfigToEnv returns nil. Emitting NO K3SM_DNS_* env makes the shim take
// its K3SM_DNS_SERVER-unset path and defer to the host resolver, whereas an empty
// or sentinel value would blackhole every in-pod lookup. Callers treat a nil map
// as "inject nothing".
func ConfigToEnv(cfg netv1.DNSConfig) map[string]string {
	if cfg.Validate() != nil {
		return nil
	}
	ndots := cfg.NDots
	if ndots <= 0 {
		ndots = netv1.DefaultNDots
	}
	if ndots > MaxNDots {
		ndots = MaxNDots
	}
	return map[string]string{
		EnvDNSServer: cfg.ClusterDNSIP,
		EnvDNSDomain: cfg.ClusterDomain,
		EnvDNSSearch: strings.Join(normalizeSearch(cfg.SearchDomains), " "),
		EnvDNSNdots:  strconv.Itoa(int(ndots)),
	}
}
