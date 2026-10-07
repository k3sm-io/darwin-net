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
	// EnvDNSServer names the cluster DNS VIP (IPv4) a ClusterFirst pod's shim
	// queries. The C side parses the value with inet_pton(AF_INET, …). It is read
	// only when EnvDNSServers is unset or empty; when both are unset (and
	// EnvDNSExclusive is not "1") the shim is disabled and defers every lookup to
	// the real getaddrinfo.
	EnvDNSServer = "K3SM_DNS_SERVER"
	// EnvDNSPort names the DNS port. Optional: the shim defaults to 53. It applies
	// to EnvDNSServer and to every EnvDNSServers token without its own ":port".
	// ConfigToEnvChecked never emits it because netv1.DNSConfig carries no port
	// field.
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
	// enable). ConfigToEnvChecked never emits it — the acceptance harness sets it
	// directly on a pod under diagnosis — but it is part of the shim ABI, so the
	// drift guard tracks it.
	EnvDNSDebug = "K3SM_DNS_DEBUG"
	// EnvDNSServers names the nameserver list for a DNSPolicyNone pod,
	// SPACE-separated, at most MaxNameservers (the C shim's K3SM_MAX_NS) tokens.
	// Each token is "ipv4" or "ipv4:port"; a bare token uses EnvDNSPort (default
	// 53). The list is IPv4-only, so the ":port" suffix is unambiguous.
	// ConfigToEnvChecked emits bare addresses only; the ":port" form exists so a
	// test can point the shim at several stub servers on 127.0.0.1 with distinct
	// ephemeral ports. The C side keeps the first K3SM_MAX_NS usable tokens and
	// skips any token that is not a dotted-quad IPv4 address (with an optional
	// decimal port in 1..65535) or is 64 bytes or longer. When set and non-empty
	// it takes precedence over EnvDNSServer, which the shim then ignores.
	EnvDNSServers = "K3SM_DNS_SERVERS"
	// EnvDNSExclusive selects exclusive mode when its value is exactly "1": names
	// resolve only through the configured servers and never fall through to the
	// host resolver. With no usable server the shim fails every name lookup
	// with EAI_AGAIN instead of deferring. Residual host paths that perform no
	// name resolution remain: numeric IPv4/IPv6 literals, AI_NUMERICHOST, and the
	// RFC 6761 loopback names localhost and *.localhost.
	EnvDNSExclusive = "K3SM_DNS_EXCLUSIVE"
)

// ErrNoUsableNameserver is returned (wrapped) when a DNSPolicyNone config has
// no IPv4 nameserver. The native getaddrinfo shim and the vm guest's NAT segment
// serve only IPv4 nameservers, so such a config cannot be honored; callers must
// fail closed rather than fall back to the host resolver.
var ErrNoUsableNameserver = errors.New("dns: no usable IPv4 nameserver")

// ErrNameserversDropped is returned (wrapped, alongside a usable env map) when a
// DNSPolicyNone config carries IPv6 nameservers that the shim cannot serve and
// that were therefore left out. The error text names the dropped addresses.
var ErrNameserversDropped = errors.New("dns: IPv6 nameservers dropped")

// ipv4Servers splits cfg.Servers() into the IPv4 subset, in order and in dotted
// form, and the dropped remainder. An address counts as IPv4 iff
// netip.ParseAddr(s).Unmap().Is4(), so an IPv4-mapped IPv6 address such as
// "::ffff:1.1.1.1" is kept as "1.1.1.1". It is the single home of that rule for
// the shim encoder, the vm guest resolv.conf, and the Go reference resolver.
func ipv4Servers(cfg netv1.DNSConfig) (kept, dropped []string) {
	for _, s := range cfg.Servers() {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Unmap().Is4() {
			dropped = append(dropped, s)
			continue
		}
		kept = append(kept, addr.Unmap().String())
	}
	return kept, dropped
}

// MaxNDots is the resolv.conf RES_MAXNDOTS ceiling (15) — the single source of the
// ndots CEILING. ConfigToEnvChecked and GuestResolvConf clamp ndots to it so the encoder
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

// ConfigToEnvChecked serializes a DNSConfig into the K3SM_DNS_* environment map
// the getaddrinfo shim consumes. It is the single pinned encoder of the shim
// ABI, so callers (k3sm's toPodBox) never hand-roll the wire format; a wrong
// separator here would silently break all in-pod DNS. The encoding is a strict
// C/Go contract that MUST stay in lockstep with shim/getaddrinfo_shim.c.
//
// For DNSPolicyClusterFirst (the zero Policy) it emits exactly four keys:
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
// For DNSPolicyNone it emits EnvDNSServers (the IPv4 subset of cfg.Servers(), in
// pod order, space-separated, bare addresses), EnvDNSExclusive="1", EnvDNSSearch
// and EnvDNSNdots encoded as above, and EnvDNSDomain only when ClusterDomain is
// set. It never emits EnvDNSServer, so the two encodings are disjoint and a None
// pod can never be mistaken for a ClusterFirst one.
//
// EnvDNSPort is intentionally omitted: netv1.DNSConfig has no port field and the
// shim already defaults to 53, so emitting a port could only misconfigure it.
// EnvDNSDebug is never emitted either.
//
// Errors: when cfg.Validate fails it returns nil and the wrapped validation
// error. A DNSPolicyNone config with no IPv4 nameserver returns nil and an error
// wrapping ErrNoUsableNameserver; the caller must fail closed. A DNSPolicyNone
// config with some IPv6 nameservers returns the env for the IPv4 subset AND an
// error wrapping ErrNameserversDropped that names the dropped servers; the env
// is usable and the caller decides how to report the drop.
func ConfigToEnvChecked(cfg netv1.DNSConfig) (map[string]string, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("dns shim env: %w", err)
	}
	ndots := cfg.NDots
	if ndots <= 0 {
		ndots = netv1.DefaultNDots
	}
	if ndots > MaxNDots {
		ndots = MaxNDots
	}
	search := strings.Join(normalizeSearch(cfg.SearchDomains), " ")

	if cfg.Policy != netv1.DNSPolicyNone {
		return map[string]string{
			EnvDNSServer: cfg.ClusterDNSIP,
			EnvDNSDomain: cfg.ClusterDomain,
			EnvDNSSearch: search,
			EnvDNSNdots:  strconv.Itoa(int(ndots)),
		}, nil
	}

	kept, dropped := ipv4Servers(cfg)
	if len(kept) == 0 {
		return nil, fmt.Errorf("dns shim env: nameservers %v: %w", dropped, ErrNoUsableNameserver)
	}
	env := map[string]string{
		EnvDNSServers:   strings.Join(kept, " "),
		EnvDNSExclusive: "1",
		EnvDNSSearch:    search,
		EnvDNSNdots:     strconv.Itoa(int(ndots)),
	}
	if cfg.ClusterDomain != "" {
		env[EnvDNSDomain] = cfg.ClusterDomain
	}
	if len(dropped) > 0 {
		return env, fmt.Errorf("dns shim env: %w: %s", ErrNameserversDropped, strings.Join(dropped, ", "))
	}
	return env, nil
}

// ConfigToEnv is the nil-on-error form of ConfigToEnvChecked for a
// DNSPolicyClusterFirst config, kept for its existing caller. It is
// ClusterFirst-only: it returns nil for any non-zero Policy, so a caller that
// has not been taught about DNSPolicyNone cannot inject an exclusive config it
// does not know how to report errors for. It also returns nil when cfg is not
// usable (e.g. a node with no cluster DNS VIP): emitting NO K3SM_DNS_* env makes
// the shim take its unconfigured path and defer to the host resolver, whereas
// an empty or sentinel value would blackhole every in-pod lookup. Callers treat
// a nil map as "inject nothing".
func ConfigToEnv(cfg netv1.DNSConfig) map[string]string {
	if cfg.Policy != netv1.DNSPolicyClusterFirst {
		return nil
	}
	env, err := ConfigToEnvChecked(cfg)
	if err != nil {
		return nil
	}
	return env
}
