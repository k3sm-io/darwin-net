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

// ResolvConfFields is the structured, NORMALIZED result of GuestResolvConfFields:
// the exact nameserver(s), search list, and resolv.conf-style options
// GuestResolvConf renders verbatim into text. The shape mirrors what
// apis/guest/v1's ResolvConf proto carries (Nameservers/Searches/Options), so a
// caller that needs the guest DNS wiring as data — rather than as pre-rendered
// text — can consume this directly instead of re-parsing GuestResolvConf's output.
type ResolvConfFields struct {
	// Nameservers are the resolv.conf "nameserver" entries, in the order they
	// should be emitted.
	Nameservers []string
	// Search is the NORMALIZED resolv.conf "search" list — already passed
	// through normalizeSearch, so it is trimmed, charset-filtered, and
	// prefix-capped. Empty means no "search" line should be rendered.
	Search []string
	// Options are the resolv.conf-style "options" entries (e.g. "ndots:5"),
	// already reflecting any clamp (ndots capped to MaxNDots).
	Options []string
}

// GuestResolvConfFields derives the NORMALIZED nameserver/search/options triple for
// a vm-RuntimeClass Linux guest from cfg — the SAME netv1.DNSConfig the Darwin
// getaddrinfo shim consumes for a host-process pod (M1). It is the SINGLE place
// that normalizes cfg for guest DNS: the only normalizeSearch call and the only
// ndots clamp for this path live here. GuestResolvConf renders this result to
// text and performs no independent normalization of its own, so the two views can
// never diverge.
//
// It returns an error if cfg is not usable (missing cluster DNS VIP or domain) —
// the same validity check GuestResolvConf applies.
func GuestResolvConfFields(cfg netv1.DNSConfig) (ResolvConfFields, error) {
	if err := cfg.Validate(); err != nil {
		return ResolvConfFields{}, fmt.Errorf("guest resolv.conf: %w", err)
	}
	cfg = cfg.WithDefaults()

	// Normalize the search list through the SAME helper the host-process shim env
	// (ConfigToEnv) and the Go reference resolver (candidateNames) use, so the
	// untrusted vm-guest path is at least as hardened as the host path: an
	// interior-whitespace domain would otherwise break a glibc/musl resolv.conf
	// `search` line the same way it breaks the shim's strtok_r split. A no-op for
	// admission-valid input.
	search := normalizeSearch(cfg.SearchDomains)

	// Clamp ndots to the resolv.conf ceiling (MaxNDots == RES_MAXNDOTS) for parity with
	// ConfigToEnv, so the guest and host emit the SAME ndots. A %d of an int32 cannot
	// inject (glibc clamps to RES_MAXNDOTS, musl ignores ndots), so this is a consistency
	// guard, not a safety one — a no-op for admission-valid input (ndots <= MaxNDots).
	ndots := cfg.NDots
	if ndots > MaxNDots {
		ndots = MaxNDots
	}

	return ResolvConfFields{
		Nameservers: []string{cfg.ClusterDNSIP},
		Search:      search,
		Options:     []string{fmt.Sprintf("ndots:%d", ndots)},
	}, nil
}

// GuestResolvConf renders the /etc/resolv.conf content for a vm-RuntimeClass Linux
// guest from cfg — the SAME netv1.DNSConfig the Darwin getaddrinfo shim consumes for
// a host-process pod (M1). Only the injection mechanism differs: the Darwin
// DYLD_INSERT_LIBRARIES shim is meaningless in a Linux guest (no dyld; glibc/musl
// NSS instead), so the guest is pointed at the cluster resolver the standard Linux
// way — nameserver = the cluster DNS VIP (cfg.ClusterDNSIP), with search + ndots
// from cfg.
//
// It returns the file CONTENT as data; darwin-net does NOT write it. The cross-repo
// DAG forbids darwin-net touching runtimed's guest rootfs, so runtimed (or the k3sm
// guest provisioner) injects this content into the guest's /etc/resolv.conf.
//
// Two caveats the injector MUST handle — they are out of darwin-net's hands and are
// flagged here, not solved:
//
//   - CLOBBERING: a Linux guest's DHCP client / systemd-resolved will rewrite
//     /etc/resolv.conf on the NAT interface, dropping the cluster nameserver. The
//     injector must PIN the file static (e.g. write it and `chattr +i`, disable the
//     DHCP resolv.conf hook, or point systemd-resolved at the VIP) so the cluster
//     resolver survives a lease renewal. darwin-net emits the content; keeping it is
//     the guest-provisioning side's job.
//   - ndots PORTABILITY: glibc honors `options ndots:` for search-list expansion;
//     musl libc (Alpine, a common micro-VM base) largely IGNORES ndots and applies
//     the search list differently. A workload relying on a specific ndots for
//     short-name expansion may resolve differently under musl than glibc — prefer
//     FQDNs in the guest where the distinction matters.
//
// It returns an error if cfg is not usable (missing cluster DNS VIP or domain).
//
// GuestResolvConf performs NO normalization of its own — it renders exactly the
// ResolvConfFields GuestResolvConfFields derives, so the two can never diverge.
func GuestResolvConf(cfg netv1.DNSConfig) (string, error) {
	fields, err := GuestResolvConfFields(cfg)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	for _, ns := range fields.Nameservers {
		fmt.Fprintf(&b, "nameserver %s\n", ns)
	}
	if len(fields.Search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(fields.Search, " "))
	}
	for _, opt := range fields.Options {
		fmt.Fprintf(&b, "options %s\n", opt)
	}
	return b.String(), nil
}
