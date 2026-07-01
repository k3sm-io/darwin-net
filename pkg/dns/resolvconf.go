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
func GuestResolvConf(cfg netv1.DNSConfig) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", fmt.Errorf("guest resolv.conf: %w", err)
	}
	cfg = cfg.WithDefaults()

	// Normalize the search list through the SAME helper the host-process shim env
	// (ConfigToEnv) and the Go reference resolver (candidateNames) use, so the
	// untrusted vm-guest path is at least as hardened as the host path: an
	// interior-whitespace domain would otherwise break a glibc/musl resolv.conf
	// `search` line the same way it breaks the shim's strtok_r split. A no-op for
	// admission-valid input.
	search := normalizeSearch(cfg.SearchDomains)

	// Clamp ndots to the resolv.conf ceiling (maxNDots == RES_MAXNDOTS) for parity with
	// ConfigToEnv, so the guest and host emit the SAME ndots. A %d of an int32 cannot
	// inject (glibc clamps to RES_MAXNDOTS, musl ignores ndots), so this is a consistency
	// guard, not a safety one — a no-op for admission-valid input (ndots <= 15).
	ndots := cfg.NDots
	if ndots > maxNDots {
		ndots = maxNDots
	}

	var b strings.Builder
	fmt.Fprintf(&b, "nameserver %s\n", cfg.ClusterDNSIP)
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	fmt.Fprintf(&b, "options ndots:%d\n", ndots)
	return b.String(), nil
}
