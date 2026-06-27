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

	var b strings.Builder
	fmt.Fprintf(&b, "nameserver %s\n", cfg.ClusterDNSIP)
	if len(cfg.SearchDomains) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(cfg.SearchDomains, " "))
	}
	fmt.Fprintf(&b, "options ndots:%d\n", cfg.NDots)
	return b.String(), nil
}
