package dns

import (
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// TestGuestResolvConfRender maps to the M5.2 deliverable: the rendered guest
// /etc/resolv.conf points the nameserver at the cluster DNS VIP and carries the
// search list + ndots from the pod DNSConfig (reusing the M1 DNSConfig data).
func TestGuestResolvConfRender(t *testing.T) {
	t.Parallel()

	t.Run("nameserver is the DNS VIP; search and ndots from DNSConfig", func(t *testing.T) {
		t.Parallel()
		cfg := PodDNSConfig(DefaultDNSVIP, "cluster.local", "default")
		got, err := GuestResolvConf(cfg)
		if err != nil {
			t.Fatalf("GuestResolvConf: %v", err)
		}
		for _, want := range []string{
			"nameserver 10.43.0.10",
			"search default.svc.cluster.local svc.cluster.local cluster.local",
			"options ndots:5",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("resolv.conf missing %q:\n%s", want, got)
			}
		}
		// The nameserver MUST be the cluster DNS VIP, not a macOS/NAT resolver.
		if !strings.HasPrefix(got, "nameserver "+DefaultDNSVIP+"\n") {
			t.Fatalf("resolv.conf must lead with the DNS VIP nameserver:\n%s", got)
		}
	})

	t.Run("honors an explicit ndots and search list from cfg", func(t *testing.T) {
		t.Parallel()
		cfg := netv1.DNSConfig{
			ClusterDNSIP:  "10.43.0.10",
			ClusterDomain: "cluster.local",
			SearchDomains: []string{"prod.svc.cluster.local", "svc.cluster.local"},
			NDots:         2,
		}
		got, err := GuestResolvConf(cfg)
		if err != nil {
			t.Fatalf("GuestResolvConf: %v", err)
		}
		if !strings.Contains(got, "options ndots:2") {
			t.Fatalf("want ndots:2:\n%s", got)
		}
		if !strings.Contains(got, "search prod.svc.cluster.local svc.cluster.local") {
			t.Fatalf("want the explicit search list:\n%s", got)
		}
	})

	t.Run("a zero ndots materializes the Kubernetes default", func(t *testing.T) {
		t.Parallel()
		cfg := netv1.DNSConfig{ClusterDNSIP: "10.43.0.10", ClusterDomain: "cluster.local"}
		got, err := GuestResolvConf(cfg)
		if err != nil {
			t.Fatalf("GuestResolvConf: %v", err)
		}
		if !strings.Contains(got, "options ndots:5") {
			t.Fatalf("a zero ndots should render DefaultNDots=5:\n%s", got)
		}
		// No search list set => no search line emitted.
		if strings.Contains(got, "search ") {
			t.Fatalf("no search line expected when SearchDomains is empty:\n%s", got)
		}
	})

	t.Run("rejects an unusable config", func(t *testing.T) {
		t.Parallel()
		if _, err := GuestResolvConf(netv1.DNSConfig{ClusterDomain: "cluster.local"}); err == nil {
			t.Fatal("want an error for a config missing ClusterDNSIP")
		}
	})
}
