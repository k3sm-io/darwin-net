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

// TestGuestResolvConfRejectsInjection is the B47 post-build hardening: the vm-guest
// /etc/resolv.conf is a LINE-structured file, so a search domain carrying an interior
// newline is a directive-injection primitive on the UNTRUSTED tenant path. The classic
// bypass splits the payload so no single entry holds a literal space/tab (defeating a
// " \t"-only predicate); the space-join on the `search` line then reintroduces the
// separator. normalizeSearch DROPs any entry with a char outside the RFC-1123 charset
// [a-zA-Z0-9.-] (whitespace, control, or a separator like ';' '#' ':' '/' '@'), so the
// forged `nameserver` line can never materialize. ndots is also clamped to the
// resolv.conf ceiling for host/guest parity.
func TestGuestResolvConfRejectsInjection(t *testing.T) {
	t.Parallel()

	t.Run("a split newline-injection payload is dropped, not rendered as a directive", func(t *testing.T) {
		t.Parallel()
		// Neither entry holds a space/tab, so a " \t"-only predicate passes both; the
		// first carries a '\n' that, once the entries are space-joined onto the `search`
		// line, would forge `search corp\nnameserver 6.6.6.6` — an attacker `nameserver`
		// directive MITMing the tenant's DNS. The broadened predicate DROPs the '\n' entry.
		cfg := netv1.DNSConfig{
			ClusterDNSIP:  "10.43.0.10",
			ClusterDomain: "cluster.local",
			SearchDomains: []string{"corp\nnameserver", "6.6.6.6", "svc.cluster.local"},
			NDots:         2,
		}
		got, err := GuestResolvConf(cfg)
		if err != nil {
			t.Fatalf("GuestResolvConf: %v", err)
		}
		// Exactly ONE nameserver directive — the cluster VIP. On the old " \t" predicate
		// the injected "corp\nnameserver 6.6.6.6" survives and Count would be 2.
		if n := strings.Count(got, "nameserver "); n != 1 {
			t.Fatalf("want exactly 1 nameserver directive (the cluster VIP), got %d:\n%s", n, got)
		}
		if strings.Contains(got, "nameserver 6.6.6.6") {
			t.Fatalf("injected nameserver directive leaked into the guest resolv.conf:\n%s", got)
		}
		if strings.Contains(got, "corp") {
			t.Fatalf("the malformed (newline-bearing) search entry must be DROPPED whole:\n%s", got)
		}
		// The well-formed sibling survives.
		if !strings.Contains(got, "svc.cluster.local") {
			t.Fatalf("the well-formed search domain should survive:\n%s", got)
		}
	})

	t.Run("ndots is clamped to the resolv.conf ceiling for host/guest parity", func(t *testing.T) {
		t.Parallel()
		cfg := netv1.DNSConfig{
			ClusterDNSIP:  "10.43.0.10",
			ClusterDomain: "cluster.local",
			NDots:         1000,
		}
		got, err := GuestResolvConf(cfg)
		if err != nil {
			t.Fatalf("GuestResolvConf: %v", err)
		}
		if !strings.Contains(got, "options ndots:15") {
			t.Fatalf("ndots 1000 should clamp to 15 (RES_MAXNDOTS) for parity with ConfigToEnv:\n%s", got)
		}
	})
}
