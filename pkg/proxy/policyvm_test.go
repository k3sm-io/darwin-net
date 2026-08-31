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

package proxy

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// vmDenyMarker is the substring that identifies the fail-closed vm-source Warn. It
// must not appear in the fail-open unknown-source Warn or the rule-mismatch deny
// Info: an operator (and this test) has to tell the three events apart
// mechanically, not by reading prose.
const vmDenyMarker = "unattributable source inside the vm (vmnet) segment"

// vmDenyWarns returns the recorded fail-closed vm-source Warns.
func vmDenyWarns(h *captureHandler) []slog.Record {
	var out []slog.Record
	for _, r := range h.warns() {
		if strings.Contains(r.Message, vmDenyMarker) {
			out = append(out, r)
		}
	}
	return out
}

// failOpenWarns returns the recorded fail-OPEN unknown-source Warns (the ones the
// vm branch must not replace anywhere outside its scope).
func failOpenWarns(h *captureHandler) []slog.Record {
	var out []slog.Record
	for _, r := range h.warns() {
		if strings.Contains(r.Message, "allowing connection from UNKNOWN source") {
			out = append(out, r)
		}
	}
	return out
}

// TestPolicyVMNetUnknownSourceFailsClosed is the M11.3-d3a acceptance table: on a
// vm-hosting node an unattributable source inside the vmnet segment is DENIED where
// a policy selects the destination — and NOTHING else changes. Every row that
// asserts the new deny is paired with a row that pins a case the deny must NOT
// reach, because the whole value of this change is its scoping.
func TestPolicyVMNetUnknownSourceFailsClosed(t *testing.T) {
	t.Parallel()

	vmnet := netip.MustParsePrefix("192.168.64.0/24")
	guestLease := netip.MustParseAddr("192.168.64.5") // a vm guest's live DHCP lease
	offSegment := netip.MustParseAddr("198.51.100.7") // an ordinary unknown source
	selected := netip.MustParseAddr("100.64.0.20")    // a policy-selected backend pod
	unselected := netip.MustParseAddr("100.64.0.21")  // a backend no policy selects
	knownPod := netip.MustParseAddr("100.64.0.22")    // an attributable pod source

	// vmTable builds a vm-hosting node's table: backend `selected` is selected and
	// admits only knownPod; `unselected` is selected by nothing.
	vmTable := func(t *testing.T, prefix netip.Prefix) (*PolicyTable, *captureHandler) {
		t.Helper()
		h := &captureHandler{}
		pt := NewPolicyTableVMNet(prefix)
		pt.log = slog.New(h)
		pt.Update(map[netip.Addr][]PolicyRule{
			selected: {{Sources: podIPSet(knownPod)}},
		}, podIPSet(knownPod, selected, unselected))
		return pt, h
	}

	t.Run("a: vmnet source + selected destination + unknown ⇒ DENY, naming the structural reason", func(t *testing.T) {
		t.Parallel()
		pt, h := vmTable(t, vmnet)

		if pt.Allow(guestLease, selected, 8080) {
			t.Fatalf("an unattributable vmnet source must be DENIED at a policy-selected backend")
		}
		warns := vmDenyWarns(h)
		if len(warns) != 1 {
			t.Fatalf("fail-closed vm deny must Warn once, got %d (warns: %d total)", len(warns), len(h.warns()))
		}
		if got, ok := attr(warns[0], "src"); !ok || got != guestLease.String() {
			t.Errorf("warn src attr = %q (present=%v), want %s", got, ok, guestLease)
		}
		if got, ok := attr(warns[0], "vmnet"); !ok || got != vmnet.String() {
			t.Errorf("warn vmnet attr = %q (present=%v), want %s — the log must name the scope that produced the deny", got, ok, vmnet)
		}
		if got, ok := attr(warns[0], "backend"); !ok || got != selected.String() {
			t.Errorf("warn backend attr = %q (present=%v), want %s", got, ok, selected)
		}
		// The message must NOT be the fail-open one: the two verdicts are opposite
		// and an operator greps for them separately.
		if n := len(failOpenWarns(h)); n != 0 {
			t.Errorf("the vm deny emitted the fail-OPEN message %d times; the two must be distinct", n)
		}
		// It must tell the operator the remediation is not to relax the policy.
		if !strings.Contains(warns[0].Message, "NOT a policy misconfiguration") {
			t.Errorf("deny message must say this is a known gap, not a misconfiguration; got %q", warns[0].Message)
		}
	})

	t.Run("b: NON-vmnet unknown source still fails OPEN (the fail-open regression negative)", func(t *testing.T) {
		t.Parallel()
		pt, h := vmTable(t, vmnet)

		// Same node, same table, same policy-selected destination — only the source
		// class differs. This is the row that proves the deny is scoped and not a
		// cluster-wide deny-unknown: a pre-informer-sync race, an unseeded node
		// address, or an off-cluster client must keep the M10.4 hint contract.
		if !pt.Allow(offSegment, selected, 8080) {
			t.Fatalf("an unknown source OUTSIDE the vmnet prefix must still fail OPEN")
		}
		if n := len(failOpenWarns(h)); n != 1 {
			t.Errorf("fail-open Warn count = %d, want 1 (the unchanged M10.4 signal)", n)
		}
		if n := len(vmDenyWarns(h)); n != 0 {
			t.Errorf("the vm deny fired for a non-vmnet source %d times, want 0", n)
		}
		// A v6 unknown source (never inside a v4 vmnet prefix) is likewise untouched.
		if !pt.Allow(netip.MustParseAddr("2001:db8::1"), selected, 8080) {
			t.Errorf("a v6 unknown source must still fail open under a v4 vmnet prefix")
		}
	})

	t.Run("c: vmnet source + UNSELECTED destination ⇒ allowed (default-allow-unless-selected)", func(t *testing.T) {
		t.Parallel()
		pt, h := vmTable(t, vmnet)

		// Upstream semantics: a backend no policy selects is allowed, whatever the
		// source. The m11-core legs ride this row — a cluster with no NetworkPolicy at
		// all must be unaffected by d3a.
		if !pt.Allow(guestLease, unselected, 8080) {
			t.Fatalf("a vmnet source must reach a backend NO policy selects")
		}
		if n := len(vmDenyWarns(h)); n != 0 {
			t.Errorf("the vm deny fired for an unselected destination %d times, want 0", n)
		}
	})

	t.Run("d: a vmnet source that IS a known pod gets normal rule evaluation", func(t *testing.T) {
		t.Parallel()
		h := &captureHandler{}
		pt := NewPolicyTableVMNet(vmnet)
		pt.log = slog.New(h)
		// The lease address is attributable here (the future registry's effect): it is
		// in the known set AND named by the rule.
		pt.Update(map[netip.Addr][]PolicyRule{
			selected:   {{Sources: podIPSet(guestLease)}},
			unselected: nil, // deny-all, to prove the deny arm is the RULE's, not the vm branch's
		}, podIPSet(guestLease, selected, unselected))

		if !pt.Allow(guestLease, selected, 8080) {
			t.Errorf("an attributable vmnet source named by the rule must be ALLOWED")
		}
		if pt.Allow(guestLease, unselected, 8080) {
			t.Errorf("an attributable vmnet source must be denied by a deny-all rule (normal evaluation)")
		}
		if n := len(vmDenyWarns(h)); n != 0 {
			t.Errorf("the vm branch fired %d times for an ATTRIBUTABLE source; it is reachable only for unknown sources", n)
		}
	})

	t.Run("e: loopback and always-allow sources inside the prefix short-circuit FIRST", func(t *testing.T) {
		t.Parallel()
		// Ladder order: the availability guardrails run before any attribution
		// question, so an always-allowed address that happens to sit inside the vmnet
		// segment (the NAT gateway is the realistic case) is never denied by d3a.
		gateway := netip.MustParseAddr("192.168.64.1")
		h := &captureHandler{}
		pt := NewPolicyTableVMNet(vmnet, gateway)
		pt.log = slog.New(h)
		pt.Update(map[netip.Addr][]PolicyRule{selected: nil}, podIPSet(selected))

		if !pt.Allow(gateway, selected, 8080) {
			t.Errorf("an always-allow seed inside the vmnet prefix must short-circuit before the vm branch")
		}
		// Same assertion for loopback, with a prefix contrived to CONTAIN 127.0.0.1 so
		// the ladder order is actually exercised rather than assumed.
		hLo := &captureHandler{}
		ptLo := NewPolicyTableVMNet(netip.MustParsePrefix("127.0.0.0/8"))
		ptLo.log = slog.New(hLo)
		ptLo.Update(map[netip.Addr][]PolicyRule{selected: nil}, podIPSet(selected))
		if !ptLo.Allow(netip.MustParseAddr("127.0.0.1"), selected, 8080) {
			t.Errorf("a loopback source inside the vmnet prefix must short-circuit before the vm branch")
		}
		if n := len(vmDenyWarns(h)) + len(vmDenyWarns(hLo)); n != 0 {
			t.Errorf("short-circuited sources produced %d vm denies, want 0", n)
		}
	})

	t.Run("f: an unset or invalid vmnet prefix is INERT — today's behavior exactly", func(t *testing.T) {
		t.Parallel()
		// A node that hosts no vm pods is the common case and must be untouched. The
		// zero Prefix is pinned as a NAMED row rather than left to stdlib accident,
		// and so is a structurally invalid one.
		for _, tc := range []struct {
			name   string
			prefix netip.Prefix
		}{
			{"zero prefix (NewPolicyTableVMNet with no segment)", netip.Prefix{}},
			{"invalid bit count", netip.PrefixFrom(netip.MustParseAddr("192.168.64.0"), 99)},
			{"NewPolicyTable (the non-vm constructor)", netip.Prefix{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var pt *PolicyTable
				h := &captureHandler{}
				if strings.HasPrefix(tc.name, "NewPolicyTable") {
					pt = NewPolicyTable()
				} else {
					pt = NewPolicyTableVMNet(tc.prefix)
				}
				pt.log = slog.New(h)
				pt.Update(map[netip.Addr][]PolicyRule{selected: {{Sources: podIPSet(knownPod)}}}, podIPSet(knownPod, selected))

				// The very address that is denied under a valid prefix now fails open.
				if !pt.Allow(guestLease, selected, 8080) {
					t.Fatalf("an inert prefix must leave the unknown-source fail-open intact")
				}
				if n := len(failOpenWarns(h)); n != 1 {
					t.Errorf("fail-open Warn count = %d, want 1", n)
				}
				if n := len(vmDenyWarns(h)); n != 0 {
					t.Errorf("the vm deny fired under an inert prefix %d times, want 0", n)
				}
				// Attributable evaluation is unchanged too.
				if !pt.Allow(knownPod, selected, 8080) {
					t.Errorf("a rule-matched source must still be allowed")
				}
			})
		}
	})

	t.Run("g: the vm deny Warn is throttled, like both sibling signals", func(t *testing.T) {
		t.Parallel()
		pt, h := vmTable(t, vmnet)
		for i := 0; i < 5; i++ {
			if pt.Allow(guestLease, selected, 8080) {
				t.Fatalf("iteration %d: vmnet unknown source must stay denied", i)
			}
		}
		// A SECOND vmnet source inside the window must not re-warn either — the
		// throttle is per table, matching warnUnknownSource and logDenied.
		if pt.Allow(netip.MustParseAddr("192.168.64.6"), selected, 8080) {
			t.Fatalf("a second vmnet unknown source must also be denied")
		}
		if n := len(vmDenyWarns(h)); n != 1 {
			t.Errorf("vm deny Warn count = %d, want 1 (throttled)", n)
		}
	})

	t.Run("h: through the real TCP accept path — the connection is refused, the backend never dialed", func(t *testing.T) {
		t.Parallel()
		be := newTCPBanner(t, "127.0.0.1:0")

		h := &captureHandler{}
		pt := NewPolicyTableVMNet(vmnet)
		pt.log = slog.New(h)
		// The banner IS the policy-selected backend, admitting only knownPod.
		pt.Update(map[netip.Addr][]PolicyRule{
			be.addrPort().Addr(): {{Sources: podIPSet(knownPod)}},
		}, podIPSet(knownPod))

		p, table := newPolicyProxy(pt)
		p.policy.log = slog.New(h) // newPolicyProxy re-points the table's logger
		key := PortKey{ClusterIP: "10.43.3.1", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{be.endpoint()})

		if handleVIP(t, p, key, guestLease) {
			t.Fatalf("a vmnet unknown source must be refused at the accept path")
		}
		if got := be.accepts.Load(); got != 0 {
			t.Errorf("backend accepts = %d, want 0 (a denied connection is never dialed)", got)
		}
		if n := len(vmDenyWarns(h)); n != 1 {
			t.Errorf("accept-path deny Warn count = %d, want 1", n)
		}
	})
}
