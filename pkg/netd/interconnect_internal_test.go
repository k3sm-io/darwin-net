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

package netd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// bridgeHost models bridge0's IPv4 addresses (with their netmasks) and its one
// Thunderbolt member, behind the applier's command and output seams, and records
// every command in order. noBridge is a host whose Thunderbolt Bridge was
// deleted; failRemove makes a -alias fail and leave the address in place (the
// macOS 27 "not in table" case); readErrs fails the next reads in order (a nil
// entry is a good read), and garbage makes every read print something that is
// not a bridge0 report.
type bridgeHost struct {
	addrs      map[netip.Addr]string
	ops        []string
	noBridge   bool
	garbage    bool
	readErrs   []error
	failRemove map[netip.Addr]bool
}

func newBridgeHost(seed map[string]string) *bridgeHost {
	h := &bridgeHost{addrs: map[netip.Addr]string{}, failRemove: map[netip.Addr]bool{}}
	for a, m := range seed {
		h.addrs[netip.MustParseAddr(a)] = m
	}
	return h
}

func (h *bridgeHost) output(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "ifconfig" || len(args) != 1 || args[0] != bridgeIface {
		return nil, fmt.Errorf("unexpected read %s %v", name, args)
	}
	if len(h.readErrs) > 0 {
		err := h.readErrs[0]
		h.readErrs = h.readErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	if h.noBridge {
		return nil, errors.New("exit status 1: ifconfig: interface bridge0 does not exist")
	}
	if h.garbage {
		return []byte("signal: killed\n"), nil
	}
	var b strings.Builder
	b.WriteString("bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n")
	for _, a := range slices.SortedFunc(maps.Keys(h.addrs), netip.Addr.Compare) {
		m := netip.MustParseAddr(h.addrs[a]).As4()
		fmt.Fprintf(&b, "\tinet %s netmask 0x%02x%02x%02x%02x\n", a, m[0], m[1], m[2], m[3])
	}
	b.WriteString("\tmember: en1 flags=3<LEARNING,DISCOVER>\n")
	return []byte(b.String()), nil
}

func (h *bridgeHost) command(_ context.Context, name string, args ...string) error {
	h.ops = append(h.ops, name+" "+strings.Join(args, " "))
	switch {
	case name == "ifconfig" && len(args) == 6 && args[0] == bridgeIface && args[1] == "inet" && args[3] == "netmask" && args[5] == "alias":
		h.addrs[netip.MustParseAddr(args[2])] = args[4]
	case name == "ifconfig" && len(args) == 3 && args[0] == bridgeIface && args[1] == "-alias":
		a := netip.MustParseAddr(args[2])
		if h.failRemove[a] {
			return errors.New("ifconfig: ioctl (SIOCDIFADDR): not in table")
		}
		delete(h.addrs, a)
	default:
		return fmt.Errorf("unexpected command %s %v", name, args)
	}
	return nil
}

// checkOps fails unless every command was an alias add or remove on bridge0:
// never a route, never lo0, never another interface, never a membership change.
func (h *bridgeHost) checkOps(t *testing.T) {
	t.Helper()
	for _, op := range h.ops {
		if !strings.HasPrefix(op, "ifconfig bridge0 inet 169.254.0.") && !strings.HasPrefix(op, "ifconfig bridge0 -alias 169.254.0.") {
			t.Errorf("command outside the interconnect alias policy: %q", op)
		}
	}
}

func (h *bridgeHost) has(a string) bool { return h.addrs[netip.MustParseAddr(a)] != "" }

// icServer builds a daemon whose executor is the production applier over h. A
// non-empty cidr is seeded as the adopted identity; ledger, when non-empty, is
// the persisted owned-alias file's content.
type keyResolver struct{}

func (keyResolver) Resolve(context.Context, string) (string, error) { return "key", nil }

// call dispatches one request through the server's own decode-and-route path.
func call(t *testing.T, s *Server, req wire.Request) wire.Response {
	t.Helper()
	req.Version = wire.CurrentVersion()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := s.dispatch(context.Background(), newConnState(wire.DefaultMaxPerConn), b)
	return resp
}

func icServer(t *testing.T, cidr string, h *bridgeHost, ledger string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "interconnect")
	if ledger != "" {
		if err := os.WriteFile(statePath, []byte(ledger), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{
		NodePodCIDR:           netip.MustParsePrefix("100.64.0.0/24"),
		InterconnectStatePath: statePath,
		MeshKeyResolver:       keyResolver{},
		Logger:                slog.New(slog.DiscardHandler),
	}
	if cidr != "" {
		cfg.NodePodCIDR = netip.MustParsePrefix(cidr)
		cfg.IdentityPath = filepath.Join(dir, "node-pod-cidr")
		if err := os.WriteFile(cfg.IdentityPath, []byte(cidr+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := newDarwinApplier(cfg.NodePodCIDR, cfg.Logger)
	a.output, a.command = h.output, h.command
	cfg.Privileged = a
	return NewServer(cfg), statePath
}

func ensureIC(t *testing.T, s *Server, slot int) wire.Response {
	t.Helper()
	return call(t, s, wire.Request{Verb: wire.VerbEnsureInterconnectAlias, EnsureInterconnectAlias: &wire.InterconnectAliasArgs{Slot: slot}})
}

func removeIC(t *testing.T, s *Server, slot int) wire.Response {
	t.Helper()
	return call(t, s, wire.Request{Verb: wire.VerbRemoveInterconnectAlias, RemoveInterconnectAlias: &wire.InterconnectAliasArgs{Slot: slot}})
}

func wantRefused(t *testing.T, resp wire.Response, reason string) {
	t.Helper()
	if resp.OK || resp.Reason != reason {
		t.Fatalf("response = %+v, want a refusal with reason %q", resp, reason)
	}
}

func wantOK(t *testing.T, resp wire.Response) {
	t.Helper()
	if !resp.OK {
		t.Fatalf("refused: %s (%s)", resp.Error, resp.Reason)
	}
}

func slotAddr(t *testing.T, idx, slot int) string {
	t.Helper()
	a, err := netv1alpha1.InterconnectSlotAddress(idx, slot)
	if err != nil {
		t.Fatal(err)
	}
	return a.String()
}

// TestInterconnectAliasPolicy is the netd interconnect gate: the daemon derives every
// interconnect alias itself from its adopted identity and the slot, puts it on
// bridge0 only, with a /24 for slot 0 and /32 for slots 1..7 and no route, and
// removes only what it owns, in /32-first order, at runtime and at start.
func TestInterconnectAliasPolicy(t *testing.T) {
	t.Run("slots 0, 1 and 7 at index 0 and 30 get the derived address and netmask on bridge0", func(t *testing.T) {
		for _, tc := range []struct {
			cidr string
			idx  int
		}{{"100.64.0.0/24", 0}, {"100.64.30.0/24", 30}} {
			for _, slot := range []int{0, 1, 7} {
				h := newBridgeHost(nil)
				s, _ := icServer(t, tc.cidr, h, "")
				resp := ensureIC(t, s, slot)
				wantOK(t, resp)
				want := slotAddr(t, tc.idx, slot)
				mask := "255.255.255.255"
				if slot == 0 {
					mask = "255.255.255.0"
				}
				if resp.InterconnectIP != want {
					t.Errorf("idx %d slot %d: interconnectIP %s, want %s", tc.idx, slot, resp.InterconnectIP, want)
				}
				wantOps := []string{"ifconfig bridge0 inet " + want + " netmask " + mask + " alias"}
				if !slices.Equal(h.ops, wantOps) {
					t.Errorf("idx %d slot %d: ops %q, want %q", tc.idx, slot, h.ops, wantOps)
				}
				h.checkOps(t)
			}
		}
	})

	t.Run("slots outside 0..7 are refused", func(t *testing.T) {
		for _, slot := range []int{8, -1} {
			h := newBridgeHost(nil)
			s, _ := icServer(t, "100.64.0.0/24", h, "")
			wantRefused(t, ensureIC(t, s, slot), wire.ReasonInterconnectSlotOutOfRange)
			wantRefused(t, removeIC(t, s, slot), wire.ReasonInterconnectSlotOutOfRange)
			if len(h.ops) != 0 {
				t.Fatalf("slot %d issued %q", slot, h.ops)
			}
		}
	})

	t.Run("a node index beyond 30 is refused with the named error", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, _ := icServer(t, "100.64.31.0/24", h, "")
		wantRefused(t, ensureIC(t, s, 0), wire.ReasonInterconnectIndexOutOfRange)
		if len(h.ops) != 0 {
			t.Fatalf("issued %q", h.ops)
		}
	})

	t.Run("an unadopted identity is refused, never a default index", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, _ := icServer(t, "", h, "")
		wantRefused(t, ensureIC(t, s, 0), wire.ReasonInterconnectIdentityUnadopted)
		wantRefused(t, removeIC(t, s, 0), wire.ReasonInterconnectIdentityUnadopted)
		if len(h.ops) != 0 {
			t.Fatalf("issued %q", h.ops)
		}
	})

	t.Run("a host without bridge0 is refused", func(t *testing.T) {
		h := newBridgeHost(nil)
		h.noBridge = true
		s, _ := icServer(t, "100.64.0.0/24", h, "")
		wantRefused(t, ensureIC(t, s, 0), wire.ReasonInterconnectNoBridge)
		if len(h.ops) != 0 {
			t.Fatalf("issued %q", h.ops)
		}
	})

	t.Run("removing an alias netd never created is a no-op", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, _ := icServer(t, "100.64.0.0/24", h, "")
		a := slotAddr(t, 0, 2)
		h.addrs[netip.MustParseAddr(a)] = "255.255.255.255" // someone else's, after start
		wantOK(t, removeIC(t, s, 2))
		if len(h.ops) != 0 || !h.has(a) {
			t.Fatalf("ops %q, %s present=%v: an unowned alias was touched", h.ops, a, h.has(a))
		}
	})

	t.Run("slot 0 is removed only after every owned slot 1..7", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, _ := icServer(t, "100.64.0.0/24", h, "")
		wantOK(t, ensureIC(t, s, 0))
		wantOK(t, ensureIC(t, s, 3))
		wantRefused(t, removeIC(t, s, 0), wire.ReasonInterconnectTeardownOrder)
		if !h.has(slotAddr(t, 0, 0)) {
			t.Fatal("slot 0 was removed under an owned /32")
		}
		wantOK(t, removeIC(t, s, 3))
		wantOK(t, removeIC(t, s, 0))
		if len(h.addrs) != 0 {
			t.Fatalf("bridge0 still carries %v", h.addrs)
		}
		h.checkOps(t)
	})

	t.Run("ensure and remove are idempotent against the kernel", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, _ := icServer(t, "100.64.0.0/24", h, "")
		a0, a4, a5 := slotAddr(t, 0, 0), slotAddr(t, 0, 4), slotAddr(t, 0, 5)
		wantOK(t, ensureIC(t, s, 0))
		delete(h.addrs, netip.MustParseAddr(a0)) // owned, but gone from the kernel
		wantOK(t, ensureIC(t, s, 0))
		if !h.has(a0) || len(h.ops) != 2 {
			t.Fatalf("an owned-but-missing alias was not re-added: ops %q", h.ops)
		}
		h.addrs[netip.MustParseAddr(a4)] = "255.255.255.255" // already present
		wantOK(t, ensureIC(t, s, 4))
		if len(h.ops) != 2 {
			t.Fatalf("an already-present alias issued a command: %q", h.ops)
		}
		wantOK(t, removeIC(t, s, 4)) // ownership was recorded, so it goes
		if h.has(a4) {
			t.Fatal("an ensured-while-present alias was not removable")
		}
		wantOK(t, ensureIC(t, s, 5))
		delete(h.addrs, netip.MustParseAddr(a5))
		n := len(h.ops)
		wantOK(t, removeIC(t, s, 5))
		if len(h.ops) != n {
			t.Fatalf("removing an already-gone alias issued %q", h.ops[n:])
		}
		h.checkOps(t)
	})

	t.Run("the startup reconcile removes only unowned derived aliases, /32s first", func(t *testing.T) {
		h := newBridgeHost(map[string]string{
			"169.254.9.209":   "255.255.0.0",     // self-assigned, outside 169.254.0.0/24
			"169.254.0.1":     "255.255.255.0",   // our slot 0, unowned
			"169.254.0.4":     "255.255.255.255", // our slot 3, unowned
			"169.254.0.9":     "255.255.255.255", // node index 1's slot 0, not ours
			"169.254.0.50":    "255.255.255.255", // in the /24, in no derived set of ours
			"192.168.200.1":   "255.255.255.0",   // anything else on the bridge
			"169.254.255.200": "255.255.255.255", // the other reserved half
		})
		// The ledger names an address outside the derived set; it widens nothing.
		_, _ = icServer(t, "100.64.0.0/24", h, `{"aliases":[{"slot":2,"address":"169.254.0.50"}]}`)
		want := []string{"ifconfig bridge0 -alias 169.254.0.4", "ifconfig bridge0 -alias 169.254.0.1"}
		if !slices.Equal(h.ops, want) {
			t.Fatalf("reconcile ops %q, want %q", h.ops, want)
		}
		for _, keep := range []string{"169.254.9.209", "169.254.0.9", "169.254.0.50", "192.168.200.1", "169.254.255.200"} {
			if !h.has(keep) {
				t.Errorf("the reconcile removed %s", keep)
			}
		}
	})

	t.Run("the startup reconcile keeps owned aliases and the slot 0 they ride", func(t *testing.T) {
		h := newBridgeHost(map[string]string{
			"169.254.0.1": "255.255.255.0",   // slot 0, unowned
			"169.254.0.7": "255.255.255.255", // slot 6, owned
		})
		_, _ = icServer(t, "100.64.0.0/24", h, `{"aliases":[{"slot":6,"address":"169.254.0.7"}]}`)
		if len(h.ops) != 0 || !h.has("169.254.0.1") || !h.has("169.254.0.7") {
			t.Fatalf("ops %q: an owned /32 or the slot 0 it rides was removed", h.ops)
		}
	})

	t.Run("a failed startup removal is logged and never re-added over", func(t *testing.T) {
		h := newBridgeHost(map[string]string{
			"169.254.0.3": "255.255.255.255",
			"169.254.0.6": "255.255.255.255",
		})
		h.failRemove[netip.MustParseAddr("169.254.0.6")] = true
		_, _ = icServer(t, "100.64.0.0/24", h, "")
		want := []string{"ifconfig bridge0 -alias 169.254.0.6", "ifconfig bridge0 -alias 169.254.0.3"}
		if !slices.Equal(h.ops, want) {
			t.Fatalf("reconcile ops %q, want %q", h.ops, want)
		}
		if h.has("169.254.0.3") {
			t.Fatal("the reconcile stopped at the failed removal")
		}
	})

	t.Run("a bridge0 read failure is reported as itself, never as no bridge", func(t *testing.T) {
		for name, fail := range map[string]func(*bridgeHost){
			"timeout":         func(h *bridgeHost) { h.readErrs = []error{context.DeadlineExceeded} },
			"killed ifconfig": func(h *bridgeHost) { h.readErrs = []error{errors.New("signal: killed")} },
			"unparsable":      func(h *bridgeHost) { h.garbage = true },
		} {
			h := newBridgeHost(nil)
			s, _ := icServer(t, "100.64.0.0/24", h, "")
			fail(h)
			resp := ensureIC(t, s, 0)
			if resp.OK || resp.Reason != "" || !strings.Contains(resp.Error, "reading bridge0 failed") {
				t.Errorf("%s: ensure = %+v, want an unnamed read failure", name, resp)
			}
			if len(h.ops) != 0 {
				t.Errorf("%s: issued %q", name, h.ops)
			}
		}
	})

	t.Run("remove keeps ownership on a read failure and drops it only on a verified absence", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, statePath := icServer(t, "100.64.0.0/24", h, "")
		a3 := slotAddr(t, 0, 3)
		wantOK(t, ensureIC(t, s, 3))
		h.readErrs = []error{context.DeadlineExceeded}
		if resp := removeIC(t, s, 3); resp.OK {
			t.Fatal("a remove whose bridge0 read failed reported success")
		}
		if raw, _ := os.ReadFile(statePath); !strings.Contains(string(raw), a3) {
			t.Fatalf("a read failure dropped ownership: ledger %s", raw)
		}
		// The -alias fails and the read-back fails too: still nothing proven.
		h.failRemove[netip.MustParseAddr(a3)] = true
		h.readErrs = []error{nil, errors.New("signal: killed")}
		if resp := removeIC(t, s, 3); resp.OK {
			t.Fatal("a failed -alias with an unreadable read-back reported success")
		}
		delete(h.failRemove, netip.MustParseAddr(a3))
		wantOK(t, removeIC(t, s, 3)) // still owned, so it goes now
		if h.has(a3) || h.ops[len(h.ops)-1] != "ifconfig bridge0 -alias "+a3 {
			t.Fatalf("the kept ownership did not remove the alias: ops %q", h.ops)
		}
		// A deleted bridge0 is a verified absence: ownership goes, no command.
		wantOK(t, ensureIC(t, s, 4))
		h.noBridge = true
		n := len(h.ops)
		wantOK(t, removeIC(t, s, 4))
		if raw, _ := os.ReadFile(statePath); strings.Contains(string(raw), slotAddr(t, 0, 4)) || len(h.ops) != n {
			t.Fatalf("no-bridge removal: ledger %s, ops %q", raw, h.ops[n:])
		}
		h.checkOps(t)
	})

	t.Run("a slot-0 address with the wrong netmask is repaired to the /24", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, _ := icServer(t, "100.64.0.0/24", h, "")
		a0 := slotAddr(t, 0, 0)
		h.addrs[netip.MustParseAddr(a0)] = "255.255.255.255" // present, but a /32
		wantOK(t, ensureIC(t, s, 0))
		want := []string{"ifconfig bridge0 -alias " + a0, "ifconfig bridge0 inet " + a0 + " netmask 255.255.255.0 alias"}
		if !slices.Equal(h.ops, want) || h.addrs[netip.MustParseAddr(a0)] != "255.255.255.0" {
			t.Fatalf("ops %q, mask %s; want %q", h.ops, h.addrs[netip.MustParseAddr(a0)], want)
		}
		wantOK(t, ensureIC(t, s, 0)) // now right: no command
		if len(h.ops) != 2 {
			t.Fatalf("a correct /24 issued %q", h.ops[2:])
		}
	})

	t.Run("an owned alias pins the identity it was derived from", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, _ := icServer(t, "100.64.0.0/24", h, "")
		wantOK(t, ensureIC(t, s, 0))
		resp := call(t, s, wire.Request{Verb: wire.VerbConfigureMesh, ConfigureMesh: &wire.ConfigureMeshArgs{LocalPrivKeyRef: "ref", NodePodCIDR: "100.64.5.0/24"}})
		if resp.OK || !strings.Contains(resp.Error, "1 interconnect alias") {
			t.Fatalf("an adoption under an owned interconnect alias = %+v, want refused", resp)
		}
	})

	t.Run("ownership survives a restart through the 0600 ledger", func(t *testing.T) {
		h := newBridgeHost(nil)
		s, statePath := icServer(t, "100.64.0.0/24", h, "")
		wantOK(t, ensureIC(t, s, 0))
		wantOK(t, ensureIC(t, s, 2))
		fi, err := os.Stat(statePath)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("ledger %s: %v, mode %v", statePath, err, fi)
		}
		raw, _ := os.ReadFile(statePath)
		h.ops = nil
		_, _ = icServer(t, "100.64.0.0/24", h, string(raw))
		if len(h.ops) != 0 || !h.has(slotAddr(t, 0, 0)) || !h.has(slotAddr(t, 0, 2)) {
			t.Fatalf("a restart removed owned aliases: ops %q", h.ops)
		}
	})
}

// TestWithdrawnLinkVerbsAreUnknown pins the withdrawal of minor 1's direct-link
// verbs: a client that still sends ConfigureLink or RemoveLink gets "unknown verb"
// (which such a client treats as a mesh-only helper), nothing reaches bridge0,
// and the reply still carries the daemon's version.
func TestWithdrawnLinkVerbsAreUnknown(t *testing.T) {
	h := newBridgeHost(nil)
	s, _ := icServer(t, "", h, "")
	for _, verb := range []wire.Verb{"ConfigureLink", "RemoveLink"} {
		resp := call(t, s, wire.Request{Verb: verb})
		if resp.OK || !strings.Contains(resp.Error, "unknown verb") {
			t.Errorf("%s reply = %+v, want an unknown-verb refusal", verb, resp)
		}
		if resp.Version != wire.CurrentVersion() {
			t.Errorf("%s reply version = %+v, want %+v", verb, resp.Version, wire.CurrentVersion())
		}
	}
	if len(h.ops) != 0 {
		t.Fatalf("a withdrawn verb touched the host: %v", h.ops)
	}
}

// interconnectLedgerGolden is the content of the apis fixture
// net/v1alpha1/testdata/interconnect-ledger.golden.json, inlined because a lone
// clone of this module has no sibling apis checkout.
const interconnectLedgerGolden = `{"aliases":[{"slot":0,"address":"169.254.0.9"},{"slot":1,"address":"169.254.0.10"},{"slot":2,"address":"169.254.0.11"}]}` + "\n"

// TestPersistInterconnectGolden pins the bytes the daemon writes for a
// three-alias ledger to the shared fixture, so the on-disk shape is the one the
// apis type defines and a restart reads it back unchanged.
func TestPersistInterconnectGolden(t *testing.T) {
	s, statePath := icServer(t, "", newBridgeHost(nil), "")
	s.persistInterconnect(ownedEntries(map[int]netip.Addr{
		2: netip.MustParseAddr("169.254.0.11"),
		0: netip.MustParseAddr("169.254.0.9"),
		1: netip.MustParseAddr("169.254.0.10"),
	}))
	got, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != interconnectLedgerGolden {
		t.Fatalf("ledger bytes:\n%q\nwant\n%q", got, interconnectLedgerGolden)
	}
	derived := map[int]netip.Addr{
		0: netip.MustParseAddr("169.254.0.9"),
		1: netip.MustParseAddr("169.254.0.10"),
		2: netip.MustParseAddr("169.254.0.11"),
	}
	if owned := s.restoreInterconnect(derived); !maps.Equal(owned, derived) {
		t.Fatalf("restored %v, want %v", owned, derived)
	}
}
