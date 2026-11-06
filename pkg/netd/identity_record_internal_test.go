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
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// A control-plane Mac's seed: its plist hands netd this /24 and its own
// ConfigureMesh carries the same one, so the identity never moves. Cluster index 2
// derives the slot-0 interconnect address below.
const (
	seededServerCIDR = "100.64.2.0/24"
	seededServerICIP = "169.254.0.17"
)

func seededConfig(path string, priv Privileged, log slog.Handler) Config {
	return Config{
		NodePodCIDR:     netip.MustParsePrefix(seededServerCIDR),
		IdentityPath:    path,
		MeshKeyResolver: keyResolver{},
		Privileged:      priv,
		Logger:          slog.New(log),
	}
}

// confirmRange is the 30 s mesh resync's verb as the server's own mesh sends it.
func confirmRange(t *testing.T, s *Server, cidr string) wire.Response {
	t.Helper()
	return call(t, s, wire.Request{Verb: wire.VerbConfigureMesh, ConfigureMesh: &wire.ConfigureMeshArgs{LocalPrivKeyRef: "ref", NodePodCIDR: cidr}})
}

func wantConfirmed(t *testing.T, s *Server, cidr string) {
	t.Helper()
	if resp := confirmRange(t, s, cidr); !resp.OK {
		t.Fatalf("ConfigureMesh carrying %s refused: %s", cidr, resp.Error)
	}
}

func wantRecorded(t *testing.T, path, cidr string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the range was not recorded: %v", err)
	}
	if got, want := string(raw), cidr+"\n"; got != want {
		t.Fatalf("identity file holds %q, want %q", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity file mode = %#o, want 0600", perm)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".nodepodcidr-") {
			t.Errorf("a temp file was left beside the record: %s", e.Name())
		}
	}
}

// bridgeServer starts a seeded daemon over the production applier and a fake
// bridge0, so a restart's interconnect reconcile runs for real against no host.
func bridgeServer(path, statePath string, h *bridgeHost) *Server {
	log := slog.New(slog.DiscardHandler)
	a := newDarwinApplier(netip.MustParsePrefix(seededServerCIDR), log)
	a.output, a.command = h.output, h.command
	cfg := seededConfig(path, a, slog.DiscardHandler)
	cfg.InterconnectStatePath = statePath
	return NewServer(cfg)
}

func ledgerHolds(t *testing.T, statePath, addr string) bool {
	t.Helper()
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read the interconnect ledger: %v", err)
	}
	l, err := netv1alpha1.ParseInterconnectLedger(raw)
	if err != nil {
		t.Fatalf("parse the interconnect ledger: %v", err)
	}
	for _, e := range l.Aliases {
		if e.Address == addr {
			return true
		}
	}
	return false
}

// TestSeededServerRecordsAdoptedPodRange pins that a confirmed adoption is durable.
// A server's netd starts on the range its plist seeds, so its ConfigureMesh never
// changes the identity; recording only a changed range left a server with no
// node-pod-cidr at all, which doctor reads as "has not joined", uninstall reads as
// "no cluster index", and a restarted netd reads as "unadopted".
func TestSeededServerRecordsAdoptedPodRange(t *testing.T) {
	t.Run("a confirmation records the range root-only and atomically", func(t *testing.T) {
		path := seedIdentity(t, "")
		s := NewServer(seededConfig(path, &recordingPriv{}, slog.DiscardHandler))
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("starting recorded a range nothing confirmed: %v", err)
		}
		wantConfirmed(t, s, seededServerCIDR)
		wantRecorded(t, path, seededServerCIDR)
	})

	t.Run("a resync leaves a matching record alone", func(t *testing.T) {
		for _, content := range []string{seededServerCIDR + "\n", seededServerCIDR, "100.64.2.9/24\n"} {
			t.Run(strings.TrimSpace(content), func(t *testing.T) {
				path := seedIdentity(t, content)
				past := time.Now().Add(-time.Hour)
				if err := os.Chtimes(path, past, past); err != nil {
					t.Fatal(err)
				}
				before, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				s := NewServer(seededConfig(path, &recordingPriv{}, slog.DiscardHandler))
				for range 3 {
					wantConfirmed(t, s, seededServerCIDR)
				}
				after, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				// A rewrite renames a new inode over the path, so this catches one
				// even within the clock's resolution.
				if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
					t.Fatal("the resync rewrote a record that already matched")
				}
			})
		}
	})

	t.Run("a confirmation replaces a record a restart would not read as this range", func(t *testing.T) {
		for _, content := range []string{"not-a-cidr\n", "  \n", "192.168.5.0/24\n", "100.64.9.0/24\n"} {
			t.Run(strings.TrimSpace(content), func(t *testing.T) {
				path := seedIdentity(t, "")
				s := NewServer(seededConfig(path, &recordingPriv{}, slog.DiscardHandler))
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				wantConfirmed(t, s, seededServerCIDR)
				wantRecorded(t, path, seededServerCIDR)
			})
		}
	})

	t.Run("a failed write does not fail the confirmation and the next resync heals it", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "keys")
		path := filepath.Join(dir, "node-pod-cidr")
		log := &errorLog{}
		s := NewServer(seededConfig(path, &recordingPriv{}, log))
		wantConfirmed(t, s, seededServerCIDR)
		if got := log.errorsContaining("persisting the adopted node pod CIDR failed"); len(got) != 1 {
			t.Fatalf("the failed write was logged %d times at Error, want 1: %v", len(got), got)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		wantConfirmed(t, s, seededServerCIDR)
		wantRecorded(t, path, seededServerCIDR)
	})

	t.Run("a refused adoption leaves the record on the identity in force", func(t *testing.T) {
		path := seedIdentity(t, "")
		s := NewServer(seededConfig(path, &recordingPriv{}, slog.DiscardHandler))
		wantConfirmed(t, s, seededServerCIDR)
		s.trackAlias(netip.MustParseAddr("100.64.2.5"))
		if resp := confirmRange(t, s, "100.64.9.0/24"); resp.OK {
			t.Fatal("an adoption under a live pod alias was admitted")
		}
		wantRecorded(t, path, seededServerCIDR)
	})

	t.Run("a restart comes back confirmed on the recorded range with no ConfigureMesh", func(t *testing.T) {
		dir := t.TempDir()
		path, statePath := filepath.Join(dir, "node-pod-cidr"), filepath.Join(dir, "interconnect")
		h := newBridgeHost(nil)
		s := bridgeServer(path, statePath, h)
		if err := s.adoptNodePodCIDR(context.Background(), seededServerCIDR); err != nil {
			t.Fatal(err)
		}
		wantOK(t, ensureIC(t, s, 0))
		h.ops = nil

		restarted := bridgeServer(path, statePath, h)
		if !h.has(seededServerICIP) || !ledgerHolds(t, statePath, seededServerICIP) {
			t.Fatalf("the restart lost the owned alias: on bridge0=%t", h.has(seededServerICIP))
		}
		if len(h.ops) != 0 {
			t.Fatalf("the restart issued %q against an alias it owns", h.ops)
		}
		wantOK(t, ensureIC(t, restarted, 1))
		h.checkOps(t)
	})

	t.Run("the first start after an upgrade keeps the alias and records both files", func(t *testing.T) {
		// An existing install: the alias is on bridge0, the ledger names it, and no
		// node-pod-cidr was ever written.
		dir := t.TempDir()
		path, statePath := filepath.Join(dir, "node-pod-cidr"), filepath.Join(dir, "interconnect")
		raw, err := netv1alpha1.InterconnectLedger{Aliases: []netv1alpha1.InterconnectLedgerEntry{{Slot: 0, Address: seededServerICIP}}}.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		h := newBridgeHost(map[string]string{seededServerICIP: "255.255.255.0"})

		// Nothing has confirmed the seed yet, so the verbs still refuse and the
		// alias stays where it is.
		s := bridgeServer(path, statePath, h)
		wantRefused(t, ensureIC(t, s, 0), wire.ReasonInterconnectIdentityUnadopted)
		if !h.has(seededServerICIP) || len(h.ops) != 0 {
			t.Fatalf("the first start touched bridge0: on bridge0=%t, ops=%q", h.has(seededServerICIP), h.ops)
		}

		// The first resync records the range; the next ensure takes the alias back.
		if err := s.adoptNodePodCIDR(context.Background(), seededServerCIDR); err != nil {
			t.Fatal(err)
		}
		wantRecorded(t, path, seededServerCIDR)
		wantOK(t, ensureIC(t, s, 0))
		if !ledgerHolds(t, statePath, seededServerICIP) || len(h.ops) != 0 {
			t.Fatalf("the alias was not taken back as it stood: ops=%q", h.ops)
		}

		// And the restart after that no longer resets anything.
		bridgeServer(path, statePath, h)
		if !h.has(seededServerICIP) || !ledgerHolds(t, statePath, seededServerICIP) || len(h.ops) != 0 {
			t.Fatalf("the second start lost the alias: on bridge0=%t, ops=%q", h.has(seededServerICIP), h.ops)
		}
	})
}
