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
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"k3sm.io/darwin-net/pkg/mesh"
)

// The flag default netd boots with (the server's own /24) and the /24 a join
// previously handed this worker and persisted.
const (
	identityBootCIDR   = "100.64.0.0/24"
	identityWorkerCIDR = "100.64.7.0/24"
)

// recordingPriv is a rootless Privileged that records only what this gate asks
// about: which node pod CIDRs the server re-pointed it at, and in what order
// relative to the first request it served. Every other verb is a no-op.
type recordingPriv struct {
	adopted    []netip.Prefix
	served     bool // set by the first datapath verb
	adoptedErr error
}

func (p *recordingPriv) EnsureAlias(context.Context, netip.Addr) error { p.served = true; return nil }
func (p *recordingPriv) RemoveAlias(context.Context, netip.Addr) error { p.served = true; return nil }

func (p *recordingPriv) ConfigureMesh(context.Context, string, int, mesh.Plan) error {
	p.served = true
	return nil
}

func (p *recordingPriv) RemoveMesh(context.Context) error { p.served = true; return nil }

func (p *recordingPriv) SetNodePodCIDR(_ context.Context, cidr netip.Prefix) error {
	if p.adoptedErr != nil {
		return p.adoptedErr
	}
	p.adopted = append(p.adopted, cidr)
	return nil
}

func (p *recordingPriv) LoadPFAnchor(context.Context, int) error { p.served = true; return nil }

func (p *recordingPriv) BindPort(context.Context, string, netip.AddrPort) (*os.File, error) {
	p.served = true
	return nil, errors.New("not used by this test")
}

// seedIdentity writes content to a fresh identity path (empty content = no file at
// all, the first-boot case) and returns the path.
func seedIdentity(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node-pod-cidr")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("seed identity file: %v", err)
		}
	}
	return path
}

func identityConfig(path string, priv Privileged) Config {
	return Config{
		NodePodCIDR:  netip.MustParsePrefix(identityBootCIDR),
		IdentityPath: path,
		Privileged:   priv,
		Logger:       slog.New(slog.DiscardHandler),
	}
}

// errorLog captures the records a Config.Logger emitted, so a test can assert the
// operator actually gets told about a state only a log reports.
type errorLog struct {
	mu      sync.Mutex
	records []slog.Record
}

func (l *errorLog) Enabled(context.Context, slog.Level) bool { return true }

func (l *errorLog) Handle(_ context.Context, rec slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, rec.Clone())
	return nil
}

func (l *errorLog) WithAttrs([]slog.Attr) slog.Handler { return l }

func (l *errorLog) WithGroup(string) slog.Handler { return l }

// errorsContaining returns the messages logged at Error that contain sub.
func (l *errorLog) errorsContaining(sub string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, rec := range l.records {
		if rec.Level >= slog.LevelError && strings.Contains(rec.Message, sub) {
			out = append(out, rec.Message)
		}
	}
	return out
}

// TestRestoredIdentityReachesTheApplier pins the half of the restore contract that
// the Server's own policy view never showed: the EXECUTOR must be on the restored
// identity too. netd derives the mesh-egress lo0 alias and the utun's own link
// address from the node pod /24, and it used to build that executor from the
// pre-adoption flag default and restore the identity only afterwards — so a
// restarted worker logged the restored /24, admitted pod aliases in it, and still
// carried a utun addressed out of the SERVER's /24, plus a lo0 alias holding the
// control plane's own mesh address. Every dial of the apiserver's mesh address was
// then refused locally by that alias. The restore now happens first, and the
// executor is constructed from (or re-pointed at) the identity that results.
func TestRestoredIdentityReachesTheApplier(t *testing.T) {
	worker := netip.MustParsePrefix(identityWorkerCIDR)
	boot := netip.MustParsePrefix(identityBootCIDR)

	t.Run("a restored worker /24 re-points a supplied executor before anything is served", func(t *testing.T) {
		priv := &recordingPriv{}
		srv := NewServer(identityConfig(seedIdentity(t, identityWorkerCIDR+"\n"), priv))

		if len(priv.adopted) != 1 || priv.adopted[0] != worker {
			t.Fatalf("executor re-pointed at %v, want exactly [%s] at construction", priv.adopted, worker)
		}
		if priv.served {
			t.Fatal("the executor served a datapath verb before the identity was applied")
		}
		if got := srv.nodeCIDR(); got != worker {
			t.Fatalf("node identity = %s, want the restored %s", got, worker)
		}
		// The alias policy follows the restored identity, in both directions.
		if err := srv.validateAliasIP(netip.MustParseAddr("100.64.7.5")); err != nil {
			t.Fatalf("an alias inside the restored /24 was rejected: %v", err)
		}
		if err := srv.validateAliasIP(netip.MustParseAddr("100.64.0.5")); err == nil {
			t.Fatal("an alias inside the pre-adoption /24 was admitted")
		}
	})

	t.Run("no identity file leaves the configured prefix alone", func(t *testing.T) {
		priv := &recordingPriv{}
		srv := NewServer(identityConfig(seedIdentity(t, ""), priv))

		if len(priv.adopted) != 0 {
			t.Fatalf("executor re-pointed at %v with no identity file, want no call", priv.adopted)
		}
		if got := srv.nodeCIDR(); got != boot {
			t.Fatalf("node identity = %s, want the configured %s", got, boot)
		}
	})

	t.Run("a malformed identity file leaves the configured prefix alone", func(t *testing.T) {
		priv := &recordingPriv{}
		srv := NewServer(identityConfig(seedIdentity(t, "not-a-cidr\n"), priv))

		if len(priv.adopted) != 0 {
			t.Fatalf("executor re-pointed at %v from a malformed file, want no call", priv.adopted)
		}
		if got := srv.nodeCIDR(); got != boot {
			t.Fatalf("node identity = %s, want the configured %s", got, boot)
		}
	})

	t.Run("a refused re-point keeps the restored prefix and says so", func(t *testing.T) {
		// A supplied executor that refuses is already live on something, and the
		// node's pod aliases are already plumbed under the restored /24. Reverting
		// the policy to the configured prefix would re-open the pre-adoption
		// window the restore exists to close, so the identity stands and the
		// disagreement is an Error the operator can see until the next
		// ConfigureMesh re-asserts it.
		log := &errorLog{}
		cfg := identityConfig(seedIdentity(t, identityWorkerCIDR+"\n"), &recordingPriv{adoptedErr: errors.New("executor says no")})
		cfg.Logger = slog.New(log)
		srv := NewServer(cfg)

		if got := srv.nodeCIDR(); got != worker {
			t.Fatalf("node identity = %s, want the restored %s to stand after a refused re-point", got, worker)
		}
		if err := srv.validateAliasIP(netip.MustParseAddr("100.64.7.5")); err != nil {
			t.Errorf("an alias inside the restored /24 was rejected: %v", err)
		}
		if err := srv.validateAliasIP(netip.MustParseAddr("100.64.0.5")); err == nil {
			t.Error("the pre-adoption window re-opened: an alias in the configured /24 was admitted")
		}
		if got := log.errorsContaining("refused the restored node pod CIDR"); len(got) != 1 {
			t.Errorf("the disagreement was logged %d times at Error, want 1: %v", len(got), got)
		}
	})

	t.Run("the default darwin applier derives its mesh addresses from the restored /24", func(t *testing.T) {
		cfg := identityConfig(seedIdentity(t, identityWorkerCIDR+"\n"), nil)
		srv := NewServer(cfg)

		app, ok := srv.priv.(*darwinApplier)
		if !ok {
			t.Fatalf("priv is %T, want the production *darwinApplier", srv.priv)
		}
		// The literals, not a re-derivation: the mesh-egress source is the restored
		// /24's .1 and the utun's own link address is its .255. The two addresses
		// the live defect produced (the boot /24's .1 — which is the CONTROL
		// PLANE's mesh address on a worker — and its .255) are named so a
		// regression cannot pass by agreeing with whatever the code computed.
		if want := netip.MustParseAddr("100.64.7.1"); app.meshIP != want {
			t.Errorf("applier meshIP = %s, want %s (the boot-derived 100.64.0.1 is the defect)", app.meshIP, want)
		}
		if want := netip.MustParseAddr("100.64.7.255"); app.linkIP != want {
			t.Errorf("applier linkIP = %s, want %s (the boot-derived 100.64.0.255 is the defect)", app.linkIP, want)
		}
		if app.nodePodCIDR != worker {
			t.Errorf("applier nodePodCIDR = %s, want the restored %s", app.nodePodCIDR, worker)
		}
	})
}
