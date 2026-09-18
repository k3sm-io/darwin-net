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

package netd_test

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// The node identity netd starts with (the --node-pod-cidr default, which is the
// server's own /24) and the /24 the join hands a worker afterwards.
const (
	bootCIDR   = "100.64.0.0/24"
	workerCIDR = "100.64.7.0/24"
)

// recorder is a concurrency-safe slog.Handler that keeps every record, so a test
// can assert both what was logged and at which level.
type recorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *recorder) WithGroup(string) slog.Handler { return r }

func (r *recorder) logger() *slog.Logger { return slog.New(r) }

// atLeastInfo returns the messages logged at Info or above that contain sub.
func (r *recorder) atLeastInfo(sub string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.records {
		if rec.Level >= slog.LevelInfo && strings.Contains(rec.Message, sub) {
			out = append(out, rec.Message)
		}
	}
	return out
}

// selfPeer is a well-formed peer whose /24 is the daemon's PRE-adoption identity.
// It is the probe for which self prefix the daemon validated the plan against: a
// peer equal to self is dropped (a node is not its own peer, 0 routes), while the
// same peer under an adopted identity is a real peer routing bootCIDR.
func selfPeer(t *testing.T) []wire.MeshPeerArg {
	t.Helper()
	return []wire.MeshPeerArg{{
		PubKey:     genKeyB64(t),
		Endpoint:   "192.0.2.10:51820",
		AllowedIPs: []string{bootCIDR},
	}}
}

// TestConfigureMeshAdoptsTheNodePodCIDR pins the worker-identity adoption: netd is
// started by the installer long before the node joins, so on a worker it boots
// with the server's /24 as its node identity and cannot be restarted to learn the
// real one (a restart drops every lo0 alias and mesh route on the node). The join
// therefore hands the node's real /24 over the ConfigureMesh channel, and the
// daemon adopts it exactly once, before anything is live.
func TestConfigureMeshAdoptsTheNodePodCIDR(t *testing.T) {
	ctx := context.Background()

	t.Run("adopts the worker /24 before anything is live", func(t *testing.T) {
		rec := &recorder{}
		sock, fp := startServer(t, netd.Config{
			MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
			Logger:          rec.logger(),
		})
		c := wire.NewClient(sock)

		// Pre-adoption the daemon is the server: a worker pod IP is out of policy.
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.7.5")); err == nil {
			t.Fatal("a worker pod IP was admitted before adoption, so the test cannot prove the adoption")
		}

		if err := c.ConfigureMesh(ctx, "ref", 51820, netip.MustParsePrefix(workerCIDR), selfPeer(t)); err != nil {
			t.Fatalf("ConfigureMesh carrying the node pod CIDR: %v", err)
		}

		// The alias policy now follows the adopted /24, in both directions.
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.7.5")); err != nil {
			t.Fatalf("alias inside the adopted /24 rejected: %v", err)
		}
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.5")); err == nil {
			t.Fatal("alias inside the PRE-adoption /24 still admitted; the node identity did not move")
		}

		// ValidatePlan saw the new self: the peer on the old /24 is a real peer now.
		plans := fp.plans()
		if len(plans) != 1 {
			t.Fatalf("executor saw %d plans, want 1", len(plans))
		}
		if got := plans[0].Routes; len(got) != 1 || got[0].String() != bootCIDR {
			t.Fatalf("plan routes = %v, want [%s] (the plan was validated against the old self)", got, bootCIDR)
		}

		// The executor was re-pointed too (its mesh-egress/link addresses derive
		// from the node /24).
		if got := fp.adoptions(); len(got) != 1 || got[0] != netip.MustParsePrefix(workerCIDR) {
			t.Fatalf("executor adoptions = %v, want [%s]", got, workerCIDR)
		}
		if got := rec.atLeastInfo("adopted node pod CIDR"); len(got) != 1 {
			t.Fatalf("adoption logged %d times at Info, want 1: %v", len(got), got)
		}
	})

	t.Run("the same CIDR again is a no-op", func(t *testing.T) {
		rec := &recorder{}
		sock, fp := startServer(t, netd.Config{
			MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
			Logger:          rec.logger(),
		})
		c := wire.NewClient(sock)
		worker := netip.MustParsePrefix(workerCIDR)

		// Up, then Apply: the real mesh device sends the CIDR on every call.
		if err := c.ConfigureMesh(ctx, "ref", 51820, worker, nil); err != nil {
			t.Fatalf("ConfigureMesh (up): %v", err)
		}
		if err := c.ConfigureMesh(ctx, "ref", 51820, worker, selfPeer(t)); err != nil {
			t.Fatalf("ConfigureMesh (apply, same CIDR): %v", err)
		}

		if got := fp.adoptions(); len(got) != 1 {
			t.Fatalf("executor saw %d adoptions, want 1 (a repeat of the same CIDR must not re-point it): %v", len(got), got)
		}
		if got := rec.atLeastInfo("adopted node pod CIDR"); len(got) != 1 {
			t.Fatalf("adoption logged %d times at Info, want 1 (a no-op must not log above Debug): %v", len(got), got)
		}
	})

	t.Run("a different CIDR under live state is refused", func(t *testing.T) {
		sock, fp := startServer(t, netd.Config{
			MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
			Logger:          quietTestLogger(),
		})
		c := wire.NewClient(sock)

		// A live pod alias on the boot identity.
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.5")); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}

		err := c.ConfigureMesh(ctx, "ref", 51820, netip.MustParsePrefix(workerCIDR), nil)
		if err == nil {
			t.Fatal("ConfigureMesh moved the node identity under a live alias, want refusal")
		}
		for _, want := range []string{"denied by policy", bootCIDR, workerCIDR} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not name %q", err, want)
			}
		}

		// State unchanged: the boot identity still governs and nothing was applied.
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.6")); err != nil {
			t.Fatalf("alias inside the pinned /24 rejected after the refusal: %v", err)
		}
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.7.5")); err == nil {
			t.Fatal("alias inside the refused /24 admitted; the identity moved anyway")
		}
		if got := fp.plans(); len(got) != 0 {
			t.Fatalf("a refused ConfigureMesh reached the executor: %v", got)
		}
		if got := fp.adoptions(); len(got) != 0 {
			t.Fatalf("a refused adoption re-pointed the executor: %v", got)
		}
	})

	t.Run("a CIDR outside the cluster aggregate is refused", func(t *testing.T) {
		sock, fp := startServer(t, netd.Config{
			MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
			Logger:          quietTestLogger(),
		})
		c := wire.NewClient(sock)

		err := c.ConfigureMesh(ctx, "ref", 51820, netip.MustParsePrefix("192.168.5.0/24"), nil)
		if err == nil {
			t.Fatal("ConfigureMesh adopted a CIDR outside the cluster aggregate, want refusal")
		}
		for _, want := range []string{"denied by policy", "192.168.5.0/24"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not name %q", err, want)
			}
		}
		if got := fp.adoptions(); len(got) != 0 {
			t.Fatalf("an out-of-aggregate adoption re-pointed the executor: %v", got)
		}
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.5")); err != nil {
			t.Fatalf("alias inside the pinned /24 rejected after the refusal: %v", err)
		}
	})

	t.Run("a live Service VIP alias does not block adoption", func(t *testing.T) {
		sock, fp := startServer(t, netd.Config{
			ServiceCIDR:     netip.MustParsePrefix("10.43.0.0/16"),
			MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
			Logger:          quietTestLogger(),
		})
		c := wire.NewClient(sock)

		// The proxy plumbs its ClusterIP VIPs as soon as it syncs, which on a worker
		// can precede the join's ConfigureMesh. A VIP is not derived from the node
		// /24 and is not orphaned by an adoption, so it must not pin the identity.
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("10.43.0.10")); err != nil {
			t.Fatalf("EnsureAlias(VIP): %v", err)
		}
		if err := c.ConfigureMesh(ctx, "ref", 51820, netip.MustParsePrefix(workerCIDR), nil); err != nil {
			t.Fatalf("a live Service VIP alias blocked the adoption: %v", err)
		}
		if got := fp.adoptions(); len(got) != 1 || got[0] != netip.MustParsePrefix(workerCIDR) {
			t.Fatalf("executor adoptions = %v, want [%s]", got, workerCIDR)
		}
		// The VIP is still admissible, and the node identity moved.
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("10.43.0.10")); err != nil {
			t.Fatalf("VIP alias rejected after the adoption: %v", err)
		}
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.7.5")); err != nil {
			t.Fatalf("alias inside the adopted /24 rejected: %v", err)
		}
	})

	t.Run("the adopted CIDR survives a helper restart", func(t *testing.T) {
		rec := &recorder{}
		cfg := netd.Config{
			IdentityPath:    filepath.Join(t.TempDir(), "node-pod-cidr"),
			MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
			Logger:          rec.logger(),
		}

		// The daemon the join talked to adopts the worker /24 ...
		sock, _ := startServer(t, cfg)
		if err := wire.NewClient(sock).ConfigureMesh(ctx, "ref", 51820, netip.MustParsePrefix(workerCIDR), nil); err != nil {
			t.Fatalf("ConfigureMesh: %v", err)
		}

		// The identity file is the node's, root-only, and holds exactly the CIDR.
		fi, err := os.Stat(cfg.IdentityPath)
		if err != nil {
			t.Fatalf("stat identity file: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("identity file mode = %#o, want 0600", perm)
		}
		if raw, err := os.ReadFile(cfg.IdentityPath); err != nil {
			t.Fatalf("read identity file: %v", err)
		} else if strings.TrimSpace(string(raw)) != workerCIDR {
			t.Fatalf("identity file holds %q, want %q", strings.TrimSpace(string(raw)), workerCIDR)
		}

		// ... and dies. launchd restarts it from the same flags, with the node's pod
		// aliases still plumbed in the kernel and nothing to re-assert the identity
		// until the mesh's next resync.
		restarted, fp2 := startServer(t, cfg)
		// The restore re-points the executor at construction, before a byte is
		// served: the mesh addresses it derives from the node /24 must come from
		// the restored identity, not from the flag default (see
		// TestRestoredIdentityReachesTheApplier).
		if got := fp2.adoptions(); len(got) != 1 || got[0].String() != workerCIDR {
			t.Fatalf("restarted executor re-pointed at %v, want exactly [%s] at construction", got, workerCIDR)
		}
		c2 := wire.NewClient(restarted)
		if err := c2.EnsureAlias(ctx, netip.MustParseAddr("100.64.7.5")); err != nil {
			t.Fatalf("the restarted daemon rejected a pod alias in the adopted /24: %v", err)
		}
		if err := c2.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.5")); err == nil {
			t.Fatal("the restarted daemon admitted an alias in the pre-adoption /24")
		}
		if got := rec.atLeastInfo("restored adopted node pod CIDR"); len(got) != 1 {
			t.Fatalf("restore logged %d times at Info, want 1: %v", len(got), got)
		}

		// An old client's frame still leaves the restored identity alone.
		resp, err := rawCall(t, restarted, mustJSON(t, wire.Request{
			Version: wire.CurrentVersion(),
			Verb:    wire.VerbConfigureMesh,
			ConfigureMesh: &wire.ConfigureMeshArgs{
				LocalPrivKeyRef: "ref",
				ListenPort:      51820,
				Peers:           selfPeer(t),
			},
		}))
		if err != nil {
			t.Fatalf("raw ConfigureMesh: %v", err)
		}
		if !resp.OK {
			t.Fatalf("raw ConfigureMesh without a nodePodCIDR rejected: %s", resp.Error)
		}
		if got := fp2.adoptions(); len(got) != 1 {
			t.Fatalf("the restarted daemon re-adopted: %v, want only the construction-time re-point", got)
		}
		// Still the restored identity: the peer on bootCIDR is a real peer, routed.
		plans := fp2.plans()
		if len(plans) != 1 || len(plans[0].Routes) != 1 || plans[0].Routes[0].String() != bootCIDR {
			t.Fatalf("plans = %+v, want one plan routing %s (self is still %s)", plans, bootCIDR, workerCIDR)
		}
	})

	t.Run("an omitted CIDR leaves the identity alone", func(t *testing.T) {
		sock, fp := startServer(t, netd.Config{
			MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
			Logger:          quietTestLogger(),
		})
		c := wire.NewClient(sock)

		// An old client: the args carry no nodePodCIDR at all.
		resp, err := rawCall(t, sock, mustJSON(t, wire.Request{
			Version: wire.CurrentVersion(),
			Verb:    wire.VerbConfigureMesh,
			ConfigureMesh: &wire.ConfigureMeshArgs{
				LocalPrivKeyRef: "ref",
				ListenPort:      51820,
				Peers:           selfPeer(t),
			},
		}))
		if err != nil {
			t.Fatalf("raw ConfigureMesh: %v", err)
		}
		if !resp.OK {
			t.Fatalf("raw ConfigureMesh without a nodePodCIDR rejected: %s", resp.Error)
		}

		// The daemon is still the boot identity: the peer on bootCIDR is its OWN
		// MeshPeer, so it is dropped and nothing is routed.
		plans := fp.plans()
		if len(plans) != 1 {
			t.Fatalf("executor saw %d plans, want 1", len(plans))
		}
		if got := plans[0].Routes; len(got) != 0 {
			t.Fatalf("plan routes = %v, want none (self is still %s)", got, bootCIDR)
		}
		if got := fp.adoptions(); len(got) != 0 {
			t.Fatalf("an omitted CIDR re-pointed the executor: %v", got)
		}
		if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.5")); err != nil {
			t.Fatalf("alias inside the unchanged /24 rejected: %v", err)
		}
	})
}

// quietTestLogger discards output for subtests that assert on state, not logs.
func quietTestLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestRestoredNodePodCIDRFailsOpen pins the restore contract's failure posture: the
// persisted identity is an optimization for the restart case, never an authority.
// A file that is absent, unreadable as a prefix, or outside the pinned cluster
// aggregate leaves the daemon on its configured Config.NodePodCIDR — the agent
// re-asserts the real identity on its next ConfigureMesh either way, and honouring
// a corrupt file would move the policy boundary on the strength of a bad byte.
func TestRestoredNodePodCIDRFailsOpen(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		content string // "" means: write no file at all
	}{
		{name: "no file (first boot)", content: ""},
		{name: "not a prefix", content: "not-a-cidr\n"},
		{name: "an address, not a prefix", content: "100.64.7.5\n"},
		{name: "outside the cluster aggregate", content: "192.168.5.0/24\n"},
		{name: "wider than the cluster aggregate", content: "100.0.0.0/8\n"},
		{name: "empty file", content: "  \n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "node-pod-cidr")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatalf("seed identity file: %v", err)
				}
			}
			sock, _ := startServer(t, netd.Config{
				IdentityPath: path,
				Logger:       quietTestLogger(),
			})
			c := wire.NewClient(sock)
			if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.5")); err != nil {
				t.Fatalf("the configured identity did not govern after an ignored identity file: %v", err)
			}
			if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.7.5")); err == nil {
				t.Fatal("an alias outside the configured identity was admitted")
			}
		})
	}
}
