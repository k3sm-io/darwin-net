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

package mesh

// B68 regression-guard gate. The wireguard swap boundary is the pkg/mesh PACKAGE,
// not a single file: the wireguard-go module (golang.zx2c4.com/wireguard/{conn,
// device,tun}) is imported ONLY by pkg/mesh/device_wireguard.go, one of two Device
// impls behind the wireguard-free Device interface (device.go). The second impl,
// device_netd.go, drives the root daemon over pkg/netd/wire and pulls in no
// wireguard type at all. The neutral swap-surface a fork re-implements is
// PeerConfig (plan.go — a hex string + netip.Prefix + ints), NOT Plan.UAPI(), which
// renders wireguard's IpcSet wire text. This gate keeps that confinement honest:
// subtest A fails if any file OUTSIDE pkg/mesh imports the wireguard module, and
// subtest C proves the Reconcile -> BuildPlan -> Apply seam works through an
// injected fakeDevice with zero wireguard involvement. No production code change.

import (
	"context"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// wgModulePath is the wireguard-go module import path. The real imports are its
// /conn, /device, and /tun subpackages, so the confinement predicate is a path
// PREFIX match, not a bare-path equality (which would match zero files). If a fork
// swap changes this constant, subtest B's positive control fires unless the genuine
// importer under pkg/mesh is updated in lockstep.
const wgModulePath = "golang.zx2c4.com/wireguard"

// wgModuleRoot walks up from this test file's directory to the darwin-net module
// root (the directory holding go.mod), independent of the `go test` working
// directory — a pkg/mesh-local anchor would see only pkg/mesh and vacuously pass.
func wgModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0): could not resolve this test file's path")
	}
	dir := filepath.Dir(file)
	start := dir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("wgModuleRoot: no go.mod found walking up from %s", start)
		}
		dir = parent
	}
}

// importsWG reports whether an import path IS the wireguard module or one of its
// subpackages (a path-BOUNDARY match: the module exactly, or a "<module>/" prefix),
// NOT a substring — so an unrelated path merely containing the string is not
// falsely flagged.
func importsWG(importPath string) bool {
	return importPath == wgModulePath || strings.HasPrefix(importPath, wgModulePath+"/")
}

// TestWireguardImportsConfinedAndDeviceFaked is the B68 gate. It has two halves that
// fail independently: a module-wide lexical import lint that keeps wireguard-go
// confined to the pkg/mesh package (subtests A and B), and a fake-device reconcile
// proof that the peer ADD/REMOVE datapath converges through the Device seam with no
// wireguard type in play (subtest C).
func TestWireguardImportsConfinedAndDeviceFaked(t *testing.T) {
	root := wgModuleRoot(t)
	meshDir := filepath.Join(root, "pkg", "mesh")
	fset := token.NewFileSet()

	type offender struct {
		file       string
		importPath string
	}
	var (
		offenders   []offender
		goFilesSeen int
		meshWGimp   bool
	)

	// inMesh reports whether dir is the pkg/mesh tree (the dir itself or a
	// descendant). It is a prefix-BOUNDARY test (meshDir + separator), so the whole
	// pkg/mesh subtree is allowed and a future pkg/mesh/internal/... survives, while
	// a sibling pkg/meshfoo is NOT wrongly excluded.
	inMesh := func(dir string) bool {
		return dir == meshDir || strings.HasPrefix(dir, meshDir+string(os.PathSeparator))
	}

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		goFilesSeen++

		// ImportsOnly is a hermetic lexical parse (never builds the darwin-only tun
		// package), so this runs anywhere `go test` does under CGO_ENABLED=0.
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Errorf("parse imports of %s: %v", path, perr)
			return nil
		}

		dir := filepath.Dir(path)
		underMesh := inMesh(dir)
		for _, spec := range f.Imports {
			ip, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				t.Errorf("unquote import %q in %s: %v", spec.Path.Value, path, uerr)
				continue
			}
			if !importsWG(ip) {
				continue
			}
			if underMesh {
				meshWGimp = true
				continue // the one sanctioned seam: the pkg/mesh package
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			offenders = append(offenders, offender{file: rel, importPath: ip})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk module root %s: %v", root, walkErr)
	}

	// Subtest A: the confinement invariant — no wireguard import outside pkg/mesh.
	t.Run("imports_confined", func(t *testing.T) {
		for _, o := range offenders {
			t.Errorf("%s imports %q directly — the wireguard-go module is confined to the pkg/mesh package (route the privileged datapath through the Device seam / pkg/netd/wire instead; B68)", o.file, o.importPath)
		}
	})

	// Subtest B: positive controls — prove the walk actually ran and actually saw
	// the coupling, so a mis-rooted or zero-file walk cannot green subtest A
	// vacuously. darwin-net has ~69 .go files; a >20 floor catches a mis-rooted
	// walk, and the genuine-importer control fires (via the SAME prefix predicate)
	// if a fork swap changes wgModulePath but forgets device_wireguard.go.
	t.Run("positive_controls", func(t *testing.T) {
		if goFilesSeen <= 20 {
			t.Fatalf("walk visited only %d .go files under %s; expected the module's full source tree (>20) — the walk is mis-rooted, so subtest A would be vacuous", goFilesSeen, root)
		}
		if !meshWGimp {
			t.Fatalf("no file under %s imports %q or a subpackage — the wireguard coupling the gate confines is missing, so subtest A proves nothing (did wgModulePath drift from the real import?)", meshDir, wgModulePath)
		}
	})

	// Subtest C: the fake-device reconcile proof. It owns the peer ADD + REMOVE
	// cases (the endpoint-MOVE case is owned by TestMeshReconcileEndpointChange). It
	// is constructed entirely inside this subtest so it fails independently of the
	// walk infra above.
	t.Run("device_faked", func(t *testing.T) {
		const (
			selfCIDR = "100.64.0.0/24"
			peerCIDR = "100.64.7.0/24"
			peerEP   = "203.0.113.7:51820"
			peerSeed = 0x37
		)
		fake := &fakeDevice{}
		m, err := New(netip.MustParsePrefix(selfCIDR), withDevice(fake), WithLogger(discardLogger()))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx := context.Background()
		if err := m.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}

		// Baseline: node A alone (its own MeshPeer is dropped — a node is not its
		// own peer), so the plan has no peers and no routes.
		selfPeer := peerSpec("nodeA", selfCIDR, "192.0.2.1:51820", 0x01)
		if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{selfPeer}); err != nil {
			t.Fatalf("baseline Reconcile: %v", err)
		}
		base := fake.last()
		if len(base.Peers) != 0 {
			t.Fatalf("baseline plan has %d peers, want 0 (self is not its own peer): %+v", len(base.Peers), base.Peers)
		}
		if containsPrefix(base.Routes, peerCIDR) {
			t.Fatalf("baseline routes already contain %s before the peer was added: %v", peerCIDR, base.Routes)
		}

		// ADD: introduce nodeB. The plan must GROW — the new peer appears in
		// Plan.Peers (assert its endpoint, not merely the count) AND its /24 route
		// appears in Plan.Routes.
		added := peerSpec("nodeB", peerCIDR, peerEP, peerSeed)
		if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{selfPeer, added}); err != nil {
			t.Fatalf("add Reconcile: %v", err)
		}
		afterAdd := fake.last()
		if len(afterAdd.Peers) != 1 {
			t.Fatalf("after ADD, plan has %d peers, want 1: %+v", len(afterAdd.Peers), afterAdd.Peers)
		}
		if got := afterAdd.Peers[0]; got.NodeName != "nodeB" || got.Endpoint != peerEP {
			t.Fatalf("after ADD, peer = {node %q, endpoint %q}, want {nodeB, %s}", got.NodeName, got.Endpoint, peerEP)
		}
		if !containsPrefix(afterAdd.Routes, peerCIDR) {
			t.Fatalf("after ADD, routes %v do not contain the new peer's %s (route not installed)", afterAdd.Routes, peerCIDR)
		}

		// REMOVE: withdraw nodeB. The plan must SHRINK — the departed peer is gone
		// from Plan.Peers AND its route is withdrawn from Plan.Routes (the
		// blackhole-if-wrong path).
		if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{selfPeer}); err != nil {
			t.Fatalf("remove Reconcile: %v", err)
		}
		afterRemove := fake.last()
		if len(afterRemove.Peers) != 0 {
			t.Fatalf("after REMOVE, plan still has %d peers, want 0: %+v", len(afterRemove.Peers), afterRemove.Peers)
		}
		if containsPrefix(afterRemove.Routes, peerCIDR) {
			t.Fatalf("after REMOVE, routes %v still contain the departed peer's %s (route not withdrawn)", afterRemove.Routes, peerCIDR)
		}

		if err := m.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}
