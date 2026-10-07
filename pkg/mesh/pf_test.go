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

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// commandRecorder is a commandFunc that records every argv and runs nothing.
type commandRecorder struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *commandRecorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{name}, args...))
	return nil, nil
}

func (r *commandRecorder) take() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

// pfLoadFlags are the pfctl flags that load rules or enable pf. The mesh never
// owns pf, so none of them may ever appear in a pfctl argv it spawns.
var pfLoadFlags = []string{"-f", "-e", "-E"}

func assertNoPFLoad(t *testing.T, phase string, calls [][]string) {
	t.Helper()
	for _, argv := range calls {
		if argv[0] != "pfctl" {
			continue
		}
		for _, a := range argv[1:] {
			if slices.Contains(pfLoadFlags, a) {
				t.Fatalf("%s spawned a pf load/enable: %q", phase, argv)
			}
		}
	}
}

// TestMeshLoadsNoPFAnchor proves, through the device's single command seam, that
// the mesh bring-up host plumbing and teardown load no pf rule and never enable
// pf, and that teardown runs exactly the backstop flush of the legacy anchor.
func TestMeshLoadsNoPFAnchor(t *testing.T) {
	rec := &commandRecorder{}
	d := newWGDevice(wgLink{
		name:       "utun",
		mtu:        MTU,
		meshIP:     netip.MustParseAddr("100.64.3.1"),
		linkIP:     netip.MustParseAddr("100.64.3.254"),
		listenPort: DefaultListenPort,
	}, discardLogger())
	d.command = rec.run
	d.rt = &fakeRouteTable{}
	ctx := context.Background()

	if err := d.plumb(ctx, "utun7"); err != nil {
		t.Fatalf("plumb: %v", err)
	}
	up := rec.take()
	wantUp := [][]string{
		{"ifconfig", "utun7", "inet", "100.64.3.254", "100.64.3.254", "netmask", "255.255.255.255", "up"},
		{"ifconfig", "lo0", "alias", "100.64.3.1/32"},
		{"ifconfig", "utun7", "inet", "100.64.3.1", "100.64.3.254", "netmask", "255.255.255.255", "alias"},
	}
	if !slices.EqualFunc(up, wantUp, slices.Equal[[]string]) {
		t.Fatalf("bring-up commands = %q, want %q", up, wantUp)
	}
	assertNoPFLoad(t, "bring-up", up)

	if err := d.Down(ctx); err != nil {
		t.Fatalf("Down: %v", err)
	}
	down := rec.take()
	if len(down) == 0 {
		t.Fatal("Down recorded no commands; the seam is not wired")
	}
	assertNoPFLoad(t, "teardown", down)
	var pf [][]string
	for _, argv := range down {
		if argv[0] == "pfctl" {
			pf = append(pf, argv)
		}
	}
	wantPF := [][]string{{"pfctl", "-a", "io.k3sm.mesh", "-F", "all"}}
	if !slices.EqualFunc(pf, wantPF, slices.Equal[[]string]) {
		t.Fatalf("teardown pfctl commands = %q, want exactly %q", pf, wantPF)
	}
	if PFAnchor != "io.k3sm.mesh" {
		t.Fatalf("PFAnchor = %q, want io.k3sm.mesh (the name older releases loaded)", PFAnchor)
	}
}

// TestMeshSourceRunsNoPFLoad is the source-level guard behind the seam test: no
// non-test Go file in pkg/mesh or pkg/netd builds a pfctl argv carrying a load or
// enable flag, and the removed loader symbols stay gone. It finds at least one
// pfctl call (the teardown flush), so it cannot pass vacuously.
func TestMeshSourceRunsNoPFLoad(t *testing.T) {
	banned := []string{"PFMSSClampRule", "LoadPFAnchor", "loadPF"}
	pfctlCalls := 0
	for _, dir := range []string{".", filepath.Join("..", "netd"), filepath.Join("..", "netd", "wire")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.Ident:
					if slices.Contains(banned, n.Name) {
						t.Errorf("%s: removed pf loader symbol %s is back", fset.Position(n.Pos()), n.Name)
					}
				case *ast.CallExpr:
					var lits []string
					for _, a := range n.Args {
						if bl, ok := a.(*ast.BasicLit); ok && bl.Kind == token.STRING {
							if v, err := strconv.Unquote(bl.Value); err == nil {
								lits = append(lits, v)
							}
						}
					}
					if !slices.Contains(lits, "pfctl") {
						return true
					}
					pfctlCalls++
					for _, v := range lits {
						if slices.Contains(pfLoadFlags, v) {
							t.Errorf("%s: pfctl call carries %s (a pf load or enable)", fset.Position(n.Pos()), v)
						}
					}
				}
				return true
			})
		}
	}
	if pfctlCalls == 0 {
		t.Fatal("found no pfctl call at all; the teardown flush is missing or the scan is broken")
	}
}
