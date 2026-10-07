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
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// backendDialAllow names the socket dials in this package's production code that
// legitimately bypass tcpseg, keyed by file and the detector's label. Each needs a
// reason; a new entry is a decision, not a convenience.
var backendDialAllow = map[string]map[string]string{
	"udprelay.go": {"net.DialUDP": "UDP has no TSO/MSS: the relay's per-flow upstream socket carries datagrams, never TCP segments"},
}

// backendDialLabels are the detector labels (realSocketUses) that open an
// outbound connection. Listen calls are not dials and are judged separately.
var backendDialLabels = []string{
	"net.Dial", "net.DialTimeout", "net.DialTCP", "net.DialIP", "net.DialUnix", "net.DialUDP",
	"net.Dialer{}", "new(net.Dialer)",
}

// backendDialViolations walks every non-test .go file in dir and reports each
// outbound dial that does not go through tcpseg: a net.Dial* call or method
// value, a net.Dialer composite literal or new(net.Dialer) (via realSocketUses),
// and any other mention of the net.Dialer type — a `var d net.Dialer`, a field,
// or a parameter — since a zero net.Dialer dials as well as a constructed one.
func backendDialViolations(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []string
	parsed := 0
	for _, path := range files {
		name := filepath.Base(path)
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		for _, u := range realSocketUses(fset, f) {
			if !slices.Contains(backendDialLabels, u.what) {
				continue
			}
			if _, ok := backendDialAllow[name][u.what]; ok {
				continue
			}
			out = append(out, name+":"+strconv.Itoa(u.line)+": "+u.what)
		}
		netName := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "net" {
				netName = "net"
				if imp.Name != nil {
					netName = imp.Name.Name
				}
			}
		}
		if netName == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Dialer" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == netName {
				out = append(out, name+":"+strconv.Itoa(fset.Position(sel.Pos()).Line)+": net.Dialer type")
			}
			return true
		})
	}
	if parsed == 0 {
		t.Fatalf("no production files under %s: the walk is vacuous", dir)
	}
	return out
}

// TestBackendDialsClampTCPMaxSeg pins that every TCP connection the Service proxy
// opens or accepts has its segment size clamped (pkg/tcpseg), so a flow
// negotiated over lo0 cannot carry lo0-sized segments onto the mesh utun if its
// destination's alias disappears mid-connection.
//
//   - No production file dials around tcpseg: no net.Dial*, no net.Dialer in any
//     form (the UDP relay's DialUDP is allowlisted with its reason).
//   - The default and the mesh-bound backend dialers are tcpseg.Dialers (the
//     field and dialBackend types make that a compile-time fact; the test pins
//     that both are populated and that the default dial is the tcpseg one).
//   - Both stream listeners handed to serve — the ClusterIP listener from the
//     binder and the *:NodePort listener — are wrapped with tcpseg.WrapListener.
func TestBackendDialsClampTCPMaxSeg(t *testing.T) {
	t.Parallel()

	t.Run("no production dial bypasses tcpseg", func(t *testing.T) {
		t.Parallel()
		if v := backendDialViolations(t, "."); len(v) > 0 {
			t.Fatalf("backend dials that bypass the tcpseg clamp:\n\t%s", strings.Join(v, "\n\t"))
		}
	})

	t.Run("the walk catches every bypass shape", func(t *testing.T) {
		t.Parallel()
		cases := map[string]string{
			"composite literal": "package p\nimport \"net\"\nvar d = &net.Dialer{}\n",
			"zero value":        "package p\nimport \"net\"\nvar d net.Dialer\n",
			"new":               "package p\nimport \"net\"\nvar d = new(net.Dialer)\n",
			"field":             "package p\nimport \"net\"\ntype s struct{ d *net.Dialer }\n",
			"net.Dial":          "package p\nimport \"net\"\nfunc f() { net.Dial(\"tcp\", \"x:1\") }\n",
			"net.DialTimeout":   "package p\nimport \"net\"\nfunc f() { net.DialTimeout(\"tcp\", \"x:1\", 0) }\n",
			"net.DialTCP":       "package p\nimport \"net\"\nfunc f() { net.DialTCP(\"tcp\", nil, nil) }\n",
			"aliased import":    "package p\nimport n \"net\"\nvar d n.Dialer\n",
			"udp outside relay": "package p\nimport \"net\"\nfunc f() { net.DialUDP(\"udp\", nil, nil) }\n",
		}
		for name, src := range cases {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			if v := backendDialViolations(t, dir); len(v) == 0 {
				t.Errorf("%s: the walk missed a bypass in %q", name, src)
			}
		}
	})

	t.Run("both backend dialers are clamped", func(t *testing.T) {
		t.Parallel()
		p := New(NewRoutingTable(netip.Prefix{}),
			withAliasManager(newNoopAliasManager()),
			WithMeshEgressSource(netip.MustParseAddr("100.64.3.1")))
		if p.dialer == nil || p.meshDialer == nil {
			t.Fatalf("dialer = %v, meshDialer = %v; want both tcpseg dialers populated", p.dialer, p.meshDialer)
		}
		if got, want := reflect.ValueOf(p.dialBackend).Pointer(), reflect.ValueOf(dialWith).Pointer(); got != want {
			t.Fatal("the default dialBackend is not dialWith, the tcpseg.Dialer.DialContext dial")
		}
	})

	t.Run("both serve listeners are wrapped", func(t *testing.T) {
		t.Parallel()
		binder := fakeBinder{bound: make(chan *fakeListener, 1)}
		p := New(NewRoutingTable(netip.Prefix{}),
			withAliasManager(newNoopAliasManager()),
			withBinder(binder),
			withListenNodePort(func(network, address string) (net.Listener, error) {
				return newFakeListener(network, address), nil
			}))
		key := PortKey{ClusterIP: "10.43.0.81", Port: 80, Protocol: netv1.ProtocolTCP}
		l, err := p.openListener(key, &netv1.ServicePort{Port: 80, TargetPort: 8080, Protocol: netv1.ProtocolTCP, NodePort: 30081})
		if err != nil {
			t.Fatalf("openListener: %v", err)
		}
		defer l.Close()
		if _, ok := l.clusterIP.(*tcpseg.Listener); !ok {
			t.Errorf("ClusterIP listener is %T, want *tcpseg.Listener", l.clusterIP)
		}
		if _, ok := l.nodePort.(*tcpseg.Listener); !ok {
			t.Errorf("NodePort listener is %T, want *tcpseg.Listener", l.nodePort)
		}
	})
}
