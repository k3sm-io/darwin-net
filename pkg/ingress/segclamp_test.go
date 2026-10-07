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

package ingress

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/tcpseg"
)

// transportViolations walks every non-test .go file in dir and reports each
// backend-transport shape that would dial around tcpseg: an
// httputil.ReverseProxy literal with no Transport (it falls back to
// http.DefaultTransport), and any use of http.DefaultTransport other than as the
// source of a Clone (whose dialer the caller then replaces).
func transportViolations(t *testing.T, dir string) []string {
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
		pkgName := func(want string) string {
			for _, imp := range f.Imports {
				if p, _ := strconv.Unquote(imp.Path.Value); p == want {
					if imp.Name != nil {
						return imp.Name.Name
					}
					return want[strings.LastIndex(want, "/")+1:]
				}
			}
			return ""
		}
		httpName, rpName := pkgName("net/http"), pkgName("net/http/httputil")
		isSel := func(e ast.Expr, pkg, member string) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok || pkg == "" || sel.Sel.Name != member {
				return false
			}
			id, ok := sel.X.(*ast.Ident)
			return ok && id.Name == pkg
		}
		cloned := map[ast.Expr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Clone" {
				return true
			}
			if ta, ok := sel.X.(*ast.TypeAssertExpr); ok && isSel(ta.X, httpName, "DefaultTransport") {
				cloned[ta.X] = true
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if isSel(x, httpName, "DefaultTransport") && !cloned[x] {
					out = append(out, name+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+": http.DefaultTransport")
				}
			case *ast.CompositeLit:
				if !isSel(x.Type, rpName, "ReverseProxy") {
					return true
				}
				hasTransport := false
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Transport" {
							hasTransport = true
						}
					}
				}
				if !hasTransport {
					out = append(out, name+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+": httputil.ReverseProxy without a Transport")
				}
			}
			return true
		})
	}
	if parsed == 0 {
		t.Fatalf("no production files under %s: the walk is vacuous", dir)
	}
	return out
}

// stubListener is a socket-free net.Listener for the bind seam.
type stubListener struct{}

func (stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (stubListener) Close() error              { return nil }
func (stubListener) Addr() net.Addr            { return &net.TCPAddr{} }

// stubBinder hands out a stubListener without opening a socket.
type stubBinder struct{}

func (stubBinder) Listen(context.Context, string, netip.AddrPort) (net.Listener, error) {
	return stubListener{}, nil
}

// TestIngressDialsThroughTheSegmentClamp pins that the L7 ingress clamps the TCP
// segment size on both legs: the reverse proxy dials Service VIPs (lo0 aliases)
// through a tcpseg.Dialer, and every listener bind returns is wrapped with
// tcpseg.WrapListener. A nil ReverseProxy Transport, or any other reliance on
// http.DefaultTransport's unclamped dialer, fails it.
func TestIngressDialsThroughTheSegmentClamp(t *testing.T) {
	t.Run("no production transport bypasses tcpseg", func(t *testing.T) {
		if v := transportViolations(t, "."); len(v) > 0 {
			t.Fatalf("backend transports that bypass the tcpseg clamp:\n\t%s", strings.Join(v, "\n\t"))
		}
	})

	t.Run("the walk catches every bypass shape", func(t *testing.T) {
		cases := map[string]string{
			"nil transport":     "package p\nimport \"net/http/httputil\"\nvar rp = &httputil.ReverseProxy{}\n",
			"default transport": "package p\nimport (\"net/http\"; \"net/http/httputil\")\nvar rp = &httputil.ReverseProxy{Transport: http.DefaultTransport}\n",
			"aliased import":    "package p\nimport h \"net/http\"\nvar rt = h.DefaultTransport\n",
		}
		for name, src := range cases {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			if v := transportViolations(t, dir); len(v) == 0 {
				t.Errorf("%s: the walk missed a bypass in %q", name, src)
			}
		}
	})

	t.Run("the reverse proxy dials through tcpseg", func(t *testing.T) {
		h := newHandler(nil, slog.New(slog.DiscardHandler))
		tr, ok := h.rp.Transport.(*http.Transport)
		if !ok || tr == http.DefaultTransport {
			t.Fatalf("reverse proxy transport = %T (%p), want a dedicated *http.Transport", h.rp.Transport, h.rp.Transport)
		}
		// A method value's code pointer names the method, not the receiver, so only
		// a tcpseg.Dialer's DialContext matches.
		want := reflect.ValueOf((&tcpseg.Dialer{}).DialContext).Pointer()
		if tr.DialContext == nil || reflect.ValueOf(tr.DialContext).Pointer() != want {
			t.Fatal("the backend transport's DialContext is not tcpseg.Dialer.DialContext")
		}
	})

	t.Run("bound listeners are wrapped", func(t *testing.T) {
		s := &Server{cfg: Config{Addr: netip.MustParseAddr("127.0.0.1")}, binder: stubBinder{}}
		ln, err := s.bind(context.Background(), 8080)
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		if _, ok := ln.(*tcpseg.Listener); !ok {
			t.Fatalf("bind returned %T, want *tcpseg.Listener", ln)
		}
	})
}
