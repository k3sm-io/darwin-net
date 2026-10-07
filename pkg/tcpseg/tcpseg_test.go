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

package tcpseg

import (
	"errors"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"k3sm.io/darwin-net/pkg/mesh"
)

// TestMSSMatchesTunnelSegment pins MSS to the mesh's own MSS derivation: the
// tunnel MSS net of the 12-byte timestamp option, which is the value XNU reports
// through getsockopt(TCP_MAXSEG) for a utun-routed connection.
func TestMSSMatchesTunnelSegment(t *testing.T) {
	if want := mesh.TunnelMSS - 12; MSS != want {
		t.Fatalf("MSS = %d, want mesh.TunnelMSS - 12 = %d", MSS, want)
	}
	if MSS != 1328 {
		t.Fatalf("MSS = %d, want 1328 for the 1380-byte mesh MTU", MSS)
	}
}

// TestImportsStayLeaf keeps the package a leaf every socket owner can import:
// only the standard library, x/sys and the apis net contract. pkg/mesh in
// particular would drag wireguard into every consumer.
func TestImportsStayLeaf(t *testing.T) {
	allowed := map[string]bool{"golang.org/x/sys/unix": true, "k3sm.io/apis/net/v1": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			stdlib := !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
			if !stdlib && !allowed[path] {
				t.Errorf("%s imports %q: tcpseg may import only the standard library, golang.org/x/sys/unix and k3sm.io/apis/net/v1", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test files found: the import check is vacuous")
	}
}

// sockoptCall is one recorded get or set through the seam.
type sockoptCall struct {
	op  string // "get" or "set"
	fd  int
	val int
}

// stubSockopts replaces the socket-option seam for one test, recording every
// call; get answers cur, set answers setErr.
func stubSockopts(t *testing.T, cur int, setErr error) *[]sockoptCall {
	t.Helper()
	var calls []sockoptCall
	oldGet, oldSet := getMaxSeg, setMaxSeg
	getMaxSeg = func(fd int) (int, error) {
		calls = append(calls, sockoptCall{op: "get", fd: fd})
		return cur, nil
	}
	setMaxSeg = func(fd, mss int) error {
		calls = append(calls, sockoptCall{op: "set", fd: fd, val: mss})
		return setErr
	}
	t.Cleanup(func() { getMaxSeg, setMaxSeg = oldGet, oldSet })
	return &calls
}

// fakeRawConn is a syscall.RawConn whose Control hands f a fixed descriptor.
type fakeRawConn struct{ fd uintptr }

func (r fakeRawConn) Control(f func(fd uintptr)) error { f(r.fd); return nil }
func (fakeRawConn) Read(func(fd uintptr) bool) error   { return errors.New("not implemented") }
func (fakeRawConn) Write(func(fd uintptr) bool) error  { return errors.New("not implemented") }

// fakeConn stands in for a connection with no real socket. A TCP fake reports a
// *net.TCPAddr local address and exposes a fake raw conn, the shape *net.TCPConn
// has; a non-TCP fake reports a unix address.
type fakeConn struct {
	net.Conn // nil: only the methods below are called
	tcp      bool
	closed   bool
}

func (c *fakeConn) LocalAddr() net.Addr {
	if c.tcp {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	}
	return &net.UnixAddr{Name: "/sock", Net: "unix"}
}
func (c *fakeConn) RemoteAddr() net.Addr                  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 80} }
func (c *fakeConn) Close() error                          { c.closed = true; return nil }
func (c *fakeConn) SyscallConn() (syscall.RawConn, error) { return fakeRawConn{fd: 42}, nil }

// TestDialClampsSegmentSizeUnit is the socket-free twin of
// TestDialClampsSegmentSizeAfterConnect: through the socket-option seam it pins
// that a lo0-sized segment is lowered to MSS, that a connection already below
// MSS is never raised (XNU answers EINVAL), that a failed set closes the dialed
// connection and returns an error, and that a non-TCP connection is untouched.
func TestDialClampsSegmentSizeUnit(t *testing.T) {
	t.Run("lo0-sized segment is lowered to MSS", func(t *testing.T) {
		calls := stubSockopts(t, 16332, nil)
		c := &fakeConn{tcp: true}
		got, err := clampDialed(c, "tcp", "10.43.0.80:80")
		if err != nil || got != c {
			t.Fatalf("clampDialed = %v, %v; want the conn and no error", got, err)
		}
		want := []sockoptCall{{op: "get", fd: 42}, {op: "set", fd: 42, val: MSS}}
		if len(*calls) != 2 || (*calls)[0] != want[0] || (*calls)[1] != want[1] {
			t.Fatalf("sockopt calls = %+v, want %+v", *calls, want)
		}
		if c.closed {
			t.Fatal("a successfully clamped connection was closed")
		}
	})

	t.Run("segment already below MSS is left alone", func(t *testing.T) {
		calls := stubSockopts(t, 1000, nil)
		c := &fakeConn{tcp: true}
		if _, err := clampDialed(c, "tcp", "10.43.0.80:80"); err != nil {
			t.Fatalf("clampDialed: %v", err)
		}
		for _, call := range *calls {
			if call.op == "set" {
				t.Fatalf("set TCP_MAXSEG called on a socket already at 1000 (< MSS): %+v", *calls)
			}
		}
	})

	t.Run("segment exactly MSS is left alone", func(t *testing.T) {
		calls := stubSockopts(t, MSS, nil)
		if err := clamp(&fakeConn{tcp: true}); err != nil {
			t.Fatalf("clamp: %v", err)
		}
		if len(*calls) != 1 {
			t.Fatalf("sockopt calls = %+v, want only the get", *calls)
		}
	})

	t.Run("a failed set closes the connection and returns an error", func(t *testing.T) {
		setErr := syscall.EINVAL
		stubSockopts(t, 16332, setErr)
		c := &fakeConn{tcp: true}
		got, err := clampDialed(c, "tcp", "10.43.0.80:80")
		if err == nil || got != nil {
			t.Fatalf("clampDialed = %v, %v; want nil and an error", got, err)
		}
		if !errors.Is(err, setErr) {
			t.Fatalf("error %v does not wrap the set failure", err)
		}
		if !c.closed {
			t.Fatal("the dialed connection was not closed after its clamp failed")
		}
	})

	t.Run("a non-TCP connection passes through untouched", func(t *testing.T) {
		calls := stubSockopts(t, 16332, nil)
		c := &fakeConn{tcp: false}
		got, err := clampDialed(c, "unix", "/sock")
		if err != nil || got != c {
			t.Fatalf("clampDialed = %v, %v; want the conn untouched", got, err)
		}
		if len(*calls) != 0 {
			t.Fatalf("sockopt calls on a unix conn: %+v", *calls)
		}
	})
}

// fakeListener hands out a fixed queue of connections, then errors.
type fakeListener struct {
	conns []net.Conn
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, os.ErrClosed
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

// TestWrapListenerClampsAccepted pins the accept side: every accepted TCP
// connection is clamped, and one whose clamp fails is closed and skipped rather
// than failing Accept.
func TestWrapListenerClampsAccepted(t *testing.T) {
	t.Run("accepted connection is clamped", func(t *testing.T) {
		calls := stubSockopts(t, 16332, nil)
		c := &fakeConn{tcp: true}
		got, err := WrapListener(&fakeListener{conns: []net.Conn{c}}).Accept()
		if err != nil || got != c {
			t.Fatalf("Accept = %v, %v", got, err)
		}
		if len(*calls) != 2 || (*calls)[1].val != MSS {
			t.Fatalf("sockopt calls = %+v, want a get then a set to %d", *calls, MSS)
		}
	})

	t.Run("a failed clamp skips to the next connection", func(t *testing.T) {
		stubSockopts(t, 16332, syscall.EINVAL)
		bad := &fakeConn{tcp: true}
		good := &fakeConn{tcp: false}
		got, err := WrapListener(&fakeListener{conns: []net.Conn{bad, good}}).Accept()
		if err != nil || got != good {
			t.Fatalf("Accept = %v, %v; want the second connection", got, err)
		}
		if !bad.closed {
			t.Fatal("the connection whose clamp failed was not closed")
		}
	})

	t.Run("a listener error is returned", func(t *testing.T) {
		if _, err := WrapListener(&fakeListener{}).Accept(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Accept error = %v, want os.ErrClosed", err)
		}
	})
}
