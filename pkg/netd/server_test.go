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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// ---------------------------------------------------------------------------
// Test doubles shared by the server tests and the client round-trip tests (both
// live in package netd_test, so they compile into one test binary).
// ---------------------------------------------------------------------------

// fakePriv is a rootless netd.Privileged: it records the validated, post-policy
// calls the server made and binds an ephemeral loopback socket for BindPort, so
// the SCM_RIGHTS path is exercised with no privilege and no <1024 bind.
type fakePriv struct {
	mu          sync.Mutex
	ensured     []netip.Addr
	removed     []netip.Addr
	meshKeys    []string
	meshPlans   []mesh.Plan
	meshRemoved int
	pfClamps    []int
	bound       []netip.AddrPort
}

func (f *fakePriv) EnsureAlias(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, ip)
	return nil
}

func (f *fakePriv) RemoveAlias(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, ip)
	return nil
}

func (f *fakePriv) ConfigureMesh(_ context.Context, privKeyB64 string, _ int, plan mesh.Plan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.meshKeys = append(f.meshKeys, privKeyB64)
	f.meshPlans = append(f.meshPlans, plan)
	return nil
}

func (f *fakePriv) RemoveMesh(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.meshRemoved++
	return nil
}

func (f *fakePriv) LoadPFAnchor(_ context.Context, mssClamp int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pfClamps = append(f.pfClamps, mssClamp)
	return nil
}

// BindPort ignores the requested addr and binds a free loopback TCP socket, so the
// returned fd is a usable listener without needing to bind the (possibly
// privileged) requested port for real.
func (f *fakePriv) BindPort(_ context.Context, _ string, addr netip.AddrPort) (*os.File, error) {
	f.mu.Lock()
	f.bound = append(f.bound, addr)
	f.mu.Unlock()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	file, err := ln.File()
	_ = ln.Close()
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (f *fakePriv) ensures() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Addr(nil), f.ensured...)
}

func (f *fakePriv) removes() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Addr(nil), f.removed...)
}

func (f *fakePriv) plans() []mesh.Plan {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mesh.Plan(nil), f.meshPlans...)
}

func (f *fakePriv) boundPorts() []netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.AddrPort(nil), f.bound...)
}

// fakeResolver resolves any ConfigureMesh ref to a fixed key.
type fakeResolver struct {
	key string
	err error
}

func (r fakeResolver) Resolve(_ context.Context, _ string) (string, error) { return r.key, r.err }

// fakeAuthorizer admits only the ports in allow for a <1024 bind.
type fakeAuthorizer struct {
	allow map[int]bool
}

func (a fakeAuthorizer) Authorize(_ context.Context, port int, _ string) error {
	if a.allow[port] {
		return nil
	}
	return fmt.Errorf("port %d not in authoritative service set", port)
}

// genKeyB64 returns a random, well-formed 32-byte wireguard key (base64).
func genKeyB64(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// tempSock returns a short unix socket path (macOS sun_path is 104 bytes), falling
// back to /tmp when the test temp dir would overflow the limit.
func tempSock(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s")
	if len(sock) < 100 {
		return sock
	}
	dir, err := os.MkdirTemp("/tmp", "knetd")
	if err != nil {
		t.Fatalf("mkdtemp /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

// startServer starts a Server on a fresh unix socket and returns its path and the
// fake executor. Defaults: the current uid is the authorized peer, the node /24 is
// 100.64.0.0/24, and the fake Privileged executor is installed.
func startServer(t *testing.T, cfg netd.Config) (string, *fakePriv) {
	t.Helper()
	sock := tempSock(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	fp := &fakePriv{}
	if cfg.Privileged == nil {
		cfg.Privileged = fp
	}
	if !cfg.NodePodCIDR.IsValid() {
		cfg.NodePodCIDR = netip.MustParsePrefix("100.64.0.0/24")
	}
	if cfg.ServiceUID == 0 && cfg.PeerVerifier == nil {
		cfg.ServiceUID = uint32(os.Getuid())
	}
	srv := netd.NewServer(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	return sock, fp
}

// rawCall dials sock, sends one framed payload, and reads one framed response.
func rawCall(t *testing.T, sock string, payload []byte) (wire.Response, error) {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return wire.Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := wire.WriteFrame(conn, payload); err != nil {
		return wire.Response{}, err
	}
	respBytes, err := wire.ReadFrame(conn, wire.DefaultMaxRequestBytes)
	if err != nil {
		return wire.Response{}, err
	}
	var resp wire.Response
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return wire.Response{}, err
	}
	return resp, nil
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Peer authentication.
// ---------------------------------------------------------------------------

// TestServerPeerAuthRejectsWrongUID proves a connection whose peer uid is not the
// authorized service uid is rejected (closed) before any request is served — the
// primary "keep other local users out" barrier.
func TestServerPeerAuthRejectsWrongUID(t *testing.T) {
	sock, fp := startServer(t, netd.Config{ServiceUID: uint32(os.Getuid()) + 1})
	ctx := context.Background()
	err := wire.NewClient(sock).EnsureAlias(ctx, netip.MustParseAddr("100.64.0.2"))
	if err == nil {
		t.Fatal("EnsureAlias succeeded despite wrong-uid peer; want rejection")
	}
	if got := fp.ensures(); len(got) != 0 {
		t.Fatalf("executor saw %v aliases despite peer rejection, want none", got)
	}
}

// TestServerPeerAuthAcceptsServiceUID is the happy-path peer-auth + alias round
// trip: the current uid is authorized, so a valid pod-IP EnsureAlias reaches the
// executor.
func TestServerPeerAuthAcceptsServiceUID(t *testing.T) {
	sock, fp := startServer(t, netd.Config{})
	ctx := context.Background()
	ip := netip.MustParseAddr("100.64.0.2")
	if err := wire.NewClient(sock).EnsureAlias(ctx, ip); err != nil {
		t.Fatalf("EnsureAlias: %v", err)
	}
	got := fp.ensures()
	if len(got) != 1 || got[0] != ip {
		t.Fatalf("executor ensured %v, want [%s]", got, ip)
	}
}

// ---------------------------------------------------------------------------
// Out-of-policy rejects.
// ---------------------------------------------------------------------------

// TestServerEnsureAliasOutsideAggregateRejected proves an alias outside the node
// podCIDR (and the pinned aggregate) is denied and never reaches the executor.
func TestServerEnsureAliasOutsideAggregateRejected(t *testing.T) {
	sock, fp := startServer(t, netd.Config{})
	ctx := context.Background()
	err := wire.NewClient(sock).EnsureAlias(ctx, netip.MustParseAddr("192.168.1.5"))
	if err == nil {
		t.Fatal("EnsureAlias(192.168.1.5) succeeded, want policy rejection")
	}
	if got := fp.ensures(); len(got) != 0 {
		t.Fatalf("out-of-policy alias reached executor: %v", got)
	}
}

// TestServerConfigureMeshRouteOutsideRouteSetRejected proves a mesh peer whose
// AllowedIPs is not a per-node /24 (so mesh.RouteSet/ValidatePlan would not admit
// it) is rejected at the boundary rather than silently skipped.
func TestServerConfigureMeshRouteOutsideRouteSetRejected(t *testing.T) {
	sock, fp := startServer(t, netd.Config{
		MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
	})
	ctx := context.Background()
	// A /16 AllowedIPs is not a per-node /24; ValidatePlan rejects it.
	peers := []wire.MeshPeerArg{{
		PubKey:     genKeyB64(t),
		Endpoint:   "192.0.2.10:51820",
		AllowedIPs: []string{"100.64.0.0/16"},
	}}
	if err := wire.NewClient(sock).ConfigureMesh(ctx, "ref", 51820, peers); err == nil {
		t.Fatal("ConfigureMesh with non-/24 AllowedIPs succeeded, want rejection")
	}
	if got := fp.plans(); len(got) != 0 {
		t.Fatalf("out-of-policy mesh plan reached executor: %v", got)
	}
}

// TestServerConfigureMeshRouteOutsideAggregateRejected proves a well-formed /24
// peer route outside the pinned cluster aggregate is denied (defense in depth on
// top of RouteSet).
func TestServerConfigureMeshRouteOutsideAggregateRejected(t *testing.T) {
	sock, fp := startServer(t, netd.Config{
		MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
	})
	ctx := context.Background()
	peers := []wire.MeshPeerArg{{
		PubKey:     genKeyB64(t),
		Endpoint:   "192.0.2.10:51820",
		AllowedIPs: []string{"10.9.9.0/24"}, // valid /24 but outside 100.64.0.0/10
	}}
	if err := wire.NewClient(sock).ConfigureMesh(ctx, "ref", 51820, peers); err == nil {
		t.Fatal("ConfigureMesh with out-of-aggregate /24 succeeded, want rejection")
	}
	if got := fp.plans(); len(got) != 0 {
		t.Fatalf("out-of-aggregate mesh plan reached executor: %v", got)
	}
}

// TestServerConfigureMeshNoResolverFailsFast proves ConfigureMesh is refused when
// no key resolver is configured — there is no embedded-key fallback (hard cut).
func TestServerConfigureMeshNoResolverFailsFast(t *testing.T) {
	sock, _ := startServer(t, netd.Config{}) // no MeshKeyResolver
	ctx := context.Background()
	peers := []wire.MeshPeerArg{{PubKey: genKeyB64(t), Endpoint: "192.0.2.10:51820", AllowedIPs: []string{"100.64.1.0/24"}}}
	if err := wire.NewClient(sock).ConfigureMesh(ctx, "ref", 51820, peers); err == nil {
		t.Fatal("ConfigureMesh without a key resolver succeeded, want fail-fast rejection")
	}
}

// TestServerBindPortPrivilegedWithoutAuthorizerRejected proves a <1024 bind is
// denied when no PortAuthorizer is configured (deny by default).
func TestServerBindPortPrivilegedWithoutAuthorizerRejected(t *testing.T) {
	sock, fp := startServer(t, netd.Config{}) // no PortAuthorizer
	ctx := context.Background()
	_, err := wire.NewClient(sock).BindPort(ctx, "tcp", netip.MustParseAddrPort("10.43.0.10:443"))
	if err == nil {
		t.Fatal("BindPort(:443) without an authorizer succeeded, want deny-by-default")
	}
	if got := fp.boundPorts(); len(got) != 0 {
		t.Fatalf("unauthorized privileged port reached executor: %v", got)
	}
}

// TestServerBindPortHighVIPPortAllowed pins the corrected port-authorization
// contract: a SPECIFIC-address non-privileged (>=1024) VIP port is allowed — it
// grants no more than the unprivileged service uid could bind itself, so the daemon
// does not gate it (only the escalation-sensitive <1024 binds and the wildcard are
// gated, and no PortAuthorizer is needed here). There is no NodePort-range carve-out:
// a NodePort is bound on the wildcard in-process by the proxy, never through this
// helper.
func TestServerBindPortHighVIPPortAllowed(t *testing.T) {
	sock, fp := startServer(t, netd.Config{}) // no PortAuthorizer: >=1024 needs none
	ctx := context.Background()
	ap := netip.MustParseAddrPort("10.43.0.10:8080")
	file, err := wire.NewClient(sock).BindPort(ctx, "tcp", ap)
	if err != nil {
		t.Fatalf("BindPort(:8080 specific VIP) rejected, want allowed (>=1024 is no privilege escalation): %v", err)
	}
	_ = file.Close()
	if got := fp.boundPorts(); len(got) != 1 || got[0] != ap {
		t.Fatalf("executor bound %v, want [%s]", got, ap)
	}
}

// TestServerBindPortWildcardRejected proves the daemon refuses to bind a wildcard
// address: it binds only a specific NodeAddr, never *. A NodePort is reached on the
// wildcard *:nodePort, which the proxy binds in-process (a >=1024 wildcard needs no
// privilege) — the helper has no NodePort path, so a wildcard bind is always rejected
// here regardless of port.
func TestServerBindPortWildcardRejected(t *testing.T) {
	sock, _ := startServer(t, netd.Config{})
	ctx := context.Background()
	if _, err := wire.NewClient(sock).BindPort(ctx, "tcp", netip.MustParseAddrPort("0.0.0.0:30080")); err == nil {
		t.Fatal("BindPort(0.0.0.0) succeeded, want wildcard rejection")
	}
}

// TestServerVersionSkewRejected proves an incompatible MAJOR version is rejected
// while the same major (different minor) is accepted.
func TestServerVersionSkewRejected(t *testing.T) {
	sock, _ := startServer(t, netd.Config{})

	bad := mustJSON(t, wire.Request{
		Version:     wire.Version{Major: wire.ProtocolVersionMajor + 1, Minor: 0},
		Verb:        wire.VerbEnsureAlias,
		EnsureAlias: &wire.EnsureAliasArgs{IP: "100.64.0.2"},
	})
	resp, err := rawCall(t, sock, bad)
	if err != nil {
		t.Fatalf("rawCall: %v", err)
	}
	if resp.OK {
		t.Fatal("incompatible major version accepted, want rejection")
	}

	// Same major, higher minor: additive/compatible, accepted.
	ok := mustJSON(t, wire.Request{
		Version:     wire.Version{Major: wire.ProtocolVersionMajor, Minor: wire.ProtocolVersionMinor + 5},
		Verb:        wire.VerbEnsureAlias,
		EnsureAlias: &wire.EnsureAliasArgs{IP: "100.64.0.2"},
	})
	resp, err = rawCall(t, sock, ok)
	if err != nil {
		t.Fatalf("rawCall (compatible minor): %v", err)
	}
	if !resp.OK {
		t.Fatalf("compatible minor version rejected: %s", resp.Error)
	}
}

// ---------------------------------------------------------------------------
// Robust decoder — malformed input is an error, never a panic.
// ---------------------------------------------------------------------------

// TestServerMalformedFrameErrorsNoPanic feeds the daemon a well-framed non-JSON
// payload, an oversized length prefix, and a zero-length frame, and proves each is
// handled as an error/clean-close (no panic) and the daemon keeps serving.
func TestServerMalformedFrameErrorsNoPanic(t *testing.T) {
	sock, _ := startServer(t, netd.Config{})

	// 1) Well-framed but not JSON: the server replies with an error response.
	resp, err := rawCall(t, sock, []byte("this is not json"))
	if err != nil {
		t.Fatalf("rawCall(bad json): %v", err)
	}
	if resp.OK {
		t.Fatal("malformed JSON accepted, want error response")
	}

	// 2) Oversized length prefix: the server refuses and closes without panicking.
	func() {
		conn, err := net.DialTimeout("unix", sock, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		// length = 0xFFFFFFFF, far above the cap; no body follows.
		if _, err := conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF}); err != nil {
			t.Fatalf("write oversized header: %v", err)
		}
		buf := make([]byte, 8)
		_, _ = conn.Read(buf) // expect EOF/close; we only care that nothing panicked
	}()

	// 3) Zero-length frame.
	func() {
		conn, err := net.DialTimeout("unix", sock, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
			t.Fatalf("write zero header: %v", err)
		}
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
	}()

	// The daemon is still alive and serving after the malformed inputs.
	if err := wire.NewClient(sock).EnsureAlias(context.Background(), netip.MustParseAddr("100.64.0.3")); err != nil {
		t.Fatalf("daemon did not survive malformed input: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS fd passing.
// ---------------------------------------------------------------------------

// TestServerBindPortPassesUsableFD is the SCM_RIGHTS guarantee: a BindPort for a
// specific-address >=1024 VIP port returns a file descriptor that wraps into a
// working net.Listener (it accepts a real connection).
func TestServerBindPortPassesUsableFD(t *testing.T) {
	sock, fp := startServer(t, netd.Config{})
	ctx := context.Background()

	file, err := wire.NewClient(sock).BindPort(ctx, "tcp", netip.MustParseAddrPort("127.0.0.1:30080"))
	if err != nil {
		t.Fatalf("BindPort: %v", err)
	}
	ln, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		t.Fatalf("FileListener over passed fd: %v", err)
	}
	defer ln.Close()

	// The passed descriptor is a real, usable listening socket.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	dialed, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial passed listener: %v", err)
	}
	defer dialed.Close()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("passed fd did not accept a connection")
	}

	if got := fp.boundPorts(); len(got) != 1 || got[0] != netip.MustParseAddrPort("127.0.0.1:30080") {
		t.Fatalf("executor bound %v, want [127.0.0.1:30080]", got)
	}
}

// ---------------------------------------------------------------------------
// Happy-path verbs + per-connection caps.
// ---------------------------------------------------------------------------

// TestServerHappyPathVerbs round-trips the non-fd verbs end to end through the
// wire client against the in-process server with a valid policy input each.
func TestServerHappyPathVerbs(t *testing.T) {
	sock, fp := startServer(t, netd.Config{
		MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
		PortAuthorizer:  fakeAuthorizer{allow: map[int]bool{443: true}},
	})
	ctx := context.Background()
	c := wire.NewClient(sock)

	if err := c.EnsureAlias(ctx, netip.MustParseAddr("100.64.0.7")); err != nil {
		t.Fatalf("EnsureAlias: %v", err)
	}
	if err := c.RemoveAlias(ctx, netip.MustParseAddr("100.64.0.7")); err != nil {
		t.Fatalf("RemoveAlias: %v", err)
	}
	peers := []wire.MeshPeerArg{{PubKey: genKeyB64(t), Endpoint: "192.0.2.10:51820", AllowedIPs: []string{"100.64.1.0/24"}}}
	if err := c.ConfigureMesh(ctx, "ref", 51820, peers); err != nil {
		t.Fatalf("ConfigureMesh: %v", err)
	}
	if err := c.LoadPFAnchor(ctx, mesh.MSSClamp); err != nil {
		t.Fatalf("LoadPFAnchor: %v", err)
	}
	if err := c.RemoveMesh(ctx); err != nil {
		t.Fatalf("RemoveMesh: %v", err)
	}
	// A privileged port the authorizer admits is bound (fd returned).
	file, err := c.BindPort(ctx, "tcp", netip.MustParseAddrPort("10.43.0.10:443"))
	if err != nil {
		t.Fatalf("BindPort(:443 authorized): %v", err)
	}
	_ = file.Close()

	plans := fp.plans()
	if len(plans) != 1 || len(plans[0].Routes) != 1 || plans[0].Routes[0].String() != "100.64.1.0/24" {
		t.Fatalf("ConfigureMesh plan routes = %+v, want [100.64.1.0/24]", plans)
	}
}

// TestServerPerConnectionAliasCap proves a single connection cannot drive more than
// the per-connection alias cap (pipelined requests on one socket).
func TestServerPerConnectionAliasCap(t *testing.T) {
	sock, _ := startServer(t, netd.Config{
		NodePodCIDR: netip.MustParsePrefix("100.64.0.0/24"),
		MaxPerConn:  3,
	})
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	rejected := false
	for i := 0; i < 6; i++ {
		req := wire.Request{
			Version:     wire.CurrentVersion(),
			Verb:        wire.VerbEnsureAlias,
			EnsureAlias: &wire.EnsureAliasArgs{IP: fmt.Sprintf("100.64.0.%d", 10+i)},
		}
		if err := wire.WriteFrame(conn, mustJSON(t, req)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		rb, err := wire.ReadFrame(conn, wire.DefaultMaxRequestBytes)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		var resp wire.Response
		if err := json.Unmarshal(rb, &resp); err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		if !resp.OK {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("per-connection alias cap (3) was never enforced across 6 aliases")
	}
}
