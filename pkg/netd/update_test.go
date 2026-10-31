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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// machO is a Mach-O 64 little-endian magic, the prefix every fake binary
// carries so the policy treats it as a Mach-O.
const machO = "\xcf\xfa\xed\xfe"

// testPKI is a cluster CA and an update signer under it.
type testPKI struct {
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caPEM     []byte
	signerKey *ecdsa.PrivateKey
	signerPEM []byte
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var serialMu sync.Mutex
var serial int64

func nextSerial() *big.Int {
	serialMu.Lock()
	defer serialMu.Unlock()
	serial++
	return big.NewInt(serial)
}

// newCA makes a self-signed ECDSA CA.
func newCA(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// codeSigning is the extended key usage an update signer carries.
var codeSigning = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}

// leaf issues a leaf certificate for key under the CA.
func leaf(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate, pub any, subj pkix.Name, notAfter time.Time) []byte {
	t.Helper()
	return leafEKU(t, caKey, ca, pub, subj, notAfter, codeSigning)
}

// leafEKU is leaf with the given extended key usages (none when nil).
func leafEKU(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate, pub any, subj pkix.Name, notAfter time.Time, eku []x509.ExtKeyUsage) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      subj,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var signerSubject = pkix.Name{CommonName: wire.UpdateSignerCommonName, Organization: []string{wire.UpdateSignerOrganization}}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{signerKey: newKey(t)}
	p.caKey, p.caCert, p.caPEM = newCA(t, "k3sm-cluster-ca")
	p.signerPEM = leaf(t, p.caKey, p.caCert, &p.signerKey.PublicKey, signerSubject, time.Now().Add(12*time.Hour))
	return p
}

// sign is a DER ECDSA signature over sha256(payload).
func sign(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	d := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// tarMember is one archive entry.
type tarMember struct {
	name     string
	body     string
	mode     int64
	typeflag byte
	linkname string
	size     int64 // a header-only size, written without a body, when set
}

// releaseMembers is a release archive's shape: the five binaries (ad-hoc
// signed per the fake inspector), the cp-payload tree with a Mach-O and a
// marker, and the members the extraction reads past.
func releaseMembers(sig string) []tarMember {
	bin := func(name string) tarMember {
		return tarMember{name: name, body: machO + name + "\n" + sig, mode: 0o755}
	}
	return []tarMember{
		{name: "LICENSE", body: "license\n", mode: 0o644},
		{name: "NOTICE", body: "notice\n", mode: 0o644},
		bin("k3sm"),
		bin("k3sm-netd"),
		bin("k3sm-execshim"),
		bin("k3sm-vmhost"),
		bin("libk3sm_getaddrinfo_shim.dylib"),
		bin("libk3sm_pathrebase_shim.dylib"),
		{name: "cp-payload/", typeflag: tar.TypeDir, mode: 0o755},
		bin("cp-payload/kine"),
		{name: "cp-payload/kube.version", body: "v1.37.1\n", mode: 0o644},
		bin("cp-payload/bin/helm"),
	}
}

// buildArchive encodes members as a gzip tar.
func buildArchive(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range members {
		tf := m.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		size := int64(len(m.body))
		if m.size != 0 {
			size = m.size
		}
		if tf != tar.TypeReg {
			size = 0
		}
		hdr := &tar.Header{Name: m.name, Mode: m.mode, Typeflag: tf, Linkname: m.linkname, Size: size, ModTime: time.Unix(1700000000, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if m.size != 0 {
			// A header that claims more than is written: the extraction must
			// refuse on the header alone. Stop here, leaving the stream short.
			_ = tw.Flush()
			_ = zw.Close()
			return buf.Bytes()
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write([]byte(m.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeInspector reads the last line of a file as its signature: ADHOC is a
// valid ad-hoc signature, TEAM:<id> a valid Developer ID signature from team
// id, NODEVID:<id> a valid signature whose TeamIdentifier is id but which fails
// the Developer ID requirement, anything else an invalid one.
type fakeInspector struct {
	mu    sync.Mutex
	paths []string
}

func (f *fakeInspector) Inspect(_ context.Context, p string) (codeSignature, error) {
	f.mu.Lock()
	f.paths = append(f.paths, p)
	f.mu.Unlock()
	b, err := os.ReadFile(p)
	if err != nil {
		return codeSignature{}, err
	}
	s := string(b)
	last := s[strings.LastIndex(s, "\n")+1:]
	switch {
	case last == "ADHOC":
		return codeSignature{Valid: true}, nil
	case strings.HasPrefix(last, "TEAM:"):
		return codeSignature{Valid: true, TeamID: strings.TrimPrefix(last, "TEAM:"), DeveloperID: true}, nil
	case strings.HasPrefix(last, "NODEVID:"):
		return codeSignature{Valid: true, TeamID: strings.TrimPrefix(last, "NODEVID:")}, nil
	}
	return codeSignature{}, nil
}

func (f *fakeInspector) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.paths)
}

// fakeInstaller records the one exec ApplyUpdate makes and what was on disk
// when it was made.
type fakeInstaller struct {
	calls    int
	argv     []string
	dir      string
	staged   map[string]string // relative path -> content, at exec time
	topLevel []string          // the staging directory's entries at exec time
	logLines string            // written to the log before returning
	err      error
}

func (f *fakeInstaller) run(_ context.Context, r installerRun) error {
	f.calls++
	f.argv = slices.Clone(r.Argv)
	f.dir = r.Dir
	if entries, err := os.ReadDir(r.Dir); err == nil {
		for _, e := range entries {
			f.topLevel = append(f.topLevel, e.Name())
		}
	}
	f.staged = map[string]string{}
	_ = filepath.WalkDir(r.Dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && d.Name() != updateLogName {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(r.Dir, p)
			f.staged[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	if f.logLines != "" {
		_, _ = r.Log.WriteString(f.logLines)
	}
	return f.err
}

// socketPair returns the two ends of a connected unix stream socket. The peer
// credential on either end is this test's own uid.
func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("pair-%d", i))
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("file conn: %v", err)
		}
		conns[i] = c.(*net.UnixConn)
		t.Cleanup(func() { _ = c.Close() })
	}
	return conns[0], conns[1]
}

// updateHarness is a Server with a cluster CA, a temp staging root, a fake
// installer, code inspector and installed version, and a connection whose
// peer is this test's uid.
type updateHarness struct {
	t         *testing.T
	pki       *testPKI
	s         *Server
	inst      *fakeInstaller
	insp      *fakeInspector
	st        *connState
	phases    []wire.UpdatePhase
	root      string
	installed string // the installed k3sm's path
	version   string // what the installed k3sm reports
	probes    int
}

type harnessOpt func(*Config)

func newUpdateHarness(t *testing.T, serviceUID uint32, opts ...harnessOpt) *updateHarness {
	t.Helper()
	pki := newTestPKI(t)
	// The installed path is resolved before use, so the harness names it by
	// its real path (the temp root itself is behind a symlink on macOS).
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "cluster-ca.crt")
	if err := os.WriteFile(caPath, pki.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		NodePodCIDR:   netip.MustParsePrefix(identityBootCIDR),
		ServiceUID:    serviceUID,
		ClusterCAPath: caPath,
		Privileged:    &recordingPriv{},
		Logger:        slog.New(slog.DiscardHandler),
	}
	for _, o := range opts {
		o(&cfg)
	}
	s := NewServer(cfg)
	h := &updateHarness{
		t: t, pki: pki, s: s, inst: &fakeInstaller{}, insp: &fakeInspector{},
		root: filepath.Join(dir, "k3sm.staging"), installed: filepath.Join(dir, "installed-k3sm"),
		version: "v0.1.9",
	}
	h.setInstalled("ADHOC")
	s.stagingRoot = h.root
	s.runInstaller = h.inst.run
	s.inspector = h.insp
	s.installedK3sm = h.installed
	// Absent unless a test writes it, so no test reads the host's plist.
	s.updaterPlist = filepath.Join(dir, "io.k3sm.updater.plist")
	s.installedVersion = func(_ context.Context, p string) (string, error) {
		h.probes++
		if p != h.installed {
			return "", fmt.Errorf("probed %s, want %s", p, h.installed)
		}
		return h.version, nil
	}
	conn, _ := socketPair(t)
	h.st = newConnState(wire.DefaultMaxPerConn)
	h.st.conn = conn
	h.st.emit = func(r wire.Response) error {
		h.phases = append(h.phases, r.Phase)
		return nil
	}
	return h
}

// setInstalled writes the installed k3sm with the given fake signature.
func (h *updateHarness) setInstalled(sig string) {
	h.t.Helper()
	if err := os.WriteFile(h.installed, []byte(machO+"installed\n"+sig), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

// writeArchive writes an archive into a fresh directory and returns its path
// and its sha256.
func (h *updateHarness) writeArchive(members []tarMember) (string, string) {
	h.t.Helper()
	b := buildArchive(h.t, members)
	p := filepath.Join(h.t.TempDir(), "k3sm-darwin-arm64.tar.gz")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		h.t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return p, hex.EncodeToString(sum[:])
}

// payload is the canonical payload JSON.
func payloadJSON(t *testing.T, version, sum, policy string, allowDowngrade bool) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"version": version, "url": "https://github.com/k3sm-io/k3sm/releases/download/" + version + "/k3sm-darwin-arm64.tar.gz",
		"sha256": sum, "signature": policy, "allowDowngrade": allowDowngrade,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// request is a signed request for members.
func (h *updateHarness) request(members []tarMember, version, policy string, allowDowngrade bool) *wire.ApplyUpdateArgs {
	h.t.Helper()
	p, sum := h.writeArchive(members)
	payload := payloadJSON(h.t, version, sum, policy, allowDowngrade)
	return &wire.ApplyUpdateArgs{ArchivePath: p, Payload: payload, Signature: sign(h.t, h.pki.signerKey, payload), SignerCert: h.pki.signerPEM}
}

// apply runs one ApplyUpdate and records the final phase after the streamed ones.
func (h *updateHarness) apply(args *wire.ApplyUpdateArgs) wire.Response {
	resp := h.s.handleApplyUpdate(context.Background(), h.st, args)
	h.phases = append(h.phases, resp.Phase)
	return resp
}

// stagingLeftovers lists what remains under the staging root (the lock file
// sits beside it, not in it).
func (h *updateHarness) stagingLeftovers() []string {
	h.t.Helper()
	entries, err := os.ReadDir(h.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// mustRefuse asserts a Failed reply naming want, with no exec, no Installing
// phase and nothing left in the staging root.
func (h *updateHarness) mustRefuse(resp wire.Response, want string) {
	h.t.Helper()
	if resp.OK || resp.Phase != wire.UpdatePhaseFailed || !strings.Contains(resp.Error, want) {
		h.t.Fatalf("resp = %+v, want Failed containing %q", resp, want)
	}
	if h.inst.calls != 0 {
		h.t.Fatalf("the installer ran %d times on a refused update", h.inst.calls)
	}
	if slices.Contains(h.phases, wire.UpdatePhaseInstalling) {
		h.t.Fatalf("phases = %v: Installing reported on a refused update", h.phases)
	}
	if left := h.stagingLeftovers(); len(left) != 0 {
		h.t.Fatalf("a refused update left %v in the staging root", left)
	}
}

// serveOne serves one connection with handleConn, writes payload as one frame,
// and reads frames until a terminal one (a reply with no phase is terminal).
func (h *updateHarness) serveOne(t *testing.T, payload []byte) ([]wire.Response, error) {
	t.Helper()
	client, server := socketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.s.handleConn(ctx, server)
	}()
	defer func() {
		_ = client.Close()
		<-done
	}()
	go func() { _ = wire.WriteFrame(client, payload) }()
	var out []wire.Response
	for {
		b, err := wire.ReadFrame(client, wire.DefaultMaxRequestBytes)
		if err != nil {
			return out, err
		}
		var resp wire.Response
		if err := json.Unmarshal(b, &resp); err != nil {
			return out, err
		}
		out = append(out, resp)
		if resp.Phase == "" || resp.Phase.Terminal() {
			return out, nil
		}
		if resp.Phase == wire.UpdatePhaseInstalling {
			// The acknowledgement the client sends after Installing.
			if err := wire.WriteFrame(client, helloFrame(t)); err != nil {
				return out, err
			}
		}
	}
}

// helloFrame is a Hello request, the acknowledgement a client sends after the
// Installing frame.
func helloFrame(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbHello})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func selfUID() uint32 { return uint32(os.Getuid()) }

// withMember returns members with the named one replaced (or appended when
// absent); a zero replacement drops it.
func withMember(members []tarMember, name string, m *tarMember) []tarMember {
	out := make([]tarMember, 0, len(members)+1)
	found := false
	for _, x := range members {
		if x.name == name {
			found = true
			if m != nil {
				out = append(out, *m)
			}
			continue
		}
		out = append(out, x)
	}
	if !found && m != nil {
		out = append(out, *m)
	}
	return out
}

// TestApplyUpdateVerifiesBeforeInstall is the root-helper gate: root
// verifies the signer certificate against the cluster CA, the signature over
// the payload, the archive digest, the extracted set, the code signatures and
// the downgrade rule, each before the next step and all before the one exec;
// the exec sees the staged path and the payload's flags; the phases arrive in
// order, also through a real frame on a socket.
func TestApplyUpdateVerifiesBeforeInstall(t *testing.T) {
	t.Run("installs a verified release with the staged path", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "if-signed", false))
		if !resp.OK || resp.Phase != wire.UpdatePhaseDone {
			t.Fatalf("resp = %+v, want OK Done", resp)
		}
		want := []wire.UpdatePhase{wire.UpdatePhaseVerifying, wire.UpdatePhaseInstalling, wire.UpdatePhaseDone}
		if !slices.Equal(h.phases, want) {
			t.Fatalf("phases = %v, want %v", h.phases, want)
		}
		if h.inst.calls != 1 {
			t.Fatalf("installer ran %d times, want 1", h.inst.calls)
		}
		dir := h.inst.dir
		if filepath.Dir(dir) != h.root || !strings.HasPrefix(filepath.Base(dir), updateDirPrefix) {
			t.Fatalf("staging dir %s is not a fresh directory directly under %s", dir, h.root)
		}
		wantArgv := []string{filepath.Join(dir, "k3sm"), "install", "--from-staging", dir}
		if !slices.Equal(h.inst.argv, wantArgv) {
			t.Fatalf("argv = %q, want %q", h.inst.argv, wantArgv)
		}
		wantTop := []string{"cp-payload", updateLogName, "k3sm", "k3sm-execshim", "k3sm-vmhost",
			"libk3sm_getaddrinfo_shim.dylib", "libk3sm_pathrebase_shim.dylib"}
		if !slices.Equal(h.inst.topLevel, wantTop) {
			t.Fatalf("staging dir at exec time = %v, want the set and the log only %v", h.inst.topLevel, wantTop)
		}
		for _, m := range releaseMembers("ADHOC") {
			if m.typeflag == tar.TypeDir || slices.Contains(updateSkippedFiles, m.name) {
				continue
			}
			if h.inst.staged[m.name] != m.body {
				t.Errorf("staged %s = %q at exec time, want %q", m.name, h.inst.staged[m.name], m.body)
			}
		}
		if len(h.inst.staged) != 8 {
			t.Errorf("staged files = %d (%v), want the eight set files", len(h.inst.staged), h.inst.staged)
		}
		if h.probes != 1 {
			t.Errorf("installed version probed %d times, want 1", h.probes)
		}
		if left := h.stagingLeftovers(); len(left) != 0 {
			t.Fatalf("staging root still holds %v after the install returned", left)
		}
		fi, err := os.Stat(h.root)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("staging root %v err %v, want mode 0700", fi.Mode(), err)
		}
	})

	t.Run("logs each check at Info, in order, on a successful apply", func(t *testing.T) {
		var buf bytes.Buffer
		h := newUpdateHarness(t, selfUID(), func(c *Config) {
			c.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		})
		members := withMember(releaseMembers("TEAM:ABCDE12345"), "cp-payload/zot.version", &tarMember{name: "cp-payload/zot.version", body: "v2.1.20 minimal\n", mode: 0o644})
		args := h.request(members, "v0.2.0", "", false)
		resp := h.apply(args)
		if !resp.OK || resp.Phase != wire.UpdatePhaseDone {
			t.Fatalf("resp = %+v, want OK Done", resp)
		}
		var payload struct {
			SHA256 string `json:"sha256"`
		}
		if err := json.Unmarshal(args.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		var lines []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("log line %q: %v", l, err)
			}
			if m["level"] == "INFO" {
				lines = append(lines, m)
			}
		}
		want := []struct {
			msg   string
			attrs map[string]any
		}{
			{"netd: update signer accepted", map[string]any{"cn": wire.UpdateSignerCommonName}},
			{"netd: update payload signature verified", nil},
			{"netd: update archive digest matched", map[string]any{"sha256": payload.SHA256, "version": "v0.2.0"}},
			{"netd: update set extracted", map[string]any{"members": float64(9), "macho": float64(7), "markers-skipped": float64(2)}},
			{"netd: update code signing accepted", map[string]any{"signer": "team ABCDE12345", "policy": "if-signed"}},
			{"netd: update version compare passed", map[string]any{"installed": "v0.1.9"}},
			{"netd: running the staged installer", nil},
			{"netd: the staged installer finished", nil},
		}
		i := 0
		for _, l := range lines {
			if i < len(want) && l["msg"] == want[i].msg {
				for k, v := range want[i].attrs {
					if l[k] != v {
						t.Errorf("%q: %s = %v, want %v", want[i].msg, k, l[k], v)
					}
				}
				i++
			}
		}
		if i != len(want) {
			t.Fatalf("Info lines %v: missing %q (or out of order)", lines, want[i].msg)
		}
		for _, l := range lines {
			switch l["msg"] {
			case "netd: update signer accepted":
				if l["serial"] == "" || l["serial"] == nil || l["not-after"] == nil {
					t.Errorf("signer line %v lacks the serial or not-after", l)
				}
			case "netd: update set extracted":
				if got := fmt.Sprint(l["markers"]); got != "[cp-payload/kube.version cp-payload/zot.version]" {
					t.Errorf("markers = %s", got)
				}
			case "netd: running the staged installer":
				if got, want := fmt.Sprint(l["argv"]), fmt.Sprint(h.inst.argv); got != want {
					t.Errorf("argv logged %s, ran %s", got, want)
				}
			}
		}
	})

	t.Run("passes --allow-downgrade when the payload allows it and installs below the installed tag", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		h.version = "v0.3.0"
		resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", true))
		if !resp.OK {
			t.Fatalf("resp = %+v", resp)
		}
		if want := []string{filepath.Join(h.inst.dir, "k3sm"), "install", "--from-staging", h.inst.dir, "--allow-downgrade"}; !slices.Equal(h.inst.argv, want) {
			t.Fatalf("argv = %q, want %q", h.inst.argv, want)
		}
		if h.probes != 0 {
			t.Fatalf("installed version probed %d times; an allowed downgrade needs no probe", h.probes)
		}
	})

	t.Run("refuses a signer outside the cluster CA before any read of the archive", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		otherKey, otherCA, _ := newCA(t, "k3sm-cluster-ca")
		key := newKey(t)
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		args.SignerCert = leaf(t, otherKey, otherCA, &key.PublicKey, signerSubject, time.Now().Add(time.Hour))
		args.Signature = sign(t, key, args.Payload)
		args.ArchivePath = filepath.Join(t.TempDir(), "absent.tar.gz") // a read would fail differently
		h.mustRefuse(h.apply(args), "does not chain to the cluster CA")
		if _, err := os.Lstat(h.root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the staging root exists (%v): the refusal came after the archive step", err)
		}
	})

	t.Run("refuses a self-signed signer that names the signer subject", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		key := newKey(t)
		tmpl := &x509.Certificate{SerialNumber: nextSerial(), Subject: signerSubject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		args.SignerCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		args.Signature = sign(t, key, args.Payload)
		h.mustRefuse(h.apply(args), "does not chain to the cluster CA")
	})

	subjects := []struct {
		name string
		subj pkix.Name
	}{
		{"a wrong CN", pkix.Name{CommonName: "system:node:worker", Organization: []string{wire.UpdateSignerOrganization}}},
		{"a wrong O", pkix.Name{CommonName: wire.UpdateSignerCommonName, Organization: []string{"system:nodes"}}},
	}
	for _, tc := range subjects {
		t.Run("refuses a valid chain with "+tc.name, func(t *testing.T) {
			h := newUpdateHarness(t, selfUID())
			key := newKey(t)
			args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
			args.SignerCert = leaf(t, h.pki.caKey, h.pki.caCert, &key.PublicKey, tc.subj, time.Now().Add(time.Hour))
			args.Signature = sign(t, key, args.Payload)
			h.mustRefuse(h.apply(args), "the signer certificate names")
		})
	}

	ekus := []struct {
		name string
		eku  []x509.ExtKeyUsage
		want string
	}{
		{"only the client auth EKU", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "does not chain to the cluster CA"},
		{"no EKU at all", nil, "does not carry the Code Signing extended key usage"},
	}
	for _, tc := range ekus {
		t.Run("refuses a valid chain with the signer CN and O but "+tc.name, func(t *testing.T) {
			h := newUpdateHarness(t, selfUID())
			key := newKey(t)
			args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
			args.SignerCert = leafEKU(t, h.pki.caKey, h.pki.caCert, &key.PublicKey, signerSubject, time.Now().Add(time.Hour), tc.eku)
			args.Signature = sign(t, key, args.Payload)
			h.mustRefuse(h.apply(args), tc.want)
		})
	}

	t.Run("refuses an expired signer", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		h.s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
		h.mustRefuse(h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)), "does not chain to the cluster CA")
	})

	t.Run("refuses every update when no cluster CA is configured", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID(), func(c *Config) { c.ClusterCAPath = "" })
		h.mustRefuse(h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)), "started without --cluster-ca")
	})

	t.Run("re-reads an absent cluster CA lazily: refuses while absent, admits once it appears", func(t *testing.T) {
		caPath := filepath.Join(t.TempDir(), "pki", "cluster-ca.crt")
		h := newUpdateHarness(t, selfUID(), func(c *Config) { c.ClusterCAPath = caPath })
		h.mustRefuse(h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)), "no such file or directory")
		h.mustRefuse(h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)), "no cluster CA is configured")
		if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(caPath, h.pki.caPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		h.phases = nil
		resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false))
		if !resp.OK || resp.Phase != wire.UpdatePhaseDone || h.inst.calls != 1 {
			t.Fatalf("resp = %+v calls %d, want an install once the CA file exists", resp, h.inst.calls)
		}
		// A loaded CA is kept: removing the file does not unload it.
		if err := os.Remove(caPath); err != nil {
			t.Fatal(err)
		}
		if resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)); !resp.OK {
			t.Fatalf("resp = %+v, want the loaded CA kept", resp)
		}
	})

	t.Run("refuses every update when the cluster CA file holds no CA", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		h := newUpdateHarness(t, selfUID(), func(c *Config) { c.ClusterCAPath = bad })
		h.mustRefuse(h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)), "holds no PEM certificate")
	})

	t.Run("fails the signature on a tampered payload byte", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		args.Payload = bytes.Replace(args.Payload, []byte(`"allowDowngrade":false`), []byte(`"allowDowngrade":true `), 1)
		h.mustRefuse(h.apply(args), "the payload signature does not verify")
	})

	t.Run("fails a signature made by another key", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		args.Signature = sign(t, newKey(t), args.Payload)
		h.mustRefuse(h.apply(args), "the payload signature does not verify")
	})

	payloads := []struct {
		name, payload, want string
	}{
		{"a version outside the tag grammar", `{"version":"v0.2.0;rm","url":"","sha256":"` + strings.Repeat("a", 64) + `","signature":""}`, "not a release tag"},
		{"a version without the v", `{"version":"0.2.0","url":"","sha256":"` + strings.Repeat("a", 64) + `","signature":""}`, "not a release tag"},
		{"an unknown field", `{"version":"v0.2.0","url":"","sha256":"` + strings.Repeat("a", 64) + `","signature":"","sourceDir":"/"}`, "not valid JSON"},
		{"an unknown policy", `{"version":"v0.2.0","url":"","sha256":"` + strings.Repeat("a", 64) + `","signature":"never"}`, "unknown signature policy"},
		{"an uppercase digest", `{"version":"v0.2.0","url":"","sha256":"` + strings.Repeat("A", 64) + `","signature":""}`, "lowercase hex"},
	}
	for _, tc := range payloads {
		t.Run("refuses a signed payload with "+tc.name, func(t *testing.T) {
			h := newUpdateHarness(t, selfUID())
			args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
			args.Payload = []byte(tc.payload)
			args.Signature = sign(t, h.pki.signerKey, args.Payload)
			h.mustRefuse(h.apply(args), tc.want)
		})
	}

	t.Run("fails a digest mismatch before extraction", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		if err := os.WriteFile(args.ArchivePath, buildArchive(t, releaseMembers("TEAM:EVIL000000")), 0o644); err != nil {
			t.Fatal(err)
		}
		h.mustRefuse(h.apply(args), "the signed payload says")
		if h.insp.calls() != 0 {
			t.Fatalf("code signatures were inspected %d times: the extraction ran", h.insp.calls())
		}
	})

	t.Run("refuses an archive path that is a symlink", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		link := filepath.Join(t.TempDir(), "link.tar.gz")
		if err := os.Symlink(args.ArchivePath, link); err != nil {
			t.Fatal(err)
		}
		args.ArchivePath = link
		h.mustRefuse(h.apply(args), "open the archive")
	})

	t.Run("refuses an archive path that is not clean", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		args.ArchivePath = filepath.Dir(args.ArchivePath) + "/./" + filepath.Base(args.ArchivePath)
		h.mustRefuse(h.apply(args), "not a clean absolute path")
	})

	sym := tarMember{name: "cp-payload/kine", typeflag: tar.TypeSymlink, linkname: "/bin/sh", mode: 0o777}
	hard := tarMember{name: "k3sm-vmhost", typeflag: tar.TypeLink, linkname: "k3sm"}
	members := []struct {
		name    string
		members []tarMember
		want    string
	}{
		{"a symlink member", withMember(releaseMembers("ADHOC"), "cp-payload/kine", &sym), "is a link"},
		{"a hard link member", withMember(releaseMembers("ADHOC"), "k3sm-vmhost", &hard), "is a link"},
		{"an unlisted member", withMember(releaseMembers("ADHOC"), "evil", &tarMember{name: "evil", body: "x", mode: 0o755}), "not in the build set"},
		{"an unlisted directory", withMember(releaseMembers("ADHOC"), "bin/", &tarMember{name: "bin/", typeflag: tar.TypeDir, mode: 0o755}), "not in the build set"},
		{"an absolute member", withMember(releaseMembers("ADHOC"), "/k3sm", &tarMember{name: "/k3sm", body: "x", mode: 0o755}), "not a clean relative path"},
		{"a climbing member", withMember(releaseMembers("ADHOC"), "cp-payload/../../k3sm", &tarMember{name: "cp-payload/../../k3sm", body: "x", mode: 0o755}), "not a clean relative path"},
		{"a missing binary", withMember(releaseMembers("ADHOC"), "k3sm-vmhost", nil), "does not carry k3sm-vmhost"},
		{"a duplicate member", append(releaseMembers("ADHOC"), tarMember{name: "k3sm", body: machO + "again\nADHOC", mode: 0o755}), "names k3sm twice"},
		{"a fifo member", withMember(releaseMembers("ADHOC"), "cp-payload/fifo", &tarMember{name: "cp-payload/fifo", typeflag: tar.TypeFifo}), "not a regular file"},
		{"a skipped member over 2 GiB", append([]tarMember{{name: "LICENSE", mode: 0o644, size: wire.MaxUpdateSetBytes + 1}}, releaseMembers("ADHOC")...), "unpacks to more than"},
	}
	for _, tc := range members {
		t.Run("refuses "+tc.name+" before the exec", func(t *testing.T) {
			h := newUpdateHarness(t, selfUID())
			h.mustRefuse(h.apply(h.request(tc.members, "v0.2.0", "", false)), tc.want)
		})
	}

	team := func(id string) []tarMember { return releaseMembers("TEAM:" + id) }
	mixed := withMember(releaseMembers("ADHOC"), "k3sm-vmhost", &tarMember{name: "k3sm-vmhost", body: machO + "vmhost\nTEAM:ABCDE12345", mode: 0o755})
	signing := []struct {
		name      string
		installed string
		members   []tarMember
		policy    string
		want      string // "" accepts
	}{
		{"a foreign team on a team-signed install", "TEAM:ABCDE12345", team("ZZZZZ99999"), "", "signed by team ABCDE12345 and the staged"},
		{"an ad-hoc tree on a team-signed install", "TEAM:ABCDE12345", releaseMembers("ADHOC"), "", "signed by team ABCDE12345 and the staged"},
		{"a mixed tree on an ad-hoc install", "ADHOC", mixed, "", "mixes signers"},
		{"an ad-hoc tree under signature: required", "ADHOC", releaseMembers("ADHOC"), "required", "requires a team signature"},
		{"an invalidly signed staged Mach-O", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/kine", &tarMember{name: "cp-payload/kine", body: machO + "kine\nBROKEN", mode: 0o755}), "", "is not validly signed"},
		{"an installed k3sm whose signature does not verify", "BROKEN", releaseMembers("ADHOC"), "", "installed k3sm's code signature does not verify"},
		{"a staged k3sm that is not a Mach-O", "ADHOC", withMember(releaseMembers("ADHOC"), "k3sm", &tarMember{name: "k3sm", body: "#!/bin/sh\nADHOC", mode: 0o755}), "", "not a Mach-O"},
		{"the installed team on a team-signed install", "TEAM:ABCDE12345", team("ABCDE12345"), "required", ""},
		{"a team string without the Developer ID requirement under signature: required", "ADHOC", releaseMembers("NODEVID:ABCDE12345"), "required", "requires a team signature"},
		{"a team string without the Developer ID requirement on a team-signed install", "TEAM:ABCDE12345", releaseMembers("NODEVID:ABCDE12345"), "", "signed by team ABCDE12345 and the staged"},
		{"a non-Mach-O k3sm-execshim", "ADHOC", withMember(releaseMembers("ADHOC"), "k3sm-execshim", &tarMember{name: "k3sm-execshim", body: "#!/bin/sh\nADHOC", mode: 0o755}), "", "the staged k3sm-execshim is not a Mach-O"},
		{"a non-Mach-O dylib", "ADHOC", withMember(releaseMembers("ADHOC"), "libk3sm_getaddrinfo_shim.dylib", &tarMember{name: "libk3sm_getaddrinfo_shim.dylib", body: "text\nADHOC", mode: 0o644}), "", "the staged libk3sm_getaddrinfo_shim.dylib is not a Mach-O"},
		{"a non-Mach-O cp-payload executable", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/kine", &tarMember{name: "cp-payload/kine", body: "#!/bin/sh\nADHOC", mode: 0o755}), "", "the staged cp-payload/kine is not a Mach-O"},
		{"a non-Mach-O file named like a marker below cp-payload/bin", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/bin/kube.version", &tarMember{name: "cp-payload/bin/kube.version", body: "v1\n", mode: 0o644}), "", "the staged cp-payload/bin/kube.version is not a Mach-O"},
		{"a cp-payload marker that is an invalidly signed Mach-O", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/kube.version", &tarMember{name: "cp-payload/kube.version", body: machO + "marker\nBROKEN", mode: 0o644}), "", "the staged cp-payload/kube.version is not validly signed"},
		{"a cp-payload/zot.version text marker is skipped", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/zot.version", &tarMember{name: "cp-payload/zot.version", body: "v2.1.20 minimal\n", mode: 0o644}), "", ""},
		{"a cp-payload/other.version text marker is skipped", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/other.version", &tarMember{name: "cp-payload/other.version", body: "v0.0.1\n", mode: 0o644}), "", ""},
		{"a cp-payload .version file of 4 KiB", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/zot.version", &tarMember{name: "cp-payload/zot.version", body: strings.Repeat("v", 4<<10), mode: 0o644}), "", "the staged cp-payload/zot.version is not a Mach-O"},
		{"a cp-payload .version file with a non-printable byte", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/zot.version", &tarMember{name: "cp-payload/zot.version", body: "v2.1.20\x01\n", mode: 0o644}), "", "the staged cp-payload/zot.version is not a Mach-O"},
		{"a non-Mach-O cp-payload/bin/x.version", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/bin/x.version", &tarMember{name: "cp-payload/bin/x.version", body: "v1\n", mode: 0o644}), "", "the staged cp-payload/bin/x.version is not a Mach-O"},
		{"a validly signed .version Mach-O is checked and accepted", "ADHOC", withMember(releaseMembers("ADHOC"), "cp-payload/zot.version", &tarMember{name: "cp-payload/zot.version", body: machO + "marker\nADHOC", mode: 0o644}), "", ""},
		{"a FAT64 universal k3sm-vmhost", "ADHOC", withMember(releaseMembers("ADHOC"), "k3sm-vmhost", &tarMember{name: "k3sm-vmhost", body: "\xca\xfe\xba\xbfvmhost\nADHOC", mode: 0o755}), "", ""},
		{"a byte-swapped FAT64 universal k3sm", "ADHOC", withMember(releaseMembers("ADHOC"), "k3sm", &tarMember{name: "k3sm", body: "\xbf\xba\xfe\xcak3sm\nADHOC", mode: 0o755}), "", ""},
		{"one team on an ad-hoc install", "ADHOC", team("ABCDE12345"), "", ""},
	}
	for _, tc := range signing {
		t.Run("code signing: "+tc.name, func(t *testing.T) {
			h := newUpdateHarness(t, selfUID())
			h.setInstalled(tc.installed)
			resp := h.apply(h.request(tc.members, "v0.2.0", tc.policy, false))
			if tc.want == "" {
				if !resp.OK || h.inst.calls != 1 {
					t.Fatalf("resp = %+v calls %d, want an install", resp, h.inst.calls)
				}
				return
			}
			h.mustRefuse(resp, tc.want)
		})
	}

	versions := []struct {
		name, installed, version, want string
	}{
		{"refuses a downgrade without the flag", "v0.2.1", "v0.2.0", "below the installed v0.2.1"},
		{"refuses a prerelease of the installed tag", "v0.2.0", "v0.2.0-rc.1", "below the installed v0.2.0"},
		{"refuses an installed dev build without the flag", "dev", "v0.2.0", "cannot be ordered"},
		{"accepts a reinstall of the installed tag", "v0.2.0", "v0.2.0", ""},
		{"accepts an upgrade past a prerelease", "v0.2.0-rc.2", "v0.2.0", ""},
	}
	for _, tc := range versions {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpdateHarness(t, selfUID())
			h.version = tc.installed
			resp := h.apply(h.request(releaseMembers("ADHOC"), tc.version, "", false))
			if tc.want == "" {
				if !resp.OK {
					t.Fatalf("resp = %+v, want an install", resp)
				}
				return
			}
			h.mustRefuse(resp, tc.want)
		})
	}

	t.Run("refuses a caller that is not the service uid", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID()+1)
		resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false))
		if resp.OK || resp.Phase != wire.UpdatePhaseFailed || !strings.Contains(resp.Error, ErrPeerUnauthorized.Error()) {
			t.Fatalf("resp = %+v, want a Failed peer refusal", resp)
		}
		if !slices.Equal(h.phases, []wire.UpdatePhase{wire.UpdatePhaseFailed}) || h.inst.calls != 0 {
			t.Fatalf("phases = %v, installer calls = %d: a foreign caller got past the check", h.phases, h.inst.calls)
		}
	})

	t.Run("refuses a request with no connection to check", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		resp := h.s.handleApplyUpdate(context.Background(), newConnState(1), h.request(releaseMembers("ADHOC"), "v0.2.0", "", false))
		if resp.OK || h.inst.calls != 0 {
			t.Fatalf("resp = %+v, calls = %d", resp, h.inst.calls)
		}
	})

	t.Run("reports Failed with the installer's last lines", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		h.inst.err = errors.New("exit status 1")
		var lines strings.Builder
		for i := range 60 {
			fmt.Fprintf(&lines, "line %d\n", i)
		}
		h.inst.logLines = lines.String()
		resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "", false))
		want := []wire.UpdatePhase{wire.UpdatePhaseVerifying, wire.UpdatePhaseInstalling, wire.UpdatePhaseFailed}
		if resp.OK || !slices.Equal(h.phases, want) {
			t.Fatalf("resp = %+v phases = %v, want %v", resp, h.phases, want)
		}
		got := strings.Split(resp.Log, "\n")
		if len(got) != updateLogTailLines || got[0] != "line 20" || got[len(got)-1] != "line 59" {
			t.Fatalf("log tail = %q, want lines 20..59", resp.Log)
		}
	})

	t.Run("works through a real frame on a socket", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		raw, err := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbApplyUpdate,
			ApplyUpdate: h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)})
		if err != nil {
			t.Fatal(err)
		}
		frames, err := h.serveOne(t, raw)
		if err != nil {
			t.Fatalf("frames %+v: %v", frames, err)
		}
		var got []wire.UpdatePhase
		for _, f := range frames {
			got = append(got, f.Phase)
		}
		want := []wire.UpdatePhase{wire.UpdatePhaseVerifying, wire.UpdatePhaseInstalling, wire.UpdatePhaseDone}
		if !slices.Equal(got, want) || !frames[len(frames)-1].OK {
			t.Fatalf("frames = %+v, want %v", frames, want)
		}
		if h.inst.calls != 1 || h.inst.argv[0] != filepath.Join(h.inst.dir, "k3sm") {
			t.Fatalf("installer calls %d argv %q", h.inst.calls, h.inst.argv)
		}
	})

	t.Run("keeps the 64 KiB cap for other verbs and closes a frame over 256 KiB", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		pad := strings.Repeat("x", wire.DefaultMaxRequestBytes)
		other := []byte(fmt.Sprintf(`{"version":{"major":1,"minor":4},"verb":"EnsureAlias","ensureAlias":{"ip":"100.64.0.5"},"pad":%q}`, pad))
		frames, err := h.serveOne(t, other)
		if err != nil || len(frames) != 1 || frames[0].OK || !strings.Contains(frames[0].Error, "exceeds the 65536-byte cap") {
			t.Fatalf("frames = %+v err = %v, want an EnsureAlias over 64 KiB refused", frames, err)
		}
		args := h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)
		args.SignerCert = bytes.Repeat([]byte("y"), wire.MaxApplyUpdateRequestBytes)
		huge, _ := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbApplyUpdate, ApplyUpdate: args})
		if _, err := h.serveOne(t, huge); err == nil {
			t.Fatal("a frame over 256 KiB was answered, want the connection closed")
		}
		if h.inst.calls != 0 {
			t.Fatalf("the installer ran %d times", h.inst.calls)
		}
	})
}

// syncBuffer is a bytes.Buffer safe for a logger writing from the handler's
// goroutine while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestUpdateHelperWaitsForTheRestartingAck is the gate: after the
// Installing frame and before the exec, the helper waits for the client's
// acknowledgement (a Hello request on the same connection), bounded by
// updateAckTimeout. The exec follows the ack when it arrives, follows the
// bound when it does not (with one log line saying the ack did not arrive),
// and follows at once when the client is gone; Installing is always sent
// before the wait.
func TestUpdateHelperWaitsForTheRestartingAck(t *testing.T) {
	const ackDelay = 300 * time.Millisecond
	cases := []struct {
		name string
		// client acts after the Installing frame arrived and returns when it
		// acted, or the zero time when it did nothing.
		client      func(t *testing.T, c *net.UnixConn) time.Time
		wantWaitMin time.Duration // exec at least this long after Installing
		wantWaitMax time.Duration // and at most this long
		wantLog     bool
	}{
		{
			name: "the ack arrives: the exec follows it",
			client: func(t *testing.T, c *net.UnixConn) time.Time {
				time.Sleep(ackDelay)
				sent := time.Now()
				if err := wire.WriteFrame(c, helloFrame(t)); err != nil {
					t.Errorf("send the ack: %v", err)
				}
				return sent
			},
			wantWaitMin: ackDelay,
			wantWaitMax: updateAckTimeout - time.Second,
		},
		{
			name:        "no ack: the exec follows the bound and one line is logged",
			client:      func(*testing.T, *net.UnixConn) time.Time { return time.Time{} },
			wantWaitMin: updateAckTimeout - 100*time.Millisecond,
			wantWaitMax: updateAckTimeout + 2*time.Second,
			wantLog:     true,
		},
		{
			name: "the client is gone: the exec does not wait out the bound",
			client: func(t *testing.T, c *net.UnixConn) time.Time {
				_ = c.CloseWrite()
				return time.Time{}
			},
			wantWaitMax: updateAckTimeout - time.Second,
			wantLog:     true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &syncBuffer{}
			h := newUpdateHarness(t, selfUID(), func(c *Config) {
				c.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			})
			execAt := make(chan time.Time, 1)
			h.s.runInstaller = func(ctx context.Context, r installerRun) error {
				execAt <- time.Now()
				return h.inst.run(ctx, r)
			}
			raw, err := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbApplyUpdate,
				ApplyUpdate: h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)})
			if err != nil {
				t.Fatal(err)
			}
			client, server := socketPair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				h.s.handleConn(context.Background(), server)
			}()
			defer func() {
				_ = client.Close()
				<-done
			}()
			if err := wire.WriteFrame(client, raw); err != nil {
				t.Fatal(err)
			}
			var phases []wire.UpdatePhase
			var installingAt time.Time
			for installingAt.IsZero() {
				b, err := wire.ReadFrame(client, wire.DefaultMaxRequestBytes)
				if err != nil {
					t.Fatalf("read a frame after %v: %v", phases, err)
				}
				var resp wire.Response
				if err := json.Unmarshal(b, &resp); err != nil {
					t.Fatal(err)
				}
				phases = append(phases, resp.Phase)
				switch resp.Phase {
				case wire.UpdatePhaseInstalling:
					installingAt = time.Now()
				case wire.UpdatePhaseVerifying:
				default:
					t.Fatalf("phases = %v before Installing", phases)
				}
			}
			select {
			case at := <-execAt:
				t.Fatalf("the installer ran %v before Installing reached the client", installingAt.Sub(at))
			default:
			}
			acked := tc.client(t, client)
			var at time.Time
			select {
			case at = <-execAt:
			case <-time.After(updateAckTimeout + 5*time.Second):
				t.Fatal("the installer never ran")
			}
			if !acked.IsZero() && at.Before(acked) {
				t.Fatalf("the installer ran %v before the ack was sent", acked.Sub(at))
			}
			if waited := at.Sub(installingAt); waited < tc.wantWaitMin || waited > tc.wantWaitMax {
				t.Fatalf("the installer ran %v after Installing, want %v..%v", waited, tc.wantWaitMin, tc.wantWaitMax)
			}
			b, err := wire.ReadFrame(client, wire.DefaultMaxRequestBytes)
			if err != nil {
				t.Fatalf("read the final frame: %v", err)
			}
			var final wire.Response
			if err := json.Unmarshal(b, &final); err != nil || !final.OK || final.Phase != wire.UpdatePhaseDone {
				t.Fatalf("final frame %s err %v, want OK Done", b, err)
			}
			_ = client.Close()
			<-done
			if n := strings.Count(logs.String(), "netd: the client did not acknowledge Installing"); (n == 1) != tc.wantLog || n > 1 {
				t.Fatalf("the missing-ack line was logged %d times, want it %t once:\n%s", n, tc.wantLog, logs.String())
			}
			if h.inst.calls != 1 {
				t.Fatalf("the installer ran %d times, want 1", h.inst.calls)
			}
		})
	}

	t.Run("a daemon stop during the wait: no exec, a Failed frame", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		waited := false
		h.st.awaitAck = func(d time.Duration) error {
			if d != updateAckTimeout {
				t.Errorf("ack bound %v, want %v", d, updateAckTimeout)
			}
			waited = slices.Contains(h.phases, wire.UpdatePhaseInstalling)
			cancel()
			return context.Canceled
		}
		resp := h.s.handleApplyUpdate(ctx, h.st, h.request(releaseMembers("ADHOC"), "v0.2.0", "", false))
		if !waited {
			t.Fatal("the wait ran before Installing was sent")
		}
		if resp.OK || resp.Phase != wire.UpdatePhaseFailed || !strings.Contains(resp.Error, "the helper is stopping") {
			t.Fatalf("resp = %+v, want Failed naming the stop", resp)
		}
		if h.inst.calls != 0 {
			t.Fatalf("the installer ran %d times after the stop", h.inst.calls)
		}
		if left := h.stagingLeftovers(); len(left) != 0 {
			t.Fatalf("the stopped update left %v in the staging root", left)
		}
	})

	t.Run("a frame other than Hello is dropped, not dispatched or answered", func(t *testing.T) {
		logs := &syncBuffer{}
		priv := &recordingPriv{}
		h := newUpdateHarness(t, selfUID(), func(c *Config) {
			c.Privileged = priv
			c.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		})
		raw, err := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbApplyUpdate,
			ApplyUpdate: h.request(releaseMembers("ADHOC"), "v0.2.0", "", false)})
		if err != nil {
			t.Fatal(err)
		}
		notAck, err := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbRemoveMesh})
		if err != nil {
			t.Fatal(err)
		}
		client, server := socketPair(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.s.handleConn(context.Background(), server)
		}()
		defer func() {
			_ = client.Close()
			<-done
		}()
		if err := wire.WriteFrame(client, raw); err != nil {
			t.Fatal(err)
		}
		var phases []wire.UpdatePhase
		for {
			b, err := wire.ReadFrame(client, wire.DefaultMaxRequestBytes)
			if err != nil {
				t.Fatalf("read a frame after %v: %v", phases, err)
			}
			var resp wire.Response
			if err := json.Unmarshal(b, &resp); err != nil {
				t.Fatal(err)
			}
			phases = append(phases, resp.Phase)
			if resp.Phase == wire.UpdatePhaseInstalling {
				if err := wire.WriteFrame(client, notAck); err != nil {
					t.Fatal(err)
				}
			}
			if resp.Phase == "" || resp.Phase.Terminal() {
				break
			}
		}
		want := []wire.UpdatePhase{wire.UpdatePhaseVerifying, wire.UpdatePhaseInstalling, wire.UpdatePhaseDone}
		if !slices.Equal(phases, want) {
			t.Fatalf("phases = %v, want %v", phases, want)
		}
		if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if b, err := wire.ReadFrame(client, wire.DefaultMaxRequestBytes); err == nil {
			t.Fatalf("the dropped frame was answered: %s", b)
		}
		_ = client.Close()
		<-done
		if priv.served {
			t.Fatal("the frame read as the ack was dispatched (RemoveMesh reached the privileged backend)")
		}
		if h.inst.calls != 1 {
			t.Fatalf("the installer ran %d times, want 1", h.inst.calls)
		}
		if n := strings.Count(logs.String(), "netd: the client did not acknowledge Installing"); n != 1 {
			t.Fatalf("the missing-ack line was logged %d times, want once:\n%s", n, logs.String())
		}
	})
}

// TestReadUpdateAckCapsTheVerb pins that a peer-chosen verb reaches the
// missing-ack log line at most maxAckVerbLog bytes long.
func TestReadUpdateAckCapsTheVerb(t *testing.T) {
	h := newUpdateHarness(t, selfUID())
	client, server := socketPair(t)
	long := strings.Repeat("v", 4096)
	go func() {
		_ = wire.WriteFrame(client, []byte(fmt.Sprintf(`{"version":{"major":1,"minor":4},"verb":%q}`, long)))
	}()
	err := h.s.readUpdateAck(server, time.Second)
	if !errors.Is(err, errNotUpdateAck) {
		t.Fatalf("err = %v, want errNotUpdateAck", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("v", maxAckVerbLog+1)) || !strings.Contains(err.Error(), strings.Repeat("v", maxAckVerbLog)+"...") {
		t.Fatalf("err = %.200s..., want the verb capped at %d bytes", err, maxAckVerbLog)
	}
}

// TestOpenUpdateArchive pins the archive open: a file the service uid does not
// own, a directory, and an archive over the size cap are refused.
func TestOpenUpdateArchive(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err := openUpdateArchive(p, selfUID()); err != nil {
		t.Fatalf("open own archive: %v", err)
	} else {
		_ = f.Close()
	}
	if _, err := openUpdateArchive(p, selfUID()+1); err == nil || !strings.Contains(err.Error(), "not the service uid") {
		t.Fatalf("foreign owner: err = %v", err)
	}
	if _, err := openUpdateArchive(dir, selfUID()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: err = %v", err)
	}
	big := filepath.Join(dir, "big.tar.gz")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(wire.MaxUpdateArchiveBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := openUpdateArchive(big, selfUID()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversize: err = %v", err)
	}
}

// TestCompareReleases pins the semver ordering the downgrade rule uses.
func TestCompareReleases(t *testing.T) {
	cases := []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"v0.2.0", "v0.2.0", 0, true},
		{"v0.2.0", "v0.10.0", -1, true},
		{"v1.0.0", "v0.99.99", 1, true},
		{"v0.2.0-rc.1", "v0.2.0", -1, true},
		{"v0.2.0-rc.2", "v0.2.0-rc.10", -1, true},
		{"v0.2.0-alpha", "v0.2.0-1", 1, true},
		{"v0.2.0", "dev", 0, false},
		{"v0.2.0", "v0.2.1-0.20261015120000-0123456789ab", 0, false},
	}
	for _, tc := range cases {
		if cmp, ok := compareReleases(tc.a, tc.b); cmp != tc.cmp || ok != tc.ok {
			t.Errorf("compareReleases(%q, %q) = %d, %t; want %d, %t", tc.a, tc.b, cmp, ok, tc.cmp, tc.ok)
		}
	}
	if v, err := parseVersionOutput("k3sm v0.2.0\n  commit: abc\n"); err != nil || v != "v0.2.0" {
		t.Errorf("parseVersionOutput = %q, %v", v, err)
	}
	if _, err := parseVersionOutput("something else\n"); err == nil {
		t.Error("parseVersionOutput accepted a foreign first line")
	}
}

func TestResolveInstalledK3sm(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	flat := filepath.Join(dir, "flat", "k3sm")
	versioned := filepath.Join(dir, "versioned", "versions", "v0.3.0", "k3sm")
	for _, p := range []string{flat, versioned} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(machO), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// versioned/current -> versions/v0.3.0, versioned/k3sm -> current/k3sm:
	// the compat name reaches the binary through two links.
	root := filepath.Join(dir, "versioned")
	if err := os.Symlink(filepath.Join("versions", "v0.3.0"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(root, "k3sm")
	if err := os.Symlink(filepath.Join("current", "k3sm"), chain); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "versions", "v9.9.9", "k3sm"), dangling); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(dir, "dirlink")
	if err := os.Symlink(filepath.Join(root, "versions", "v0.3.0"), dirLink); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "a flat file resolves to itself", path: flat, want: flat},
		{name: "a symlink chain resolves into the versioned directory", path: chain, want: versioned},
		{name: "a dangling link fails closed", path: dangling, wantErr: true},
		{name: "a link loop fails closed", path: loop, wantErr: true},
		{name: "a link to a directory fails closed", path: dirLink, wantErr: true},
		{name: "a missing path fails closed", path: filepath.Join(dir, "absent"), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveInstalledK3sm(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveInstalledK3sm(%s) = %s, want an error", tc.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveInstalledK3sm(%s): %v", tc.path, err)
			}
			if got != tc.want {
				t.Fatalf("resolveInstalledK3sm(%s) = %s, want %s", tc.path, got, tc.want)
			}
		})
	}
}

func TestApplyUpdateResolvesTheInstalledK3sm(t *testing.T) {
	t.Run("a versioned install is inspected and probed at its real path", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		target := h.installed
		link := filepath.Join(filepath.Dir(target), "compat-k3sm")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		h.s.installedK3sm = link
		resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "if-signed", false))
		if !resp.OK || resp.Phase != wire.UpdatePhaseDone {
			t.Fatalf("resp = %+v, want OK Done", resp)
		}
		if h.probes != 1 {
			t.Fatalf("installed version probed %d times, want 1 (at %s)", h.probes, target)
		}
		if len(h.insp.paths) == 0 || h.insp.paths[0] != target {
			t.Fatalf("first inspected path = %v, want the resolved %s", h.insp.paths, target)
		}
		if slices.Contains(h.insp.paths, link) {
			t.Fatalf("inspected the link %s itself: %v", link, h.insp.paths)
		}
	})

	t.Run("a dangling installed link refuses the update before the install", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		link := filepath.Join(filepath.Dir(h.installed), "dangling-k3sm")
		if err := os.Symlink(filepath.Join(filepath.Dir(h.installed), "versions", "v0.1.9", "k3sm"), link); err != nil {
			t.Fatal(err)
		}
		h.s.installedK3sm = link
		resp := h.apply(h.request(releaseMembers("ADHOC"), "v0.2.0", "if-signed", false))
		if resp.OK {
			t.Fatalf("resp = %+v, want a refusal", resp)
		}
		if h.inst.calls != 0 || h.probes != 0 {
			t.Fatalf("installer ran %d times, version probed %d times, want neither", h.inst.calls, h.probes)
		}
	})
}
