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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// updateSetFiles is a build set's shape: the five binaries and a cp-payload.
var updateSetFiles = map[string]string{
	"k3sm":                           "staged k3sm\n",
	"k3sm-execshim":                  "execshim\n",
	"k3sm-vmhost":                    "vmhost\n",
	"libk3sm_getaddrinfo_shim.dylib": "gai shim\n",
	"libk3sm_pathrebase_shim.dylib":  "rebase shim\n",
	"cp-payload/manifest.json":       "{}\n",
	"cp-payload/charts/a.tgz":        "chart\n",
}

// writeUpdateSet writes the build set into a fresh directory and returns it
// with its manifest.
func writeUpdateSet(t *testing.T) (string, map[string]string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "set")
	manifest := map[string]string{}
	for rel, body := range updateSetFiles {
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if !strings.Contains(rel, "/") && !strings.HasSuffix(rel, ".dylib") {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		manifest[rel] = hex.EncodeToString(sum[:])
	}
	return src, manifest
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

// fakeInstaller records the one exec ApplyUpdate makes and what was on disk
// when it was made.
type fakeInstaller struct {
	calls     int
	argv      []string
	dir       string
	stagedSum map[string]string // sha256 of every staged set file at exec time
	topLevel  []string          // the staging directory's entries at exec time
	logLines  string            // written to the log before returning
	err       error
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
	f.stagedSum = map[string]string{}
	for rel := range updateSetFiles {
		b, err := os.ReadFile(filepath.Join(r.Dir, filepath.FromSlash(rel)))
		if err == nil {
			sum := sha256.Sum256(b)
			f.stagedSum[rel] = hex.EncodeToString(sum[:])
		}
	}
	if f.logLines != "" {
		_, _ = r.Log.WriteString(f.logLines)
	}
	return f.err
}

// updateHarness is a Server with a temp staging root and a fake installer, and
// a connection whose peer is this test's uid.
type updateHarness struct {
	s      *Server
	inst   *fakeInstaller
	st     *connState
	phases []wire.UpdatePhase
	root   string
}

func newUpdateHarness(t *testing.T, serviceUID uint32) *updateHarness {
	t.Helper()
	s := NewServer(Config{
		NodePodCIDR: netip.MustParsePrefix(identityBootCIDR),
		ServiceUID:  serviceUID,
		Privileged:  &recordingPriv{},
		Logger:      slog.New(slog.DiscardHandler),
	})
	h := &updateHarness{s: s, inst: &fakeInstaller{}, root: filepath.Join(t.TempDir(), "k3sm.staging")}
	s.stagingRoot = h.root
	s.runInstaller = h.inst.run
	conn, _ := socketPair(t)
	h.st = newConnState(defaultMaxPerConnForTest)
	h.st.conn = conn
	h.st.emit = func(r wire.Response) error {
		h.phases = append(h.phases, r.Phase)
		return nil
	}
	return h
}

// defaultMaxPerConnForTest mirrors the server default.
const defaultMaxPerConnForTest = wire.DefaultMaxPerConn

// apply runs one ApplyUpdate and records the final phase after the streamed ones.
func (h *updateHarness) apply(args *wire.ApplyUpdateArgs) wire.Response {
	resp := h.s.handleApplyUpdate(context.Background(), h.st, args)
	h.phases = append(h.phases, resp.Phase)
	return resp
}

// stagingLeftovers lists what remains under the staging root (the lock file
// sits beside it, not in it).
func (h *updateHarness) stagingLeftovers(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(h.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
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
	}
}

func selfUID() uint32 { return uint32(os.Getuid()) }

// TestApplyUpdateVerifiesBeforeInstall is the B598 root-helper gate: the copy
// refuses a symlink (and every other unsafe or unlisted entry), a digest
// mismatch refuses before any exec, the one exec sees the staged path and the
// requested flags and no token file, the phases are reported in order, and an
// ApplyUpdate request may exceed the other verbs' 64 KiB cap up to 256 KiB.
func TestApplyUpdateVerifiesBeforeInstall(t *testing.T) {
	t.Run("installs a verified set with the staged path and the flags", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		src, manifest := writeUpdateSet(t)
		resp := h.apply(&wire.ApplyUpdateArgs{
			SourceDir: src, Manifest: manifest, Version: "v0.2.0",
			AllowDowngrade: true, RequireTeamSignature: true,
		})
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
		wantArgv := []string{filepath.Join(dir, "k3sm"), "install", "--from-staging", dir,
			"--allow-downgrade", "--require-team-signature"}
		if !slices.Equal(h.inst.argv, wantArgv) {
			t.Fatalf("argv = %q, want %q", h.inst.argv, wantArgv)
		}
		wantTop := []string{"cp-payload", updateLogName, "k3sm", "k3sm-execshim", "k3sm-vmhost",
			"libk3sm_getaddrinfo_shim.dylib", "libk3sm_pathrebase_shim.dylib"}
		if !slices.Equal(h.inst.topLevel, wantTop) {
			t.Fatalf("staging dir at exec time = %v, want the set and the log only (no token file) %v", h.inst.topLevel, wantTop)
		}
		for rel, sum := range manifest {
			if h.inst.stagedSum[rel] != sum {
				t.Errorf("staged %s sha256 = %q at exec time, want %q", rel, h.inst.stagedSum[rel], sum)
			}
		}
		if left := h.stagingLeftovers(t); len(left) != 0 {
			t.Fatalf("staging root still holds %v after the install returned", left)
		}
	})

	t.Run("passes no optional flag unless asked", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		src, manifest := writeUpdateSet(t)
		if resp := h.apply(&wire.ApplyUpdateArgs{SourceDir: src, Manifest: manifest, Version: "v0.2.0"}); !resp.OK {
			t.Fatalf("resp = %+v", resp)
		}
		if n := len(h.inst.argv); n != 4 || slices.Contains(h.inst.argv, "--allow-downgrade") || slices.Contains(h.inst.argv, "--require-team-signature") {
			t.Fatalf("argv = %q, want the four install arguments only", h.inst.argv)
		}
	})

	refusals := []struct {
		name   string
		mutate func(t *testing.T, src string, manifest map[string]string)
		want   string
	}{
		{"a symlink in the set", func(t *testing.T, src string, _ map[string]string) {
			if err := os.Symlink("/etc/master.passwd", filepath.Join(src, "cp-payload", "link")); err != nil {
				t.Fatal(err)
			}
		}, "is a symlink"},
		{"a symlinked binary", func(t *testing.T, src string, _ map[string]string) {
			p := filepath.Join(src, "k3sm-vmhost")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/bin/sh", p); err != nil {
				t.Fatal(err)
			}
		}, "is a symlink"},
		{"a digest mismatch", func(t *testing.T, _ string, manifest map[string]string) {
			manifest["k3sm-vmhost"] = strings.Repeat("0", 64)
		}, "the manifest says"},
		{"a changed staged k3sm", func(t *testing.T, src string, _ map[string]string) {
			if err := os.WriteFile(filepath.Join(src, "k3sm"), []byte("tampered\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "the manifest says"},
		{"a file the manifest does not name", func(t *testing.T, src string, _ map[string]string) {
			if err := os.WriteFile(filepath.Join(src, "extra"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "not in the manifest"},
		{"a manifest file missing from the set", func(t *testing.T, src string, _ map[string]string) {
			if err := os.Remove(filepath.Join(src, "k3sm-execshim")); err != nil {
				t.Fatal(err)
			}
		}, "not in the set"},
		{"a setuid file", func(t *testing.T, src string, _ map[string]string) {
			if err := unix.Chmod(filepath.Join(src, "k3sm-execshim"), 0o4755); err != nil {
				t.Fatal(err)
			}
		}, "set-id"},
		{"a fifo", func(t *testing.T, src string, _ map[string]string) {
			if err := unix.Mkfifo(filepath.Join(src, "cp-payload", "fifo"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file or directory"},
		{"a set over 2 GiB", func(t *testing.T, src string, manifest map[string]string) {
			p := filepath.Join(src, "cp-payload", "huge")
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(wire.MaxUpdateSetBytes + 1); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			manifest["cp-payload/huge"] = strings.Repeat("0", 64)
		}, "larger than"},
		{"a manifest path that climbs out", func(t *testing.T, _ string, manifest map[string]string) {
			manifest["../k3sm"] = strings.Repeat("0", 64)
		}, "not a clean relative path"},
	}
	for _, tc := range refusals {
		t.Run("refuses "+tc.name+" before any exec", func(t *testing.T) {
			h := newUpdateHarness(t, selfUID())
			src, manifest := writeUpdateSet(t)
			tc.mutate(t, src, manifest)
			resp := h.apply(&wire.ApplyUpdateArgs{SourceDir: src, Manifest: manifest, Version: "v0.2.0"})
			if resp.OK || resp.Phase != wire.UpdatePhaseFailed || !strings.Contains(resp.Error, tc.want) {
				t.Fatalf("resp = %+v, want Failed containing %q", resp, tc.want)
			}
			if h.inst.calls != 0 {
				t.Fatalf("the installer ran %d times on a refused set", h.inst.calls)
			}
			if slices.Contains(h.phases, wire.UpdatePhaseInstalling) {
				t.Fatalf("phases = %v: Installing reported on a refused set", h.phases)
			}
			if left := h.stagingLeftovers(t); len(left) != 0 {
				t.Fatalf("a refused set left %v in the staging root", left)
			}
		})
	}

	t.Run("refuses a caller that is not the service uid", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID()+1)
		src, manifest := writeUpdateSet(t)
		resp := h.apply(&wire.ApplyUpdateArgs{SourceDir: src, Manifest: manifest, Version: "v0.2.0"})
		if resp.OK || resp.Phase != wire.UpdatePhaseFailed || !strings.Contains(resp.Error, ErrPeerUnauthorized.Error()) {
			t.Fatalf("resp = %+v, want a Failed peer refusal", resp)
		}
		if !slices.Equal(h.phases, []wire.UpdatePhase{wire.UpdatePhaseFailed}) || h.inst.calls != 0 {
			t.Fatalf("phases = %v, installer calls = %d: a foreign caller got past the check", h.phases, h.inst.calls)
		}
	})

	t.Run("refuses a request with no connection to check", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		src, manifest := writeUpdateSet(t)
		resp := h.s.handleApplyUpdate(context.Background(), newConnState(1), &wire.ApplyUpdateArgs{SourceDir: src, Manifest: manifest, Version: "v0.2.0"})
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
		src, manifest := writeUpdateSet(t)
		resp := h.apply(&wire.ApplyUpdateArgs{SourceDir: src, Manifest: manifest, Version: "v0.2.0"})
		want := []wire.UpdatePhase{wire.UpdatePhaseVerifying, wire.UpdatePhaseInstalling, wire.UpdatePhaseFailed}
		if resp.OK || !slices.Equal(h.phases, want) {
			t.Fatalf("resp = %+v phases = %v, want %v", resp, h.phases, want)
		}
		got := strings.Split(resp.Log, "\n")
		if len(got) != updateLogTailLines || got[0] != "line 20" || got[len(got)-1] != "line 59" {
			t.Fatalf("log tail = %q, want lines 20..59", resp.Log)
		}
	})

	t.Run("refuses a source not owned by the service uid", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("the test runs as root, which owns everything it writes")
		}
		h := newUpdateHarness(t, selfUID())
		manifest := map[string]string{"k3sm": strings.Repeat("0", 64)}
		resp := h.apply(&wire.ApplyUpdateArgs{SourceDir: "/usr/bin", Manifest: manifest, Version: "v0.2.0"})
		if resp.OK || !strings.Contains(resp.Error, "not the service uid") || h.inst.calls != 0 {
			t.Fatalf("resp = %+v calls = %d, want an ownership refusal", resp, h.inst.calls)
		}
	})

	t.Run("admits an ApplyUpdate request over 64 KiB and up to 256 KiB, and no other verb", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		src, manifest := writeUpdateSet(t)
		for i := range 1800 {
			manifest[fmt.Sprintf("cp-payload/pad/file-%04d", i)] = strings.Repeat("a", 64)
		}
		big, _ := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbApplyUpdate,
			ApplyUpdate: &wire.ApplyUpdateArgs{SourceDir: src, Manifest: manifest, Version: "v0.2.0"}})
		if n := len(big); n <= wire.DefaultMaxRequestBytes || n > wire.MaxApplyUpdateRequestBytes {
			t.Fatalf("the test request is %d bytes, want between %d and %d", n, wire.DefaultMaxRequestBytes, wire.MaxApplyUpdateRequestBytes)
		}
		frames, err := h.serveOne(t, big)
		if err != nil {
			t.Fatalf("the large ApplyUpdate got no reply: %v", err)
		}
		last := frames[len(frames)-1]
		if frames[0].Phase != wire.UpdatePhaseVerifying || last.Phase != wire.UpdatePhaseFailed || !strings.Contains(last.Error, "not in the set") {
			t.Fatalf("frames = %+v, want the verb to run and refuse the padded manifest's absent files", frames)
		}
		if h.inst.calls != 0 {
			t.Fatalf("the installer ran %d times", h.inst.calls)
		}

		pad := strings.Repeat("x", wire.DefaultMaxRequestBytes)
		other := []byte(fmt.Sprintf(`{"version":{"major":1,"minor":3},"verb":"EnsureAlias","ensureAlias":{"ip":"100.64.0.5"},"pad":%q}`, pad))
		frames, err = h.serveOne(t, other)
		if err != nil || len(frames) != 1 || frames[0].OK || !strings.Contains(frames[0].Error, "exceeds the 65536-byte cap") {
			t.Fatalf("frames = %+v err = %v, want an EnsureAlias over 64 KiB refused", frames, err)
		}

		huge, _ := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbApplyUpdate,
			ApplyUpdate: &wire.ApplyUpdateArgs{SourceDir: src + "/" + strings.Repeat("y", wire.MaxApplyUpdateRequestBytes), Manifest: manifest, Version: "v0.2.0"}})
		if _, err := h.serveOne(t, huge); err == nil {
			t.Fatal("a frame over 256 KiB was answered, want the connection closed")
		}
	})

	t.Run("streams the phase frames on the connection", func(t *testing.T) {
		h := newUpdateHarness(t, selfUID())
		src, manifest := writeUpdateSet(t)
		client, server := socketPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.s.handleConn(ctx, server)
		}()
		raw, _ := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: wire.VerbApplyUpdate,
			ApplyUpdate: &wire.ApplyUpdateArgs{SourceDir: src, Manifest: manifest, Version: "v0.2.0"}})
		if err := wire.WriteFrame(client, raw); err != nil {
			t.Fatal(err)
		}
		var got []wire.UpdatePhase
		for len(got) == 0 || !got[len(got)-1].Terminal() {
			b, err := wire.ReadFrame(client, wire.DefaultMaxRequestBytes)
			if err != nil {
				t.Fatalf("read frame after %v: %v", got, err)
			}
			var resp wire.Response
			if err := json.Unmarshal(b, &resp); err != nil {
				t.Fatal(err)
			}
			got = append(got, resp.Phase)
		}
		want := []wire.UpdatePhase{wire.UpdatePhaseVerifying, wire.UpdatePhaseInstalling, wire.UpdatePhaseDone}
		if !slices.Equal(got, want) {
			t.Fatalf("frames = %v, want %v", got, want)
		}
		_ = client.Close()
		<-done
	})
}
