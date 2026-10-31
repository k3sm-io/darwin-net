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

package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// updateDaemon answers Hello as a daemon of minor would, then answers an
// ApplyUpdate with the scripted frames and, when hangUp is set, closes the
// connection instead of sending a final one.
type updateDaemon struct {
	minor  int
	frames []Response
	verbs  []Verb
	args   *ApplyUpdateArgs
	done   chan struct{}
	// installingSeen is set by the test's progress callback when it returns
	// from Installing; ackAfterProgress records whether it was set when the
	// ack arrived.
	installingSeen   *atomic.Bool
	ackAfterProgress bool
}

func (d *updateDaemon) open(context.Context) (io.ReadWriteCloser, error) {
	client, server := net.Pipe()
	d.done = make(chan struct{})
	go func() {
		defer close(d.done)
		defer server.Close()
		v := Version{Major: ProtocolVersionMajor, Minor: d.minor}
		for {
			raw, err := ReadFrame(server, DefaultMaxRequestBytes)
			if err != nil {
				return
			}
			var req Request
			_ = json.Unmarshal(raw, &req)
			d.verbs = append(d.verbs, req.Verb)
			switch {
			case d.minor < MinorInterconnect || (req.Verb == VerbApplyUpdate && d.minor < MinorApplyUpdate):
				b, _ := json.Marshal(Response{Version: v, Error: fmt.Sprintf("unknown verb %q", req.Verb)})
				_ = WriteFrame(server, b)
			case req.Verb == VerbHello:
				b, _ := json.Marshal(Response{Version: v, OK: true})
				_ = WriteFrame(server, b)
			case req.Verb == VerbApplyUpdate:
				d.args = req.ApplyUpdate
				for _, f := range d.frames {
					f.Version = v
					b, _ := json.Marshal(f)
					if WriteFrame(server, b) != nil {
						return
					}
					if f.Phase == UpdatePhaseInstalling {
						// The client's acknowledgement, read as the helper does
						// before it runs the installer.
						raw, err := ReadFrame(server, DefaultMaxRequestBytes)
						if err != nil {
							return
						}
						var ack Request
						_ = json.Unmarshal(raw, &ack)
						d.verbs = append(d.verbs, ack.Verb)
						d.ackAfterProgress = d.installingSeen != nil && d.installingSeen.Load()
					}
				}
				return
			}
		}
	}()
	return client, nil
}

// TestClientApplyUpdate pins the client half of ApplyUpdate: the phase stream
// in order, Failed as an error carrying the log, the end of the stream after
// Installing as Restarting (the installer restarted the helper), the
// Installing frame acknowledged with a Hello once progress returned, the signed
// request carried verbatim, and nothing beyond Hello sent to a helper older
// than minor 4 (a minor-3 helper speaks the withdrawn request shape).
func TestClientApplyUpdate(t *testing.T) {
	args := ApplyUpdateArgs{ArchivePath: "/var/lib/k3sm/update/k3sm-darwin-arm64.tar.gz",
		Payload: []byte(`{"version":"v0.2.0"}`), Signature: []byte{0x30, 0x01, 0xff}, SignerCert: []byte("-----BEGIN CERTIFICATE-----\n")}
	phase := func(p UpdatePhase, ok bool) Response { return Response{OK: ok, Phase: p} }
	cases := []struct {
		name      string
		minor     int
		frames    []Response
		want      UpdateResult
		wantSeen  []UpdatePhase
		wantErr   bool
		wantOld   bool
		wantVerbs []Verb
	}{
		{
			name:  "done",
			minor: MinorApplyUpdate,
			frames: []Response{phase(UpdatePhaseVerifying, true), phase(UpdatePhaseInstalling, true),
				{OK: true, Phase: UpdatePhaseDone, Log: "installed"}},
			want:      UpdateResult{Phase: UpdatePhaseDone, Log: "installed"},
			wantSeen:  []UpdatePhase{UpdatePhaseVerifying, UpdatePhaseInstalling, UpdatePhaseDone},
			wantVerbs: []Verb{VerbHello, VerbApplyUpdate, VerbHello},
		},
		{
			name:  "failed",
			minor: MinorApplyUpdate,
			frames: []Response{phase(UpdatePhaseVerifying, true),
				{Phase: UpdatePhaseFailed, Error: "digest mismatch", Log: "tail"}},
			want:      UpdateResult{Phase: UpdatePhaseFailed, Log: "tail"},
			wantSeen:  []UpdatePhase{UpdatePhaseVerifying, UpdatePhaseFailed},
			wantErr:   true,
			wantVerbs: []Verb{VerbHello, VerbApplyUpdate},
		},
		{
			name:      "the helper restarts during the install",
			minor:     MinorApplyUpdate,
			frames:    []Response{phase(UpdatePhaseVerifying, true), phase(UpdatePhaseInstalling, true)},
			want:      UpdateResult{Phase: UpdatePhaseRestarting},
			wantSeen:  []UpdatePhase{UpdatePhaseVerifying, UpdatePhaseInstalling, UpdatePhaseRestarting},
			wantVerbs: []Verb{VerbHello, VerbApplyUpdate, VerbHello},
		},
		{
			name:      "the stream ends before the install",
			minor:     MinorApplyUpdate,
			frames:    []Response{phase(UpdatePhaseVerifying, true)},
			want:      UpdateResult{Phase: UpdatePhaseVerifying},
			wantSeen:  []UpdatePhase{UpdatePhaseVerifying},
			wantErr:   true,
			wantVerbs: []Verb{VerbHello, VerbApplyUpdate},
		},
		{
			name:      "a minor-3 helper",
			minor:     3,
			wantErr:   true,
			wantOld:   true,
			wantVerbs: []Verb{VerbHello},
		},
		{
			name:      "a minor-2 helper",
			minor:     MinorInterconnect,
			wantErr:   true,
			wantOld:   true,
			wantVerbs: []Verb{VerbHello},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &updateDaemon{minor: tc.minor, frames: tc.frames, installingSeen: &atomic.Bool{}}
			c := NewClient("/nonexistent/netd.sock")
			c.open = d.open
			var seen []UpdatePhase
			got, err := c.ApplyUpdate(context.Background(), args, func(p UpdatePhase) {
				seen = append(seen, p)
				if p == UpdatePhaseInstalling {
					d.installingSeen.Store(true)
				}
			})
			<-d.done
			if slices.Contains(tc.wantSeen, UpdatePhaseInstalling) && !d.ackAfterProgress {
				t.Fatal("the Installing ack was sent before the progress callback returned")
			}
			if (err != nil) != tc.wantErr || errors.Is(err, ErrHelperTooOld) != tc.wantOld {
				t.Fatalf("err = %v, wantErr %t wantOld %t", err, tc.wantErr, tc.wantOld)
			}
			if got != tc.want || !slices.Equal(seen, tc.wantSeen) {
				t.Fatalf("result %+v seen %v, want %+v seen %v", got, seen, tc.want, tc.wantSeen)
			}
			if !slices.Equal(d.verbs, tc.wantVerbs) {
				t.Fatalf("verbs sent = %v, want %v", d.verbs, tc.wantVerbs)
			}
			if tc.wantVerbs[len(tc.wantVerbs)-1] == VerbApplyUpdate {
				if d.args == nil || d.args.ArchivePath != args.ArchivePath || !bytes.Equal(d.args.Payload, args.Payload) ||
					!bytes.Equal(d.args.Signature, args.Signature) || !bytes.Equal(d.args.SignerCert, args.SignerCert) {
					t.Fatalf("the daemon received %+v, want %+v", d.args, args)
				}
			}
		})
	}
}

// TestApplyUpdateIsMinorFour pins the 1.3 -> 1.4 bump (the signed request),
// that every later minor still supports it, and that a reply to any other verb
// carries neither of the update fields.
func TestApplyUpdateIsMinorFour(t *testing.T) {
	if v := CurrentVersion(); v.Minor < 4 || MinorApplyUpdate != 4 || !v.SupportsApplyUpdate() || !v.SupportsInterconnect() {
		t.Fatalf("CurrentVersion = %+v, want 1.4 or later supporting ApplyUpdate and the interconnect verbs", v)
	}
	if (Version{Major: 1, Minor: 3}).SupportsApplyUpdate() || (Version{Major: 2, Minor: 9}).SupportsApplyUpdate() {
		t.Fatal("a 1.3 daemon (the withdrawn request shape) or another major must not be treated as supporting ApplyUpdate")
	}
	b, err := json.Marshal(Response{Version: CurrentVersion(), OK: true})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"phase", "log"} {
		if _, ok := m[k]; ok {
			t.Fatalf("a non-update reply carries %s: %s", k, b)
		}
	}
}

// silentDaemon answers Hello, reads the ApplyUpdate request, sends Verifying
// and then goes silent, reading until the client's side of the connection
// closes; readErr is what that final read returned.
type silentDaemon struct {
	done    chan struct{}
	readErr error
}

func (d *silentDaemon) open(context.Context) (io.ReadWriteCloser, error) {
	client, server := net.Pipe()
	d.done = make(chan struct{})
	go func() {
		defer close(d.done)
		defer server.Close()
		v := CurrentVersion()
		for range 2 { // Hello, then ApplyUpdate.
			raw, err := ReadFrame(server, DefaultMaxRequestBytes)
			if err != nil {
				d.readErr = err
				return
			}
			var req Request
			_ = json.Unmarshal(raw, &req)
			resp := Response{Version: v, OK: true}
			if req.Verb == VerbApplyUpdate {
				resp.Phase = UpdatePhaseVerifying
			}
			b, _ := json.Marshal(resp)
			if err := WriteFrame(server, b); err != nil {
				d.readErr = err
				return
			}
		}
		_, d.readErr = ReadFrame(server, DefaultMaxRequestBytes)
	}()
	return client, nil
}

// cancelOnEOF cancels a context the moment its connection reads the
// helper's end of stream, before the read returns, so the client sees the
// EOF and a done context together.
type cancelOnEOF struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
}

func (c cancelOnEOF) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if errors.Is(err, io.EOF) {
		c.cancel()
	}
	return n, err
}

// settledGoroutines waits up to a second for the goroutine count to fall to
// at most want and returns the last count seen.
func settledGoroutines(want int) int {
	n := runtime.NumGoroutine()
	for deadline := time.Now().Add(time.Second); n > want && time.Now().Before(deadline); n = runtime.NumGoroutine() {
		time.Sleep(10 * time.Millisecond)
	}
	return n
}

// TestApplyUpdateReadStopsOnContextCancel pins that ApplyUpdate obeys its
// context: a cancel while a frame read is blocked ends the call within a
// second with an error wrapping context.Canceled, the connection closed (the
// helper reads EOF) and no goroutine left behind; a cancel that arrives with
// the stream's end after Installing still returns Restarting, and one that
// arrives once the Done frame was read leaves the normal result in place.
func TestApplyUpdateReadStopsOnContextCancel(t *testing.T) {
	args := ApplyUpdateArgs{ArchivePath: "/var/lib/k3sm/update/k3sm-darwin-arm64.tar.gz"}
	type outcome struct {
		res UpdateResult
		err error
	}
	t.Run("a cancel during a blocked read", func(t *testing.T) {
		before := runtime.NumGoroutine()
		d := &silentDaemon{}
		c := NewClient("/nonexistent/netd.sock")
		c.open = d.open
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		verifying := make(chan struct{})
		out := make(chan outcome, 1)
		go func() {
			res, err := c.ApplyUpdate(ctx, args, func(p UpdatePhase) {
				if p == UpdatePhaseVerifying {
					close(verifying)
				}
			})
			out <- outcome{res, err}
		}()
		select {
		case <-verifying:
		case <-time.After(5 * time.Second):
			t.Fatal("the Verifying frame never arrived")
		}
		cancel()
		var got outcome
		select {
		case got = <-out:
		case <-time.After(time.Second):
			t.Fatal("ApplyUpdate still blocked a second after its context was cancelled")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("err = %v, want one wrapping context.Canceled", got.err)
		}
		if got.res.Phase != UpdatePhaseVerifying {
			t.Fatalf("result phase = %q, want the last phase read (%q)", got.res.Phase, UpdatePhaseVerifying)
		}
		select {
		case <-d.done:
		case <-time.After(time.Second):
			t.Fatal("the helper never saw the connection close")
		}
		if !errors.Is(d.readErr, io.EOF) {
			t.Fatalf("the helper's read ended with %v, want EOF", d.readErr)
		}
		if n := settledGoroutines(before); n > before {
			t.Fatalf("%d goroutines after the call, %d before", n, before)
		}
	})
	t.Run("a cancel racing the stream's end after Installing", func(t *testing.T) {
		d := &updateDaemon{minor: MinorApplyUpdate, frames: []Response{{OK: true, Phase: UpdatePhaseVerifying},
			{OK: true, Phase: UpdatePhaseInstalling}}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := NewClient("/nonexistent/netd.sock")
		c.open = func(ctx context.Context) (io.ReadWriteCloser, error) {
			conn, err := d.open(ctx)
			return cancelOnEOF{conn, cancel}, err
		}
		var seen []UpdatePhase
		res, err := c.ApplyUpdate(ctx, args, func(p UpdatePhase) { seen = append(seen, p) })
		<-d.done
		if ctx.Err() == nil {
			t.Fatal("the context was not cancelled by the stream's end; the case tests nothing")
		}
		if err != nil || res != (UpdateResult{Phase: UpdatePhaseRestarting}) {
			t.Fatalf("ApplyUpdate = %+v, %v; want Restarting and no error", res, err)
		}
		if want := []UpdatePhase{UpdatePhaseVerifying, UpdatePhaseInstalling, UpdatePhaseRestarting}; !slices.Equal(seen, want) {
			t.Fatalf("seen %v, want %v", seen, want)
		}
	})
	t.Run("a cancel after the Done frame", func(t *testing.T) {
		d := &updateDaemon{minor: MinorApplyUpdate, frames: []Response{{OK: true, Phase: UpdatePhaseVerifying},
			{OK: true, Phase: UpdatePhaseInstalling}, {OK: true, Phase: UpdatePhaseDone, Log: "installed"}}}
		c := NewClient("/nonexistent/netd.sock")
		c.open = d.open
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		res, err := c.ApplyUpdate(ctx, args, func(p UpdatePhase) {
			if p == UpdatePhaseDone {
				cancel() // the frame is read; the cancel races only the return
			}
		})
		<-d.done
		if err != nil || res != (UpdateResult{Phase: UpdatePhaseDone, Log: "installed"}) {
			t.Fatalf("ApplyUpdate = %+v, %v; want Done with its log and no error", res, err)
		}
	})
}
