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
	"slices"
	"sync/atomic"
	"testing"
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

// TestApplyUpdateIsMinorFour pins the 1.3 -> 1.4 bump (the signed request)
// and that a reply to any other verb carries neither of the update fields.
func TestApplyUpdateIsMinorFour(t *testing.T) {
	if v := CurrentVersion(); v.Minor != 4 || MinorApplyUpdate != 4 || !v.SupportsApplyUpdate() || !v.SupportsInterconnect() {
		t.Fatalf("CurrentVersion = %+v, want 1.4 supporting ApplyUpdate and the interconnect verbs", v)
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
