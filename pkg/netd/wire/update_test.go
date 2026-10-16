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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
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
				}
				return
			}
		}
	}()
	return client, nil
}

// TestClientApplyUpdate pins the client half of ApplyUpdate: the phase stream
// in order, Failed as an error carrying the log, the end of the stream after
// Installing as Restarting (the installer restarted the helper), and nothing
// beyond Hello sent to a helper older than minor 3.
func TestClientApplyUpdate(t *testing.T) {
	args := ApplyUpdateArgs{SourceDir: "/var/lib/k3sm/update/v0.2.0", Manifest: map[string]string{"k3sm": "ab"},
		Version: "v0.2.0", AllowDowngrade: true, RequireTeamSignature: true}
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
			wantVerbs: []Verb{VerbHello, VerbApplyUpdate},
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
			wantVerbs: []Verb{VerbHello, VerbApplyUpdate},
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
			name:      "a minor-2 helper",
			minor:     MinorInterconnect,
			wantErr:   true,
			wantOld:   true,
			wantVerbs: []Verb{VerbHello},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &updateDaemon{minor: tc.minor, frames: tc.frames}
			c := NewClient("/nonexistent/netd.sock")
			c.open = d.open
			var seen []UpdatePhase
			got, err := c.ApplyUpdate(context.Background(), args, func(p UpdatePhase) { seen = append(seen, p) })
			<-d.done
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
				if d.args == nil || d.args.SourceDir != args.SourceDir || !d.args.AllowDowngrade || !d.args.RequireTeamSignature || d.args.Manifest["k3sm"] != "ab" {
					t.Fatalf("the daemon received %+v, want %+v", d.args, args)
				}
			}
		})
	}
}

// TestApplyUpdateIsMinorThree pins the 1.2 -> 1.3 bump and that a reply to any
// other verb carries neither of the new fields.
func TestApplyUpdateIsMinorThree(t *testing.T) {
	if v := CurrentVersion(); v.Minor != MinorApplyUpdate || !v.SupportsApplyUpdate() || !v.SupportsInterconnect() {
		t.Fatalf("CurrentVersion = %+v, want 1.3 supporting ApplyUpdate and the interconnect verbs", v)
	}
	if (Version{Major: 1, Minor: 2}).SupportsApplyUpdate() || (Version{Major: 2, Minor: 9}).SupportsApplyUpdate() {
		t.Fatal("a 1.2 daemon or another major must not be treated as supporting ApplyUpdate")
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
