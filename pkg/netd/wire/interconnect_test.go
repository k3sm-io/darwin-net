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
	"net/netip"
	"slices"
	"sync"
	"testing"
)

// pipeDaemon is an in-memory netd: every client connection is one net.Pipe,
// served by a goroutine that records each frame the client wrote and answers as
// a daemon of version minor would. A daemon older than minor 2 answers every
// verb it does not know, Hello included, with "unknown verb" and its version,
// exactly as Server.dispatch does.
type pipeDaemon struct {
	mu     sync.Mutex
	minor  int
	reason string    // a named refusal for the interconnect verbs, when set
	conns  [][]frame // frames written, per connection
	wg     sync.WaitGroup
}

// frame is one request as the daemon read it: its verb and raw payload.
type frame struct {
	verb Verb
	raw  []byte
}

func (d *pipeDaemon) setMinor(m int) {
	d.mu.Lock()
	d.minor = m
	d.mu.Unlock()
}

func (d *pipeDaemon) open(context.Context) (io.ReadWriteCloser, error) {
	client, server := net.Pipe()
	d.mu.Lock()
	d.conns = append(d.conns, nil)
	n := len(d.conns) - 1
	d.mu.Unlock()
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer server.Close()
		for {
			raw, err := ReadFrame(server, DefaultMaxRequestBytes)
			if err != nil {
				return
			}
			var req Request
			_ = json.Unmarshal(raw, &req)
			d.mu.Lock()
			d.conns[n] = append(d.conns[n], frame{verb: req.Verb, raw: raw})
			minor, reason := d.minor, d.reason
			d.mu.Unlock()
			resp := Response{Version: Version{Major: ProtocolVersionMajor, Minor: minor}}
			switch {
			case minor < MinorInterconnect && slices.Contains([]Verb{VerbHello, VerbEnsureInterconnectAlias, VerbRemoveInterconnectAlias}, req.Verb):
				resp.Error = fmt.Sprintf("unknown verb %q", req.Verb)
			case req.Verb == VerbHello:
				resp.OK = true
			case reason != "":
				resp.Error, resp.Reason = "refused", reason
			default:
				resp.OK, resp.InterconnectIP = true, "169.254.0.1"
			}
			b, _ := json.Marshal(resp)
			if WriteFrame(server, b) != nil {
				return
			}
		}
	}()
	return client, nil
}

// verbs returns the verbs connection n carried.
func (d *pipeDaemon) verbs(n int) []Verb {
	d.wg.Wait()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Verb
	for _, f := range d.conns[n] {
		out = append(out, f.verb)
	}
	return out
}

func newPipeClient(d *pipeDaemon) *Client {
	c := NewClient("/nonexistent/netd.sock")
	c.open = d.open
	return c
}

// TestClientNeverSendsInterconnectVerbsToOldHelper is the BI3 client gate: an
// interconnect verb reaches a daemon only when that daemon reported minor >= 2
// on the same connection. Against an older one the client writes the Hello probe
// and nothing else, and returns ErrHelperTooOld; a version learned on an earlier
// connection is never reused. The verb frame carries the slot and nothing else.
func TestClientNeverSendsInterconnectVerbsToOldHelper(t *testing.T) {
	ctx := context.Background()
	ensure := func(c *Client) error { _, err := c.EnsureInterconnectAlias(ctx, 0); return err }
	remove := func(c *Client) error { return c.RemoveInterconnectAlias(ctx, 3) }

	for _, tc := range []struct {
		name  string
		minor int
		call  func(*Client) error
		want  []Verb
		err   error
	}{
		{"ensure against minor 1 sends nothing", 1, ensure, []Verb{VerbHello}, ErrHelperTooOld},
		{"ensure against minor 0 sends nothing", 0, ensure, []Verb{VerbHello}, ErrHelperTooOld},
		{"remove against minor 1 sends nothing", 1, remove, []Verb{VerbHello}, ErrHelperTooOld},
		{"ensure against minor 2 is sent", 2, ensure, []Verb{VerbHello, VerbEnsureInterconnectAlias}, nil},
		{"remove against minor 2 is sent", 2, remove, []Verb{VerbHello, VerbRemoveInterconnectAlias}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &pipeDaemon{minor: tc.minor}
			err := tc.call(newPipeClient(d))
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if got := d.verbs(0); !slices.Equal(got, tc.want) {
				t.Fatalf("frames written = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("a reconnect to a minor-1 daemon after a minor-2 one sends nothing", func(t *testing.T) {
		d := &pipeDaemon{minor: 2}
		c := newPipeClient(d)
		addr, err := c.EnsureInterconnectAlias(ctx, 0)
		if err != nil || addr != netip.MustParseAddr("169.254.0.1") {
			t.Fatalf("against minor 2: %s, %v", addr, err)
		}
		d.setMinor(1) // the helper was replaced by an older one
		if _, err := c.EnsureInterconnectAlias(ctx, 0); !errors.Is(err, ErrHelperTooOld) {
			t.Fatalf("against the downgraded helper: err = %v, want ErrHelperTooOld", err)
		}
		if got := d.verbs(1); !slices.Equal(got, []Verb{VerbHello}) {
			t.Fatalf("second connection wrote %v, want only the Hello probe", got)
		}
	})

	t.Run("the verb frame carries only the slot", func(t *testing.T) {
		d := &pipeDaemon{minor: 2}
		if _, err := newPipeClient(d).EnsureInterconnectAlias(ctx, 5); err != nil {
			t.Fatal(err)
		}
		d.verbs(0)
		var req map[string]json.RawMessage
		if err := json.Unmarshal(d.conns[0][1].raw, &req); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(req))
		for k := range req {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"ensureInterconnectAlias", "verb", "version"}) {
			t.Fatalf("request keys = %v", keys)
		}
		var args map[string]json.RawMessage
		if err := json.Unmarshal(req["ensureInterconnectAlias"], &args); err != nil {
			t.Fatal(err)
		}
		if len(args) != 1 || string(args["slot"]) != "5" {
			t.Fatalf("args = %s, want exactly {\"slot\":5}", req["ensureInterconnectAlias"])
		}
	})

	t.Run("a named refusal maps back to its sentinel", func(t *testing.T) {
		d := &pipeDaemon{minor: 2, reason: ReasonInterconnectIndexOutOfRange}
		_, err := newPipeClient(d).EnsureInterconnectAlias(ctx, 0)
		if !errors.Is(err, ErrInterconnectIndexOutOfRange) {
			t.Fatalf("err = %v, want ErrInterconnectIndexOutOfRange", err)
		}
	})
}

// TestInterconnectIsMinorTwo pins the 1.1 -> 1.2 bump and its additive fields.
func TestInterconnectIsMinorTwo(t *testing.T) {
	if v := CurrentVersion(); v.Minor != MinorInterconnect || !v.SupportsInterconnect() {
		t.Fatalf("CurrentVersion = %+v, want 1.2 supporting interconnect", v)
	}
	if (Version{Major: 1, Minor: 1}).SupportsInterconnect() || (Version{Major: 2, Minor: 9}).SupportsInterconnect() {
		t.Fatal("a 1.1 daemon or another major must not be treated as supporting the interconnect verbs")
	}
	b, err := json.Marshal(Response{Version: CurrentVersion(), OK: true})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["reason"]; ok {
		t.Fatalf("an unnamed reply carries reason: %s", b)
	}
	if _, ok := m["interconnectIP"]; ok {
		t.Fatalf("a non-interconnect reply carries interconnectIP: %s", b)
	}
}
