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
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// cannedDaemon answers one request on an in-memory pipe with resp.
func cannedDaemon(t *testing.T, resp Response) *Client {
	t.Helper()
	c := NewClient("/nonexistent/netd.sock")
	c.open = func(context.Context) (io.ReadWriteCloser, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			raw, err := ReadFrame(server, DefaultMaxRequestBytes)
			if err != nil {
				return
			}
			var req Request
			if json.Unmarshal(raw, &req) != nil || req.Verb != VerbMeshPeerStats {
				return
			}
			b, _ := json.Marshal(resp)
			_ = WriteFrame(server, b)
		}()
		return client, nil
	}
	return c
}

// TestMeshPeerStatsClient pins the client half of the minor-5 verb: an older
// daemon's "unknown verb" becomes ErrHelperTooOld, a good reply is returned as
// sent, an oversized reply is refused whole, and a malformed entry is skipped.
func TestMeshPeerStatsClient(t *testing.T) {
	v5 := Version{Major: ProtocolVersionMajor, Minor: MinorMeshPeerStats}
	good := []MeshPeerStat{{PubKey: "a2V5", LastHandshakeUnixNano: 1_700_000_000_000_000_000}}
	tooMany := make([]MeshPeerStat, DefaultMaxPerConn+1)
	for i := range tooMany {
		tooMany[i] = good[0]
	}
	cases := []struct {
		name    string
		resp    Response
		want    int
		wantErr error
		anyErr  bool
	}{
		{"minor 4 is too old", Response{Version: Version{Major: ProtocolVersionMajor, Minor: 4}, Error: `unknown verb "MeshPeerStats"`}, 0, ErrHelperTooOld, true},
		{"minor 5 answers", Response{Version: v5, OK: true, MeshPeerStats: good}, 1, nil, false},
		{"minor 5 with no mesh", Response{Version: v5, OK: true}, 0, nil, false},
		{"too many peers", Response{Version: v5, OK: true, MeshPeerStats: tooMany}, 0, nil, true},
		{"zero handshake time is skipped", Response{Version: v5, OK: true, MeshPeerStats: []MeshPeerStat{{PubKey: "a2V5"}}}, 0, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cannedDaemon(t, tc.resp).MeshPeerStats(context.Background())
			if tc.anyErr != (err != nil) {
				t.Fatalf("MeshPeerStats err = %v, want error %v", err, tc.anyErr)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("MeshPeerStats err = %v, want %v", err, tc.wantErr)
			}
			if len(got) != tc.want {
				t.Fatalf("MeshPeerStats returned %d entries, want %d", len(got), tc.want)
			}
		})
	}
}

// TestMeshPeerStatsSkipsMalformedEntry pins that one unusable entry in a
// helper reply costs only that entry: the good peers come back, and neither
// the error nor the log carries any value from the bad entry.
func TestMeshPeerStatsSkipsMalformedEntry(t *testing.T) {
	v5 := Version{Major: ProtocolVersionMajor, Minor: MinorMeshPeerStats}
	good := MeshPeerStat{PubKey: "Z29vZC1wZWVyLWtleQ==", LastHandshakeUnixNano: 1_700_000_000_000_000_000}
	const badKey = "YmFkLXBlZXIta2V5LXNlbnRpbmVs"
	const badTime int64 = -987654321
	cases := []struct {
		name    string
		stats   []MeshPeerStat
		want    int
		skipped string
		leaks   []string
	}{
		{"empty key", []MeshPeerStat{good, {LastHandshakeUnixNano: 424242424242}}, 1, "skipped=1", []string{"424242424242"}},
		{"negative time", []MeshPeerStat{{PubKey: badKey, LastHandshakeUnixNano: badTime}, good}, 1, "skipped=1", []string{badKey, "987654321"}},
		{"zero time", []MeshPeerStat{good, {PubKey: badKey}}, 1, "skipped=1", []string{badKey}},
		{"all bad", []MeshPeerStat{{PubKey: badKey}, {LastHandshakeUnixNano: badTime}}, 0, "skipped=2", []string{badKey, "987654321"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			c := cannedDaemon(t, Response{Version: v5, OK: true, MeshPeerStats: tc.stats})
			c.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			got, err := c.MeshPeerStats(context.Background())
			surfaces := logs.String()
			if err != nil {
				surfaces += "\n" + err.Error()
				t.Errorf("MeshPeerStats err = %v, want nil", err)
			}
			if len(got) != tc.want {
				t.Errorf("MeshPeerStats returned %d entries, want %d", len(got), tc.want)
			}
			for _, st := range got {
				if st != good {
					t.Errorf("MeshPeerStats returned %+v, want only the good peer", st)
				}
			}
			if !strings.Contains(logs.String(), tc.skipped) {
				t.Errorf("log does not report %s; logs:\n%s", tc.skipped, logs.String())
			}
			for _, leak := range tc.leaks {
				if strings.Contains(surfaces, leak) {
					t.Errorf("bad entry value %q leaked into the error or log:\n%s", leak, surfaces)
				}
			}
		})
	}
}
