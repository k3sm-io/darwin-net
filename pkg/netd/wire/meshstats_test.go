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
	"io"
	"net"
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
// sent, and an oversized or malformed reply is refused whole.
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
		{"zero handshake time", Response{Version: v5, OK: true, MeshPeerStats: []MeshPeerStat{{PubKey: "a2V5"}}}, 0, nil, true},
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
