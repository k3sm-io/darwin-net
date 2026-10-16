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
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// flushedSource is a fake daemon for the fd-carrying exchange: each call hands
// over a fresh descriptor (a pipe end, never a socket), and the fake inspect
// reports the scripted SO_RCVBUF for the call's position, so a flushed socket
// can be served without a real socket or the kernel race.
type flushedSource struct {
	t       *testing.T
	rcvBufs []int
	calls   int
	reqs    []Request
	files   []*os.File
	byFD    map[int]int
}

func (s *flushedSource) exchangeFD(_ context.Context, req Request) (Response, *os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		s.t.Fatalf("pipe: %v", err)
	}
	_ = w.Close()
	s.reqs = append(s.reqs, req)
	s.files = append(s.files, r)
	s.byFD[int(r.Fd())] = s.rcvBufs[s.calls]
	s.calls++
	return Response{Version: CurrentVersion(), OK: true, FDPassed: true}, r, nil
}

func (s *flushedSource) inspect(fd int) (socketState, error) {
	rcv, ok := s.byFD[fd]
	if !ok {
		s.t.Fatalf("inspect of fd %d the source never handed over", fd)
	}
	return socketState{rcvBuf: rcv, local: "10.43.0.10:53"}, nil
}

// TestBindPortRefusesAFlushedSocket pins the client's check for a socket the
// darwin unix-socket garbage collector flushed in flight: a flushed descriptor
// (SO_RCVBUF zero) is closed and the same request re-issued, one Warn is logged
// per flushed descriptor, the healthy one is returned, and three flushed in a
// row fail with ErrFlushedSocket.
func TestBindPortRefusesAFlushedSocket(t *testing.T) {
	addr := netip.MustParseAddrPort("10.43.0.10:53")
	cases := []struct {
		name      string
		rcvBufs   []int
		wantCalls int
		wantErr   bool
		wantWarns int
	}{
		{name: "a healthy socket is returned on the first try", rcvBufs: []int{786896}, wantCalls: 1, wantWarns: 0},
		{name: "a flushed socket is refused and the retry's healthy one returned", rcvBufs: []int{0, 786896}, wantCalls: 2, wantWarns: 1},
		{name: "two flushed then healthy still succeeds", rcvBufs: []int{0, 0, 786896}, wantCalls: 3, wantWarns: 2},
		{name: "three flushed in a row is the named error", rcvBufs: []int{0, 0, 0, 786896}, wantCalls: 3, wantErr: true, wantWarns: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &flushedSource{t: t, rcvBufs: tc.rcvBufs, byFD: map[int]int{}}
			var logs bytes.Buffer
			c := NewClient("/nonexistent/netd.sock")
			c.exchangeFD = src.exchangeFD
			c.inspect = src.inspect
			c.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

			file, err := c.BindPort(context.Background(), "udp", addr)
			if src.calls != tc.wantCalls {
				t.Fatalf("exchanges = %d, want %d", src.calls, tc.wantCalls)
			}
			for i, req := range src.reqs {
				if req.Verb != VerbBindPort || req.BindPort == nil || req.BindPort.Port != 53 ||
					req.BindPort.NodeAddr != "10.43.0.10" || req.BindPort.Protocol != "udp" {
					t.Fatalf("request %d = %+v (args %+v), want the same BindPort udp 10.43.0.10:53", i, req, req.BindPort)
				}
			}
			if got := strings.Count(logs.String(), "level=WARN"); got != tc.wantWarns {
				t.Fatalf("warnings = %d, want %d; log:\n%s", got, tc.wantWarns, logs.String())
			}
			if tc.wantWarns > 0 && !strings.Contains(logs.String(), "rcvbuf=0") {
				t.Fatalf("warning does not carry the socket state; log:\n%s", logs.String())
			}
			// Every flushed descriptor was closed by the client.
			for i, f := range src.files {
				if tc.rcvBufs[i] != 0 {
					continue
				}
				if err := f.Close(); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("flushed descriptor %d was left open (close = %v)", i, err)
				}
			}
			if tc.wantErr {
				if !errors.Is(err, ErrFlushedSocket) {
					t.Fatalf("err = %v, want ErrFlushedSocket", err)
				}
				if !strings.Contains(err.Error(), "netd handed over a socket the kernel had flushed, three times") {
					t.Fatalf("err = %q does not name the condition", err)
				}
				if file != nil {
					t.Fatalf("file = %v on the error path, want nil", file)
				}
				return
			}
			if err != nil {
				t.Fatalf("BindPort: %v", err)
			}
			last := src.files[len(src.files)-1]
			if file != last {
				t.Fatalf("BindPort returned %v, want the healthy descriptor %v", file, last)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("the returned descriptor was already closed: %v", err)
			}
		})
	}
}
