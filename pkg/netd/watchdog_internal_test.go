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
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckSocketPathIdentity pins the watchdog's identity check itself, with no
// timing involved: the path is the same in every case, so only the (device, inode)
// comparison can tell "still my socket" from "someone else's object at my name".
// The end-to-end Serve tests prove the wiring; this proves the discriminator.
func TestCheckSocketPathIdentity(t *testing.T) {
	tests := []struct {
		name string
		// disturb runs after the baseline identity is recorded; it returns the
		// listener (if any) it left behind so the case can close it.
		disturb  func(t *testing.T, path string)
		wantLost bool
	}{
		{
			name:     "untouched socket is still itself",
			disturb:  func(*testing.T, string) {},
			wantLost: false,
		},
		{
			name: "removed socket",
			disturb: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove socket: %v", err)
				}
			},
			wantLost: true,
		},
		{
			name: "socket unlinked and rebound by a second listener",
			disturb: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove socket: %v", err)
				}
				l, err := net.Listen("unix", path)
				if err != nil {
					t.Fatalf("second listen: %v", err)
				}
				t.Cleanup(func() { _ = l.Close() })
			},
			wantLost: true,
		},
		{
			name: "socket replaced by a regular file",
			disturb: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove socket: %v", err)
				}
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatalf("write regular file: %v", err)
				}
			},
			wantLost: true,
		},
		{
			name: "socket's directory removed",
			disturb: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove socket: %v", err)
				}
				if err := os.Remove(filepath.Dir(path)); err != nil {
					t.Fatalf("remove socket dir: %v", err)
				}
			},
			wantLost: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "knetdwd")
			if err != nil {
				t.Fatalf("mkdtemp: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "s")
			l, err := net.Listen("unix", path)
			if err != nil {
				t.Fatalf("listen unix %s: %v", path, err)
			}
			t.Cleanup(func() { _ = l.Close() })

			want, err := statSocketIdentity(path)
			if err != nil {
				t.Fatalf("baseline stat: %v", err)
			}
			tc.disturb(t, path)

			err = checkSocketPath(path, want)
			if gotLost := errors.Is(err, ErrSocketLost); gotLost != tc.wantLost {
				t.Fatalf("checkSocketPath = %v (ErrSocketLost=%v), want ErrSocketLost=%v", err, gotLost, tc.wantLost)
			}
			if !tc.wantLost && err != nil {
				t.Fatalf("checkSocketPath on an untouched socket returned %v, want nil", err)
			}
		})
	}
}
