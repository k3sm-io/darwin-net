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
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// bridgeMembers is the archive shape a node without the root updater is sent
// on its way to one: Mach-Os and cp-payload version markers only. The signed
// manifest travels beside the archive, never inside it.
func bridgeMembers(sig string) []tarMember {
	bin := func(name string) tarMember {
		return tarMember{name: name, body: machO + name + "\n" + sig, mode: 0o755}
	}
	return []tarMember{
		bin("k3sm"),
		bin("k3sm-netd"),
		bin("k3sm-execshim"),
		bin("k3sm-vmhost"),
		bin("libk3sm_getaddrinfo_shim.dylib"),
		bin("libk3sm_pathrebase_shim.dylib"),
		bin("cp-payload/kine"),
		{name: "cp-payload/kube.version", body: "v1.37.1\n", mode: 0o644},
		{name: "cp-payload/zot.version", body: "v2.1.20 minimal\n", mode: 0o644},
		bin("cp-payload/bin/helm"),
	}
}

// TestApplyUpdateBridge pins the two halves of the hop to the root updater:
// the archive shape the updater's release ships is one this handler accepts,
// and once the updater's LaunchDaemon plist is present the handler refuses
// every request before any other check, whoever owns the plist and whatever
// it is.
func TestApplyUpdateBridge(t *testing.T) {
	writePlist := func(t *testing.T, h *updateHarness) {
		t.Helper()
		if err := os.WriteFile(h.s.updaterPlist, []byte("<plist/>\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name string
		// members is the archive; nil means bridgeMembers("ADHOC").
		members []tarMember
		// setup arranges the updater plist and its owner.
		setup func(t *testing.T, h *updateHarness)
		// wantErr is empty for an accepted install, else the refusal text.
		wantErr string
		// wantUpdater is whether the refusal must name the updater sentinel.
		wantUpdater bool
	}{
		{
			name: "an archive of Mach-Os and version markers with no MANIFEST.json is accepted",
		},
		{
			name:    "a MANIFEST.json member would be refused, so the manifest rides beside the archive",
			members: append(bridgeMembers("ADHOC"), tarMember{name: "MANIFEST.json", body: "{}\n", mode: 0o644}),
			wantErr: "the archive member MANIFEST.json is not in the build set",
		},
		{
			name:    "a MANIFEST.json under cp-payload would be refused as a non-Mach-O",
			members: append(bridgeMembers("ADHOC"), tarMember{name: "cp-payload/MANIFEST.json", body: "{}\n", mode: 0o644}),
			wantErr: "the staged cp-payload/MANIFEST.json is not a Mach-O",
		},
		{
			name: "refused when the updater plist exists and is root-owned",
			setup: func(t *testing.T, h *updateHarness) {
				writePlist(t, h)
				h.s.updaterPlistOwner = selfUID()
			},
			wantErr:     "is installed",
			wantUpdater: true,
		},
		{
			name: "not refused when the updater plist is absent",
			setup: func(t *testing.T, h *updateHarness) {
				h.s.updaterPlistOwner = selfUID()
			},
		},
		{
			name: "refused, fail closed, when the updater plist exists but is not root-owned",
			setup: func(t *testing.T, h *updateHarness) {
				writePlist(t, h)
				h.s.updaterPlistOwner = selfUID() + 1
			},
			wantErr:     "not the trusted owner",
			wantUpdater: true,
		},
		{
			name: "refused, fail closed, when the updater plist is a symlink",
			setup: func(t *testing.T, h *updateHarness) {
				target := filepath.Join(t.TempDir(), "elsewhere.plist")
				if err := os.WriteFile(target, []byte("<plist/>\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, h.s.updaterPlist); err != nil {
					t.Fatal(err)
				}
				h.s.updaterPlistOwner = selfUID()
			},
			wantErr:     "not a regular file",
			wantUpdater: true,
		},
		{
			name: "refused, fail closed, when the updater plist is a dangling symlink",
			setup: func(t *testing.T, h *updateHarness) {
				if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), h.s.updaterPlist); err != nil {
					t.Fatal(err)
				}
				h.s.updaterPlistOwner = selfUID()
			},
			wantErr:     "not a regular file",
			wantUpdater: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf syncBuffer
			h := newUpdateHarness(t, selfUID(), func(c *Config) {
				c.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			})
			if tc.setup != nil {
				tc.setup(t, h)
			}
			members := tc.members
			if members == nil {
				members = bridgeMembers("ADHOC")
			}
			resp := h.apply(h.request(members, "v0.2.0", "if-signed", false))
			logged := strings.Count(buf.String(), "applyUpdate refused because the root updater is installed")
			if tc.wantErr == "" {
				if !resp.OK || resp.Phase != wire.UpdatePhaseDone {
					t.Fatalf("resp = %+v, want OK Done", resp)
				}
				if h.inst.calls != 1 {
					t.Fatalf("installer ran %d times, want 1", h.inst.calls)
				}
				if logged != 0 {
					t.Fatalf("the updater refusal was logged %d times on an accepted update", logged)
				}
				return
			}
			h.mustRefuse(resp, tc.wantErr)
			gotUpdater := strings.Contains(resp.Error, ErrUpdaterInstalled.Error())
			if gotUpdater != tc.wantUpdater {
				t.Fatalf("error %q names the updater sentinel = %v, want %v", resp.Error, gotUpdater, tc.wantUpdater)
			}
			if !tc.wantUpdater {
				return
			}
			if logged != 1 {
				t.Fatalf("the updater refusal was logged %d times, want once:\n%s", logged, buf.String())
			}
			if slices.Contains(h.phases, wire.UpdatePhaseVerifying) {
				t.Fatalf("phases = %v: the updater refusal must precede Verifying", h.phases)
			}
			if h.insp.calls() != 0 || h.probes != 0 {
				t.Fatalf("inspector calls %d, version probes %d: nothing may be read once the updater is installed", h.insp.calls(), h.probes)
			}
		})
	}
}

// TestCheckUpdaterAbsent pins the sentinel on the helper itself, so a caller
// can match the refusal with errors.Is.
func TestCheckUpdaterAbsent(t *testing.T) {
	dir := t.TempDir()
	plist := filepath.Join(dir, "io.k3sm.updater.plist")
	if err := checkUpdaterAbsent(plist, selfUID()); err != nil {
		t.Fatalf("absent plist: %v, want nil", err)
	}
	if err := os.WriteFile(plist, []byte("<plist/>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []uint32{selfUID(), selfUID() + 1} {
		err := checkUpdaterAbsent(plist, owner)
		if !errors.Is(err, ErrUpdaterInstalled) || !errors.Is(err, errUpdateRefused) {
			t.Fatalf("owner %d: err = %v, want ErrUpdaterInstalled wrapped in errUpdateRefused", owner, err)
		}
	}
	unreadable := filepath.Join(dir, "file", "io.k3sm.updater.plist")
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkUpdaterAbsent(unreadable, selfUID()); !errors.Is(err, ErrUpdaterInstalled) {
		t.Fatalf("an unstatable path: err = %v, want a fail-closed ErrUpdaterInstalled", err)
	}
}
