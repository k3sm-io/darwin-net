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
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// publishedMembers is the top level the release publisher packs, with a
// cp-payload holding one binary and one version marker. The digest files come
// first, as they do in a published tarball.
func publishedMembers() []tarMember {
	bin := func(name string) tarMember {
		return tarMember{name: name, body: machO + name + "\nADHOC", mode: 0o755}
	}
	return []tarMember{
		{name: "PAYLOAD-SHA256", body: "digests after signing\n", mode: 0o644},
		{name: "UPSTREAM-DIGESTS", body: "digests before signing\n", mode: 0o644},
		{name: "cp-payload/", typeflag: tar.TypeDir, mode: 0o755},
		bin("cp-payload/kine"),
		{name: "cp-payload/kine.version", body: "v0.13.0\n", mode: 0o644},
		bin("k3sm"),
		bin("k3sm-execshim"),
		bin("k3sm-vmhost"),
		bin("libk3sm_getaddrinfo_shim.dylib"),
		bin("libk3sm_pathrebase_shim.dylib"),
		{name: "LICENSE", body: "license\n", mode: 0o644},
		{name: "NOTICE", body: "notice\n", mode: 0o644},
	}
}

// TestExtractAcceptsThePublishedArchiveShape pins the archive a published
// release actually is: the two digest files and the legal files are read past
// and never written, so what reaches the code-signing check is only the build
// set, which refuses any other non-Mach-O.
func TestExtractAcceptsThePublishedArchiveShape(t *testing.T) {
	dir := t.TempDir()
	if err := extractUpdateArchive(bytes.NewReader(buildArchive(t, publishedMembers())), dir); err != nil {
		t.Fatalf("the published archive shape was refused: %v", err)
	}
	var got []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		got = append(got, rel)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{
		"cp-payload/kine",
		"cp-payload/kine.version",
		"k3sm",
		"k3sm-execshim",
		"k3sm-vmhost",
		"libk3sm_getaddrinfo_shim.dylib",
		"libk3sm_pathrebase_shim.dylib",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("extracted %q, want %q", got, want)
	}
	if _, err := stagedSigningSet(dir); err != nil {
		t.Fatalf("the extracted set fails the signing-set check: %v", err)
	}
}

// TestApplyUpdateInstallsThePublishedArchiveShape runs that archive through
// the whole root-helper verb, up to and including the staged installer.
func TestApplyUpdateInstallsThePublishedArchiveShape(t *testing.T) {
	h := newUpdateHarness(t, selfUID())
	resp := h.apply(h.request(publishedMembers(), "v0.2.0", "", false))
	if !resp.OK || resp.Phase != wire.UpdatePhaseDone {
		t.Fatalf("the published archive shape was not installed: %+v", resp)
	}
	if h.inst.calls != 1 {
		t.Fatalf("installer ran %d times, want 1", h.inst.calls)
	}
}

// TestExtractRefusesWhatOnlyLooksLikeASkippedDigestFile holds the skip to the
// exact top-level regular file: every other entry under or near those names
// keeps its refusal, and a skipped file still counts against the size bound.
func TestExtractRefusesWhatOnlyLooksLikeASkippedDigestFile(t *testing.T) {
	tests := []struct {
		name   string
		member tarMember
		want   string
	}{
		{"a suffixed name", tarMember{name: "PAYLOAD-SHA256.sig", body: "x", mode: 0o644}, "not in the build set"},
		{"another case", tarMember{name: "payload-sha256", body: "x", mode: 0o644}, "not in the build set"},
		{"a nested name", tarMember{name: "sub/UPSTREAM-DIGESTS", body: "x", mode: 0o644}, "not in the build set"},
		{"a directory", tarMember{name: "UPSTREAM-DIGESTS/", typeflag: tar.TypeDir, mode: 0o755}, "not in the build set"},
		{"a symlink", tarMember{name: "PAYLOAD-SHA256", typeflag: tar.TypeSymlink, linkname: "/etc/passwd", mode: 0o777}, "is a link"},
		{"a hard link", tarMember{name: "UPSTREAM-DIGESTS", typeflag: tar.TypeLink, linkname: "k3sm"}, "is a link"},
		{"a fifo", tarMember{name: "PAYLOAD-SHA256", typeflag: tar.TypeFifo}, "not a regular file"},
		{"a climbing path", tarMember{name: "cp-payload/../PAYLOAD-SHA256", body: "x", mode: 0o644}, "not a clean relative path"},
		{"a file over the size bound", tarMember{name: "PAYLOAD-SHA256", mode: 0o644, size: wire.MaxUpdateSetBytes + 1}, "unpacks to more than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			members := append([]tarMember{tc.member}, publishedMembers()[2:]...)
			err := extractUpdateArchive(bytes.NewReader(buildArchive(t, members)), dir)
			if !errors.Is(err, errUpdateRefused) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}
