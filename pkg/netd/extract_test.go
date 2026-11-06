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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
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

// extractedFiles is the sorted list of regular files below dir.
func extractedFiles(t *testing.T, dir string) []string {
	t.Helper()
	got := []string{}
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
	return got
}

// TestExtractReadsPastRepeatedAndDotSlashSkippedNames pins that a skipped name
// is skipped every time it appears, also with a leading "./", and that none of
// the copies is written.
func TestExtractReadsPastRepeatedAndDotSlashSkippedNames(t *testing.T) {
	extra := []tarMember{
		{name: "PAYLOAD-SHA256", body: "again\n", mode: 0o644},
		{name: "./PAYLOAD-SHA256", body: "dot slash\n", mode: 0o644},
		{name: "LICENSE", body: "again\n", mode: 0o644},
		{name: "LICENSE", body: "and again\n", mode: 0o644},
	}
	dir := t.TempDir()
	members := append(publishedMembers(), extra...)
	if err := extractUpdateArchive(bytes.NewReader(buildArchive(t, members)), dir); err != nil {
		t.Fatalf("repeated skipped names were refused: %v", err)
	}
	want := []string{
		"cp-payload/kine",
		"cp-payload/kine.version",
		"k3sm",
		"k3sm-execshim",
		"k3sm-vmhost",
		"libk3sm_getaddrinfo_shim.dylib",
		"libk3sm_pathrebase_shim.dylib",
	}
	if got := extractedFiles(t, dir); !slices.Equal(got, want) {
		t.Fatalf("extracted %q, want %q", got, want)
	}
}

// TestExtractRefusesASkippedNameBesideAMissingRequiredMember pins that a
// skipped file does not stand in for a required one.
func TestExtractRefusesASkippedNameBesideAMissingRequiredMember(t *testing.T) {
	var members []tarMember
	for _, m := range publishedMembers() {
		if m.name != "k3sm-vmhost" {
			members = append(members, m)
		}
	}
	err := extractUpdateArchive(bytes.NewReader(buildArchive(t, members)), t.TempDir())
	if !errors.Is(err, errUpdateRefused) || !strings.Contains(err.Error(), "does not carry k3sm-vmhost") {
		t.Fatalf("got %v, want a refusal naming the missing k3sm-vmhost", err)
	}
}

// TestExtractCountsEverySkippedCopyAgainstTheSizeBound streams repeated copies
// of a skipped name whose sizes sum past wire.MaxUpdateSetBytes. The earlier
// copies carry real (zero) bytes, the last claims its size in the header only,
// so the refusal must come from the running total.
func TestExtractCountsEverySkippedCopyAgainstTheSizeBound(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 128 MiB of zeros")
	}
	const copies = 4
	const each = 32 << 20 // copies*each is what the last claim must not fit beside
	pr, pw := io.Pipe()
	go func() {
		zw, _ := gzip.NewWriterLevel(pw, gzip.BestSpeed)
		tw := tar.NewWriter(zw)
		zeros := make([]byte, 1<<20)
		for i := 0; i < copies; i++ {
			name := "PAYLOAD-SHA256"
			if i%2 == 1 {
				name = "LICENSE"
			}
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeReg, Size: each}); err != nil {
				pw.CloseWithError(err)
				return
			}
			for left := int64(each); left > 0; {
				n := min(left, int64(len(zeros)))
				if _, err := tw.Write(zeros[:n]); err != nil {
					pw.CloseWithError(err)
					return
				}
				left -= n
			}
		}
		// The last copy tips the total over; its body is never sent.
		_ = tw.WriteHeader(&tar.Header{Name: "PAYLOAD-SHA256", Mode: 0o644, Typeflag: tar.TypeReg, Size: wire.MaxUpdateSetBytes - copies*each + 1})
		_ = tw.Flush()
		_ = zw.Close()
		pw.Close()
	}()
	dir := t.TempDir()
	err := extractUpdateArchive(pr, dir)
	pr.Close()
	if !errors.Is(err, errUpdateRefused) || !strings.Contains(err.Error(), "unpacks to more than") {
		t.Fatalf("got %v, want the size-bound refusal", err)
	}
	if got := extractedFiles(t, dir); len(got) != 0 {
		t.Fatalf("wrote %q, want nothing", got)
	}
}

// TestExtractRefusesARegularFileWithADirectoryName pins that "PAYLOAD-SHA256/"
// typed as a regular file is no skipped name. tar.Writer will not encode such a
// header, so the name is patched into the raw block and its checksum redone.
func TestExtractRefusesARegularFileWithADirectoryName(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: "PAYLOAD-SHA256X", Mode: 0o644, Typeflag: tar.TypeReg, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := raw.Bytes()
	b[len("PAYLOAD-SHA256")] = '/'
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	var sum int
	for _, c := range b[:512] {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	err := extractUpdateArchive(bytes.NewReader(gz.Bytes()), t.TempDir())
	if !errors.Is(err, errUpdateRefused) || !strings.Contains(err.Error(), "not a clean relative path") {
		t.Fatalf("got %v, want a refusal naming the unclean path", err)
	}
}
