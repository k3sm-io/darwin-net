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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// updatePayloadDir is the one directory a release archive may carry: the
// control-plane payload, whose members are extracted at any depth below it.
const updatePayloadDir = "cp-payload"

// updateSetFiles are the top-level files a release archive must carry, each
// once: k3sm and the siblings `k3sm install` requires beside it.
var updateSetFiles = []string{
	"k3sm",
	"k3sm-execshim",
	"k3sm-vmhost",
	"libk3sm_getaddrinfo_shim.dylib",
	"libk3sm_pathrebase_shim.dylib",
}

// updateSkippedFiles are release archive members that are not part of the
// build set (the legal files and the k3sm-netd copy of the binary, which
// install never copies). They are read past, counted, and never written.
var updateSkippedFiles = []string{"LICENSE", "NOTICE", "k3sm-netd"}

// maxUpdateArchiveDepth bounds the directory depth below cp-payload.
const maxUpdateArchiveDepth = 16

// extractUpdateArchive unpacks the gzip tar r into dst, an existing empty
// root-only directory. Call it only after the archive's sha256 matched the
// signed payload.
//
// It writes regular files only: the updateSetFiles names at the top (each
// once, all present) and any file below cp-payload/. A directory is created
// only for cp-payload and below it. A symlink, a hard link, a device or any
// other entry type refuses, as does an absolute path, a "." or ".." component,
// an unclean path, a name outside the set (updateSkippedFiles aside), more than
// wire.MaxUpdateArchiveMembers entries, and an archive that unpacks to more
// than wire.MaxUpdateSetBytes, skipped members included. Files are created
// exclusively and never through a symlink, with their permission bits less
// group and other write and any set-id bit.
//
// The rules mirror the payload layout the k3sm repository's pkg/install
// defines (its cp-payload directory); the cp-payload members are matched by
// prefix here because the payload binary list lives in k3sm.
func extractUpdateArchive(r io.Reader, dst string) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: the archive is not gzip: %w", errUpdateRefused, err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	seen := map[string]bool{}
	var total int64
	for entries := 0; ; entries++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: read the archive: %w", errUpdateRefused, err)
		}
		if entries >= wire.MaxUpdateArchiveMembers {
			return fmt.Errorf("%w: the archive holds more than %d entries", errUpdateRefused, wire.MaxUpdateArchiveMembers)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name, err := archiveMemberName(hdr)
		if err != nil {
			return err
		}
		mode := hdr.FileInfo().Mode()
		switch {
		case hdr.Typeflag == tar.TypeLink || mode&fs.ModeSymlink != 0:
			return fmt.Errorf("%w: the archive member %s is a link", errUpdateRefused, name)
		case mode.IsDir():
			if !inPayloadTree(name, true) {
				return fmt.Errorf("%w: the archive names the directory %s, which is not in the build set", errUpdateRefused, name)
			}
			if err := mkdirAllOwn(dst, name); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			return fmt.Errorf("%w: the archive member %s is not a regular file", errUpdateRefused, name)
		}
		if hdr.Size < 0 || hdr.Size > wire.MaxUpdateSetBytes-total {
			return fmt.Errorf("%w: the archive unpacks to more than %d bytes", errUpdateRefused, wire.MaxUpdateSetBytes)
		}
		total += hdr.Size
		if slices.Contains(updateSkippedFiles, name) {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return fmt.Errorf("%w: read the archive: %w", errUpdateRefused, err)
			}
			continue
		}
		if !slices.Contains(updateSetFiles, name) && !inPayloadTree(name, false) {
			return fmt.Errorf("%w: the archive member %s is not in the build set", errUpdateRefused, name)
		}
		if seen[name] {
			return fmt.Errorf("%w: the archive names %s twice", errUpdateRefused, name)
		}
		seen[name] = true
		if err := writeArchiveMember(tr, dst, name, hdr.Size, mode.Perm()); err != nil {
			return err
		}
	}
	for _, m := range updateSetFiles {
		if !seen[m] {
			return fmt.Errorf("%w: the archive does not carry %s", errUpdateRefused, m)
		}
	}
	return nil
}

// inPayloadTree reports whether name lies in the cp-payload tree: cp-payload
// itself (for a directory) or a path below it, within the depth bound.
func inPayloadTree(name string, dir bool) bool {
	if name == updatePayloadDir {
		return dir
	}
	rest, ok := strings.CutPrefix(name, updatePayloadDir+"/")
	return ok && strings.Count(rest, "/") < maxUpdateArchiveDepth
}

// archiveMemberName is the member's clean relative path ("./" and a
// directory's trailing "/" dropped), or a refusal.
func archiveMemberName(hdr *tar.Header) (string, error) {
	name := strings.TrimPrefix(hdr.Name, "./")
	if hdr.Typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
	}
	bad := name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\x00\\") || path.Clean(name) != name
	for _, c := range strings.Split(name, "/") {
		if c == ".." || c == "." {
			bad = true
		}
	}
	if bad {
		return "", fmt.Errorf("%w: the archive member name %q is not a clean relative path", errUpdateRefused, hdr.Name)
	}
	return name, nil
}

// mkdirAllOwn creates every component of the relative directory rel under dst,
// mode 0700, requiring each existing component to be a real directory.
func mkdirAllOwn(dst, rel string) error {
	cur := dst
	for _, c := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, c)
		err := os.Mkdir(cur, 0o700)
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create %s: %w", cur, err)
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", cur, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", errUpdateRefused, cur)
		}
	}
	return nil
}

// writeArchiveMember writes size bytes of r to dst/name.
func writeArchiveMember(r io.Reader, dst, name string, size int64, perm fs.FileMode) error {
	if dir := path.Dir(name); dir != "." {
		if err := mkdirAllOwn(dst, dir); err != nil {
			return err
		}
	}
	p := filepath.Join(dst, filepath.FromSlash(name))
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", p, err)
	}
	n, err := io.Copy(out, io.LimitReader(r, size))
	if err == nil && n != size {
		err = fmt.Errorf("%w: the archive member %s is truncated", errUpdateRefused, name)
	}
	if err == nil {
		err = out.Chmod(perm&0o755 | 0o600)
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", p, err)
	}
	return nil
}
