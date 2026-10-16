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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// DefaultUpdateStagingRoot is the install staging root ApplyUpdate copies a set
// under: the same root the k3sm.app copy-out uses, whose directories
// `k3sm install --from-staging` accepts.
const DefaultUpdateStagingRoot = "/Library/k3sm.staging"

// updateLogName is the installer log ApplyUpdate writes beside the set. It is
// created with O_EXCL, so a set that already holds a file of that name is
// refused before the exec.
const updateLogName = "install.log"

// updateDirPrefix names the staging directories ApplyUpdate creates, so a later
// ApplyUpdate removes only its own leftovers.
const updateDirPrefix = "netd-update-"

// stagingLockSuffix makes the staging lock path from the staging root, the
// installer's StagingLockPath (/Library/k3sm.staging.lock).
const stagingLockSuffix = ".lock"

// Bounds on the set and the reply.
const (
	maxUpdateDepth     = 16
	updateLogTailLines = 40
	updateLogTailBytes = 8 << 10
	maxVersionLen      = 128
)

// errUpdateRefused is the base error every ApplyUpdate refusal wraps.
var errUpdateRefused = errors.New("applyUpdate refused")

// installerRun is the one exec ApplyUpdate makes.
type installerRun struct {
	// Argv is the staged k3sm and its install arguments.
	Argv []string
	// Dir is the staging directory, the working directory of the run.
	Dir string
	// Log receives the installer's stdout and stderr.
	Log *os.File
	// Inherit are descriptors the installer inherits (the staging lock).
	Inherit []*os.File
}

// installerRunner runs the installer and returns nil on exit 0. It is the seam
// the unit tests replace.
type installerRunner func(ctx context.Context, run installerRun) error

// execInstaller is the production installerRunner. The installer runs in its
// own session, so the launchd stop of this daemon (which the install itself
// performs) does not take its process group with it, and writes straight to
// the log file, so it never writes into a pipe this daemon would leave behind.
// The staging lock descriptor is inherited, so the lock lives exactly as long
// as the installer, whether or not this daemon does. ctx's expiry kills the
// whole session.
func execInstaller(ctx context.Context, run installerRun) error {
	cmd := exec.CommandContext(ctx, run.Argv[0], run.Argv[1:]...)
	cmd.Dir = run.Dir
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Stdout = run.Log
	cmd.Stderr = run.Log
	cmd.ExtraFiles = run.Inherit
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error {
		return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	cmd.WaitDelay = 10 * time.Second
	return cmd.Run()
}

// handleApplyUpdate serves VerbApplyUpdate. The steps run in a fixed order and
// each is reported: the caller check, Verifying (the copy into a fresh
// root-only directory and the digest check of every copied file), the log
// file, Installing (the one exec of the staged k3sm), then Done or
// Failed. Nothing in the set is executed before every digest matched, and
// nothing but the staged k3sm is ever executed.
//
// The reply is a stream: emit sends the intermediate phases and the returned
// response is the final frame. emit is nil when no connection is attached.
func (s *Server) handleApplyUpdate(ctx context.Context, st *connState, args *wire.ApplyUpdateArgs) wire.Response {
	if err := s.authorizeUpdatePeer(st); err != nil {
		s.log.Warn("netd: applyUpdate caller rejected", "err", err)
		return s.updateFailed(err, "")
	}
	if args == nil {
		return s.updateFailed(fmt.Errorf("%w: missing args", errUpdateRefused), "")
	}
	if !s.updateMu.TryLock() {
		return s.updateFailed(fmt.Errorf("%w: another update is running in this helper", errUpdateRefused), "")
	}
	defer s.updateMu.Unlock()
	if err := validateUpdateArgs(args); err != nil {
		return s.updateFailed(err, "")
	}
	log := s.log.With("version", args.Version)
	st.emitPhase(s, wire.UpdatePhaseVerifying)

	root := s.stagingRoot
	if err := ensureStagingRoot(root); err != nil {
		return s.updateFailed(err, "")
	}
	lock, err := lockStaging(root + stagingLockSuffix)
	if err != nil {
		return s.updateFailed(err, "")
	}
	// abandoned is set when the daemon stops while the installer runs: the
	// installer goroutine may still be handing the lock and the log to the
	// child, so neither is closed under it (the process is exiting anyway).
	abandoned := false
	defer func() {
		if !abandoned {
			_ = lock.Close()
		}
	}()
	sweepUpdateDirs(root, log)
	dir, err := os.MkdirTemp(root, updateDirPrefix)
	if err != nil {
		return s.updateFailed(fmt.Errorf("create a staging directory in %s: %w", root, err), "")
	}
	defer func() {
		if !abandoned {
			if err := os.RemoveAll(dir); err != nil {
				log.Warn("netd: removing the update staging directory failed", "dir", dir, "err", err)
			}
		}
	}()
	if err := ownRootOnly(dir); err != nil {
		return s.updateFailed(err, "")
	}

	got, err := copyUpdateSet(args.SourceDir, dir, s.cfg.ServiceUID, args.Manifest)
	if err != nil {
		log.Warn("netd: update set refused", "source", args.SourceDir, "err", err)
		return s.updateFailed(err, "")
	}
	if err := checkManifest(args.Manifest, got); err != nil {
		log.Warn("netd: update set refused", "source", args.SourceDir, "err", err)
		return s.updateFailed(err, "")
	}

	logPath := filepath.Join(dir, updateLogName)
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return s.updateFailed(fmt.Errorf("create %s: %w", logPath, err), "")
	}
	defer func() {
		if !abandoned {
			_ = logf.Close()
		}
	}()

	argv := []string{filepath.Join(dir, "k3sm"), "install", "--from-staging", dir}
	if args.AllowDowngrade {
		argv = append(argv, "--allow-downgrade")
	}
	if args.RequireTeamSignature {
		argv = append(argv, "--require-team-signature")
	}
	st.emitPhase(s, wire.UpdatePhaseInstalling)
	log.Info("netd: running the staged installer", "dir", dir)

	// The installer restarts this daemon, so its run must not end with this
	// daemon's context: it is bounded by its own wall clock only.
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wire.UpdateInstallTimeout)
	done := make(chan error, 1)
	go func() {
		defer cancel()
		done <- s.runInstaller(runCtx, installerRun{Argv: argv, Dir: dir, Log: logf, Inherit: []*os.File{lock}})
	}()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		// The daemon is stopping, most likely because the installer restarted
		// it. The installer carries on in its own session; its directory stays
		// for the log and is removed by the next ApplyUpdate or the uninstall.
		abandoned = true
		log.Info("netd: stopping while the installer runs; it continues in its own session", "dir", dir)
		return s.updateFailed(fmt.Errorf("the helper stopped while the installer ran: %w", ctx.Err()), "")
	}
	tail := logTail(logPath)
	if runErr != nil {
		log.Error("netd: the staged installer failed", "err", runErr, "log", tail)
		return s.updateFailed(fmt.Errorf("the installer failed: %w", runErr), tail)
	}
	log.Info("netd: the staged installer finished")
	resp := s.okResp()
	resp.Phase = wire.UpdatePhaseDone
	resp.Log = tail
	return resp
}

// authorizeUpdatePeer re-checks, on this verb, that the connection's peer is the
// k3sm agent's service uid. The connection already passed the configured
// PeerVerifier at accept; this verb installs software as root, so it reads the
// peer credential itself rather than trust whatever verifier was configured.
func (s *Server) authorizeUpdatePeer(st *connState) error {
	if st == nil || st.conn == nil {
		return fmt.Errorf("%w: no peer credential to check", ErrPeerUnauthorized)
	}
	return newUIDVerifier(s.cfg.ServiceUID).Verify(st.conn)
}

// updateFailed builds the final Failed frame.
func (s *Server) updateFailed(err error, tail string) wire.Response {
	resp := s.errResp(err.Error())
	resp.Phase = wire.UpdatePhaseFailed
	resp.Log = tail
	return resp
}

// validateUpdateArgs checks the shape of the request before anything is
// touched: a clean absolute source, a non-empty manifest of clean relative
// paths and sha256 digests that names the staged k3sm, and a plain version.
func validateUpdateArgs(a *wire.ApplyUpdateArgs) error {
	if !filepath.IsAbs(a.SourceDir) || filepath.Clean(a.SourceDir) != a.SourceDir {
		return fmt.Errorf("%w: sourceDir %q is not a clean absolute path", errUpdateRefused, a.SourceDir)
	}
	if a.Version == "" || len(a.Version) > maxVersionLen || strings.ContainsFunc(a.Version, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return fmt.Errorf("%w: version %q is empty, too long or holds a control or space character", errUpdateRefused, a.Version)
	}
	if len(a.Manifest) == 0 || len(a.Manifest) > wire.MaxUpdateManifestEntries {
		return fmt.Errorf("%w: the manifest names %d files (1..%d)", errUpdateRefused, len(a.Manifest), wire.MaxUpdateManifestEntries)
	}
	if _, ok := a.Manifest["k3sm"]; !ok {
		return fmt.Errorf("%w: the manifest does not name k3sm", errUpdateRefused)
	}
	for rel, sum := range a.Manifest {
		if !validSetPath(rel) {
			return fmt.Errorf("%w: manifest path %q is not a clean relative path", errUpdateRefused, rel)
		}
		if len(sum) != sha256.Size*2 || strings.ToLower(sum) != sum {
			return fmt.Errorf("%w: manifest digest for %q is not a lowercase hex sha256", errUpdateRefused, rel)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return fmt.Errorf("%w: manifest digest for %q is not a lowercase hex sha256", errUpdateRefused, rel)
		}
	}
	return nil
}

// validSetPath reports whether rel is a clean, slash-separated relative path
// with no "." or ".." component.
func validSetPath(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.ContainsRune(rel, 0) || path.Clean(rel) != rel {
		return false
	}
	for _, c := range strings.Split(rel, "/") {
		if c == "." || c == ".." {
			return false
		}
	}
	return true
}

// ensureStagingRoot creates the staging root when it is absent (0700) and
// otherwise requires a real directory, owned by this process's euid, mode 0700.
func ensureStagingRoot(root string) error {
	fi, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create the staging root %s: %w", root, err)
		}
		if err := ownRootOnly(root); err != nil {
			return err
		}
		fi, err = os.Lstat(root)
	}
	if err != nil {
		return fmt.Errorf("inspect the staging root %s: %w", root, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: the staging root %s is not a directory", errUpdateRefused, root)
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Geteuid() || fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: the staging root %s is not a mode 0700 directory owned by this helper", errUpdateRefused, root)
	}
	return nil
}

// ownRootOnly sets dir to mode 0700 and, when this process is root, to
// root:wheel, the owner the installer requires of a staging directory.
func ownRootOnly(dir string) error {
	if os.Geteuid() == 0 {
		if err := os.Lchown(dir, 0, 0); err != nil {
			return fmt.Errorf("chown %s: %w", dir, err)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}

// lockStaging takes the installer's staging lock without waiting. The
// descriptor is close-on-exec here; execInstaller hands the installer its own
// inherited copy, which keeps the lock held for as long as the installer runs.
func lockStaging(lockPath string) (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the staging lock %s: %w", lockPath, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: another install holds the staging lock %s", errUpdateRefused, lockPath)
		}
		return nil, fmt.Errorf("lock %s: %w", lockPath, err)
	}
	return f, nil
}

// sweepUpdateDirs removes the staging directories an earlier ApplyUpdate left
// when this daemon was stopped under its installer. It runs under the staging
// lock, which a still-running installer holds, so a live directory is never
// removed. Only real directories with the ApplyUpdate prefix are touched.
func sweepUpdateDirs(root string, log *slog.Logger) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), updateDirPrefix) || e.Type()&os.ModeType != os.ModeDir {
			continue
		}
		p := filepath.Join(root, e.Name())
		if err := os.RemoveAll(p); err != nil {
			log.Warn("netd: removing a stale update staging directory failed", "dir", p, "err", err)
		}
	}
}

// copyUpdateSet copies the set at src into dst, which exists and is empty, and
// returns the sha256 of every regular file it wrote, by relative path. It never
// follows a symlink: every directory is opened relative to its parent with
// O_NOFOLLOW and every entry is judged by an lstat and again on its open
// descriptor. It refuses a symlink, a special file, a set-id file, an entry not
// owned by uid, a file the manifest does not name, and a set over
// wire.MaxUpdateSetBytes. Permission bits are kept, less group and other write,
// which the installer refuses.
func copyUpdateSet(src, dst string, uid uint32, manifest map[string]string) (map[string]string, error) {
	fd, err := unix.Open(src, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open the set %s: %w", errUpdateRefused, src, err)
	}
	c := &setCopier{uid: uid, manifest: manifest, sums: make(map[string]string)}
	if err := c.dir(fd, src, dst, "", 0); err != nil {
		return nil, err
	}
	return c.sums, nil
}

// setCopier carries one copy's running state.
type setCopier struct {
	uid      uint32
	manifest map[string]string
	total    int64
	sums     map[string]string
}

// dir copies the directory open at fd (closing fd) into dstDir. rel is its
// path inside the set ("" for the set itself).
func (c *setCopier) dir(fd int, srcName, dstDir, rel string, depth int) error {
	f := os.NewFile(uintptr(fd), srcName)
	defer f.Close()
	if depth > maxUpdateDepth {
		return fmt.Errorf("%w: %s is nested deeper than %d", errUpdateRefused, srcName, maxUpdateDepth)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: stat %s: %w", errUpdateRefused, srcName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: %s is not a directory", errUpdateRefused, srcName)
	}
	if st.Uid != c.uid {
		return fmt.Errorf("%w: %s is owned by uid %d, not the service uid %d", errUpdateRefused, srcName, st.Uid, c.uid)
	}
	names, err := f.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("%w: list %s: %w", errUpdateRefused, srcName, err)
	}
	sort.Strings(names)
	for _, name := range names {
		childRel := name
		if rel != "" {
			childRel = rel + "/" + name
		}
		if err := c.entry(fd, srcName, dstDir, name, childRel, depth); err != nil {
			return err
		}
	}
	return nil
}

// entry copies one directory entry of the directory open at parent.
func (c *setCopier) entry(parent int, parentName, dstDir, name, rel string, depth int) error {
	srcName := filepath.Join(parentName, name)
	var lst unix.Stat_t
	if err := unix.Fstatat(parent, name, &lst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("%w: lstat %s: %w", errUpdateRefused, srcName, err)
	}
	switch lst.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return fmt.Errorf("%w: %s is a symlink", errUpdateRefused, srcName)
	case unix.S_IFDIR:
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("%w: open %s: %w", errUpdateRefused, srcName, err)
		}
		dst := filepath.Join(dstDir, name)
		if err := os.Mkdir(dst, 0o700); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("create %s: %w", dst, err)
		}
		if err := c.dir(fd, srcName, dst, rel, depth+1); err != nil {
			return err
		}
		return os.Chmod(dst, setMode(lst.Mode))
	case unix.S_IFREG:
		return c.file(parent, srcName, filepath.Join(dstDir, name), name, rel)
	default:
		return fmt.Errorf("%w: %s is not a regular file or directory", errUpdateRefused, srcName)
	}
}

// file copies one regular file, hashing the bytes it writes.
func (c *setCopier) file(parent int, srcName, dst, name, rel string) error {
	if _, ok := c.manifest[rel]; !ok {
		return fmt.Errorf("%w: %s is not in the manifest", errUpdateRefused, rel)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("%w: open %s: %w", errUpdateRefused, srcName, err)
	}
	in := os.NewFile(uintptr(fd), srcName)
	defer in.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: stat %s: %w", errUpdateRefused, srcName, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%w: %s is not a regular file", errUpdateRefused, srcName)
	case st.Uid != c.uid:
		return fmt.Errorf("%w: %s is owned by uid %d, not the service uid %d", errUpdateRefused, srcName, st.Uid, c.uid)
	case st.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0:
		return fmt.Errorf("%w: %s carries a set-id or sticky bit", errUpdateRefused, srcName)
	}
	room := wire.MaxUpdateSetBytes - c.total
	if st.Size > room {
		return fmt.Errorf("%w: the set is larger than %d bytes", errUpdateRefused, wire.MaxUpdateSetBytes)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, room+1))
	if err == nil && n > room {
		err = fmt.Errorf("%w: the set is larger than %d bytes", errUpdateRefused, wire.MaxUpdateSetBytes)
	}
	if err == nil {
		err = out.Chmod(setMode(st.Mode))
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("copy %s: %w", srcName, err)
	}
	c.total += n
	c.sums[rel] = hex.EncodeToString(h.Sum(nil))
	return nil
}

// setMode is the permission a staged copy carries: the source's permission
// bits without group or other write.
func setMode(mode uint16) os.FileMode {
	return os.FileMode(mode) & 0o755
}

// checkManifest compares the digests of the copied files with the manifest:
// every manifest file must have been copied, and with the same digest. (A
// copied file the manifest does not name was refused during the copy.)
func checkManifest(manifest, got map[string]string) error {
	rels := make([]string, 0, len(manifest))
	for rel := range manifest {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		sum, ok := got[rel]
		if !ok {
			return fmt.Errorf("%w: %s is in the manifest but not in the set", errUpdateRefused, rel)
		}
		if sum != manifest[rel] {
			return fmt.Errorf("%w: %s has sha256 %s, the manifest says %s", errUpdateRefused, rel, sum, manifest[rel])
		}
	}
	for rel := range got {
		if _, ok := manifest[rel]; !ok {
			return fmt.Errorf("%w: %s is not in the manifest", errUpdateRefused, rel)
		}
	}
	return nil
}

// logTail returns the last updateLogTailLines lines of the installer log, from
// at most its last updateLogTailBytes bytes.
func logTail(logPath string) string {
	f, err := os.Open(logPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	off := max(fi.Size()-updateLogTailBytes, 0)
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if off > 0 && len(lines) > 1 {
		lines = lines[1:] // the first line was cut by the byte bound
	}
	if len(lines) > updateLogTailLines {
		lines = lines[len(lines)-updateLogTailLines:]
	}
	return strings.Join(lines, "\n")
}

// emitPhase sends one intermediate ApplyUpdate frame. A failed send is logged
// and ignored: the update continues whether or not the caller is listening.
func (c *connState) emitPhase(s *Server, phase wire.UpdatePhase) {
	if c == nil || c.emit == nil {
		return
	}
	resp := s.okResp()
	resp.Phase = phase
	if err := c.emit(resp); err != nil {
		s.log.Debug("netd: sending an applyUpdate phase failed", "phase", phase, "err", err)
	}
}
