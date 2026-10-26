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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
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

// DefaultInstalledK3sm is the installed k3sm binary whose code signature and
// version the update policy compares the staged build against.
const DefaultInstalledK3sm = "/Library/k3sm/k3sm"

// Bounds on the request, the reply and the installed-version probe.
const (
	updateLogTailLines   = 40
	updateLogTailBytes   = 8 << 10
	maxVersionLen        = 128
	maxClusterCABytes    = 1 << 20
	versionProbeTimeout  = 30 * time.Second
	versionProbeMaxBytes = 4 << 10
)

// updateAckTimeout bounds the wait, after the Installing frame and before the
// exec, for the client's acknowledgement: the node writes its Restarting phase
// on that frame and then acknowledges, so the installer, which stops the node's
// daemon, starts only after that write landed. A missing ack costs this much
// and no more; the exec then goes ahead.
const updateAckTimeout = 3 * time.Second

// releaseTagGrammar is the release tag a signed payload may name.
var releaseTagGrammar = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// updatePayload is the signed payload the update controller wrote on the Node.
// Every decision ApplyUpdate takes from the request comes from here, after the
// signature over its bytes verified.
type updatePayload struct {
	// Version is the release tag being installed.
	Version string `json:"version"`
	// URL is where the agent downloaded the archive from. The daemon fetches
	// nothing and does not read it.
	URL string `json:"url"`
	// SHA256 is the archive's lowercase hex sha256.
	SHA256 string `json:"sha256"`
	// Signature is the code-signing policy: if-signed (also when empty) or
	// required.
	Signature updatesv1alpha1.UpdateSignaturePolicy `json:"signature"`
	// AllowDowngrade permits a tag below the installed build.
	AllowDowngrade bool `json:"allowDowngrade,omitempty"`
}

// requireTeam reports whether the payload refuses a tree without a team
// signature.
func (p updatePayload) requireTeam() bool {
	return p.Signature == updatesv1alpha1.UpdateSignatureRequired
}

// policyName is the payload's code-signing policy for a log line: an empty
// policy is if-signed.
func (p updatePayload) policyName() string {
	if p.Signature == "" {
		return string(updatesv1alpha1.UpdateSignatureIfSigned)
	}
	return string(p.Signature)
}

// installedVersionFunc reports the release version of the installed k3sm at
// path. It is the seam the unit tests replace.
type installedVersionFunc func(ctx context.Context, path string) (string, error)

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

// handleApplyUpdate serves VerbApplyUpdate. The steps run in a fixed order,
// each refusal is a Failed frame with the reason, and no step runs after a
// refusal:
//
//  1. the caller is the service uid;
//  2. Verifying: the signer certificate chains to the cluster CA and names the
//     update signer, the signature over the payload verifies, and the payload
//     parses with a release tag;
//  3. the archive, opened without following a symlink, is a regular file the
//     service uid owns, and the bytes netd copies out of it into a root-only
//     file hash to the payload's sha256;
//  4. netd extracts that copy itself into a fresh root-only staging directory;
//  5. every member of the staged set is a Mach-O (cp-payload version markers,
//     by shape, aside) and passes the code-signing policy against the installed
//     k3sm, where a team counts only behind a Developer ID signature; then the
//     downgrade check;
//  6. Installing: the client's acknowledgement of that frame, awaited for at
//     most updateAckTimeout; a daemon stop during that wait is a Failed frame
//     and no exec (the stop cannot be the update's own restart, which only the
//     installer performs); then the one exec of the staged k3sm, then Done or
//     Failed.
//
// Nothing from the archive runs before every check passed, and nothing but the
// staged k3sm ever runs. The reply is a stream: emit sends the intermediate
// phases and the returned response is the final frame. emit is nil when no
// connection is attached.
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
	st.emitPhase(s, wire.UpdatePhaseVerifying)

	payload, err := s.verifyUpdatePayload(args)
	if err != nil {
		s.log.Warn("netd: update payload refused", "err", err)
		return s.updateFailed(err, "")
	}
	log := s.log.With("version", payload.Version)
	archive, err := openUpdateArchive(args.ArchivePath, s.cfg.ServiceUID)
	if err != nil {
		log.Warn("netd: update archive refused", "archive", args.ArchivePath, "err", err)
		return s.updateFailed(err, "")
	}
	defer archive.Close()

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

	copied, err := copyVerifiedArchive(archive, root, payload.SHA256)
	if err != nil {
		log.Warn("netd: update archive refused", "archive", args.ArchivePath, "err", err)
		return s.updateFailed(err, "")
	}
	defer copied.Close()
	log.Info("netd: update archive digest matched", "sha256", payload.SHA256)

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
	if err := extractUpdateArchive(copied, dir); err != nil {
		log.Warn("netd: update archive refused", "archive", args.ArchivePath, "err", err)
		return s.updateFailed(err, "")
	}
	_ = copied.Close()

	set, err := stagedSigningSet(dir)
	if err != nil {
		log.Warn("netd: update code signing refused", "err", err)
		return s.updateFailed(err, "")
	}
	log.Info("netd: update set extracted", "members", set.Members, "macho", len(set.MachOs),
		"markers-skipped", len(set.Markers), "markers", set.Markers)
	installed, tree, err := inspectStagedTree(ctx, s.inspector, dir, set, s.installedK3sm)
	if err == nil {
		err = checkCodeSigning(installed, tree, payload.requireTeam())
	}
	if err != nil {
		log.Warn("netd: update code signing refused", "err", err)
		return s.updateFailed(err, "")
	}
	log.Info("netd: update code signing accepted", "signer", treeSigner(tree),
		"installed-signer", signerName(installed), "policy", payload.policyName())
	if payload.AllowDowngrade {
		log.Info("netd: update version compare skipped: the payload allows a downgrade")
	} else {
		installedVersion, err := s.checkNotDowngrade(ctx, payload.Version)
		if err != nil {
			log.Warn("netd: update refused as a downgrade", "err", err)
			return s.updateFailed(err, "")
		}
		log.Info("netd: update version compare passed", "installed", installedVersion)
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
	if payload.AllowDowngrade {
		argv = append(argv, "--allow-downgrade")
	}
	st.emitPhase(s, wire.UpdatePhaseInstalling)
	if err := st.awaitUpdateAck(); err != nil {
		log.Warn("netd: the client did not acknowledge Installing; running the installer anyway",
			"bound", updateAckTimeout, "err", err)
	}
	// A daemon stop during the wait must not start the installer. The stop
	// cannot be the update's own restart of this daemon: the installer, which
	// performs that restart, has not run yet.
	if err := ctx.Err(); err != nil {
		log.Info("netd: stopping before the installer ran; the update is not applied", "dir", dir)
		return s.updateFailed(fmt.Errorf("the helper is stopping; the installer did not run: %w", err), "")
	}
	log.Info("netd: running the staged installer", "dir", dir, "argv", argv)

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

// verifyUpdatePayload checks the request's chain of trust and returns the
// payload it authorises: the cluster CA is configured and loads (re-read while
// none is loaded), the signer certificate
// chains to it (the system roots excluded) within its validity, carries the
// Code Signing extended key usage and names the update signer, the ECDSA signature verifies over sha256(Payload), and the
// payload parses with a release tag, a sha256 and a known signing policy.
func (s *Server) verifyUpdatePayload(a *wire.ApplyUpdateArgs) (updatePayload, error) {
	s.loadClusterCALocked()
	if s.clusterCA == nil {
		return updatePayload{}, fmt.Errorf("%w: no cluster CA is configured (%v), so no update can be verified", errUpdateRefused, s.clusterCAErr)
	}
	signer, err := parseSignerCert(a.SignerCert)
	if err != nil {
		return updatePayload{}, err
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots:       s.clusterCA,
		CurrentTime: s.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return updatePayload{}, fmt.Errorf("%w: the signer certificate does not chain to the cluster CA: %w", errUpdateRefused, err)
	}
	// x509.Verify treats a leaf with no extended key usage as valid for any
	// usage, so the Code Signing EKU is required of the leaf explicitly: a
	// client certificate under the same CA can never stand in for the signer.
	if !slices.Contains(signer.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return updatePayload{}, fmt.Errorf("%w: the signer certificate does not carry the Code Signing extended key usage", errUpdateRefused)
	}
	if signer.Subject.CommonName != wire.UpdateSignerCommonName || !slices.Contains(signer.Subject.Organization, wire.UpdateSignerOrganization) {
		return updatePayload{}, fmt.Errorf("%w: the signer certificate names CN=%q O=%q, not CN=%q O=%q", errUpdateRefused,
			signer.Subject.CommonName, signer.Subject.Organization, wire.UpdateSignerCommonName, wire.UpdateSignerOrganization)
	}
	s.log.Info("netd: update signer accepted", "cn", signer.Subject.CommonName,
		"serial", signer.SerialNumber.String(), "not-after", signer.NotAfter.UTC().Format(time.RFC3339))
	pub, ok := signer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return updatePayload{}, fmt.Errorf("%w: the signer key is %T, not ECDSA", errUpdateRefused, signer.PublicKey)
	}
	digest := sha256.Sum256(a.Payload)
	if !ecdsa.VerifyASN1(pub, digest[:], a.Signature) {
		return updatePayload{}, fmt.Errorf("%w: the payload signature does not verify", errUpdateRefused)
	}
	s.log.Info("netd: update payload signature verified")
	return parseUpdatePayload(a.Payload)
}

// loadClusterCALocked re-reads Config.ClusterCAPath when no cluster CA is
// loaded yet: a fresh server install starts this daemon before the cluster PKI
// exists, and the first update after the CA appears must not need a restart.
// A loaded CA is kept and never re-read. An empty path is not retried. The
// caller holds updateMu.
func (s *Server) loadClusterCALocked() {
	if s.clusterCA != nil || s.cfg.ClusterCAPath == "" {
		return
	}
	pool, err := loadClusterCA(s.cfg.ClusterCAPath)
	if err != nil {
		s.clusterCAErr = err
		return
	}
	s.clusterCA, s.clusterCAErr = pool, nil
	s.log.Info("netd: loaded the cluster CA for applyUpdate", "path", s.cfg.ClusterCAPath)
}

// parseSignerCert decodes the one PEM certificate the request carries.
func parseSignerCert(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: the signer certificate is not a PEM CERTIFICATE", errUpdateRefused)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: the signer certificate PEM holds more than one block", errUpdateRefused)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse the signer certificate: %w", errUpdateRefused, err)
	}
	return cert, nil
}

// parseUpdatePayload decodes the verified payload strictly and checks its
// fields.
func parseUpdatePayload(raw []byte) (updatePayload, error) {
	var p updatePayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return updatePayload{}, fmt.Errorf("%w: the payload is not valid JSON: %w", errUpdateRefused, err)
	}
	if dec.More() {
		return updatePayload{}, fmt.Errorf("%w: the payload holds more than one JSON value", errUpdateRefused)
	}
	if len(p.Version) > maxVersionLen || !releaseTagGrammar.MatchString(p.Version) {
		return updatePayload{}, fmt.Errorf("%w: the payload version %q is not a release tag", errUpdateRefused, p.Version)
	}
	if len(p.SHA256) != sha256.Size*2 || strings.ToLower(p.SHA256) != p.SHA256 {
		return updatePayload{}, fmt.Errorf("%w: the payload sha256 is not a lowercase hex sha256", errUpdateRefused)
	}
	if _, err := hex.DecodeString(p.SHA256); err != nil {
		return updatePayload{}, fmt.Errorf("%w: the payload sha256 is not a lowercase hex sha256", errUpdateRefused)
	}
	switch p.Signature {
	case "", updatesv1alpha1.UpdateSignatureIfSigned, updatesv1alpha1.UpdateSignatureRequired:
	default:
		return updatePayload{}, fmt.Errorf("%w: unknown signature policy %q", errUpdateRefused, p.Signature)
	}
	return p, nil
}

// loadClusterCA reads the cluster CA certificates (PEM) at path into a pool.
// Every certificate in the file must be a CA.
func loadClusterCA(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("netd was started without --cluster-ca")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open the cluster CA: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxClusterCABytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the cluster CA %s: %w", path, err)
	}
	if len(raw) > maxClusterCABytes {
		return nil, fmt.Errorf("the cluster CA %s is larger than %d bytes", path, maxClusterCABytes)
	}
	pool := x509.NewCertPool()
	n := 0
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse the cluster CA %s: %w", path, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("the cluster CA %s holds a certificate that is not a CA (%s)", path, cert.Subject)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("the cluster CA %s holds no PEM certificate", path)
	}
	return pool, nil
}

// openUpdateArchive opens the archive without following a final symlink and
// requires a clean absolute path, a regular file, the service uid as owner,
// and at most wire.MaxUpdateArchiveBytes.
func openUpdateArchive(p string, uid uint32) (*os.File, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return nil, fmt.Errorf("%w: the archive path %q is not a clean absolute path", errUpdateRefused, p)
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open the archive %s: %w", errUpdateRefused, p, err)
	}
	f := os.NewFile(uintptr(fd), p)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: stat the archive %s: %w", errUpdateRefused, p, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		err = fmt.Errorf("%w: the archive %s is not a regular file", errUpdateRefused, p)
	case st.Uid != uid:
		err = fmt.Errorf("%w: the archive %s is owned by uid %d, not the service uid %d", errUpdateRefused, p, st.Uid, uid)
	case st.Size > wire.MaxUpdateArchiveBytes:
		err = fmt.Errorf("%w: the archive %s is larger than %d bytes", errUpdateRefused, p, wire.MaxUpdateArchiveBytes)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// copyVerifiedArchive copies the archive into an unlinked root-only file
// under root, hashing the bytes as it writes them, and returns that copy at
// offset 0 when they hash to want. The extraction then reads the copy, so the
// service uid, which owns the original, cannot change the bytes after they
// were hashed.
func copyVerifiedArchive(archive *os.File, root, want string) (*os.File, error) {
	tmp, err := os.CreateTemp(root, updateDirPrefix+"archive-")
	if err != nil {
		return nil, fmt.Errorf("create the archive copy in %s: %w", root, err)
	}
	if err := os.Remove(tmp.Name()); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("unlink the archive copy %s: %w", tmp.Name(), err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(archive, wire.MaxUpdateArchiveBytes+1))
	switch {
	case err != nil:
		err = fmt.Errorf("%w: read the archive: %w", errUpdateRefused, err)
	case n > wire.MaxUpdateArchiveBytes:
		err = fmt.Errorf("%w: the archive is larger than %d bytes", errUpdateRefused, wire.MaxUpdateArchiveBytes)
	default:
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			err = fmt.Errorf("%w: the archive has sha256 %s, the signed payload says %s", errUpdateRefused, got, want)
		}
	}
	if err == nil {
		_, err = tmp.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = tmp.Close()
		return nil, err
	}
	return tmp, nil
}

// checkNotDowngrade refuses a version below the installed k3sm's, and refuses
// when the two cannot be ordered (an installed dev build, say): without
// allowDowngrade the daemon installs only what it can prove is not older. It
// returns the installed version it compared against.
func (s *Server) checkNotDowngrade(ctx context.Context, version string) (string, error) {
	installed, err := s.installedVersion(ctx, s.installedK3sm)
	if err != nil {
		return "", fmt.Errorf("%w: read the installed version: %w", errUpdateRefused, err)
	}
	cmp, ok := compareReleases(version, installed)
	switch {
	case !ok:
		return "", fmt.Errorf("%w: %s cannot be ordered against the installed %q; the payload must allow a downgrade", errUpdateRefused, version, installed)
	case cmp < 0:
		return "", fmt.Errorf("%w: %s is below the installed %s and the payload does not allow a downgrade", errUpdateRefused, version, installed)
	}
	return installed, nil
}

// probeInstalledVersion is the production installedVersionFunc: it runs
// `<path> version` with a fixed argv and environment, bounded in time and
// output, and returns the tag of its first line ("k3sm <tag>").
func probeInstalledVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, versionProbeTimeout)
	defer cancel()
	out := &capBuffer{max: versionProbeMaxBytes}
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run %s version: %w", path, err)
	}
	return parseVersionOutput(out.String())
}

// parseVersionOutput reads the tag from `k3sm version` output.
func parseVersionOutput(out string) (string, error) {
	first, _, _ := strings.Cut(out, "\n")
	name, tag, ok := strings.Cut(strings.TrimSpace(first), " ")
	if !ok || name != "k3sm" || tag == "" || strings.ContainsAny(tag, " \t") {
		return "", fmt.Errorf("unexpected version output %q", first)
	}
	return tag, nil
}

// releaseSemver matches MAJOR.MINOR.PATCH, an optional prerelease and optional
// build metadata (ignored for ordering), with an optional leading "v".
var releaseSemver = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$`)

// pseudoPrerelease is the tail of a Go pseudo-version prerelease: a build of
// an untagged commit, which is not a release.
var pseudoPrerelease = regexp.MustCompile(`(^|\.)\d{14}-[0-9a-f]{12}$`)

// releaseVersion is a parsed release version.
type releaseVersion struct {
	core [3]uint64
	pre  []string
}

// parseRelease parses a tagged release version, or false for anything else (a
// dev build, a pseudo-version, garbage).
func parseRelease(s string) (releaseVersion, bool) {
	m := releaseSemver.FindStringSubmatch(s)
	if m == nil {
		return releaseVersion{}, false
	}
	var v releaseVersion
	for i := range 3 {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return releaseVersion{}, false
		}
		v.core[i] = n
	}
	if m[4] != "" {
		if pseudoPrerelease.MatchString(m[4]) {
			return releaseVersion{}, false
		}
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

// compareReleases orders two release versions by semver precedence: -1, 0 or
// 1 as a sorts before, with or after b; ok is false when either is not a
// tagged release. Ported from k3sm's pkg/version CompareReleases (Apache-2.0,
// The k3sm Authors).
func compareReleases(a, b string) (int, bool) {
	va, okA := parseRelease(a)
	vb, okB := parseRelease(b)
	if !okA || !okB {
		return 0, false
	}
	for i := range 3 {
		if va.core[i] != vb.core[i] {
			if va.core[i] < vb.core[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return comparePrerelease(va.pre, vb.pre), true
}

// comparePrerelease orders two prerelease lists (semver §11): none sorts after
// any, numeric identifiers compare numerically and before alphanumeric ones,
// and a shorter prefix sorts first.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := comparePreIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// comparePreIdent orders two prerelease identifiers.
func comparePreIdent(a, b string) int {
	na, errA := strconv.ParseUint(a, 10, 64)
	nb, errB := strconv.ParseUint(b, 10, 64)
	switch {
	case errA == nil && errB == nil:
		switch {
		case na < nb:
			return -1
		case na > nb:
			return 1
		}
		return 0
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
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
// when this daemon was stopped under its installer (and an archive copy a
// crash left before it was unlinked). It runs under the staging
// lock, which a still-running installer holds, so a live directory is never
// removed. Only real directories and regular files with the ApplyUpdate prefix are
// touched; a symlink or any other type is left alone.
func sweepUpdateDirs(root string, log *slog.Logger) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), updateDirPrefix) || (e.Type()&os.ModeType != os.ModeDir && !e.Type().IsRegular()) {
			continue
		}
		p := filepath.Join(root, e.Name())
		if err := os.RemoveAll(p); err != nil {
			log.Warn("netd: removing a stale update staging directory failed", "dir", p, "err", err)
		}
	}
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

// maxAckVerbLog caps the bytes of a peer-chosen verb that reach a log line
// when a frame read as the acknowledgement is not one.
const maxAckVerbLog = 64

// errNotUpdateAck is returned by readUpdateAck for a frame that is not the
// acknowledgement.
var errNotUpdateAck = errors.New("the frame is not an acknowledgement")

// awaitUpdateAck waits, bounded by updateAckTimeout, for the client's
// acknowledgement of the Installing frame. It returns nil at once when no
// connection is attached, and the reason otherwise when no ack arrived: the
// bound expired, the client closed its end, or it sent something else (which
// is consumed and not answered).
func (c *connState) awaitUpdateAck() error {
	if c == nil || c.awaitAck == nil {
		return nil
	}
	return c.awaitAck(updateAckTimeout)
}

// readUpdateAck reads one frame from conn within d and requires it to be the
// acknowledgement: a Hello request of a compatible major. The frame is held to
// the configured request cap. The connection loop re-arms its own read
// deadline before the next request, so the one set here does not outlive the
// verb.
func (s *Server) readUpdateAck(conn *net.UnixConn, d time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		return fmt.Errorf("arm the acknowledgement deadline: %w", err)
	}
	payload, err := wire.ReadFrame(conn, s.cfg.MaxRequestBytes)
	if err != nil {
		return fmt.Errorf("read the acknowledgement: %w", err)
	}
	var req wire.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return fmt.Errorf("%w: decode: %w", errNotUpdateAck, err)
	}
	if !req.Version.Compatible() || req.Verb != wire.VerbHello {
		verb := string(req.Verb)
		if len(verb) > maxAckVerbLog {
			verb = verb[:maxAckVerbLog] + "..."
		}
		return fmt.Errorf("%w: a %q request of protocol %d.%d, want %q", errNotUpdateAck,
			verb, req.Version.Major, req.Version.Minor, wire.VerbHello)
	}
	return nil
}
