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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// systemCodesign is the code-signing tool ApplyUpdate runs, by absolute path
// and never through PATH.
const systemCodesign = "/usr/bin/codesign"

// codesignTimeout bounds one codesign run; codesignOutputBytes bounds what is
// kept of its output.
const (
	codesignTimeout     = time.Minute
	codesignOutputBytes = 64 << 10
)

// developerIDAnchor is the Developer ID requirement: a chain anchored at
// Apple through the Developer ID intermediate (certificate 1 carries
// 1.2.840.113635.100.6.2.6) to a Developer ID Application leaf (which carries
// 1.2.840.113635.100.6.1.13). An Apple-signed system binary, an Apple
// Development or Mac App Store signature, an ad-hoc signature and a chain to
// any other anchor all fail it.
const developerIDAnchor = `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists`

// teamIDLen is the length of an Apple Team ID.
const teamIDLen = 10

// validTeamID reports whether id has the shape of an Apple Team ID: ten
// characters from A-Z and 0-9.
func validTeamID(id string) bool {
	if len(id) != teamIDLen {
		return false
	}
	for _, c := range id {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// developerIDRequirement is developerIDAnchor narrowed to a leaf issued to
// team, the requirement the k3sm installer checks a staged build against. team
// must be a validTeamID, so it needs no quoting.
func developerIDRequirement(team string) string {
	return developerIDAnchor + ` and certificate leaf[subject.OU] = "` + team + `"`
}

// codeSignature is what the code-signing policy needs to know of one Mach-O.
type codeSignature struct {
	// Valid is true when `codesign --verify --strict` accepted the file.
	Valid bool
	// TeamID is the TeamIdentifier `codesign -dv` reports, empty for an
	// ad-hoc signature or none. On its own it proves nothing: see team.
	TeamID string
	// DeveloperID is true when the file also satisfies
	// developerIDRequirement(TeamID).
	DeveloperID bool
}

// team is the signing team the policy counts: TeamID when the signature is
// valid and satisfies the Developer ID requirement for it, and "" (no team)
// otherwise. A file that verifies but is ad hoc, Apple-signed, signed with a
// non-Developer ID certificate or anchored anywhere but Apple has no team.
func (c codeSignature) team() string {
	if c.Valid && c.DeveloperID && validTeamID(c.TeamID) {
		return c.TeamID
	}
	return ""
}

// codeInspector reads a Mach-O's code signature. It is the seam the unit tests
// replace; the production implementation runs systemCodesign.
type codeInspector interface {
	// Inspect reports path's signature. Only a failure to run the tool is an
	// error; a signature that does not verify is a zero codeSignature.
	Inspect(ctx context.Context, path string) (codeSignature, error)
}

// codesignTool is the production codeInspector: `codesign --verify --strict`;
// on a valid signature `codesign -dv` for the Team ID; and, when that is a
// Team ID, `codesign --verify --strict -R=<developerIDRequirement(team)>`, so
// a team counts only behind a Developer ID signature issued to it. Each run
// has a fixed argv, an empty environment but a fixed PATH, a timeout, and
// bounded output.
type codesignTool struct{}

// Inspect implements codeInspector.
func (codesignTool) Inspect(ctx context.Context, path string) (codeSignature, error) {
	if !filepath.IsAbs(path) {
		return codeSignature{}, fmt.Errorf("codesign: %q is not an absolute path", path)
	}
	ok, _, err := runCodesign(ctx, "--verify", "--strict", path)
	if err != nil || !ok {
		return codeSignature{}, err
	}
	ok, out, err := runCodesign(ctx, "-dv", path)
	if err != nil || !ok {
		return codeSignature{}, err
	}
	sig := codeSignature{Valid: true, TeamID: parseCodesignTeam(out)}
	if validTeamID(sig.TeamID) {
		ok, _, err := runCodesign(ctx, "--verify", "--strict", "-R="+developerIDRequirement(sig.TeamID), path)
		if err != nil {
			return codeSignature{}, err
		}
		sig.DeveloperID = ok
	}
	return sig, nil
}

// runCodesign runs systemCodesign with args and reports whether it exited 0
// and its combined output. Only a failure to run the tool is an error.
func runCodesign(ctx context.Context, args ...string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, codesignTimeout)
	defer cancel()
	out := &capBuffer{max: codesignOutputBytes}
	cmd := exec.CommandContext(ctx, systemCodesign, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	if err == nil {
		return true, out.String(), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return false, out.String(), nil
	}
	return false, "", fmt.Errorf("run %s: %w", systemCodesign, err)
}

// parseCodesignTeam reads the Team ID from `codesign -dv` output: the value of
// TeamIdentifier, or "" when it is "not set" (an ad-hoc signature) or absent.
func parseCodesignTeam(out string) string {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "TeamIdentifier" && val != "not set" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

// capBuffer keeps at most max bytes of what is written to it and discards the
// rest, so a runaway tool cannot grow this daemon's memory.
type capBuffer struct {
	bytes.Buffer
	max int
}

// Write implements io.Writer, always reporting the whole write.
func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// machOMagics are the first four bytes of a Mach-O (MH_MAGIC, MH_MAGIC_64) or
// a universal binary (FAT_MAGIC, FAT_MAGIC_64), in either byte order: the set
// the k3sm installer's isMachOMagic recognises.
var machOMagics = []uint32{
	0xfeedface, 0xcefaedfe, // MH_MAGIC
	0xfeedfacf, 0xcffaedfe, // MH_MAGIC_64
	0xcafebabe, 0xbebafeca, // FAT_MAGIC
	0xcafebabf, 0xbfbafeca, // FAT_MAGIC_64
}

// updatePayloadMarkers are the cp-payload files that are data, not code: the
// version markers the k3sm installer copies beside the payload and never
// executes or loads. They are the only staged files that may be something
// other than a Mach-O. The installer's signing scan skips every non-Mach-O
// file; netd skips only these, and checks one of them like any other member
// when it is a Mach-O.
var updatePayloadMarkers = []string{
	updatePayloadDir + "/etcd.version",
	updatePayloadDir + "/etcdutl.version",
	updatePayloadDir + "/kine.version",
	updatePayloadDir + "/kube.version",
}

// isMachO reports whether the regular file at p starts with a Mach-O magic.
func isMachO(p string) (bool, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", p, err)
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", p, err)
	}
	m := binary.BigEndian.Uint32(hdr[:])
	for _, want := range machOMagics {
		if m == want {
			return true, nil
		}
	}
	return false, nil
}

// stagedSigningSet lists, sorted, the slash-separated relative paths of the
// staged files the signing policy checks: every regular file under dir (the
// updateSetFiles at the top and the whole cp-payload tree), each of which must
// be a Mach-O. A file that is not one refuses before any signature is read,
// except an updatePayloadMarkers file, which is skipped. Anything under dir
// that is neither a directory nor a regular file refuses.
func stagedSigningSet(dir string) ([]string, error) {
	var out []string
	var refusal error
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			refusal = fmt.Errorf("%w: the staged %s is not a regular file", errUpdateRefused, rel)
			return fs.SkipAll
		}
		ok, err := isMachO(p)
		switch {
		case err != nil:
			return err
		case ok:
			out = append(out, rel)
		case slices.Contains(updatePayloadMarkers, rel):
		default:
			refusal = fmt.Errorf("%w: the staged %s is not a Mach-O, and every member of the build set must be one", errUpdateRefused, rel)
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list the staged build set: %w", err)
	}
	if refusal != nil {
		return nil, refusal
	}
	sort.Strings(out)
	for _, m := range updateSetFiles {
		if i := sort.SearchStrings(out, m); i == len(out) || out[i] != m {
			return nil, fmt.Errorf("%w: the staged set carries no Mach-O %s", errUpdateRefused, m)
		}
	}
	return out, nil
}

// checkCodeSigning applies the update code-signing policy to the staged tree
// (the signature of every member of stagedSigningSet, by relative path)
// against the installed k3sm's signature. A team is a Developer ID team
// (codeSignature.team): a TeamIdentifier without a Developer ID signature
// issued to it counts as no team, on the installed k3sm and in the tree.
//
//   - every staged member must be validly signed;
//   - a team-signed install requires every staged member to carry that team;
//   - an install with no team accepts a tree with no team throughout or a
//     tree signed throughout by one team;
//   - requireTeam (the payload's signature: required) refuses a tree without a
//     team;
//   - a tree that mixes teams, or a team with no team, is refused.
func checkCodeSigning(installed codeSignature, tree map[string]codeSignature, requireTeam bool) error {
	if !installed.Valid {
		return fmt.Errorf("%w: the installed k3sm's code signature does not verify, so no signing policy applies", errUpdateRefused)
	}
	rels := make([]string, 0, len(tree))
	for rel := range tree {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	teams := map[string]string{} // team -> first file carrying it
	for _, rel := range rels {
		sig := tree[rel]
		if !sig.Valid {
			return fmt.Errorf("%w: the staged %s is not validly signed", errUpdateRefused, rel)
		}
		if want := installed.team(); want != "" && sig.team() != want {
			return fmt.Errorf("%w: the installed k3sm is signed by team %s and the staged %s by %s", errUpdateRefused, want, rel, signerName(sig))
		}
		if _, ok := teams[sig.team()]; !ok {
			teams[sig.team()] = rel
		}
	}
	if len(teams) > 1 {
		names := make([]string, 0, len(teams))
		for _, rel := range teams {
			names = append(names, rel+" by "+signerName(tree[rel]))
		}
		sort.Strings(names)
		return fmt.Errorf("%w: the staged tree mixes signers (%s)", errUpdateRefused, strings.Join(names, ", "))
	}
	if _, adhoc := teams[""]; requireTeam && adhoc {
		return fmt.Errorf("%w: the payload requires a team signature (Developer ID) and the staged %s carries none (%s)", errUpdateRefused, teams[""], signerName(tree[teams[""]]))
	}
	return nil
}

// signerName renders a signature's counted signer for a message.
func signerName(sig codeSignature) string {
	switch {
	case sig.team() != "":
		return "team " + sig.team()
	case sig.TeamID != "":
		return "no team (" + sig.TeamID + " without a Developer ID signature)"
	}
	return "no team (ad hoc or not Developer ID)"
}

// inspectStagedTree inspects every member of stagedSigningSet and the
// installed k3sm.
func inspectStagedTree(ctx context.Context, in codeInspector, dir, installedPath string) (codeSignature, map[string]codeSignature, error) {
	rels, err := stagedSigningSet(dir)
	if err != nil {
		return codeSignature{}, nil, err
	}
	installed, err := in.Inspect(ctx, installedPath)
	if err != nil {
		return codeSignature{}, nil, fmt.Errorf("inspect the installed %s: %w", installedPath, err)
	}
	tree := make(map[string]codeSignature, len(rels))
	for _, rel := range rels {
		sig, err := in.Inspect(ctx, filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return codeSignature{}, nil, fmt.Errorf("inspect the staged %s: %w", rel, err)
		}
		tree[rel] = sig
	}
	return installed, tree, nil
}
