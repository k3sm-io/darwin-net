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

// codeSignature is what the code-signing policy needs to know of one Mach-O.
type codeSignature struct {
	// Valid is true when `codesign --verify --strict` accepted the file.
	Valid bool
	// TeamID is the signing team, empty for an ad-hoc signature or none.
	TeamID string
}

// codeInspector reads a Mach-O's code signature. It is the seam the unit tests
// replace; the production implementation runs systemCodesign.
type codeInspector interface {
	// Inspect reports path's signature. Only a failure to run the tool is an
	// error; a signature that does not verify is a zero codeSignature.
	Inspect(ctx context.Context, path string) (codeSignature, error)
}

// codesignTool is the production codeInspector: `codesign --verify --strict`
// and, on a valid signature, `codesign -dv` for the Team ID, each with a fixed
// argv, an empty environment but a fixed PATH, a timeout, and bounded output.
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
	return codeSignature{Valid: true, TeamID: parseCodesignTeam(out)}, nil
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

// machOMagics are the first four bytes of a Mach-O or a universal binary, in
// either byte order.
var machOMagics = []uint32{0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca}

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

// stagedMachOs lists, sorted, the slash-separated relative paths of the Mach-O
// files under dir. The staged k3sm must be one of them.
func stagedMachOs(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ok, err := isMachO(p)
		if err != nil || !ok {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list the staged Mach-O files: %w", err)
	}
	sort.Strings(out)
	if i := sort.SearchStrings(out, "k3sm"); i == len(out) || out[i] != "k3sm" {
		return nil, fmt.Errorf("%w: the staged k3sm is not a Mach-O", errUpdateRefused)
	}
	return out, nil
}

// checkCodeSigning applies the update code-signing policy to the staged tree
// (the signature of every staged Mach-O, by relative path) against the
// installed k3sm's signature:
//
//   - every staged Mach-O must be validly signed;
//   - a team-signed install requires every staged Mach-O to carry that team;
//   - an ad-hoc install accepts an all-ad-hoc tree or a tree signed throughout
//     by one team;
//   - requireTeam (the payload's signature: required) refuses a tree without a
//     team;
//   - a tree that mixes teams, or a team with ad-hoc, is refused.
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
		if installed.TeamID != "" && sig.TeamID != installed.TeamID {
			return fmt.Errorf("%w: the installed k3sm is signed by team %s and the staged %s by %s", errUpdateRefused, installed.TeamID, rel, teamName(sig.TeamID))
		}
		if _, ok := teams[sig.TeamID]; !ok {
			teams[sig.TeamID] = rel
		}
	}
	if len(teams) > 1 {
		names := make([]string, 0, len(teams))
		for team, rel := range teams {
			names = append(names, rel+" by "+teamName(team))
		}
		sort.Strings(names)
		return fmt.Errorf("%w: the staged tree mixes signers (%s)", errUpdateRefused, strings.Join(names, ", "))
	}
	if _, adhoc := teams[""]; requireTeam && adhoc {
		return fmt.Errorf("%w: the payload requires a team signature and the staged tree carries none", errUpdateRefused)
	}
	return nil
}

// teamName renders a Team ID for a message.
func teamName(team string) string {
	if team == "" {
		return "no team (ad hoc)"
	}
	return "team " + team
}

// inspectStagedTree inspects every staged Mach-O and the installed k3sm.
func inspectStagedTree(ctx context.Context, in codeInspector, dir, installedPath string) (codeSignature, map[string]codeSignature, error) {
	rels, err := stagedMachOs(dir)
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
