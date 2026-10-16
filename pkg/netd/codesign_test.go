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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckCodeSigning pins the update signing policy table.
func TestCheckCodeSigning(t *testing.T) {
	adhoc := codeSignature{Valid: true}
	teamA := codeSignature{Valid: true, TeamID: "ABCDE12345", DeveloperID: true}
	teamB := codeSignature{Valid: true, TeamID: "ZZZZZ99999", DeveloperID: true}
	// noDevID carries teamA's TeamIdentifier without satisfying the Developer
	// ID requirement (an Apple Development certificate, or a forged string).
	noDevID := codeSignature{Valid: true, TeamID: "ABCDE12345"}
	// badTeam satisfies the requirement check but its TeamIdentifier is not
	// a Team ID; the policy never counts it.
	badTeam := codeSignature{Valid: true, TeamID: "abcde", DeveloperID: true}
	cases := []struct {
		name      string
		installed codeSignature
		tree      map[string]codeSignature
		required  bool
		want      string
	}{
		{"ad-hoc install, ad-hoc tree", adhoc, map[string]codeSignature{"k3sm": adhoc, "x": adhoc}, false, ""},
		{"ad-hoc install, one-team tree", adhoc, map[string]codeSignature{"k3sm": teamA, "x": teamA}, false, ""},
		{"ad-hoc install, two teams", adhoc, map[string]codeSignature{"k3sm": teamA, "x": teamB}, false, "mixes signers"},
		{"ad-hoc install, team and ad hoc", adhoc, map[string]codeSignature{"k3sm": teamA, "x": adhoc}, false, "mixes signers"},
		{"ad-hoc install, required, ad-hoc tree", adhoc, map[string]codeSignature{"k3sm": adhoc}, true, "requires a team signature"},
		{"ad-hoc install, required, team tree", adhoc, map[string]codeSignature{"k3sm": teamA}, true, ""},
		{"team install, same team", teamA, map[string]codeSignature{"k3sm": teamA, "x": teamA}, false, ""},
		{"team install, foreign team", teamA, map[string]codeSignature{"k3sm": teamB}, false, "signed by team ABCDE12345"},
		{"team install, ad-hoc file", teamA, map[string]codeSignature{"k3sm": teamA, "x": adhoc}, false, "signed by team ABCDE12345"},
		{"invalid staged file", adhoc, map[string]codeSignature{"k3sm": adhoc, "x": {}}, false, "not validly signed"},
		{"invalid installed", codeSignature{}, map[string]codeSignature{"k3sm": adhoc}, false, "does not verify"},
		{"team string without Developer ID counts as no team: required refuses", adhoc, map[string]codeSignature{"k3sm": noDevID, "x": noDevID}, true, "requires a team signature"},
		{"team string without Developer ID counts as no team: team install refuses", teamA, map[string]codeSignature{"k3sm": teamA, "x": noDevID}, false, "signed by team ABCDE12345 and the staged x by no team (ABCDE12345 without a Developer ID"},
		{"team string without Developer ID counts as no team: mixed with its own team", adhoc, map[string]codeSignature{"k3sm": teamA, "x": noDevID}, false, "mixes signers"},
		{"team string without Developer ID counts as no team: accepted beside ad hoc", adhoc, map[string]codeSignature{"k3sm": noDevID, "x": adhoc}, false, ""},
		{"installed team string without Developer ID counts as no team", noDevID, map[string]codeSignature{"k3sm": adhoc}, false, ""},
		{"installed team string without Developer ID counts as no team: required still refuses", noDevID, map[string]codeSignature{"k3sm": adhoc}, true, "requires a team signature"},
		{"a TeamIdentifier that is not a Team ID counts as no team", adhoc, map[string]codeSignature{"k3sm": badTeam}, true, "requires a team signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCodeSigning(tc.installed, tc.tree, tc.required)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v, want accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestParseCodesignTeam pins the Team ID read from `codesign -dv` output.
func TestParseCodesignTeam(t *testing.T) {
	cases := map[string]string{
		"Executable=/x\nSignature=adhoc\nTeamIdentifier=not set\n":           "",
		"Executable=/x\nAuthority=Developer ID\nTeamIdentifier=ABCDE12345\n": "ABCDE12345",
		"Executable=/x\n": "",
	}
	for out, want := range cases {
		if got := parseCodesignTeam(out); got != want {
			t.Errorf("parseCodesignTeam(%q) = %q, want %q", out, got, want)
		}
	}
}

// TestCheckCodeSigningMachOMagics pins the Mach-O recognition the set check
// rests on: the thin and universal magics in both byte orders, FAT_MAGIC_64
// included, and nothing else.
func TestCheckCodeSigningMachOMagics(t *testing.T) {
	cases := []struct {
		name string
		head string
		want bool
	}{
		{"MH_MAGIC", "\xfe\xed\xfa\xce", true},
		{"MH_CIGAM", "\xce\xfa\xed\xfe", true},
		{"MH_MAGIC_64", "\xfe\xed\xfa\xcf", true},
		{"MH_CIGAM_64", "\xcf\xfa\xed\xfe", true},
		{"FAT_MAGIC", "\xca\xfe\xba\xbe", true},
		{"FAT_CIGAM", "\xbe\xba\xfe\xca", true},
		{"FAT_MAGIC_64", "\xca\xfe\xba\xbf", true},
		{"FAT_CIGAM_64", "\xbf\xba\xfe\xca", true},
		{"a script", "#!/bin/sh\n", false},
		{"a short file", "\xca\xfe", false},
		{"an empty file", "", false},
	}
	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.WriteFile(p, []byte(tc.head), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := isMachO(p)
			if err != nil || got != tc.want {
				t.Fatalf("isMachO = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// TestValidTeamIDAndRequirement pins the Team ID shape and the requirement
// text codesign evaluates, which must carry the Developer ID anchor.
func TestValidTeamIDAndRequirement(t *testing.T) {
	for id, want := range map[string]bool{"ABCDE12345": true, "abcde12345": false, "ABCDE1234": false, "ABCDE12345X": false, `ABCDE"1234`: false, "": false} {
		if got := validTeamID(id); got != want {
			t.Errorf("validTeamID(%q) = %v, want %v", id, got, want)
		}
	}
	req := developerIDRequirement("ABCDE12345")
	for _, part := range []string{"anchor apple generic", "certificate 1[field.1.2.840.113635.100.6.2.6] exists", "certificate leaf[field.1.2.840.113635.100.6.1.13] exists", `certificate leaf[subject.OU] = "ABCDE12345"`} {
		if !strings.Contains(req, part) {
			t.Errorf("requirement %q lacks %q", req, part)
		}
	}
}
