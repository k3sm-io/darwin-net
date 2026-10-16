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
	"strings"
	"testing"
)

// TestCheckCodeSigning pins the update signing policy table.
func TestCheckCodeSigning(t *testing.T) {
	adhoc := codeSignature{Valid: true}
	teamA := codeSignature{Valid: true, TeamID: "ABCDE12345"}
	teamB := codeSignature{Valid: true, TeamID: "ZZZZZ99999"}
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
