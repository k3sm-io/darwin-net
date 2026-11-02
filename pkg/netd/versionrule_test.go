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

// vmhostRoot is the install root the call-site tests resolve under.
// installedWithinRoot works on path strings only, so it is never created.
const vmhostRoot = "/k3sm-root"

// TestInstalledVersionNamesMatchTable runs validInstalledVersion over the
// shared table of version directory names, so this repo's rule and its
// sibling's cannot drift apart unnoticed.
func TestInstalledVersionNamesMatchTable(t *testing.T) {
	checkVersionNames(t, "validInstalledVersion", func(_ *testing.T, name string) bool {
		return validInstalledVersion(name)
	})
}

// oneElement reports whether name stays one path element when joined under
// versions/. Any other name is changed by path cleaning before the
// version-directory rule sees it, so the call site cannot express it.
func oneElement(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/")
}

// vmhostAccepted reports whether the install-tree check accepts the vmhost
// binary at <root>/versions/<name>/k3sm-vmhost.
func vmhostAccepted(name string) bool {
	target := vmhostRoot + "/versions/" + name + "/k3sm-vmhost"
	return installedWithinRoot(target, vmhostRoot, "k3sm-vmhost") == nil
}

// TestInstalledVMHostUsesVersionRule drives the install-tree check, the
// production call site of the version rule, over versions/<name>/k3sm-vmhost
// for every row of the shared table, so a different rule inlined at the call
// site goes red even while validInstalledVersion itself stays right.
func TestInstalledVMHostUsesVersionRule(t *testing.T) {
	checkVersionNames(t, "installedWithinRoot(versions/<name>/k3sm-vmhost)", func(t *testing.T, name string) bool {
		if !oneElement(name) {
			t.Skipf("%q is not one path element; path cleaning changes it before the rule sees it", name)
		}
		return vmhostAccepted(name)
	})
}

// FuzzInstalledVersionAgreesWithRegex checks, for any one-element name, that
// the install-tree check accepts versions/<name>/k3sm-vmhost exactly when the
// name is within the length bound and matches installedVersionDir. The seeds
// are every row of the shared table.
func FuzzInstalledVersionAgreesWithRegex(f *testing.F) {
	for _, c := range readVersionNames(f) {
		f.Add(c.name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if !oneElement(name) {
			return
		}
		want := len(name) <= maxInstalledVersionLen && installedVersionDir.MatchString(name)
		if got := vmhostAccepted(name); got != want {
			t.Errorf("installedWithinRoot(versions/%q/k3sm-vmhost) accepted=%v, installedVersionDir with the %d-byte bound says %v",
				name, got, maxInstalledVersionLen, want)
		}
	})
}
