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

package dns

import "testing"

// TestCompletePartialName is the B243 darwin-net gate: the classifier the
// per-node resolver applies before its zone switch, over every verdict shape,
// opted-in vs not, plus the reserved-suffix set netd consults before it
// registers a namespace as a host match domain.
func TestCompletePartialName(t *testing.T) {
	const domain = "cluster.local"
	optedIn := func(ns string) bool { return ns == "demo" || ns == "local" }

	tests := []struct {
		name    string
		qname   string
		optedIn func(string) bool
		want    string
		verdict Verdict
	}{
		{"name.ns.svc is completed", "kubernetes.default.svc", nil, "kubernetes.default.svc.cluster.local", Completed},
		{"name.ns.svc completion lower-cases", "Kubernetes.Default.SVC", nil, "kubernetes.default.svc.cluster.local", Completed},
		{"name.ns completed for an opted-in namespace", "postgres.demo", optedIn, "postgres.demo.svc.cluster.local", Completed},
		{"name.ns not completed for a namespace that did not opt in", "postgres.default", optedIn, "postgres.default", Forward},
		{"name.ns not completed with no opt-in source", "postgres.demo", nil, "postgres.demo", Forward},
		{"name.ns not completed under a reserved suffix even if opted in", "printer.local", optedIn, "printer.local", Forward},
		{"name.svc is refused", "kubernetes.svc", optedIn, "kubernetes.svc", Refused},
		{"bare svc is refused", "svc", optedIn, "svc", Refused},
		{"deeper name under svc is refused, never forwarded", "a.kubernetes.default.svc", optedIn, "a.kubernetes.default.svc", Refused},
		{"malformed label under svc is refused", "under_score.default.svc", optedIn, "under_score.default.svc", Refused},
		{"unknown deeper name under an opted-in namespace is forwarded", "api.foo.demo", optedIn, "api.foo.demo", Forward},
		{"external name is forwarded", "github.com", optedIn, "github.com", Forward},
		{"single label is forwarded", "kubernetes", optedIn, "kubernetes", Forward},
		{"malformed two-label name is forwarded", "bad_name.demo", optedIn, "bad_name.demo", Forward},
		{"FQDN under the cluster domain passes through", "kubernetes.default.svc.cluster.local", optedIn, "kubernetes.default.svc.cluster.local", Passthrough},
		{"the cluster domain itself passes through", "cluster.local", optedIn, "cluster.local", Passthrough},
		{"absolute name with a trailing dot passes through", "kubernetes.default.svc.", optedIn, "kubernetes.default.svc.", Passthrough},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, v := CompletePartialName(tt.qname, domain, tt.optedIn)
			if got != tt.want || v != tt.verdict {
				t.Errorf("CompletePartialName(%q) = (%q, %v), want (%q, %v)", tt.qname, got, v, tt.want, tt.verdict)
			}
		})
	}

	t.Run("invalid cluster domain declines to classify", func(t *testing.T) {
		got, v := CompletePartialName("kubernetes.default.svc", "", optedIn)
		if got != "kubernetes.default.svc" || v != Passthrough {
			t.Errorf("empty domain: got (%q, %v), want passthrough unchanged", got, v)
		}
	})

	reserved := []struct {
		label string
		want  bool
	}{
		{"local", true},
		{"internal", true},
		{"com", true},
		{"COM.", true},
		{"lan", true},
		{"arpa", true},
		{"demo", false},
		{"default", false},
	}
	for _, tt := range reserved {
		t.Run("reserved suffix "+tt.label, func(t *testing.T) {
			if got := IsReservedSuffix(tt.label); got != tt.want {
				t.Errorf("IsReservedSuffix(%q) = %v, want %v", tt.label, got, tt.want)
			}
		})
	}
}
