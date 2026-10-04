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

import (
	"reflect"
	"testing"

	"k3sm.io/darwin-net/pkg/tcpseg"
)

// TestResolverDialsThroughTheSegmentClamp pins that the resolver's default dial —
// the one its TCP refetch on a truncated answer uses toward the DNS VIP — is a
// tcpseg.Dialer's DialContext, so that connection has its segment size clamped.
// A method value's code pointer identifies the method, not the receiver, so any
// other dial function (a plain net.Dialer's included) fails the comparison.
func TestResolverDialsThroughTheSegmentClamp(t *testing.T) {
	r, err := NewResolver(stdConfig())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	want := reflect.ValueOf((&tcpseg.Dialer{}).DialContext).Pointer()
	if got := reflect.ValueOf(r.dial).Pointer(); got != want {
		t.Fatal("the resolver's default dial is not tcpseg.Dialer.DialContext")
	}
}
