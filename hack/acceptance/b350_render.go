//go:build ignore

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

// b350_render prints the pf MSS-clamp rule the mesh loads into its anchor, for
// one utun name, through the same call the daemon and the in-process device use
// (mesh.PFMSSClampRule with mesh.MSSClamp). hack/acceptance/B350.sh diffs its
// output against a literal expectation (CI tier) and against the live anchor
// (lab tier). The ignore build tag keeps it out of `go build ./...`; run it
// with `go run hack/acceptance/b350_render.go <utun>`.
package main

import (
	"fmt"
	"os"

	"k3sm.io/darwin-net/pkg/mesh"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: go run b350_render.go <utun>")
		os.Exit(2)
	}
	fmt.Print(mesh.PFMSSClampRule(os.Args[1], mesh.MSSClamp))
}
