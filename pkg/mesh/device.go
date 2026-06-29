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

package mesh

import (
	"context"
)

// Device is the privileged, root-only mesh datapath the Mesh controller drives.
// It is defined here, at the consumer, per the standards: the production
// WGDevice creates a utun, runs userspace wireguard over it, installs the
// per-peer kernel routes, and loads the utun-scoped MSS-clamp pf anchor — all
// root-only operations that run inside the netd daemon boundary in deployment.
// Unit tests substitute a fake so the controller's reconcile logic is exercised
// without privilege; the root-gated integration test drives the real device.
//
// Splitting the device out is what keeps the route-set / AllowedIPs / UAPI logic
// pure: the Mesh controller computes a Plan (table-tested) and the Device merely
// applies it.
type Device interface {
	// Up brings the mesh interface up: it creates/opens the utun at the mesh MTU,
	// starts wireguard with the node's private key and listen port, assigns the
	// mesh-egress source address so it is locally bindable, and loads the
	// utun-scoped MSS-clamp pf anchor. It is idempotent. Root-only — it returns an
	// error without privilege.
	Up(ctx context.Context) error
	// Apply programs the desired state: it sets the wireguard peers from plan.UAPI
	// (a full replacement, so endpoint moves and removals converge) and reconciles
	// the kernel routes to exactly plan.Routes, each routed to the utun. It is
	// idempotent and safe to call on every MeshPeer change.
	Apply(ctx context.Context, plan Plan) error
	// Down tears the mesh down leak-free: it removes every route it installed,
	// unloads the pf anchor, removes the mesh-egress alias, and closes the
	// wireguard device.
	Down(ctx context.Context) error
}
