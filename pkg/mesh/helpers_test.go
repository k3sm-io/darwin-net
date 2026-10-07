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

// withDevice injects a Device, bypassing the default wireguard device (tests use
// it to drive the reconcile logic without privilege).
func withDevice(d Device) Option {
	return func(m *Mesh) { m.dev = d }
}

// withPinger injects the direct-link probe's I/O, so the liveness logic runs with
// no ICMP socket.
func withPinger(p pinger) Option {
	return func(m *Mesh) { m.prober = newProber(p, m.probeChanged) }
}
