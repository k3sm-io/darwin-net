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

// Package linkenum enumerates a Mac's direct-link ports: the Thunderbolt
// receptacles, the network interface each one presents as, the domain at each
// end of a cable, and the RDMA device a port carries.
//
// # Exec only
//
// Every fact comes from a plain system executable run by absolute path, parsed
// from its output: /usr/sbin/system_profiler SPThunderboltDataType -json for the
// receptacles and the cabled peer, /usr/sbin/networksetup -listallhardwareports
// for the receptacle-to-interface mapping, and /usr/bin/ibv_devices for the RDMA
// devices. There is no SPI, no cgo, and no RDMA library link: the package builds
// CGO_ENABLED=0 and never includes a verbs header. The commands need no privilege,
// so the unprivileged service user runs the enumeration; the root network helper
// runs only the networksetup half (HardwarePorts) to validate what it is asked to
// configure.
//
// # The join
//
// The join is the one MLX's distributed_config uses. system_profiler lists one
// entry per Thunderbolt bus with the port's domain_uuid_key, its receptacle number
// (receptacle_1_tag.receptacle_id_key), its negotiated speed, and, under _items,
// whatever is plugged in; the cabled peer is the first item that carries a
// domain_uuid_key of its own (a display or a dock has none). networksetup names
// each receptacle's interface as "Hardware Port: Thunderbolt N" followed by
// "Device: enX". The two are joined on N.
//
// An interface counts as a Thunderbolt port ONLY through that networksetup line,
// never by its name: interface names are assigned at boot and may change across an
// unplug, so a consumer keys state by DomainUUID and treats Iface as the current
// spelling. When networksetup lists no Thunderbolt port at all (the Thunderbolt
// Bridge service was deleted, say) every call returns ErrNoThunderboltService.
//
// # Canaries
//
// The parsers are pinned by recorded fixtures in testdata, one per output format
// and machine shape (a six-port desktop and a two-port laptop, cabled and not). A
// macOS release that changes a format turns those tests red, the same idiom as a
// symbol canary for an SPI.
package linkenum
