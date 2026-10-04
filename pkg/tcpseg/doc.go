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

// Package tcpseg clamps the TCP maximum segment size of the connections the
// k3sm process opens and accepts toward pod and Service addresses, so a flow
// negotiated over the loopback cannot carry loopback-sized segments onto a
// smaller link.
//
// # Why
//
// Every pod IP and Service VIP is an lo0 /32 alias, and lo0's MTU is 16384, so a
// TCP connection to one negotiates an MSS of about 16332. When the destination's
// alias is removed while the connection is open (the pod went away), the /32
// falls through to the cluster pod aggregate, which is routed over the mesh
// utun, and the still-open connection re-routes onto a skywalk netif. XNU's GSO
// path then builds packets from the connection's lo0-sized segment and trips
// the kernel assertion
//
//	(tx_headroom + state->hlen + mss) <= PP_BUF_SIZE_DEF(pp)
//
// in nx_netif_gso.c: a kernel panic from an ordinary send(2).
//
// # What the clamp does
//
// Dialer and WrapListener lower TCP_MAXSEG on each TCP connection to MSS, the
// segment size XNU itself derives for a utun-routed flow. Facts measured on
// macOS 26 that shape the design:
//
//   - TCP_MAXSEG cannot usefully be set before connect: values above 512 are
//     refused with EINVAL, and lower values are overwritten by the handshake.
//   - A value set on a listening socket is not inherited by accepted sockets.
//   - Set after connect, on either end, it holds (16332 lowered to 1340 in the
//     probe) and only ever lowers the segment size: setting it above the current
//     value is EINVAL, so a connection already below MSS is left alone.
//   - getsockopt(TCP_MAXSEG) reports the segment size net of the 12-byte TCP
//     timestamp option, which is why MSS subtracts it.
//
// # Residual
//
// The clamp lowers the connection's t_maxseg. Whether XNU sizes TSO/GSO bursts
// from t_maxseg or from t_maxopd on a re-routed connection is not proven here,
// so the clamp is the secondary defence. The primary one lives in pkg/podnet:
// a pod address whose alias is torn down is blackholed on lo0 rather than left to
// fall through to the mesh route, so the connection never leaves lo0.
package tcpseg
