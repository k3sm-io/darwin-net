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

package proxy

import (
	"net"
	"testing"
)

// spliceBench drives one proxied TCP connection per iteration: a client that writes
// payload bytes and half-closes, a backend that echoes them back and closes, and
// splice in between. Dials, accepts, and the helper goroutines (with their buffers)
// are set up with the timer stopped, so allocs/op is the splice's own. The client
// writes and drains on separate goroutines so a payload larger than the socket
// buffers cannot deadlock the loop.
//
// The two dialed sockets are the active closers and would each leave a TIME_WAIT on
// an ephemeral port, which two fresh connections per iteration exhaust within one
// run; they close with linger 0 instead. Both close only after everything they sent
// has been consumed by the peer, so the RST discards nothing. The accepted sides
// close normally: a linger-0 close with echo still unsent resets the proxy's read,
// the reset can go unnoticed on darwin, and splice then never returns.
func spliceBench(b *testing.B, payload int) {
	b.Helper()
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer backendLn.Close()
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer proxyLn.Close()
	out := make([]byte, payload)
	in := make([]byte, 32<<10)
	echo := make([]byte, 32<<10)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		clientConn, err := net.Dial("tcp", proxyLn.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		client, err := proxyLn.Accept()
		if err != nil {
			b.Fatal(err)
		}
		backendConn, err := net.Dial("tcp", backendLn.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		backend, err := backendLn.Accept()
		if err != nil {
			b.Fatal(err)
		}
		_ = clientConn.(*net.TCPConn).SetLinger(0)
		_ = backendConn.(*net.TCPConn).SetLinger(0)
		go func() { // the backend: echo until EOF, then close
			defer backend.Close()
			for {
				n, err := backend.Read(echo)
				if n > 0 {
					_, _ = backend.Write(echo[:n])
				}
				if err != nil {
					return
				}
			}
		}()
		clientDone := make(chan struct{})
		go func() { // the client's writer: send the payload, then half-close
			_, _ = clientConn.Write(out)
			_ = clientConn.(*net.TCPConn).CloseWrite()
		}()
		go func() { // the client's reader: drain the echo to EOF with a fixed buffer, then close
			defer close(clientDone)
			defer clientConn.Close()
			for {
				if _, err := clientConn.Read(in); err != nil {
					return
				}
			}
		}()
		b.StartTimer()
		splice(client, backendConn)
		b.StopTimer()
		client.Close()
		backendConn.Close()
		<-clientDone
	}
}

func BenchmarkSplice(b *testing.B) { spliceBench(b, 4<<10) }
