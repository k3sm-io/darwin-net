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

package linkwatch

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// routeMsgMinLen is the length of the routing-message prefix this reader decodes:
// rtm_msglen (u16), version (u8), type (u8), addrs (i32), flags (i32), index
// (u16). if_msghdr and ifa_msghdr share that prefix on darwin, so one decode
// serves RTM_IFINFO, RTM_NEWADDR and RTM_DELADDR.
const routeMsgMinLen = 14

// RouteReader is the PF_ROUTE source: it reads the kernel's routing-socket
// broadcast (read-only, so unprivileged) and turns RTM_IFINFO, RTM_NEWADDR and
// RTM_DELADDR into events. It is an optimisation over the poll, never a
// replacement: a message it cannot decode, or an interface it cannot name, is
// skipped and left to the poll.
type RouteReader struct {
	f *os.File
	// lookup resolves an interface index; nil uses net.InterfaceByIndex.
	lookup func(index int) (*net.Interface, error)

	mu    sync.Mutex
	names map[int]string // last name seen per index, to name a vanished one
}

// OpenRouteReader opens a non-blocking PF_ROUTE socket for reading. A failure is
// the signal to run the poll alone.
func OpenRouteReader() (*RouteReader, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("open PF_ROUTE socket: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set PF_ROUTE socket non-blocking: %w", err)
	}
	return &RouteReader{f: os.NewFile(uintptr(fd), "pf_route"), names: make(map[int]string)}, nil
}

// Events implements LinkEvents. It owns the socket: the socket is closed when
// ctx ends, which also unblocks the read.
func (r *RouteReader) Events(ctx context.Context) <-chan Event {
	out := make(chan Event, eventBuffer)
	go func() {
		<-ctx.Done()
		_ = r.f.Close()
	}()
	go func() {
		defer close(out)
		buf := make([]byte, 2048)
		for {
			n, err := r.f.Read(buf)
			if err != nil {
				// A closed socket (ctx ended) or a read failure both end this
				// source; the poll keeps the merged stream alive either way.
				return
			}
			for _, ev := range r.decode(buf[:n]) {
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// decode turns one read's worth of routing messages into events.
func (r *RouteReader) decode(b []byte) []Event {
	var out []Event
	for len(b) >= routeMsgMinLen {
		msgLen := int(binary.NativeEndian.Uint16(b[0:2]))
		if msgLen < routeMsgMinLen || msgLen > len(b) {
			return out
		}
		if ev, ok := r.event(parseRouteMsg(b[:msgLen])); ok {
			out = append(out, ev)
		}
		b = b[msgLen:]
	}
	return out
}

// routeMsg is the decoded prefix of one routing message.
type routeMsg struct {
	typ   int
	flags int32
	index int
}

// parseRouteMsg decodes the shared if_msghdr / ifa_msghdr prefix. b holds at
// least routeMsgMinLen bytes.
func parseRouteMsg(b []byte) routeMsg {
	return routeMsg{
		typ:   int(b[3]),
		flags: int32(binary.NativeEndian.Uint32(b[8:12])),
		index: int(binary.NativeEndian.Uint16(b[12:14])),
	}
}

// event maps a message to the interface's current state. RTM_IFINFO carries the
// interface flags itself; an address change re-reads the interface. An index the
// system no longer has is a vanishing, named from the cache.
func (r *RouteReader) event(m routeMsg) (Event, bool) {
	switch m.typ {
	case unix.RTM_IFINFO, unix.RTM_NEWADDR, unix.RTM_DELADDR:
	default:
		return Event{}, false
	}
	lookup := r.lookup
	if lookup == nil {
		lookup = net.InterfaceByIndex
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ifi, err := lookup(m.index)
	if err != nil {
		name, ok := r.names[m.index]
		if !ok {
			return Event{}, false
		}
		delete(r.names, m.index)
		return Event{Iface: name, Gone: true}, true
	}
	r.names[m.index] = ifi.Name
	if m.typ == unix.RTM_IFINFO {
		return Event{Iface: ifi.Name, Up: m.flags&unix.IFF_UP != 0 && m.flags&unix.IFF_RUNNING != 0}, true
	}
	return Event{Iface: ifi.Name, Up: linkUp(ifi.Flags)}, true
}
