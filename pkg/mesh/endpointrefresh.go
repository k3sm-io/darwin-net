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
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// UnreachableRefreshInterval is the most often a send failure to one peer
// endpoint re-applies that peer's registered endpoint. wireguard-go retries a
// handshake every few seconds and every queued data packet is its own send, so
// a dead endpoint fails many times a second; one re-application per interval
// is enough to move the device off it, and a bound keeps a peer that is down at
// both addresses from turning into a UAPI write per packet.
const UnreachableRefreshInterval = 5 * time.Second

// isUnreachable reports whether a send error says the destination cannot be
// reached at all: the next hop did not answer ARP (EHOSTDOWN, which darwin
// reports as "sendmsg: host is down"), or there is no route to the host or its
// network. These are the failures a peer that changed address leaves behind;
// a full buffer or a closed socket says nothing about the endpoint.
func isUnreachable(err error) bool {
	return errors.Is(err, unix.EHOSTDOWN) || errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ENETUNREACH)
}

// refreshLimiter admits at most one refresh per key per interval. The key is
// the failing destination endpoint, which names one peer at a time.
//
// Locking: mu guards last; allow is called from the device's refresh goroutine
// and from tests.
type refreshLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	last     map[string]time.Time
}

// allow reports whether a refresh for key may run at now, and records it if so.
func (l *refreshLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = make(map[string]time.Time)
	}
	if t, ok := l.last[key]; ok && now.Sub(t) < l.interval {
		return false
	}
	l.last[key] = now
	return true
}

// PeerStatus is one wireguard peer as the device reports it: the endpoint it
// currently sends to (registered or roamed) and the time of its last completed
// handshake.
type PeerStatus struct {
	// NodeName is the peer's node, from the plan the device last applied; empty
	// for a key the plan does not carry.
	NodeName string
	// PublicKeyHex is the peer's public key in UAPI (hex) form.
	PublicKeyHex string
	// Endpoint is the host:port the device currently sends to; empty if none.
	Endpoint string
	// LastHandshake is the last completed handshake; the zero Time means never.
	LastHandshake time.Time
}

// HandshakeAge returns how long ago the last handshake completed, and false
// when the peer has never completed one.
func (s PeerStatus) HandshakeAge(now time.Time) (time.Duration, bool) {
	if s.LastHandshake.IsZero() {
		return 0, false
	}
	return now.Sub(s.LastHandshake), true
}

// format renders the status as node=age for a log line ("never" when no
// handshake has completed).
func (s PeerStatus) format(now time.Time) string {
	name := s.NodeName
	if name == "" {
		name = s.PublicKeyHex
	}
	age, ok := s.HandshakeAge(now)
	if !ok {
		return name + "=never"
	}
	return name + "=" + age.Truncate(time.Second).String()
}

// parsePeerStatus reads the peer sections of a wireguard UAPI "get" reply.
// Unknown keys are ignored; a malformed handshake time is an error, since a
// reader that guessed would report a handshake age that is not real.
func parsePeerStatus(uapi string) ([]PeerStatus, error) {
	var (
		out       []PeerStatus
		cur       *PeerStatus
		sec, nsec int64
	)
	flush := func() {
		if cur == nil {
			return
		}
		if sec != 0 || nsec != 0 {
			cur.LastHandshake = time.Unix(sec, nsec)
		}
		out = append(out, *cur)
		cur, sec, nsec = nil, 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(uapi))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		var err error
		switch key {
		case "public_key":
			flush()
			cur = &PeerStatus{PublicKeyHex: val}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = val
			}
		case "last_handshake_time_sec":
			if cur != nil {
				sec, err = strconv.ParseInt(val, 10, 64)
			}
		case "last_handshake_time_nsec":
			if cur != nil {
				nsec, err = strconv.ParseInt(val, 10, 64)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("parse wireguard peer status %s: %w", key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read wireguard peer status: %w", err)
	}
	flush()
	return out, nil
}
