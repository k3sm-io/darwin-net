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

package linkenum

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The executables the enumeration runs, by absolute path so a PATH entry can
// never substitute one.
const (
	SystemProfilerPath = "/usr/sbin/system_profiler"
	NetworksetupPath   = "/usr/sbin/networksetup"
	IBVDevicesPath     = "/usr/bin/ibv_devices"
)

// maxReceptacle is the largest receptacle number a port may carry: the port
// ordinal (receptacle − 1) has eight values, 0..7.
const maxReceptacle = 8

// ErrNoThunderboltService reports that networksetup lists no Thunderbolt hardware
// port, so no interface can be mapped to a receptacle. It is a condition of the
// host (typically the Thunderbolt Bridge service was deleted), not a transient
// failure; compare with errors.Is.
var ErrNoThunderboltService = errors.New("linkenum: networksetup lists no Thunderbolt hardware port")

// ErrFormat reports output a parser could not read. A recorded-fixture test turns
// red before this reaches production on a format change.
var ErrFormat = errors.New("linkenum: unrecognised command output")

// Port is one Thunderbolt receptacle that presents a network interface.
type Port struct {
	// Iface is the interface the receptacle presents as today (e.g. "en2"). It may
	// change across an unplug; key state by DomainUUID.
	Iface string
	// PortOrdinal is the receptacle number − 1 (0..7).
	PortOrdinal int
	// DomainUUID identifies this end of the cable.
	DomainUUID string
	// PeerDomainUUID identifies the cabled peer's domain; empty when nothing with
	// a domain of its own is plugged in.
	PeerDomainUUID string
	// SpeedGbps is the port's reported speed in Gb/s (0 when unreadable).
	SpeedGbps int
	// RDMADevice is "rdma_" + Iface when ibv_devices lists that device, else
	// empty.
	RDMADevice string
}

// Enumerator lists the host's Thunderbolt ports. Consumers depend on this
// interface; Exec is the production implementation and tests inject fakes.
type Enumerator interface {
	// Ports returns the host's Thunderbolt ports, sorted by PortOrdinal.
	Ports(ctx context.Context) ([]Port, error)
}

// CommandFunc runs one executable and returns its standard output. It is the seam
// every command goes through.
type CommandFunc func(ctx context.Context, path string, args ...string) ([]byte, error)

// Exec is the production Enumerator: it runs the three executables through Run
// (nil = os/exec) and joins their output. The zero value is ready to use.
type Exec struct {
	// Run executes a command; nil runs it with os/exec.
	Run CommandFunc
}

// Ports runs system_profiler, networksetup and ibv_devices and joins them (see
// the package doc). A missing or failing ibv_devices is not an error: the port
// simply has no RDMA device. It returns ErrNoThunderboltService when networksetup
// lists no Thunderbolt port.
func (e Exec) Ports(ctx context.Context) ([]Port, error) {
	hw, err := e.HardwarePorts(ctx)
	if err != nil {
		return nil, err
	}
	out, err := e.run(ctx, SystemProfilerPath, "SPThunderboltDataType", "-json")
	if err != nil {
		return nil, fmt.Errorf("system_profiler SPThunderboltDataType: %w", err)
	}
	buses, err := ParseThunderbolt(out)
	if err != nil {
		return nil, err
	}
	var rdma map[string]bool
	if ibv, err := e.run(ctx, IBVDevicesPath); err == nil {
		rdma = ParseIBVDevices(ibv)
	}
	return Join(buses, hw, rdma), nil
}

// HardwarePorts returns the host's Thunderbolt interfaces, interface name →
// receptacle number (1..8), from networksetup alone. It is the single mapping the
// root network helper validates an interface against and the node uses for its
// pairing decision. It returns ErrNoThunderboltService when no Thunderbolt port is
// listed.
func (e Exec) HardwarePorts(ctx context.Context) (map[string]int, error) {
	out, err := e.run(ctx, NetworksetupPath, "-listallhardwareports")
	if err != nil {
		return nil, fmt.Errorf("networksetup -listallhardwareports: %w", err)
	}
	return ParseHardwarePorts(out)
}

// HardwarePorts is Exec{}.HardwarePorts: the production mapping.
func HardwarePorts(ctx context.Context) (map[string]int, error) {
	return Exec{}.HardwarePorts(ctx)
}

func (e Exec) run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if e.Run != nil {
		return e.Run(ctx, path, args...)
	}
	return exec.CommandContext(ctx, path, args...).Output()
}

// Bus is one system_profiler Thunderbolt entry, reduced to what the join needs.
type Bus struct {
	// Receptacle is the receptacle number (receptacle_id_key, 1-based).
	Receptacle int
	// DomainUUID is the port's own domain_uuid_key.
	DomainUUID string
	// PeerDomainUUID is the first _items entry's domain_uuid_key, if any.
	PeerDomainUUID string
	// SpeedGbps is parsed from current_speed_key ("40 Gb/s", "Up to 40 Gb/s").
	SpeedGbps int
}

// spDump is the slice of system_profiler's JSON the parser reads.
type spDump struct {
	Thunderbolt *[]spEntry `json:"SPThunderboltDataType"`
}

type spEntry struct {
	DomainUUID string `json:"domain_uuid_key"`
	Receptacle *struct {
		ID    string `json:"receptacle_id_key"`
		Speed string `json:"current_speed_key"`
	} `json:"receptacle_1_tag"`
	Items []struct {
		DomainUUID string `json:"domain_uuid_key"`
	} `json:"_items"`
}

var speedRE = regexp.MustCompile(`([0-9]+)\s*Gb/s`)

// ParseThunderbolt reads `system_profiler SPThunderboltDataType -json` output.
// Entries without a domain_uuid_key or a receptacle tag are not host ports and are
// skipped, as MLX skips them; a receptacle number outside 1..8 is a format error.
// The result is sorted by receptacle.
func ParseThunderbolt(b []byte) ([]Bus, error) {
	var d spDump
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%w: system_profiler json: %v", ErrFormat, err)
	}
	if d.Thunderbolt == nil {
		return nil, fmt.Errorf("%w: system_profiler json has no SPThunderboltDataType", ErrFormat)
	}
	var out []Bus
	for _, e := range *d.Thunderbolt {
		if e.DomainUUID == "" || e.Receptacle == nil {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(e.Receptacle.ID))
		if err != nil || n < 1 || n > maxReceptacle {
			return nil, fmt.Errorf("%w: receptacle_id_key %q for domain %s", ErrFormat, e.Receptacle.ID, e.DomainUUID)
		}
		bus := Bus{Receptacle: n, DomainUUID: e.DomainUUID}
		for _, it := range e.Items {
			if it.DomainUUID != "" {
				bus.PeerDomainUUID = it.DomainUUID
				break
			}
		}
		if m := speedRE.FindStringSubmatch(e.Receptacle.Speed); m != nil {
			bus.SpeedGbps, _ = strconv.Atoi(m[1])
		}
		out = append(out, bus)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Receptacle < out[j].Receptacle })
	return out, nil
}

// ParseHardwarePorts reads `networksetup -listallhardwareports` output into
// interface → receptacle number for every "Hardware Port: Thunderbolt N" block
// (N in 1..8). "Thunderbolt Bridge" and every other port are ignored. It returns
// ErrNoThunderboltService when no such block exists.
func ParseHardwarePorts(b []byte) (map[string]int, error) {
	out := make(map[string]int)
	receptacle := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			receptacle = 0
			name := strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
			num, ok := strings.CutPrefix(name, "Thunderbolt ")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(num)
			if err != nil || n < 1 || n > maxReceptacle {
				continue // "Thunderbolt Bridge", or a numbering this release does not model
			}
			receptacle = n
		case strings.HasPrefix(line, "Device:") && receptacle != 0:
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev != "" {
				out[dev] = receptacle
			}
			receptacle = 0
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: networksetup output: %v", ErrFormat, err)
	}
	if len(out) == 0 {
		return nil, ErrNoThunderboltService
	}
	return out, nil
}

// ParseIBVDevices reads `ibv_devices` output into the set of device names it
// lists (e.g. "rdma_en3"). The two header lines and blank lines are skipped; an
// empty table is an empty set.
func ParseIBVDevices(b []byte) map[string]bool {
	out := make(map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || f[0] == "device" || strings.HasPrefix(f[0], "---") {
			continue
		}
		out[f[0]] = true
	}
	return out
}

// Join combines the three parses into Ports: one per bus whose receptacle
// networksetup maps to an interface, sorted by PortOrdinal. A bus with no mapped
// interface (or an interface with no bus) is not a usable port and is dropped.
func Join(buses []Bus, hw map[string]int, rdma map[string]bool) []Port {
	byReceptacle := make(map[int]string, len(hw))
	for iface, n := range hw {
		byReceptacle[n] = iface
	}
	var out []Port
	for _, b := range buses {
		iface, ok := byReceptacle[b.Receptacle]
		if !ok {
			continue
		}
		p := Port{
			Iface:          iface,
			PortOrdinal:    b.Receptacle - 1,
			DomainUUID:     b.DomainUUID,
			PeerDomainUUID: b.PeerDomainUUID,
			SpeedGbps:      b.SpeedGbps,
		}
		if rdma["rdma_"+iface] {
			p.RDMADevice = "rdma_" + iface
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PortOrdinal < out[j].PortOrdinal })
	return out
}
