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
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fixtureRun serves recorded command output from testdata: system_profiler,
// networksetup and ibv_devices each map to one file. An empty name makes that
// command fail, the way a missing executable does.
func fixtureRun(t *testing.T, sp, ns, ibv string) CommandFunc {
	t.Helper()
	files := map[string]string{SystemProfilerPath: sp, NetworksetupPath: ns, IBVDevicesPath: ibv}
	return func(_ context.Context, path string, args ...string) ([]byte, error) {
		switch path {
		case SystemProfilerPath:
			if strings.Join(args, " ") != "SPThunderboltDataType -json" {
				t.Errorf("system_profiler args = %v", args)
			}
		case NetworksetupPath:
			if strings.Join(args, " ") != "-listallhardwareports" {
				t.Errorf("networksetup args = %v", args)
			}
		case IBVDevicesPath:
		default:
			t.Errorf("ran %q: the enumeration runs only its three executables, by absolute path", path)
		}
		name := files[path]
		if name == "" {
			return nil, errors.New("executable not found")
		}
		return os.ReadFile(filepath.Join("testdata", name))
	}
}

const (
	studioUUID = "00000000-0000-4000-8000-0000000000"
	laptopUUID = "00000000-0000-4000-8000-0000000000"
)

// TestPortsFromRecordedFixtures is the format canary: each case is a recorded
// shape of the three outputs, and the joined ports must come out exactly.
func TestPortsFromRecordedFixtures(t *testing.T) {
	studio := func(cabledReceptacle3 string, rdma map[int]bool) []Port {
		var ports []Port
		for r := 1; r <= 6; r++ {
			p := Port{
				Iface:       "en" + string(rune('0'+r+1)),
				PortOrdinal: r - 1,
				DomainUUID:  studioUUID + "0" + string(rune('0'+r)),
				SpeedGbps:   40,
			}
			if r == 3 {
				p.PeerDomainUUID = cabledReceptacle3
			}
			if rdma[r] {
				p.RDMADevice = "rdma_" + p.Iface
			}
			ports = append(ports, p)
		}
		return ports
	}
	cases := []struct {
		name        string
		sp, ns, ibv string
		want        []Port
		wantErr     error
	}{
		{
			name: "six-port desktop, nothing cabled",
			sp:   "system_profiler-studio-6port-uncabled.json", ns: "networksetup-studio.txt", ibv: "ibv_devices-empty.txt",
			want: studio("", nil),
		},
		{
			// Receptacle 4 carries a display (no domain of its own): it is not a
			// peer. Receptacle 3 is cabled to the laptop.
			name: "six-port desktop, one Mac and one display cabled",
			sp:   "system_profiler-studio-6port-cabled.json", ns: "networksetup-studio.txt", ibv: "ibv_devices-empty.txt",
			want: studio(laptopUUID+"11", nil),
		},
		{
			name: "six-port desktop with RDMA devices listed",
			sp:   "system_profiler-studio-6port-cabled.json", ns: "networksetup-studio.txt", ibv: "ibv_devices-rdma.txt",
			want: studio(laptopUUID+"11", map[int]bool{2: true, 3: true}),
		},
		{
			name: "six-port desktop, ibv_devices missing",
			sp:   "system_profiler-studio-6port-cabled.json", ns: "networksetup-studio.txt", ibv: "",
			want: studio(laptopUUID+"11", nil),
		},
		{
			name: "two-port laptop, nothing cabled",
			sp:   "system_profiler-laptop-2port-uncabled.json", ns: "networksetup-laptop.txt", ibv: "ibv_devices-empty.txt",
			want: []Port{
				{Iface: "en1", PortOrdinal: 0, DomainUUID: laptopUUID + "11", SpeedGbps: 40},
				{Iface: "en2", PortOrdinal: 1, DomainUUID: laptopUUID + "12", SpeedGbps: 40},
			},
		},
		{
			name: "two-port laptop cabled to the desktop's receptacle 3",
			sp:   "system_profiler-laptop-2port-cabled.json", ns: "networksetup-laptop.txt", ibv: "ibv_devices-empty.txt",
			want: []Port{
				{Iface: "en1", PortOrdinal: 0, DomainUUID: laptopUUID + "11", PeerDomainUUID: studioUUID + "03", SpeedGbps: 40},
				{Iface: "en2", PortOrdinal: 1, DomainUUID: laptopUUID + "12", SpeedGbps: 40},
			},
		},
		{
			name: "no Thunderbolt hardware port listed",
			sp:   "system_profiler-laptop-2port-uncabled.json", ns: "networksetup-no-thunderbolt.txt", ibv: "ibv_devices-empty.txt",
			wantErr: ErrNoThunderboltService,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Exec{Run: fixtureRun(t, tc.sp, tc.ns, tc.ibv)}.Ports(context.Background())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Ports error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Ports: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Ports =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
}

// TestHardwarePortsMapsOnlyThunderboltNames pins that the mapping comes from the
// "Thunderbolt N" hardware-port names alone: the bridge, Wi-Fi and Ethernet
// adapters are never Thunderbolt ports, whatever their interface name looks like.
func TestHardwarePortsMapsOnlyThunderboltNames(t *testing.T) {
	cases := []struct {
		file string
		want map[string]int
	}{
		{"networksetup-studio.txt", map[string]int{"en2": 1, "en3": 2, "en4": 3, "en5": 4, "en6": 5, "en7": 6}},
		{"networksetup-laptop.txt", map[string]int{"en1": 1, "en2": 2}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got, err := Exec{Run: fixtureRun(t, "", tc.file, "")}.HardwarePorts(context.Background())
			if err != nil {
				t.Fatalf("HardwarePorts: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("HardwarePorts = %v, want %v", got, tc.want)
			}
		})
	}
	if _, err := ParseHardwarePorts([]byte("Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n")); !errors.Is(err, ErrNoThunderboltService) {
		t.Errorf("a bridge-only listing: error = %v, want ErrNoThunderboltService", err)
	}
	if _, err := ParseHardwarePorts([]byte("Hardware Port: Thunderbolt 9\nDevice: en9\n")); !errors.Is(err, ErrNoThunderboltService) {
		t.Errorf("a receptacle outside 1..8 must not map: error = %v", err)
	}
}

// TestParseThunderboltRejectsUnknownShapes pins the fail-closed half of the
// canary: output this release cannot read is an error, never an empty port list.
func TestParseThunderboltRejectsUnknownShapes(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"not json", "Thunderbolt/USB4:"},
		{"no data type", `{"SPUSBDataType": []}`},
		{"receptacle out of range", `{"SPThunderboltDataType":[{"domain_uuid_key":"a","receptacle_1_tag":{"receptacle_id_key":"9"}}]}`},
		{"receptacle not a number", `{"SPThunderboltDataType":[{"domain_uuid_key":"a","receptacle_1_tag":{"receptacle_id_key":"left"}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseThunderbolt([]byte(tc.in)); !errors.Is(err, ErrFormat) {
				t.Errorf("ParseThunderbolt error = %v, want ErrFormat", err)
			}
		})
	}
}

// TestParseIBVDevices pins the RDMA table parse: headers skipped, names kept.
func TestParseIBVDevices(t *testing.T) {
	for _, tc := range []struct {
		file string
		want map[string]bool
	}{
		{"ibv_devices-empty.txt", map[string]bool{}},
		{"ibv_devices-rdma.txt", map[string]bool{"rdma_en3": true, "rdma_en4": true}},
	} {
		b, err := os.ReadFile(filepath.Join("testdata", tc.file))
		if err != nil {
			t.Fatal(err)
		}
		if got := ParseIBVDevices(b); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: ParseIBVDevices = %v, want %v", tc.file, got, tc.want)
		}
	}
}
