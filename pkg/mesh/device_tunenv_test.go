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
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// TestWireguardBringUpIgnoresTunNameFileEnv pins that Up clears WG_TUN_NAME_FILE
// before the TUN is created, so wireguard-go cannot write to an env-chosen path as root.
func TestWireguardBringUpIgnoresTunNameFileEnv(t *testing.T) {
	target := filepath.Join(t.TempDir(), "victim")
	t.Setenv(tunNameFileEnv, target)

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	d := newWGDevice(wgLink{
		name:          "utun",
		mtu:           MTU,
		linkIP:        netip.MustParseAddr("100.64.255.1"),
		privateKeyB64: key,
		listenPort:    DefaultListenPort,
	}, nil)

	called := false
	seen := "unset-by-test"
	d.createTUN = func(string, int) (tun.Device, error) {
		called = true
		seen = os.Getenv(tunNameFileEnv)
		return nil, errors.New("fake: no tun")
	}

	if err := d.Up(t.Context()); err == nil {
		t.Fatal("Up succeeded with a failing fake TUN")
	}
	if !called {
		t.Fatal("createTUN seam was not invoked")
	}
	if seen != "" {
		t.Fatalf("%s = %q when the TUN was created; want it cleared", tunNameFileEnv, seen)
	}
}
