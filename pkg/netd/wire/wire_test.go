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

package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// TestFrameRoundTrip proves a payload survives Frame -> ReadFrame unchanged.
func TestFrameRoundTrip(t *testing.T) {
	payload := []byte(`{"verb":"EnsureAlias"}`)
	got, err := ReadFrame(bytes.NewReader(Frame(payload)), DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip = %q, want %q", got, payload)
	}
}

// TestReadFrameRejectsOversizeNoPanic proves an oversized length prefix is a
// bounded error (the allocation guard), never a panic or huge allocation.
func TestReadFrameRejectsOversizeNoPanic(t *testing.T) {
	// length prefix 0xFFFFFFFF, no body.
	r := bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	_, err := ReadFrame(r, 1024)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame oversize err = %v, want ErrFrameTooLarge", err)
	}
}

// TestReadFrameRejectsEmptyAndTruncated proves a zero-length frame and a truncated
// body are errors (no panic).
func TestReadFrameRejectsEmptyAndTruncated(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0}), 1024); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("zero-length frame err = %v, want ErrEmptyFrame", err)
	}
	// length says 10, only 2 bytes follow.
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 10, 1, 2}), 1024); err == nil {
		t.Fatal("truncated frame did not error")
	}
}

// TestParseFrameEdgeCasesNoPanic proves ParseFrame returns errors (never panics) on
// short and truncated SCM_RIGHTS buffers.
func TestParseFrameEdgeCasesNoPanic(t *testing.T) {
	if _, err := ParseFrame([]byte{1, 2}); err == nil {
		t.Fatal("short buffer did not error")
	}
	if _, err := ParseFrame([]byte{0, 0, 0, 9, 1, 2}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated parse err = %v, want ErrUnexpectedEOF", err)
	}
	payload := []byte("hello")
	got, err := ParseFrame(Frame(payload))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ParseFrame round-trip = %q,%v, want %q,nil", got, err, payload)
	}
}

// TestVersionCompatibility proves a matching MAJOR (any MINOR) is compatible and a
// differing MAJOR is not.
func TestVersionCompatibility(t *testing.T) {
	if !(Version{Major: ProtocolVersionMajor, Minor: ProtocolVersionMinor + 9}).Compatible() {
		t.Fatal("same major, higher minor should be compatible")
	}
	if (Version{Major: ProtocolVersionMajor + 1, Minor: 0}).Compatible() {
		t.Fatal("different major should be incompatible")
	}
}

// TestConfigureMeshArgsNodePodCIDRIsAdditive pins the compatibility contract of the
// nodePodCIDR field: it is omitted when unset (so the frame an older client sends
// is byte-identical to today's), and a frame that lacks it decodes to the empty
// string — which the daemon reads as "keep the configured identity" — rather than
// failing the decode. The protocol Version is deliberately NOT bumped for it.
func TestConfigureMeshArgsNodePodCIDRIsAdditive(t *testing.T) {
	t.Run("unset is omitted from the encoding", func(t *testing.T) {
		b, err := json.Marshal(ConfigureMeshArgs{LocalPrivKeyRef: "ref", ListenPort: 51820})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if bytes.Contains(b, []byte("nodePodCIDR")) {
			t.Fatalf("encoding %s carries nodePodCIDR when unset", b)
		}
	})

	t.Run("set is carried verbatim", func(t *testing.T) {
		b, err := json.Marshal(ConfigureMeshArgs{LocalPrivKeyRef: "ref", NodePodCIDR: "100.64.7.0/24"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Contains(b, []byte(`"nodePodCIDR":"100.64.7.0/24"`)) {
			t.Fatalf("encoding %s does not carry the node pod CIDR", b)
		}
	})

	t.Run("an old client's frame still decodes", func(t *testing.T) {
		var req Request
		if err := json.Unmarshal([]byte(`{"version":{"major":1,"minor":0},"verb":"ConfigureMesh","configureMesh":{"localPrivKeyRef":"ref","peers":[]}}`), &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.ConfigureMesh == nil {
			t.Fatal("configureMesh args did not decode")
		}
		if req.ConfigureMesh.NodePodCIDR != "" {
			t.Fatalf("nodePodCIDR = %q, want empty for a frame that omits it", req.ConfigureMesh.NodePodCIDR)
		}
	})
}
