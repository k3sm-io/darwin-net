package wire

import (
	"bytes"
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
