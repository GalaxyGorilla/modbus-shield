//go:build linux

package proxy

import (
	"encoding/binary"
	"net"
	"testing"
)

// parseOrigDst only exists on Linux (netfilter conntrack), so its tests
// carry the same build tag: the rest of the transparent-mode tests inject
// a fake resolver and compile everywhere.

// TestParseOrigDstV4 checks IPv4 sockaddr parsing (family in host byte
// order, port in network byte order, IP raw bytes).
func TestParseOrigDstV4(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], 2) // AF_INET = 2
	binary.BigEndian.PutUint16(buf[2:4], 502)  // port, network order
	copy(buf[4:8], net.IPv4(10, 0, 0, 42).To4())
	got, err := parseOrigDst(buf)
	if err != nil {
		t.Fatalf("parseOrigDst: %v", err)
	}
	if want := "10.0.0.42:502"; got != want {
		t.Fatalf("parseOrigDst = %q, want %q", got, want)
	}
}

// TestParseOrigDstV6 checks IPv6 sockaddr parsing.
func TestParseOrigDstV6(t *testing.T) {
	buf := make([]byte, 28)
	binary.LittleEndian.PutUint16(buf[0:2], 10) // AF_INET6 = 10
	binary.BigEndian.PutUint16(buf[2:4], 1502)
	ip := net.ParseIP("2001:db8::42").To16()
	copy(buf[8:24], ip)
	got, err := parseOrigDst(buf)
	if err != nil {
		t.Fatalf("parseOrigDst: %v", err)
	}
	if want := "[2001:db8::42]:1502"; got != want {
		t.Fatalf("parseOrigDst = %q, want %q", got, want)
	}
}

// TestParseOrigDstErrors checks short and unknown-family sockaddrs.
func TestParseOrigDstErrors(t *testing.T) {
	if _, err := parseOrigDst([]byte{0, 0, 0}); err == nil {
		t.Fatal("short sockaddr: want error, got nil")
	}
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], 99) // unknown family
	if _, err := parseOrigDst(buf); err == nil {
		t.Fatal("unknown family: want error, got nil")
	}
}
