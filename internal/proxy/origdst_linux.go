//go:build linux

package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// originalDST recovers the pre-redirect destination of a transparently
// intercepted connection (B3): when netfilter REDIRECT steers inbound
// TCP/502 into the local gateway, the ORIGINAL destination (device
// IP:port) is stored in conntrack and readable via
// getsockopt(SOL_IP, SO_ORIGINAL_DST). Must be called on the accepted
// connection before any traffic is sent upstream.
func originalDST(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("original-dst: not a plain TCP connection (%T); transparent mode requires the front leg without TLS", conn)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("original-dst: %w", err)
	}
	var dst string
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		dst, opErr = parseOrigDst(getsockoptOrigDst(int(fd)))
	}); err != nil {
		return "", fmt.Errorf("original-dst: %w", err)
	}
	if opErr != nil {
		return "", fmt.Errorf("original-dst: %w", opErr)
	}
	return dst, nil
}

// getsockoptOrigDst performs the raw getsockopt(SOL_IP, SO_ORIGINAL_DST)
// and returns the kernel sockaddr bytes (sockaddr_in or sockaddr_in6).
// This is the only part that cannot be unit-tested without netfilter.
func getsockoptOrigDst(fd int) []byte {
	// sockaddr_storage is 128 bytes on Linux; x/sys/unix doesn't export
	// SizeofSockaddrStorage, so size the buffer manually.
	var buf [128]byte
	l := uint32(len(buf))
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(unix.SOL_IP), uintptr(unix.SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0); errno != 0 {
		return nil
	}
	return buf[:l]
}

// parseOrigDst formats kernel sockaddr bytes as host:port. split out for
// unit testing (family in host byte order, port in network byte order).
func parseOrigDst(buf []byte) (string, error) {
	if len(buf) < 8 {
		return "", fmt.Errorf("original-dst: short sockaddr (%d bytes) — is the connection actually redirected?", len(buf))
	}
	switch family := *(*uint16)(unsafe.Pointer(&buf[0])); family {
	case unix.AF_INET:
		port := binary.BigEndian.Uint16(buf[2:4])
		ip := net.IP(buf[4:8])
		return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
	case unix.AF_INET6:
		if len(buf) < 24 {
			return "", fmt.Errorf("original-dst: short IPv6 sockaddr (%d bytes)", len(buf))
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		ip := net.IP(buf[8:24])
		return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
	default:
		return "", fmt.Errorf("original-dst: unsupported address family %d", family)
	}
}
