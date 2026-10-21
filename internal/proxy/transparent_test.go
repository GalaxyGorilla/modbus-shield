package proxy

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

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

// fakeOrigDST returns an originalDST replacement that always reports the
// given target (stands in for the kernel conntrack lookup, which cannot
// run without CAP_NET_ADMIN).
func fakeOrigDST(target string) func(net.Conn) (string, error) {
	return func(net.Conn) (string, error) { return target, nil }
}

// TestTransparentGateway is the B3 acceptance test: a gateway with an
// injected fake original-dst resolver forwards to the RESOLVED address,
// not the configured device_addr — the reverse-proxy core is unchanged
// otherwise. The fake device listens on the resolved address.
func TestTransparentGateway(t *testing.T) {
	dev := newFakeDevice(t)
	resolved := dev.Addr()

	cfg := config.Device{
		Name:       "transparent-dev",
		ListenAddr: "127.0.0.1:0",
		DeviceAddr: "10.255.255.1:502", // NOT the device; resolver wins
		Transparent: true,
		TimeoutMs:  2000,
	}
	front := startGatewayTransparent(t, cfg, fakeOrigDST(resolved))
	readReg(t, front) // exchange resolves orig-dst and dials the REAL device
}

// TestTransparentPerConnTarget verifies the per-connection behavior: each
// client connection resolves its own original destination; the upstream
// connection is re-dialed when the client connection changes.
func TestTransparentPerConnTarget(t *testing.T) {
	dev1 := newFakeDevice(t)
	dev2 := newFakeDevice(t)

	cfg := config.Device{
		Name:        "transparent-dev",
		ListenAddr:  "127.0.0.1:0",
		DeviceAddr:  "10.255.255.1:502",
		Transparent: true,
		TimeoutMs:   2000,
	}
	front := startGatewayTransparent(t, cfg, func(c net.Conn) (string, error) {
		// Alternate targets per connection to force the re-dial path.
		if dev1.Served() == 0 {
			return dev1.Addr(), nil
		}
		return dev2.Addr(), nil
	})

	conn1 := dial(t, front)
	defer conn1.Close()
	if resp := rawExchange(t, conn1, 1); resp.IsException() {
		t.Fatalf("first conn: unexpected exception %x", resp.PDU)
	}
	if dev1.Served() != 1 {
		t.Fatalf("dev1 served = %d, want 1", dev1.Served())
	}

	// Second client connection -> resolver now returns dev2 -> upstream
	// must re-dial (dev1 connection belongs to the old client conn).
	conn2 := dial(t, front)
	defer conn2.Close()
	if resp := rawExchange(t, conn2, 2); resp.IsException() {
		t.Fatalf("second conn: unexpected exception %x", resp.PDU)
	}
	if dev2.Served() != 1 {
		t.Fatalf("dev2 served = %d, want 1", dev2.Served())
	}
}

// TestTransparentResolverError verifies that a failing original-dst
// resolution surfaces as a Modbus gateway exception (0x0B) and the
// client connection stays usable for a later successful request.
func TestTransparentResolverError(t *testing.T) {
	dev := newFakeDevice(t)
	calls := 0
	cfg := config.Device{
		Name:        "transparent-dev",
		ListenAddr:  "127.0.0.1:0",
		DeviceAddr:  "10.255.255.1:502",
		Transparent: true,
		TimeoutMs:   2000,
	}
	front := startGatewayTransparent(t, cfg, func(net.Conn) (string, error) {
		calls++
		if calls == 1 {
			return "", net.UnknownNetworkError("no conntrack entry")
		}
		return dev.Addr(), nil
	})

	conn := dial(t, front)
	defer conn.Close()
	resp := rawExchange(t, conn, 1)
	if !resp.IsException() || resp.PDU[1] != 0x0B {
		t.Fatalf("first exchange: want gateway exception 0x0B, got PDU %x", resp.PDU)
	}
	if resp := rawExchange(t, conn, 2); resp.IsException() {
		t.Fatalf("second exchange after resolver recovery: unexpected exception %x", resp.PDU)
	}
}

// startGatewayTransparent builds a runner with one transparent device and
// returns the front address. origDST is injected directly into the
// upstream (the kernel conntrack lookup cannot run without
// CAP_NET_ADMIN).
func startGatewayTransparent(t *testing.T, dev config.Device, origDST func(net.Conn) (string, error)) string {
	t.Helper()
	cfg := config.Config{Devices: []config.Device{dev}}
	cfg.Defaults()
	r, err := NewRunner(&cfg, nopLogger{}, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	// Inject the fake resolver into the gateway's upstream before serving.
	r.gws[0].up.origDST = origDST
	go func() { _ = r.Run() }()
	t.Cleanup(r.Stop)
	<-r.bound
	return r.lns[0].Addr().String()
}
