package proxy

import (
	"strings"
	"testing"
	"time"

	"net"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

// startGatewayExtra starts a Runner for a device with extra listeners
// (B10) and returns all bound front-leg addresses in bind order
// (primary listen_addr first, then extra_listen entries).
func startGatewayExtra(t *testing.T, dev config.Device) []string {
	t.Helper()
	cfg := &config.Config{Devices: []config.Device{dev}}
	cfg.Defaults()
	r, err := NewRunner(cfg, nopLogger{}, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- r.Run() }()
	t.Cleanup(r.Stop)
	<-r.bound
	var addrs []string
	for _, ln := range r.lns {
		addrs = append(addrs, ln.Addr().String())
	}
	return addrs
}

// freeExtraAddr reserves a free loopback port for re-binding a fake
// device or listener onto.
func freeExtraAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestExtraListenSharedUpstream is the B10 acceptance: all three front
// doors serve reads through the SAME upstream device connection — the
// fragile single-connection device still sees exactly one connection.
func TestExtraListenSharedUpstream(t *testing.T) {
	devAddr := freeExtraAddr(t)
	// Fake single-connection device bound to a fixed address.
	fdev := newFakeDeviceCfg(t, fakeDeviceCfg{LockStep: true, OnAddr: devAddr})

	addrs := startGatewayExtra(t, config.Device{
		Name:       "extra-dev",
		DeviceAddr: devAddr,
		ExtraListen: []string{
			"127.0.0.1:0",
			"127.0.0.1:0",
		},
	})
	if len(addrs) != 3 {
		t.Fatalf("want 3 bound listeners, got %d: %v", len(addrs), addrs)
	}

	// One connection per front door, in parallel, all multiplexing onto
	// the one upstream connection (LockStep device refuses a second).
	for _, addr := range addrs {
		addr := addr
		go func() {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Errorf("dial %s: %v", addr, err)
				return
			}
			defer conn.Close()
			for i := 0; i < 5; i++ {
				if _, err := readOn(t, conn); err != nil {
					t.Errorf("read via %s: %v", addr, err)
					return
				}
			}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && fdev.Served() < 15 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := fdev.Served(); got != 15 {
		t.Fatalf("device served %d, want 15 (3 doors x 5 reads)", got)
	}
	if got := fdev.Accepted(); got != 1 {
		t.Fatalf("LockStep device accepted %d connections, want exactly 1", got)
	}
}

// TestExtraListenSharedCap verifies the connection cap applies across
// ALL front doors: a client on the extra listener consumes the same
// shielding budget as one on the primary.
func TestExtraListenSharedCap(t *testing.T) {
	devAddr := freeExtraAddr(t)
	_ = newFakeDeviceCfg(t, fakeDeviceCfg{OnAddr: devAddr})

	addrs := startGatewayExtra(t, config.Device{
		Name:       "cap-dev",
		DeviceAddr: devAddr,
		MaxClients: 1,
		ExtraListen: []string{
			"127.0.0.1:0",
		},
	})
	if len(addrs) != 2 {
		t.Fatalf("want 2 bound listeners, got %d: %v", len(addrs), addrs)
	}
	c1 := dial(t, addrs[0])
	defer c1.Close()
	if _, err := readOn(t, c1); err != nil {
		t.Fatalf("read via primary: %v", err)
	}
	// Second client through the EXTRA door must hit the shared cap:
	// the proxy closes it at accept time (reject = connection closed).
	c2, err := net.DialTimeout("tcp", addrs[1], 2*time.Second)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readOn(t, c2); err == nil {
		t.Fatal("read via extra door succeeded despite shared connection cap")
	}
}

// TestExtraListenConfigErrors covers the validate rules for extra
// listeners: bad syntax, duplicate of the primary address, and
// collisions with other devices' addresses.
func TestExtraListenConfigErrors(t *testing.T) {
	base := func(extra ...string) *config.Config {
		return &config.Config{Devices: []config.Device{
			{Name: "a", ListenAddr: "127.0.0.1:5020", DeviceAddr: "127.0.0.1:502", ExtraListen: extra},
		}}
	}
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"bad syntax", base("no-port"), "bad extra_listen[0]"},
		{"dup primary", base("127.0.0.1:5020"), "duplicates listen_addr"},
	}
	for _, tc := range cases {
		if err := tc.cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error %q, got %v", tc.name, tc.want, err)
		}
	}
	// Cross-device collision: extra of device a collides with listen of b.
	cfg := &config.Config{Devices: []config.Device{
		{Name: "a", ListenAddr: "127.0.0.1:5020", DeviceAddr: "127.0.0.1:502", ExtraListen: []string{"127.0.0.1:5030"}},
		{Name: "b", ListenAddr: "127.0.0.1:5030", DeviceAddr: "127.0.0.1:503"},
	}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "already used by") {
		t.Errorf("cross-device collision: want 'already used by', got %v", err)
	}
}
