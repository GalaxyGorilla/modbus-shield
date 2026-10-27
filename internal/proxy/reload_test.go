package proxy

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// startReloadable starts a Runner for one device on an ephemeral port and
// returns it plus the bound front-leg address.
func startReloadable(t *testing.T, dev config.Device) (*Runner, string) {
	t.Helper()
	dev.ListenAddr = "127.0.0.1:0"
	cfg := &config.Config{Devices: []config.Device{dev}}
	cfg.Defaults()
	r, err := NewRunner(cfg, nopLogger{}, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	go func() { _ = r.Run() }()
	t.Cleanup(r.Stop)
	<-r.bound
	return r, r.lns[0].Addr().String()
}

// writeFC6 sends a write-single-register request and returns the response.
func writeFC6(t *testing.T, conn net.Conn, txn uint16, addr uint16) mbtcp.ADU {
	t.Helper()
	pdu := []byte{6, byte(addr >> 8), byte(addr), 0x2A, 0x2A}
	adu, err := mbtcp.NewADU(txn, 1, pdu)
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// TestReloadWritePolicy: the address-scoped write policy is swapped by a
// reload on a LIVE connection, without touching the device connection.
func TestReloadWritePolicy(t *testing.T) {
	dev := newFakeDevice(t)
	r, front := startReloadable(t, config.Device{
		Name:       "dev1",
		DeviceAddr: dev.Addr(),
		WritePolicy: &config.WritePolicyConfig{
			Default: "deny",
			Rules: []config.WriteRule{{
				FC: []int{6}, From: intp(0x0100), To: intp(0x0100), Action: "allow",
			}},
		},
	})

	conn := dial(t, front)
	defer conn.Close()

	if resp := writeFC6(t, conn, 1, 0x0100); resp.IsException() {
		t.Fatalf("initial policy denied 0x0100: %x", resp.PDU)
	}
	if got := dev.Accepted(); got != 1 {
		t.Fatalf("device accepted %d connections, want 1", got)
	}

	// Reload: the allowed window moves to 0x0200.
	cfg := &config.Config{Devices: []config.Device{{
		Name:       "dev1",
		DeviceAddr: dev.Addr(),
		ListenAddr: r.gws[0].dev.ListenAddr,
		WritePolicy: &config.WritePolicyConfig{
			Default: "deny",
			Rules: []config.WriteRule{{
				FC: []int{6}, From: intp(0x0200), To: intp(0x0200), Action: "allow",
			}},
		},
	}}}
	cfg.Defaults()
	if warn := r.Reload(cfg); len(warn) != 0 {
		t.Fatalf("unexpected reload warnings: %v", warn)
	}

	// Same connection: 0x0100 is now denied, 0x0200 allowed.
	servedBefore := dev.Served()
	if resp := writeFC6(t, conn, 2, 0x0100); !resp.IsException() {
		t.Fatalf("after reload 0x0100 was still allowed: %x (served %d -> %d)", resp.PDU, servedBefore, dev.Served())
	} else if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalDataAddr {
		t.Fatalf("exception code = %#x, want 0x02", code)
	}
	if resp := writeFC6(t, conn, 3, 0x0200); resp.IsException() {
		t.Fatalf("after reload 0x0200 was denied: %x", resp.PDU)
	}
	// The device connection survived the reload: no redial.
	if got := dev.Accepted(); got != 1 {
		t.Fatalf("device accepted %d connections after reload, want 1 (connection must survive)", got)
	}
}

// TestReloadACL: a tightened allow-list takes effect for NEW connections
// while established connections keep working (an ACL is an admission
// gate, not a session killer — documented behavior).
func TestReloadACL(t *testing.T) {
	dev := newFakeDevice(t)
	r, front := startReloadable(t, config.Device{Name: "dev1", DeviceAddr: dev.Addr()})

	live := dial(t, front)
	defer live.Close()
	if _, err := readRegOnConn(t, live); err != nil {
		t.Fatalf("initial read: %v", err)
	}

	cfg := &config.Config{Devices: []config.Device{{
		Name:       "dev1",
		DeviceAddr: dev.Addr(),
		ListenAddr: r.gws[0].dev.ListenAddr,
		Allow:      []string{"10.0.0.0/8"}, // loopback is now excluded
	}}}
	cfg.Defaults()
	if warn := r.Reload(cfg); len(warn) != 0 {
		t.Fatalf("unexpected reload warnings: %v", warn)
	}

	// New connection from 127.0.0.1 must be refused (closed immediately).
	conn, err := net.DialTimeout("tcp", front, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := mbtcp.ReadADU(conn); err == nil {
		t.Fatal("new connection was served although the reloaded allow-list excludes it")
	}

	// The established connection is unaffected.
	if _, err := readRegOnConn(t, live); err != nil {
		t.Fatalf("established connection broke on reload: %v", err)
	}
}

// readRegOnConn reads holding register 0x0100 on an open connection.
func readRegOnConn(t *testing.T, conn net.Conn) (uint16, error) {
	t.Helper()
	adu, err := mbtcp.NewADU(0x0BAD, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		return 0, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		return 0, err
	}
	if len(resp.PDU) < 4 {
		t.Fatalf("short read response: %x", resp.PDU)
	}
	return uint16(resp.PDU[2])<<8 | uint16(resp.PDU[3]), nil
}

// TestReloadRestartRequired: changes bound to the listener or the device
// connection are reported as warnings instead of silently ignored.
func TestReloadRestartRequired(t *testing.T) {
	dev := newFakeDevice(t)
	r, _ := startReloadable(t, config.Device{Name: "dev1", DeviceAddr: dev.Addr()})

	cfg := &config.Config{Devices: []config.Device{{
		Name:       "dev1",
		DeviceAddr: "192.0.2.10:502", // device_addr change
		ListenAddr: "127.0.0.1:1",    // listen_addr change
		RTUOverTCP: true,
	}}}
	cfg.Defaults()
	warn := strings.Join(r.Reload(cfg), "\n")
	for _, want := range []string{"device_addr", "listen_addr", "rtu_over_tcp", "restart required"} {
		if !strings.Contains(warn, want) {
			t.Fatalf("reload warnings missing %q:\n%s", want, warn)
		}
	}
	// The running gateway must still point at the real device.
	if r.gws[0].dev.DeviceAddr != dev.Addr() {
		t.Fatalf("gateway device_addr changed without restart: %s", r.gws[0].dev.DeviceAddr)
	}
}

// TestReloadDeviceSetChanges: adding or removing a device cannot be
// applied by a reload; both are reported so the operator does not believe
// the new device is protected.
func TestReloadDeviceSetChanges(t *testing.T) {
	dev := newFakeDevice(t)
	r, _ := startReloadable(t, config.Device{Name: "dev1", DeviceAddr: dev.Addr()})

	// dev1 removed, dev2 added.
	cfg := &config.Config{Devices: []config.Device{{
		Name: "dev2", DeviceAddr: "192.0.2.11:502", ListenAddr: "127.0.0.1:0",
	}}}
	cfg.Defaults()
	warn := strings.Join(r.Reload(cfg), "\n")
	if !strings.Contains(warn, "device dev1: no longer in the config") {
		t.Fatalf("missing removal warning:\n%s", warn)
	}
	if !strings.Contains(warn, "device dev2: new in the config") {
		t.Fatalf("missing addition warning:\n%s", warn)
	}
}

// TestReloadHealthUnitID: the health endpoint's unit ID is reloadable
// while the counters keep running.
func TestReloadHealthUnitID(t *testing.T) {
	dev := newFakeDevice(t)
	r, front := startReloadable(t, config.Device{
		Name: "dev1", DeviceAddr: dev.Addr(), HealthUnitID: u8p(100),
	})

	readUnit := func(unit uint8) bool {
		conn := dial(t, front)
		defer conn.Close()
		adu, _ := mbtcp.NewADU(0x7777, unit, []byte{3, 0, 0, 0, 1})
		if _, err := conn.Write(adu.Frame()); err != nil {
			t.Fatalf("write: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := mbtcp.ReadADU(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return len(resp.PDU) >= 4 && !resp.IsException()
	}
	if !readUnit(100) {
		t.Fatal("health unit 100 not served before reload")
	}

	cfg := &config.Config{Devices: []config.Device{{
		Name: "dev1", DeviceAddr: dev.Addr(), ListenAddr: r.gws[0].dev.ListenAddr, HealthUnitID: u8p(101),
	}}}
	cfg.Defaults()
	if warn := r.Reload(cfg); len(warn) != 0 {
		t.Fatalf("unexpected reload warnings: %v", warn)
	}
	if !readUnit(101) {
		t.Fatal("health unit 101 not served after reload")
	}
	// Unit 100 is now a normal device request: the fake device answers
	// 0xCAFE for register 0x0100 only, so the health magic is gone.
	if readUnit(100) {
		t.Fatal("health unit 100 still answered after reload")
	}
}
