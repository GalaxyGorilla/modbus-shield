package proxy

import (
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

// connsMu guards conns in TestGatewayNoGoroutineLeak (appended from
// concurrent client goroutines).
var connsMu sync.Mutex

// dialErr is dial() for concurrent goroutines: returns the error instead
// of calling t.Fatalf from a non-test goroutine.
func dialErr(front string) (net.Conn, error) {
	return net.DialTimeout("tcp", front, 2*time.Second)
}

// errValue formats a wrong-value read result.
func errValue(val uint16) error {
	return &valErr{got: val}
}

type valErr struct{ got uint16 }

func (e *valErr) Error() string {
	return "read: got " + hexVal(e.got) + ", want 0xcafe"
}

func hexVal(v uint16) string {
	const digits = "0123456789abcdef"
	out := []byte{'0', 'x', digits[v>>12&0xf], digits[v>>8&0xf], digits[v>>4&0xf], digits[v&0xf]}
	return string(out)
}

// TestGatewayMultiplexing is the milestone 4 acceptance: N clients read
// the device concurrently through the box and all get correct answers,
// while the fragile single-connection device sees exactly ONE upstream
// connection for the whole test.
func TestGatewayMultiplexing(t *testing.T) {
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{LockStep: true})
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr()})

	const nClients = 8
	const readsPerClient = 25

	var wg sync.WaitGroup
	errs := make(chan error, nClients)
	for i := 0; i < nClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialErr(front)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			for r := 0; r < readsPerClient; r++ {
				val, err := readOn(t, conn)
				if err != nil {
					errs <- err
					return
				}
				if val != 0xCAFE {
					errs <- errValue(val)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	if got := dev.Accepted(); got != 1 {
		t.Fatalf("fragile device saw %d connections, want exactly 1", got)
	}
	if got := dev.Served(); got != nClients*readsPerClient {
		t.Fatalf("device served %d requests, want %d", got, nClients*readsPerClient)
	}
}

// TestGatewayFairness verifies the upstream multiplexer serializes without
// starvation: while every request takes the device 100ms to answer, all
// clients still complete all their reads (queued, first come first
// served) — nobody is stuck behind the queue forever.
func TestGatewayFairness(t *testing.T) {
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{RespondDelay: 100 * time.Millisecond})
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr(), TimeoutMs: 8000})

	const nClients = 4
	var wg sync.WaitGroup
	errs := make(chan error, nClients)
	for i := 0; i < nClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialErr(front)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			for r := 0; r < 3; r++ {
				val, err := readOn(t, conn)
				if err != nil {
					errs <- err
					return
				}
				if val != 0xCAFE {
					errs <- errValue(val)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestGatewayIdleClientDoesNotBlock verifies an open, idle front-leg
// connection never blocks other clients: while client 1 sits idle, client
// 2 performs reads normally.
func TestGatewayIdleClientDoesNotBlock(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr()})

	idle := dial(t, front)
	defer idle.Close()

	for i := 0; i < 3; i++ {
		val, err := readReg(t, front)
		if err != nil {
			t.Fatalf("read %d with idle client present: %v", i, err)
		}
		if val != 0xCAFE {
			t.Fatalf("read %d: got %#x, want 0xCAFE", i, val)
		}
	}
}

// TestGatewayStalledClient verifies a stalled front-leg client (accepted,
// sends a partial frame, then goes silent and disconnects) fails alone;
// subsequent clients work.
func TestGatewayStalledClient(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr()})

	stall := dial(t, front)
	stall.Write([]byte{0x42}) // partial header, then silence
	time.Sleep(50 * time.Millisecond)
	stall.Close()

	val, err := readReg(t, front)
	if err != nil {
		t.Fatalf("gateway wedged after stalled client: %v", err)
	}
	if val != 0xCAFE {
		t.Fatalf("got %#x, want 0xCAFE", val)
	}
}

// TestGatewayConnCapFriendly verifies the connection cap: with
// max_clients=2, the first two connections are admitted and work; the
// third and fourth are rejected (closed by the proxy before any Modbus
// exchange).
func TestGatewayConnCapFriendly(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr: dev.Addr(),
		MaxClients: 2,
	})

	conns := make([]net.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		conns = append(conns, dial(t, front))
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	admitted, rejected := 0, 0
	for _, c := range conns {
		if _, err := readOn(t, c); err != nil {
			rejected++
		} else {
			admitted++
		}
	}
	if admitted != 2 || rejected != 2 {
		t.Fatalf("admitted=%d rejected=%d, want 2/2", admitted, rejected)
	}
}

// devAddr reserves a free 127.0.0.1 port that a fake device can re-bind
// after being closed (device-outage test).
func devAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestGatewayDeviceOutageRecovery verifies never-down semantics: when the
// device connection dies mid-operation, the failing request surfaces an
// error (exception), the upstream connection is dropped, and after the
// device returns the proxy re-dials and traffic flows again — no restart
// needed.
func TestGatewayDeviceOutageRecovery(t *testing.T) {
	addr := devAddr(t) // fixed address: device goes away and re-binds here
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{OnAddr: addr})
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr(), TimeoutMs: 1000})

	// Warm up: one successful read establishes the upstream conn.
	if val, err := readReg(t, front); err != nil || val != 0xCAFE {
		t.Fatalf("warm-up read: val=%#x err=%v", val, err)
	}

	// Take the device down (listener AND live device connections).
	dev.Close()
	if _, err := readReg(t, front); err == nil {
		t.Fatal("expected failure while device down")
	}

	// Resurrect a device on the same address; the proxy must re-dial.
	dev2 := newFakeDeviceCfg(t, fakeDeviceCfg{OnAddr: addr})
	val, err := readReg(t, front)
	if err != nil {
		t.Fatalf("no recovery after device returned: %v", err)
	}
	if val != 0xCAFE {
		t.Fatalf("got %#x, want 0xCAFE", val)
	}
	if got := dev2.Accepted(); got != 1 {
		t.Fatalf("resurrected device saw %d connections, want 1 (re-dial)", got)
	}
}

// TestGatewayNoGoroutineLeak is the regression test for goroutine leaks:
// after a burst of client connections is closed, the proxy must return to
// its baseline goroutine count (no per-connection goroutine survives).
func TestGatewayNoGoroutineLeak(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr()})

	// Warm up (establishes the upstream conn) and let things settle.
	if _, err := readReg(t, front); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	base := runtime.NumGoroutine()

	const nClients = 8
	conns := make([]net.Conn, 0, nClients)
	var wg sync.WaitGroup
	for i := 0; i < nClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialErr(front)
			if err != nil {
				return
			}
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
			for r := 0; r < 10; r++ {
				if _, err := readOn(t, conn); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	for _, c := range conns {
		c.Close()
	}

	// All client handler goroutines must exit after their conns close.
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		if runtime.NumGoroutine() <= base {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: baseline=%d, now=%d", base, runtime.NumGoroutine())
		}
		time.Sleep(25 * time.Millisecond)
	}
}
