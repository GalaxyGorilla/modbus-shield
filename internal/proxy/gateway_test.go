package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// nopLogger satisfies proxy.Logger, discarding everything.
type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// ptrUnit returns a pointer to a unit ID (config.DeviceUnitID is *uint8).
func ptrUnit(u uint8) *uint8 { return &u }

// dial connects to a front-leg address with a test timeout.
func dial(t *testing.T, front string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", front, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", front, err)
	}
	return conn
}

// startGateway builds a one-device config around dev, starts a Runner,
// and returns the front-leg address.
func startGateway(t *testing.T, dev config.Device) string {
	t.Helper()
	dev.ListenAddr = "127.0.0.1:0"
	cfg := &config.Config{Devices: []config.Device{dev}}
	cfg.Defaults()
	r, err := NewRunner(cfg, nopLogger{})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- r.Run() }()
	t.Cleanup(r.Stop)
	<-r.bound // wait until Run() has bound the listeners
	ln := r.lns[0]
	return ln.Addr().String()
}

// readReg reads holding register 0x0100 through the proxy front end.
func readReg(t *testing.T, front string) (uint16, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", front, 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	adu, err := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		return 0, err
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		return 0, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		return 0, err
	}
	if resp.Header.TransactionID != 0x1234 || resp.Header.UnitID != 1 {
		return 0, fmt.Errorf("correlation failed: %+v", resp.Header)
	}
	return binary.BigEndian.Uint16(resp.PDU[2:4]), nil
}

// TestGatewayEndToEnd is the milestone acceptance: a client reads a fake
// device through the box and gets the right value back.
func TestGatewayEndToEnd(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr()})

	for i := 0; i < 5; i++ {
		val, err := readReg(t, front)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if val != 0xCAFE {
			t.Fatalf("read %d: got %#x, want 0xCAFE", i, val)
		}
	}
	if got := dev.Served(); got != 5 {
		t.Fatalf("device served %d requests, want 5", got)
	}
}

// TestGatewayUnitRemap verifies client unit IDs pass through while the
// device sees the configured upstream unit ID and responses are rewritten
// back to the client's unit ID.
func TestGatewayUnitRemap(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr:   dev.Addr(),
		DeviceUnitID: ptrUnit(17),
	})

	conn := dial(t, front)
	defer conn.Close()
	// Client speaks unit 5; the device must see 17.
	adu, _ := mbtcp.NewADU(42, 5, []byte{3, 0x01, 0x00, 0x00, 0x01})
	conn.Write(adu.Frame())
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Header.UnitID != 5 {
		t.Fatalf("response unit ID = %d, want client's 5", resp.Header.UnitID)
	}
	if resp.Header.TransactionID != 42 {
		t.Fatalf("response txn = %d, want 42", resp.Header.TransactionID)
	}
}

// TestGatewayReadOnly verifies write function codes are rejected locally
// with exception 0x01 and never reach the device.
func TestGatewayReadOnly(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr(), ReadOnly: true})

	conn := dial(t, front)
	defer conn.Close()
	// FC 5 write single coil.
	adu, _ := mbtcp.NewADU(7, 1, []byte{5, 0x00, 0x01, 0xFF, 0x00})
	conn.Write(adu.Frame())
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !resp.IsException() {
		t.Fatalf("expected exception, got FC %d", resp.FunctionCode())
	}
	code, ok := resp.ExceptionCode()
	if !ok || code != mbtcp.ExceptionIllegalFunction {
		t.Fatalf("exception code = %d (ok=%v), want 0x01", code, ok)
	}
	if dev.Served() != 0 {
		t.Fatalf("device saw %d requests; write must not reach device", dev.Served())
	}
}

// TestUpstreamStaleDiscardUnit exercises upstream.exchange directly: the
// first exchange times out (device never answers), the device's late reply
// arrives during the next exchange and must be discarded so the second
// request gets its own response.
func TestUpstreamStaleDiscardUnit(t *testing.T) {
	// Device that answers each request first with a stale (wrong txn)
	// response, then with the correct one. Exercises the discard path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	devDone := make(chan struct{})
	go func() {
		defer close(devDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 7)
		pdu := make([]byte, 255)
		for {
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(hdr[4:6]))
			if _, err := io.ReadFull(conn, pdu[:length-1]); err != nil {
				return
			}
			// Stale response: echo everything but use txn 0xFFFF.
			stale := make([]byte, 0, 7+length)
			stale = append(stale, 0xFF, 0xFF)
			stale = append(stale, hdr[2:6]...)
			stale = append(stale, hdr[6])
			stale = append(stale, pdu[:length-1]...)
			conn.Write(stale)
			// Correct response: echo header + PDU unchanged.
			out := make([]byte, 0, 7+length)
			out = append(out, hdr[:]...)
			out = append(out, pdu[:length-1]...)
			conn.Write(out)
		}
	}()

	u := newUpstream(ln.Addr().String(), nopLogger{})
	defer u.close()

	req, _ := mbtcp.NewADU(1, 1, []byte{3, 0x00, 0x00, 0x00, 0x01})
	resp, err := u.exchange(req, 3*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Header.TransactionID != 1 {
		t.Fatalf("got txn %d, want 1 (stale response not discarded)", resp.Header.TransactionID)
	}
	u.close() // unblock the device read loop
	<-devDone
}

// TestGatewayClientErrorNeverWedges verifies a client that dies mid-frame
// and a client sending garbage both fail alone; the next client works.
func TestGatewayClientErrorNeverWedges(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr()})

	// Client 1: dies mid-frame.
	c1 := dial(t, front)
	c1.Write([]byte{0x12, 0x34})
	c1.Close()

	// Client 2: garbage that is a valid-length but protocol-0 frame.
	c2 := dial(t, front)
	adu, _ := mbtcp.NewADU(9, 1, []byte{0xEE})
	c2.Write(adu.Frame())
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := mbtcp.ReadADU(c2)
	if err != nil {
		t.Fatalf("garbage client broke the gateway: %v", err)
	}
	_ = resp
	c2.Close()

	// Client 3: normal read must still work.
	val, err := readReg(t, front)
	if err != nil {
		t.Fatalf("gateway wedged after client errors: %v", err)
	}
	if val != 0xCAFE {
		t.Fatalf("got %#x, want 0xCAFE", val)
	}
}
