package proxy

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// rtuDevice is a fake serial-to-TCP converter: it speaks bare Modbus RTU
// frames (addr + PDU + CRC16) instead of MBAP. FC3 reads of register
// 0x0100 qty 1 answer 0xCAFE; other reads get exception 0x02; writes are
// echoed; frames with a bad CRC are dropped without response.
type rtuDevice struct {
	t        *testing.T
	ln       net.Listener
	done     chan struct{}
	closeOne sync.Once
	served   int64
	mu       sync.Mutex
}

func newRTUDevice(t *testing.T) *rtuDevice {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("rtu device listen: %v", err)
	}
	d := &rtuDevice{t: t, ln: ln, done: make(chan struct{})}
	t.Cleanup(d.Close)
	go d.serve()
	return d
}

func (d *rtuDevice) Addr() string { return d.ln.Addr().String() }

func (d *rtuDevice) Served() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.served
}

func (d *rtuDevice) Close() {
	d.closeOne.Do(func() {
		close(d.done)
		d.ln.Close()
	})
}

func (d *rtuDevice) serve() {
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			return
		}
		go d.handle(conn)
	}
}

func (d *rtuDevice) handle(conn net.Conn) {
	defer conn.Close()
	readFull := func(buf []byte) bool {
		total := 0
		for total < len(buf) {
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := conn.Read(buf[total:])
			total += n
			if err != nil {
				return false
			}
		}
		return true
	}
	for {
		// Read one RTU REQUEST frame. Request shapes (no bytecount on
		// requests — that is a response-only field): addr + fc, then a
		// fixed body of 6 bytes (register/qty or value) + CRC.
		head := make([]byte, 2)
		if !readFull(head) {
			return
		}
		fc := head[1]
		restLen := 0
		switch {
		case fc&0x80 != 0:
			restLen = 3 // exception: code + CRC
		case fc == 1 || fc == 2 || fc == 3 || fc == 4:
			restLen = 6 // addr(2) + qty(2) + CRC(2)
		case fc == 5 || fc == 6:
			restLen = 6 // reg(2) + value(2) + CRC(2)
		case fc == 15 || fc == 16 || fc == 23:
			restLen = 7 // addr(2) + qty(2) + bytecount(1) + CRC(2), data follows
		default:
			return // unknown: close
		}
		rest := make([]byte, restLen)
		if !readFull(rest) {
			return
		}
		// Multi-write requests (15/16/23) carry data after the bytecount.
		if (fc == 15 || fc == 16 || fc == 23) && len(rest) >= 5 {
			extra := make([]byte, int(rest[4])+2) // data + CRC
			if !readFull(extra) {
				return
			}
			rest = append(rest, extra...)
		}
		frame := append(append([]byte{}, head...), rest...)
		if err := mbtcp.VerifyRTUFrame(frame); err != nil {
			continue // bad CRC: silently dropped (serial bridges do this)
		}
		resp := d.respond(frame)
		if resp == nil {
			continue
		}
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(resp); err != nil {
			return
		}
		d.mu.Lock()
		d.served++
		d.mu.Unlock()
	}
}

// respond builds the RTU response frame for a verified request frame.
func (d *rtuDevice) respond(req []byte) []byte {
	unit, fc := req[0], req[1]
	var pdu []byte
	switch {
	case fc == 3 && bytes.Equal(req[2:6], []byte{0x01, 0x00, 0x00, 0x01}):
		pdu = []byte{3, 2, 0xCA, 0xFE}
	case fc == 3:
		pdu = []byte{0x83, 0x02} // exception: illegal data address
	case fc == 6:
		pdu = req[1:7] // echo request PDU per spec
	case fc == 5:
		pdu = req[1:6] // echo request PDU per spec
	default:
		pdu = []byte{fc | 0x80, 0x01}
	}
	f, err := mbtcp.RTUFrame(unit, pdu)
	if err != nil {
		return nil
	}
	return f
}

// readFullRTU removed: the device reads with an inline readFull loop.

// TestRTUDeviceDirect exercises the fake RTU device without the proxy.
func TestRTUDeviceDirect(t *testing.T) {
	dev := newRTUDevice(t)
	req, err := mbtcp.RTUFrame(1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("RTUFrame: %v", err)
	}
	conn, err := net.Dial("tcp", dev.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	unit, pdu, err := mbtcp.ReadRTUResponse(conn, conn, 50*time.Millisecond, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if unit != 1 || !bytes.Equal(pdu, []byte{3, 2, 0xCA, 0xFE}) {
		t.Fatalf("unit %d pdu %x", unit, pdu)
	}
}

// TestGatewayRTUOverTCP is the B7 acceptance: an MBAP client reads
// through the box from a bare-RTU device; the proxy translates MBAP to
// RTU and back, including exceptions and unit-ID addressing.
func TestGatewayRTUOverTCP(t *testing.T) {
	dev := newRTUDevice(t)
	var cfg config.Device
	cfg.Name = "rtu-dev"
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.DeviceAddr = dev.Addr()
	cfg.RTUOverTCP = true
	cfg.TimeoutMs = 2000
	full := &config.Config{Devices: []config.Device{cfg}}
	full.Defaults()

	front := startDeviceGateway(t, cfg)
	conn := dial(t, front)
	defer conn.Close()
	req, err := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if err := writeAllRTU(t, conn, req.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Header.TransactionID != 0x1234 || resp.Header.UnitID != 1 {
		t.Fatalf("correlation: txn %d unit %d", resp.Header.TransactionID, resp.Header.UnitID)
	}
	if !bytes.Equal(resp.PDU, []byte{3, 2, 0xCA, 0xFE}) {
		t.Fatalf("PDU = %x, want 0302cafe", resp.PDU)
	}

	// Exception pass-through: register that does not exist.
	req2, err := mbtcp.NewADU(0x1235, 1, []byte{3, 0x02, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU2: %v", err)
	}
	if err := writeAllRTU(t, conn, req2.Frame()); err != nil {
		t.Fatalf("write2: %v", err)
	}
	resp2, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read2: %v", err)
	}
	code, ok := resp2.ExceptionCode()
	if !ok || code != mbtcp.ExceptionIllegalDataAddr {
		t.Fatalf("want exception 0x02, got fc %d code %d ok %v", resp2.FunctionCode(), code, ok)
	}

	// Unit-ID addressing: unit 17 reaches the device as RTU addr 17.
	req3, err := mbtcp.NewADU(0x1236, 17, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU3: %v", err)
	}
	if err := writeAllRTU(t, conn, req3.Frame()); err != nil {
		t.Fatalf("write3: %v", err)
	}
	resp3, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read3: %v", err)
	}
	if resp3.Header.UnitID != 17 || !bytes.Equal(resp3.PDU, []byte{3, 2, 0xCA, 0xFE}) {
		t.Fatalf("unit addressing failed: unit %d pdu %x", resp3.Header.UnitID, resp3.PDU)
	}

	if got := dev.Served(); got != 3 {
		t.Errorf("device served = %d, want 3", got)
	}
}

// TestGatewayRTUWithUnitRemap checks device_unit_id remap over the RTU
// leg: the client's unit ID is rewritten to the device's RTU address and
// back.
func TestGatewayRTUWithUnitRemap(t *testing.T) {
	dev := newRTUDevice(t)
	var cfg config.Device
	cfg.Name = "rtu-remap"
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.DeviceAddr = dev.Addr()
	cfg.RTUOverTCP = true
	cfg.DeviceUnitID = ptrUnit(17)
	cfg.TimeoutMs = 2000
	full := &config.Config{Devices: []config.Device{cfg}}
	full.Defaults()

	front := startDeviceGateway(t, cfg)
	conn := dial(t, front)
	defer conn.Close()
	req, err := mbtcp.NewADU(0x42, 5, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if err := writeAllRTU(t, conn, req.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Header.UnitID != 5 {
		t.Fatalf("client unit = %d, want 5 (remapped back)", resp.Header.UnitID)
	}
	if !bytes.Equal(resp.PDU, []byte{3, 2, 0xCA, 0xFE}) {
		t.Fatalf("PDU = %x", resp.PDU)
	}
}

// writeAllRTU writes the whole frame.
func writeAllRTU(t *testing.T, conn net.Conn, frame []byte) error {
	t.Helper()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(frame)
	return err
}
