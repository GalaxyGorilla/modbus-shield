// Package proxy contains the modbus-shield gateway core: front-leg
// listener, per-client lock-step loops, the upstream connection pool, and
// the transaction multiplexer.
package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// fakeDevice is an in-Go Modbus TCP device for e2e tests. It serves reads
// of holding register 0x0100 (value 0xCAFE) and echoes transaction and
// unit IDs exactly, like a well-behaved legacy device.
type fakeDevice struct {
	t    *testing.T
	ln   net.Listener
	done chan struct{}

	// LockStep caps the device at one concurrent connection when true
	// (models fragile legacy devices); unlimited when false.
	LockStep bool

	served atomic.Int64 // completed request/response cycles
	active atomic.Int64 // currently open device connections
}

func newFakeDevice(t *testing.T) *fakeDevice {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake device listen: %v", err)
	}
	f := &fakeDevice{t: t, ln: ln, done: make(chan struct{})}
	go f.serve()
	t.Cleanup(f.Close)
	return f
}

// Addr returns the device's listen address.
func (f *fakeDevice) Addr() string { return f.ln.Addr().String() }

// Served returns the number of completed request/response cycles.
func (f *fakeDevice) Served() int64 { return f.served.Load() }

// Active returns the number of currently open device connections.
func (f *fakeDevice) Active() int64 { return f.active.Load() }

// Close stops the listener and drops open device connections.
func (f *fakeDevice) Close() {
	select {
	case <-f.done:
		return
	default:
	}
	close(f.done)
	f.ln.Close()
}

func (f *fakeDevice) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
				continue
			}
		}
		go f.handle(conn)
	}
}

func (f *fakeDevice) handle(conn net.Conn) {
	defer conn.Close()
	f.active.Add(1)
	if f.LockStep && f.active.Load() > 1 {
		f.active.Add(-1)
		return // fragile device: refuse concurrent connection
	}
	defer f.active.Add(-1)

	hdr := make([]byte, mbtcp.HeaderLen)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(hdr[4:6]))
		if length < mbtcp.MinLength || length > mbtcp.MaxLength {
			return // malformed: drop connection like a real device
		}
		pdu := make([]byte, length-1)
		if _, err := io.ReadFull(conn, pdu); err != nil {
			return
		}
		resp := f.respond(hdr, pdu)
		if resp == nil {
			return
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
		f.served.Add(1)
	}
}

// respond builds the response frame for a request. Returns nil to drop
// the connection (unsupported function code).
func (f *fakeDevice) respond(hdr []byte, pdu []byte) []byte {
	fc := pdu[0]
	switch fc {
	case 3: // read holding registers: only register 0x0100 exists
		if len(pdu) < 5 {
			return nil
		}
		start := binary.BigEndian.Uint16(pdu[1:3])
		qty := binary.BigEndian.Uint16(pdu[3:5])
		if start != 0x0100 || qty != 1 {
			return exception(hdr, pdu, 0x02) // illegal data address
		}
		body := []byte{fc, 2, 0xCA, 0xFE}
		return frame(hdr, body)
	default:
		return exception(hdr, pdu, 0x01) // illegal function
	}
}

// exception builds a Modbus exception response echoing the request header.
func exception(hdr []byte, reqPDU []byte, code byte) []byte {
	return frame(hdr, []byte{reqPDU[0] | 0x80, code})
}

// frame assembles a wire frame from the request header (echoing txn and
// unit IDs) and a response PDU.
func frame(hdr []byte, pdu []byte) []byte {
	out := make([]byte, 0, mbtcp.HeaderLen+len(pdu))
	out = append(out, hdr[0:6]...) // txn, proto, length
	out[4] = byte((len(pdu) + 1) >> 8)
	out[5] = byte(len(pdu) + 1)
	out = append(out, hdr[6]) // unit ID
	return append(out, pdu...)
}
