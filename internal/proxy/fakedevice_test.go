// Package proxy contains the modbus-shield gateway core: front-leg
// listener, per-client lock-step loops, the upstream connection pool, and
// the transaction multiplexer.
package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// fakeDevice is an in-Go Modbus TCP device for e2e tests. It serves reads
// of holding register 0x0100 (value 0xCAFE) and echoes transaction and
// unit IDs exactly, like a well-behaved legacy device.
type fakeDevice struct {
	t  *testing.T
	ln net.Listener

	// LockStep caps the device at one concurrent connection when true
	// (models fragile legacy devices); unlimited when false.
	LockStep bool

	// RespondDelay makes the device take this long to answer each
	// request (models slow devices; exercises the fairness queue).
	RespondDelay time.Duration

	served   atomic.Int64 // completed request/response cycles
	active   atomic.Int64 // currently open device connections
	accepted atomic.Int64 // total accepted connections (incl. LockStep-refused)

	mu   sync.Mutex
	open map[net.Conn]struct{} // live device connections (for Close)

	// knobs (see fakeDeviceCfg); set at construction only.
	mangleTxn    uint16
	foreignProto uint16
	record       bool
	unitValues   bool

	muReq  sync.Mutex
	reqLog []uint8 // unit IDs of recorded requests, in arrival order

	done chan struct{}
	once sync.Once
}

func newFakeDevice(t *testing.T) *fakeDevice {
	t.Helper()
	return newFakeDeviceCfg(t, fakeDeviceCfg{})
}

// fakeDeviceCfg carries the test knobs for a fake device; all fields are
// applied BEFORE the device starts serving (no post-construction races).
type fakeDeviceCfg struct {
	LockStep     bool
	RespondDelay time.Duration
	OnAddr       string // listen on this address instead of 127.0.0.1:0

	// MangleTxn, when non-zero, is added to the echoed transaction ID —
	// models converters/gateways that mishandle transaction correlation.
	MangleTxn uint16

	// ForeignProtocolID, when non-zero, is written into the response's
	// MBAP protocol-ID field — models devices that put junk there.
	ForeignProtocolID uint16

	// RecordRequests makes the device remember the unit ID of every
	// request in arrival order (fairness assertions).
	RecordRequests bool

	// UnitValues answers a register read with 0xCA00|unit-ID instead of
	// the fixed 0xCAFE, so a client can tell its own answer from another
	// client's (parallel clients use distinct unit IDs).
	UnitValues bool
}

func newFakeDeviceCfg(t *testing.T, cfg fakeDeviceCfg) *fakeDevice {
	t.Helper()
	listen := cfg.OnAddr
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatalf("fake device listen: %v", err)
	}
	f := &fakeDevice{
		t:            t,
		ln:           ln,
		done:         make(chan struct{}),
		open:         make(map[net.Conn]struct{}),
		LockStep:     cfg.LockStep,
		RespondDelay: cfg.RespondDelay,
		mangleTxn:    cfg.MangleTxn,
		foreignProto: cfg.ForeignProtocolID,
		record:       cfg.RecordRequests,
		unitValues:   cfg.UnitValues,
	}
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

// Accepted returns the total number of connections the device accepted
// over the test's lifetime (including LockStep-refused ones).
func (f *fakeDevice) Accepted() int64 { return f.accepted.Load() }

// Requests returns the unit IDs of recorded requests in arrival order
// (only populated when fakeDeviceCfg.RecordRequests is set).
func (f *fakeDevice) Requests() []uint8 {
	f.muReq.Lock()
	defer f.muReq.Unlock()
	return append([]uint8(nil), f.reqLog...)
}

// trackConn adds/removes conn from the open-connections set (for Close to
// force-close live device connections, like a powered-off device).
func (f *fakeDevice) trackConn(conn net.Conn, add bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if add {
		f.open[conn] = struct{}{}
	} else {
		delete(f.open, conn)
	}
}

// Close stops the listener, force-closes live device connections, and is
// idempotent — models the device losing power mid-operation.
func (f *fakeDevice) Close() {
	f.once.Do(func() {
		close(f.done)
		f.ln.Close()
		f.mu.Lock()
		for c := range f.open {
			c.Close()
		}
		f.open = nil
		f.mu.Unlock()
	})
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
	f.accepted.Add(1)
	f.trackConn(conn, true)
	if f.LockStep && f.active.Load() > 1 {
		f.active.Add(-1)
		f.trackConn(conn, false)
		return // fragile device: refuse concurrent connection
	}
	defer func() {
		f.active.Add(-1)
		f.trackConn(conn, false)
	}()

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
		if f.RespondDelay > 0 {
			time.Sleep(f.RespondDelay)
		}
		if f.record {
			f.muReq.Lock()
			f.reqLog = append(f.reqLog, hdr[6])
			f.muReq.Unlock()
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
			return f.exception(hdr, pdu, 0x02) // illegal data address
		}
		val := uint16(0xCAFE)
		if f.unitValues {
			val = 0xCA00 | uint16(hdr[6])
		}
		body := []byte{fc, 2, byte(val >> 8), byte(val)}
		return f.frame(hdr, body)
	case 6: // write single register: per spec the response echoes the request PDU
		if len(pdu) < 5 {
			return nil
		}
		return f.frame(hdr, pdu)
	default:
		return f.exception(hdr, pdu, 0x01) // illegal function
	}
}

// exception builds a Modbus exception response echoing the request header.
func (f *fakeDevice) exception(hdr []byte, reqPDU []byte, code byte) []byte {
	return f.frame(hdr, []byte{reqPDU[0] | 0x80, code})
}

// frame assembles a wire frame from the request header and a response PDU.
// By default it echoes the transaction and protocol IDs like a well-behaved
// device; mangleTxn/foreignProto model non-conforming peers.
func (f *fakeDevice) frame(hdr []byte, pdu []byte) []byte {
	txn := binary.BigEndian.Uint16(hdr[0:2]) + f.mangleTxn
	proto := binary.BigEndian.Uint16(hdr[2:4])
	if f.foreignProto != 0 {
		proto = f.foreignProto
	}
	out := make([]byte, 0, mbtcp.HeaderLen+len(pdu))
	out = append(out,
		byte(txn>>8), byte(txn),
		byte(proto>>8), byte(proto),
		byte((len(pdu)+1)>>8), byte(len(pdu)+1),
		hdr[6], // unit ID
	)
	return append(out, pdu...)
}
