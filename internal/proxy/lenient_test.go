package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// rawExchangeUnit sends one FC3 read on an open front-leg connection
// addressed to the given unit ID and returns the response ADU.
func rawExchangeUnit(t *testing.T, conn net.Conn, txn uint16, unit uint8) mbtcp.ADU {
	t.Helper()
	adu, err := mbtcp.NewADU(txn, unit, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Header.TransactionID != txn {
		t.Fatalf("correlation failed: got txn %d, want %d", resp.Header.TransactionID, txn)
	}
	return resp
}

// readOnUnit sends one register-0x0100 read on an open front-leg
// connection addressed to the given unit ID and returns the value.
func readOnUnit(t *testing.T, conn net.Conn, unit uint8) (uint16, error) {
	t.Helper()
	adu, err := mbtcp.NewADU(0x1234, unit, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		return 0, err
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		return 0, err
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		return 0, err
	}
	if resp.IsException() {
		code, _ := resp.ExceptionCode()
		return 0, fmt.Errorf("device exception: code=%#x", code)
	}
	return binary.BigEndian.Uint16(resp.PDU[2:4]), nil
}

// TestStrictCorrelationRejectsForeignTxn pins the default: a device that
// does not echo transaction IDs is not usable through a strict gateway —
// the mismatched frame is discarded until the request deadline expires
// and the client sees gateway exception 0x0B.
func TestStrictCorrelationRejectsForeignTxn(t *testing.T) {
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{MangleTxn: 7})
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr(), TimeoutMs: 500})

	conn := dial(t, front)
	defer conn.Close()
	resp := rawExchangeUnit(t, conn, 1, 1)
	if !resp.IsException() || resp.PDU[1] != mbtcp.ExceptionGatewayTargetFail {
		t.Fatalf("strict mode: want exception 0x0B, got PDU %x", resp.PDU)
	}
}

// TestLenientCorrelationAcceptsForeignTxn is the lenient_correlation
// contract: the response is matched even though the device echoed a
// different transaction ID, and the client still sees ITS OWN transaction
// ID and protocol ID 0 on the wire.
func TestLenientCorrelationAcceptsForeignTxn(t *testing.T) {
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{MangleTxn: 7})
	front := startGateway(t, config.Device{
		DeviceAddr:         dev.Addr(),
		TimeoutMs:          1000,
		LenientCorrelation: true,
	})

	conn := dial(t, front)
	defer conn.Close()
	for _, txn := range []uint16{1, 2, 0x7FFF} {
		resp := rawExchangeUnit(t, conn, txn, 1)
		if resp.IsException() {
			t.Fatalf("txn %d: unexpected exception %x", txn, resp.PDU)
		}
		if resp.Header.ProtocolID != mbtcp.ProtocolID {
			t.Fatalf("txn %d: protocol ID %d, want 0 (normalized)", txn, resp.Header.ProtocolID)
		}
		if got := binary.BigEndian.Uint16(resp.PDU[2:4]); got != 0xCAFE {
			t.Fatalf("txn %d: value %#x, want 0xCAFE", txn, got)
		}
	}
}

// TestForeignProtocolID pins both sides of the protocol-ID policy: strict
// rejects a device that puts junk in the MBAP protocol field, lenient
// accepts it (and still hands the client protocol ID 0).
func TestForeignProtocolID(t *testing.T) {
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{ForeignProtocolID: 0x1234})

	strictFront := startGateway(t, config.Device{
		Name: "strict-proto", DeviceAddr: dev.Addr(), TimeoutMs: 500,
	})
	strictConn := dial(t, strictFront)
	defer strictConn.Close()
	if resp := rawExchangeUnit(t, strictConn, 1, 1); !resp.IsException() || resp.PDU[1] != mbtcp.ExceptionGatewayTargetFail {
		t.Fatalf("strict mode: want exception 0x0B, got PDU %x", resp.PDU)
	}

	lenientFront := startGateway(t, config.Device{
		Name: "lenient-proto", DeviceAddr: dev.Addr(), TimeoutMs: 500,
		LenientCorrelation: true,
	})
	lenientConn := dial(t, lenientFront)
	defer lenientConn.Close()
	resp := rawExchangeUnit(t, lenientConn, 2, 1)
	if resp.IsException() {
		t.Fatalf("lenient mode: unexpected exception %x", resp.PDU)
	}
	if resp.Header.ProtocolID != mbtcp.ProtocolID {
		t.Fatalf("lenient mode: protocol ID %d, want 0 (normalized)", resp.Header.ProtocolID)
	}
	if got := binary.BigEndian.Uint16(resp.PDU[2:4]); got != 0xCAFE {
		t.Fatalf("lenient mode: value %#x, want 0xCAFE", got)
	}
}
