package proxy

import (
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

func intp(n int) *int { return &n }

func u8p(n uint8) *uint8 { return &n }

// exchangePDU sends one request PDU on an open front-leg connection and
// returns the response.
func exchangePDU(t *testing.T, conn interface {
	Write([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, txn uint16, unit uint8, pdu []byte, read func() (mbtcp.ADU, error)) mbtcp.ADU {
	t.Helper()
	adu, err := mbtcp.NewADU(txn, unit, pdu)
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	resp, err := read()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// TestGatewayWritePolicyUnitScoped e2e: only unit 2 may write register
// 0x0100 with FC6. Unit 2's write reaches the device; unit 1's identical
// write is answered with exception 0x02 and the device never sees it.
func TestGatewayWritePolicyUnitScoped(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr: dev.Addr(),
		WritePolicy: &config.WritePolicyConfig{
			Default: "deny",
			Rules: []config.WriteRule{{
				Unit:   intp(2),
				FC:     []int{6},
				From:   intp(0x0100),
				To:     intp(0x0100),
				Action: "allow",
			}},
		},
	})

	conn := dial(t, front)
	defer conn.Close()

	// Unit 1: denied by the default (no rule covers it).
	resp := exchangePDU(t, conn, 0x1001, 1, []byte{6, 0x01, 0x00, 0x2A, 0x2A}, func() (mbtcp.ADU, error) {
		return mbtcp.ReadADU(conn)
	})
	if !resp.IsException() {
		t.Fatalf("unit 1 write was forwarded: PDU %x", resp.PDU)
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalDataAddr {
		t.Fatalf("exception code = %#x, want 0x02 (Illegal Data Address)", code)
	}
	if got := dev.Served(); got != 0 {
		t.Fatalf("device served %d requests, want 0 (denied write must not reach it)", got)
	}

	// Unit 2: allowed, forwarded verbatim.
	resp = exchangePDU(t, conn, 0x1002, 2, []byte{6, 0x01, 0x00, 0x2A, 0x2A}, func() (mbtcp.ADU, error) {
		return mbtcp.ReadADU(conn)
	})
	if resp.IsException() {
		t.Fatalf("unit 2 write was denied: %x", resp.PDU)
	}
	if got := dev.Served(); got != 1 {
		t.Fatalf("device served %d requests, want 1", got)
	}
}

// TestGatewayWritePolicyAllowMustCover: an allow window 0x0100..0x0103
// covers a 4-register FC16 write exactly; a 5-register write starting at
// 0x0100 straddles the window end and must be denied.
func TestGatewayWritePolicyAllowMustCover(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr: dev.Addr(),
		WritePolicy: &config.WritePolicyConfig{
			Default: "deny",
			Rules: []config.WriteRule{{
				FC:     []int{16},
				From:   intp(0x0100),
				To:     intp(0x0103),
				Action: "allow",
			}},
		},
	})
	conn := dial(t, front)
	defer conn.Close()

	fc16 := func(addr, qty uint16) []byte {
		pdu := []byte{16, byte(addr >> 8), byte(addr), byte(qty >> 8), byte(qty), byte(2 * qty)}
		return append(pdu, make([]byte, 2*qty)...)
	}

	resp := exchangePDU(t, conn, 0x2001, 1, fc16(0x0100, 4), func() (mbtcp.ADU, error) {
		return mbtcp.ReadADU(conn)
	})
	if resp.IsException() {
		t.Fatalf("write covering the allowed window was denied: %x", resp.PDU)
	}
	resp = exchangePDU(t, conn, 0x2002, 1, fc16(0x0100, 5), func() (mbtcp.ADU, error) {
		return mbtcp.ReadADU(conn)
	})
	if code, _ := resp.ExceptionCode(); !resp.IsException() || code != mbtcp.ExceptionIllegalDataAddr {
		t.Fatalf("straddling write: want exception 0x02, got %x", resp.PDU)
	}
	if got := dev.Served(); got != 1 {
		t.Fatalf("device served %d requests, want 1", got)
	}
}

// TestGatewayWritePolicyDenyCarveOut: deny-list mode (default allow) with
// a protected block — writes inside the block are denied, everything else
// flows, and a multi-register write touching the block is denied too.
func TestGatewayWritePolicyDenyCarveOut(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr: dev.Addr(),
		WritePolicy: &config.WritePolicyConfig{
			Default: "allow",
			Rules: []config.WriteRule{{
				FC:     []int{6, 16},
				From:   intp(0x8000),
				To:     intp(0x800F),
				Action: "deny",
			}},
		},
	})
	conn := dial(t, front)
	defer conn.Close()

	fc16 := func(addr, qty uint16) []byte {
		pdu := []byte{16, byte(addr >> 8), byte(addr), byte(qty >> 8), byte(qty), byte(2 * qty)}
		return append(pdu, make([]byte, 2*qty)...)
	}

	cases := []struct {
		name string
		pdu  []byte
		want bool // true = forwarded
	}{
		{"outside block", []byte{6, 0x01, 0x00, 0x11, 0x11}, true},
		{"inside block", []byte{6, 0x80, 0x03, 0x11, 0x11}, false},
		{"multi write ending inside block", fc16(0x7FFE, 4), false},
		{"multi write entirely outside", fc16(0x7FF0, 4), true},
	}
	for i, tc := range cases {
		resp := exchangePDU(t, conn, uint16(0x3000+i), 1, tc.pdu, func() (mbtcp.ADU, error) {
			return mbtcp.ReadADU(conn)
		})
		if tc.want && resp.IsException() {
			t.Fatalf("%s: denied, want forwarded (%x)", tc.name, resp.PDU)
		}
		if !tc.want {
			if code, _ := resp.ExceptionCode(); !resp.IsException() || code != mbtcp.ExceptionIllegalDataAddr {
				t.Fatalf("%s: want exception 0x02, got %x", tc.name, resp.PDU)
			}
		}
	}
	if got := dev.Served(); got != 2 {
		t.Fatalf("device served %d requests, want 2", got)
	}
}

// TestGatewayWritePolicyFC23ChecksWritePart: FC23 is a read/write combo;
// authorization applies to the WRITE half (spec: the write is the state
// change), so the read address range must not satisfy the policy.
func TestGatewayWritePolicyFC23ChecksWritePart(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr: dev.Addr(),
		WritePolicy: &config.WritePolicyConfig{
			Default: "deny",
			Rules: []config.WriteRule{{
				FC:     []int{23},
				From:   intp(0x0100),
				To:     intp(0x0101),
				Action: "allow",
			}},
		},
	})
	conn := dial(t, front)
	defer conn.Close()

	fc23 := func(writeAddr, writeQty uint16) []byte {
		pdu := []byte{23, 0x01, 0x00, 0x00, 0x01,
			byte(writeAddr >> 8), byte(writeAddr), byte(writeQty >> 8), byte(writeQty), 2, 0xAB, 0xCD}
		return pdu
	}

	resp := exchangePDU(t, conn, 0x4001, 1, fc23(0x0100, 2), func() (mbtcp.ADU, error) {
		return mbtcp.ReadADU(conn)
	})
	if resp.IsException() {
		t.Fatalf("FC23 write inside the window was denied: %x", resp.PDU)
	}
	resp = exchangePDU(t, conn, 0x4002, 1, fc23(0x0101, 2), func() (mbtcp.ADU, error) {
		return mbtcp.ReadADU(conn)
	})
	if code, _ := resp.ExceptionCode(); !resp.IsException() || code != mbtcp.ExceptionIllegalDataAddr {
		t.Fatalf("FC23 write past the window: want exception 0x02, got %x", resp.PDU)
	}
	if got := dev.Served(); got != 1 {
		t.Fatalf("device served %d requests, want 1", got)
	}
}
