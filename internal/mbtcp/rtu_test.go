package mbtcp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// decode must hex-decode s or fail the test.
func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestCRC16KnownAnswers checks CRC-16/MODBUS against the canonical spec
// examples: empty CRC 0xFFFF; the two frames from the MODBUS over Serial
// Line spec V1.02.
func TestCRC16KnownAnswers(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want uint16
	}{
		{"empty", []byte{}, 0xFFFF},
		// CRC-16/MODBUS catalog check value ("123456789" -> 0x4B37).
		{"catalog check", []byte("123456789"), 0x4B37},
		// Spec V1.02 example: wire bytes end 76 87 (low byte first) =
		// uint16 0x8776.
		{"spec read-holding-regs", decode(t, "1103006B0003"), 0x8776},
		// Spec V1.02 example frame: CRC16 = 0x87BA, wire bytes BA 87
		// (low byte first).
		{"spec write-single-reg", decode(t, "1106006B0003"), 0x87BA},
	}
	for _, c := range cases {
		if got := CRC16(c.in); got != c.want {
			t.Errorf("%s: CRC16 = %#04x, want %#04x", c.name, got, c.want)
		}
	}
}

// TestRTUFrameRoundTrip builds frames from ADUs and re-reads them with
// ReadRTUResponse across all shape classes; PDU and unit must survive.
func TestRTUFrameRoundTrip(t *testing.T) {
	pdus := [][]byte{
		{3, 2, 0xCA, 0xFE},        // byte-count shape (FC3 response)
		{1, 1, 1},                 // byte-count (FC1)
		{2, 1, 0},                 // byte-count (FC2)
		{4, 2, 0x12, 0x34},        // byte-count (FC4)
		{23, 2, 0x01, 0x02},       // byte-count (FC23)
		{6, 0x01, 0x00, 0x00, 0x2A},  // fixed echo (FC6): addr + value
		{5, 0x01, 0x00, 0xFF, 0x00},  // fixed echo (FC5): addr + value
		{16, 0x00, 0x01, 0x00, 0x02}, // fixed echo (FC16)
		{15, 0x00, 0x01, 0x00, 0x02}, // fixed echo (FC15)
		{22, 0, 1, 0, 2, 0, 3},    // mask write (FC22)
	}
	for _, pdu := range pdus {
		f, err := RTUFrame(17, pdu)
		if err != nil {
			t.Fatalf("RTUFrame(%v): %v", pdu, err)
		}
		if len(f) < RTUMinFrame || len(f) > RTUMaxFrame {
			t.Fatalf("frame length %d out of bounds", len(f))
		}
		gotUnit, gotPDU, err := ReadRTUResponse(bytes.NewReader(f), nil, 0, time.Time{})
		if err != nil {
			t.Fatalf("ReadRTUResponse(%v): %v", pdu, err)
		}
		if gotUnit != 17 {
			t.Errorf("unit = %d, want 17", gotUnit)
		}
		if !bytes.Equal(gotPDU, pdu) {
			t.Errorf("PDU = %x, want %x", gotPDU, pdu)
		}
	}
}

// TestRTUExceptionFrameRoundTrip covers exception responses (fc|0x80):
// code + CRC.
func TestRTUExceptionFrameRoundTrip(t *testing.T) {
	f, err := RTUFrame(1, ExceptionPDU(6, ExceptionIllegalDataAddr))
	if err != nil {
		t.Fatalf("RTUFrame: %v", err)
	}
	unit, pdu, err := ReadRTUResponse(bytes.NewReader(f), nil, 0, time.Time{})
	if err != nil {
		t.Fatalf("ReadRTUResponse: %v", err)
	}
	if unit != 1 || !bytes.Equal(pdu, ExceptionPDU(6, ExceptionIllegalDataAddr)) {
		t.Fatalf("got unit %d pdu %x", unit, pdu)
	}
}

// TestRTUFrameErrors covers PDU validation and CRC mismatch.
func TestRTUFrameErrors(t *testing.T) {
	if _, err := RTUFrame(1, nil); !errors.Is(err, ErrPDUEmpty) {
		t.Errorf("empty PDU: err = %v, want ErrPDUEmpty", err)
	}
	if _, err := RTUFrame(1, make([]byte, MaxPDU+1)); !errors.Is(err, ErrPDULarge) {
		t.Errorf("oversized PDU: err = %v, want ErrPDULarge", err)
	}
	// Corrupt one CRC byte of a valid frame.
	f, _ := RTUFrame(1, []byte{3, 2, 0xCA, 0xFE})
	bad := append([]byte(nil), f...)
	bad[len(bad)-1] ^= 0xFF
	if _, _, err := ReadRTUResponse(bytes.NewReader(bad), nil, 0, time.Time{}); !errors.Is(err, ErrRTUCRC) {
		t.Errorf("bad CRC: err = %v, want ErrRTUCRC", err)
	}
	// Truncated frame (header only).
	if _, _, err := ReadRTUResponse(bytes.NewReader(f[:2]), nil, 0, time.Time{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated: err = %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestReadRTUResponseGapFallback covers unlisted function codes (here an
// encapsulated/vendor code) read via idle-gap framing over a real pipe:
// bytes arrive in bursts with sleeps between them; the reader must stop
// at the first quiet gap and verify the CRC.
func TestReadRTUResponseGapFallback(t *testing.T) {
	pdu := append([]byte{65}, bytes.Repeat([]byte{0xAA}, 10)...) // vendor fc 65 + 10 data bytes
	f, err := RTUFrame(9, pdu)
	if err != nil {
		t.Fatalf("RTUFrame: %v", err)
	}
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	go func() {
		// Burst-write the frame in three chunks with gaps between them,
		// mimicking a serial bridge sending one frame.
		for _, chunk := range [][]byte{f[:5], f[5:12], f[12:]} {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	// gap 50ms, overall deadline 2s: chunks are 15ms apart, so the reader
	// must only finish after the final chunk plus one quiet gap.
	start := time.Now()
	unit, got, err := ReadRTUResponse(r, r, 50*time.Millisecond, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("ReadRTUResponse: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Errorf("returned after %v; gap loop finished too early", elapsed)
	}
	if unit != 9 || !bytes.Equal(got, pdu) {
		t.Errorf("got unit %d pdu %x, want unit 9 pdu %x", unit, got, pdu)
	}
}

// TestReadRTUResponseDeadlineSupersedesGap ensures a non-zero deadline
// clamps the idle gap: a stalled stream cannot hold the reader forever.
func TestReadRTUResponseDeadlineSupersedesGap(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()
	go func() {
		_, _ = w.Write([]byte{9, 65}) // addr + unlisted fc, then silence
	}()
	start := time.Now()
	_, _, err := ReadRTUResponse(r, r, 10*time.Second, time.Now().Add(150*time.Millisecond))
	if err == nil {
		t.Fatal("stalled stream: expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("read blocked for %v; deadline did not clamp the gap", elapsed)
	}
}

// TestRTUFrameMaxSize checks a maximum-size PDU round-trips.
func TestRTUFrameMaxSize(t *testing.T) {
	pdu := append([]byte{3, 250}, make([]byte, 250)...) // 252-byte PDU (fc + count + 250)
	f, err := RTUFrame(255, pdu)
	if err != nil {
		t.Fatalf("RTUFrame: %v", err)
	}
	unit, got, err := ReadRTUResponse(bytes.NewReader(f), nil, 0, time.Time{})
	if err != nil {
		t.Fatalf("ReadRTUResponse: %v", err)
	}
	if unit != 255 || !bytes.Equal(got, pdu) {
		t.Errorf("got unit %d len %d", unit, len(got))
	}
}
