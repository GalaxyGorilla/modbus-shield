package mbtcp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// wantADU is the expected parse of the spec example frame below.
// Example from MODBUS Messaging on TCP/IP Implementation Guide V1.0b:
// transaction ID 0x1234, protocol ID 0, length 6, unit ID 1,
// function code 3 (read multiple holding registers), 2 more PDU bytes.
var wantADU = ADU{
	Header: Header{TransactionID: 0x1234, ProtocolID: 0, Length: 6, UnitID: 1},
	PDU:    []byte{0x03, 0x00, 0x01, 0x00, 0x01},
}

var specExampleFrame = []byte{0x12, 0x34, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01}

func aduEqual(a, b ADU) bool {
	return a.Header == b.Header && bytes.Equal(a.PDU, b.PDU)
}

func TestParseADUSpecExample(t *testing.T) {
	got, err := ParseADU(specExampleFrame)
	if err != nil {
		t.Fatalf("ParseADU(spec example) = %v, want nil error", err)
	}
	if !aduEqual(got, wantADU) {
		t.Errorf("ParseADU(spec example) = %+v, want %+v", got, wantADU)
	}
}

func TestParseADURoundTrip(t *testing.T) {
	pdus := [][]byte{
		{0x01},                             // bare function code (minimum)
		{0x03, 0x00, 0x01, 0x00, 0x01},     // read holding registers
		bytes.Repeat([]byte{0xAB}, MaxPDU), // maximum-size PDU
		{0x86, 0x02},                       // exception response
	}
	units := []uint8{0, 1, 17, 247, 255}
	txn := uint16(0)
	for _, pdu := range pdus {
		for _, unit := range units {
			txn++ // exercise transaction IDs including wraparound via ++
			adu, err := NewADU(txn, unit, pdu)
			if err != nil {
				t.Fatalf("NewADU(%d, %d, %d bytes) = %v, want nil error", txn, unit, len(pdu), err)
			}
			frame := adu.Frame()
			if len(frame) != HeaderLen+len(pdu) {
				t.Fatalf("frame length = %d, want %d", len(frame), HeaderLen+len(pdu))
			}
			got, err := ParseADU(frame)
			if err != nil {
				t.Fatalf("ParseADU(round trip) = %v, want nil error", err)
			}
			if !aduEqual(got, adu) {
				t.Errorf("round trip mismatch: got %+v, want %+v", got, adu)
			}
			if got.FunctionCode() != adu.FunctionCode() {
				t.Errorf("function code = %#x, want %#x", got.FunctionCode(), adu.FunctionCode())
			}
		}
	}
}

func TestParseADUErrors(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want error
	}{
		{"empty", nil, ErrShortFrame},
		{"six bytes", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x02}, ErrShortFrame},
		{"bad protocol ID", []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03}, ErrProtocolID},
		{"length zero", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01}, ErrLengthTooSmall},
		{"length one", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01}, ErrLengthTooSmall},
		{"length 255", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x01}, ErrLengthTooLarge},
		{"truncated body", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x00}, ErrTruncated},
		{"trailing bytes", append(specExampleFrame, 0x00), ErrTrailingBytes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseADU(tt.buf)
			if !errors.Is(err, tt.want) {
				t.Errorf("ParseADU(% x) = %v, want %v", tt.buf, err, tt.want)
			}
		})
	}
}

func TestNewADUErrors(t *testing.T) {
	if _, err := NewADU(1, 1, nil); !errors.Is(err, ErrPDUEmpty) {
		t.Errorf("NewADU with nil PDU = %v, want %v", err, ErrPDUEmpty)
	}
	if _, err := NewADU(1, 1, []byte{}); !errors.Is(err, ErrPDUEmpty) {
		t.Errorf("NewADU with empty PDU = %v, want %v", err, ErrPDUEmpty)
	}
	if _, err := NewADU(1, 1, bytes.Repeat([]byte{0x00}, MaxPDU+1)); !errors.Is(err, ErrPDULarge) {
		t.Errorf("NewADU with oversized PDU = %v, want %v", err, ErrPDULarge)
	}
}

func TestHeaderValidateBoundaries(t *testing.T) {
	ok := Header{ProtocolID: ProtocolID, Length: MinLength}
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for minimum-length header", err)
	}
	ok = Header{ProtocolID: ProtocolID, Length: MaxLength}
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for maximum-length header", err)
	}
	bad := Header{ProtocolID: 1, Length: MinLength}
	if err := bad.Validate(); !errors.Is(err, ErrProtocolID) {
		t.Errorf("Validate() = %v, want %v", err, ErrProtocolID)
	}
}

func TestReadADU(t *testing.T) {
	t.Run("spec example", func(t *testing.T) {
		got, err := ReadADU(bytes.NewReader(specExampleFrame))
		if err != nil {
			t.Fatalf("ReadADU = %v, want nil error", err)
		}
		if !aduEqual(got, wantADU) {
			t.Errorf("ReadADU = %+v, want %+v", got, wantADU)
		}
	})

	t.Run("clean EOF at frame boundary", func(t *testing.T) {
		_, err := ReadADU(bytes.NewReader(nil))
		if !errors.Is(err, io.EOF) {
			t.Errorf("ReadADU(empty) = %v, want io.EOF", err)
		}
	})

	t.Run("partial header is unexpected EOF", func(t *testing.T) {
		_, err := ReadADU(bytes.NewReader(specExampleFrame[:4]))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("ReadADU(partial header) = %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("truncated body", func(t *testing.T) {
		truncated := specExampleFrame[:len(specExampleFrame)-2]
		_, err := ReadADU(bytes.NewReader(truncated))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("ReadADU(truncated body) = %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("invalid header rejected before body read", func(t *testing.T) {
		bad := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03} // protocol ID 1
		_, err := ReadADU(bytes.NewReader(bad))
		if !errors.Is(err, ErrProtocolID) {
			t.Errorf("ReadADU(bad protocol ID) = %v, want %v", err, ErrProtocolID)
		}
	})

	t.Run("oversized length rejected without allocation", func(t *testing.T) {
		bad := []byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01}
		_, err := ReadADU(bytes.NewReader(bad))
		if !errors.Is(err, ErrLengthTooLarge) {
			t.Errorf("ReadADU(oversized length) = %v, want %v", err, ErrLengthTooLarge)
		}
	})

	// A real Modbus client may pipeline the next request into the same
	// TCP segment as the current one. io.ReadFull must consume exactly one
	// frame and leave the remainder in the stream for the next read.
	t.Run("pipelined frames", func(t *testing.T) {
		second, err := NewADU(0x4321, 9, []byte{0x06, 0x00, 0x01, 0x12, 0x34})
		if err != nil {
			t.Fatalf("NewADU = %v, want nil error", err)
		}
		stream := append(append([]byte{}, specExampleFrame...), second.Frame()...)
		r := bytes.NewReader(stream)

		first, err := ReadADU(r)
		if err != nil {
			t.Fatalf("ReadADU(first) = %v, want nil error", err)
		}
		if !aduEqual(first, wantADU) {
			t.Errorf("first frame = %+v, want %+v", first, wantADU)
		}
		gotSecond, err := ReadADU(r)
		if err != nil {
			t.Fatalf("ReadADU(second) = %v, want nil error", err)
		}
		if !aduEqual(gotSecond, second) {
			t.Errorf("second frame = %+v, want %+v", gotSecond, second)
		}
		if _, err := ReadADU(r); !errors.Is(err, io.EOF) {
			t.Errorf("ReadADU(then) = %v, want io.EOF", err)
		}
	})

	// The reader may deliver the frame in tiny chunks (slow networks,
	// tests using io.Pipe). ReadADU must loop until the frame is complete.
	t.Run("chunked delivery", func(t *testing.T) {
		r := io.MultiReader(
			strings.NewReader(string(specExampleFrame[:1])),
			strings.NewReader(string(specExampleFrame[1:5])),
			strings.NewReader(string(specExampleFrame[5:])),
		)
		got, err := ReadADU(r)
		if err != nil {
			t.Fatalf("ReadADU(chunked) = %v, want nil error", err)
		}
		if !aduEqual(got, wantADU) {
			t.Errorf("ReadADU(chunked) = %+v, want %+v", got, wantADU)
		}
	})
}

func TestAppendToReusesBuffer(t *testing.T) {
	adu, err := NewADU(0x0102, 3, []byte{0x04, 0x00, 0x00, 0x00, 0x02})
	if err != nil {
		t.Fatalf("NewADU = %v, want nil error", err)
	}
	buf := make([]byte, 0, 2*HeaderLen+len(adu.PDU))
	buf = append(buf, 0xEE, 0xFF) // pre-existing bytes must survive

	full := adu.AppendTo(buf)
	if !bytes.Equal(full[:2], []byte{0xEE, 0xFF}) {
		t.Errorf("AppendTo clobbered existing bytes: % x", full[:2])
	}
	want := append([]byte{0xEE, 0xFF}, adu.Frame()...)
	if !bytes.Equal(full, want) {
		t.Errorf("AppendTo = % x, want % x", full, want)
	}
}

func TestExceptionHelpers(t *testing.T) {
	pdu := ExceptionPDU(0x05, 0x01) // write single coil, illegal function
	if !bytes.Equal(pdu, []byte{0x85, 0x01}) {
		t.Errorf("ExceptionPDU = % x, want 85 01", pdu)
	}
	adu, err := NewADU(7, 1, pdu)
	if err != nil {
		t.Fatalf("NewADU = %v, want nil error", err)
	}
	if !adu.IsException() {
		t.Error("IsException() = false, want true")
	}
	code, ok := adu.ExceptionCode()
	if !ok || code != 0x01 {
		t.Errorf("ExceptionCode() = (%#x, %v), want (0x01, true)", code, ok)
	}

	// Normal responses are not exceptions.
	normal, err := NewADU(7, 1, []byte{0x05, 0x00, 0x00, 0xFF, 0x00})
	if err != nil {
		t.Fatalf("NewADU = %v, want nil error", err)
	}
	if normal.IsException() {
		t.Error("IsException() = true, want false for normal response")
	}
	if _, ok := normal.ExceptionCode(); ok {
		t.Error("ExceptionCode() ok = true, want false for normal response")
	}
}

func TestFunctionCodeZeroADU(t *testing.T) {
	var a ADU
	if a.FunctionCode() != 0 {
		t.Error("FunctionCode() != 0 for zero ADU")
	}
	if a.IsException() {
		t.Error("IsException() = true, want false for zero ADU")
	}
}
