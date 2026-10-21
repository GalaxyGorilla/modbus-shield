// Package mbtcp implements the Modbus TCP wire format: MBAP header
// framing, ADU parsing and serialization.
//
// Ground truth is the Modbus Organization specification (no RFCs exist):
//
//   - MODBUS Application Protocol Specification V1.1b3 (Apr 2012)
//   - MODBUS Messaging on TCP/IP Implementation Guide V1.0b
//
// Wire layout of a Modbus TCP frame (ADU):
//
//	transaction ID | protocol ID | length | unit ID | function code | data
//	2 bytes        | 2 bytes     | 2 bytes| 1 byte  | 1 byte        | n bytes
//
// The length field counts the unit ID plus the PDU, so a full frame is
// 6+length bytes and the PDU itself is length-1 bytes. Valid length values
// are 2..254, making the maximum frame 260 bytes (max PDU 253).
//
// The package is deliberately a single small, fuzz-ready parser: it is the
// only component that ever touches untrusted wire bytes. Validation happens
// before any allocation sized from the frame, so malformed input can never
// drive memory use. Parsing is strict (exact frame length, protocol ID
// fixed at 0); correlation across requests is deliberately handled by the
// caller, not here.
package mbtcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocol constants (MODBUS Messaging on TCP/IP Implementation Guide V1.0b).
const (
	// HeaderLen is the size of the MBAP header in bytes.
	HeaderLen = 7

	// ProtocolID is the only valid MBAP protocol identifier (Modbus/TCP).
	ProtocolID = 0

	// MinLength is the smallest valid MBAP length field value: the unit
	// ID (1 byte) plus at least a function code (1 byte).
	MinLength = 2

	// MaxLength is the largest valid MBAP length field value: the unit
	// ID plus a maximum-size PDU.
	MaxLength = 254

	// MaxPDU is the maximum PDU size per spec V1.1b3.
	MaxPDU = 253

	// MaxADU is the maximum on-the-wire frame size in bytes.
	MaxADU = 260
)

// Parsing and construction errors. All are package-level sentinels so
// callers (and fuzz regression tests) can match on them with errors.Is.
var (
	ErrShortFrame     = errors.New("mbtcp: frame shorter than MBAP header")
	ErrTruncated      = errors.New("mbtcp: frame shorter than declared length")
	ErrTrailingBytes  = errors.New("mbtcp: trailing bytes after declared frame length")
	ErrProtocolID     = errors.New("mbtcp: protocol ID is not Modbus/TCP (0)")
	ErrLengthTooSmall = errors.New("mbtcp: MBAP length below minimum of 2")
	ErrLengthTooLarge = errors.New("mbtcp: MBAP length above Modbus TCP ADU cap of 254")
	ErrPDUEmpty       = errors.New("mbtcp: PDU must contain at least a function code")
	ErrPDULarge       = errors.New("mbtcp: PDU exceeds maximum size of 253 bytes")
)

// Header is a parsed MBAP header.
type Header struct {
	TransactionID uint16 // client-chosen, echoed by the server
	ProtocolID    uint16 // always ProtocolID (0) for Modbus/TCP
	Length        uint16 // unit ID + PDU byte count
	UnitID        uint8  // server address / gateway target
}

// Validate checks the header against the Modbus TCP framing rules:
// protocol ID fixed at 0 and length within [MinLength, MaxLength].
func (h Header) Validate() error {
	if h.ProtocolID != ProtocolID {
		return ErrProtocolID
	}
	if h.Length < MinLength {
		return ErrLengthTooSmall
	}
	if h.Length > MaxLength {
		return ErrLengthTooLarge
	}
	return nil
}

// ADU is a complete Modbus TCP application data unit.
//
// PDU holds the protocol data unit (function code + data) and never the
// unit ID, which lives in Header.UnitID. The slice aliases the buffer the
// ADU was parsed from or built around; treat it as read-only and do not
// retain it beyond the ADU's use.
type ADU struct {
	Header Header
	PDU    []byte
}

// NewADU builds an ADU from parts. The PDU must contain at least a
// function code and at most MaxPDU bytes. It aliases pdu; copy first if
// the buffer will be reused.
func NewADU(transactionID uint16, unitID uint8, pdu []byte) (ADU, error) {
	if len(pdu) < 1 {
		return ADU{}, ErrPDUEmpty
	}
	if len(pdu) > MaxPDU {
		return ADU{}, ErrPDULarge
	}
	return ADU{
		Header: Header{
			TransactionID: transactionID,
			ProtocolID:    ProtocolID,
			Length:        uint16(1 + len(pdu)),
			UnitID:        unitID,
		},
		PDU: pdu,
	}, nil
}

// ParseADU parses one complete frame from buf and returns the ADU.
//
// The parse is strict: buf must be exactly one frame (no truncation, no
// trailing bytes) and the header must pass Validate. The returned PDU
// aliases buf.
func ParseADU(buf []byte) (ADU, error) {
	if len(buf) < HeaderLen {
		return ADU{}, ErrShortFrame
	}
	h := Header{
		TransactionID: binary.BigEndian.Uint16(buf[0:2]),
		ProtocolID:    binary.BigEndian.Uint16(buf[2:4]),
		Length:        binary.BigEndian.Uint16(buf[4:6]),
		UnitID:        buf[6],
	}
	if err := h.Validate(); err != nil {
		return ADU{}, err
	}
	total := HeaderLen - 1 + int(h.Length) // 6 fixed bytes + length field
	if len(buf) < total {
		return ADU{}, ErrTruncated
	}
	if len(buf) > total {
		return ADU{}, ErrTrailingBytes
	}
	return ADU{Header: h, PDU: buf[HeaderLen:total]}, nil
}

// ReadADU reads exactly one ADU from r.
//
// The 7-byte header is read and validated before the body is read, and the
// body size is bounded by MaxLength, so a malformed or hostile stream can
// never trigger an oversized allocation. io.EOF is returned unwrapped when
// the stream ends cleanly at a frame boundary; a truncated frame wraps
// io.ErrUnexpectedEOF or the underlying read error.
func ReadADU(r io.Reader) (ADU, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return ADU{}, fmt.Errorf("mbtcp: truncated MBAP header: %w", err)
		}
		return ADU{}, err // io.EOF (clean close) and I/O errors pass through
	}
	h := Header{
		TransactionID: binary.BigEndian.Uint16(hdr[0:2]),
		ProtocolID:    binary.BigEndian.Uint16(hdr[2:4]),
		Length:        binary.BigEndian.Uint16(hdr[4:6]),
		UnitID:        hdr[6],
	}
	if err := h.Validate(); err != nil {
		return ADU{}, err
	}
	pdu := make([]byte, int(h.Length)-1) // length already bounds this to 1..253
	if _, err := io.ReadFull(r, pdu); err != nil {
		return ADU{}, fmt.Errorf("mbtcp: truncated ADU body: %w", err)
	}
	return ADU{Header: h, PDU: pdu}, nil
}

// AppendTo appends the full on-the-wire frame (header, unit ID, PDU) to
// dst and returns the extended slice, so write buffers can be reused.
func (a ADU) AppendTo(dst []byte) []byte {
	length := uint16(1 + len(a.PDU)) // unit ID + PDU
	dst = append(dst,
		byte(a.Header.TransactionID>>8), byte(a.Header.TransactionID),
		byte(a.Header.ProtocolID>>8), byte(a.Header.ProtocolID),
		byte(length>>8), byte(length),
		a.Header.UnitID,
	)
	return append(dst, a.PDU...)
}

// Frame returns the ADU as a freshly allocated on-the-wire frame.
func (a ADU) Frame() []byte {
	return a.AppendTo(make([]byte, 0, HeaderLen+len(a.PDU)))
}

// FunctionCode returns the PDU's function code, or 0 for the zero ADU.
// 0 is unambiguous: the spec defines function codes 1..255 only, and every
// parsed or built ADU carries at least one PDU byte.
func (a ADU) FunctionCode() uint8 {
	if len(a.PDU) == 0 {
		return 0
	}
	return a.PDU[0]
}

// IsException reports whether the ADU is a Modbus exception response
// (function code with the MSB set, per spec V1.1b3).
func (a ADU) IsException() bool {
	return a.FunctionCode()&0x80 != 0
}

// ExceptionCode returns the exception code of an exception response, or 0
// with ok=false unless the ADU is a well-formed exception response.
func (a ADU) ExceptionCode() (code uint8, ok bool) {
	if !a.IsException() || len(a.PDU) < 2 {
		return 0, false
	}
	return a.PDU[1], true
}

// ExceptionPDU builds the two-byte PDU of a Modbus exception response:
// the requested function code with the MSB set, plus the exception code.
// The proxy uses this to reject requests locally (read-only policy,
// upstream failures) with a clean protocol-level error the device never
// sees.
func ExceptionPDU(functionCode, exceptionCode uint8) []byte {
	return []byte{functionCode | 0x80, exceptionCode}
}
