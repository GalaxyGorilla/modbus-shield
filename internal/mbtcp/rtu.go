package mbtcp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Modbus RTU framing (MODBUS over Serial Line Specification V1.02),
// used by the rtu_over_tcp device mode (B7): cheap serial-to-TCP
// converters bridge raw serial frames over TCP without MBAP wrapping.
//
// Wire layout of an RTU frame:
//
//	unit address | function code | data | CRC16
//	1 byte       | 1 byte        | n    | 2 bytes (low byte first)
//
// There is no length field on the wire, so response frames are read by
// predicting their shape from the response's function code (fixed-size
// and byte-count-prefixed shapes per spec V1.1b3), with an idle-gap
// fallback for unlisted function codes. The CRC is CRC-16/MODBUS
// (poly 0xA001 reflected, init 0xFFFF), transmitted low byte first.

const (
	// RTUMinFrame is the smallest RTU frame: addr + fc + CRC.
	RTUMinFrame = 4

	// RTUMaxFrame is the largest RTU frame: addr + max PDU (253) + CRC.
	RTUMaxFrame = 256
)

// RTU parsing errors. Sentinels like the MBAP ones so callers can match
// with errors.Is.
var (
	ErrRTUShortFrame = errors.New("mbtcp: RTU frame too short")
	ErrRTUCRC        = errors.New("mbtcp: RTU CRC mismatch")
)

// CRC16 computes CRC-16/MODBUS over data (poly 0xA001 reflected,
// init 0xFFFF, no final xor) — the checksum of Modbus RTU frames.
func CRC16(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// RTUFrame builds one RTU frame from a unit address and PDU (function
// code + data, never the unit address): addr | pdu | CRC16(low, high).
func RTUFrame(unit uint8, pdu []byte) ([]byte, error) {
	if len(pdu) < 1 {
		return nil, ErrPDUEmpty
	}
	if len(pdu) > MaxPDU {
		return nil, ErrPDULarge
	}
	frame := make([]byte, 0, 3+len(pdu))
	frame = append(frame, unit)
	frame = append(frame, pdu...)
	crc := CRC16(frame)
	return append(frame, byte(crc), byte(crc>>8)), nil
}

// VerifyRTUFrame checks the trailing CRC of a complete RTU frame
// (including its CRC bytes). Useful for test devices and tooling that
// read whole frames without stream framing.
func VerifyRTUFrame(frame []byte) error {
	return verifyRTUCRC(frame)
}

// Deadliner is the deadline-setting part of net.Conn. ReadRTUResponse
// temporarily shortens read deadlines for its idle-gap fallback.
type Deadliner interface {
	SetReadDeadline(time.Time) error
}

// ReadRTUResponse reads one RTU response frame from r and returns the
// unit address and PDU (function code + data). The frame shape is
// predicted from the RESPONSE's function code (devices echo the request
// code); unlisted codes fall back to idle-gap framing: reads continue
// until a quiet gap of the given duration (clamped to deadline when
// non-zero) — a serial bridge sends a frame as one burst, so silence
// means the frame is complete.
//
// The caller sets r's read deadline to bound the whole read (typically
// the exchange deadline). io.EOF passes through unwrapped on a clean
// close between frames; truncated frames wrap io.ErrUnexpectedEOF.
func ReadRTUResponse(r io.Reader, dl Deadliner, gap time.Duration, deadline time.Time) (uint8, []byte, error) {
	head := make([]byte, 2) // addr, fc
	if _, err := io.ReadFull(r, head); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, fmt.Errorf("mbtcp: truncated RTU header: %w", err)
		}
		return 0, nil, err
	}
	frame, err := readRTURest(r, dl, head, head[1], gap, deadline)
	if err != nil {
		return 0, nil, err
	}
	return head[0], frame[1 : len(frame)-2], nil
}

// readRTURest reads the remainder of an RTU frame whose addr and fc are
// already in frame, classifying the shape by fc, and verifies the CRC.
func readRTURest(r io.Reader, dl Deadliner, frame []byte, fc uint8, gap time.Duration, deadline time.Time) ([]byte, error) {
	read := func(n int) error {
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			// Mid-frame EOF (bare or unexpected) = truncated frame; a
			// clean EOF is only legal between frames (checked by the
			// caller's first ReadFull).
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("mbtcp: truncated RTU frame: %w", io.ErrUnexpectedEOF)
			}
			return err
		}
		frame = append(frame, buf...)
		return nil
	}
	switch {
	case fc&0x80 != 0:
		// Exception response: code (1) + CRC (2).
		if err := read(3); err != nil {
			return nil, err
		}
	case fc == 1 || fc == 2 || fc == 3 || fc == 4 || fc == 23:
		// Byte-count-prefixed response: bytecount (1) + data + CRC (2).
		if err := read(1); err != nil {
			return nil, err
		}
		// frame[2] is the byte count; bounded by 255 so the read can
		// never allocate more than 257 bytes.
		if err := read(int(frame[2]) + 2); err != nil {
			return nil, err
		}
	case fc == 5 || fc == 6 || fc == 15 || fc == 16:
		// Fixed echo response: reg/value or start/qty (4) + CRC (2).
		if err := read(6); err != nil {
			return nil, err
		}
	case fc == 22:
		// Mask write response: addr + AND + OR (6) + CRC (2).
		if err := read(8); err != nil {
			return nil, err
		}
	default:
		rest, err := readRTUGap(r, dl, gap, deadline)
		if err != nil {
			return nil, err
		}
		frame = append(frame, rest...)
	}
	if len(frame) < RTUMinFrame {
		return nil, ErrRTUShortFrame
	}
	if err := verifyRTUCRC(frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// readRTUGap reads frame bytes until an idle gap of the given duration
// (clamped to deadline when non-zero). The last two bytes read are the
// CRC; the gap loop itself never validates anything.
func readRTUGap(r io.Reader, dl Deadliner, gap time.Duration, deadline time.Time) ([]byte, error) {
	var rest []byte
	buf := make([]byte, 1)
	for {
		gapEnd := time.Now().Add(gap)
		if !deadline.IsZero() && gapEnd.After(deadline) {
			gapEnd = deadline
		}
		if err := dl.SetReadDeadline(gapEnd); err != nil {
			return nil, err
		}
		n, err := r.Read(buf)
		if n > 0 {
			rest = append(rest, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return rest, nil // quiet gap: frame complete
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("mbtcp: truncated RTU frame: %w", io.ErrUnexpectedEOF)
			}
			return nil, err
		}
	}
}

// verifyRTUCRC checks the trailing CRC (low byte first) of an RTU frame.
func verifyRTUCRC(frame []byte) error {
	if len(frame) < RTUMinFrame {
		return ErrRTUShortFrame
	}
	want := CRC16(frame[:len(frame)-2])
	got := uint16(frame[len(frame)-2]) | uint16(frame[len(frame)-1])<<8
	if want != got {
		return ErrRTUCRC
	}
	return nil
}
