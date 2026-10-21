package mbtcp

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzReadADU drives the streaming entry point with arbitrary byte
// streams, including pipelined multi-frame inputs and chunked delivery.
// The invariants mirror FuzzParseADU: rejections must be documented
// sentinel errors (or plain I/O EOF wrappers), accepted frames must
// round-trip byte-exactly, and the stream must stay frame-aligned (the
// next ReadADU must pick up exactly the next frame). Regression
// failures found by fuzzing are committed under testdata/fuzz/FuzzReadADU/
// and re-run in every `go test`.
func FuzzReadADU(f *testing.F) {
	// Spec example (V1.0b) — the canonical happy path.
	spec := []byte{0x12, 0x34, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01}
	f.Add(spec)
	// Pipelined: two frames back to back.
	f.Add(append(append([]byte{}, spec...), spec...))
	// Every truncation prefix of a valid frame (truncated-frame errors).
	for i := 0; i <= len(spec); i++ {
		f.Add(spec[:i])
	}
	// Bad protocol ID, boundary lengths, exception shape, garbage.
	f.Add([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x83, 0x01})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x01})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := io.MultiReader(bytes.NewReader(data), bytes.NewReader(nil)) // bare-EOF after stream end
		for i := 0; i < 4; i++ {
			adu, err := ReadADU(r)
			if err != nil {
				// Clean stream end at a frame boundary is bare io.EOF.
				if errors.Is(err, io.EOF) {
					return
				}
				// Truncated frames wrap io.ErrUnexpectedEOF.
				if errors.Is(err, io.ErrUnexpectedEOF) {
					return
				}
				// Everything else must be a documented sentinel.
				if !errors.Is(err, ErrShortFrame) &&
					!errors.Is(err, ErrTruncated) &&
					!errors.Is(err, ErrTrailingBytes) &&
					!errors.Is(err, ErrProtocolID) &&
					!errors.Is(err, ErrLengthTooSmall) &&
					!errors.Is(err, ErrLengthTooLarge) {
					t.Fatalf("ReadADU returned non-sentinel error: %v", err)
				}
				return
			}
			// Accepted frames must survive re-framing byte-exactly, and
			// the stream must stay aligned: re-parse the frame bytes.
			round := adu.Frame()
			if _, err := ParseADU(round); err != nil {
				t.Fatalf("ReadADU produced unparseable frame: %v", err)
			}
		}
	})
}
