package mbtcp

import (
	"errors"
	"testing"
)

// FuzzParseADU drives the single untrusted-input parser with arbitrary
// bytes. The invariant: ParseADU may reject any input, but it must never
// panic and every accepted frame must survive a round trip through
// AppendTo. Regression failures found by fuzzing are committed under
// testdata/fuzz/FuzzParseADU/ and re-run in every `go test`.
func FuzzParseADU(f *testing.F) {
	// Spec example (V1.0b) — the canonical happy path.
	f.Add([]byte{0x12, 0x34, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01})
	// Boundary lengths: minimum, maximum, just past both edges.
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x03})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFE})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x01})
	// Truncations of a valid frame at every prefix length.
	full := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01}
	for i := 0; i <= len(full); i++ {
		f.Add(full[:i])
	}
	// Trailing garbage, protocol-ID corruption, exception shapes.
	f.Add(append(append([]byte{}, full...), 0x00, 0xFF))
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x83, 0x01})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, buf []byte) {
		adu, err := ParseADU(buf)
		if err != nil {
			// Rejections must be our documented sentinel errors, never
			// something else (guards against stray panics-as-errors).
			if !errors.Is(err, ErrShortFrame) &&
				!errors.Is(err, ErrTruncated) &&
				!errors.Is(err, ErrTrailingBytes) &&
				!errors.Is(err, ErrProtocolID) &&
				!errors.Is(err, ErrLengthTooSmall) &&
				!errors.Is(err, ErrLengthTooLarge) {
				t.Fatalf("ParseADU(% x) returned non-sentinel error: %v", buf, err)
			}
			return
		}
		// Accepted frames must be exactly the input and survive re-framing.
		if len(adu.PDU) == 0 {
			t.Fatalf("ParseADU(% x) accepted frame with empty PDU", buf)
		}
		round := adu.Frame()
		if string(round) != string(buf) {
			t.Fatalf("round trip mismatch: in % x, out % x", buf, round)
		}
		got, err := ParseADU(round)
		if err != nil {
			t.Fatalf("ParseADU(re-framed) = %v, want nil error", err)
		}
		if got.Header != adu.Header || string(got.PDU) != string(adu.PDU) {
			t.Fatalf("re-parse mismatch: first %+v, second %+v", adu, got)
		}
	})
}
