package acl

import (
	"testing"
)

// fc6 builds a write-single-register request PDU for one address.
func fc6(addr uint16) []byte {
	return []byte{6, byte(addr >> 8), byte(addr), 0x12, 0x34}
}

// fc16 builds a write-multiple-registers request PDU.
func fc16(addr, qty uint16) []byte {
	return []byte{16, byte(addr >> 8), byte(addr), byte(qty >> 8), byte(qty),
		2 * byte(qty), 0, 0}
}

// fc23 builds a read/write-multiple-registers request PDU with the given
// write address and quantity.
func fc23(writeAddr, writeQty uint16) []byte {
	return []byte{23,
		0x01, 0x00, 0x00, 0x01, // read addr + qty
		byte(writeAddr >> 8), byte(writeAddr),
		byte(writeQty >> 8), byte(writeQty),
		2, 0xAB, 0xCD}
}

func unitPtr(u uint8) *uint8 { return &u }

func TestWriteRangeShapes(t *testing.T) {
	cases := []struct {
		name     string
		pdu      []byte
		from, to uint16
		hasRange bool
		ok       bool
	}{
		{"fc5 single coil", []byte{5, 0x00, 0x10, 0xFF, 0x00}, 0x10, 0x10, true, true},
		{"fc6 single register", fc6(0x0100), 0x0100, 0x0100, true, true},
		{"fc15 multiple coils", []byte{15, 0x00, 0x10, 0x00, 0x03, 1, 0x07}, 0x10, 0x12, true, true},
		{"fc16 multiple registers", fc16(0x0100, 4), 0x0100, 0x0103, true, true},
		{"fc22 mask write", []byte{22, 0x00, 0x20, 0xFF, 0xFF, 0x00, 0x00}, 0x20, 0x20, true, true},
		{"fc23 write part wins", fc23(0x0200, 2), 0x0200, 0x0201, true, true},
		{"fc21 file record has no address", []byte{21, 0x00, 0x04}, 0, 0, false, true},

		{"fc6 truncated", []byte{6, 0x01}, 0, 0, true, false},
		{"fc16 zero quantity", fc16(0x0100, 0), 0, 0, true, false},
		{"fc16 range overflow", []byte{16, 0xFF, 0xFF, 0x00, 0x02}, 0, 0, true, false},
		{"fc23 truncated", []byte{23, 0x01, 0x00, 0x00}, 0, 0, true, false},
		{"fc23 zero write quantity", fc23(0x0100, 0), 0, 0, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from, to, hasRange, ok := WriteRange(tc.pdu[0], tc.pdu)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if hasRange != tc.hasRange || from != tc.from || to != tc.to {
				t.Fatalf("range = (%#x..%#x, hasRange=%v), want (%#x..%#x, hasRange=%v)",
					from, to, hasRange, tc.from, tc.to, tc.hasRange)
			}
		})
	}
}

func TestWritePolicyNilAllowsEverything(t *testing.T) {
	var p *WritePolicy
	if !p.Allowed(1, fc6(0x0100)) {
		t.Fatal("nil policy must allow writes")
	}
	if p.DefaultAllow() || p.Len() != 0 {
		t.Fatal("nil policy accessors must be zero")
	}
}

func TestWritePolicyDefaultDenyAllowsOnlyCovered(t *testing.T) {
	p, err := NewWritePolicy(false, []WriteRule{
		{FCs: []uint8{6}, HasRange: true, From: 0x0100, To: 0x014F, Allow: true},
	})
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}

	if !p.Allowed(1, fc6(0x0100)) {
		t.Fatal("FC6 inside the allowed window was rejected")
	}
	if p.Allowed(1, fc6(0x0150)) {
		t.Fatal("FC6 outside the allowed window was allowed")
	}
	// Failing fast on a different FC: not covered by the FC6 rule, so the
	// default (deny) applies.
	if p.Allowed(1, fc16(0x0100, 1)) {
		t.Fatal("FC16 was allowed although only FC6 is covered")
	}
	// Reads are never governed by the write policy.
	if !p.Allowed(1, []byte{3, 0x01, 0x00, 0x00, 0x01}) {
		t.Fatal("a read was blocked by the write policy")
	}
}

func TestWritePolicyAllowMustCoverWholeRequest(t *testing.T) {
	p, err := NewWritePolicy(false, []WriteRule{
		{FCs: []uint8{16}, HasRange: true, From: 0x0100, To: 0x0103, Allow: true},
	})
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}
	if !p.Allowed(1, fc16(0x0100, 4)) {
		t.Fatal("write exactly covering the window was rejected")
	}
	if p.Allowed(1, fc16(0x0102, 3)) {
		t.Fatal("write straddling the window end was allowed (must be fully covered)")
	}
	if p.Allowed(1, fc16(0x00FF, 2)) {
		t.Fatal("write straddling the window start was allowed")
	}
}

func TestWritePolicyDenyOverridesAllow(t *testing.T) {
	p, err := NewWritePolicy(false, []WriteRule{
		{FCs: []uint8{6, 16}, HasRange: true, From: 0x0100, To: 0x01FF, Allow: true},
		{HasRange: true, From: 0x0180, To: 0x018F, Allow: false}, // carve-out
	})
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}
	if !p.Allowed(1, fc6(0x017F)) {
		t.Fatal("address outside the carve-out was rejected")
	}
	if p.Allowed(1, fc6(0x0185)) {
		t.Fatal("address inside the deny carve-out was allowed")
	}
	// A multi-write that touches the carve-out is denied even though it is
	// also inside the allow window.
	if p.Allowed(1, fc16(0x017E, 4)) {
		t.Fatal("multi-write intersecting the deny carve-out was allowed")
	}
}

func TestWritePolicyUnitScoping(t *testing.T) {
	p, err := NewWritePolicy(false, []WriteRule{
		{Unit: unitPtr(1), FCs: []uint8{6}, HasRange: true, From: 0, To: 0xFFFF, Allow: true},
		{Unit: unitPtr(2), FCs: []uint8{6}, HasRange: true, From: 0, To: 0xFFFF, Allow: true},
	})
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}
	if !p.Allowed(1, fc6(0x0010)) || !p.Allowed(2, fc6(0x0010)) {
		t.Fatal("allowed units were rejected")
	}
	if p.Allowed(3, fc6(0x0010)) {
		t.Fatal("unit 3 has no rule and must be denied by the default")
	}
}

func TestWritePolicyDefaultAllowWithDenyList(t *testing.T) {
	p, err := NewWritePolicy(true, []WriteRule{
		{FCs: []uint8{5, 6}, HasRange: true, From: 0x8000, To: 0x8FFF, Allow: false},
	})
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}
	if !p.Allowed(1, fc6(0x0100)) {
		t.Fatal("default-allow policy rejected an unlisted address")
	}
	if p.Allowed(1, fc6(0x8001)) {
		t.Fatal("default-allow policy allowed a denied address")
	}
	if !p.Allowed(1, fc16(0x8001, 1)) {
		t.Fatal("deny rule scoped to FC5/6 leaked onto FC16")
	}
}

func TestWritePolicyUnparseableWriteDenied(t *testing.T) {
	p, err := NewWritePolicy(true, nil)
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}
	if p.Allowed(1, []byte{16, 0x01}) {
		t.Fatal("truncated write was allowed")
	}
	if p.Allowed(1, nil) {
		t.Fatal("empty PDU was allowed")
	}
}

func TestWritePolicyFileRecordNeedsUnscopedRule(t *testing.T) {
	// Address-scoped rules cannot authorize a file-record write (no
	// address to compare), so a default-deny policy blocks it.
	scoped, err := NewWritePolicy(false, []WriteRule{
		{FCs: []uint8{6}, HasRange: true, From: 0, To: 0xFFFF, Allow: true},
	})
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}
	if scoped.Allowed(1, []byte{21, 0x00, 0x04}) {
		t.Fatal("file-record write was allowed by an address-scoped rule")
	}

	unscoped, err := NewWritePolicy(false, []WriteRule{
		{FCs: []uint8{21}, Allow: true},
	})
	if err != nil {
		t.Fatalf("NewWritePolicy: %v", err)
	}
	if !unscoped.Allowed(1, []byte{21, 0x00, 0x04}) {
		t.Fatal("file-record write was blocked by an unscoped FC21 allow rule")
	}
}

func TestNewWritePolicyErrors(t *testing.T) {
	if _, err := NewWritePolicy(false, nil); err == nil {
		t.Fatal("empty default-deny policy: want error, got nil")
	}
	if _, err := NewWritePolicy(false, []WriteRule{
		{HasRange: true, From: 0x0200, To: 0x0100, Allow: true},
	}); err == nil {
		t.Fatal("inverted range: want error, got nil")
	}
	if _, err := NewWritePolicy(false, []WriteRule{
		{FCs: []uint8{3}, Allow: true}, // a READ is not a write FC
	}); err == nil {
		t.Fatal("read function code in a write rule: want error, got nil")
	}
}
