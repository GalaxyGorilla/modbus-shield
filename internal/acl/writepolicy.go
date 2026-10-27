package acl

import "strconv"

// WritePolicy is an address-scoped write policy: the coarse read_only
// switch answers "may anyone write at all?", this answers "may THIS unit
// write THIS function code at THESE addresses?".
//
// Evaluation is deny-overrides and allow-must-cover:
//
//   - a DENY rule matches when the request's address range INTERSECTS the
//     rule's range (touching any forbidden address is enough to reject);
//   - an ALLOW rule matches only when the rule's range CONTAINS the whole
//     request range (a multi-register write may never straddle an allowed
//     window and leak into a forbidden one);
//   - any matching deny wins; otherwise a matching allow wins; otherwise
//     the policy's default applies (deny unless configured otherwise).
//
// Rules are evaluated as a SET, not in order — rule order in the config is
// irrelevant, which makes the policy auditable ("what denies exist?").
//
// A nil *WritePolicy allows every write (no policy configured): callers
// never check for nil, mirroring the allow-list/rate-limiter pattern.

// WriteRule is one parsed policy rule. The zero value is a rule that
// allows any write by any unit at any address (rarely useful, but it makes
// the struct honest).
type WriteRule struct {
	// Unit, when non-nil, restricts the rule to that CLIENT unit ID
	// (pre-remap: the unit ID the client addressed).
	Unit *uint8
	// FCs, when non-empty, restricts the rule to those function codes.
	FCs []uint8
	// HasRange marks From/To as meaningful. A rule without a range
	// matches regardless of address — the only way to cover function
	// codes that carry no register address (file record 21).
	HasRange bool
	From     uint16
	To       uint16
	// Allow is true for allow rules, false for deny rules.
	Allow bool
}

// WritePolicy is a compiled set of write rules plus the default for
// unmatched writes.
type WritePolicy struct {
	defaultAllow bool
	rules        []WriteRule
}

// NewWritePolicy compiles rules into a policy. defaultAllow is the verdict
// for a write no rule matches. A policy with no rules is legal only with
// defaultAllow (otherwise it would reject every write — that is what
// read_only is for).
func NewWritePolicy(defaultAllow bool, rules []WriteRule) (*WritePolicy, error) {
	if len(rules) == 0 && !defaultAllow {
		return nil, errEmptyDenyPolicy
	}
	for i, r := range rules {
		if r.HasRange && r.From > r.To {
			return nil, &RuleError{Index: i, Msg: "from must be <= to"}
		}
		for _, fc := range r.FCs {
			if !IsWrite(fc) {
				return nil, &RuleError{Index: i, Msg: "function code is not a write function code"}
			}
		}
	}
	return &WritePolicy{defaultAllow: defaultAllow, rules: rules}, nil
}

// RuleError reports a bad rule; Index is the position in the config list.
type RuleError struct {
	Index int
	Msg   string
}

func (e *RuleError) Error() string {
	if e.Index < 0 {
		return "write policy: " + e.Msg
	}
	return "write policy: rule " + strconv.Itoa(e.Index) + ": " + e.Msg
}

var errEmptyDenyPolicy = &RuleError{Index: -1, Msg: "no rules and default deny would block every write (use read_only instead)"}

// DefaultAllow reports the verdict for writes no rule matches.
func (p *WritePolicy) DefaultAllow() bool { return p != nil && p.defaultAllow }

// Len returns the number of rules (observability/validation convenience).
func (p *WritePolicy) Len() int {
	if p == nil {
		return 0
	}
	return len(p.rules)
}

// Allowed reports whether the write request in pdu may proceed to the
// device. pdu starts with the function code. Non-write function codes are
// always allowed (the policy governs writes only). A write whose address
// range cannot be parsed — truncated PDU, quantity 0, range overflow — is
// denied: an unparseable range cannot be authorized.
func (p *WritePolicy) Allowed(unit uint8, pdu []byte) bool {
	if p == nil {
		return true
	}
	if len(pdu) == 0 {
		return false
	}
	fc := pdu[0]
	if !IsWrite(fc) {
		return true
	}
	from, to, hasRange, ok := WriteRange(fc, pdu)
	if !ok {
		return false
	}

	allowed := false
	for _, r := range p.rules {
		if r.Unit != nil && *r.Unit != unit {
			continue
		}
		if len(r.FCs) > 0 && !containsFC(r.FCs, fc) {
			continue
		}
		if r.HasRange {
			// A rule scoped to addresses cannot judge a request that
			// carries none (file record), and vice versa.
			if !hasRange {
				continue
			}
			if r.Allow && !(from >= r.From && to <= r.To) {
				continue // allow must cover the whole request
			}
			if !r.Allow && (to < r.From || from > r.To) {
				continue // deny needs an intersection
			}
		} else if hasRange {
			// An unscoped rule matches any address.
		}
		if !r.Allow {
			return false // deny overrides everything
		}
		allowed = true
	}
	if allowed {
		return true
	}
	return p.defaultAllow
}

func containsFC(set []uint8, fc uint8) bool {
	for _, s := range set {
		if s == fc {
			return true
		}
	}
	return false
}

// WriteRange extracts the address range a write request affects.
// hasRange is false for function codes that carry no register address
// (file-record write 21). ok is false when the PDU is too short, the
// quantity is zero, or the range would overflow 16 bits — all of which
// must be treated as unauthorized.
func WriteRange(fc uint8, pdu []byte) (from, to uint16, hasRange bool, ok bool) {
	switch fc {
	case 5, 6: // write single coil / register: one address
		if len(pdu) < 5 {
			return 0, 0, true, false
		}
		a := be16(pdu[1:3])
		return a, a, true, true
	case 15, 16: // write multiple coils / registers: address + quantity
		if len(pdu) < 5 {
			return 0, 0, true, false
		}
		a := be16(pdu[1:3])
		q := be16(pdu[3:5])
		if q == 0 {
			return 0, 0, true, false
		}
		end := uint32(a) + uint32(q) - 1
		if end > 0xFFFF {
			return 0, 0, true, false
		}
		return a, uint16(end), true, true
	case 22: // mask write register: one address (and/or masks follow)
		if len(pdu) < 7 {
			return 0, 0, true, false
		}
		a := be16(pdu[1:3])
		return a, a, true, true
	case 23: // read/write multiple: the WRITE part is what is authorized
		// fc, read addr(2), read qty(2), write addr(2), write qty(2), ...
		if len(pdu) < 9 {
			return 0, 0, true, false
		}
		a := be16(pdu[5:7])
		q := be16(pdu[7:9])
		if q == 0 {
			return 0, 0, true, false
		}
		end := uint32(a) + uint32(q) - 1
		if end > 0xFFFF {
			return 0, 0, true, false
		}
		return a, uint16(end), true, true
	case 21: // write file record: file number + record number, no address
		return 0, 0, false, true
	default:
		// Not a write function code (callers only ask about writes);
		// report "no address" so unscoped rules still apply.
		return 0, 0, false, true
	}
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
