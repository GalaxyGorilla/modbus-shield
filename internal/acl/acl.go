// Package acl implements the front-leg access policy: a client IP
// allow-list and the function-code write classifier backing the read-only
// mode.
package acl

import (
	"net"
	"sync"
)

// writeFuncs is the set of function codes that modify device state.
// Per spec V1.1b3: write single/multiple coil and register (5, 6, 15, 16),
// mask write (22), read/write multiple registers (23), and the file-record
// write (21). FIFO read (24) and all reads are allowed in read-only mode.
var writeFuncs = map[uint8]bool{
	5: true, 6: true, 15: true, 16: true, 21: true, 22: true, 23: true,
}

// IsWrite reports whether the function code modifies device state
// (blocked in read-only mode).
func IsWrite(functionCode uint8) bool { return writeFuncs[functionCode] }

// List is a client IP allow-list. A nil *List allows every client.
type List struct {
	mu    sync.RWMutex
	ips   []net.IP
	cidrs []*net.IPNet
}

// NewList parses allow-list entries (bare IPs or CIDR ranges, e.g.
// "10.8.0.0/24"). An empty entry list returns nil (no restriction).
// Entries were already validated by config; a parse failure here is a
// programming error and returns an error.
func NewList(entries []string) (*List, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	l := &List{}
	for _, e := range entries {
		if ip := net.ParseIP(e); ip != nil {
			l.ips = append(l.ips, ip)
			continue
		}
		_, cidr, err := net.ParseCIDR(e)
		if err != nil {
			return nil, err
		}
		l.cidrs = append(l.cidrs, cidr)
	}
	return l, nil
}

// Allowed reports whether ip passes the allow-list.
func (l *List) Allowed(ip net.IP) bool {
	if l == nil {
		return true
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, allowed := range l.ips {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, cidr := range l.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
