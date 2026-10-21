package proxy

import (
	"sync"
	"time"
)

// readCache is the opt-in TTL cache for read responses (B8): repeated
// FC 1–4 requests within the TTL are answered from memory, shielding
// very slow devices from heavy polling. OFF unless a TTL is configured.
//
// The cache key is the upstream unit ID plus the full request PDU (so
// register addresses and quantities are inherently part of the key).
// Only non-exception responses to read function codes are stored, so
// writes, exceptions and health reads never hit the cache. Cached
// responses skip the rate limiter and the device entirely — no device
// traffic is generated for a hit.
//
// Concurrency: the map is guarded by a mutex; the cache is best-effort
// and safe under concurrent access. Entry values are response PDUs
// (copied on insert and on return so callers cannot mutate them).
type readCache struct {
	ttl time.Duration

	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
}

type cacheKey struct {
	unit uint8
	pdu  string // request PDU bytes (FC + addressing)
}

type cacheEntry struct {
	pdu     []byte
	expires time.Time
}

// newReadCache returns nil for ttl <= 0 (disabled) — same nil-guard
// pattern as the rate limiter and the allow-list.
func newReadCache(ttl time.Duration) *readCache {
	if ttl <= 0 {
		return nil
	}
	return &readCache{ttl: ttl, entries: make(map[cacheKey]cacheEntry)}
}

// isReadFC reports whether fc is a read function code (FC 1–4 per spec
// V1.1b3) whose responses are cacheable.
func isReadFC(fc uint8) bool {
	return fc == 1 || fc == 2 || fc == 3 || fc == 4
}

// lookup returns the cached response PDU for a request, or nil on miss
// (also nil when the entry is expired — lazily evicted).
func (c *readCache) lookup(unit uint8, reqPDU []byte) []byte {
	if c == nil {
		return nil
	}
	key := cacheKey{unit: unit, pdu: string(reqPDU)}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.expires) {
		delete(c.entries, key) // lazy expiry
		return nil
	}
	out := make([]byte, len(e.pdu))
	copy(out, e.pdu)
	return out
}

// store inserts a response PDU (copied) for a successful read request.
func (c *readCache) store(unit uint8, reqPDU, respPDU []byte) {
	if c == nil {
		return
	}
	key := cacheKey{unit: unit, pdu: string(reqPDU)}
	pdu := make([]byte, len(respPDU))
	copy(pdu, respPDU)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{pdu: pdu, expires: time.Now().Add(c.ttl)}
}
