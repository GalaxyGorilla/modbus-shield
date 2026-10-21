package proxy

import (
	"sync"
	"time"
)

// rateLimiter is a token bucket capping front-leg requests per second.
// The bucket starts full and refills continuously; capacity is one
// second's worth of tokens (min 1), so short bursts up to the configured
// rate are absorbed without rejecting.
//
// nil = unlimited: all gateway rate checks are nil-guarded, mirroring the
// nil allow-list pattern (no restriction configured = no restriction at
// runtime).
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	refill float64 // tokens per second
	last   time.Time
	nowFn  func() time.Time // stubbed in tests
}

func newRateLimiter(perSec int) *rateLimiter {
	if perSec <= 0 {
		return nil // 0 = unlimited
	}
	max := float64(perSec)
	return &rateLimiter{
		tokens: max,
		max:    max,
		refill: max,
		nowFn:  time.Now,
		// last is initialized lazily on the first Allow() so the
		// limiter never depends on construction-time clock reads
		// (keeps test clock injection exact).
	}
}

// Allow reports whether one request is admitted under the configured
// rate and, if so, consumes one token.
func (r *rateLimiter) Allow() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowFn()
	if r.last.IsZero() {
		r.last = now
	}
	elapsed := now.Sub(r.last).Seconds()
	r.last = now
	r.tokens = min(r.max, r.tokens+elapsed*r.refill)

	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}
