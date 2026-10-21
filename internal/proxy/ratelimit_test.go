package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// fakeClock is a controllable clock for token-bucket tests: advance()
// moves time forward without sleeping and is safe for concurrent use.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves the fake clock forward by d.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestRateLimiterUnlimited verifies 0 or negative rates disable limiting.
func TestRateLimiterUnlimited(t *testing.T) {
	for _, perSec := range []int{0, -5} {
		if lim := newRateLimiter(perSec); lim != nil {
			t.Fatalf("newRateLimiter(%d) = limiter, want nil", perSec)
		}
	}
	// nil limiter admits everything (nil-guard contract).
	var lim *rateLimiter
	for i := 0; i < 1000; i++ {
		if !lim.Allow() {
			t.Fatalf("nil limiter denied request %d", i)
		}
	}
}

// TestRateLimiterBurst verifies a fresh bucket admits a full burst (one
// second's worth of tokens) and then starts rejecting.
func TestRateLimiterBurst(t *testing.T) {
	clk := newFakeClock()
	lim := newRateLimiter(10)
	lim.nowFn = clk.Now

	for i := 0; i < 10; i++ {
		if !lim.Allow() {
			t.Fatalf("burst request %d denied; full bucket must admit 10", i)
		}
	}
	if lim.Allow() {
		t.Fatal("11th request admitted; bucket must be empty after burst")
	}

	// Half a second refills 5 tokens at 10/s.
	clk.advance(500 * time.Millisecond)
	admitted := 0
	for i := 0; i < 10; i++ {
		if lim.Allow() {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("after 500ms refill admitted %d, want 5", admitted)
	}
}

// TestRateLimiterRefillCap verifies refill never exceeds bucket capacity.
func TestRateLimiterRefillCap(t *testing.T) {
	clk := newFakeClock()
	lim := newRateLimiter(5)
	lim.nowFn = clk.Now

	if !lim.Allow() {
		t.Fatal("first request denied")
	}
	// Long idle must refill to capacity (5), not grow beyond it.
	clk.advance(10 * time.Second)
	for i := 0; i < 5; i++ {
		if !lim.Allow() {
			t.Fatalf("request %d after idle denied; bucket should be full", i)
		}
	}
	if lim.Allow() {
		t.Fatal("6th request admitted; refill must cap at bucket size")
	}
}

// TestGatewayRateLimit verifies front-leg shielding end to end: with
// rate_per_sec=5, the first burst passes and further requests get
// exception 0x06 (Server Device Busy) — and the device never sees them.
func TestGatewayRateLimit(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr(), RatePerSec: 5})

	conn := dial(t, front)
	defer conn.Close()

	admitted := 0
	busy := 0
	for i := 0; i < 20; i++ {
		adu, _ := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
		if _, err := conn.Write(adu.Frame()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := mbtcp.ReadADU(conn)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if resp.IsException() {
			code, ok := resp.ExceptionCode()
			if !ok || code != mbtcp.ExceptionServerBusy {
				t.Fatalf("read %d: exception %d (ok=%v), want 0x06", i, code, ok)
			}
			busy++
			continue
		}
		admitted++
	}
	// The burst is 5 (one second's worth); a couple more tokens may refill
	// during the loop, so accept 5..8 admitted but the rest must be busy.
	if admitted < 5 || admitted > 8 {
		t.Fatalf("admitted %d/20, want burst of ~5 plus small refill", admitted)
	}
	if busy == 0 {
		t.Fatal("no busy responses; rate limit did not engage")
	}
	// Rejected requests must never have reached the device.
	if got := int(dev.Served()); got != admitted {
		t.Fatalf("device served %d, want exactly the %d admitted", got, admitted)
	}
}
