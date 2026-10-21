package proxy

import (
	"net"
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

// B5: request_delay_ms paces requests toward the device — the gateway
// serializes all client traffic onto one upstream connection, so the gap
// is enforced across ALL clients exactly at the device-facing point.

// rawExchange sends one FC3 read of register 0x0100 with the given
// transaction ID and returns the raw response ADU (exceptions included).
func rawExchange(t *testing.T, conn net.Conn, txn uint16) mbtcp.ADU {
	t.Helper()
	adu, err := mbtcp.NewADU(txn, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Header.TransactionID != txn {
		t.Fatalf("correlation failed: got txn %d, want %d", resp.Header.TransactionID, txn)
	}
	return resp
}

func TestGatewayRequestDelay(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGatewayTLS(t, dev, func(d *config.Device) {
		d.Name = "paced-dev"
		d.RequestDelayMs = 100
		d.TimeoutMs = 8000
	})
	conn := dial(t, front)
	defer conn.Close()

	// 5 sequential reads; with 100ms pacing the total must take at least
	// 4 * 100ms = 400ms (the gap applies between consecutive requests).
	start := time.Now()
	for i := 0; i < 5; i++ {
		resp := rawExchange(t, conn, 0x1234)
		if resp.IsException() {
			t.Fatalf("read %d: unexpected exception", i)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 380*time.Millisecond {
		t.Fatalf("5 paced reads took %v, want >= ~400ms (pacing not enforced)", elapsed)
	}
	if dev.Served() != 5 {
		t.Fatalf("device served = %d, want 5", dev.Served())
	}
}

// B6: idle_timeout_ms reaps front connections that stay idle beyond the
// TTL — a dead/hung client must not hold a connection-cap slot forever.
func TestGatewayIdleTimeoutReapsClient(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGatewayTLS(t, dev, func(d *config.Device) {
		d.Name = "idle-dev"
		d.IdleTimeoutMs = 300
		d.TimeoutMs = 2000
	})
	conn := dial(t, front)

	// First read works.
	resp := rawExchange(t, conn, 0x1234)
	if resp.IsException() {
		t.Fatal("first read: unexpected exception")
	}

	// Idle beyond the TTL: the proxy must close the connection.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("connection still open after idle TTL; want closed by proxy")
	}

	// A fresh connection works fine afterward.
	conn2 := dial(t, front)
	defer conn2.Close()
	if r := rawExchange(t, conn2, 0x4321); r.IsException() {
		t.Fatal("post-reap read: unexpected exception")
	}
}
