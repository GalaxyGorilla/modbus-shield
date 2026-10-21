package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// TestReadCacheDisabled checks the nil-guard: ttl <= 0 disables the
// cache; a nil cache never hits.
func TestReadCacheDisabled(t *testing.T) {
	if c := newReadCache(0); c != nil {
		t.Errorf("newReadCache(0) = %v, want nil", c)
	}
	if c := newReadCache(-5 * time.Millisecond); c != nil {
		t.Errorf("newReadCache(-5ms) = %v, want nil", c)
	}
	var c *readCache
	if got := c.lookup(1, []byte{3}); got != nil {
		t.Errorf("nil cache lookup returned %v, want nil", got)
	}
	c.store(1, []byte{3}, []byte{3, 2, 0, 0}) // must not panic
}

// TestReadCacheHitAndExpiry checks hit, expiry, and key isolation.
func TestReadCacheHitAndExpiry(t *testing.T) {
	c := newReadCache(50 * time.Millisecond)
	req := []byte{3, 0x01, 0x00, 0x00, 0x01}
	resp := []byte{3, 2, 0xCA, 0xFE}

	if got := c.lookup(1, req); got != nil {
		t.Fatalf("empty cache: lookup = %v, want nil", got)
	}
	c.store(1, req, resp)
	got := c.lookup(1, req)
	if got == nil || string(got) != string(resp) {
		t.Fatalf("lookup = %x, want %x", got, resp)
	}

	// Different unit -> different key.
	if got := c.lookup(2, req); got != nil {
		t.Fatalf("different unit: lookup = %x, want nil", got)
	}
	// Different PDU -> different key.
	if got := c.lookup(1, []byte{3, 0x02, 0x00, 0x00, 0x01}); got != nil {
		t.Fatalf("different PDU: lookup = %x, want nil", got)
	}

	// Expiry: after the TTL the entry is gone.
	time.Sleep(70 * time.Millisecond)
	if got := c.lookup(1, req); got != nil {
		t.Fatalf("expired entry: lookup = %x, want nil", got)
	}
}

// TestReadCacheConcurrentAccess runs parallel lookups/stores to exercise
// the mutex under -race.
func TestReadCacheConcurrentAccess(t *testing.T) {
	c := newReadCache(200 * time.Millisecond)
	req := []byte{3, 0x01, 0x00, 0x00, 0x01}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c.lookup(1, req)
				c.store(uint8(n), req, []byte{3, 2, byte(n), byte(j)})
			}
		}(i)
	}
	wg.Wait()
}

// TestGatewayReadCache is the B8 acceptance: repeated identical reads are
// answered from memory — the device sees only the first request — and
// different registers still reach the device.
func TestGatewayReadCache(t *testing.T) {
	dev := newFakeDevice(t)
	cfg := &config.Device{
		Name:           "cache-dev",
		ListenAddr:     "127.0.0.1:0",
		DeviceAddr:     dev.Addr(),
		ReadCacheTTLMs: 2000,
		TimeoutMs:      2000,
	}
	full := &config.Config{Devices: []config.Device{*cfg}}
	full.Defaults()
	front := startDeviceGateway(t, *cfg)

	conn := dial(t, front)
	defer conn.Close()

	readOnce := func(txn uint16) mbtcp.ADU {
		t.Helper()
		req, err := mbtcp.NewADU(txn, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
		if err != nil {
			t.Fatalf("NewADU: %v", err)
		}
		if err := writeAllRTU(t, conn, req.Frame()); err != nil {
			t.Fatalf("write: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := mbtcp.ReadADU(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return resp
	}

	r1 := readOnce(0x10)
	if r1.Header.TransactionID != 0x10 || string(r1.PDU) != string([]byte{3, 2, 0xCA, 0xFE}) {
		t.Fatalf("first read: txn %d pdu %x", r1.Header.TransactionID, r1.PDU)
	}
	r2 := readOnce(0x11)
	if r2.Header.TransactionID != 0x11 {
		t.Fatalf("cache hit must carry the new txn ID: %d", r2.Header.TransactionID)
	}
	if string(r2.PDU) != string([]byte{3, 2, 0xCA, 0xFE}) {
		t.Fatalf("cache hit pdu %x", r2.PDU)
	}

	// The device must have served exactly ONE request (the first read);
	// the second came from the cache.
	if got := dev.Served(); got != 1 {
		t.Errorf("device served = %d, want 1 (second read must be a cache hit)", got)
	}

	// A different register range is a different key -> reaches the device.
	req2, err := mbtcp.NewADU(0x12, 1, []byte{3, 0x02, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if err := writeAllRTU(t, conn, req2.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp2, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The fake device answers register 0x0200 with exception 0x02.
	if code, ok := resp2.ExceptionCode(); !ok || code != mbtcp.ExceptionIllegalDataAddr {
		t.Fatalf("want exception 0x02, got fc %d code %d ok %v", resp2.FunctionCode(), code, ok)
	}
	if got := dev.Served(); got != 2 {
		t.Errorf("device served = %d, want 2 (different key reaches the device)", got)
	}
}

// TestGatewayReadCacheWriteNotCached checks that write responses are
// never cached: a write always reaches the device.
func TestGatewayReadCacheWriteNotCached(t *testing.T) {
	dev := newFakeDevice(t)
	cfg := &config.Device{
		Name:           "cache-write-dev",
		ListenAddr:     "127.0.0.1:0",
		DeviceAddr:     dev.Addr(),
		ReadCacheTTLMs: 2000,
		TimeoutMs:      2000,
	}
	full := &config.Config{Devices: []config.Device{*cfg}}
	full.Defaults()
	front := startDeviceGateway(t, *cfg)

	conn := dial(t, front)
	defer conn.Close()
	for i := 0; i < 2; i++ {
		req, err := mbtcp.NewADU(uint16(0x20+i), 1, []byte{6, 0x01, 0x00, 0x00, 0x2A})
		if err != nil {
			t.Fatalf("NewADU: %v", err)
		}
		if err := writeAllRTU(t, conn, req.Frame()); err != nil {
			t.Fatalf("write: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := mbtcp.ReadADU(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if resp.IsException() {
			t.Fatalf("write %d: unexpected exception %x", i, resp.PDU)
		}
	}
	if got := dev.Served(); got != 2 {
		t.Errorf("device served = %d, want 2 (writes are never cached)", got)
	}
}

// TestGatewayRateLimitBeforeCache pins the serve() ordering: the rate
// limiter runs BEFORE the cache lookup, so a cache hit still consumes a
// rate token and is rejected with 0x06 when the limit is exhausted.
// (A hit saves the DEVICE, not the rate budget.) The contract text in
// gateway.go, README.md and configs/gateway.yaml documents this — this
// test keeps code and docs in sync.
func TestGatewayRateLimitBeforeCache(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr:     dev.Addr(),
		RatePerSec:     2,
		ReadCacheTTLMs: 60000, // any hit would mask the limiter if it ran first
	})

	conn := dial(t, front)
	defer conn.Close()

	adu, _ := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	busy := 0
	for i := 0; i < 10; i++ {
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
		}
	}
	// rate_per_sec=2: burst 2 plus refill during 10 sequential requests —
	// a few pass, the rest MUST be rejected by the limiter even though
	// every response is identical and cacheable. If the cache ran before
	// the limiter, only the first request would ever reach it and the
	// remaining 9 would be cache hits (busy stays 0).
	if busy == 0 {
		t.Fatal("no busy responses; cache appears to run before the rate limiter")
	}
	if got := int(dev.Served()); got > 3 {
		t.Fatalf("device served %d, want <= ~3 (burst + refill)", got)
	}
}
