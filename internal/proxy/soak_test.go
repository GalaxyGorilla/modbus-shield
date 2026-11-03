// Soak test for the multi-device data plane: the property only minutes of
// continuous traffic can show.
//
// It is skipped unless MODBUS_SHIELD_SOAK=1 (`make soak`), because a
// ten-minute test in `go test ./...` would be a ten-minute edit loop. The
// normal suite already pins correctness; this pins the operational shape:
// every request is answered, goroutines and live heap stay flat, and two
// co-hosted devices do not interfere with each other.
package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

const soakPollInterval = 5 * time.Millisecond

// soakDuration returns the wall-clock budget. A soak that skips silently is
// worthless, so the skip reason names the switch.
func soakDuration(t *testing.T) time.Duration {
	t.Helper()
	if os.Getenv("MODBUS_SHIELD_SOAK") != "1" {
		t.Skip("soak test: set MODBUS_SHIELD_SOAK=1 (`make soak`) to run it")
	}
	const def = 10 * time.Minute
	v := os.Getenv("MODBUS_SHIELD_SOAK_DURATION")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		t.Fatalf("MODBUS_SHIELD_SOAK_DURATION=%q: want a positive Go duration such as 90s or 10m", v)
	}
	return d
}

// soakRead performs one holding-register read on an open front-leg
// connection and checks the value. It returns an error instead of calling
// t.Fatalf so a single failed round is counted, not fatal.
func soakRead(conn net.Conn, want uint16) error {
	adu, err := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		return err
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		return err
	}
	if resp.Header.TransactionID != 0x1234 || resp.Header.UnitID != 1 {
		return fmt.Errorf("correlation failed: %+v", resp.Header)
	}
	if resp.IsException() {
		code, _ := resp.ExceptionCode()
		return fmt.Errorf("device exception: code=%d", code)
	}
	got := binary.BigEndian.Uint16(resp.PDU[2:4])
	if got != want {
		return fmt.Errorf("register = %#04x, want %#04x", got, want)
	}
	return nil
}

// TestSoakMultiDeviceSteadyState keeps two co-hosted devices busy for the
// budget. Each device has its own listener, upstream connection and unit-ID
// remap, so the answer also proves the requests did not cross devices.
func TestSoakMultiDeviceSteadyState(t *testing.T) {
	budget := soakDuration(t)

	devA := newFakeDeviceCfg(t, fakeDeviceCfg{UnitValues: true})
	devB := newFakeDeviceCfg(t, fakeDeviceCfg{UnitValues: true})
	cfg := &config.Config{Devices: []config.Device{
		{
			Name:         "a",
			ListenAddr:   "127.0.0.1:0",
			DeviceAddr:   devA.Addr(),
			DeviceUnitID: ptrUnit(10),
		},
		{
			Name:         "b",
			ListenAddr:   "127.0.0.1:0",
			DeviceAddr:   devB.Addr(),
			DeviceUnitID: ptrUnit(20),
		},
	}}
	cfg.Defaults()
	r, err := NewRunner(cfg, nopLogger{}, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	go func() { _ = r.Run() }()
	t.Cleanup(r.Stop)
	<-r.bound
	if len(r.lns) != 2 {
		t.Fatalf("want 2 bound listeners, got %d", len(r.lns))
	}
	connA := dial(t, r.lns[0].Addr().String())
	defer connA.Close()
	connB := dial(t, r.lns[1].Addr().String())
	defer connB.Close()

	// Warm up so the baseline includes both upstream connections and loops.
	for i := 0; i < 5; i++ {
		if err := soakRead(connA, 0xCA0A); err != nil {
			t.Fatalf("warmup a: %v", err)
		}
		if err := soakRead(connB, 0xCA14); err != nil {
			t.Fatalf("warmup b: %v", err)
		}
	}

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	var baseHeap runtime.MemStats
	runtime.ReadMemStats(&baseHeap)

	var (
		ok, failed, maxGoroutines int
		worst                     time.Duration
		lastErr                   error
	)
	sampleEvery := budget / 20
	if sampleEvery < time.Second {
		sampleEvery = time.Second
	}
	nextSample := time.Now().Add(sampleEvery)
	deadline := time.Now().Add(budget)

	for time.Now().Before(deadline) {
		start := time.Now()
		errA := soakRead(connA, 0xCA0A)
		errB := soakRead(connB, 0xCA14)
		if errA != nil || errB != nil {
			failed++
			if errA != nil {
				lastErr = errA
			} else {
				lastErr = errB
			}
		} else {
			ok++
			if elapsed := time.Since(start); elapsed > worst {
				worst = elapsed
			}
		}
		if time.Now().After(nextSample) {
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
			nextSample = time.Now().Add(sampleEvery)
		}
		time.Sleep(soakPollInterval)
	}

	if failed != 0 {
		t.Fatalf("%d of %d rounds were unanswered over %s (last error: %v)", failed, ok+failed, budget, lastErr)
	}
	if maxGoroutines > baseGoroutines+8 {
		t.Fatalf("goroutines grew %d -> %d during the soak", baseGoroutines, maxGoroutines)
	}

	runtime.GC()
	var endHeap runtime.MemStats
	runtime.ReadMemStats(&endHeap)
	if grew := int64(endHeap.HeapAlloc) - int64(baseHeap.HeapAlloc); grew > 24<<20 {
		t.Fatalf("live heap grew %.1fMiB over the soak (%.1fMiB -> %.1fMiB): something retains per-request state",
			float64(grew)/(1<<20), float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
	}

	t.Logf("multi-device soak: %s, %d rounds, worst round trip %s, goroutines %d (baseline %d, peak %d), live heap %.1fMiB -> %.1fMiB",
		budget, ok, worst.Round(time.Millisecond), runtime.NumGoroutine(), baseGoroutines, maxGoroutines,
		float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))

	_ = connA.Close()
	_ = connB.Close()
	r.Stop()
	waitForGoroutines(t, baseGoroutines+8, 15*time.Second)
}

// TestSoakMultiClientSteadyState keeps one device busy from several
// concurrent front-leg clients for the budget. The property is fan-in: the
// fragile device still sees exactly one upstream connection, every client
// gets its own answer, and per-client state does not accumulate.
func TestSoakMultiClientSteadyState(t *testing.T) {
	budget := soakDuration(t)

	// UnitValues makes the fake device answer 0xCA00|unit-ID, so a response
	// delivered to the wrong client is detectable from the payload as well
	// as from the unit/transaction header.
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{UnitValues: true})
	cfg := &config.Config{Devices: []config.Device{{
		Name:       "fan-in",
		ListenAddr: "127.0.0.1:0",
		DeviceAddr: dev.Addr(),
		MaxClients: 16,
		TimeoutMs:  8000,
	}}}
	cfg.Defaults()
	r, err := NewRunner(cfg, nopLogger{}, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	go func() { _ = r.Run() }()
	t.Cleanup(r.Stop)
	<-r.bound
	if len(r.lns) != 1 {
		t.Fatalf("want 1 bound listener, got %d", len(r.lns))
	}
	front := r.lns[0].Addr().String()

	const clients = 8
	conns := make([]net.Conn, clients)
	for i := range conns {
		conns[i] = dial(t, front)
		// Distinct unit IDs and transaction IDs per client: a crossed
		// answer carries the wrong unit, the wrong value and the wrong
		// transaction ID, so correlation bugs cannot hide behind a
		// shared 0xCAFE payload.
		for j := 0; j < 3; j++ {
			if err := soakReadClient(conns[i], uint8(10+i), uint16(0x1000+i*0x100+j), uint16(0xCA00)|uint16(10+i)); err != nil {
				t.Fatalf("warmup client %d: %v", i, err)
			}
		}
	}

	var (
		ok, failed atomic.Int64
		errMu      sync.Mutex
		lastErr    error
	)
	deadline := time.Now().Add(budget)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range conns {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sent := 0
			for time.Now().Before(deadline) {
				unit := uint8(10 + i)
				txn := uint16(0x1000 + i*0x100 + sent)
				want := uint16(0xCA00) | uint16(unit)
				if err := soakReadClient(conns[i], unit, txn, want); err != nil {
					failed.Add(1)
					errMu.Lock()
					lastErr = err
					errMu.Unlock()
				} else {
					ok.Add(1)
				}
				sent++
				time.Sleep(soakPollInterval)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	runtime.GC()
	runtime.Gosched()
	time.Sleep(20 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()
	var baseHeap runtime.MemStats
	runtime.ReadMemStats(&baseHeap)
	close(start)

	var maxGoroutines int
	sampleEvery := budget / 20
	if sampleEvery < time.Second {
		sampleEvery = time.Second
	}
	ticker := time.NewTicker(sampleEvery)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
			goto finished
		case <-ticker.C:
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
		}
	}

finished:
	if n := failed.Load(); n != 0 {
		errMu.Lock()
		last := lastErr
		errMu.Unlock()
		t.Fatalf("%d of %d requests were unanswered over %s (last error: %v)", n, ok.Load()+n, budget, last)
	}
	if maxGoroutines > baseGoroutines+8 {
		t.Fatalf("goroutines grew %d -> %d during the soak", baseGoroutines, maxGoroutines)
	}
	// The fragile device must still have seen exactly one upstream
	// connection: fan-in is multiplexed, not one dial per client.
	if got := dev.Accepted(); got != 1 {
		t.Fatalf("device accepted %d connections, want exactly 1", got)
	}

	runtime.GC()
	var endHeap runtime.MemStats
	runtime.ReadMemStats(&endHeap)
	if grew := int64(endHeap.HeapAlloc) - int64(baseHeap.HeapAlloc); grew > 24<<20 {
		t.Fatalf("live heap grew %.1fMiB over the soak (%.1fMiB -> %.1fMiB): something retains per-request state",
			float64(grew)/(1<<20), float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
	}

	t.Logf("multi-client soak: %s, %d clients, %d requests, device connections %d, goroutines %d (baseline %d, peak %d), live heap %.1fMiB -> %.1fMiB",
		budget, clients, ok.Load(), dev.Accepted(), runtime.NumGoroutine(), baseGoroutines, maxGoroutines,
		float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))

	for _, c := range conns {
		_ = c.Close()
	}
	r.Stop()
	waitForGoroutines(t, baseGoroutines+8, 15*time.Second)
}

// soakReadClient is soakRead with a caller-chosen unit, transaction ID and
// expected value. It verifies the whole correlation tuple, so a response
// that belongs to another client cannot pass.
func soakReadClient(conn net.Conn, unit uint8, txn, want uint16) error {
	adu, err := mbtcp.NewADU(txn, unit, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		return err
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		return err
	}
	if resp.Header.TransactionID != txn || resp.Header.UnitID != unit {
		return fmt.Errorf("correlation failed: got txn=%#04x unit=%d, want txn=%#04x unit=%d",
			resp.Header.TransactionID, resp.Header.UnitID, txn, unit)
	}
	if resp.IsException() {
		code, _ := resp.ExceptionCode()
		return fmt.Errorf("device exception: code=%d", code)
	}
	got := binary.BigEndian.Uint16(resp.PDU[2:4])
	if got != want {
		return fmt.Errorf("register = %#04x, want %#04x", got, want)
	}
	return nil
}

func waitForGoroutines(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		n := runtime.NumGoroutine()
		if n <= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d after teardown, want <= %d", n, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
