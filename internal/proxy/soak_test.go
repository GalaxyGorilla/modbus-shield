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
