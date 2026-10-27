package proxy

import (
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// TestShutdownDrainsInFlightRequest pins the drain contract: a SIGTERM
// arriving while a request is at the device must not cut the response
// off — the client still gets its answer, and Stop returns promptly even
// though the client keeps its connection open (idle handlers are closed
// out instead of waiting for the full grace period).
func TestShutdownDrainsInFlightRequest(t *testing.T) {
	dev := newFakeDeviceCfg(t, fakeDeviceCfg{RespondDelay: 150 * time.Millisecond})

	cfg := &config.Config{Devices: []config.Device{{
		Name:       "drain-dev",
		ListenAddr: "127.0.0.1:0",
		DeviceAddr: dev.Addr(),
		TimeoutMs:  5000,
	}}}
	cfg.Defaults()
	r, err := NewRunner(cfg, nopLogger{}, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	go func() { _ = r.Run() }()
	<-r.bound
	front := r.lns[0].Addr().String()

	conn := dial(t, front)
	defer conn.Close()

	adu, err := mbtcp.NewADU(0x7777, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("NewADU: %v", err)
	}
	if _, err := conn.Write(adu.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(40 * time.Millisecond) // the device is working on it now

	stopped := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		r.Stop()
		stopped <- time.Since(start)
	}()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("response cut off by shutdown: %v", err)
	}
	if resp.Header.TransactionID != 0x7777 {
		t.Fatalf("txn = %d, want 0x7777", resp.Header.TransactionID)
	}
	if resp.IsException() {
		t.Fatalf("unexpected exception %x during drain", resp.PDU)
	}

	select {
	case d := <-stopped:
		// The idle connection must not cost the full drain grace.
		if d > 2*time.Second {
			t.Fatalf("Stop took %v, want prompt shutdown (idle clients are closed out)", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return")
	}
}
