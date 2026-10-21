package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// metricsDevice returns a test device with a fixed name so metric
// labels are predictable (default name would be the device address).
func metricsDevice(dev *fakeDevice, mutate func(*config.Device)) config.Device {
	d := config.Device{Name: "test-device", DeviceAddr: dev.Addr()}
	if mutate != nil {
		mutate(&d)
	}
	return d
}

// captureMetrics records every observability call for assertions.
// Implements Metrics; safe for concurrent use.
type captureMetrics struct {
	mu      sync.Mutex
	acc     int
	rej     int
	reqs    map[[2]string]int
	lat     map[string]int
	upErr   int
	stale   int
	recon   int
	upState map[string]bool
}

func newCaptureMetrics() *captureMetrics {
	return &captureMetrics{
		reqs:    map[[2]string]int{},
		lat:     map[string]int{},
		upState: map[string]bool{},
	}
}

func (c *captureMetrics) IncConnAccepted() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acc++
}

func (c *captureMetrics) IncConnRejected() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rej++
}

func (c *captureMetrics) ObserveRequest(device, outcome string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs[[2]string{device, outcome}]++
}

func (c *captureMetrics) ObserveLatency(device string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lat[device]++
}

func (c *captureMetrics) IncUpstreamError() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.upErr++
}

func (c *captureMetrics) IncStaleDiscard() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stale++
}

func (c *captureMetrics) IncReconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recon++
}

func (c *captureMetrics) SetDeviceUp(device string, up bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.upState[device] = up
}

// --- read helpers (must not race with the hook) ---

func (c *captureMetrics) counts() (acc, rej int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.acc, c.rej
}

func (c *captureMetrics) requestCount(device, outcome string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reqs[[2]string{device, outcome}]
}

func (c *captureMetrics) latencyCount(device string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lat[device]
}

func (c *captureMetrics) errorCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.upErr
}

func (c *captureMetrics) reconnectCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recon
}

func (c *captureMetrics) deviceUp(device string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.upState[device]
}

// startGatewayWithMetrics is startGateway with a capture hook.
func startGatewayWithMetrics(t *testing.T, dev config.Device) (string, *captureMetrics) {
	t.Helper()
	dev.ListenAddr = "127.0.0.1:0"
	cfg := &config.Config{Devices: []config.Device{dev}}
	cfg.Defaults()
	met := newCaptureMetrics()
	r, err := NewRunner(cfg, nopLogger{}, met)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- r.Run() }()
	t.Cleanup(r.Stop)
	<-r.bound
	return r.lns[0].Addr().String(), met
}

// TestMetricsForwarded: a successful read counts as forwarded, latency
// observed, connection accepted, device up.
func TestMetricsForwarded(t *testing.T) {
	dev := newFakeDevice(t)
	front, met := startGatewayWithMetrics(t, metricsDevice(dev, nil))

	v, err := readReg(t, front)
	if err != nil {
		t.Fatalf("readReg: %v", err)
	}
	if v != 0xCAFE {
		t.Fatalf("value = %#x, want 0xCAFE", v)
	}

	if got := met.requestCount("test-device", outcomeForwarded); got != 1 {
		t.Errorf("forwarded requests = %d, want 1", got)
	}
	if got := met.latencyCount("test-device"); got != 1 {
		t.Errorf("latency observations = %d, want 1", got)
	}
	acc, rej := met.counts()
	if acc != 1 || rej != 0 {
		t.Errorf("accepted = %d, rejected = %d, want 1/0", acc, rej)
	}
	if !met.deviceUp("test-device") {
		t.Error("device_up should be true after a successful exchange")
	}
}

// TestMetricsPolicyOutcomes: read-only rejections count under their own
// outcome label; the device never sees the write. Read-only is checked
// before the rate limiter, so the write is policy-rejected even with a
// tight rate budget.
func TestMetricsPolicyOutcomes(t *testing.T) {
	dev := newFakeDevice(t)
	front, met := startGatewayWithMetrics(t, metricsDevice(dev, func(d *config.Device) {
		d.ReadOnly = true
		d.RatePerSec = 1
	}))

	if _, err := readReg(t, front); err != nil {
		t.Fatalf("readReg: %v", err)
	}
	conn := dial(t, front)
	t.Cleanup(func() { conn.Close() })
	resp := writeSingle(t, conn, 0x0100, 0x0001)
	if !resp.IsException() {
		t.Fatal("write should be rejected with an exception")
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalFunction {
		t.Fatalf("exception code = %d, want %d (illegal function)", code, mbtcp.ExceptionIllegalFunction)
	}

	if got := met.requestCount("test-device", outcomeExceptionPolicy); got != 1 {
		t.Errorf("policy rejections = %d, want 1", got)
	}
	if got := met.requestCount("test-device", outcomeForwarded); got != 1 {
		t.Errorf("forwarded = %d, want 1 (the initial read)", got)
	}
	if dev.Served() != 1 {
		t.Errorf("device served = %d, want 1 (write must not reach device)", dev.Served())
	}
}

// TestMetricsRateOutcome: rate-limited requests count under
// exception_rate; forwarded and rate rejections together account for
// every request.
func TestMetricsRateOutcome(t *testing.T) {
	dev := newFakeDevice(t)
	front, met := startGatewayWithMetrics(t, metricsDevice(dev, func(d *config.Device) {
		d.RatePerSec = 2
	}))

	conn := dial(t, front)
	t.Cleanup(func() { conn.Close() })

	const total = 10
	var rate int
	for i := 0; i < total; i++ {
		adu, err := mbtcp.NewADU(uint16(i), 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
		if err != nil {
			t.Fatalf("NewADU: %v", err)
		}
		if _, err := conn.Write(adu.Frame()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := mbtcp.ReadADU(conn)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if resp.IsException() {
			if code, _ := resp.ExceptionCode(); code == mbtcp.ExceptionServerBusy {
				rate++
			}
		}
	}

	fwd := met.requestCount("test-device", outcomeForwarded)
	rateCounted := met.requestCount("test-device", outcomeExceptionRate)
	if fwd+rateCounted != total {
		t.Errorf("forwarded %d + rate %d = %d, want %d", fwd, rateCounted, fwd+rateCounted, total)
	}
	if rate == 0 {
		t.Error("expected at least one rate-limited response (0x06)")
	}
	if rate != rateCounted {
		t.Errorf("responses 0x06 = %d, counted exception_rate = %d", rate, rateCounted)
	}
}

// TestMetricsUpstreamErrorOutcome: an unreachable device counts
// exception_device + upstream error, and device_up is false.
func TestMetricsUpstreamErrorOutcome(t *testing.T) {
	front, met := startGatewayWithMetrics(t, config.Device{
		Name:       "test-device",
		DeviceAddr: "127.0.0.1:1", // nothing listens there
		TimeoutMs:  300,
	})

	if _, err := readReg(t, front); err == nil {
		t.Fatal("readReg should fail with a gateway exception")
	}

	if got := met.requestCount("test-device", outcomeExceptionDevice); got != 1 {
		t.Errorf("device rejections = %d, want 1", got)
	}
	if got := met.errorCount(); got < 1 {
		t.Errorf("upstream errors = %d, want >= 1", got)
	}
	if met.deviceUp("test-device") {
		t.Error("device_up should be false when unreachable")
	}
}

// TestMetricsReconnect: re-dials after a device outage are counted and
// device_up tracks the connection state.
func TestMetricsReconnect(t *testing.T) {
	dev := newFakeDevice(t)
	front, met := startGatewayWithMetrics(t, metricsDevice(dev, nil))

	if _, err := readReg(t, front); err != nil {
		t.Fatalf("warm-up readReg: %v", err)
	}
	if !met.deviceUp("test-device") {
		t.Fatal("device_up should be true after the warm-up exchange")
	}
	if got := met.reconnectCount(); got != 1 {
		t.Fatalf("reconnects after warm-up = %d, want 1 (initial dial)", got)
	}

	// Power off the device (force-closes the proxy's upstream conn),
	// then bring an identical device back on the same address.
	dev.Close()
	time.Sleep(100 * time.Millisecond)
	newFakeDeviceCfg(t, fakeDeviceCfg{OnAddr: dev.Addr()})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := readReg(t, front); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no successful read after device recovery")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got := met.reconnectCount(); got != 2 {
		t.Errorf("reconnects = %d, want 2 (initial dial + re-dial)", got)
	}
	if !met.deviceUp("test-device") {
		t.Error("device_up should be true after recovery")
	}
}
