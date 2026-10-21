package proxy

import (
	"encoding/binary"
	"testing"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// readHealth sends a read (FC3) against the health unit and returns the
// response ADU (connection closed after one exchange).
func readHealth(t *testing.T, front string, unit uint8, start, qty uint16) mbtcp.ADU {
	t.Helper()
	conn := dial(t, front)
	defer conn.Close()
	pdu := []byte{3,
		byte(start >> 8), byte(start),
		byte(qty >> 8), byte(qty)}
	req, err := mbtcp.NewADU(0x99, unit, pdu)
	if err != nil {
		t.Fatalf("build health request: %v", err)
	}
	if _, err := conn.Write(req.Frame()); err != nil {
		t.Fatalf("write health request: %v", err)
	}
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read health response: %v", err)
	}
	return resp
}

// healthValue extracts register value i (0-based within the response).
func healthValue(t *testing.T, resp mbtcp.ADU, i int) uint16 {
	t.Helper()
	if resp.IsException() {
		t.Fatalf("health read returned exception code 0x%02x", resp.PDU[1])
	}
	n := int(resp.PDU[1]) / 2
	if i >= n {
		t.Fatalf("health response has %d registers, want index %d", n, i)
	}
	return binary.BigEndian.Uint16(resp.PDU[2+2*i : 4+2*i])
}

// warmUp performs one real device read through the proxy.
func warmUp(t *testing.T, front string) {
	t.Helper()
	if _, err := readReg(t, front); err != nil {
		t.Fatalf("warm-up read: %v", err)
	}
}

// TestHealthDisabled: without health_unit_id, requests to a high unit-ID
// go upstream (the fake device answers with exception 0x02 for registers
// other than 0x0100).
func TestHealthDisabled(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, metricsDevice(dev, nil))
	resp := readHealth(t, front, 200, 0, 2)
	if !resp.IsException() {
		t.Fatalf("unit 200 should hit the device (exception 0x02), got data frame")
	}
	if code, _ := resp.ExceptionCode(); code != 0x02 {
		t.Fatalf("want device exception 0x02, got 0x%02x", code)
	}
}

// TestHealthMagicAndVersion: registers 0/1 identify the endpoint, and the
// response carries the client's txn-ID + health unit-ID.
func TestHealthMagicAndVersion(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, metricsDevice(dev, func(d *config.Device) {
		d.HealthUnitID = ptrUnit(200)
	}))
	resp := readHealth(t, front, 200, 0, 2)
	if got := healthValue(t, resp, 0); got != healthMagic {
		t.Fatalf("magic: want 0x%04x, got 0x%04x", healthMagic, got)
	}
	if got := healthValue(t, resp, 1); got != healthRegisterMapVersion {
		t.Fatalf("map version: want %d, got %d", healthRegisterMapVersion, got)
	}
	if resp.Header.TransactionID != 0x99 || resp.Header.UnitID != 200 {
		t.Fatalf("correlation broken: txn %d unit %d", resp.Header.TransactionID, resp.Header.UnitID)
	}
}

// TestHealthUptimeAndUpstreamState: uptime is small on a fresh gateway
// and the upstream gauge shows up after a warm-up read.
func TestHealthUptimeAndUpstreamState(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, metricsDevice(dev, func(d *config.Device) {
		d.HealthUnitID = ptrUnit(200)
	}))
	warmUp(t, front)
	resp := readHealth(t, front, 200, 2, 3)
	hi := healthValue(t, resp, 0)
	lo := healthValue(t, resp, 1)
	uptime := uint32(hi)<<16 | uint32(lo)
	if uptime > 5 {
		t.Fatalf("uptime %ds too large for a fresh gateway", uptime)
	}
	if got := healthValue(t, resp, 2); got != 1 {
		t.Fatalf("upstream state after warm-up: want 1, got %d", got)
	}
}

// TestHealthReconnectsCounted: the first successful dial counts as a
// reconnect (same semantics as the Prometheus counter).
func TestHealthReconnectsCounted(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, metricsDevice(dev, func(d *config.Device) {
		d.HealthUnitID = ptrUnit(200)
	}))
	warmUp(t, front)
	resp := readHealth(t, front, 200, 5, 1)
	if got := healthValue(t, resp, 0); got != 1 {
		t.Fatalf("reconnects after first connect: want 1, got %d", got)
	}
}

// TestHealthPolicyBypass: read-only policy and the rate limiter must not
// block health reads — monitoring stays responsive during a shielding
// event.
func TestHealthPolicyBypass(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, metricsDevice(dev, func(d *config.Device) {
		d.HealthUnitID = ptrUnit(200)
		d.ReadOnly = true
		d.RatePerSec = 1
	}))
	for i := 0; i < 5; i++ {
		resp := readHealth(t, front, 200, 0, 2)
		if resp.IsException() {
			t.Fatalf("health read %d blocked despite read-only+rate limit: 0x%02x", i, resp.PDU[1])
		}
	}
	// Device reads, in contrast, hit the rate limiter eventually.
	denied := 0
	for i := 0; i < 6; i++ {
		if _, err := readReg(t, front); err != nil {
			denied++
		}
	}
	if denied == 0 {
		t.Fatalf("rate limiter never rejected device reads")
	}
}

// TestHealthBoundsAndCorrelation: out-of-range/zero-quantity reads and
// write FCs are rejected with clean Modbus exceptions; the last register
// reads fine.
func TestHealthBoundsAndCorrelation(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, metricsDevice(dev, func(d *config.Device) {
		d.HealthUnitID = ptrUnit(200)
	}))

	resp := readHealth(t, front, 200, healthRegCount, 2)
	if !resp.IsException() {
		t.Fatalf("out-of-range health read should fail")
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalDataAddr {
		t.Fatalf("want exception 0x%02x, got 0x%02x", mbtcp.ExceptionIllegalDataAddr, code)
	}

	resp = readHealth(t, front, 200, 0, 0)
	if !resp.IsException() {
		t.Fatalf("zero-quantity health read should fail")
	}

	conn := dial(t, front)
	defer conn.Close()
	req, err := mbtcp.NewADU(0x77, 200, []byte{5, 0x01, 0x00, 0xFF, 0x00})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := conn.Write(req.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err = mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !resp.IsException() {
		t.Fatalf("health write should fail")
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalFunction {
		t.Fatalf("want exception 0x%02x, got 0x%02x", mbtcp.ExceptionIllegalFunction, code)
	}

	resp = readHealth(t, front, 200, healthRegCount-1, 1)
	if resp.IsException() {
		t.Fatalf("last-register health read failed: 0x%02x", resp.PDU[1])
	}
	if got := healthValue(t, resp, 0); got != 0 {
		t.Fatalf("rate_per_sec register: want 0, got %d", got)
	}
}

// TestHealthDeviceNeverSeesHealthTraffic: the device is untouched by
// health polling.
func TestHealthDeviceNeverSeesHealthTraffic(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, metricsDevice(dev, func(d *config.Device) {
		d.HealthUnitID = ptrUnit(200)
	}))
	before := dev.Served()
	for i := 0; i < 3; i++ {
		readHealth(t, front, 200, 0, 2)
	}
	if got := dev.Served(); got != before {
		t.Fatalf("device saw %d health requests, want 0", got-before)
	}
}
