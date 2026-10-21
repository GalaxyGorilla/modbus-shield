package observ

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestLog validates level parsing and error handling.
func TestLog(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "error"} {
		for _, format := range []string{"console", "json"} {
			l, err := Log(lvl, format)
			if err != nil {
				t.Fatalf("Log(%q, %q): %v", lvl, format, err)
			}
			l.Sync()
		}
	}
	if _, err := Log("bogus", "console"); err == nil {
		t.Error("bogus level should fail")
	}
}

// TestMetricsImplementsProxyInterface pins the interface contract.
func TestMetricsImplementsProxyInterface(t *testing.T) {
	m := NewMetrics()
	// Every hook must work on a fresh registry (first-use registration).
	m.IncConnAccepted()
	m.IncConnRejected()
	m.ObserveRequest("dev1", "forwarded")
	m.ObserveLatency("dev1", 1500*time.Microsecond)
	m.IncUpstreamError()
	m.IncStaleDiscard()
	m.IncReconnect()
	m.SetDeviceUp("dev1", true)
	m.SetDeviceUp("dev1", false)
	m.SetDeviceUp("dev2", true)
}

// TestMetricsHandler: the scrape handler serves the registered series.
func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()
	m.IncConnAccepted()
	m.ConnAccepted.Add(4) // total 5
	m.ObserveRequest("plc", "forwarded")
	m.DeviceUp.WithLabelValues("plc").Set(1)

	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, want := range []string{
		"modbus_shield_connections_accepted_total 5",
		`modbus_shield_requests_total{device="plc",outcome="forwarded"} 1`,
		`modbus_shield_device_up{device="plc"} 1`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}
