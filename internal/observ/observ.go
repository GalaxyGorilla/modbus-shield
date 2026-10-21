// Package observ provides the shared logging (zap) and Prometheus
// metrics baseline for the gateway role. It adapts zap to the
// zap-agnostic proxy.Logger interface and implements proxy.Metrics.
package observ

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/proxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Compile-time check: observ.Metrics satisfies the proxy metrics
// interface consumed by the gateway/upstream.
var _ proxy.Metrics = (*Metrics)(nil)

// Log builds the process logger from the config log settings. level is
// one of debug|info|warn|error; format console yields human-friendly
// output, json yields the production line format.
func Log(level, format string) (*zap.Logger, error) {
	lvl := zap.NewAtomicLevelAt(zap.InfoLevel)
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	var cfg zap.Config
	if format == "console" {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}
	cfg.Level = lvl
	return cfg.Build()
}

// AsProxyLogger adapts a zap.Logger to the zap-agnostic proxy.Logger
// interface. *zap.SugaredLogger satisfies proxy.Logger directly — its
// formatted methods have the exact required signature.
func AsProxyLogger(l *zap.Logger) proxy.Logger {
	return l.Sugar()
}

// Metrics holds the process-wide Prometheus instruments and implements
// proxy.Metrics. The zero value is not usable; use NewMetrics.
type Metrics struct {
	reg *prometheus.Registry

	ConnAccepted prometheus.Counter // front-leg connections accepted
	ConnRejected prometheus.Counter // front-leg connections rejected (cap or allow-list)
	Requests     *prometheus.CounterVec
	// Requests labels: device, outcome ∈
	// forwarded|exception_device|exception_policy|exception_rate.
	ReqErrors    prometheus.Counter // upstream forwarding errors (dial, timeout, read/write)
	StaleDiscard prometheus.Counter // stale/late upstream responses discarded
	Reconnects   prometheus.Counter // upstream connections re-established after a drop
	DeviceUp     *prometheus.GaugeVec
	// DeviceUp labels: device; 1 when the upstream connection is up.

	latMu sync.Mutex
	lat   map[string]prometheus.Histogram // per-device latency histograms
}

// NewMetrics registers a fresh metric set on a new registry.
func NewMetrics() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry(), lat: map[string]prometheus.Histogram{}}
	m.ConnAccepted = mustCounter(m.reg, "modbus_shield_connections_accepted_total",
		"Front-leg client connections accepted.")
	m.ConnRejected = mustCounter(m.reg, "modbus_shield_connections_rejected_total",
		"Front-leg client connections rejected (connection cap or allow-list).")
	m.Requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "modbus_shield_requests_total",
		Help: "Requests by device and outcome (forwarded, exception_device, exception_policy, exception_rate).",
	}, []string{"device", "outcome"})
	m.reg.MustRegister(m.Requests)
	m.ReqErrors = mustCounter(m.reg, "modbus_shield_request_errors_total",
		"Upstream forwarding errors (dial, timeout, read/write).")
	m.StaleDiscard = mustCounter(m.reg, "modbus_shield_stale_responses_discarded_total",
		"Stale or late upstream responses discarded (transaction ID mismatch).")
	m.Reconnects = mustCounter(m.reg, "modbus_shield_reconnects_total",
		"Upstream connections re-established after a drop.")
	m.DeviceUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "modbus_shield_device_up",
		Help: "1 when the upstream device connection is established.",
	}, []string{"device"})
	m.reg.MustRegister(m.DeviceUp)
	return m
}

// histogram returns the latency histogram for a device, registering it
// on first use. Buckets are tuned for Modbus: sub-millisecond local
// exchanges up to multi-second timeouts.
func (m *Metrics) histogram(device string) prometheus.Histogram {
	m.latMu.Lock()
	defer m.latMu.Unlock()
	if h, ok := m.lat[device]; ok {
		return h
	}
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "modbus_shield_forward_latency_seconds",
		Help:        "Upstream exchange latency (request forwarded to response received).",
		ConstLabels: prometheus.Labels{"device": device},
		Buckets:     prometheus.ExponentialBuckets(0.0005, 2, 16),
	})
	m.reg.MustRegister(h)
	m.lat[device] = h
	return h
}

// Handler returns the Prometheus scrape handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ServeMetrics serves /metrics on addr until the process exits. It is
// intended to run in its own goroutine.
func ServeMetrics(addr string, handler http.Handler, log *zap.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("metrics server", zap.Error(err))
		}
	}()
	return srv
}

// ShutdownMetrics stops the metrics server.
func ShutdownMetrics(srv *http.Server) {
	if srv == nil {
		return
	}
	_ = srv.Close()
}

func (m *Metrics) IncConnAccepted() { m.ConnAccepted.Inc() }
func (m *Metrics) IncConnRejected() { m.ConnRejected.Inc() }

func (m *Metrics) ObserveRequest(device, outcome string) {
	m.Requests.WithLabelValues(device, outcome).Inc()
}

func (m *Metrics) ObserveLatency(device string, d time.Duration) {
	m.histogram(device).Observe(d.Seconds())
}

func (m *Metrics) IncUpstreamError() { m.ReqErrors.Inc() }
func (m *Metrics) IncStaleDiscard()  { m.StaleDiscard.Inc() }
func (m *Metrics) IncReconnect()     { m.Reconnects.Inc() }

func (m *Metrics) SetDeviceUp(device string, up bool) {
	if up {
		m.DeviceUp.WithLabelValues(device).Set(1)
	} else {
		m.DeviceUp.WithLabelValues(device).Set(0)
	}
}

func mustCounter(reg *prometheus.Registry, name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	reg.MustRegister(c)
	return c
}
