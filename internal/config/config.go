// Package config loads per-instance configuration for the modbus-shield
// binary. One YAML file describes one or more proxy instances; each entry
// couples exactly one front-leg listener with one upstream legacy device
// (the v1 gateway shape: N clients -> box -> 1 device).
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Device couples one front-leg listener with one upstream legacy device.
type Device struct {
	// Name is an optional label used in logs and metrics. Falls back to
	// DeviceAddr when unset.
	Name string `yaml:"name"`

	// ListenAddr is the front-leg bind address clients connect to,
	// e.g. ":5020" or "0.0.0.0:502".
	ListenAddr string `yaml:"listen_addr"`

	// ExtraListen are optional additional front-leg bind addresses for
	// the same device (B10): every address is served by the same gateway,
	// so all listeners share ONE upstream device connection, one
	// connection cap, one allow-list, one rate limit and one TLS config.
	// Shielding stays per-device no matter how many doors clients use.
	ExtraListen []string `yaml:"extra_listen"`

	// DeviceAddr is the upstream legacy device, e.g. "10.0.0.42:502".
	DeviceAddr string `yaml:"device_addr"`

	// ReadOnly blocks all write function codes (5, 6, 15, 16, 21, 22, 23)
	// with a proxy-generated Modbus exception (FC|0x80, code 0x01) — the
	// device never sees the write.
	ReadOnly bool `yaml:"read_only"`

	// Allow is an optional client allow-list of IPs or CIDRs
	// (e.g. "10.8.0.0/24"). Empty = any client may connect. When set,
	// only matching client addresses are accepted.
	Allow []string `yaml:"allow"`

	// MaxClients caps concurrent client connections on the front leg
	// (protects fragile single-connection devices). 0 = default (16).
	MaxClients int `yaml:"max_clients"`

	// RatePerSec caps accepted requests per second on the front leg
	// (defends the device against polling storms). 0 = unlimited.
	RatePerSec int `yaml:"rate_per_sec"`

	// TimeoutMs is the per-request upstream deadline in milliseconds.
	// 0 = default (5000).
	TimeoutMs int `yaml:"timeout_ms"`

	// RequestDelayMs, when set, paces requests toward the device (B5):
	// the proxy enforces at least this much gap between consecutive
	// requests on the upstream connection, shielding picky legacy
	// devices from back-to-back traffic. 0 = unpaced.
	RequestDelayMs int `yaml:"request_delay_ms"`

	// IdleTimeoutMs, when set, closes front-leg connections that stay
	// idle longer than this (B6) — reclaims connection-cap slots from
	// dead or hung clients (e.g. crashed pollers). 0 = disabled.
	IdleTimeoutMs int `yaml:"idle_timeout_ms"`

	// DeviceUnitID, when set, overrides the unit ID sent upstream
	// (serial-gateway style remap: client unit IDs pass through the
	// front leg, the device always sees this value; the gateway rewrites
	// the client's original unit ID back into responses).
	DeviceUnitID *uint8 `yaml:"device_unit_id"`

	// TLS, when set, terminates TLS on the front-leg listener (the
	// device-side wire stays plain Modbus TCP). With ClientCA set, client
	// certificates signed by that CA are required (mTLS).
	TLS *TLSConfig `yaml:"tls"`

	// DeviceTLS, when set, secures the upstream leg with TLS (client
	// side): the box dials the device address over TLS instead of plain
	// TCP. This is the front box of a two-proxy secured line — the far
	// box is a gateway with a front-leg `tls:` block exposing the local
	// device. CACert verifies the far box's certificate (empty = system
	// roots); Cert/Key present a client certificate for mTLS.
	DeviceTLS *DeviceTLSConfig `yaml:"device_tls"`

	// HealthUnitID, when set, enables the health-via-Modbus endpoint
	// (B4): requests addressed to this virtual unit-ID are answered by
	// the proxy itself with readable health registers (uptime, upstream
	// state, counters) — the device never sees them. Health reads bypass
	// read-only policy and the rate limiter so monitoring stays
	// responsive during a shielding event; the allow-list and connection
	// cap still apply.
	HealthUnitID *uint8 `yaml:"health_unit_id"`
}

// TLSConfig configures front-leg TLS termination for a device.
type TLSConfig struct {
	// Cert and Key are the server certificate/key pair (PEM files).
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// ClientCA, when set, is a PEM file of CA certificates; clients must
	// present a certificate signed by one of them (mTLS).
	ClientCA string `yaml:"client_ca"`
}

// DeviceTLSConfig configures the upstream (device-side) TLS leg: the box
// acts as the TLS client when dialing the device address. This is the
// near side of a two-proxy secured line.
type DeviceTLSConfig struct {
	// CACert, when set, is a PEM file of CA certificates used to verify
	// the device-side (far box) server certificate. Empty = system roots.
	CACert string `yaml:"ca_cert"`
	// ServerName, when set, overrides the TLS server-name check (use when
	// the far box presents a certificate for a different name; IP
	// addresses need no override when they are in the cert's IP SANs).
	ServerName string `yaml:"server_name"`
	// Cert and Key, when set together, present a client certificate to
	// the far box (mTLS on the upstream leg).
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// LogConfig selects logging behavior.
type LogConfig struct {
	// Level is one of "debug", "info", "warn", "error". Default "info".
	Level string `yaml:"level"`
	// Format is "console" (default) or "json".
	Format string `yaml:"format"`
}

// Config is the top-level instance configuration.
type Config struct {
	// Devices is the list of listener<->device pairs. At least one is
	// required (v1: unique listen addresses).
	Devices []Device `yaml:"devices"`

	// Log configures structured logging.
	Log LogConfig `yaml:"log"`

	// MetricsListenAddr, when set, serves Prometheus metrics on that
	// address (e.g. ":9202"). Empty = metrics endpoint disabled.
	MetricsListenAddr string `yaml:"metrics_listen"`
}

// Load reads, parses, and validates a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse parses and validates YAML configuration bytes.
func Parse(data []byte) (*Config, error) {
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Defaults fills unset fields with sane values.
func (c *Config) Defaults() {
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.Name == "" {
			d.Name = d.DeviceAddr
		}
		if d.MaxClients == 0 {
			d.MaxClients = 16
		}
		if d.TimeoutMs == 0 {
			d.TimeoutMs = 5000
		}
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "console"
	}
}

// Validate checks the configuration. Called by Load/Parse; safe to call
// again after mutating fields programmatically.
func (c *Config) Validate() error {
	if len(c.Devices) == 0 {
		return fmt.Errorf("config: at least one device entry is required")
	}
	seen := make(map[string]string, len(c.Devices))
	for i := range c.Devices {
		d := &c.Devices[i]
		label := d.Name
		if label == "" {
			label = fmt.Sprintf("devices[%d]", i)
		}
		if d.ListenAddr == "" {
			return fmt.Errorf("config: %s: listen_addr is required", label)
		}
		if d.DeviceAddr == "" {
			return fmt.Errorf("config: %s: device_addr is required", label)
		}
		if _, _, err := net.SplitHostPort(d.ListenAddr); err != nil {
			return fmt.Errorf("config: %s: bad listen_addr %q: %w", label, d.ListenAddr, err)
		}
		// B10: extra front-leg listeners — same uniqueness + syntax rules
		// as the primary listen_addr, and no collisions with other
		// devices' addresses either.
		for j, extra := range d.ExtraListen {
			if _, _, err := net.SplitHostPort(extra); err != nil {
				return fmt.Errorf("config: %s: bad extra_listen[%d] %q: %w", label, j, extra, err)
			}
			if prev, dup := seen[extra]; dup {
				return fmt.Errorf("config: %s: extra_listen[%d] %q already used by %s", label, j, extra, prev)
			}
			if extra == d.ListenAddr {
				return fmt.Errorf("config: %s: extra_listen[%d] %q duplicates listen_addr", label, j, extra)
			}
			seen[extra] = label
		}
		if _, _, err := net.SplitHostPort(d.DeviceAddr); err != nil {
			return fmt.Errorf("config: %s: bad device_addr %q: %w", label, d.DeviceAddr, err)
		}
		if prev, dup := seen[d.ListenAddr]; dup {
			return fmt.Errorf("config: %s: listen_addr %q already used by %s", label, d.ListenAddr, prev)
		}
		seen[d.ListenAddr] = label
		if d.MaxClients < 0 {
			return fmt.Errorf("config: %s: max_clients must be >= 0", label)
		}
		if d.RatePerSec < 0 {
			return fmt.Errorf("config: %s: rate_per_sec must be >= 0", label)
		}
		if d.TimeoutMs < 0 {
			return fmt.Errorf("config: %s: timeout_ms must be >= 0", label)
		}
		if d.RequestDelayMs < 0 {
			return fmt.Errorf("config: %s: request_delay_ms must be >= 0", label)
		}
		if d.IdleTimeoutMs < 0 {
			return fmt.Errorf("config: %s: idle_timeout_ms must be >= 0", label)
		}
		for j, cidr := range d.Allow {
			if !validIPorCIDR(cidr) {
				return fmt.Errorf("config: %s: allow[%d]: invalid IP or CIDR %q", label, j, cidr)
			}
		}
		if err := d.TLS.Validate(); err != nil {
			return fmt.Errorf("config: %s: %w", label, err)
		}
		if err := d.DeviceTLS.Validate(); err != nil {
			return fmt.Errorf("config: %s: %w", label, err)
		}
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log.level must be one of debug|info|warn|error (got %q)", c.Log.Level)
	}
	switch c.Log.Format {
	case "console", "json":
	default:
		return fmt.Errorf("config: log.format must be console or json (got %q)", c.Log.Format)
	}
	if c.MetricsListenAddr != "" {
		if _, _, err := net.SplitHostPort(c.MetricsListenAddr); err != nil {
			return fmt.Errorf("config: bad metrics_listen %q: %w", c.MetricsListenAddr, err)
		}
	}
	return nil
}

// RequestTimeout returns the per-request upstream deadline for a device.
func (d *Device) RequestTimeout() time.Duration {
	return time.Duration(d.TimeoutMs) * time.Millisecond
}

// RequestDelay returns the minimum gap between consecutive upstream
// requests (0 = unpaced).
func (d *Device) RequestDelay() time.Duration {
	return time.Duration(d.RequestDelayMs) * time.Millisecond
}

// HasIdleTimeout reports whether idle client connections are reaped
// (idle_timeout_ms > 0).
func (d *Device) HasIdleTimeout() bool { return d.IdleTimeoutMs > 0 }

// IdleTimeout returns the idle-client connection TTL (0 = disabled).
func (d *Device) IdleTimeout() time.Duration {
	return time.Duration(d.IdleTimeoutMs) * time.Millisecond
}

// HasUnitRemap reports whether a device-side unit ID override is set.
func (d *Device) HasUnitRemap() bool { return d.DeviceUnitID != nil }

// UpstreamUnitID returns the device-side unit ID override (call only when
// HasUnitRemap() is true).
func (d *Device) UpstreamUnitID() uint8 { return *d.DeviceUnitID }

// HasTLS reports whether front-leg TLS termination is configured.
func (d *Device) HasTLS() bool { return d.TLS != nil }

// HasClientCA reports whether mTLS (required client certificates) is
// configured for the front leg.
func (d *Device) HasClientCA() bool { return d.HasTLS() && d.TLS.ClientCA != "" }

// HasDeviceTLS reports whether the upstream (device-side) TLS leg is
// configured: the box dials the device over TLS (two-proxy secured line).
func (d *Device) HasDeviceTLS() bool { return d.DeviceTLS != nil }

// HasHealth reports whether the health-via-Modbus endpoint (B4) is
// enabled via health_unit_id.
func (d *Device) HasHealth() bool { return d.HealthUnitID != nil }

// HealthUnitIDValue returns the virtual health unit-ID (call only when
// HasHealth() is true).
func (d *Device) HealthUnitIDValue() uint8 { return *d.HealthUnitID }

// Validate checks a TLS configuration block: cert and key are
// both-or-neither, client_ca requires cert/key, and all configured files
// must be readable at validate time.
func (t *TLSConfig) Validate() error {
	if t == nil {
		return nil
	}
	if (t.Cert == "") != (t.Key == "") {
		return fmt.Errorf("tls: cert and key must be set together")
	}
	if t.ClientCA != "" && t.Cert == "" {
		return fmt.Errorf("tls: client_ca requires cert and key")
	}
	for _, f := range []string{t.Cert, t.Key, t.ClientCA} {
		if f == "" {
			continue
		}
		if _, err := os.ReadFile(f); err != nil {
			return fmt.Errorf("tls: %s: %w", f, err)
		}
	}
	return nil
}

// Validate checks a device TLS (upstream leg) configuration block:
// client cert and key are both-or-neither, and all configured files must
// be readable at validate time.
func (t *DeviceTLSConfig) Validate() error {
	if t == nil {
		return nil
	}
	if (t.Cert == "") != (t.Key == "") {
		return fmt.Errorf("device_tls: cert and key must be set together")
	}
	for _, f := range []string{t.CACert, t.Cert, t.Key} {
		if f == "" {
			continue
		}
		if _, err := os.ReadFile(f); err != nil {
			return fmt.Errorf("device_tls: %s: %w", f, err)
		}
	}
	return nil
}

// validIPorCIDR accepts a bare IP or a CIDR range.
func validIPorCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
