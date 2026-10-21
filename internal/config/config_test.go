package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidMultiDevice(t *testing.T) {
	path := writeTemp(t, `
devices:
  - name: temp-sensor
    listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    read_only: true
    allow: ["10.8.0.0/24", "192.168.1.7"]
    max_clients: 4
    rate_per_sec: 10
    timeout_ms: 2500
    device_unit_id: 17
  - listen_addr: ":5021"
    device_addr: "192.0.2.10:502"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Devices) != 2 {
		t.Fatalf("devices = %d, want 2", len(cfg.Devices))
	}
	d0 := cfg.Devices[0]
	if d0.Name != "temp-sensor" {
		t.Errorf("name = %q", d0.Name)
	}
	if !d0.ReadOnly {
		t.Errorf("read_only = false")
	}
	if d0.MaxClients != 4 {
		t.Errorf("max_clients = %d", d0.MaxClients)
	}
	if d0.RatePerSec != 10 {
		t.Errorf("rate_per_sec = %d", d0.RatePerSec)
	}
	if d0.TimeoutMs != 2500 {
		t.Errorf("timeout_ms = %d", d0.TimeoutMs)
	}
	if d0.RequestTimeout() != 2500*time.Millisecond {
		t.Errorf("request timeout = %v", d0.RequestTimeout())
	}
	if !d0.HasUnitRemap() || d0.UpstreamUnitID() != 17 {
		t.Errorf("unit remap = %v/%v", d0.HasUnitRemap(), d0.UpstreamUnitID())
	}
	if len(d0.Allow) != 2 || d0.Allow[0] != "10.8.0.0/24" {
		t.Errorf("allow = %v", d0.Allow)
	}

	// Defaults applied to the second device.
	d1 := &cfg.Devices[1]
	if d1.Name != "192.0.2.10:502" {
		t.Errorf("default name = %q, want device_addr", d1.Name)
	}
	if d1.MaxClients != 16 || d1.TimeoutMs != 5000 {
		t.Errorf("defaults not applied: %+v", d1)
	}
	if d1.HasUnitRemap() {
		t.Errorf("unexpected unit remap")
	}

	// Logging defaults.
	if cfg.Log.Level != "info" || cfg.Log.Format != "console" {
		t.Errorf("log defaults = %+v", cfg.Log)
	}
	if cfg.MetricsListenAddr != "" {
		t.Errorf("metrics_listen default = %q, want empty", cfg.MetricsListenAddr)
	}
}

func TestParseMinimal(t *testing.T) {
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Devices) != 1 {
		t.Fatalf("devices = %d", len(cfg.Devices))
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"no devices", "devices: []", "at least one device"},
		{"missing listen", `
devices:
  - device_addr: "10.0.0.1:502"
`, "listen_addr is required"},
		{"missing device", `
devices:
  - listen_addr: ":502"
`, "device_addr is required"},
		{"bad listen", `
devices:
  - listen_addr: "no-port"
    device_addr: "10.0.0.1:502"
`, "bad listen_addr"},
		{"bad device", `
devices:
  - listen_addr: ":502"
    device_addr: "not-an-addr"
`, "bad device_addr"},
		{"duplicate listen", `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
  - listen_addr: ":502"
    device_addr: "10.0.0.2:502"
`, "already used by"},
		{"negative max_clients", `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
    max_clients: -1
`, "max_clients"},
		{"negative rate", `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
    rate_per_sec: -5
`, "rate_per_sec"},
		{"negative timeout", `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
    timeout_ms: -1
`, "timeout_ms"},
		{"bad allow entry", `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
    allow: ["10.0.0.0/24", "not-a-cidr"]
`, "invalid IP or CIDR"},
		{"bad log level", `
log:
  level: chatty
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
`, "log.level"},
		{"bad log format", `
log:
  format: xml
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
`, "log.format"},
		{"bad metrics listen", `
metrics_listen: "no-port"
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
`, "bad metrics_listen"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("devices: [oops\n  broken"))
	if err == nil {
		t.Fatal("expected yaml error, got nil")
	}
}

func TestTLSConfigParsing(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "s.crt")
	key := filepath.Join(dir, "s.key")
	ca := filepath.Join(dir, "ca.crt")
	for _, f := range []string{cert, key, ca} {
		if err := os.WriteFile(f, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    tls:
      cert: "` + cert + `"
      key: "` + key + `"
      client_ca: "` + ca + `"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasTLS() {
		t.Fatal("HasTLS = false")
	}
	if d.TLS.Cert == "" || d.TLS.Key == "" || d.TLS.ClientCA == "" {
		t.Errorf("tls block = %+v", d.TLS)
	}
	if !d.HasClientCA() {
		t.Errorf("HasClientCA = false")
	}
}

func TestTLSValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		tls  string
		want string
	}{
		{"key without cert", `
    tls:
      key: "/tmp/server.key"
`, "cert and key must be set together"},
		{"cert without key", `
    tls:
      cert: "/tmp/server.crt"
`, "cert and key must be set together"},
		{"client_ca without cert", `
    tls:
      client_ca: "/tmp/ca.crt"
`, "client_ca requires cert and key"},
		{"missing cert file", `
    tls:
      cert: "/nonexistent/server.crt"
      key: "/tmp/server.key"
`, "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
` + tc.tls
			_, err := Parse([]byte(yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestTLSValidateValidFiles(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "s.crt")
	key := filepath.Join(dir, "s.key")
	ca := filepath.Join(dir, "ca.crt")
	for _, f := range []string{cert, key, ca} {
		if err := os.WriteFile(f, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := writeTemp(t, `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
    tls:
      cert: "`+cert+`"
      key: "`+key+`"
      client_ca: "`+ca+`"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load with readable files: %v", err)
	}
	if !cfg.Devices[0].HasClientCA() {
		t.Errorf("HasClientCA = false")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestValidIPorCIDRAcceptance(t *testing.T) {
	good := []string{"10.0.0.1", "10.0.0.0/24", "::1", "fe80::/10"}
	for _, s := range good {
		if !validIPorCIDR(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	bad := []string{"", "10.0.0.256", "10.0.0.0/33", "host-name"}
	for _, s := range bad {
		if validIPorCIDR(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestDeviceTLSParsing(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	cert := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")
	for _, f := range []string{ca, cert, key} {
		if err := os.WriteFile(f, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    device_tls:
      ca_cert: "` + ca + `"
      server_name: "farbox.example"
      cert: "` + cert + `"
      key: "` + key + `"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasDeviceTLS() {
		t.Fatal("HasDeviceTLS = false")
	}
	if d.DeviceTLS.CACert == "" || d.DeviceTLS.ServerName == "" || d.DeviceTLS.Cert == "" || d.DeviceTLS.Key == "" {
		t.Errorf("device_tls block = %+v", d.DeviceTLS)
	}
}

func TestDeviceTLSValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		tls  string
		want string
	}{
		{"cert without key", `
    device_tls:
      cert: "/tmp/c.pem"
`, "device_tls: cert and key must be set together"},
		{"key without cert", `
    device_tls:
      key: "/tmp/k.pem"
`, "device_tls: cert and key must be set together"},
		{"missing ca file", `
    device_tls:
      ca_cert: "/nonexistent/ca.pem"
`, "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
devices:
  - listen_addr: ":502"
    device_addr: "10.0.0.1:502"
` + tc.tls
			_, err := Parse([]byte(yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestHealthUnitIDParsing(t *testing.T) {
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    health_unit_id: 200
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasHealth() {
		t.Fatal("HasHealth = false")
	}
	if d.HealthUnitIDValue() != 200 {
		t.Fatalf("HealthUnitIDValue = %d, want 200", d.HealthUnitIDValue())
	}

	// Disabled when unset.
	cfg, err = Parse([]byte(`
devices:
  - listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Devices[0].HasHealth() {
		t.Fatal("HasHealth = true without health_unit_id")
	}
}

func TestShieldingDelayParsing(t *testing.T) {
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
    request_delay_ms: 25
    idle_timeout_ms: 60000
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasIdleTimeout() {
		t.Fatal("HasIdleTimeout = false, want true")
	}
	if got := d.IdleTimeout(); got != 60*time.Second {
		t.Fatalf("IdleTimeout = %v, want 60s", got)
	}
	if got := d.RequestDelay(); got != 25*time.Millisecond {
		t.Fatalf("RequestDelay = %v, want 25ms", got)
	}
	// Disabled variants.
	cfg2, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
`))
	if err != nil {
		t.Fatalf("parse minimal: %v", err)
	}
	d2 := cfg2.Devices[0]
	if d2.HasIdleTimeout() {
		t.Fatal("HasIdleTimeout = true for unset field")
	}
	if d2.IdleTimeout() != 0 || d2.RequestDelay() != 0 {
		t.Fatal("delay/timeout should default to 0 (disabled)")
	}
}

func TestShieldingDelayValidateErrors(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"negative delay", `
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
    request_delay_ms: -5
`, "request_delay_ms must be >= 0"},
		{"negative idle", `
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
    idle_timeout_ms: -1
`, "idle_timeout_ms must be >= 0"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(tc.yaml))
		if err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error %q, want substring %q", tc.name, err, tc.want)
		}
	}
}
