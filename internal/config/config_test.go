package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
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

// tlsChainFiles builds a minimal throwaway ECDSA P-256 PKI for config
// tests that reference certificate files (B12 validation tests): a
// self-signed CA, a server cert with IP SAN 127.0.0.1, and a client
// cert. Config validation only checks file readability, so no TLS
// handshake is exercised here (the proxy package covers that e2e).
func tlsChainFiles(t *testing.T) (serverCert, serverKey, clientCA, clientCert, clientKey string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "config test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, mustParseCert(t, caDER), &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "config test client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, mustParseCert(t, caDER), &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverKey = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	clientCA = filepath.Join(dir, "client-ca.crt")
	clientCert, clientKey = filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	writeFile := func(path string, typ string, der []byte) {
		t.Helper()
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(serverCert, "CERTIFICATE", srvDER)
	writeFile(serverKey, "EC PRIVATE KEY", mustMarshalECKey(t, srvKey))
	writeFile(clientCA, "CERTIFICATE", caDER)
	writeFile(clientCert, "CERTIFICATE", cliDER)
	writeFile(clientKey, "EC PRIVATE KEY", mustMarshalECKey(t, cliKey))
	return serverCert, serverKey, clientCA, clientCert, clientKey
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustMarshalECKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
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

func TestReadCacheTTParsing(t *testing.T) {
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
    read_cache_ttl_ms: 1500
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasReadCache() {
		t.Fatal("HasReadCache = false, want true")
	}
	if got := d.ReadCacheTTL(); got != 1500*time.Millisecond {
		t.Fatalf("ReadCacheTTL = %v, want 1.5s", got)
	}
	// Disabled variant.
	cfg2, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
`))
	if err != nil {
		t.Fatalf("parse minimal: %v", err)
	}
	d2 := cfg2.Devices[0]
	if d2.HasReadCache() || d2.ReadCacheTTL() != 0 {
		t.Fatal("read cache should default to disabled")
	}
	// Negative is rejected.
	if _, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
    read_cache_ttl_ms: -1
`)); err == nil || !contains(err.Error(), "read_cache_ttl_ms must be >= 0") {
		t.Fatalf("negative ttl: err = %v", err)
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

// TestExtraListenParsing covers the B10 YAML block: extra front-leg
// listeners parse into ExtraListen and Validate accepts a consistent
// multi-door setup.
func TestExtraListenParsing(t *testing.T) {
	path := writeTemp(t, `
devices:
  - name: legacy-plc
    listen_addr: ":5020"
    extra_listen: [":5021", "127.0.0.2:5020"]
    device_addr: "10.0.0.42:502"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := cfg.Devices[0]
	if len(d.ExtraListen) != 2 || d.ExtraListen[0] != ":5021" || d.ExtraListen[1] != "127.0.0.2:5020" {
		t.Fatalf("extra_listen = %v", d.ExtraListen)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestMBAPSParsing covers the B12 YAML block: role-to-FC mapping parses
// and the accessors resolve rights.
func TestMBAPSParsing(t *testing.T) {
	serverCert, serverKey, clientCA, _, _ := tlsChainFiles(t)
	path := writeTemp(t, fmt.Sprintf(`
devices:
  - name: secure-plc
    listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    tls:
      cert: %s
      key: %s
      client_ca: %s
    mbaps:
      roles:
        operator: [1, 2, 3, 4]
        engineer: [1, 2, 3, 4, 5, 6, 15, 16]
`, serverCert, serverKey, clientCA))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasMBAPS() {
		t.Fatal("HasMBAPS() = false, want true")
	}
	if codes, ok := d.MBAPSRoleRights("operator"); !ok || len(codes) != 4 || codes[0] != 1 {
		t.Fatalf("operator rights = %v, ok=%v", codes, ok)
	}
	if codes, ok := d.MBAPSRoleRights("engineer"); !ok || len(codes) != 8 {
		t.Fatalf("engineer rights = %v, ok=%v", codes, ok)
	}
	if _, ok := d.MBAPSRoleRights("ghost"); ok {
		t.Fatal("ghost role should have no rights")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestMBAPSValidateErrors covers the B12 config validation: mTLS is
// mandatory (mbaps without tls/client_ca), roles must exist and carry
// valid function codes.
func TestMBAPSValidateErrors(t *testing.T) {
	serverCert, serverKey, clientCA, _, _ := tlsChainFiles(t)
	cases := []struct {
		name string
		tls  string
		mb   string
		want string
	}{
		{
			name: "no tls at all",
			tls:  "",
			mb:   "    mbaps:\n      roles:\n        operator: [1, 2, 3]\n",
			want: "mbaps requires tls with client_ca",
		},
		{
			name: "tls without client_ca",
			tls:  fmt.Sprintf("    tls:\n      cert: %s\n      key: %s\n", serverCert, serverKey),
			mb:   "    mbaps:\n      roles:\n        operator: [1, 2, 3]\n",
			want: "mbaps requires tls with client_ca",
		},
		{
			name: "empty roles map",
			tls:  fmt.Sprintf("    tls:\n      cert: %s\n      key: %s\n      client_ca: %s\n", serverCert, serverKey, clientCA),
			mb:   "    mbaps: {}\n",
			want: "at least one role must be defined",
		},
		{
			name: "role without codes",
			tls:  fmt.Sprintf("    tls:\n      cert: %s\n      key: %s\n      client_ca: %s\n", serverCert, serverKey, clientCA),
			mb:   "    mbaps:\n      roles:\n        operator: []\n",
			want: "at least one function code",
		},
		{
			name: "invalid function code",
			tls:  fmt.Sprintf("    tls:\n      cert: %s\n      key: %s\n      client_ca: %s\n", serverCert, serverKey, clientCA),
			mb:   "    mbaps:\n      roles:\n        operator: [0]\n",
			want: "invalid function code 0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, fmt.Sprintf(`
devices:
  - name: secure-plc
    listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
%s%s`, tc.tls, tc.mb))
			_, err := Load(path)
			if err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: error %q, want substring %q", tc.name, err, tc.want)
			}
		})
	}
}

// TestTransparentParsing checks the B3 transparent config flag: parse,
// accessor, and that device_addr stays required (label only).
func TestTransparentParsing(t *testing.T) {
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "legacy-plc:502"
    transparent: true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasTransparent() {
		t.Fatal("HasTransparent = false, want true")
	}
	// device_addr still required when transparent is set.
	_, err = Parse([]byte(`
devices:
  - listen_addr: ":502"
    transparent: true
`))
	if err == nil {
		t.Fatal("transparent without device_addr: want error, got nil")
	}
}

func TestPerClientRateAndLenientCorrelation(t *testing.T) {
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
    rate_per_sec: 50
    rate_per_client_per_sec: 5
    lenient_correlation: true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if d.RatePerSec != 50 || d.RatePerClientPerSec != 5 {
		t.Fatalf("rates = %d/%d, want 50/5", d.RatePerSec, d.RatePerClientPerSec)
	}
	if !d.HasLenientCorrelation() {
		t.Fatal("HasLenientCorrelation = false, want true")
	}

	// Defaults: no per-client cap, strict correlation.
	cfg2, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
`))
	if err != nil {
		t.Fatalf("parse minimal: %v", err)
	}
	d2 := cfg2.Devices[0]
	if d2.RatePerClientPerSec != 0 {
		t.Fatalf("RatePerClientPerSec = %d, want 0 (unlimited)", d2.RatePerClientPerSec)
	}
	if d2.HasLenientCorrelation() {
		t.Fatal("HasLenientCorrelation = true by default, want strict")
	}
}

func TestPerClientRateValidateErrors(t *testing.T) {
	cfg, err := Parse([]byte(`
devices:
  - listen_addr: ":502"
    device_addr: "10.1.1.1:502"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg.Devices[0].RatePerClientPerSec = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative rate_per_client_per_sec: want error, got nil")
	}
}

// TestWritePolicyParsing covers the address-scoped write policy schema:
// deny-list and allow-list modes, optional unit/FC/range fields.
func TestWritePolicyParsing(t *testing.T) {
	path := writeTemp(t, `
devices:
  - name: plc
    listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    write_policy:
      default: deny
      rules:
        - fc: [6, 16]
          from: 0
          to: 99
          action: allow
        - unit: 2
          fc: [6]
          from: 100
          to: 199
          action: deny
        - fc: [21]
          action: allow
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasWritePolicy() {
		t.Fatal("HasWritePolicy() = false, want true")
	}
	if d.WritePolicyDefaultAllow() {
		t.Fatal("WritePolicyDefaultAllow() = true, want false")
	}
	rules := d.WritePolicy.Rules
	if len(rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(rules))
	}
	if rules[0].Unit != nil || len(rules[0].FC) != 2 || *rules[0].To != 99 {
		t.Fatalf("rule 0 = %+v", rules[0])
	}
	if rules[1].Unit == nil || *rules[1].Unit != 2 || rules[1].Action != "deny" {
		t.Fatalf("rule 1 = %+v", rules[1])
	}
	if rules[2].From != nil {
		t.Fatal("rule 2 (address-agnostic FC21 rule) has a range")
	}

	// Deny-list mode: default allow, no rules required.
	path = writeTemp(t, `
devices:
  - listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    write_policy:
      default: allow
      rules:
        - fc: [6]
          from: 8000
          to: 8999
          action: deny
`)
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("load deny-list: %v", err)
	}
	if !cfg.Devices[0].WritePolicyDefaultAllow() {
		t.Fatal("deny-list policy default = deny, want allow")
	}
}

// TestWritePolicyValidateErrors covers the schema rules: read_only and
// write_policy are exclusive, defaults/actions are allow|deny, FCs must be
// write FCs, ranges must be complete and ordered, and an empty default-deny
// policy is a config error.
func TestWritePolicyValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		dev  Device
	}{
		{"read_only + write policy", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502", ReadOnly: true,
			WritePolicy: &WritePolicyConfig{Default: "allow"},
		}},
		{"empty default-deny policy", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502",
			WritePolicy: &WritePolicyConfig{Default: "deny"},
		}},
		{"bad default", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502",
			WritePolicy: &WritePolicyConfig{Default: "maybe"},
		}},
		{"bad action", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502",
			WritePolicy: &WritePolicyConfig{Default: "allow", Rules: []WriteRule{{Action: "block"}}},
		}},
		{"read function code", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502",
			WritePolicy: &WritePolicyConfig{Default: "deny", Rules: []WriteRule{{FC: []int{3}, Action: "allow"}}},
		}},
		{"half range", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502",
			WritePolicy: &WritePolicyConfig{Default: "deny", Rules: []WriteRule{{To: intPtr(9), Action: "allow"}}},
		}},
		{"inverted range", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502",
			WritePolicy: &WritePolicyConfig{Default: "deny", Rules: []WriteRule{{
				From: intPtr(20), To: intPtr(10), Action: "allow",
			}}},
		}},
		{"address out of range", Device{
			ListenAddr: ":5020", DeviceAddr: "10.0.0.42:502",
			WritePolicy: &WritePolicyConfig{Default: "deny", Rules: []WriteRule{{
				From: intPtr(0), To: intPtr(70000), Action: "allow",
			}}},
		}},
	}
	for _, tc := range cases {
		cfg := &Config{Devices: []Device{tc.dev}}
		cfg.Defaults()
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s: expected error, got nil", tc.name)
		}
	}
}

func intPtr(n int) *int { return &n }
