// cmd smoke tests: verify flag-built configs validate, flag-vs-YAML
// equivalence holds, and the CLI dispatch works (package main).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
	"github.com/spf13/pflag"
)

// newFlags builds a cliFlags with default flag storage, then applies
// mutate. Values are set through the flag pointers, exactly as pflag
// Parse would.
func newFlags(mutate func(c cliFlags)) cliFlags {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	c := register(fs)
	if mutate != nil {
		mutate(c)
	}
	return c
}

func validFlags() cliFlags {
	return newFlags(func(c cliFlags) {
		*c.listen = "127.0.0.1:5020"
		*c.device = "127.0.0.1:502"
	})
}

func TestFlagsConfig(t *testing.T) {
	cfg, err := flagsConfig(validFlags())
	if err != nil {
		t.Fatalf("flagsConfig: %v", err)
	}
	if len(cfg.Devices) != 1 {
		t.Fatalf("devices = %d", len(cfg.Devices))
	}
	d := cfg.Devices[0]
	if d.ListenAddr != "127.0.0.1:5020" || d.DeviceAddr != "127.0.0.1:502" {
		t.Fatalf("device = %+v", d)
	}
	if d.MaxClients != 16 || d.TimeoutMs != 5000 {
		t.Fatalf("defaults not applied: %+v", d)
	}
}

func TestFlagsConfigReadOnlyAndUnitRemap(t *testing.T) {
	c := validFlags()
	*c.readOnly = true
	*c.deviceUnitID = "17"
	cfg, err := flagsConfig(c)
	if err != nil {
		t.Fatalf("flagsConfig: %v", err)
	}
	d := cfg.Devices[0]
	if !d.ReadOnly {
		t.Fatal("read_only not applied")
	}
	if !d.HasUnitRemap() || d.UpstreamUnitID() != 17 {
		t.Fatalf("unit remap not applied: %v", d.DeviceUnitID)
	}
}

func TestFlagsConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(c cliFlags)
	}{
		{"no listen", func(c cliFlags) { *c.listen = "" }},
		{"no device", func(c cliFlags) { *c.device = "" }},
		{"unit id too big", func(c cliFlags) { *c.deviceUnitID = "999" }},
		{"unit id not a number", func(c cliFlags) { *c.deviceUnitID = "abc" }},
	}
	for _, tc := range cases {
		if _, err := flagsConfig(newFlags(func(c cliFlags) {
			*c.listen = "127.0.0.1:5020"
			*c.device = "127.0.0.1:502"
			tc.mut(c)
		})); err == nil {
			t.Fatalf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestLoadCheckedFromYAML(t *testing.T) {
	yaml := `devices:
  - listen_addr: 127.0.0.1:5020
    device_addr: 127.0.0.1:502
`
	path := filepath.Join(t.TempDir(), "gw.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	c := validFlags()
	*c.configPath = path
	cfg, err := loadChecked(c)
	if err != nil {
		t.Fatalf("loadChecked: %v", err)
	}
	if len(cfg.Devices) != 1 || cfg.Devices[0].DeviceAddr != "127.0.0.1:502" {
		t.Fatalf("yaml config = %+v", cfg.Devices)
	}
}

func TestSelftestProbeAgainstFakeDevice(t *testing.T) {
	// A fake device that answers FC3 reads on register 0.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveProbeClient(conn)
		}
	}()

	c := validFlags()
	*c.device = ln.Addr().String()
	cfg, err := loadChecked(c)
	if err != nil {
		t.Fatalf("loadChecked: %v", err)
	}
	ch := probeDevice(context.Background(), cfg.Devices[0])
	if !ch.OK {
		t.Fatalf("probeDevice failed: %s", ch.Detail)
	}
	if !strings.Contains(ch.Detail, "read ok") {
		t.Fatalf("unexpected detail: %s", ch.Detail)
	}
}

// serveProbeClient answers exactly one FC3 read of register 0, then
// closes.
func serveProbeClient(conn net.Conn) {
	defer conn.Close()
	adu, err := mbtcp.ReadADU(conn)
	if err != nil {
		return
	}
	// Answer reads of register 0; anything else gets exception 0x02.
	var pdu []byte
	if adu.FunctionCode() == 3 && adu.PDU[1] == 0 && adu.PDU[2] == 0 && adu.PDU[3] == 0 && adu.PDU[4] == 1 {
		pdu = []byte{3, 2, 0xCA, 0xFE}
	} else {
		pdu = mbtcp.ExceptionPDU(adu.FunctionCode(), 2)
	}
	resp, err := mbtcp.NewADU(adu.Header.TransactionID, adu.Header.UnitID, pdu)
	if err != nil {
		return
	}
	_, _ = conn.Write(resp.Frame())
}

func TestSelftestProbeRefused(t *testing.T) {
	// A listener that immediately closes connections models a dead
	// or refusing device.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	c := validFlags()
	*c.device = ln.Addr().String()
	cfg, err := loadChecked(c)
	if err != nil {
		t.Fatalf("loadChecked: %v", err)
	}
	ch := probeDevice(context.Background(), cfg.Devices[0])
	if ch.OK {
		t.Fatalf("probeDevice unexpectedly succeeded: %s", ch.Detail)
	}
}

func TestValidateSelftestInvalidConfig(t *testing.T) {
	// validate with no listen/device must fail cleanly (exit path 1).
	c := newFlags(func(c cliFlags) { *c.listen = ""; *c.device = "" })
	rep := report{}
	cfg, err := loadChecked(c)
	if err == nil {
		t.Fatalf("loadChecked unexpectedly succeeded: %+v", cfg)
	}
	rep.Error = err.Error()
	rep.OK = rep.Error == ""
	if rep.OK {
		t.Fatal("report should not be ok")
	}
}

func TestRunOsArgs(t *testing.T) {
	for _, args := range [][]string{{"modbus-shield", "version"}, {"modbus-shield", "--version"}, {"modbus-shield", "-v"}} {
		if rc := swapArgs(t, args, run); rc != 0 {
			t.Fatalf("run(%v) = %d, want 0", args, rc)
		}
	}
	for _, args := range [][]string{{"modbus-shield", "help"}, {"modbus-shield", "--help"}, {"modbus-shield", "-h"}} {
		if rc := swapArgs(t, args, run); rc != 0 {
			t.Fatalf("run(%v) = %d, want 0", args, rc)
		}
	}
	if rc := swapArgs(t, []string{"modbus-shield", "genpsk"}, run); rc != 0 {
		t.Fatalf("run(genpsk) = %d, want 0", rc)
	}
	if rc := swapArgs(t, []string{"modbus-shield", "bogus"}, run); rc != 2 {
		t.Fatalf("run(bogus) = %d, want 2", rc)
	}
	if rc := swapArgs(t, []string{"modbus-shield"}, run); rc != 2 {
		t.Fatalf("run(no args) = %d, want 2", rc)
	}
}

func swapArgs(t *testing.T, args []string, f func() int) int {
	t.Helper()
	old := os.Args
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Args = args
	os.Stdout = w
	os.Stderr = w
	defer func() {
		os.Args = old
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		_ = w.Close()
		_ = r.Close()
	}()
	return f()
}

func TestUsage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	usage(os.Stdout)
	_ = w.Close()
	os.Stdout = oldStdout
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	_ = r.Close()
	if !strings.Contains(string(buf[:n]), "modbus-shield") {
		t.Fatalf("usage output missing program name")
	}
}

// TestParseMBAPSRoleSpec covers the --mbaps-role entry parser (B12).
func TestParseMBAPSRoleSpec(t *testing.T) {
	role, codes, err := parseMBAPSRoleSpec("operator=1,2,3,4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if role != "operator" || len(codes) != 4 || codes[0] != 1 || codes[3] != 4 {
		t.Fatalf("role=%q codes=%v", role, codes)
	}
	if _, _, err := parseMBAPSRoleSpec("operator"); err == nil {
		t.Fatal("missing = should fail")
	}
	if _, _, err := parseMBAPSRoleSpec("=1,2"); err == nil {
		t.Fatal("empty role should fail")
	}
	if _, _, err := parseMBAPSRoleSpec("operator="); err == nil {
		t.Fatal("empty codes should fail")
	}
	if _, _, err := parseMBAPSRoleSpec("operator=1,abc"); err == nil {
		t.Fatal("bad code should fail")
	}
}

// TestFlagsConfigMBAPS wires --mbaps-role through flagsConfig (B12).
func TestFlagsConfigMBAPS(t *testing.T) {
	serverCert, serverKey, clientCA, _, _ := tlsChainFilesCmd(t)
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	c := register(fs)
	fs.Set("listen", "127.0.0.1:5020")
	fs.Set("device", "127.0.0.1:502")
	fs.Set("tls-cert", serverCert)
	fs.Set("tls-key", serverKey)
	fs.Set("tls-client-ca", clientCA)
	if err := fs.Parse([]string{"--mbaps-role", "operator=1,2,3,4"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	cfg, err := flagsConfig(c)
	if err != nil {
		t.Fatalf("flagsConfig: %v", err)
	}
	d := cfg.Devices[0]
	if !d.HasMBAPS() {
		t.Fatal("HasMBAPS() = false, want true")
	}
	if codes, ok := d.MBAPSRoleRights("operator"); !ok || len(codes) != 4 {
		t.Fatalf("operator rights = %v ok=%v", codes, ok)
	}
}

// tlsChainFilesCmd mirrors the config-package PKI helper: a throwaway
// ECDSA P-256 CA + server cert (IP SAN) + client cert for flag tests
// that only need readable PEM files (validation-level checks).
func tlsChainFilesCmd(t *testing.T) (serverCert, serverKey, clientCA, clientCert, clientKey string) {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cmd test CA"},
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
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, mustParseCmdCert(t, caDER), &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "cmd test client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, mustParseCmdCert(t, caDER), &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	clientCA, clientCert, clientKey = filepath.Join(dir, "ca.crt"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	w := func(path, typ string, der []byte) {
		t.Helper()
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w(serverCert, "CERTIFICATE", srvDER)
	w(serverKey, "EC PRIVATE KEY", mustCmdECKey(t, srvKey))
	w(clientCA, "CERTIFICATE", caDER)
	w(clientCert, "CERTIFICATE", cliDER)
	w(clientKey, "EC PRIVATE KEY", mustCmdECKey(t, cliKey))
	return serverCert, serverKey, clientCA, clientCert, clientKey
}

func mustParseCmdCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustCmdECKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestFlagsConfigShieldingKeys(t *testing.T) {
	c := validFlags()
	*c.ratePerClient = 5
	*c.lenientCorr = true
	cfg, err := flagsConfig(c)
	if err != nil {
		t.Fatalf("flagsConfig: %v", err)
	}
	d := cfg.Devices[0]
	if d.RatePerClientPerSec != 5 {
		t.Fatalf("RatePerClientPerSec = %d, want 5", d.RatePerClientPerSec)
	}
	if !d.HasLenientCorrelation() {
		t.Fatal("LenientCorrelation not applied from --lenient-correlation")
	}
}
