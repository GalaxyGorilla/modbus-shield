package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// tlsChain builds a throwaway ECDSA P-256 PKI in t.TempDir(): a self-signed
// CA, a server certificate with IP SAN 127.0.0.1 and DNS localhost, and a
// client certificate signed by the CA. Returns PEM file paths: server
// cert/key and client CA/client cert/client key.
func tlsChain(t *testing.T) (serverCert, serverKey, clientCA, clientCert, clientKey string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "modbus-shield test CA"},
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
	caCert, err := x509.ParseCertificate(caDER)
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
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "modbus-shield test client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	serverCert = filepath.Join(dir, "server.crt")
	serverKey = filepath.Join(dir, "server.key")
	clientCA = filepath.Join(dir, "client-ca.crt")
	clientCert = filepath.Join(dir, "client.crt")
	clientKey = filepath.Join(dir, "client.key")
	tlsClientCertPath, tlsClientKeyPath = clientCert, clientKey

	writePEM := func(path string, typ string, der []byte, key *ecdsa.PrivateKey) {
		t.Helper()
		var buf []byte
		buf = pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
		if key != nil {
			kb, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})...)
		}
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePEM(serverCert, "CERTIFICATE", srvDER, nil)
	if err := os.WriteFile(serverKey, pem.EncodeToMemory(mustMarshalECKey(t, srvKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	writePEM(clientCA, "CERTIFICATE", caDER, nil)
	writePEM(clientCert, "CERTIFICATE", cliDER, nil)
	if err := os.WriteFile(clientKey, pem.EncodeToMemory(mustMarshalECKey(t, cliKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	return serverCert, serverKey, clientCA, clientCert, clientKey
}

func mustMarshalECKey(t *testing.T, k *ecdsa.PrivateKey) *pem.Block {
	t.Helper()
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}
}

// tlsClientConfig builds a client-side TLS config trusting the test CA.
// withCert additionally presents the test client certificate (mTLS).
func tlsClientConfig(t *testing.T, clientCA string, withCert bool) *tls.Config {
	t.Helper()
	pemCA, err := os.ReadFile(clientCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemCA) {
		t.Fatal("test CA pool empty")
	}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost", // matches the server cert SAN
		MinVersion: tls.VersionTLS12,
	}
	if withCert {
		cert, err := tls.LoadX509KeyPair(certFile(t), keyFile(t))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

// certFile/keyFile are set by tlsChain via package vars so
// tlsClientConfig can load the client cert pair without threading five
// return values through every call site.
var (
	tlsClientCertPath string
	tlsClientKeyPath  string
)

func certFile(t *testing.T) string {
	t.Helper()
	if tlsClientCertPath == "" {
		t.Fatal("tlsChain not called before certFile")
	}
	return tlsClientCertPath
}

func keyFile(t *testing.T) string {
	t.Helper()
	if tlsClientKeyPath == "" {
		t.Fatal("tlsChain not called before keyFile")
	}
	return tlsClientKeyPath
}

func TestGatewayTLS(t *testing.T) {
	serverCert, serverKey, clientCA, _, _ := tlsChain(t)
	dev := newFakeDevice(t)
	gw := startGatewayTLS(t, dev, func(d *config.Device) {
		d.TLS = &config.TLSConfig{Cert: serverCert, Key: serverKey}
	})

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", gw,
		tlsClientConfig(t, clientCA, false))
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	for i := 0; i < 5; i++ {
		resp := readRegTLS(t, conn)
		if got := binary.BigEndian.Uint16(resp.PDU[2:4]); got != 0xCAFE {
			t.Fatalf("read %d: value = 0x%04X", i, got)
		}
	}
	if n := dev.Served(); n != 5 {
		t.Errorf("device served = %d, want 5", n)
	}
}

func TestGatewayMTLS(t *testing.T) {
	serverCert, serverKey, clientCA, _, _ := tlsChain(t)
	dev := newFakeDevice(t)
	gw := startGatewayTLS(t, dev, func(d *config.Device) {
		d.TLS = &config.TLSConfig{Cert: serverCert, Key: serverKey, ClientCA: clientCA}
	})

	// Without a client certificate the handshake must fail. Under TLS
	// 1.3 the client's dial may return before the server's rejection
	// arrives, so the failure surfaces on first use.
	noCert, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", gw,
		tlsClientConfig(t, clientCA, false))
	if err == nil {
		// Force the alert: any read after the handshake must fail.
		req, _ := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
		_, werr := noCert.Write(req.Frame())
		_ = noCert.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, rerr := mbtcp.ReadADU(noCert)
		noCert.Close()
		if werr == nil && rerr == nil {
			t.Fatal("exchange without client cert succeeded, want failure")
		}
	}

	// With the signed client certificate it must work end to end.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", gw,
		tlsClientConfig(t, clientCA, true))
	if err != nil {
		t.Fatalf("tls dial with client cert: %v", err)
	}
	defer conn.Close()
	resp := readRegTLS(t, conn)
	if got := binary.BigEndian.Uint16(resp.PDU[2:4]); got != 0xCAFE {
		t.Fatalf("value = 0x%04X, want 0xCAFE", got)
	}
}

func TestGatewayTLSPlainClientFails(t *testing.T) {
	serverCert, serverKey, clientCA, _, _ := tlsChain(t)
	dev := newFakeDevice(t)
	gw := startGatewayTLS(t, dev, func(d *config.Device) {
		d.TLS = &config.TLSConfig{Cert: serverCert, Key: serverKey}
	})

	// A plain (non-TLS) client against the TLS listener: the lazy
	// handshake fails in the handler goroutine, the listener never dies.
	plain, err := net.DialTimeout("tcp", gw, 5*time.Second)
	if err != nil {
		t.Fatalf("plain dial: %v", err)
	}
	plain.Close()

	// The chain stays alive for proper TLS clients afterwards.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", gw,
		tlsClientConfig(t, clientCA, false))
	if err != nil {
		t.Fatalf("tls dial after plain client: %v", err)
	}
	defer conn.Close()
	readRegTLS(t, conn)
}

// startGatewayTLS starts a gateway with a TLS device config and returns
// the front-leg address.
func startGatewayTLS(t *testing.T, dev *fakeDevice, mutate func(*config.Device)) string {
	t.Helper()
	d := config.Device{
		Name:       "tls-dev",
		ListenAddr: "127.0.0.1:0",
		DeviceAddr: dev.Addr(),
		TimeoutMs:  2000,
	}
	if mutate != nil {
		mutate(&d)
	}
	cfg := &config.Config{Devices: []config.Device{d}}
	cfg.Defaults()
	r, err := NewRunner(cfg, nopLogger{}, nil)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	t.Cleanup(r.Stop)
	go func() { _ = r.Run() }()
	<-r.bound
	return r.lns[0].Addr().String()
}

// readRegTLS sends FC3 read of register 0x0100 over the TLS connection
// and returns the verified response ADU (txn 0x1234, unit 1).
func readRegTLS(t *testing.T, conn net.Conn) mbtcp.ADU {
	t.Helper()
	req, err := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(req.Frame()); err != nil {
		t.Fatal(err)
	}
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Header.TransactionID != 0x1234 || resp.Header.UnitID != 1 {
		t.Fatalf("correlation: txn=%d unit=%d", resp.Header.TransactionID, resp.Header.UnitID)
	}
	if resp.IsException() {
		code, _ := resp.ExceptionCode()
		t.Fatalf("unexpected exception 0x%02x", code)
	}
	return resp
}
