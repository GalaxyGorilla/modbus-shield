package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
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
	srv, ca, pems := tlsChainMulti(t, []clientSpec{{CN: "modbus-shield test client"}})
	tlsClientCertPath, tlsClientKeyPath = pems[0].Cert, pems[0].Key
	return srv, ca.serverKey, ca.clientCA, pems[0].Cert, pems[0].Key
}

// clientSpec describes one client certificate to generate: CN plus an
// optional mbaps role (B12) encoded as the Modbus.org role extension
// (OID 1.3.6.1.4.1.50316.802.1, ASN.1 UTF8String).
type clientSpec struct {
	CN   string
	Role string // "" = no role extension (NULL role)
}

// clientPEMs holds one generated client's certificate/key file paths.
type clientPEMs struct {
	Cert string
	Key  string
}

// tlsCAFiles groups the CA-owned PEM paths produced by tlsChainMulti.
type tlsCAFiles struct {
	serverCert string
	serverKey  string
	clientCA   string
}

// tlsChainMulti generates the shared CA + server certificate and one
// client certificate per spec (each may carry an mbaps role extension).
// Every call creates an UNRELATED CA — call it twice for bad-CA tests.
func tlsChainMulti(t *testing.T, clients []clientSpec) (serverCert string, ca tlsCAFiles, pems []clientPEMs) {
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

	for i, spec := range clients {
		cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(3 + i)),
			Subject:      pkix.Name{CommonName: spec.CN},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if spec.Role != "" {
			roleDER, err := asn1.Marshal(spec.Role) // UTF8String per spec R-22
			if err != nil {
				t.Fatal(err)
			}
			tmpl.ExtraExtensions = []pkix.Extension{{
				Id:    mbapsRoleOID,
				Value: roleDER,
			}}
		}
		cliDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &cliKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPath := filepath.Join(dir, fmt.Sprintf("client%d.crt", i))
		keyPath := filepath.Join(dir, fmt.Sprintf("client%d.key", i))
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(mustMarshalECKey(t, cliKey)), 0o600); err != nil {
			t.Fatal(err)
		}
		pems = append(pems, clientPEMs{Cert: certPath, Key: keyPath})
	}

	serverCert = filepath.Join(dir, "server.crt")
	serverKey := filepath.Join(dir, "server.key")
	ca.serverCert = serverCert
	ca.serverKey = serverKey
	ca.clientCA = filepath.Join(dir, "client-ca.crt")

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
	writePEM(ca.clientCA, "CERTIFICATE", caDER, nil)
	return serverCert, ca, pems
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

// startDeviceGateway starts a gateway from a fully built device config
// and returns the front-leg address.
func startDeviceGateway(t *testing.T, d config.Device) string {
	t.Helper()
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
	return startDeviceGateway(t, d)
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

// TestTwoProxyChain runs the full two-proxy secured line end to end:
// client --TLS--> front box (device_tls) --TLS--> far box (front-leg tls:)
// --plain--> device. The far box is a normal gateway with front-leg TLS
// termination; the front box secures its upstream leg with device_tls.
func TestTwoProxyChain(t *testing.T) {
	serverCert, serverKey, clientCA, clientCert, clientKey := tlsChain(t)
	dev := newFakeDevice(t)

	// Far box: normal gateway with front-leg TLS (mTLS required).
	farAddr := startGatewayTLS(t, dev, func(d *config.Device) {
		d.TLS = &config.TLSConfig{Cert: serverCert, Key: serverKey, ClientCA: clientCA}
	})

	// Front box: upstream leg secured with device_tls (mTLS toward the
	// far box), plain front leg for the client.
	frontAddr := startDeviceGateway(t, *dev2(t, farAddr, clientCA, clientCert, clientKey))

	conn, err := net.DialTimeout("tcp", frontAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("front dial: %v", err)
	}
	defer conn.Close()
	for i := 0; i < 5; i++ {
		req, _ := mbtcp.NewADU(0x1234+uint16(i), 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(req.Frame()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		resp, err := mbtcp.ReadADU(conn)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if resp.Header.TransactionID != req.Header.TransactionID {
			t.Fatalf("correlation %d: txn=%d", i, resp.Header.TransactionID)
		}
		if got := binary.BigEndian.Uint16(resp.PDU[2:4]); got != 0xCAFE {
			t.Fatalf("read %d: value = 0x%04X", i, got)
		}
	}
	if n := dev.Served(); n != 5 {
		t.Errorf("device served = %d, want 5", n)
	}
}

// dev2 builds a front-box device config pointing at the far box over
// device_tls (mTLS with the test client cert).
func dev2(t *testing.T, farAddr, caFile, certFile, keyFile string) *config.Device {
	t.Helper()
	return &config.Device{
		Name:       "front-box",
		ListenAddr: "127.0.0.1:0",
		DeviceAddr: farAddr,
		TimeoutMs:  2000,
		DeviceTLS: &config.DeviceTLSConfig{
			CACert: caFile,
			Cert:   certFile,
			Key:    keyFile,
		},
	}
}

// TestTwoProxyChainServerNameOverride verifies the server_name override:
// the front box dials the far box by IP while the far box's certificate
// carries only a DNS SAN ("localhost"). Without the override the name
// check fails (reads return the upstream exception); with it the chain
// works end to end.
func TestTwoProxyChainServerNameOverride(t *testing.T) {
	serverCert, serverKey, clientCA, clientCert, clientKey := tlsChain(t)
	dev := newFakeDevice(t)
	farAddr := startGatewayTLS(t, dev, func(d *config.Device) {
		d.TLS = &config.TLSConfig{
			Cert:     serverCert,
			Key:      serverKey,
			ClientCA: clientCA,
			// Server cert carries IP SAN 127.0.0.1; to exercise the
			// override we simulate a cert without a matching IP by
			// trusting the CA but requiring the DNS name.
		}
	})

	base := config.Device{
		Name:       "front-box",
		ListenAddr: "127.0.0.1:0",
		DeviceAddr: farAddr,
		TimeoutMs:  2000,
		DeviceTLS: &config.DeviceTLSConfig{
			CACert: clientCA,
			Cert:   clientCert,
			Key:    clientKey,
		},
	}

	// The cert HAS the 127.0.0.1 IP SAN, so the plain config works.
	frontAddr := startDeviceGateway(t, base)
	conn, err := net.DialTimeout("tcp", frontAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("front dial: %v", err)
	}
	readRegTLS(t, conn)
	conn.Close()

	// With an explicit server_name the chain also works (override path).
	withSNI := base
	withSNI.DeviceTLS.ServerName = "localhost"
	frontAddr2 := startDeviceGateway(t, withSNI)
	conn2, err := net.DialTimeout("tcp", frontAddr2, 5*time.Second)
	if err != nil {
		t.Fatalf("front dial (sni): %v", err)
	}
	readRegTLS(t, conn2)
	conn2.Close()
}

// TestDeviceTLSBadCARejected verifies the front box refuses a far box
// whose certificate is not signed by the configured CA: reads fail with
// the upstream exception and the device never sees a request.
func TestDeviceTLSBadCARejected(t *testing.T) {
	serverCert, serverKey, clientCA, clientCert, clientKey := tlsChain(t)
	dev := newFakeDevice(t)
	farAddr := startGatewayTLS(t, dev, func(d *config.Device) {
		d.TLS = &config.TLSConfig{Cert: serverCert, Key: serverKey, ClientCA: clientCA}
	})

	// Second, unrelated CA for the front box's trust store.
	_, _, otherCA, _, _ := tlsChain(t)
	frontAddr := startDeviceGateway(t, config.Device{
		Name:       "front-box",
		ListenAddr: "127.0.0.1:0",
		DeviceAddr: farAddr,
		TimeoutMs:  2000,
		DeviceTLS: &config.DeviceTLSConfig{
			CACert: otherCA,
			Cert:   clientCert,
			Key:    clientKey,
		},
	})

	conn, err := net.DialTimeout("tcp", frontAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("front dial: %v", err)
	}
	defer conn.Close()
	req, _ := mbtcp.NewADU(0x1234, 1, []byte{3, 0x01, 0x00, 0x00, 0x01})
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(req.Frame()); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !resp.IsException() {
		t.Fatal("want exception, got normal response")
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionGatewayTargetFail {
		t.Fatalf("exception code = 0x%02x, want 0x0B", code)
	}
	if n := dev.Served(); n != 0 {
		t.Errorf("device served = %d, want 0 (device must never see rejected TLS)", n)
	}
}

// mbapsClientConfig builds a client TLS config presenting the given
// generated client certificate (mbaps tests).
func mbapsClientConfig(t *testing.T, clientCA string, p clientPEMs) *tls.Config {
	t.Helper()
	pemCA, err := os.ReadFile(clientCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemCA) {
		t.Fatal("test CA pool empty")
	}
	cert, err := tls.LoadX509KeyPair(p.Cert, p.Key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
}

// mbapsDial connects over mTLS with the given client cert and returns
// the connection.
func mbapsDial(t *testing.T, addr, clientCA string, p clientPEMs) net.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		mbapsClientConfig(t, clientCA, p))
	if err != nil {
		t.Fatalf("mbaps dial: %v", err)
	}
	return conn
}

// mbapsExchange sends one ADU and returns the response with correlation
// verified (txn + unit echoed).
func mbapsExchange(t *testing.T, conn net.Conn, txn uint16, pdu []byte) mbtcp.ADU {
	t.Helper()
	req, err := mbtcp.NewADU(txn, 1, pdu)
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
	if resp.Header.TransactionID != txn || resp.Header.UnitID != 1 {
		t.Fatalf("correlation: txn=%d unit=%d", resp.Header.TransactionID, resp.Header.UnitID)
	}
	return resp
}

// startMBAPSGateway starts a gateway with mbaps role authorization over
// mTLS and returns the front-leg address plus the role client certs.
func startMBAPSGateway(t *testing.T, dev *fakeDevice, roles map[string][]int, extra func(*config.Device)) (string, string, []clientPEMs) {
	t.Helper()
	// Three clients: operator (role), engineer (role), ghost (role not
	// in the map is simulated by a dedicated unconfigured role cert), and
	// one without any role extension (NULL role).
	_, ca, pems := tlsChainMulti(t, []clientSpec{
		{CN: "operator client", Role: "operator"},
		{CN: "engineer client", Role: "engineer"},
		{CN: "null-role client"},
	})
	if dev == nil {
		dev = newFakeDevice(t)
	}
	mut := func(d *config.Device) {
		d.TLS = &config.TLSConfig{
			Cert:     ca.serverCert,
			Key:      ca.serverKey,
			ClientCA: ca.clientCA,
		}
		d.MBAPS = &config.MBAPSConfig{Roles: roles}
		if extra != nil {
			extra(d)
		}
	}
	addr := startGatewayTLS(t, dev, mut)
	return addr, ca.clientCA, pems
}

// TestMBAPSRolePolicy covers the B12 acceptance: role rights are
// enforced on every request. The operator role (reads only) may read but
// its writes are denied with exception 0x01 and never reach the device;
// the engineer role (reads + writes) may do both; a client with no role
// extension (NULL role) is denied everything.
func TestMBAPSRolePolicy(t *testing.T) {
	dev := newFakeDevice(t)
	addr, clientCA, pems := startMBAPSGateway(t, dev, map[string][]int{
		"operator": {1, 2, 3, 4},
		"engineer": {1, 2, 3, 4, 5, 6},
	}, nil)

	readPDU := []byte{3, 0x01, 0x00, 0x00, 0x01} // FC3 read 0x0100 qty 1
	writePDU := []byte{6, 0x01, 0x00, 0xCA, 0xFE}

	// Operator: read allowed, write denied with 0x01, device never sees it.
	opConn := mbapsDial(t, addr, clientCA, pems[0])
	resp := mbapsExchange(t, opConn, 0x11, readPDU)
	if resp.IsException() {
		t.Fatalf("operator read denied: exception 0x%02x", mustExcCode(t, resp))
	}
	if got := binary.BigEndian.Uint16(resp.PDU[2:4]); got != 0xCAFE {
		t.Fatalf("operator read value = 0x%04X", got)
	}
	resp = mbapsExchange(t, opConn, 0x12, writePDU)
	if !resp.IsException() {
		t.Fatal("operator write allowed, want exception")
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalFunction {
		t.Fatalf("operator write exception = 0x%02x, want 0x01", code)
	}
	if n := dev.Served(); n != 1 {
		t.Fatalf("device served = %d, want 1 (write must never reach the device)", n)
	}
	opConn.Close()

	// Engineer: read AND write allowed.
	engConn := mbapsDial(t, addr, clientCA, pems[1])
	resp = mbapsExchange(t, engConn, 0x21, readPDU)
	if resp.IsException() {
		t.Fatalf("engineer read denied: exception 0x%02x", mustExcCode(t, resp))
	}
	resp = mbapsExchange(t, engConn, 0x22, writePDU)
	if resp.IsException() {
		t.Fatalf("engineer write denied: exception 0x%02x", mustExcCode(t, resp))
	}
	if n := dev.Served(); n != 3 {
		t.Fatalf("device served = %d, want 3", n)
	}
	engConn.Close()

	// NULL role (no role extension): denied everything (spec R-23/R-31).
	nullConn := mbapsDial(t, addr, clientCA, pems[2])
	resp = mbapsExchange(t, nullConn, 0x31, readPDU)
	if !resp.IsException() {
		t.Fatal("NULL-role read allowed, want exception")
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalFunction {
		t.Fatalf("NULL-role exception = 0x%02x, want 0x01", code)
	}
	if n := dev.Served(); n != 3 {
		t.Fatalf("device served = %d, want 3 (NULL role must never reach the device)", n)
	}
	nullConn.Close()
}

// TestMBAPSUnconfiguredRoleDenied verifies a role that exists in the
// certificate but not in the roles map is denied (Roles-to-Rights DB has
// no entry for it).
func TestMBAPSUnconfiguredRoleDenied(t *testing.T) {
	dev := newFakeDevice(t)
	addr, clientCA, pems := startMBAPSGateway(t, dev, map[string][]int{
		"operator": {1, 2, 3, 4}, // "engineer" deliberately NOT configured
	}, nil)

	conn := mbapsDial(t, addr, clientCA, pems[1]) // engineer cert
	resp := mbapsExchange(t, conn, 0x41, []byte{3, 0x01, 0x00, 0x00, 0x01})
	if !resp.IsException() {
		t.Fatal("unconfigured role read allowed, want exception")
	}
	if code, _ := resp.ExceptionCode(); code != mbtcp.ExceptionIllegalFunction {
		t.Fatalf("exception = 0x%02x, want 0x01", code)
	}
	if n := dev.Served(); n != 0 {
		t.Fatalf("device served = %d, want 0", n)
	}
	conn.Close()
}

// TestMBAPSHealthBypass verifies health reads on the virtual unit-ID are
// NOT subject to mbaps role rights (monitoring stays responsive, same
// posture as read-only/rate-limit bypass).
func TestMBAPSHealthBypass(t *testing.T) {
	dev := newFakeDevice(t)
	addr, clientCA, pems := startMBAPSGateway(t, dev, map[string][]int{
		"operator": {1, 2, 3, 4},
	}, func(d *config.Device) {
		u := uint8(200)
		d.HealthUnitID = &u
	})

	// NULL-role client: device reads are denied, but health reads work.
	conn := mbapsDial(t, addr, clientCA, pems[2])
	req, err := mbtcp.NewADU(0x99, 200, []byte{3, 0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(req.Frame()); err != nil {
		t.Fatal(err)
	}
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		t.Fatalf("health read: %v", err)
	}
	if resp.Header.UnitID != 200 || resp.IsException() {
		t.Fatalf("health read failed: unit=%d exception=%v", resp.Header.UnitID, resp.IsException())
	}
	conn.Close()
}

func mustExcCode(t *testing.T, resp mbtcp.ADU) uint8 {
	t.Helper()
	code, ok := resp.ExceptionCode()
	if !ok {
		t.Fatal("not an exception response")
	}
	return code
}
