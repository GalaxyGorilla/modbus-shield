package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/acl"
	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// gateway is one listener<->device pair: it accepts front-leg clients,
// enforces the IP allow-list and shielding limits (connection cap,
// read-only policy), and multiplexes all client traffic over the single
// upstream device connection.
type gateway struct {
	dev config.Device
	up  *upstream
	log Logger

	// allow is the parsed client IP allow-list; nil = any client.
	allow *acl.List

	// maxClients caps concurrent front-leg connections (shielding).
	maxClients int64
	clients    atomic.Int64

	// lim enforces rate_per_sec on the front leg (shielding); nil when
	// rate_per_sec is 0 (unlimited).
	lim *rateLimiter

	// tlsCfg terminates TLS on the front leg when set (nil = plain TCP).
	tlsCfg *tls.Config

	// met is the observability hook; never nil (normalized to a no-op).
	met Metrics

	// health exposes the box's state as readable registers on a virtual
	// unit-ID (B4); nil when disabled.
	health *healthRegistry

	// healthUnitID is the virtual unit-ID health requests are addressed
	// to (only meaningful when health != nil).
	healthUnitID uint8

	// connSeq hands out per-gateway connection IDs (B9) so client-side
	// and device-side log lines correlate on one ID.
	connSeq atomic.Uint64

	// mbaps maps role names (from client certificates' mbaps role
	// extension) to their allowed function codes (B12); nil when the
	// mbaps mode is disabled.
	mbaps map[string]map[uint8]bool

	// cache serves repeated read responses from memory (B8, opt-in via
	// read_cache_ttl_ms); nil when disabled.
	cache *readCache
}

func newGateway(dev config.Device, log Logger, met Metrics) (*gateway, error) {
	allow, err := acl.NewList(dev.Allow)
	if err != nil {
		return nil, fmt.Errorf("device %s: %w", dev.Name, err)
	}
	var tlsCfg *tls.Config
	if dev.HasTLS() {
		tlsCfg, err = tlsConfigFor(dev)
		if err != nil {
			return nil, fmt.Errorf("device %s: %w", dev.Name, err)
		}
	}
	var devTLS *tls.Config
	if dev.HasDeviceTLS() {
		devTLS, err = deviceTLSConfigFor(dev)
		if err != nil {
			return nil, fmt.Errorf("device %s: %w", dev.Name, err)
		}
	}
	var health *healthRegistry
	var healthUnitID uint8
	if dev.HasHealth() {
		health = newHealthRegistry()
		healthUnitID = dev.HealthUnitIDValue()
	}
	var mbaps map[string]map[uint8]bool
	if dev.HasMBAPS() {
		mbaps = make(map[string]map[uint8]bool, len(dev.MBAPS.Roles))
		for role, codes := range dev.MBAPS.Roles {
			set := make(map[uint8]bool, len(codes))
			for _, fc := range codes {
				set[uint8(fc)] = true
			}
			mbaps[role] = set
		}
	}
	up := newUpstream(dev.DeviceAddr, dev.Name, log, met)
	up.tlsDial = devTLS
	up.requestDelay = dev.RequestDelay()
	up.rtuOverTCP = dev.HasRTUOverTCP()
	up.setUpstreamHealth(health)
	if dev.HasTransparent() {
		// B3: the upstream target is the client's original destination
		// from conntrack, resolved per front-leg connection.
		up.origDST = originalDST
	}
	g := &gateway{
		dev:          dev,
		up:           up,
		log:          log,
		allow:        allow,
		maxClients:   int64(dev.MaxClients),
		cache:        newReadCache(dev.ReadCacheTTL()),
		lim:          newRateLimiter(dev.RatePerSec),
		tlsCfg:       tlsCfg,
		met:          metricsOrNop(met),
		health:       health,
		healthUnitID: healthUnitID,
		mbaps:        mbaps,
	}
	up.connSeq = &g.connSeq
	return g, nil
}

// Serve runs the accept loop on ln until it is closed. Client-side errors
// never kill the loop: a misbehaving client costs its connection only.
// When front-leg TLS is configured, ln is wrapped and the TLS handshake
// happens lazily in the handler goroutine (never in the accept loop —
// a hanging or slow handshake must not block new connections).
func (g *gateway) Serve(ln net.Listener) error {
	if g.tlsCfg != nil {
		ln = tls.NewListener(ln, g.tlsCfg)
	}
	g.log.Infof("gateway %s: listening on %s -> %s (read_only=%v max_clients=%d tls=%v)",
		g.dev.Name, ln.Addr(), g.dev.DeviceAddr, g.dev.ReadOnly, g.maxClients, g.tlsCfg != nil)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // Stop() closed the listener: clean shutdown
			}
			return err // listener fatal; caller decides
		}
		if !g.admit(conn) {
			g.met.IncConnRejected()
			g.health.incConnRejected()
			continue
		}
		g.met.IncConnAccepted()
		g.health.incConnAccepted()
		go func() {
			defer g.clients.Add(-1)
			g.handleClient(conn)
		}()
	}
}

// admit applies the shielding limits and ACL gate to a fresh connection.
// The connection is counted as part of the cap decision (atomic Add
// returns the new value), so a burst of concurrent dials cannot slip
// past max_clients before handler goroutines start. Returns false when
// the connection was rejected (and closed).
func (g *gateway) admit(conn net.Conn) bool {
	// n includes this connection: allowed while n <= max_clients.
	if n := g.clients.Add(1); n > g.maxClients {
		g.clients.Add(-1)
		g.log.Warnf("gateway %s: rejecting %s: connection limit (%d) reached",
			g.dev.Name, conn.RemoteAddr(), g.maxClients)
		conn.Close()
		return false
	}
	if g.allow != nil {
		ip := remoteIP(conn)
		if ip == nil || !g.allow.Allowed(ip) {
			g.log.Warnf("gateway %s: rejecting %s: not in allow-list",
				g.dev.Name, conn.RemoteAddr())
			g.clients.Add(-1)
			conn.Close()
			return false
		}
	}
	return true
}

// handleClient runs the per-client lock-step loop: read one request,
// forward it upstream, write one response. Any client-side error ends the
// connection; upstream errors are converted to Modbus gateway exceptions
// and the connection stays usable. When idle_timeout_ms is configured,
// the read is deadline-bounded: clients that stay idle longer than the
// TTL lose their connection (reclaims a shielding connection-cap slot
// from dead or hung pollers).
func (g *gateway) handleClient(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	connID := g.connSeq.Add(1) // B9: correlate client + device log lines

	// B12: in mbaps mode the client's role comes from its certificate.
	// mTLS is mandatory in this mode (config validation enforces
	// tls+client_ca), so the connection is always a *tls.Conn here. The
	// handshake happens eagerly (bounded) in this handler goroutine —
	// the accept loop is never blocked — and the extracted role applies
	// to every request on the connection (spec: role extracted at
	// handshake, cached for the session).
	var mbapsRights map[uint8]bool // nil = deny every device request
	if g.mbaps != nil {
		tc, isTLS := conn.(*tls.Conn)
		if !isTLS {
			// Unreachable: mbaps config validation requires mTLS. A
			// non-TLS connection gets the NULL role (deny all).
			g.log.Warnf("gateway %s: [conn %d] %s: mbaps on non-TLS connection",
				g.dev.Name, connID, remote)
		} else {
			_ = conn.SetDeadline(deadlineFromNow(handshakeTimeout))
			if err := tc.Handshake(); err != nil {
				g.log.Debugf("gateway %s: [conn %d] %s: closing: handshake: %v",
					g.dev.Name, connID, remote, err)
				return
			}
			_ = conn.SetDeadline(time.Time{})
			if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
				role, ok := mbapsRole(certs[0])
				mbapsRights = mbapsRightsFor(g.mbaps, role, ok)
				if ok {
					g.log.Debugf("gateway %s: [conn %d] %s: mbaps role %q",
						g.dev.Name, connID, remote, role)
				} else {
					g.log.Infof("gateway %s: [conn %d] %s: mbaps NULL role (no role extension)",
						g.dev.Name, connID, remote)
				}
			}
		}
	}

	for {
		// B6: reap idle clients. Only the read (waiting for the next
		// request) is idle-bounded; an in-flight exchange has its own
		// upstream deadline and response writes get writeTimeout.
		if g.dev.HasIdleTimeout() {
			conn.SetReadDeadline(deadlineFromNow(g.dev.IdleTimeout()))
		} else {
			conn.SetReadDeadline(time.Time{}) // no TTL: clear any prior deadline
		}
		req, err := mbtcp.ReadADU(conn)
		if err != nil {
			g.log.Debugf("gateway %s: [conn %d] %s: closing: %v",
				g.dev.Name, connID, remote, err)
			return
		}

		resp := g.serve(conn, req, connID, mbapsRights)
		if err := writeADU(conn, resp); err != nil {
			g.log.Debugf("gateway %s: [conn %d] %s: write failed: %v",
				g.dev.Name, connID, remote, err)
			return
		}
	}
}

// serve processes one request and returns the response to send back to
// the client (never touches conn). connID is the B9 connection ID for
// log correlation; mbapsRights is the connection role's allowed function
// code set (B12; nil = deny every device request, NULL role).
func (g *gateway) serve(conn net.Conn, req mbtcp.ADU, connID uint64, mbapsRights map[uint8]bool) mbtcp.ADU {
	clientUnit := req.Header.UnitID

	// Health endpoint: requests addressed to the virtual health unit-ID
	// are answered by the proxy itself (B4) — before policy and rate
	// limiting, so monitoring stays responsive during a shielding event.
	if g.health != nil && clientUnit == g.healthUnitID {
		g.log.Debugf("gateway %s: [conn %d] %s: serving health unit %d",
			g.dev.Name, connID, conn.RemoteAddr(), g.healthUnitID)
		return g.serveHealth(req)
	}

	// mbaps role authorization (B12): every request is checked against
	// the connection role's function-code rights (spec: AuthZ occurs on
	// every request; rejection = exception 0x01). A NULL role or a role
	// without an entry has no rights. The device never sees a denied
	// request.
	if g.mbaps != nil && !mbapsRights[req.FunctionCode()] {
		g.log.Infof("gateway %s: [conn %d] %s: mbaps denied FC %d (not authorized)",
			g.dev.Name, connID, conn.RemoteAddr(), req.FunctionCode())
		g.met.ObserveRequest(g.dev.Name, outcomeExceptionAuthZ)
		g.health.incPolicy()
		return g.exception(req, clientUnit, mbtcp.ExceptionIllegalFunction)
	}

	// Read-only policy: reject writes locally; the device never sees them.
	if g.dev.ReadOnly && acl.IsWrite(req.FunctionCode()) {
		g.log.Infof("gateway %s: [conn %d] %s: blocked write FC %d (read-only)",
			g.dev.Name, connID, conn.RemoteAddr(), req.FunctionCode())
		g.met.ObserveRequest(g.dev.Name, outcomeExceptionPolicy)
		g.health.incPolicy()
		return g.exception(req, clientUnit, mbtcp.ExceptionIllegalFunction)
	}

	// Rate limiting: shield the device from polling storms. Rejected
	// requests get Server Device Busy and the device never sees them.
	if g.lim != nil && !g.lim.Allow() {
		g.log.Warnf("gateway %s: [conn %d] %s: rate limit (%d/s) exceeded, FC %d rejected",
			g.dev.Name, connID, conn.RemoteAddr(), g.dev.RatePerSec, req.FunctionCode())
		g.met.ObserveRequest(g.dev.Name, outcomeExceptionRate)
		g.health.incRate()
		return g.exception(req, clientUnit, mbtcp.ExceptionServerBusy)
	}

	// Read cache (B8): repeated read requests within the TTL are answered
	// from memory — no device traffic and no rate-token consumption on a
	// hit. The cache key uses the CLIENT's unit ID and request PDU
	// (pre-remap), so remapped devices are cached per-client-unit.
	if g.cache != nil && isReadFC(req.FunctionCode()) {
		if pdu := g.cache.lookup(clientUnit, req.PDU); pdu != nil {
			g.log.Debugf("gateway %s: [conn %d] %s: cache hit FC %d",
				g.dev.Name, connID, conn.RemoteAddr(), req.FunctionCode())
			g.met.ObserveRequest(g.dev.Name, outcomeCacheHit)
			g.health.incCacheHit()
			adu, err := mbtcp.NewADU(req.Header.TransactionID, clientUnit, pdu)
			if err != nil { // unreachable: cached PDUs came from valid ADUs
				g.log.Errorf("gateway %s: building cache response: %v", g.dev.Name, err)
				return g.exception(req, clientUnit, mbtcp.ExceptionGatewayTargetFail)
			}
			return adu
		}
	}

	// Unit-ID remap: the device always sees the configured unit ID.
	if g.dev.HasUnitRemap() {
		req.Header.UnitID = g.dev.UpstreamUnitID()
	}

	start := time.Now()
	resp, err := g.up.exchange(req, g.dev.RequestTimeout(), connID, conn)
	g.met.ObserveLatency(g.dev.Name, time.Since(start))
	if err != nil {
		g.log.Warnf("gateway %s: [conn %d] %s: upstream error: %v",
			g.dev.Name, connID, conn.RemoteAddr(), err)
		g.met.IncUpstreamError()
		g.met.ObserveRequest(g.dev.Name, outcomeExceptionDevice)
		g.health.incUpstreamError()
		g.health.incDeviceErr()
		return g.exception(req, clientUnit, mbtcp.ExceptionGatewayTargetFail)
	}
	g.met.ObserveRequest(g.dev.Name, outcomeForwarded)
	g.health.incForwarded()
	if g.dev.HasUnitRemap() {
		resp.Header.UnitID = clientUnit
	}
	// Store successful read responses in the cache (B8). Keyed by the
	// CLIENT's unit ID (pre-remap) + request PDU; the response PDU is
	// remap-independent (unit ID lives in the header).
	if g.cache != nil && isReadFC(req.FunctionCode()) && !resp.IsException() {
		g.cache.store(clientUnit, req.PDU, resp.PDU)
	}
	return resp
}

// exception builds a proxy-generated exception response carrying the
// client's original transaction ID and unit ID.
func (g *gateway) exception(req mbtcp.ADU, unitID uint8, code uint8) mbtcp.ADU {
	adu, err := mbtcp.NewADU(req.Header.TransactionID, unitID,
		mbtcp.ExceptionPDU(req.FunctionCode(), code))
	if err != nil { // unreachable: exception PDU is always 2 bytes
		g.log.Errorf("gateway %s: building exception: %v", g.dev.Name, err)
	}
	return adu
}

// writeADU writes one frame with a bounded write deadline.
func writeADU(conn net.Conn, adu mbtcp.ADU) error {
	_ = conn.SetWriteDeadline(deadlineFromNow(writeTimeout))
	_, err := conn.Write(adu.Frame())
	return err
}

// remoteIP extracts the client IP from a connection.
func remoteIP(conn net.Conn) net.IP {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP
	}
	return nil
}

// tlsConfigFor builds the front-leg TLS termination config from a device
// entry: TLS 1.2 minimum, and mTLS (required, CA-verified client certs)
// when client_ca is configured.
func tlsConfigFor(d config.Device) (*tls.Config, error) {
	t := d.TLS
	cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if t.ClientCA != "" {
		pem, err := os.ReadFile(t.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client CA %s: no valid certificates found", t.ClientCA)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// deviceTLSConfigFor builds the upstream (device-side) TLS client config
// from a device entry (two-proxy secured line): TLS 1.2 minimum, custom
// CA pool when ca_cert is set, server-name override, and optional client
// certificate for mTLS toward the far box.
func deviceTLSConfigFor(d config.Device) (*tls.Config, error) {
	t := d.DeviceTLS
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if t.CACert != "" {
		pem, err := os.ReadFile(t.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA cert %s: no valid certificates found", t.CACert)
		}
		cfg.RootCAs = pool
	}
	if t.ServerName != "" {
		cfg.ServerName = t.ServerName
	}
	if t.Cert != "" && t.Key != "" {
		cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// writeTimeout bounds a front-leg response write.
const writeTimeout = 10 * time.Second

// handshakeTimeout bounds the eager mTLS handshake in mbaps mode (B12).
const handshakeTimeout = 10 * time.Second

// Request outcome labels for the metrics hook.
const (
	outcomeForwarded       = "forwarded"
	outcomeExceptionDevice = "exception_device" // upstream dial/timeout/read/write error
	outcomeExceptionPolicy = "exception_policy" // read-only blocked write
	outcomeExceptionRate   = "exception_rate"   // rate limiter rejection
	outcomeExceptionAuthZ  = "exception_authz"  // mbaps role denial (B12)
	outcomeCacheHit        = "cache_hit"        // served from the read cache (B8)
)

// metricsOrNop normalizes a nil metrics hook to a concurrency-safe no-op.
func metricsOrNop(m Metrics) Metrics {
	if m == nil {
		return nopMetrics{}
	}
	return m
}

// nopMetrics is the "no metrics" implementation; every method is a no-op.
type nopMetrics struct{}

func (nopMetrics) IncConnAccepted()                     {}
func (nopMetrics) IncConnRejected()                     {}
func (nopMetrics) ObserveRequest(string, string)        {}
func (nopMetrics) ObserveLatency(string, time.Duration) {}
func (nopMetrics) IncUpstreamError()                    {}
func (nopMetrics) IncStaleDiscard()                     {}
func (nopMetrics) IncReconnect()                        {}
func (nopMetrics) SetDeviceUp(string, bool)             {}

// deadlineFromNow returns a connection deadline duration from now.
func deadlineFromNow(d time.Duration) time.Time { return time.Now().Add(d) }
