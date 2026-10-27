package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// ErrDeviceUnreachable reports that the upstream device could not be
// reached (dial failed or no connection could be established within the
// per-request deadline). Clients receive a Modbus gateway exception
// (0x0B) when this happens; the connection stays usable.
var ErrDeviceUnreachable = errors.New("proxy: device unreachable")

// upstream manages the single connection to the legacy device.
//
// Legacy devices typically accept one (or very few) TCP connections, so
// all client traffic is multiplexed over this one connection: exchanges
// are strictly serialized, one request in flight at a time, in FIFO
// arrival order (see gate — a busy client cannot starve a quiet one).
// Responses are matched by transaction ID; late or stale responses from
// earlier timed-out requests are discarded.
//
// Any exchange failure (write error, read error, timeout) drops the
// connection: after a timeout the device's reply may still be in flight
// and the stream state is unknown. The next exchange dials again, with
// bounded backoff between attempts.
type upstream struct {
	addr string
	name string // config device name (metrics + logs)
	log  Logger
	met  Metrics

	// connSeq hands out per-gateway connection IDs (B9); shared with the
	// gateway that owns this upstream so client and device log lines
	// carry the same ID.
	connSeq *atomic.Uint64

	// tlsDial, when set, dials the device address over TLS (device_tls
	// config; two-proxy secured line). nil = plain TCP.
	tlsDial *tls.Config

	// requestDelay, when > 0, enforces a minimum gap between consecutive
	// requests toward the device (request_delay_ms; B5 — picky legacy
	// devices that choke on back-to-back traffic). 0 = unpaced.
	requestDelay time.Duration

	// lastRequest is when the last exchange happened; used by the B5
	// pacing logic.
	lastRequest time.Time

	// rtuOverTCP, when true, makes the device leg speak bare Modbus RTU
	// frames instead of MBAP (rtu_over_tcp; B7): requests are translated
	// MBAP ADU -> RTU frame, responses RTU frame -> MBAP ADU. The front
	// leg stays Modbus TCP; clients notice nothing. The response's
	// transaction ID and protocol ID are reconstructed (RTU has none).
	rtuOverTCP bool

	// lenient, when true, relaxes DEVICE-leg correlation
	// (lenient_correlation): the device's response is accepted even when
	// it does not echo the transaction ID or sets a non-zero protocol ID.
	// Framing stays strict — only correlation is tolerant. Safe because
	// exactly one request is ever in flight on this connection; the
	// response is rewritten to the client's transaction ID either way.
	lenient bool

	// origDST, when set, resolves the upstream target per CLIENT
	// connection (B3 transparent mode): the client's conntrack
	// SO_ORIGINAL_DST — the device IP it was actually dialing. nil =
	// static addr from config. This is the only structural difference a
	// transparent gateway has from a reverse-proxy gateway.
	origDST func(conn net.Conn) (string, error)

	// origDSTConn is the client connection the current device connection
	// targets (transparent mode multiplexes one client connection's
	// traffic onto its own device connection; see gateway.serve).
	// Only meaningful when origDST != nil; guarded by mu.
	origDSTConn net.Conn

	// gate serializes exchanges in ARRIVAL order. A plain mutex does not
	// promise that (a waiter can be beaten to the lock by a late arrival),
	// and the fairness claim is that a quiet poller is never starved by a
	// noisy one. A cap-1 channel hands the slot over in the order the
	// goroutines blocked, so scheduling is FIFO by construction.
	gate chan struct{}

	mu   sync.Mutex
	conn net.Conn

	// health mirrors reconnect/stale counters into the B4 health
	// registry; nil-safe.
	health *healthRegistry
}

func newUpstream(addr, name string, log Logger, met Metrics) *upstream {
	return &upstream{
		addr: addr,
		name: name,
		log:  log,
		met:  metricsOrNop(met),
		gate: make(chan struct{}, 1),
	}
}

// setUpstreamHealth wires the B4 health registry into the upstream so
// reconnect/stale counters mirror into the health registers.
func (u *upstream) setUpstreamHealth(h *healthRegistry) {
	u.health = h
}

// exchange forwards req to the device and returns the matching response.
// timeout bounds the whole exchange (dial retries included). connID is
// the front-leg connection ID (B9) that caused this exchange; it is
// attached to device-side log lines so client and device logs correlate.
// clientConn is the front-leg connection that produced req (only used in
// transparent mode to resolve the per-connection original destination).
func (u *upstream) exchange(req mbtcp.ADU, timeout time.Duration, connID uint64, clientConn net.Conn) (mbtcp.ADU, error) {
	// FIFO admission first (fairness), then the state lock. The channel is
	// the queue: whichever goroutine blocked first gets the slot first.
	u.gate <- struct{}{}
	defer func() { <-u.gate }()
	u.mu.Lock()
	defer u.mu.Unlock()

	deadline := time.Now().Add(timeout)

	// B5 pacing: enforce a minimum gap between consecutive requests
	// toward the device. Under u.mu, so the gap is measured across ALL
	// client requests multiplexed onto this connection — exactly the
	// serialization point a picky device cares about. Charged against
	// the exchange deadline (a slow-paced device is a slow exchange).
	if u.requestDelay > 0 && !u.lastRequest.IsZero() {
		if wait := u.requestDelay - time.Since(u.lastRequest); wait > 0 {
			u.log.Debugf("device %s: [conn %d] pacing %v between requests",
				u.addr, connID, u.requestDelay)
			time.Sleep(wait)
		}
	}
	u.lastRequest = time.Now()

	// B3 transparent mode: resolve the upstream target from THIS client
	// connection's conntrack entry. When the client connection changes
	// (different front-leg connection), the previously dialed device
	// connection belongs to a different client — drop it so the next
	// dial targets the new client's original destination.
	if u.origDST != nil {
		if clientConn == nil {
			return mbtcp.ADU{}, fmt.Errorf("transparent mode: no client connection for original-dst resolution")
		}
		if u.conn != nil && u.origDSTConn != clientConn {
			u.drop(u.conn)
		}
		target, err := u.origDST(clientConn)
		if err != nil {
			return mbtcp.ADU{}, fmt.Errorf("transparent mode: %w", err)
		}
		u.origDSTConn = clientConn
		if target != u.addr {
			u.log.Debugf("device %s: [conn %d] transparent target %s", u.addr, connID, target)
			u.addr = target
			if u.conn != nil {
				u.drop(u.conn)
			}
		}
	}

	conn, err := u.ensureConn(deadline)
	if err != nil {
		return mbtcp.ADU{}, err
	}
	if u.rtuOverTCP {
		return u.exchangeRTU(conn, req, deadline, connID)
	}
	if err := u.send(conn, req, deadline); err != nil {
		u.drop(conn)
		return mbtcp.ADU{}, fmt.Errorf("write to device: %w", err)
	}
	opts := mbtcp.ReadOptions{AllowForeignProtocolID: u.lenient}
	for {
		conn.SetReadDeadline(deadline)
		resp, err := mbtcp.ReadADUWith(conn, opts)
		if err != nil {
			u.drop(conn)
			return mbtcp.ADU{}, fmt.Errorf("read from device: %w", err)
		}
		if resp.Header.TransactionID != req.Header.TransactionID {
			if !u.lenient {
				// Late/stale response from an earlier timed-out request.
				// The stream is frame-aligned, so skipping is safe.
				u.log.Debugf("device %s: [conn %d] discarding stale response (txn %d, want %d)",
					u.addr, connID, resp.Header.TransactionID, req.Header.TransactionID)
				u.met.IncStaleDiscard()
				u.health.incStale()
				continue
			}
			// Lenient mode: the device does not echo transaction IDs.
			// Exactly one request is in flight, so the frame that just
			// arrived answers THIS request; the client still sees its own
			// transaction ID below.
			u.log.Debugf("device %s: [conn %d] accepting response with foreign txn %d (want %d; lenient correlation)",
				u.addr, connID, resp.Header.TransactionID, req.Header.TransactionID)
		}
		// Normalize the response header: front-leg clients correlate on
		// THEIR transaction ID and expect protocol ID 0, whatever the
		// device echoed (lenient mode may hand back junk in both fields).
		resp.Header.TransactionID = req.Header.TransactionID
		resp.Header.ProtocolID = mbtcp.ProtocolID
		return resp, nil
	}
}

// exchangeRTU translates one MBAP ADU to a bare RTU frame, exchanges it
// with the device, and translates the RTU response back to an MBAP ADU
// (rtu_over_tcp; B7). RTU frames carry no transaction ID, so the
// response's txn/protocol IDs are reconstructed from the request and the
// stale-response loop reduces to CRC-verified single-frame reads — still
// frame-safe, because a serial bridge sends each response as one burst
// and the CRC anchors the frame boundary.
func (u *upstream) exchangeRTU(conn net.Conn, req mbtcp.ADU, deadline time.Time, connID uint64) (mbtcp.ADU, error) {
	rtuFrame, err := mbtcp.RTUFrame(req.Header.UnitID, req.PDU)
	if err != nil {
		return mbtcp.ADU{}, fmt.Errorf("rtu encode: %w", err)
	}
	conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(rtuFrame); err != nil {
		u.drop(conn)
		return mbtcp.ADU{}, fmt.Errorf("write to device: %w", err)
	}
	for {
		conn.SetReadDeadline(deadline)
		unit, pdu, err := mbtcp.ReadRTUResponse(conn, conn, rtuGap, deadline)
		if err != nil {
			u.drop(conn)
			return mbtcp.ADU{}, fmt.Errorf("read from device: %w", err)
		}
		if unit != req.Header.UnitID {
			// Stale frame from an earlier timed-out request (RTU has no
			// txn-IDs; the unit address is the only correlation anchor).
			u.log.Debugf("device %s: [conn %d] discarding stale RTU response (unit %d, want %d)",
				u.addr, connID, unit, req.Header.UnitID)
			u.met.IncStaleDiscard()
			u.health.incStale()
			continue
		}
		return mbtcp.NewADU(req.Header.TransactionID, unit, pdu)
	}
}

// rtuGap is the idle-gap used by RTU reads when the exchange deadline
// does not bound the frame first (unlisted function codes only).
const rtuGap = 50 * time.Millisecond

// ensureConn returns the current connection, dialing with bounded backoff
// until deadline when necessary.
func (u *upstream) ensureConn(deadline time.Time) (net.Conn, error) {
	backoff := 100 * time.Millisecond
	for {
		if u.conn != nil {
			return u.conn, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("%w: %s", ErrDeviceUnreachable, u.addr)
		}
		dialTimeout := remaining
		if dialTimeout > time.Second {
			dialTimeout = time.Second
		}
		dialer := &net.Dialer{Timeout: dialTimeout}
		var conn net.Conn
		var err error
		if u.tlsDial != nil {
			// TLS handshake included in the dial deadline (eager, not
			// lazy — the connection is unusable without a completed
			// handshake, and a half-open conn must not look "up").
			conn, err = tls.DialWithDialer(dialer, "tcp", u.addr, u.tlsDial)
		} else {
			conn, err = dialer.Dial("tcp", u.addr)
		}
		if err == nil {
			u.conn = conn
			u.met.IncReconnect()
			u.met.SetDeviceUp(u.name, true)
			u.health.incReconnect()
			u.log.Debugf("device %s: connected (tls=%v)", u.addr, u.tlsDial != nil)
			return conn, nil
		}
		sleep := backoff
		if sleep > remaining {
			sleep = remaining
		}
		if backoff < time.Second {
			backoff *= 2
		}
		time.Sleep(sleep)
	}
}

// send writes one frame, respecting the deadline.
func (u *upstream) send(conn net.Conn, adu mbtcp.ADU, deadline time.Time) error {
	conn.SetWriteDeadline(deadline)
	_, err := conn.Write(adu.Frame())
	return err
}

// drop closes the current connection if it is still the one in use.
func (u *upstream) drop(conn net.Conn) {
	if u.conn == conn {
		u.conn = nil
	}
	conn.Close()
	u.met.SetDeviceUp(u.name, false)
	u.log.Debugf("device %s: connection dropped", u.addr)
}

// up reports whether the device connection is currently established.
func (u *upstream) up() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conn != nil
}

// close shuts the device connection down (idempotent).
func (u *upstream) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil {
		u.conn.Close()
		u.conn = nil
	}
	u.met.SetDeviceUp(u.name, false)
}
