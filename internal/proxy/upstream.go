package proxy

import (
	"errors"
	"fmt"
	"net"
	"sync"
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
// are strictly serialized (first come, first served), one request in
// flight at a time. Responses are matched by transaction ID; late or
// stale responses from earlier timed-out requests are discarded.
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

	mu   sync.Mutex
	conn net.Conn
}

func newUpstream(addr, name string, log Logger, met Metrics) *upstream {
	return &upstream{addr: addr, name: name, log: log, met: metricsOrNop(met)}
}

// exchange forwards req to the device and returns the matching response.
// timeout bounds the whole exchange (dial retries included).
func (u *upstream) exchange(req mbtcp.ADU, timeout time.Duration) (mbtcp.ADU, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	deadline := time.Now().Add(timeout)
	conn, err := u.ensureConn(deadline)
	if err != nil {
		return mbtcp.ADU{}, err
	}
	if err := u.send(conn, req, deadline); err != nil {
		u.drop(conn)
		return mbtcp.ADU{}, fmt.Errorf("write to device: %w", err)
	}
	for {
		conn.SetReadDeadline(deadline)
		resp, err := mbtcp.ReadADU(conn)
		if err != nil {
			u.drop(conn)
			return mbtcp.ADU{}, fmt.Errorf("read from device: %w", err)
		}
		if resp.Header.TransactionID != req.Header.TransactionID {
			// Late/stale response from an earlier timed-out request.
			// The stream is frame-aligned, so skipping is safe.
			u.log.Debugf("device %s: discarding stale response (txn %d, want %d)",
				u.addr, resp.Header.TransactionID, req.Header.TransactionID)
			u.met.IncStaleDiscard()
			continue
		}
		return resp, nil
	}
}

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
		conn, err := net.DialTimeout("tcp", u.addr, dialTimeout)
		if err == nil {
			u.conn = conn
			u.met.IncReconnect()
			u.met.SetDeviceUp(u.name, true)
			u.log.Debugf("device %s: connected", u.addr)
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
