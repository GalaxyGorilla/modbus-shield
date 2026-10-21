package proxy

import (
	"fmt"
	"net"
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
}

func newGateway(dev config.Device, log Logger) (*gateway, error) {
	allow, err := acl.NewList(dev.Allow)
	if err != nil {
		return nil, fmt.Errorf("device %s: %w", dev.Name, err)
	}
	return &gateway{
		dev:        dev,
		up:         newUpstream(dev.DeviceAddr, log),
		log:        log,
		allow:      allow,
		maxClients: int64(dev.MaxClients),
	}, nil
}

// Serve runs the accept loop on ln until it is closed. Client-side errors
// never kill the loop: a misbehaving client costs its connection only.
func (g *gateway) Serve(ln net.Listener) error {
	g.log.Infof("gateway %s: listening on %s -> %s (read_only=%v max_clients=%d)",
		g.dev.Name, ln.Addr(), g.dev.DeviceAddr, g.dev.ReadOnly, g.maxClients)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err // listener closed or fatal; caller decides
		}
		if !g.admit(conn) {
			continue
		}
		g.clients.Add(1)
		go func() {
			defer g.clients.Add(-1)
			g.handleClient(conn)
		}()
	}
}

// admit applies the shielding limits and ACL gate to a fresh connection.
// It returns false when the connection was rejected (and closed).
func (g *gateway) admit(conn net.Conn) bool {
	if n := g.clients.Load(); n >= g.maxClients {
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
			conn.Close()
			return false
		}
	}
	return true
}

// handleClient runs the per-client lock-step loop: read one request,
// forward it upstream, write one response. Any client-side error ends the
// connection; upstream errors are converted to Modbus gateway exceptions
// and the connection stays usable.
func (g *gateway) handleClient(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	for {
		req, err := mbtcp.ReadADU(conn)
		if err != nil {
			g.log.Debugf("gateway %s: %s: closing: %v", g.dev.Name, remote, err)
			return
		}

		resp := g.serve(conn, req)
		if err := writeADU(conn, resp); err != nil {
			g.log.Debugf("gateway %s: %s: write failed: %v", g.dev.Name, remote, err)
			return
		}
	}
}

// serve processes one request and returns the response to send back to
// the client (never touches conn).
func (g *gateway) serve(conn net.Conn, req mbtcp.ADU) mbtcp.ADU {
	clientUnit := req.Header.UnitID

	// Read-only policy: reject writes locally; the device never sees them.
	if g.dev.ReadOnly && acl.IsWrite(req.FunctionCode()) {
		g.log.Infof("gateway %s: %s: blocked write FC %d (read-only)",
			g.dev.Name, conn.RemoteAddr(), req.FunctionCode())
		return g.exception(req, clientUnit, mbtcp.ExceptionIllegalFunction)
	}

	// Unit-ID remap: the device always sees the configured unit ID.
	if g.dev.HasUnitRemap() {
		req.Header.UnitID = g.dev.UpstreamUnitID()
	}

	resp, err := g.up.exchange(req, g.dev.RequestTimeout())
	if err != nil {
		g.log.Warnf("gateway %s: %s: upstream error: %v",
			g.dev.Name, conn.RemoteAddr(), err)
		return g.exception(req, clientUnit, mbtcp.ExceptionGatewayTargetFail)
	}
	if g.dev.HasUnitRemap() {
		resp.Header.UnitID = clientUnit
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

// writeTimeout bounds a front-leg response write.
const writeTimeout = 10 * time.Second

// deadlineFromNow returns a connection deadline duration from now.
func deadlineFromNow(d time.Duration) time.Time { return time.Now().Add(d) }
