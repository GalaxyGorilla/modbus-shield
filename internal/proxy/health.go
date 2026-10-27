package proxy

import (
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// Health via Modbus (B4): the proxy exposes its own health as readable
// registers on a virtual unit-ID, so a plant SCADA can monitor the box
// with the Modbus tooling it already has. Requests addressed to the
// health unit-ID are answered by the proxy itself — the device never
// sees them, and health reads bypass read-only policy and the rate
// limiter (the endpoint must stay responsive exactly when the box is
// shielding a polling storm). The front-leg gates (allow-list,
// connection cap) still apply: they run at accept time.

// healthRegisterMapVersion is bumped whenever the register layout below
// changes meaning. Clients can detect the layout via register 1.
const healthRegisterMapVersion = 2

// healthMagic identifies the health endpoint (ASCII "MS").
const healthMagic = 0x4D53

// healthRegCount is the number of health registers (addresses 0..N-1).
const healthRegCount = 19

// Register map (0-based addresses, 16-bit big-endian, FC3/FC4):
//
//	 0     magic (0x4D53 "MS")
//	 1     register map version
//	 2..3  uptime seconds (uint32, high word first)
//	 4     upstream state (1 = device connection up, 0 = down)
//	 5     upstream reconnects (16-bit wrap)
//	 6     upstream errors (16-bit wrap)
//	 7     stale responses discarded (16-bit wrap)
//	 8     front connections accepted (16-bit wrap)
//	 9     front connections rejected (16-bit wrap)
//	10     current client connections
//	11     requests forwarded (16-bit wrap)
//	12     requests -> exception_device (16-bit wrap)
//	13     requests -> exception_policy (16-bit wrap)
//	14     requests -> exception_rate (16-bit wrap)
//	15     read-only policy (1 = on, 0 = off)
//	16     max_clients
//	17     rate_per_sec (0 = unlimited)
//	18     read-cache hits (16-bit wrap; 0 when cache disabled)

// healthRegistry holds the per-gateway health counters. All methods are
// nil-receiver safe: call sites stay unchanged when health is disabled.
type healthRegistry struct {
	start time.Time

	connAccepted  atomicU16
	connRejected  atomicU16
	reqForwarded  atomicU16
	reqDevice     atomicU16
	reqPolicy     atomicU16
	reqRate       atomicU16
	upstreamErrs  atomicU16
	staleDiscards atomicU16
	reconnects    atomicU16
	cacheHits     atomicU16
}

func newHealthRegistry() *healthRegistry {
	return &healthRegistry{start: time.Now()}
}

func (h *healthRegistry) incConnAccepted() {
	if h != nil {
		h.connAccepted.add(1)
	}
}
func (h *healthRegistry) incConnRejected() {
	if h != nil {
		h.connRejected.add(1)
	}
}
func (h *healthRegistry) incForwarded() {
	if h != nil {
		h.reqForwarded.add(1)
	}
}
func (h *healthRegistry) incDeviceErr() {
	if h != nil {
		h.reqDevice.add(1)
	}
}
func (h *healthRegistry) incPolicy() {
	if h != nil {
		h.reqPolicy.add(1)
	}
}
func (h *healthRegistry) incRate() {
	if h != nil {
		h.reqRate.add(1)
	}
}
func (h *healthRegistry) incUpstreamError() {
	if h != nil {
		h.upstreamErrs.add(1)
	}
}
func (h *healthRegistry) incStale() {
	if h != nil {
		h.staleDiscards.add(1)
	}
}
func (h *healthRegistry) incReconnect() {
	if h != nil {
		h.reconnects.add(1)
	}
}
func (h *healthRegistry) incCacheHit() {
	if h != nil {
		h.cacheHits.add(1)
	}
}

// serveHealth answers one request addressed to the health unit-ID.
// Only FC3 (read holding) and FC4 (read input) are valid; both return
// the same register image.
func (g *gateway) serveHealth(req mbtcp.ADU) mbtcp.ADU {
	fc := req.FunctionCode()
	if fc != 3 && fc != 4 {
		return g.exception(req, req.Header.UnitID, mbtcp.ExceptionIllegalFunction)
	}
	if len(req.PDU) < 5 {
		return g.exception(req, req.Header.UnitID, mbtcp.ExceptionIllegalDataAddr)
	}
	start := binary.BigEndian.Uint16(req.PDU[1:3])
	quantity := binary.BigEndian.Uint16(req.PDU[3:5])
	if quantity == 0 || quantity > 125 {
		return g.exception(req, req.Header.UnitID, mbtcp.ExceptionIllegalDataAddr)
	}
	if uint32(start)+uint32(quantity) > healthRegCount {
		return g.exception(req, req.Header.UnitID, mbtcp.ExceptionIllegalDataAddr)
	}

	regs := make([]uint16, quantity)
	for i := range regs {
		regs[i] = g.healthRegister(int(start) + i)
	}
	pdu := make([]byte, 2+2*len(regs))
	pdu[0] = fc
	pdu[1] = byte(2 * len(regs))
	for i, r := range regs {
		binary.BigEndian.PutUint16(pdu[2+2*i:], r)
	}
	adu, err := mbtcp.NewADU(req.Header.TransactionID, req.Header.UnitID, pdu)
	if err != nil { // unreachable: read response is at most 252 bytes
		g.log.Errorf("gateway %s: building health response: %v", g.dev.Name, err)
		return g.exception(req, req.Header.UnitID, mbtcp.ExceptionGatewayTargetFail)
	}
	return adu
}

// healthRegister returns one register of the health image. The
// configuration-derived registers read the live runtime snapshot, so a
// reload is visible in the health image without a restart.
func (g *gateway) healthRegister(addr int) uint16 {
	h := g.health
	rt := g.runtime()
	switch addr {
	case 0:
		return healthMagic
	case 1:
		return healthRegisterMapVersion
	case 2, 3:
		uptime := uint32(time.Since(h.start).Seconds())
		if addr == 2 {
			return uint16(uptime >> 16)
		}
		return uint16(uptime)
	case 4:
		if g.up.up() {
			return 1
		}
		return 0
	case 5:
		return h.reconnects.get()
	case 6:
		return h.upstreamErrs.get()
	case 7:
		return h.staleDiscards.get()
	case 8:
		return h.connAccepted.get()
	case 9:
		return h.connRejected.get()
	case 10:
		return uint16(g.clients.Load())
	case 11:
		return h.reqForwarded.get()
	case 12:
		return h.reqDevice.get()
	case 13:
		return h.reqPolicy.get()
	case 14:
		return h.reqRate.get()
	case 15:
		if rt.readOnly {
			return 1
		}
		return 0
	case 16:
		return uint16(rt.maxClients)
	case 17:
		return uint16(rt.sharedRate)
	case 18:
		return h.cacheHits.get()
	}
	return 0 // unreachable: bounds checked in serveHealth
}

// atomicU16 is a wrap-around 16-bit counter backed by an atomic uint32.
type atomicU16 struct {
	v atomic.Uint32
}

func (c *atomicU16) add(n uint16) {
	for {
		old := c.v.Load()
		newV := uint32(uint16(old) + n)
		if c.v.CompareAndSwap(old, newV) {
			return
		}
	}
}

func (c *atomicU16) get() uint16 { return uint16(c.v.Load()) }
