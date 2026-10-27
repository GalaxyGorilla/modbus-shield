package proxy

import (
	"fmt"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/acl"
	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

// gatewayRuntime is the set of config-derived knobs that a SIGHUP reload
// can swap without touching listeners, TLS, or the device connection.
// The whole struct is replaced under gateway.rtMu, so a request always
// sees ONE consistent configuration instead of a half-applied reload
// (e.g. new ACL with old rate limit).
//
// Everything that is NOT in here (listen_addr, extra_listen, device_addr,
// tls, device_tls, transparent, rtu_over_tcp) is bound to the listener
// and/or the open device connection and therefore requires a restart —
// Reload reports that instead of pretending to apply it.
type gatewayRuntime struct {
	readOnly    bool
	writePol    *acl.WritePolicy
	allow       *acl.List
	maxClients  int64
	lim         *rateLimiter
	sharedRate  int
	clientRate  int
	cache       *readCache
	mbaps       map[string]map[uint8]bool
	healthUnit  *uint8
	idleTimeout time.Duration
	timeout     time.Duration
	unitRemap   *uint8
}

// newGatewayRuntime compiles the reloadable parts of a device config.
func newGatewayRuntime(dev config.Device) (gatewayRuntime, error) {
	allow, err := acl.NewList(dev.Allow)
	if err != nil {
		return gatewayRuntime{}, fmt.Errorf("device %s: allow-list: %w", dev.Name, err)
	}
	pol, err := writePolicyFor(dev)
	if err != nil {
		return gatewayRuntime{}, fmt.Errorf("device %s: %w", dev.Name, err)
	}
	var healthUnit *uint8
	if dev.HasHealth() {
		u := dev.HealthUnitIDValue()
		healthUnit = &u
	}
	return gatewayRuntime{
		readOnly:    dev.ReadOnly,
		writePol:    pol,
		allow:       allow,
		maxClients:  int64(dev.MaxClients),
		lim:         newRateLimiter(dev.RatePerSec),
		sharedRate:  dev.RatePerSec,
		clientRate:  dev.RatePerClientPerSec,
		cache:       newReadCache(dev.ReadCacheTTL()),
		mbaps:       mbapsRightsTable(dev),
		healthUnit:  healthUnit,
		idleTimeout: dev.IdleTimeout(),
		timeout:     dev.RequestTimeout(),
		unitRemap:   dev.DeviceUnitID,
	}, nil
}

// writePolicyFor compiles a device's YAML write policy into the acl rule
// set. Returns nil when no policy is configured (nil = allow all writes,
// the nil-guard pattern used everywhere else).
func writePolicyFor(dev config.Device) (*acl.WritePolicy, error) {
	if !dev.HasWritePolicy() {
		return nil, nil
	}
	rules := make([]acl.WriteRule, 0, len(dev.WritePolicy.Rules))
	for _, r := range dev.WritePolicy.Rules {
		cr := acl.WriteRule{Allow: r.Action != "deny"}
		if r.Unit != nil {
			u := uint8(*r.Unit)
			cr.Unit = &u
		}
		for _, fc := range r.FC {
			cr.FCs = append(cr.FCs, uint8(fc))
		}
		if r.From != nil {
			cr.HasRange = true
			cr.From = uint16(*r.From)
			cr.To = uint16(*r.To)
		}
		rules = append(rules, cr)
	}
	return acl.NewWritePolicy(dev.WritePolicyDefaultAllow(), rules)
}

// mbapsRightsTable converts the per-role function-code lists into lookup
// sets (nil when mbaps is not configured).
func mbapsRightsTable(dev config.Device) map[string]map[uint8]bool {
	if !dev.HasMBAPS() {
		return nil
	}
	table := make(map[string]map[uint8]bool, len(dev.MBAPS.Roles))
	for role, codes := range dev.MBAPS.Roles {
		set := make(map[uint8]bool, len(codes))
		for _, fc := range codes {
			set[uint8(fc)] = true
		}
		table[role] = set
	}
	return table
}

// runtime returns a consistent snapshot; the value is copied, so callers
// never hold the lock while doing I/O.
func (g *gateway) runtime() gatewayRuntime {
	g.rtMu.RLock()
	defer g.rtMu.RUnlock()
	return g.rt
}

// setRuntime swaps the reloadable configuration atomically for readers.
func (g *gateway) setRuntime(rt gatewayRuntime) {
	g.rtMu.Lock()
	defer g.rtMu.Unlock()
	g.rt = rt
}
