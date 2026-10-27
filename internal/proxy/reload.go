package proxy

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

// Reload applies a freshly loaded configuration to the running gateways
// WITHOUT dropping listeners, front-leg TLS, or the device connections.
// It returns human-readable warnings for everything it could not apply;
// the caller (main, on SIGHUP) logs them. An empty slice means the new
// configuration was applied completely.
//
// Reloadable: read_only, write_policy, allow, max_clients, rate limits,
// read_cache_ttl_ms, request_delay_ms, lenient_correlation,
// idle_timeout_ms, timeout_ms, device_unit_id, health_unit_id (when the
// health endpoint already exists) and the mbaps role table.
//
// Restart required (reported, not applied): listen_addr, extra_listen,
// device_addr, tls, device_tls, transparent, rtu_over_tcp, enabling the
// health endpoint, and the device NAME (devices are matched by name).
// Adding/removing devices also needs a restart. Disabling the health
// endpoint (dropping health_unit_id) IS reloadable — the registry simply
// stops answering.
//
// Safety property: a device whose new config fails to compile keeps
// serving its previous settings — Reload never leaves a gateway without a
// usable runtime.
func (r *Runner) Reload(cfg *config.Config) []string {
	var warnings []string
	running := make(map[string]bool, len(r.gws))
	for _, gw := range r.gws {
		running[gw.dev.Name] = true
	}

	for _, gw := range r.gws {
		name := gw.dev.Name
		dev := findDevice(cfg, name)
		if dev == nil {
			warnings = append(warnings, fmt.Sprintf(
				"device %s: no longer in the config; still serving (restart required to remove it)", name))
			continue
		}
		for _, msg := range restartRequired(gw, *dev) {
			warnings = append(warnings, fmt.Sprintf("device %s: %s (restart required)", name, msg))
		}
		rt, err := newGatewayRuntime(*dev)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"device %s: reload failed, keeping previous settings: %v", name, err))
			continue
		}
		gw.setRuntime(rt)
		gw.up.setRequestDelay(dev.RequestDelay())
		gw.up.setLenient(dev.HasLenientCorrelation())
		r.log.Infof("device %s: configuration reloaded (read_only=%v write_policy=%v mbaps=%v max_clients=%d rate=%d/s cache_ttl=%v)",
			name, rt.readOnly, rt.writePol != nil, rt.mbaps != nil, rt.maxClients,
			rt.sharedRate, dev.ReadCacheTTL())
	}

	// New devices cannot be added without binding their listeners, so they
	// are reported instead of silently ignored (the operator would
	// otherwise believe the new device is protected).
	for i := range cfg.Devices {
		if !running[cfg.Devices[i].Name] {
			warnings = append(warnings, fmt.Sprintf(
				"device %s: new in the config, not running (restart required to add it)", cfg.Devices[i].Name))
		}
	}
	return warnings
}

// findDevice returns the config entry for a running gateway (matched by
// name — the identity main and the DNS/metrics labels use).
func findDevice(cfg *config.Config, name string) *config.Device {
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			return &cfg.Devices[i]
		}
	}
	return nil
}

// restartRequired lists the differences between the running device config
// and the new one that a SIGHUP cannot apply: everything bound to a
// listener, the TLS configs, or the open device connection.
func restartRequired(gw *gateway, dev config.Device) []string {
	old := gw.dev
	var msgs []string
	if old.ListenAddr != dev.ListenAddr {
		msgs = append(msgs, fmt.Sprintf("listen_addr %s -> %s", old.ListenAddr, dev.ListenAddr))
	}
	if !slices.Equal(old.ExtraListen, dev.ExtraListen) {
		msgs = append(msgs, fmt.Sprintf("extra_listen %v -> %v", old.ExtraListen, dev.ExtraListen))
	}
	if old.DeviceAddr != dev.DeviceAddr {
		msgs = append(msgs, fmt.Sprintf("device_addr %s -> %s", old.DeviceAddr, dev.DeviceAddr))
	}
	if !reflect.DeepEqual(old.TLS, dev.TLS) {
		msgs = append(msgs, "tls block changed")
	}
	if !reflect.DeepEqual(old.DeviceTLS, dev.DeviceTLS) {
		msgs = append(msgs, "device_tls block changed")
	}
	if old.HasTransparent() != dev.HasTransparent() {
		msgs = append(msgs, fmt.Sprintf("transparent %v -> %v", old.HasTransparent(), dev.HasTransparent()))
	}
	if old.HasRTUOverTCP() != dev.HasRTUOverTCP() {
		msgs = append(msgs, fmt.Sprintf("rtu_over_tcp %v -> %v", old.HasRTUOverTCP(), dev.HasRTUOverTCP()))
	}
	if gw.health == nil && dev.HasHealth() {
		msgs = append(msgs, "health_unit_id enabled")
	}
	return msgs
}
