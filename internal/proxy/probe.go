package proxy

import (
	"fmt"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// ProbeDevice performs one device-side exchange with the same transport and
// correlation settings as the gateway. It is used by the commissioning
// selftest, where bypassing device TLS or RTU-over-TCP would report a healthy
// configured deployment as broken.
func ProbeDevice(dev config.Device, req mbtcp.ADU, timeout time.Duration) (mbtcp.ADU, error) {
	if dev.HasTransparent() {
		return mbtcp.ADU{}, fmt.Errorf("transparent mode has no fixed upstream target to probe")
	}
	var tlsCfgErr error
	up := newUpstream(dev.DeviceAddr, dev.Name, probeLogger{}, nil)
	if dev.HasDeviceTLS() {
		up.tlsDial, tlsCfgErr = deviceTLSConfigFor(dev)
		if tlsCfgErr != nil {
			return mbtcp.ADU{}, tlsCfgErr
		}
	}
	up.rtuOverTCP = dev.HasRTUOverTCP()
	up.setLenient(dev.HasLenientCorrelation())
	defer up.close()
	return up.exchange(req, timeout, 0, nil)
}

type probeLogger struct{}

func (probeLogger) Debugf(string, ...any) {}
func (probeLogger) Infof(string, ...any)  {}
func (probeLogger) Warnf(string, ...any)  {}
func (probeLogger) Errorf(string, ...any) {}
