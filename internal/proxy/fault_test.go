package proxy

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

// TestGatewayPartialDeviceResponseRecovers sends only the first five bytes
// of the device's first response and closes the connection. The gateway must
// turn that into a gateway-target-failure exception (not hang), drop the
// broken upstream connection, and serve the next request on a fresh one.
func TestGatewayPartialDeviceResponseRecovers(t *testing.T) {
	dev := newFakeDevice(t)
	var responses atomic.Int32
	relay := newTCPFaultRelay(t, dev.Addr(), func(dir tcpFaultDir, seq int, frame []byte) tcpFaultAction {
		if dir == tcpToClient && responses.Add(1) == 1 {
			return tcpFaultAction{Truncate: 5}
		}
		return tcpFaultAction{}
	})
	front := startGateway(t, config.Device{DeviceAddr: relay.Addr(), TimeoutMs: 500})

	conn := dial(t, front)
	defer conn.Close()

	_, err := readOn(t, conn)
	if err == nil || !strings.Contains(err.Error(), "code=11") {
		t.Fatalf("first read = %v, want a gateway-target-failure exception (code=11)", err)
	}
	if responses.Load() == 0 {
		t.Fatal("the relay did not see the first response")
	}

	val, err := readOn(t, conn)
	if err != nil {
		t.Fatalf("read after a truncated response: %v", err)
	}
	if val != 0xCAFE {
		t.Fatalf("read after recovery = %#x, want 0xCAFE", val)
	}
}

// TestGatewayDeviceResetRecovers closes the device-side connection after the
// first request. The client gets a gateway-target-failure exception and the
// next request reconnects.
func TestGatewayDeviceResetRecovers(t *testing.T) {
	dev := newFakeDevice(t)
	var requests atomic.Int32
	relay := newTCPFaultRelay(t, dev.Addr(), func(dir tcpFaultDir, seq int, frame []byte) tcpFaultAction {
		if dir == tcpToDevice && requests.Add(1) == 1 {
			return tcpFaultAction{Close: true}
		}
		return tcpFaultAction{}
	})
	front := startGateway(t, config.Device{DeviceAddr: relay.Addr(), TimeoutMs: 500})

	conn := dial(t, front)
	defer conn.Close()

	_, err := readOn(t, conn)
	if err == nil || !strings.Contains(err.Error(), "code=11") {
		t.Fatalf("first read = %v, want a gateway-target-failure exception (code=11)", err)
	}
	if requests.Load() == 0 {
		t.Fatal("the relay did not see the first request")
	}

	val, err := readOn(t, conn)
	if err != nil {
		t.Fatalf("read after a device reset: %v", err)
	}
	if val != 0xCAFE {
		t.Fatalf("read after recovery = %#x, want 0xCAFE", val)
	}
}

// TestGatewayDroppedRequestTimesOutRecovers drops the first request and
// keeps the connection open. The upstream deadline must bound the wait, the
// client must get an exception, and the next request must reconnect.
func TestGatewayDroppedRequestTimesOutRecovers(t *testing.T) {
	dev := newFakeDevice(t)
	var requests atomic.Int32
	relay := newTCPFaultRelay(t, dev.Addr(), func(dir tcpFaultDir, seq int, frame []byte) tcpFaultAction {
		if dir == tcpToDevice && requests.Add(1) == 1 {
			return tcpFaultAction{Drop: true}
		}
		return tcpFaultAction{}
	})
	front := startGateway(t, config.Device{DeviceAddr: relay.Addr(), TimeoutMs: 200})

	conn := dial(t, front)
	defer conn.Close()

	start := time.Now()
	_, err := readOn(t, conn)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "code=11") {
		t.Fatalf("first read = %v, want a gateway-target-failure exception (code=11)", err)
	}
	if requests.Load() == 0 {
		t.Fatal("the relay did not see the first request")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("dropped request took %s; the upstream deadline did not bound it", elapsed)
	}

	val, err := readOn(t, conn)
	if err != nil {
		t.Fatalf("read after a dropped request: %v", err)
	}
	if val != 0xCAFE {
		t.Fatalf("read after recovery = %#x, want 0xCAFE", val)
	}
}
