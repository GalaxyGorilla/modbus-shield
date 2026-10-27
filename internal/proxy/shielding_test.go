package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

// TestGatewayFairScheduling pins the observable fairness property: with
// several clients polling the same slow device, no client is starved —
// the device must not see one client three times in a row. The FIFO gate
// makes that ordering explicit (a plain mutex gives no such promise);
// what is asserted here is the property, not the mechanism. The device
// records the unit ID of every request, which identifies the client.
func TestGatewayFairScheduling(t *testing.T) {
	const nClients = 4
	const perClient = 4

	dev := newFakeDeviceCfg(t, fakeDeviceCfg{
		RespondDelay:   15 * time.Millisecond,
		RecordRequests: true,
		UnitValues:     true,
	})
	front := startGateway(t, config.Device{DeviceAddr: dev.Addr(), TimeoutMs: 8000})

	var wg sync.WaitGroup
	errs := make(chan error, nClients)
	for i := 1; i <= nClients; i++ {
		unit := uint8(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialErr(front)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			for r := 0; r < perClient; r++ {
				val, err := readOnUnit(t, conn, unit)
				if err != nil {
					errs <- err
					return
				}
				if want := uint16(0xCA00) | uint16(unit); val != want {
					errs <- errValue(val)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	order := dev.Requests()
	if len(order) != nClients*perClient {
		t.Fatalf("device saw %d requests, want %d (order %v)", len(order), nClients*perClient, order)
	}
	// A client may appear at most twice in a row (once in flight, once
	// re-admitted right after its own response); three in a row means a
	// quiet client was overtaken, i.e. the queue is not FIFO.
	run := 1
	for i := 1; i < len(order); i++ {
		if order[i] == order[i-1] {
			run++
		} else {
			run = 1
		}
		if run > 2 {
			t.Fatalf("unfair scheduling: client %d served %d times in a row\norder: %v", order[i], run, order)
		}
	}
}

// TestGatewayPerClientRateLimit pins the starvation fix: a single runaway
// poller is capped by rate_per_client_per_sec, and its REJECTED requests
// must not consume the shared rate_per_sec budget (the per-client check
// runs first) — so the other clients still get through.
func TestGatewayPerClientRateLimit(t *testing.T) {
	dev := newFakeDevice(t)
	front := startGateway(t, config.Device{
		DeviceAddr:          dev.Addr(),
		RatePerSec:          2, // shared: barely enough for one of each client
		RatePerClientPerSec: 1, // per connection: one request
	})

	hog := dial(t, front)
	defer hog.Close()
	admitted, busy := 0, 0
	for i := 0; i < 5; i++ {
		if _, err := readOn(t, hog); err != nil {
			busy++
		} else {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("hog admitted %d of 5 requests, want exactly 1 (per-client cap)", admitted)
	}
	if busy != 4 {
		t.Fatalf("hog rejected %d of 5 requests, want 4 (0x06)", busy)
	}

	// The shared budget was charged once, not five times: a second client
	// still gets its own request through (it would be starved if the
	// hog's rejections had consumed the shared tokens).
	quiet := dial(t, front)
	defer quiet.Close()
	if _, err := readOn(t, quiet); err != nil {
		t.Fatalf("quiet client rejected: %v (the hog drained the shared budget)", err)
	}
}
