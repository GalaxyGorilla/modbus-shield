package proxy

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
)

// Runner owns all gateway instances and listeners. Created from a
// validated config; Run blocks until Stop.
type Runner struct {
	log   Logger
	met   Metrics
	gws   []*gateway
	lns   []net.Listener
	wg    sync.WaitGroup
	bound chan struct{}
}

// NewRunner builds one gateway per config device. A device may carry
// extra_listen addresses (B10): every listener is served by the same
// gateway so all of its front doors share one upstream connection and
// one set of shielding limits. met may be nil (no metrics).
func NewRunner(cfg *config.Config, log Logger, met Metrics) (*Runner, error) {
	met = metricsOrNop(met)
	r := &Runner{log: log, met: met, bound: make(chan struct{})}
	for i := range cfg.Devices {
		gw, err := newGateway(cfg.Devices[i], log, met)
		if err != nil {
			return nil, err
		}
		r.gws = append(r.gws, gw)
	}
	return r, nil
}

// listenerAddrs returns every front-leg address for a gateway: the
// primary listen_addr plus any extra_listen entries.
func listenerAddrs(gw *gateway) []string {
	addrs := make([]string, 0, 1+len(gw.dev.ExtraListen))
	addrs = append(addrs, gw.dev.ListenAddr)
	addrs = append(addrs, gw.dev.ExtraListen...)
	return addrs
}

// Run binds all listeners and serves them until Stop. The first bind
// error aborts startup and closes earlier listeners.
func (r *Runner) Run() error {
	for _, gw := range r.gws {
		for _, addr := range listenerAddrs(gw) {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				r.closeListeners()
				return fmt.Errorf("bind %s: %w", addr, err)
			}
			r.lns = append(r.lns, ln)
		}
	}
	close(r.bound)
	errCh := make(chan error, len(r.lns))
	for i, gw := range r.gws {
		n := len(listenerAddrs(gw))
		for _, ln := range r.lns[i : i+n] {
			ln := ln
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				errCh <- gw.Serve(ln)
			}()
		}
	}
	return <-errCh
}

// Stop shuts the gateways down: listeners first (no new clients), then a
// bounded drain of the client handlers so in-flight responses are not cut
// off mid-write, then the device connections. Always terminates — idle
// clients are force-closed once the drain grace period expires.
func (r *Runner) Stop() {
	r.closeListeners()
	r.wg.Wait()
	for _, gw := range r.gws {
		gw.drain(drainGrace)
	}
	for _, gw := range r.gws {
		gw.up.close()
	}
}

// drainGrace bounds how long Stop waits for in-flight client handlers
// before force-closing the remaining (idle) client connections.
const drainGrace = 5 * time.Second

func (r *Runner) closeListeners() {
	for _, ln := range r.lns {
		ln.Close()
	}
}
