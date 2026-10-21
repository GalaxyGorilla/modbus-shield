package proxy

import (
	"fmt"
	"net"
	"sync"

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

// NewRunner builds one gateway per config device. met may be nil
// (no metrics).
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

// Run binds all listeners and serves them until Stop. The first bind
// error aborts startup and closes earlier listeners.
func (r *Runner) Run() error {
	for _, gw := range r.gws {
		ln, err := net.Listen("tcp", gw.dev.ListenAddr)
		if err != nil {
			r.closeListeners()
			return fmt.Errorf("bind %s: %w", gw.dev.ListenAddr, err)
		}
		r.lns = append(r.lns, ln)
	}
	close(r.bound)
	errCh := make(chan error, len(r.gws))
	for i, gw := range r.gws {
		ln := r.lns[i]
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			errCh <- gw.Serve(ln)
		}()
	}
	return <-errCh
}

// Stop closes all listeners and waits for client loops to exit.
func (r *Runner) Stop() {
	r.closeListeners()
	r.wg.Wait()
	for _, gw := range r.gws {
		gw.up.close()
	}
}

func (r *Runner) closeListeners() {
	for _, ln := range r.lns {
		ln.Close()
	}
}
