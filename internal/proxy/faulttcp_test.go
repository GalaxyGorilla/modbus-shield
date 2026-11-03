package proxy

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
)

// tcpFaultDir says which leg of the relay a frame is on.
type tcpFaultDir int

const (
	tcpToDevice tcpFaultDir = iota
	tcpToClient
)

// tcpFaultAction is what the relay should do with one complete MBAP frame.
type tcpFaultAction struct {
	Drop     bool
	Close    bool
	Truncate int
	Delay    time.Duration
}

// tcpFaultFunc decides the action for one frame. seq starts at 1 per
// direction and counts every frame, including dropped ones.
type tcpFaultFunc func(dir tcpFaultDir, seq int, frame []byte) tcpFaultAction

// tcpFaultRelay is a frame-aware TCP relay between one proxy and one device.
// It exists because the failure modes that matter for a stream proxy —
// a truncated response, a reset mid-exchange, a request that never arrives —
// are timing-dependent in the real world but can be made deterministic here.
type tcpFaultRelay struct {
	ln       net.Listener
	upstream string
	fault    tcpFaultFunc

	closed chan struct{}
	wg     sync.WaitGroup
}

func newTCPFaultRelay(t *testing.T, upstream string, fault tcpFaultFunc) *tcpFaultRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fault relay listen: %v", err)
	}
	if fault == nil {
		fault = func(tcpFaultDir, int, []byte) tcpFaultAction { return tcpFaultAction{} }
	}
	r := &tcpFaultRelay{
		ln:       ln,
		upstream: upstream,
		fault:    fault,
		closed:   make(chan struct{}),
	}
	r.wg.Add(1)
	go r.accept()
	t.Cleanup(r.Close)
	return r
}

func (r *tcpFaultRelay) Addr() string { return r.ln.Addr().String() }

func (r *tcpFaultRelay) Close() {
	select {
	case <-r.closed:
		return
	default:
		close(r.closed)
	}
	_ = r.ln.Close()
	r.wg.Wait()
}

func (r *tcpFaultRelay) accept() {
	defer r.wg.Done()
	for {
		client, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.serve(client)
		}()
	}
}

func (r *tcpFaultRelay) serve(client net.Conn) {
	defer client.Close()
	device, err := net.Dial("tcp", r.upstream)
	if err != nil {
		return
	}
	defer device.Close()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = client.Close()
			_ = device.Close()
		})
	}
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.pump(tcpToDevice, client, device)
		stop()
	}()
	go func() {
		defer wg.Done()
		r.pump(tcpToClient, device, client)
		stop()
	}()
	wg.Wait()
}

func (r *tcpFaultRelay) pump(dir tcpFaultDir, src, dst net.Conn) {
	seq := 0
	for {
		adu, err := mbtcp.ReadADU(src)
		if err != nil {
			return
		}
		seq++
		frame := adu.Frame()
		act := r.fault(dir, seq, frame)
		if act.Delay > 0 {
			time.Sleep(act.Delay)
		}
		if act.Drop {
			continue
		}
		if act.Truncate > 0 && act.Truncate < len(frame) {
			_, _ = dst.Write(frame[:act.Truncate])
			return
		}
		if _, err := dst.Write(frame); err != nil {
			return
		}
		if act.Close {
			return
		}
	}
}
