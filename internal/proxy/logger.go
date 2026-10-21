package proxy

import "time"

// Metrics is the zap-agnostic and prometheus-agnostic observability hook
// injected into the gateway and upstream. All methods must be safe for
// concurrent use; a nil implementation means "no metrics" — every
// implementation must stay nil-receiver-safe so call sites never need
// nil checks.
type Metrics interface {
	IncConnAccepted()                      // front-leg connection accepted
	IncConnRejected()                      // front-leg connection rejected (cap or allow-list)
	ObserveRequest(device, outcome string) // outcome: forwarded | exception_device | exception_policy | exception_rate
	ObserveLatency(device string, d time.Duration)
	IncUpstreamError()                  // upstream forwarding error (dial/timeout/read/write)
	IncStaleDiscard()                   // stale/late upstream response discarded
	IncReconnect()                      // upstream connection re-established after a drop
	SetDeviceUp(device string, up bool) // upstream connection established state
}

// Logger is the minimal logging interface the gateway needs. It matches
// the subset of *zap.SugaredLogger used here, so the real logger is
// injected by main without a hard dependency in this package (observability
// wiring lands with the observability milestone).
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}
