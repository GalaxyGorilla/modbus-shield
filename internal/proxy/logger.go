package proxy

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
