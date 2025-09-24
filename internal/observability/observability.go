package observability

import (
	"context"
	"log/slog"
)

type contextKey string

const (
	observabilityKey = contextKey("OBSERVABILITY")
)

// Observability holds Loggers & Metrics.
// nil *Observability are safe to use.
type Observability struct {
	Logger *slog.Logger
}

// Log returns inner Logger or slog.Default().
func (self *Observability) Log() *slog.Logger {
	if (nil == self) || (nil == self.Logger) {
		return slog.Default()
	}

	return self.Logger
}

// GetObservability returns ctx Observability.
func GetObservability(ctx context.Context) *Observability {
	var rv *Observability
	rv, _ = ctx.Value(observabilityKey).(*Observability)
	return rv
}

// SetObservability returns new Context containing obs.
func SetObservability(ctx context.Context, obs *Observability) context.Context {
	return context.WithValue(ctx, observabilityKey, obs)
}
