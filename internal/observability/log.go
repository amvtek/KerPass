package observability

import (
	"io"
	"log/slog"
	"math"
)

var noopLogger *slog.Logger

// NoopLogger returns a disabled Logger
func NoopLogger() *slog.Logger {
	return noopLogger
}

func init() {
	hdlr := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.Level(math.MaxInt)})
	noopLogger = slog.New(hdlr)
}
