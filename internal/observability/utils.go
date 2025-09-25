package observability

import (
	"log/slog"
	"testing"
)

// SetTestDebugLogging assigns DEBUG level to slog Default logger for test duration
func SetTestDebugLogging(t *testing.T) {
	oldLevel := slog.SetLogLoggerLevel(slog.LevelDebug)
	if oldLevel != slog.LevelDebug {
		t.Logf("Setting slog level to %s", slog.LevelDebug)
		t.Cleanup(func() {
			t.Logf("Restoring slog level to %s", oldLevel)
			slog.SetLogLoggerLevel(oldLevel)
		})
	}
}
