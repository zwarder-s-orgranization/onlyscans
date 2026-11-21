// Package main implements the one-shot idempotent Garage bootstrapper for SecFlow.
// It waits for Garage Admin API readiness, assigns a single-node layout if needed,
// creates all four SecFlow buckets, writes S3 credentials to GARAGE_CRED_FILE,
// and seeds secflow-catalogs/default.json from the bundled vulnerability database.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/obs"
)

func main() {
	obs.SetupLogger("garage-init")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var lastErr error
	for attempt := 1; attempt <= 30; attempt++ {
		if err := blobstore.Ensure(ctx); err == nil {
			slog.Info("garage bootstrap completed", "attempt", attempt)
			return
		} else {
			lastErr = err
			slog.Warn("garage bootstrap retry", "attempt", attempt, "err", err)
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			slog.Error("garage bootstrap cancelled", "err", ctx.Err())
			os.Exit(1)
		case <-timer.C:
		}
	}
	slog.Error("garage bootstrap failed", "err", lastErr)
	os.Exit(1)
}
