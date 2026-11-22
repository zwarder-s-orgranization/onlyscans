package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewHandler returns an HTTP handler serving /healthz, /readyz, and Prometheus /metrics.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	okHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
	mux.HandleFunc("/healthz", okHandler)
	mux.HandleFunc("/readyz", okHandler)
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

// Start serves liveness (/healthz) and Prometheus metrics (/metrics) on addr in the background
// with explicit timeouts and graceful shutdown on ctx cancellation.
func Start(ctx context.Context, addr string) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			slog.Warn("health server shutdown", "addr", addr, "err", err)
		}
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("health server stopped", "addr", addr, "err", err)
		}
	}()
}
