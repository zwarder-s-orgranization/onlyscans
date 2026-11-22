// Reference external LOGIC plugin: demo-risk-router (logic.risk-router).
// Connects outbound to orchestrator:50051 using PLUGIN_TOKEN (ADR-0001 / ADR-0010),
// exposes custom output ports BLOCK / REVIEW / OK, patches branch-local Envelope.gate
// and Envelope.vars["plugins.logic.risk-router.*"], and never mutates Run Findings.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/riskrouter"
	"github.com/secflow/secflow/services/internal/workerclient"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownObs, err := obs.Init(ctx, "demo-risk-router")
	if err != nil {
		slog.Warn("obs init failed", "err", err)
	} else {
		defer func() {
			sCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdownObs(sCtx)
		}()
	}

	orchAddr := envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051")
	workerID := envutil.Get("WORKER_INSTANCE_ID", "demo-risk-router-1")
	namespace := envutil.Get("POD_NAMESPACE", "secflow-sandbox")
	pluginToken := strings.TrimSpace(os.Getenv("PLUGIN_TOKEN"))

	slog.Info("starting demo-risk-router", "orchestrator", orchAddr, "worker_id", workerID, "namespace", namespace)
	if err := workerclient.RunWithConfig(ctx, workerclient.Config{
		Addr:        orchAddr,
		WorkerID:    workerID,
		Namespace:   namespace,
		PluginToken: pluginToken,
		Manifests:   []*secflowv1.PluginManifest{riskrouter.Manifest()},
		Handle: func(_ context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
			return riskrouter.Evaluate(task)
		},
	}); err != nil && ctx.Err() == nil {
		slog.Error("demo-risk-router exited with error", "err", err)
		os.Exit(1)
	}
}
