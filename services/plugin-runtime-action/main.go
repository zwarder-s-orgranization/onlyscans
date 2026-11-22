package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/declruntime"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/obs"
)

func main() {
	obs.SetupLogger("plugin-runtime-action")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "plugin-runtime-action")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}

	httpserver.Start(ctx, envutil.Get("HTTP_ADDR", ":8091"))

	workerID := strings.TrimSpace(os.Getenv("WORKER_INSTANCE_ID"))
	if workerID == "" {
		if host, hErr := os.Hostname(); hErr == nil && host != "" {
			workerID = "plugin-runtime-action-" + host
		} else {
			workerID = "plugin-runtime-action"
		}
	}
	allowDevHTTP := os.Getenv("SECFLOW_ENV") != "production" && os.Getenv("ALLOW_DEV_EGRESS_LOCAL") == "1"

	cfg := declruntime.Config{
		OrchestratorAddr: envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"),
		WorkerID:         workerID,
		Namespace:        envutil.Get("POD_NAMESPACE", "secflow-sandbox"),
		ServiceToken:     envutil.Get("SERVICE_TOKEN", "dev-service-token"),
		Tier:             declruntime.TierAction,
		HandleTask: func(taskCtx context.Context, conn *grpc.ClientConn, entry declruntime.SpecEntry, task *secflowv1.NodeTask) *secflowv1.NodeResult {
			return declruntime.HandleActionTask(taskCtx, conn, entry, task, allowDevHTTP)
		},
	}
	if err := declruntime.Run(ctx, cfg); err != nil && ctx.Err() == nil {
		slog.Error("plugin-runtime-action stopped", "err", err)
		os.Exit(1)
	}
}
