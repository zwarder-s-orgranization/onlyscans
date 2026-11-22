package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/declruntime"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/sourcetree"
)

func main() {
	obs.SetupLogger("plugin-runtime-internal")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "plugin-runtime-internal")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}

	httpserver.Start(ctx, envutil.Get("HTTP_ADDR", ":8090"))

	workerID := strings.TrimSpace(os.Getenv("WORKER_INSTANCE_ID"))
	if workerID == "" {
		if host, hErr := os.Hostname(); hErr == nil && host != "" {
			workerID = "plugin-runtime-internal-" + host
		} else {
			workerID = "plugin-runtime-internal"
		}
	}

	if err := blobstore.WaitReachable(ctx, 15*time.Second); err != nil && ctx.Err() == nil {
		slog.Warn("garage reachability wait timed out", "err", err)
	}

	cfg := declruntime.Config{
		OrchestratorAddr: envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"),
		WorkerID:         workerID,
		Namespace:        envutil.Get("POD_NAMESPACE", "secflow-sandbox"),
		ServiceToken:     envutil.Get("SERVICE_TOKEN", "dev-service-token"),
		Tier:             declruntime.TierInternal,
		HandleTask: func(taskCtx context.Context, _ *grpc.ClientConn, entry declruntime.SpecEntry, task *secflowv1.NodeTask) *secflowv1.NodeResult {
			return declruntime.HandleInternalTask(taskCtx, entry, task, sourcetree.Resolve)
		},
	}
	if err := declruntime.Run(ctx, cfg); err != nil && ctx.Err() == nil {
		slog.Error("plugin-runtime-internal stopped", "err", err)
		os.Exit(1)
	}
}
