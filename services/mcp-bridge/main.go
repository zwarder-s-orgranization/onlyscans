package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/workerclient"
)

func mcpToolManifest() *secflowv1.PluginManifest {
	if spec, ok := manifest.LookupBuiltin("mcp.tool"); ok {
		rawSchema, _ := paramschema.RawDef("mcp.tool")
		return spec.ToProto(string(rawSchema))
	}
	m := manifest.One("mcp.tool", "MCP Tool Node", secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, []string{"mcp"}, false)
	m.Description = "Invokes one explicitly selected tool on an allowlisted MCP Connection."
	m.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL
	return m
}

func main() {
	obs.SetupLogger("mcp-bridge")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "mcp-bridge")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}
	b := newDefaultBridge()
	httpserver.Start(ctx, envutil.Get("HTTP_ADDR", ":8088"))
	m := mcpToolManifest()
	workerID := envutil.Get("WORKER_INSTANCE_ID", "")
	if workerID == "" {
		if host, hErr := os.Hostname(); hErr == nil && host != "" {
			workerID = "mcp-bridge-" + host
		} else {
			workerID = "mcp-bridge"
		}
	}
	if err := workerclient.Run(ctx, envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"), workerID, []*secflowv1.PluginManifest{m}, b.callTool); err != nil && ctx.Err() == nil {
		slog.Error("worker", "err", err)
		os.Exit(1)
	}
}
