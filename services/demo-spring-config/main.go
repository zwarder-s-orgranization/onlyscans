package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/sourcetree"
	"github.com/secflow/secflow/services/internal/springscan"
	"github.com/secflow/secflow/services/internal/workerclient"
)

func main() {
	obs.SetupLogger("demo-spring-config")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "demo-spring-config")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}
	m := manifest.One("scan.spring-config", "Spring Config Hardening", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"analyzer"}, true)
	m.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
	if err := workerclient.Run(ctx, envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"), envutil.Get("WORKER_INSTANCE_ID", "demo-spring-config"), []*secflowv1.PluginManifest{m}, func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
		_ = workerclient.ReportProgress(taskCtx, 10, "resolving source tree")
		root, done := sourcetree.Resolve(taskCtx, task.GetEnvelopeJson())
		defer done()
		if root == "" {
			return &secflowv1.NodeResult{
				NodeRunId:         task.GetNodeRunId(),
				RunId:             task.GetRunId(),
				NodeId:            task.GetNodeId(),
				PluginId:          "scan.spring-config",
				Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
				ErrorCode:         "MISSING_SOURCE",
				ErrorMessage:      "source root is empty",
				ActiveOutputPorts: []string{"default"},
			}
		}
		if _, err := os.Stat(root); err != nil {
			return &secflowv1.NodeResult{
				NodeRunId:         task.GetNodeRunId(),
				RunId:             task.GetRunId(),
				NodeId:            task.GetNodeId(),
				PluginId:          "scan.spring-config",
				Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
				ErrorCode:         "SCAN_ERROR",
				ErrorMessage:      err.Error(),
				ActiveOutputPorts: []string{"default"},
			}
		}
		if err := taskCtx.Err(); err != nil {
			return &secflowv1.NodeResult{
				NodeRunId:         task.GetNodeRunId(),
				RunId:             task.GetRunId(),
				NodeId:            task.GetNodeId(),
				PluginId:          "scan.spring-config",
				Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
				ErrorCode:         "TASK_CANCELLED",
				ErrorMessage:      err.Error(),
				ActiveOutputPorts: []string{"default"},
			}
		}
		_ = workerclient.ReportProgress(taskCtx, 50, "scanning spring configuration")
		var findings []*secflowv1.Finding
		for _, f := range springscan.Scan(root) {
			line := int32(f.Line)
			findings = append(findings, &secflowv1.Finding{
				Path:         f.Path,
				FindingClass: f.Class,
				Line:         &line,
				Description:  f.Description,
				Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
				Severity:     secflowv1.Severity_SEVERITY_HIGH,
				PluginId:     "scan.spring-config",
			})
		}
		_ = workerclient.ReportProgress(taskCtx, 100, "spring config scan completed")
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "scan.spring-config",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings:          findings,
			ActiveOutputPorts: []string{"default"},
		}
	}); err != nil && ctx.Err() == nil {
		slog.Error("worker", "err", err)
		os.Exit(1)
	}
}
