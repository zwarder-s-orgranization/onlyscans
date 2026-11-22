package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/kotlinscan"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/protoconv"
	"github.com/secflow/secflow/services/internal/sourcetree"
	"github.com/secflow/secflow/services/internal/workerclient"
)

func main() {
	obs.SetupLogger("worker-kotlin")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "worker-kotlin")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}

	if err := blobstore.WaitReachable(ctx, 15*time.Second); err != nil && ctx.Err() == nil {
		slog.Warn("garage reachability wait timed out", "err", err)
	}

	manifests := workerManifests()
	if err := workerclient.Run(ctx, envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"), envutil.Get("WORKER_INSTANCE_ID", "worker-kotlin"), manifests, func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
		_ = workerclient.ReportProgress(taskCtx, 10, "resolving source tree")
		root, done := sourcetree.Resolve(taskCtx, task.GetEnvelopeJson())
		defer done()
		if root == "" {
			slog.Error("kotlin scan failed: empty source root", "run_id", task.GetRunId(), "node_id", task.GetNodeId())
			return &secflowv1.NodeResult{
				NodeRunId:         task.GetNodeRunId(),
				RunId:             task.GetRunId(),
				NodeId:            task.GetNodeId(),
				PluginId:          task.GetPluginId(),
				Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
				ErrorCode:         "MISSING_SOURCE",
				ErrorMessage:      "source root is empty",
				ActiveOutputPorts: []string{"default"},
			}
		}
		_ = workerclient.ReportProgress(taskCtx, 40, "running kotlin static analysis")
		got, err := scanTree(taskCtx, task.GetPluginId(), root, task.GetParamsJson())
		if err != nil {
			slog.Error("kotlin scan failed", "run_id", task.GetRunId(), "node_id", task.GetNodeId(), "err", err)
			return &secflowv1.NodeResult{
				NodeRunId:         task.GetNodeRunId(),
				RunId:             task.GetRunId(),
				NodeId:            task.GetNodeId(),
				PluginId:          task.GetPluginId(),
				Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
				ErrorCode:         "SCAN_ERROR",
				ErrorMessage:      err.Error(),
				ActiveOutputPorts: []string{"default"},
			}
		}
		findings := toProtoFindings(task.GetPluginId(), got)
		_ = workerclient.ReportProgress(taskCtx, 100, "kotlin analysis completed")
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          task.GetPluginId(),
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings:          findings,
			ActiveOutputPorts: []string{"default"},
		}
	}); err != nil && ctx.Err() == nil {
		slog.Error("worker", "err", err)
		os.Exit(1)
	}
}

func workerManifests() []*secflowv1.PluginManifest {
	secManifest := manifest.One("scan.secrets", "Secrets", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"analyzer"}, false)
	secManifest.RuntimeLanguage = "kotlin-jvm"
	secManifest.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY

	sastManifest := manifest.One("scan.sast.kotlin", "Kotlin SAST", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"analyzer"}, false)
	sastManifest.RuntimeLanguage = "kotlin-jvm"
	sastManifest.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY

	return []*secflowv1.PluginManifest{secManifest, sastManifest}
}

func toProtoFindings(pluginID string, in []kotlinscan.Finding) []*secflowv1.Finding {
	findings := make([]*secflowv1.Finding, 0, len(in))
	for _, f := range in {
		line := int32(f.Line)
		pf := &secflowv1.Finding{
			Path:         f.Path,
			FindingClass: f.Class,
			Category:     protoconv.CategoryProto(f.Category),
			Severity:     protoconv.SeverityProto(f.Severity),
			Description:  f.Description,
			Remediation:  f.Remediation,
			Line:         &line,
			PluginId:     pluginID,
		}
		if f.EndLine > 0 {
			endLine := int32(f.EndLine)
			if endLine < line {
				endLine = line
			}
			if endLine > line+14 {
				endLine = line + 14
			}
			pf.EndLine = &endLine
		}
		findings = append(findings, pf)
	}
	return findings
}
