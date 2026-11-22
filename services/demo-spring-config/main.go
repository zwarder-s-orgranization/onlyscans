package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/sourcetree"
	"github.com/secflow/secflow/services/internal/springscan"
	"github.com/secflow/secflow/services/internal/workerclient"
)

const (
	springConfigPluginID = "scan.spring-config"
	defaultPortID        = "default"
	defaultSeverity      = "HIGH"
)

const springConfigParamsSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "checkActuatorExposure": {
      "type": "boolean",
      "default": true,
      "description": "Detect Spring Boot Actuator endpoints exposed with a wildcard (*)."
    },
    "checkPlaintextPasswords": {
      "type": "boolean",
      "default": true,
      "description": "Detect hardcoded plaintext datasource or property passwords in Spring configuration."
    },
    "severity": {
      "type": "string",
      "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      "default": "HIGH",
      "description": "Severity assigned to Spring configuration hardening findings."
    },
    "includePaths": {
      "type": "array",
      "items": {
        "type": "string",
        "minLength": 1
      },
      "default": [],
      "description": "Optional relative path prefixes or glob patterns to include (empty scans all application config files)."
    },
    "excludePaths": {
      "type": "array",
      "items": {
        "type": "string",
        "minLength": 1
      },
      "default": [],
      "description": "Optional relative path prefixes or glob patterns to skip (e.g. src/test/, fixtures/)."
    }
  }
}`

type springConfigParams struct {
	CheckActuatorExposure   *bool    `json:"checkActuatorExposure"`
	CheckPlaintextPasswords *bool    `json:"checkPlaintextPasswords"`
	Severity                string   `json:"severity"`
	IncludePaths            []string `json:"includePaths"`
	ExcludePaths            []string `json:"excludePaths"`
}

func springConfigManifest() *secflowv1.PluginManifest {
	return &secflowv1.PluginManifest{
		PluginId:         springConfigPluginID,
		Version:          "1.0.0",
		DisplayName:      "Spring Config Hardening",
		Description:      "Detects exposed Spring Boot Actuator endpoints and plaintext datasource passwords in application.{yml,yaml,properties}.",
		Category:         secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		Capabilities:     []string{"analyzer"},
		ParamsJsonSchema: []byte(springConfigParamsSchemaJSON),
		InputPorts:       []*secflowv1.PortDefinition{{Id: defaultPortID, Label: defaultPortID}},
		OutputPorts:      []*secflowv1.PortDefinition{{Id: defaultPortID, Label: defaultPortID}},
		RuntimeLanguage:  "go",
		SandboxProfile:   secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:       true,
		MaxConcurrency:   4,
	}
}

func parseSpringConfigParams(raw []byte) (springscan.Options, secflowv1.Severity, error) {
	opts := springscan.DefaultOptions()
	sev := secflowv1.Severity_SEVERITY_HIGH
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return opts, sev, nil
	}
	if trimmed[0] != '{' {
		return opts, sev, fmt.Errorf("invalid params JSON: expected JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var parsed springConfigParams
	if err := dec.Decode(&parsed); err != nil {
		return opts, sev, fmt.Errorf("invalid params JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return opts, sev, fmt.Errorf("invalid params JSON: unexpected trailing data")
	}
	if parsed.CheckActuatorExposure != nil {
		opts.CheckActuatorExposure = *parsed.CheckActuatorExposure
	}
	if parsed.CheckPlaintextPasswords != nil {
		opts.CheckPlaintextPasswords = *parsed.CheckPlaintextPasswords
	}
	if parsed.Severity != "" {
		switch parsed.Severity {
		case "LOW":
			sev = secflowv1.Severity_SEVERITY_LOW
		case "MEDIUM":
			sev = secflowv1.Severity_SEVERITY_MEDIUM
		case defaultSeverity:
			sev = secflowv1.Severity_SEVERITY_HIGH
		case "CRITICAL":
			sev = secflowv1.Severity_SEVERITY_CRITICAL
		default:
			return opts, sev, fmt.Errorf("unsupported severity %q", parsed.Severity)
		}
	}
	opts.IncludePaths = parsed.IncludePaths
	opts.ExcludePaths = parsed.ExcludePaths
	return opts, sev, nil
}

func failedTaskResult(task *secflowv1.NodeTask, errCode, errMsg string) *secflowv1.NodeResult {
	return &secflowv1.NodeResult{
		NodeRunId:         task.GetNodeRunId(),
		RunId:             task.GetRunId(),
		NodeId:            task.GetNodeId(),
		PluginId:          springConfigPluginID,
		Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
		ErrorCode:         errCode,
		ErrorMessage:      errMsg,
		ActiveOutputPorts: []string{defaultPortID},
	}
}

func handleSpringConfigTask(
	ctx context.Context,
	task *secflowv1.NodeTask,
	resolveSource func(context.Context, []byte) (string, func()),
) *secflowv1.NodeResult {
	opts, sev, err := parseSpringConfigParams(task.GetParamsJson())
	if err != nil {
		return failedTaskResult(task, "INVALID_PARAMS", err.Error())
	}
	_ = workerclient.ReportProgress(ctx, 10, "resolving source tree")
	root, done := resolveSource(ctx, task.GetEnvelopeJson())
	defer done()
	if root == "" {
		return failedTaskResult(task, "MISSING_SOURCE", "source root is empty")
	}
	if _, statErr := os.Stat(root); statErr != nil {
		return failedTaskResult(task, "SCAN_ERROR", statErr.Error())
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return failedTaskResult(task, "TASK_CANCELLED", ctxErr.Error())
	}
	_ = workerclient.ReportProgress(ctx, 50, "scanning spring configuration")
	scanned := springscan.ScanWithOptions(root, opts)
	findings := make([]*secflowv1.Finding, 0, len(scanned))
	for _, f := range scanned {
		line := int32(f.Line)
		findings = append(findings, &secflowv1.Finding{
			SourceNodeId: task.GetNodeId(),
			Path:         f.Path,
			FindingClass: f.Class,
			Line:         &line,
			Description:  f.Description,
			Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
			Severity:     sev,
			PluginId:     springConfigPluginID,
		})
	}
	_ = workerclient.ReportProgress(ctx, 100, "spring config scan completed")
	return &secflowv1.NodeResult{
		NodeRunId:         task.GetNodeRunId(),
		RunId:             task.GetRunId(),
		NodeId:            task.GetNodeId(),
		PluginId:          springConfigPluginID,
		Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		Findings:          findings,
		ActiveOutputPorts: []string{defaultPortID},
	}
}

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
	cfg := workerclient.Config{
		Addr:        envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"),
		WorkerID:    envutil.Get("WORKER_INSTANCE_ID", "demo-spring-config"),
		Namespace:   envutil.Get("POD_NAMESPACE", "secflow-sandbox"),
		PluginToken: strings.TrimSpace(os.Getenv("PLUGIN_TOKEN")),
		Manifests:   []*secflowv1.PluginManifest{springConfigManifest()},
		Handle: func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
			return handleSpringConfigTask(taskCtx, task, sourcetree.Resolve)
		},
	}
	if err := workerclient.RunWithConfig(ctx, cfg); err != nil && ctx.Err() == nil {
		slog.Error("worker", "err", err)
		os.Exit(1)
	}
}
