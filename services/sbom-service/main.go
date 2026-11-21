package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/gradleparser"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/sourcetree"
	"github.com/secflow/secflow/services/internal/workerclient"
)

type sbomParams struct {
	IncludeDevDependencies *bool `json:"includeDevDependencies"`
}

type envelopeInput struct {
	Findings []envelopeFinding `json:"findings"`
}

type envelopeFinding struct {
	Category    string `json:"category"`
	Group       string `json:"group"`
	Artifact    string `json:"artifact"`
	Version     string `json:"version"`
	AdvisoryID  string `json:"advisoryId"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type cdxDocument struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Version         int                `json:"version"`
	Components      []cdxComponent     `json:"components"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxComponent struct {
	BomRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
	Scope   string `json:"scope,omitempty"`
}

type cdxVulnerability struct {
	ID          string          `json:"id"`
	Ratings     []cdxRating     `json:"ratings,omitempty"`
	Description string          `json:"description,omitempty"`
	Affects     []cdxAffectItem `json:"affects"`
}

type cdxRating struct {
	Severity string `json:"severity"`
}

type cdxAffectItem struct {
	Ref string `json:"ref"`
}

func main() {
	obs.SetupLogger("sbom-service")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "sbom-service")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}

	m := manifest.One("sbom.generate", "SBOM", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"sbom"}, false)
	m.RuntimeLanguage = "go"
	m.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY

	if err := workerclient.Run(ctx, envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"), envutil.Get("WORKER_INSTANCE_ID", "sbom-service"), []*secflowv1.PluginManifest{m}, func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
		return executeSBOMTask(taskCtx, task, sourcetree.Resolve, blobstore.Configured, blobstore.Put)
	}); err != nil && ctx.Err() == nil {
		slog.Error("worker", "err", err)
		os.Exit(1)
	}
}

func executeSBOMTask(
	ctx context.Context,
	task *secflowv1.NodeTask,
	resolveSource func(context.Context, []byte) (string, func()),
	blobConfigured func() bool,
	blobPut func(context.Context, string, string, []byte) error,
) *secflowv1.NodeResult {
	_ = workerclient.ReportProgress(ctx, 10, "resolving source tree")
	root, done := resolveSource(ctx, task.GetEnvelopeJson())
	defer done()
	if root == "" {
		return failResult(task, "MISSING_SOURCE", "source root is empty")
	}
	if err := ctx.Err(); err != nil {
		return failResult(task, "TASK_CANCELLED", err.Error())
	}

	includeDev := parseIncludeDevDependencies(task.GetParamsJson())
	_ = workerclient.ReportProgress(ctx, 50, "parsing gradle dependencies for CycloneDX SBOM")
	deps, err := gradleparser.ParseProject(root)
	if err != nil {
		slog.Error("parse gradle for sbom", "err", err)
		return failResult(task, "PARSE_ERROR", err.Error())
	}

	doc := buildCycloneDX(deps, includeDev, extractSCAFindings(task.GetEnvelopeJson()))
	raw, err := json.Marshal(doc)
	if err != nil {
		slog.Error("marshal sbom", "err", err)
		return failResult(task, "MARSHAL_ERROR", "sbom marshal failed")
	}

	var payloadKey string
	if blobConfigured != nil && blobConfigured() && blobPut != nil {
		payloadKey = fmt.Sprintf("runs/%s/sbom.cdx.json", task.GetRunId())
		_ = workerclient.ReportProgress(ctx, 85, "uploading sbom.cdx.json to garage")
		if err := blobPut(ctx, "secflow-sbom", payloadKey, raw); err != nil {
			slog.Error("upload sbom to garage", "run_id", task.GetRunId(), "key", payloadKey, "err", err)
			return failResult(task, "UPLOAD_ERROR", fmt.Sprintf("upload sbom to garage: %v", err))
		}
	}

	_ = workerclient.ReportProgress(ctx, 100, "sbom generated")
	return &secflowv1.NodeResult{
		NodeRunId:         task.GetNodeRunId(),
		RunId:             task.GetRunId(),
		NodeId:            task.GetNodeId(),
		PluginId:          "sbom.generate",
		Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		EnvelopePatchJson: raw,
		PayloadS3Key:      payloadKey,
		ActiveOutputPorts: []string{"default"},
	}
}

func failResult(task *secflowv1.NodeTask, code, msg string) *secflowv1.NodeResult {
	return &secflowv1.NodeResult{
		NodeRunId:         task.GetNodeRunId(),
		RunId:             task.GetRunId(),
		NodeId:            task.GetNodeId(),
		PluginId:          "sbom.generate",
		Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
		ErrorCode:         code,
		ErrorMessage:      msg,
		ActiveOutputPorts: []string{"default"},
	}
}

func parseIncludeDevDependencies(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var p sbomParams
	if err := json.Unmarshal(raw, &p); err != nil || p.IncludeDevDependencies == nil {
		return false
	}
	return *p.IncludeDevDependencies
}

func extractSCAFindings(envelopeRaw []byte) []envelopeFinding {
	if len(envelopeRaw) == 0 {
		return nil
	}
	var env envelopeInput
	if err := json.Unmarshal(envelopeRaw, &env); err != nil {
		return nil
	}
	var out []envelopeFinding
	for _, f := range env.Findings {
		if !strings.EqualFold(strings.TrimSpace(f.Category), "SCA") {
			continue
		}
		if strings.TrimSpace(f.AdvisoryID) == "" || strings.TrimSpace(f.Group) == "" || strings.TrimSpace(f.Artifact) == "" || strings.TrimSpace(f.Version) == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func buildCycloneDX(deps []gradleparser.Dependency, includeDev bool, scaFindings []envelopeFinding) cdxDocument {
	components := make([]cdxComponent, 0, len(deps))
	compIdxByPURL := make(map[string]int, len(deps))
	for _, d := range deps {
		if !includeDev && d.IsDev {
			continue
		}
		purl := mavenPURL(d.Group, d.Artifact, d.Version)
		scope := "required"
		if d.IsDev {
			scope = "optional"
		}
		if idx, exists := compIdxByPURL[purl]; exists {
			if components[idx].Scope == "optional" && scope == "required" {
				components[idx].Scope = "required"
			}
			continue
		}
		compIdxByPURL[purl] = len(components)
		components = append(components, cdxComponent{
			BomRef:  purl,
			Type:    "library",
			Group:   d.Group,
			Name:    d.Artifact,
			Version: d.Version,
			Purl:    purl,
			Scope:   scope,
		})
	}

	vulns := make([]cdxVulnerability, 0, len(scaFindings))
	byID := make(map[string]int, len(scaFindings))
	affectsSeen := make(map[string]map[string]struct{}, len(scaFindings))

	for _, f := range scaFindings {
		id := strings.TrimSpace(f.AdvisoryID)
		purl := mavenPURL(strings.TrimSpace(f.Group), strings.TrimSpace(f.Artifact), strings.TrimSpace(f.Version))
		if idx, exists := byID[id]; exists {
			if _, seen := affectsSeen[id][purl]; !seen {
				affectsSeen[id][purl] = struct{}{}
				vulns[idx].Affects = append(vulns[idx].Affects, cdxAffectItem{Ref: purl})
			}
			continue
		}
		byID[id] = len(vulns)
		affectsSeen[id] = map[string]struct{}{purl: {}}

		var ratings []cdxRating
		if sev := strings.ToLower(strings.TrimSpace(f.Severity)); sev != "" {
			ratings = []cdxRating{{Severity: sev}}
		}
		desc := strings.TrimSpace(f.Description)
		if desc == "" {
			desc = fmt.Sprintf("Known vulnerability %s affecting %s:%s@%s", id, f.Group, f.Artifact, f.Version)
		}
		vulns = append(vulns, cdxVulnerability{
			ID:          id,
			Ratings:     ratings,
			Description: desc,
			Affects:     []cdxAffectItem{{Ref: purl}},
		})
	}

	return cdxDocument{
		BomFormat:       "CycloneDX",
		SpecVersion:     "1.6",
		Version:         1,
		Components:      components,
		Vulnerabilities: vulns,
	}
}

func mavenPURL(group, artifact, version string) string {
	return "pkg:maven/" + group + "/" + artifact + "@" + version
}
