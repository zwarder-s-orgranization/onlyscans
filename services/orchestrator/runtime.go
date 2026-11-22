package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/expr"
	"github.com/secflow/secflow/services/internal/gradleparser"
	"github.com/secflow/secflow/services/internal/lease"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/protoconv"
	"github.com/secflow/secflow/services/internal/report"
	"github.com/secflow/secflow/services/internal/sourcetree"
	"github.com/secflow/secflow/services/internal/urlguard"
)

func mcpOutputVarKey(n engine.Node) string {
	if n.Params != nil {
		if k, ok := n.Params["outputVarKey"].(string); ok && strings.TrimSpace(k) != "" {
			return strings.TrimSpace(k)
		}
	}
	return "mcpToolResult"
}

func sbomRefFromJSON(runID string, raw []byte) *secflowv1.SbomRef {
	var doc struct {
		SpecVersion     string            `json:"specVersion"`
		Components      []json.RawMessage `json:"components"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	_ = json.Unmarshal(raw, &doc)
	specVer := strings.TrimSpace(doc.SpecVersion)
	if specVer == "" {
		specVer = "1.6"
	}
	sum := sha256.Sum256(raw)
	return &secflowv1.SbomRef{
		Bucket:             "secflow-sbom",
		Key:                fmt.Sprintf("runs/%s/sbom.cdx.json", runID),
		Digest:             "sha256:" + hex.EncodeToString(sum[:]),
		SpecVersion:        specVer,
		ComponentCount:     int32(len(doc.Components)),
		VulnerabilityCount: int32(len(doc.Vulnerabilities)),
		GeneratedAt:        timestamppb.Now(),
	}
}

type externalEnvelopePatch struct {
	Findings        *[]engine.Finding                `json:"findings,omitempty"`
	Gate            *engine.GateInfo                 `json:"gate,omitempty"`
	Vars            map[string]string                `json:"vars,omitempty"`
	PortEnvelopes   map[string]externalEnvelopePatch `json:"portEnvelopes,omitempty"`
	ArtifactContent string                           `json:"artifactContent,omitempty"`
}

func isValidFindingCategory(cat string) bool {
	switch strings.ToUpper(strings.TrimSpace(cat)) {
	case "SECRET", "SAST", "SCA":
		return true
	default:
		return false
	}
}

func pluginVarKey(pluginID, key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		return ""
	}
	prefix := "plugins." + pluginID + "."
	if strings.HasPrefix(k, prefix) {
		return k
	}
	return prefix + k
}

func applyNamespacedVars(target map[string]string, pluginID string, vars map[string]string) {
	if target == nil {
		return
	}
	for k, v := range vars {
		if nk := pluginVarKey(pluginID, k); nk != "" {
			target[nk] = v
		}
	}
}

func applyExternalVarsOrFallback(target map[string]string, pluginID string, patchRaw []byte, fallbackKey string) externalEnvelopePatch {
	var patch externalEnvelopePatch
	if len(patchRaw) == 0 {
		return patch
	}
	if err := json.Unmarshal(patchRaw, &patch); err != nil {
		slog.Warn("unmarshal external plugin envelope patch", "plugin_id", pluginID, "err", err)
		target[pluginVarKey(pluginID, fallbackKey)] = string(patchRaw)
		return patch
	}
	if len(patch.Vars) > 0 {
		applyNamespacedVars(target, pluginID, patch.Vars)
	} else if patch.ArtifactContent == "" {
		target[pluginVarKey(pluginID, fallbackKey)] = string(patchRaw)
	}
	return patch
}

// sanitizeNodeArtifactKey validates that an external AI_REPORT artifact key stays
// strictly under runs/<runId>/nodes/<nodeId>/ without traversal or overwriting submission.json.
func sanitizeNodeArtifactKey(runID, nodeID, rawKey string) string {
	key := strings.TrimSpace(rawKey)
	if key == "" || runID == "" || nodeID == "" {
		return ""
	}
	if strings.Contains(key, "\\") || strings.Contains(key, "..") {
		return ""
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+key), "/")
	prefix := fmt.Sprintf("runs/%s/nodes/%s/", runID, nodeID)
	if !strings.HasPrefix(cleaned, prefix) || len(cleaned) <= len(prefix) {
		return ""
	}
	if strings.EqualFold(path.Base(cleaned), "submission.json") {
		return ""
	}
	return cleaned
}

func applyLogicPatch(n engine.Node, base engine.Envelope, patch externalEnvelopePatch) engine.Envelope {
	env := base.Normalize()
	if patch.Findings != nil {
		allowedByID := make(map[string]engine.Finding, len(env.Findings))
		allowedByFP := make(map[string]engine.Finding, len(env.Findings))
		for _, existing := range env.Findings {
			if existing.ID != "" {
				allowedByID[existing.ID] = existing
			}
			if fp := engine.FindingFingerprint(existing); fp != "" {
				allowedByFP[fp] = existing
			}
		}
		filtered := make([]engine.Finding, 0, len(*patch.Findings))
		seen := make(map[string]bool, len(*patch.Findings))
		for _, candidate := range *patch.Findings {
			var matched engine.Finding
			var ok bool
			if candidate.ID != "" {
				matched, ok = allowedByID[candidate.ID]
			}
			if !ok {
				if fp := engine.FindingFingerprint(candidate); fp != "" {
					matched, ok = allowedByFP[fp]
				}
			}
			if !ok {
				continue
			}
			dedupKey := matched.ID
			if dedupKey == "" {
				dedupKey = engine.FindingFingerprint(matched)
			}
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true
			filtered = append(filtered, matched)
		}
		env.Findings = filtered
	}
	if patch.Gate != nil && strings.TrimSpace(patch.Gate.Status) != "" {
		gateCopy := *patch.Gate
		gateCopy.Status = strings.ToUpper(strings.TrimSpace(gateCopy.Status))
		if gateCopy.NodeID == "" {
			gateCopy.NodeID = n.ID
		}
		if gateCopy.EvaluatedAt == "" {
			gateCopy.EvaluatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		env.Gate = &gateCopy
	}
	applyNamespacedVars(env.Vars, n.PluginID, patch.Vars)
	env.RefreshStats()
	return env
}

func filterDeclaredOutputPorts(returned []string, plugManifest *secflowv1.PluginManifest) []string {
	if plugManifest == nil || len(plugManifest.GetOutputPorts()) == 0 {
		if len(returned) == 0 {
			return []string{"default"}
		}
		return returned
	}
	allowed := make(map[string]bool, len(plugManifest.GetOutputPorts()))
	for _, p := range plugManifest.GetOutputPorts() {
		if portID := strings.TrimSpace(p.GetId()); portID != "" {
			allowed[portID] = true
		}
	}
	filtered := make([]string, 0, len(returned))
	for _, h := range returned {
		if allowed[h] {
			filtered = append(filtered, h)
		}
	}
	if len(filtered) == 0 && len(returned) == 0 && allowed["default"] {
		return []string{"default"}
	}
	return filtered
}

func workerResult(n engine.Node, in engine.Envelope, res *secflowv1.NodeResult, plugManifest *secflowv1.PluginManifest) engine.Result {
	preview := slices.Clone(res.GetRedactedPreviewJson())
	if res.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED {
		return engine.Result{Status: "FAILED", Err: res.GetErrorMessage(), RedactedPreview: preview}
	}
	pluginID := res.GetPluginId()
	if pluginID == "" {
		pluginID = n.PluginID
	}
	category := secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED
	if plugManifest != nil {
		category = plugManifest.GetCategory()
	}
	if category == secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED {
		if engine.IsAnalyzer(pluginID) {
			category = secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER
		}
	}

	out := in.Normalize()
	var found []engine.Finding
	if category == secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER && pluginID != "sbom.generate" {
		for _, f := range res.GetFindings() {
			catName := protoconv.CategoryName(f.GetCategory())
			if !isValidFindingCategory(catName) {
				continue
			}
			line := int(f.GetLine())
			endLine := int(f.GetEndLine())
			found = append(found, engine.Finding{
				ID: f.GetFindingId(), Fingerprint: f.GetFingerprint(), SourceNodeID: f.GetSourceNodeId(),
				Class: f.GetFindingClass(), Category: catName,
				Severity: protoconv.TrimEnum(f.GetSeverity().String(), "SEVERITY_"), Path: f.GetPath(),
				Line: line, EndLine: endLine, Group: f.GetGroup(), Artifact: f.GetArtifact(), Version: f.GetVersion(),
				AdvisoryID: f.GetAdvisoryId(), Description: f.GetDescription(), Remediation: f.GetRemediation(),
				MaskedSnippet: f.GetMaskedSnippet(), IsNewVsBaseline: f.GetIsNewVsBaseline(), PluginID: nonEmpty(f.GetPluginId(), pluginID),
			})
		}
		out.Findings = append(out.Findings, found...)
	}

	var portEnvelopes map[string]engine.Envelope
	var artifactKey string
	var artifactContent []byte
	patchRaw := res.GetEnvelopePatchJson()
	switch pluginID {
	case "sbom.generate":
		if len(patchRaw) > 0 {
			out.Vars["sbom"] = string(patchRaw)
		}
	case "ai.explain":
		if len(patchRaw) > 0 {
			out.Vars["explain"] = string(patchRaw)
			var aiInfo engine.AIReportInfo
			if err := json.Unmarshal(patchRaw, &aiInfo); err != nil {
				slog.Warn("unmarshal ai.explain envelope patch", "node_id", n.ID, "err", err)
			} else if aiInfo.ExecutiveSummary != "" {
				if aiInfo.Groups == nil {
					aiInfo.Groups = []engine.AIReportGroupInfo{}
				}
				if aiInfo.Items == nil {
					aiInfo.Items = []engine.AIReportItemInfo{}
				}
				if aiInfo.CreatedAt == "" {
					aiInfo.CreatedAt = time.Now().UTC().Format(time.RFC3339)
				}
				out.AIReport = &aiInfo
			}
		}
	case "mcp.tool":
		if len(patchRaw) > 0 {
			out.Vars[mcpOutputVarKey(n)] = string(patchRaw)
		}
	default:
		switch category {
		case secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC:
			if len(patchRaw) > 0 {
				var patch externalEnvelopePatch
				if err := json.Unmarshal(patchRaw, &patch); err != nil {
					slog.Warn("unmarshal logic plugin envelope patch", "plugin_id", pluginID, "node_id", n.ID, "err", err)
				} else {
					out = applyLogicPatch(n, out, patch)
					if len(patch.PortEnvelopes) > 0 {
						portEnvelopes = make(map[string]engine.Envelope, len(patch.PortEnvelopes))
						for handle, pp := range patch.PortEnvelopes {
							portEnvelopes[handle] = applyLogicPatch(n, out, pp)
						}
					}
				}
			}
		case secflowv1.PluginCategory_PLUGIN_CATEGORY_AI_REPORT:
			runID := res.GetRunId()
			if runID == "" {
				runID = out.RunID
			}
			if key := sanitizeNodeArtifactKey(runID, n.ID, res.GetPayloadS3Key()); key != "" {
				artifactKey = key
				out.Vars[pluginVarKey(pluginID, "artifactKey")] = key
			} else if strings.TrimSpace(res.GetPayloadS3Key()) != "" {
				slog.Warn("rejected unsafe ai_report artifact key", "plugin_id", pluginID, "node_id", n.ID, "key", res.GetPayloadS3Key())
			}
			patch := applyExternalVarsOrFallback(out.Vars, pluginID, patchRaw, "metadata")
			if artifactKey != "" && patch.ArtifactContent != "" {
				artifactContent = []byte(patch.ArtifactContent)
			}
		case secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION:
			_ = applyExternalVarsOrFallback(out.Vars, pluginID, patchRaw, "result")
		}
	}

	out.RefreshStats()
	ports := filterDeclaredOutputPorts(res.GetActiveOutputPorts(), plugManifest)
	return engine.Result{
		Findings:        found,
		Envelope:        out,
		PortEnvelopes:   portEnvelopes,
		ActivePorts:     ports,
		ArtifactKey:     artifactKey,
		ArtifactContent: artifactContent,
		Status:          "SUCCEEDED",
		RedactedPreview: preview,
	}
}

func sbomResult(root string, in engine.Envelope) engine.Result {
	doc := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []any{}}
	if root != "" {
		if deps, err := gradleparser.ParseProject(root); err == nil {
			var components []map[string]string
			for _, d := range deps {
				components = append(components, map[string]string{"type": "library", "group": d.Group, "name": d.Artifact, "version": d.Version, "purl": "pkg:maven/" + d.Group + "/" + d.Artifact + "@" + d.Version})
			}
			doc["components"] = components
		}
	}
	raw, _ := json.Marshal(doc)
	out := in
	if out.Vars == nil {
		out.Vars = map[string]string{}
	}
	out.Vars["sbom"] = string(raw)
	return engine.Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
}

func extraGraphIssues(g *secflowv1.WorkflowGraph) []engine.Issue {
	var out []engine.Issue
	if g == nil {
		return out
	}
	for _, n := range g.GetNodes() {
		params := map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			_ = json.Unmarshal(n.GetParamsJson(), &params)
		}
		if err := paramschema.Check(n.GetPluginId(), params); err != nil {
			out = append(out, engine.Issue{Code: "INVALID_PARAM_SCHEMA", Severity: "ERROR", NodeID: n.GetId(), Message: err.Error()})
		}
		if n.GetPluginId() == "source.git" {
			repo, _ := params["repoUrl"].(string)
			if repo != "" && !strings.Contains(repo, "{{") && !repoAllowed(repo) {
				out = append(out, engine.Issue{Code: "URL_NOT_ALLOWLISTED", Severity: "ERROR", NodeID: n.GetId(), Message: "URL репозитория вне allowlist"})
			}
		}
	}
	return out
}

func repoAllowed(raw string) bool {
	ok, _, _ := urlguard.RepoAllowed(raw, os.Getenv("REPO_ALLOWLIST"))
	return ok
}

func (s *Server) ingestSource(n engine.Node, in engine.Envelope, git bool) engine.Result {
	return s.ingestSourceCtx(context.Background(), n, in, git, "", "")
}

func (s *Server) ingestSourceCtx(ctx context.Context, n engine.Node, in engine.Envelope, git bool, sourceIDOverride, repoURLOverride string) engine.Result {
	if ctx == nil {
		ctx = context.Background()
	}
	n = resolveNodeParams(n, in)
	out := in.Normalize()
	if git {
		repo, _ := n.Params["repoUrl"].(string)
		if strings.TrimSpace(repoURLOverride) != "" {
			repo = strings.TrimSpace(repoURLOverride)
		}
		gitRef, _ := n.Params["gitRef"].(string)
		if bad, ok := expr.HasUnresolved(repo); ok {
			return engine.Result{Status: "FAILED", Err: fmt.Sprintf("unresolved expression %s in source.git repoUrl", bad)}
		}
		if bad, ok := expr.HasUnresolved(gitRef); ok {
			return engine.Result{Status: "FAILED", Err: fmt.Sprintf("unresolved expression %s in source.git gitRef", bad)}
		}
		repo = strings.TrimSpace(repo)
		if repo == "" {
			return engine.Result{Status: "FAILED", Err: "source.git requires non-empty repoUrl"}
		}
		out.Vars["repoUrl"] = repo
		if gitRef != "" {
			out.Vars["gitRef"] = gitRef
		}
		if s.ingest == nil {
			return engine.Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED", Findings: out.Findings}
		}
		callCtx, cancel := context.WithTimeout(obs.ExtractTraceparent(ctx, out.Vars["traceparent"]), 50*time.Second)
		defer cancel()
		runID := out.RunID
		if runID == "" {
			runID = out.Vars["runId"]
		}
		req := &secflowv1.IngestGitRequest{RunId: runID, NodeId: n.ID, RepoUrl: repo, GitRef: gitRef, Traceparent: out.Vars["traceparent"]}
		if secretRef := n.Secrets["gitToken"]; secretRef != "" {
			if tok, err := lease.Sign(s.leaseKey, runID, runID+":"+n.ID, n.ID, "source.git", 2*time.Minute); err == nil {
				req.AuthSecretRef = secretRef
				req.TaskLeaseToken = tok
			}
		}
		resp, err := s.ingest.IngestGit(callCtx, req)
		if err != nil {
			return engine.Result{Status: "FAILED", Err: err.Error()}
		}
		if ref := resp.GetSourceRef(); ref != nil {
			out.Vars["sourceBucket"] = ref.GetBucket()
			out.Vars["sourceKey"] = ref.GetKey()
			out.Vars["sourceId"] = ref.GetSourceId()
			out.SourceRef = sourceRefInfoFromProto(ref)
		}
		return engine.Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED", Findings: out.Findings}
	}

	sourceID, _ := n.Params["sourceId"].(string)
	if strings.TrimSpace(sourceIDOverride) != "" {
		sourceID = strings.TrimSpace(sourceIDOverride)
	}
	if s.ingest == nil {
		if sourceID != "" && sourceID != "pending-upload" {
			out.Vars["sourceId"] = sourceID
		}
		return engine.Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED", Findings: out.Findings}
	}
	if sourceID == "" || sourceID == "pending-upload" {
		return engine.Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED", Findings: out.Findings}
	}
	callCtx, cancel := context.WithTimeout(obs.ExtractTraceparent(ctx, out.Vars["traceparent"]), 50*time.Second)
	defer cancel()
	resp, err := s.ingest.GetSource(callCtx, &secflowv1.GetSourceRequest{SourceId: sourceID})
	if err != nil {
		return engine.Result{Status: "FAILED", Err: err.Error()}
	}
	if ref := resp.GetSourceRef(); ref != nil {
		out.Vars["sourceBucket"] = ref.GetBucket()
		out.Vars["sourceKey"] = ref.GetKey()
		out.Vars["sourceId"] = ref.GetSourceId()
		out.SourceRef = sourceRefInfoFromProto(ref)
	}
	return engine.Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED", Findings: out.Findings}
}

func exprVarsFromEnvelope(in engine.Envelope, runID string) map[string]string {
	if runID == "" {
		runID = in.RunID
	}
	if runID == "" && in.Vars != nil {
		runID = in.Vars["runId"]
	}
	raw, _ := json.Marshal(in)
	return expr.VarsFromEnvelopeJSON(raw, runID)
}

func resolveNodeParams(n engine.Node, in engine.Envelope) engine.Node {
	return resolveNodeParamsWithSecretKeys(n, in, nil)
}

func resolveNodeParamsWithSecretKeys(n engine.Node, in engine.Envelope, secretKeys []string) engine.Node {
	if len(n.Params) == 0 {
		return n
	}
	preserveUnknown := false
	switch n.PluginID {
	case "source.git", "notify.telegram", "notify.webhook", "notify.smtp":
		preserveUnknown = true
	case "mcp.tool", "report.export":
		vars := exprVarsFromEnvelope(in, in.RunID)
		cp := n
		cp.Params = expr.EvalMap(n.Params, vars)
		return cp
	default:
		if _, isBuiltin := manifest.LookupBuiltin(n.PluginID); isBuiltin {
			return n
		}
		preserveUnknown = true
	}

	if !preserveUnknown {
		return n
	}
	vars := exprVarsFromEnvelope(in, in.RunID)
	skip := map[string]bool{}
	for k := range n.Secrets {
		skip[k] = true
	}
	for _, k := range secretKeys {
		if trimmed := strings.TrimSpace(k); trimmed != "" {
			skip[trimmed] = true
		}
	}
	evaluated := make(map[string]any, len(n.Params))
	for k, v := range n.Params {
		if skip[k] {
			evaluated[k] = v
			continue
		}
		evaluated[k] = expr.EvalValuePreserveUnknown(v, vars)
	}
	cp := n
	cp.Params = evaluated
	return cp
}

func wrapHandlersWithExpr(base map[string]engine.Handler) map[string]engine.Handler {
	wrapped := make(map[string]engine.Handler, len(base)+1)
	for pluginID, h := range base {
		if h == nil {
			continue
		}
		fn := h
		wrapped[pluginID] = func(n engine.Node, in engine.Envelope) engine.Result {
			return fn(resolveNodeParams(n, in), in)
		}
	}
	if _, exists := wrapped["report.export"]; !exists {
		wrapped["report.export"] = func(n engine.Node, in engine.Envelope) engine.Result {
			resolved := resolveNodeParams(n, in)
			return engine.Step(resolved, in, nil)
		}
	}
	return wrapped
}

func triggerInfoFromProto(t *secflowv1.TriggerMetadata) engine.TriggerInfo {
	if t == nil {
		return engine.TriggerInfo{Type: "MANUAL"}
	}
	typ := protoconv.TrimEnum(t.GetType().String(), "TRIGGER_TYPE_")
	if typ == "" || typ == "UNSPECIFIED" {
		typ = "MANUAL"
	}
	gp := protoconv.TrimEnum(t.GetGitProvider().String(), "GIT_PROVIDER_")
	if gp == "UNSPECIFIED" {
		gp = ""
	}
	info := engine.TriggerInfo{
		Type:            typ,
		RepoURL:         t.GetRepoUrl(),
		Branch:          t.GetBranch(),
		CommitSHA:       t.GetCommitSha(),
		GitProvider:     gp,
		DeliveryID:      t.GetDeliveryId(),
		TriggeredBy:     t.GetTriggeredBy(),
		CommitStatusURL: t.GetCommitStatusUrl(),
	}
	if t.PrNumber != nil {
		pr := int(t.GetPrNumber())
		info.PRNumber = &pr
	}
	if ts := t.GetTriggeredAt(); ts != nil {
		info.TriggeredAt = ts.AsTime().UTC().Format(time.RFC3339)
	}
	return info
}

func sourceRefInfoFromProto(ref *secflowv1.SourceRef) *engine.SourceRefInfo {
	if ref == nil {
		return nil
	}
	return &engine.SourceRefInfo{
		SourceID:  ref.GetSourceId(),
		Bucket:    ref.GetBucket(),
		Key:       ref.GetKey(),
		SHA256:    ref.GetSha256(),
		RepoName:  ref.GetRepoName(),
		RepoURL:   ref.GetRepoUrl(),
		GitRef:    ref.GetGitRef(),
		CommitSHA: ref.GetCommitSha(),
		SizeBytes: ref.GetSizeBytes(),
		FileCount: int(ref.GetFileCount()),
	}
}

func sourceRefProtoFromInfo(ref *engine.SourceRefInfo) *secflowv1.SourceRef {
	if ref == nil {
		return nil
	}
	return &secflowv1.SourceRef{
		SourceId:  ref.SourceID,
		Bucket:    ref.Bucket,
		Key:       ref.Key,
		Sha256:    ref.SHA256,
		RepoName:  ref.RepoName,
		RepoUrl:   ref.RepoURL,
		GitRef:    ref.GitRef,
		CommitSha: ref.CommitSHA,
		SizeBytes: ref.SizeBytes,
		FileCount: int32(ref.FileCount),
	}
}

func gateResultFromInfo(nodeID string, gate *engine.GateInfo, fallbackPort string) *secflowv1.GateResult {
	statusStr := fallbackPort
	reason := "policy gate evaluated: " + fallbackPort
	if gate != nil {
		if gate.Status != "" {
			statusStr = gate.Status
		}
		if gate.Reason != "" {
			reason = gate.Reason
		}
		if gate.NodeID != "" {
			nodeID = gate.NodeID
		}
	}
	var st secflowv1.GateStatus
	switch strings.ToUpper(statusStr) {
	case "PASS":
		st = secflowv1.GateStatus_GATE_STATUS_PASS
	case "WARN":
		st = secflowv1.GateStatus_GATE_STATUS_WARN
	case "FAIL":
		st = secflowv1.GateStatus_GATE_STATUS_FAIL
	default:
		st = secflowv1.GateStatus_GATE_STATUS_UNSPECIFIED
	}
	return &secflowv1.GateResult{Status: st, NodeId: nodeID, Reason: reason}
}

func envelopeStatsProto(fs []report.Finding) *secflowv1.EnvelopeStats {
	efs := make([]engine.Finding, len(fs))
	for i, f := range fs {
		efs[i] = engine.Finding{Category: f.Category, Severity: f.Severity, Path: f.Path, Class: f.Class}
	}
	s := engine.ComputeStats(efs)
	return &secflowv1.EnvelopeStats{
		Total:       int32(s.Total),
		NewCount:    int32(s.NewCount),
		Critical:    int32(s.Critical),
		High:        int32(s.High),
		Medium:      int32(s.Medium),
		Low:         int32(s.Low),
		SecretCount: int32(s.SecretCount),
		SastCount:   int32(s.SastCount),
		ScaCount:    int32(s.ScaCount),
		MaxSeverity: protoconv.SeverityProto(s.MaxSeverity),
	}
}

func treeOf(ctx context.Context, fallback string, in engine.Envelope) (string, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	raw, _ := json.Marshal(in)
	dir, done := sourcetree.Resolve(ctx, raw)
	if dir == "" {
		return fallback, func() {}
	}
	return dir, done
}

func reportFindingFingerprint(f report.Finding) string {
	return strings.Join([]string{f.Category, f.Path, f.Class, f.Group, f.Artifact, f.AdvisoryID}, "|")
}

func groundedSummaryFromReport(f report.Finding) *secflowv1.GroundedFindingSummary {
	summary := &secflowv1.GroundedFindingSummary{
		Category:     protoconv.CategoryProto(f.Category),
		Path:         f.Path,
		FindingClass: f.Class,
		Group:        f.Group,
		Artifact:     f.Artifact,
		Version:      f.Version,
		AdvisoryId:   f.AdvisoryID,
		Severity:     protoconv.SeverityProto(f.Severity),
	}
	if f.Line > 0 {
		line := int32(f.Line)
		summary.Line = &line
	}
	if f.EndLine > 0 {
		endLine := int32(f.EndLine)
		summary.EndLine = &endLine
	}
	return summary
}

func aiReportFromPayload(items []report.Finding, raw []byte) *secflowv1.AIReport {
	if len(raw) == 0 {
		return aiFromFindings(items)
	}
	var doc struct {
		Quality                      string `json:"quality"`
		ModelID                      string `json:"modelId"`
		ProviderMode                 string `json:"providerMode"`
		PrivacyMode                  string `json:"privacyMode"`
		StrippedHallucinatedAdvisory int32  `json:"strippedHallucinatedAdvisories"`
		Cached                       bool   `json:"cached"`
		PromptHash                   string `json:"promptHash"`
		TokensIn                     int32  `json:"tokensIn"`
		TokensOut                    int32  `json:"tokensOut"`
		LatencyMs                    int64  `json:"latencyMs"`
		ReleaseDecision              string `json:"releaseDecision"`
		ExecutiveSummary             string `json:"executiveSummary"`
		Groups                       []struct {
			Title       string   `json:"title"`
			MaxSeverity string   `json:"maxSeverity"`
			FindingIDs  []string `json:"findingIds"`
			Summary     string   `json:"summary"`
		} `json:"groups"`
		Items []struct {
			FindingID            string   `json:"findingId"`
			Fingerprint          string   `json:"fingerprint"`
			PriorityRank         int32    `json:"priorityRank"`
			PlainLanguageRisk    string   `json:"plainLanguageRisk"`
			BusinessImpact       string   `json:"businessImpact"`
			RemediationSteps     []string `json:"remediationSteps"`
			ReferencedAdvisories []string `json:"referencedAdvisories"`
			Finding              *struct {
				Category     string `json:"category"`
				Path         string `json:"path"`
				Line         *int   `json:"line"`
				FindingClass string `json:"findingClass"`
				Class        string `json:"class"`
				Group        string `json:"group"`
				Artifact     string `json:"artifact"`
				AdvisoryID   string `json:"advisoryId"`
			} `json:"finding"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || strings.TrimSpace(doc.ExecutiveSummary) == "" {
		return aiFromFindings(items)
	}

	type indexedFinding struct {
		canonicalID string
		finding     report.Finding
	}
	byID := make(map[string]indexedFinding, len(items))
	byLineFP := make(map[string][]indexedFinding, len(items))
	byFingerprint := make(map[string][]indexedFinding, len(items))
	for i, f := range items {
		cid := fmt.Sprintf("F-%03d", i+1)
		entry := indexedFinding{canonicalID: cid, finding: f}
		byID[cid] = entry
		fp := reportFindingFingerprint(f)
		byFingerprint[fp] = append(byFingerprint[fp], entry)
		if f.Line > 0 {
			lfp := fmt.Sprintf("%s|%d", fp, f.Line)
			byLineFP[lfp] = append(byLineFP[lfp], entry)
		}
	}

	usedCanonical := make(map[string]bool, len(items))
	pickCandidate := func(candidates []indexedFinding) (indexedFinding, bool) {
		for _, c := range candidates {
			if !usedCanonical[c.canonicalID] {
				return c, true
			}
		}
		if len(candidates) > 0 {
			return candidates[0], true
		}
		return indexedFinding{}, false
	}

	remappedID := make(map[string]string, len(doc.Items))
	var reportItems []*secflowv1.AIReportItem
	for _, it := range doc.Items {
		var matched indexedFinding
		var ok bool

		if it.Finding != nil {
			cls := nonEmpty(it.Finding.FindingClass, it.Finding.Class)
			fp := strings.Join([]string{it.Finding.Category, it.Finding.Path, cls, it.Finding.Group, it.Finding.Artifact, it.Finding.AdvisoryID}, "|")
			if it.Finding.Line != nil && *it.Finding.Line > 0 {
				matched, ok = pickCandidate(byLineFP[fmt.Sprintf("%s|%d", fp, *it.Finding.Line)])
			}
			if !ok {
				matched, ok = pickCandidate(byFingerprint[fp])
			}
		}
		if !ok {
			if fp := strings.TrimSpace(it.Fingerprint); fp != "" {
				matched, ok = pickCandidate(byFingerprint[fp])
			}
		}
		if !ok {
			matched, ok = pickCandidate(byFingerprint[strings.TrimSpace(it.FindingID)])
		}
		if !ok {
			matched, ok = byID[strings.TrimSpace(it.FindingID)]
		}
		if !ok {
			continue
		}
		usedCanonical[matched.canonicalID] = true
		remappedID[it.FindingID] = matched.canonicalID
		reportItems = append(reportItems, &secflowv1.AIReportItem{
			FindingId:            matched.canonicalID,
			PriorityRank:         it.PriorityRank,
			PlainLanguageRisk:    it.PlainLanguageRisk,
			BusinessImpact:       it.BusinessImpact,
			RemediationSteps:     it.RemediationSteps,
			ReferencedAdvisories: it.ReferencedAdvisories,
			Finding:              groundedSummaryFromReport(matched.finding),
		})
	}

	var groups []*secflowv1.AIReportGroup
	for _, g := range doc.Groups {
		mappedIDs := make([]string, 0, len(g.FindingIDs))
		seen := make(map[string]bool, len(g.FindingIDs))
		for _, fid := range g.FindingIDs {
			resolved := fid
			if mapped, ok := remappedID[fid]; ok {
				resolved = mapped
			}
			if !seen[resolved] {
				seen[resolved] = true
				mappedIDs = append(mappedIDs, resolved)
			}
		}
		groups = append(groups, &secflowv1.AIReportGroup{
			Title:       g.Title,
			MaxSeverity: protoconv.SeverityProto(g.MaxSeverity),
			FindingIds:  mappedIDs,
			Summary:     g.Summary,
		})
	}

	quality := secflowv1.AIQuality(secflowv1.AIQuality_value["AI_QUALITY_"+strings.ToUpper(doc.Quality)])
	if quality == secflowv1.AIQuality_AI_QUALITY_UNSPECIFIED {
		quality = secflowv1.AIQuality_AI_QUALITY_VERIFIED
	}
	decision := secflowv1.ReleaseDecision(secflowv1.ReleaseDecision_value["RELEASE_DECISION_"+strings.ToUpper(doc.ReleaseDecision)])
	if decision == secflowv1.ReleaseDecision_RELEASE_DECISION_UNSPECIFIED {
		decision = aiFromFindings(items).GetReleaseDecision()
	}
	mode := secflowv1.AIProviderMode(secflowv1.AIProviderMode_value["AI_PROVIDER_MODE_"+strings.ToUpper(doc.ProviderMode)])
	if mode == secflowv1.AIProviderMode_AI_PROVIDER_MODE_UNSPECIFIED {
		mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD
	}
	privacy := secflowv1.PrivacyMode(secflowv1.PrivacyMode_value["PRIVACY_MODE_"+strings.ToUpper(doc.PrivacyMode)])
	if privacy == secflowv1.PrivacyMode_PRIVACY_MODE_UNSPECIFIED {
		privacy = secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET
	}
	return &secflowv1.AIReport{
		Quality:                        quality,
		ReleaseDecision:                decision,
		ExecutiveSummary:               doc.ExecutiveSummary,
		Groups:                         groups,
		Items:                          reportItems,
		ModelId:                        nonEmpty(doc.ModelID, "template-fallback"),
		ProviderMode:                   mode,
		PrivacyMode:                    privacy,
		StrippedHallucinatedAdvisories: doc.StrippedHallucinatedAdvisory,
		Cached:                         doc.Cached,
		PromptHash:                     doc.PromptHash,
		TokensIn:                       doc.TokensIn,
		TokensOut:                      doc.TokensOut,
		LatencyMs:                      doc.LatencyMs,
		CreatedAt:                      timestamppb.Now(),
	}
}

func aiFromFindings(items []report.Finding) *secflowv1.AIReport {
	decision := secflowv1.ReleaseDecision_RELEASE_DECISION_PASS
	maxSev := secflowv1.Severity_SEVERITY_LOW
	var ids []string
	var reportItems []*secflowv1.AIReportItem
	for i, f := range items {
		fid := fmt.Sprintf("F-%03d", i+1)
		ids = append(ids, fid)
		if protoconv.SeverityRank(f.Severity) >= protoconv.SeverityRank("HIGH") {
			decision = secflowv1.ReleaseDecision_RELEASE_DECISION_BLOCK
		} else if decision != secflowv1.ReleaseDecision_RELEASE_DECISION_BLOCK && protoconv.SeverityRank(f.Severity) >= protoconv.SeverityRank("MEDIUM") {
			decision = secflowv1.ReleaseDecision_RELEASE_DECISION_WARN
		}
		if protoconv.SeverityRank(f.Severity) > protoconv.SeverityRank(protoconv.TrimEnum(maxSev.String(), "SEVERITY_")) {
			maxSev = protoconv.SeverityProto(f.Severity)
		}
		reportItems = append(reportItems, &secflowv1.AIReportItem{
			FindingId: fid, PriorityRank: int32(i + 1), PlainLanguageRisk: f.Description, BusinessImpact: f.Category,
			RemediationSteps: []string{nonEmpty(f.Remediation, "Исправьте находку и перезапустите прогон.")},
			Finding:          groundedSummaryFromReport(f),
		})
	}
	if len(items) == 0 {
		maxSev = secflowv1.Severity_SEVERITY_UNSPECIFIED
	}
	return &secflowv1.AIReport{
		Quality: secflowv1.AIQuality_AI_QUALITY_FALLBACK, ReleaseDecision: decision,
		ExecutiveSummary: "Детерминированный отчёт по реестру Run Findings. LLM не подменяет вердикт анализаторов.",
		Groups:           []*secflowv1.AIReportGroup{{Title: "Все находки", MaxSeverity: maxSev, FindingIds: ids, Summary: "Сводка построена из неизменяемого реестра."}},
		Items:            reportItems, ModelId: "template-fallback", ProviderMode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK,
		PrivacyMode: secflowv1.PrivacyMode_PRIVACY_MODE_METADATA_ONLY, CreatedAt: timestamppb.Now(),
	}
}

func readable(items []report.Finding, format secflowv1.ReportFormat, aiReports ...*secflowv1.AIReport) []byte {
	var ai *secflowv1.AIReport
	if len(aiReports) > 0 && aiReports[0] != nil {
		ai = aiReports[0]
	} else {
		ai = aiFromFindings(items)
	}

	decision := protoconv.TrimEnum(ai.GetReleaseDecision().String(), "RELEASE_DECISION_")
	quality := protoconv.TrimEnum(ai.GetQuality().String(), "AI_QUALITY_")
	topSteps := collectTopRemediationSteps(ai, 8)

	var b strings.Builder
	if format == secflowv1.ReportFormat_REPORT_FORMAT_HTML {
		b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>SecFlow Security Report</title></head><body>")
		b.WriteString("<h1>SecFlow Security Report</h1>")
		b.WriteString("<section id=\"ai-summary\"><h2>AI Summary</h2>")
		b.WriteString("<p><strong>Release Decision:</strong> " + html.EscapeString(decision) + " | <strong>AI Quality:</strong> " + html.EscapeString(quality) + "</p>")
		if summary := strings.TrimSpace(ai.GetExecutiveSummary()); summary != "" {
			b.WriteString("<p>" + html.EscapeString(summary) + "</p>")
		}
		if len(topSteps) > 0 {
			b.WriteString("<h3>Top Remediation Steps</h3><ol>")
			for _, step := range topSteps {
				b.WriteString("<li>" + html.EscapeString(step) + "</li>")
			}
			b.WriteString("</ol>")
		}
		b.WriteString("</section>")
		b.WriteString(fmt.Sprintf("<section id=\"findings\"><h2>Findings (%d)</h2><ul>", len(items)))
		for _, f := range items {
			b.WriteString("<li>")
			b.WriteString("<strong>[" + html.EscapeString(nonEmpty(f.Severity, "UNKNOWN")) + "] [" + html.EscapeString(f.Category) + "]</strong> ")
			if strings.EqualFold(f.Category, "SCA") {
				b.WriteString("<code>" + html.EscapeString(formatSCACoordinate(f)) + "</code>")
				if f.Path != "" {
					b.WriteString(" (<code>" + html.EscapeString(f.Path) + "</code>)")
				}
			} else {
				if f.Class != "" {
					b.WriteString("<code>" + html.EscapeString(f.Class) + "</code> ")
				}
				b.WriteString("<code>" + html.EscapeString(formatCodeLocation(f)) + "</code>")
			}
			if desc := strings.TrimSpace(f.Description); desc != "" {
				b.WriteString("<div><strong>Description:</strong> " + html.EscapeString(desc) + "</div>")
			}
			if rem := strings.TrimSpace(f.Remediation); rem != "" {
				b.WriteString("<div><strong>Remediation:</strong> " + html.EscapeString(rem) + "</div>")
			}
			b.WriteString("</li>")
		}
		b.WriteString("</ul></section></body></html>")
		return []byte(b.String())
	}

	b.WriteString("# SecFlow Security Report\n\n")
	b.WriteString("## AI Summary\n")
	b.WriteString("- **Release Decision:** " + decision + "\n")
	b.WriteString("- **AI Quality:** " + quality + "\n")
	if model := strings.TrimSpace(ai.GetModelId()); model != "" {
		b.WriteString("- **Model:** " + model + "\n")
	}
	if summary := strings.TrimSpace(ai.GetExecutiveSummary()); summary != "" {
		b.WriteString("\n" + summary + "\n")
	}
	if len(topSteps) > 0 {
		b.WriteString("\n### Top Remediation Steps\n")
		for i, step := range topSteps {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
	}
	b.WriteString(fmt.Sprintf("\n## Findings (%d)\n\n", len(items)))
	for _, f := range items {
		sev := nonEmpty(f.Severity, "UNKNOWN")
		if strings.EqualFold(f.Category, "SCA") {
			b.WriteString(fmt.Sprintf("- **[%s] [%s]** `%s`", sev, f.Category, formatSCACoordinate(f)))
			if f.Path != "" {
				b.WriteString(fmt.Sprintf(" (`%s`)", f.Path))
			}
			b.WriteString("\n")
		} else {
			loc := formatCodeLocation(f)
			if f.Class != "" {
				b.WriteString(fmt.Sprintf("- **[%s] [%s] `%s`** — `%s`\n", sev, f.Category, f.Class, loc))
			} else {
				b.WriteString(fmt.Sprintf("- **[%s] [%s]** — `%s`\n", sev, f.Category, loc))
			}
		}
		if desc := strings.TrimSpace(f.Description); desc != "" {
			b.WriteString("  - **Description:** " + desc + "\n")
		}
		if rem := strings.TrimSpace(f.Remediation); rem != "" {
			b.WriteString("  - **Remediation:** " + rem + "\n")
		}
	}
	return []byte(b.String())
}

func collectTopRemediationSteps(ai *secflowv1.AIReport, limit int) []string {
	if ai == nil || len(ai.GetItems()) == 0 || limit <= 0 {
		return nil
	}
	sorted := append([]*secflowv1.AIReportItem(nil), ai.GetItems()...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].GetPriorityRank() < sorted[j].GetPriorityRank()
	})
	var out []string
	seen := map[string]bool{}
	for _, it := range sorted {
		for _, step := range it.GetRemediationSteps() {
			trimmed := strings.TrimSpace(step)
			if trimmed == "" || seen[trimmed] {
				continue
			}
			seen[trimmed] = true
			out = append(out, trimmed)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func formatCodeLocation(f report.Finding) string {
	if f.Line <= 0 {
		return f.Path
	}
	end := f.EndLine
	if end < f.Line {
		end = f.Line
	}
	return fmt.Sprintf("%s:%d-%d", f.Path, f.Line, end)
}

func formatSCACoordinate(f report.Finding) string {
	coord := fmt.Sprintf("%s:%s:%s", f.Group, f.Artifact, f.Version)
	if adv := strings.TrimSpace(f.AdvisoryID); adv != "" {
		return fmt.Sprintf("%s (%s)", coord, adv)
	}
	return coord
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
