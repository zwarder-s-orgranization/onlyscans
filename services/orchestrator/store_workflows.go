package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/urlguard"
)

func cloneWorkflow(wf *secflowv1.Workflow) *secflowv1.Workflow {
	if wf == nil {
		return nil
	}
	cp, _ := proto.Clone(wf).(*secflowv1.Workflow)
	return cp
}

func cloneWorkflowGraph(g *secflowv1.WorkflowGraph) *secflowv1.WorkflowGraph {
	if g == nil {
		return nil
	}
	cp, _ := proto.Clone(g).(*secflowv1.WorkflowGraph)
	return cp
}

func cloneTemplate(tpl *secflowv1.WorkflowTemplate) *secflowv1.WorkflowTemplate {
	if tpl == nil {
		return nil
	}
	cp, _ := proto.Clone(tpl).(*secflowv1.WorkflowTemplate)
	return cp
}

func (s *Server) CreateWorkflow(ctx context.Context, req *secflowv1.CreateWorkflowRequest) (*secflowv1.CreateWorkflowResponse, error) {
	if req.GetName() == "" || req.GetGraph() == nil {
		return nil, status.Error(codes.InvalidArgument, "name and graph are required")
	}
	if err := rejectInlineSecrets(req.GetGraph()); err != nil {
		return nil, err
	}
	now := timestamppb.Now()
	wfID := id("wf")
	graphCopy := cloneWorkflowGraph(req.GetGraph())
	wf := &secflowv1.Workflow{
		Id:               wfID,
		Name:             req.GetName(),
		Description:      req.GetDescription(),
		Version:          1,
		Graph:            graphCopy,
		OwnerSubject:     subject(req.GetActor()),
		CreatedAt:        now,
		UpdatedAt:        now,
		WebhookPath:      "/webhooks/git/" + wfID,
		ValidationIssues: s.validateGraph(ctx, req.GetActor(), graphCopy),
	}
	applyTriggerMetadata(wf)
	s.wfMu.Lock()
	s.workflows[wf.GetId()] = wf
	snap := cloneWorkflow(wf)
	s.wfMu.Unlock()
	s.persistWorkflow(ctx, snap)
	return &secflowv1.CreateWorkflowResponse{Workflow: cloneWorkflow(snap)}, nil
}

func (s *Server) UpdateWorkflow(ctx context.Context, req *secflowv1.UpdateWorkflowRequest) (*secflowv1.UpdateWorkflowResponse, error) {
	if err := rejectInlineSecrets(req.GetGraph()); err != nil {
		return nil, err
	}
	s.secMu.Lock()
	validSecrets := make(map[string]bool, len(s.secrets))
	for ref := range s.secrets {
		validSecrets[ref] = true
	}
	s.secMu.Unlock()

	graphCopy := cloneWorkflowGraph(req.GetGraph())
	s.wfMu.RLock()
	existing, exists := s.workflows[req.GetWorkflowId()]
	if !exists {
		s.wfMu.RUnlock()
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	preserveExistingSecretBindings(existing.GetGraph(), graphCopy, validSecrets)
	s.wfMu.RUnlock()

	issues := s.validateGraph(ctx, req.GetActor(), graphCopy)

	s.wfMu.Lock()
	wf, ok := s.workflows[req.GetWorkflowId()]
	if !ok {
		s.wfMu.Unlock()
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	if req.ExpectedVersion != nil && req.GetExpectedVersion() != wf.GetVersion() {
		s.wfMu.Unlock()
		return nil, status.Error(codes.Aborted, "version conflict")
	}
	preserveExistingSecretBindings(wf.GetGraph(), graphCopy, validSecrets)
	wf.Name = req.GetName()
	wf.Description = req.GetDescription()
	wf.Graph = graphCopy
	wf.Version++
	wf.UpdatedAt = timestamppb.Now()
	wf.ValidationIssues = issues
	applyTriggerMetadata(wf)
	snap := cloneWorkflow(wf)
	s.wfMu.Unlock()
	s.persistWorkflow(ctx, snap)
	return &secflowv1.UpdateWorkflowResponse{Workflow: cloneWorkflow(snap)}, nil
}

func (s *Server) GetWorkflow(_ context.Context, req *secflowv1.GetWorkflowRequest) (*secflowv1.GetWorkflowResponse, error) {
	s.wfMu.RLock()
	wf, ok := s.workflows[req.GetWorkflowId()]
	snap := cloneWorkflow(wf)
	s.wfMu.RUnlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	return &secflowv1.GetWorkflowResponse{Workflow: snap}, nil
}

func (s *Server) ListWorkflows(_ context.Context, req *secflowv1.ListWorkflowsRequest) (*secflowv1.ListWorkflowsResponse, error) {
	s.wfMu.RLock()
	defer s.wfMu.RUnlock()
	search := strings.ToLower(req.GetSearch())
	var items []*secflowv1.Workflow
	for _, wf := range s.workflows {
		if search == "" || strings.Contains(strings.ToLower(wf.GetName()), search) {
			items = append(items, cloneWorkflow(wf))
		}
	}
	wfUpdatedAt := func(wf *secflowv1.Workflow) time.Time {
		if ts := wf.GetUpdatedAt(); ts != nil {
			return ts.AsTime()
		}
		return time.Time{}
	}
	slices.SortFunc(items, func(a, b *secflowv1.Workflow) int {
		if c := wfUpdatedAt(b).Compare(wfUpdatedAt(a)); c != 0 {
			return c
		}
		return strings.Compare(a.GetId(), b.GetId())
	})
	return &secflowv1.ListWorkflowsResponse{Workflows: items, PageInfo: &secflowv1.PageInfo{TotalCount: int64(len(items))}}, nil
}

func (s *Server) DeleteWorkflow(ctx context.Context, req *secflowv1.DeleteWorkflowRequest) (*secflowv1.DeleteWorkflowResponse, error) {
	s.wfMu.Lock()
	if _, ok := s.workflows[req.GetWorkflowId()]; !ok {
		s.wfMu.Unlock()
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	delete(s.workflows, req.GetWorkflowId())
	s.wfMu.Unlock()
	if s.pool != nil {
		if _, err := s.pool.Exec(ctx, `DELETE FROM workflows WHERE id = $1`, req.GetWorkflowId()); err != nil {
			slog.Warn("delete workflow from db", "workflow_id", req.GetWorkflowId(), "err", err)
		}
	}
	return &secflowv1.DeleteWorkflowResponse{Deleted: true}, nil
}

func (s *Server) ValidateWorkflow(ctx context.Context, req *secflowv1.ValidateWorkflowRequest) (*secflowv1.ValidateWorkflowResponse, error) {
	issues := s.validateGraph(ctx, req.GetActor(), req.GetGraph())
	return &secflowv1.ValidateWorkflowResponse{
		Valid:  !hasProtoValidationError(issues),
		Issues: issues,
	}, nil
}

func (s *Server) validateGraph(ctx context.Context, actor *secflowv1.ActorContext, g *secflowv1.WorkflowGraph) []*secflowv1.ValidationIssue {
	plugins, disabled := s.pluginRegistrySnapshot()
	var out []*secflowv1.ValidationIssue
	for _, issue := range engine.ValidateWithPlugins(toEngine(g), pluginLookupFromSnapshot(plugins, disabled)) {
		sev := secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR
		if issue.Severity == "WARNING" {
			sev = secflowv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING
		}
		out = append(out, &secflowv1.ValidationIssue{
			Code:      issue.Code,
			Severity:  sev,
			Message:   issue.Message,
			NodeId:    issue.NodeID,
			EdgeId:    issue.EdgeID,
			FieldPath: inferEngineFieldPath(issue),
		})
	}
	if g == nil {
		return out
	}
	out = append(out, s.checkDraftDeclarativeNodes(g)...)

	for _, n := range g.GetNodes() {
		pid := n.GetPluginId()
		manifest, known := plugins[pid]
		if !known {
			continue
		}

		params := map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			if err := json.Unmarshal(n.GetParamsJson(), &params); err != nil {
				out = append(out, &secflowv1.ValidationIssue{
					Code:      "INVALID_PARAM_SCHEMA",
					Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
					NodeId:    n.GetId(),
					FieldPath: "params",
					Message:   "параметры ноды должны быть валидным JSON-объектом",
				})
				continue
			}
		}
		var schemaErr error
		if _, isBuiltinDef := paramschema.RawDef(pid); isBuiltinDef {
			schemaErr = paramschema.Check(pid, params)
		} else if manifest != nil && len(manifest.GetParamsJsonSchema()) > 0 {
			schemaErr = paramschema.CheckSchema(pid, manifest.GetParamsJsonSchema(), params)
		}
		if schemaErr != nil {
			code, fp := classifyParamSchemaError(pid, schemaErr)
			out = append(out, &secflowv1.ValidationIssue{
				Code:      code,
				Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
				NodeId:    n.GetId(),
				FieldPath: fp,
				Message:   schemaErr.Error(),
			})
		}
		if pid == "source.git" {
			repo, _ := params["repoUrl"].(string)
			if repo != "" && !strings.Contains(repo, "{{") {
				if ok, reason := s.checkRepoURLAllowlist(ctx, actor, repo); !ok {
					if reason == "" {
						reason = "URL репозитория вне allowlist"
					}
					out = append(out, &secflowv1.ValidationIssue{
						Code:      "URL_NOT_ALLOWLISTED",
						Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
						NodeId:    n.GetId(),
						FieldPath: "params.repoUrl",
						Message:   reason,
					})
				}
			}
		}
	}
	return out
}

func (s *Server) checkRepoURLAllowlist(ctx context.Context, actor *secflowv1.ActorContext, repoURL string) (bool, string) {
	if s.ingest != nil {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		resp, err := s.ingest.CheckRepoAllowlist(checkCtx, &secflowv1.CheckRepoAllowlistRequest{
			Actor:   actor,
			RepoUrl: repoURL,
		})
		if err == nil {
			return resp.GetAllowed(), resp.GetReason()
		}
		slog.Warn("source-ingester CheckRepoAllowlist failed, falling back to local urlguard", "err", err)
	}
	ok, _, reason := urlguard.RepoAllowed(repoURL, os.Getenv("REPO_ALLOWLIST"))
	return ok, reason
}

func hasProtoValidationError(issues []*secflowv1.ValidationIssue) bool {
	for _, issue := range issues {
		if issue.GetSeverity() == secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR {
			return true
		}
	}
	return false
}

func inferEngineFieldPath(issue engine.Issue) string {
	switch issue.Code {
	case engine.CodeBadPort:
		return "sourceHandle"
	case engine.CodePluginDisabled, engine.CodePluginUnregistered:
		return "pluginId"
	case engine.CodeMissingSecret:
		if rest, ok := strings.CutPrefix(issue.Message, "нет секрета "); ok {
			key, _, _ := strings.Cut(rest, " ")
			if key != "" {
				return "secretBindings." + key
			}
		}
		return "secretBindings"
	default:
		return ""
	}
}

func classifyParamSchemaError(pluginID string, err error) (code string, fieldPath string) {
	msg := err.Error()
	code = "INVALID_PARAM_SCHEMA"
	if strings.Contains(msg, ": нет поля ") {
		code = "MISSING_REQUIRED_PARAM"
	}
	prefix, detail, hasColon := strings.Cut(msg, ": ")
	if hasColon {
		if key, ok := strings.CutPrefix(detail, "нет поля "); ok && key != "" {
			return code, paramFieldPath(pluginID, prefix, strings.TrimSpace(key))
		}
		if key, ok := strings.CutPrefix(detail, "лишнее поле "); ok && key != "" {
			return code, paramFieldPath(pluginID, prefix, strings.TrimSpace(key))
		}
		return code, paramFieldPath(pluginID, prefix, "")
	}
	return code, "params"
}

func paramFieldPath(pluginID, rawPrefix, extraKey string) string {
	trimmed := strings.TrimPrefix(rawPrefix, pluginID)
	trimmed = strings.TrimPrefix(trimmed, ".")
	parts := []string{"params"}
	if trimmed != "" {
		parts = append(parts, trimmed)
	}
	if extraKey != "" {
		parts = append(parts, extraKey)
	}
	return strings.Join(parts, ".")
}

func (s *Server) PublishTemplate(ctx context.Context, req *secflowv1.PublishTemplateRequest) (*secflowv1.PublishTemplateResponse, error) {
	s.wfMu.RLock()
	wf, ok := s.workflows[req.GetWorkflowId()]
	var graph *secflowv1.WorkflowGraph
	if ok {
		graph = sanitizeGraph(wf.GetGraph())
	}
	s.wfMu.RUnlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	tpl := &secflowv1.WorkflowTemplate{
		Id: id("tpl"), Slug: slug(req.GetName()), Name: req.GetName(), Description: req.GetDescription(),
		ProblemSolved: req.GetProblemSolved(), Tags: req.GetTags(), SanitizedGraph: graph,
		AuthorSubject: subject(req.GetActor()), CreatedAt: timestamppb.Now(), UpdatedAt: timestamppb.Now(),
	}
	s.wfMu.Lock()
	s.templates[tpl.GetId()] = tpl
	snap := cloneTemplate(tpl)
	s.wfMu.Unlock()
	s.persistTemplate(ctx, snap)
	return &secflowv1.PublishTemplateResponse{Template: cloneTemplate(snap)}, nil
}

func (s *Server) ListTemplates(_ context.Context, _ *secflowv1.ListTemplatesRequest) (*secflowv1.ListTemplatesResponse, error) {
	s.wfMu.RLock()
	defer s.wfMu.RUnlock()
	items := make([]*secflowv1.WorkflowTemplate, 0, len(s.templates))
	for _, tpl := range s.templates {
		items = append(items, cloneTemplate(tpl))
	}
	slices.SortFunc(items, func(a, b *secflowv1.WorkflowTemplate) int {
		if a.GetIsBuiltin() != b.GetIsBuiltin() {
			if a.GetIsBuiltin() {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.GetName(), b.GetName()); c != 0 {
			return c
		}
		return strings.Compare(a.GetId(), b.GetId())
	})
	return &secflowv1.ListTemplatesResponse{Templates: items, PageInfo: &secflowv1.PageInfo{TotalCount: int64(len(items))}}, nil
}

func (s *Server) GetTemplate(_ context.Context, req *secflowv1.GetTemplateRequest) (*secflowv1.GetTemplateResponse, error) {
	s.wfMu.RLock()
	tpl, ok := s.templates[req.GetTemplateId()]
	snap := cloneTemplate(tpl)
	s.wfMu.RUnlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	return &secflowv1.GetTemplateResponse{Template: snap}, nil
}

func (s *Server) CloneTemplate(ctx context.Context, req *secflowv1.CloneTemplateRequest) (*secflowv1.CloneTemplateResponse, error) {
	s.wfMu.RLock()
	tpl, ok := s.templates[req.GetTemplateId()]
	var tplID, tplDesc string
	var tplGraph *secflowv1.WorkflowGraph
	if ok {
		tplID = tpl.GetId()
		tplDesc = tpl.GetDescription()
		tplGraph = sanitizeGraph(tpl.GetSanitizedGraph())
	}
	s.wfMu.RUnlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	created, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Actor: req.GetActor(), Name: req.GetNewWorkflowName(), Description: tplDesc, Graph: tplGraph,
	})
	if err != nil {
		return nil, err
	}
	wfID := created.GetWorkflow().GetId()
	var wfSnap *secflowv1.Workflow
	var tplSnap *secflowv1.WorkflowTemplate
	s.wfMu.Lock()
	if liveWf, exists := s.workflows[wfID]; exists && liveWf != nil {
		liveWf.SourceTemplateId = tplID
		wfSnap = cloneWorkflow(liveWf)
	}
	if liveTpl, exists := s.templates[tplID]; exists && liveTpl != nil {
		liveTpl.CloneCount++
		liveTpl.UpdatedAt = timestamppb.Now()
		tplSnap = cloneTemplate(liveTpl)
	}
	s.wfMu.Unlock()
	if wfSnap == nil {
		wfSnap = created.GetWorkflow()
		wfSnap.SourceTemplateId = tplID
	}
	s.persistWorkflow(ctx, wfSnap)
	if tplSnap != nil {
		s.persistTemplate(ctx, tplSnap)
	}
	return &secflowv1.CloneTemplateResponse{Workflow: cloneWorkflow(wfSnap)}, nil
}

var ciWorkflowIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validateCiWorkflowID(workflowID string) error {
	if !ciWorkflowIDRe.MatchString(workflowID) {
		return status.Error(codes.InvalidArgument, "workflowId must match ^[A-Za-z0-9_-]{1,64}$")
	}
	return nil
}

func validateCiBaseURL(raw string) (string, error) {
	if raw == "" {
		return "http://localhost:8080", nil
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f {
			return "", status.Error(codes.InvalidArgument, "secflowBaseUrl must not contain whitespace or control characters")
		}
		switch r {
		case '\'', '"', ';', '$', '`', '\\', '|', '&', '<', '>', '(', ')':
			return "", status.Error(codes.InvalidArgument, "secflowBaseUrl contains forbidden shell characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", status.Error(codes.InvalidArgument, "secflowBaseUrl must be a valid http or https URL without query, fragment, or userinfo")
	}
	return strings.TrimRight(raw, "/"), nil
}

func ciSeverityPattern(sev secflowv1.Severity) (label, pattern string) {
	switch sev {
	case secflowv1.Severity_SEVERITY_CRITICAL:
		return "CRITICAL", "CRITICAL"
	case secflowv1.Severity_SEVERITY_MEDIUM:
		return "MEDIUM", "(CRITICAL|HIGH|MEDIUM)"
	case secflowv1.Severity_SEVERITY_LOW:
		return "LOW", "(CRITICAL|HIGH|MEDIUM|LOW)"
	default:
		// Default HIGH (matches workflow.proto and schema.graphqls).
		return "HIGH", "(CRITICAL|HIGH)"
	}
}

func (s *Server) GenerateCiConfig(_ context.Context, req *secflowv1.GenerateCiConfigRequest) (*secflowv1.GenerateCiConfigResponse, error) {
	workflowID := req.GetWorkflowId()
	if err := validateCiWorkflowID(workflowID); err != nil {
		return nil, err
	}
	base, err := validateCiBaseURL(req.GetSecflowBaseUrl())
	if err != nil {
		return nil, err
	}
	sevLabel, sevPattern := ciSeverityPattern(req.GetFailOnSeverity())

	var gateCheck string
	if req.GetFailOnPolicyGate() {
		gateCheck = `
GATE_STATUS=$(echo "$RUN_JSON" | sed -n 's/.*"gateStatus"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ "$GATE_STATUS" = "FAIL" ]; then
  echo "SecFlow gate failed: policy gateResult.status=FAIL" >&2
  exit 1
fi`
	}

	script := fmt.Sprintf(`set -euo pipefail
RUN_ID=$(curl -fsS "%s/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SECFLOW_CI_TOKEN" \
  -d '{"query":"mutation { startRun(input: {workflowId: \"%s\"}) { id status } }"}' \
  | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
test -n "$RUN_ID"
echo "Started SecFlow run: $RUN_ID"
STATUS="QUEUED"
RUN_JSON=""
for i in $(seq 1 60); do
  RUN_JSON=$(curl -fsS "%s/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SECFLOW_CI_TOKEN" \
    -d "{\"query\":\"query { run(id: \\\"$RUN_ID\\\") { runStatus: status gateResult { gateStatus: status } } }\"}")
  STATUS=$(echo "$RUN_JSON" | sed -n 's/.*"runStatus"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  case "$STATUS" in
    SUCCEEDED|FAILED|CANCELLED) break ;;
  esac
  sleep 2
done
echo "SecFlow run $RUN_ID finished with status: $STATUS"
REPORT=$(curl -fsS "%s/runs/$RUN_ID/submission.json" -H "Authorization: Bearer $SECFLOW_CI_TOKEN")
echo "$REPORT"
if [ "$STATUS" != "SUCCEEDED" ]; then
  echo "SecFlow gate failed: run status=$STATUS" >&2
  exit 1
fi%s
if echo "$REPORT" | grep -Eqi '"severity"[[:space:]]*:[[:space:]]*"%s"'; then
  echo "SecFlow gate failed: findings at or above %s severity detected" >&2
  exit 1
fi`, base, workflowID, base, base, gateCheck, sevPattern, sevLabel)

	name := ".github/workflows/secflow-security.yml"
	yaml := "name: secflow-security\non: [push, pull_request]\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Run SecFlow Security Gate\n        env:\n          SECFLOW_CI_TOKEN: ${{ secrets.SECFLOW_CI_TOKEN }}\n        run: |\n" + indentLines(script, "          ")
	if req.GetProvider() == secflowv1.CiProvider_CI_PROVIDER_GITLAB_CI {
		name = ".gitlab-ci.yml"
		yaml = "secflow_security_gate:\n  stage: test\n  script:\n    - |\n" + indentLines(script, "      ")
	}
	return &secflowv1.GenerateCiConfigResponse{Provider: req.GetProvider(), Filename: name, YamlContent: yaml, RequiredCiSecrets: []string{"SECFLOW_CI_TOKEN"}}, nil
}

func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n") + "\n"
}

func (s *Server) mustWorkflow(wfID string) *secflowv1.Workflow {
	s.wfMu.RLock()
	defer s.wfMu.RUnlock()
	return cloneWorkflow(s.workflows[wfID])
}

func (s *Server) persistWorkflow(ctx context.Context, wf *secflowv1.Workflow) {
	if s.pool == nil || wf == nil {
		return
	}
	raw, err := protojson.Marshal(wf.GetGraph())
	if err != nil {
		slog.Warn("marshal workflow graph", "workflow_id", wf.GetId(), "err", err)
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(dbCtx, `
		INSERT INTO workflows (id, name, description, version, graph_json, owner_subject, source_template_id)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, version = EXCLUDED.version, graph_json = EXCLUDED.graph_json, source_template_id = EXCLUDED.source_template_id, updated_at = now()`,
		wf.GetId(), wf.GetName(), wf.GetDescription(), wf.GetVersion(), string(raw), wf.GetOwnerSubject(), wf.GetSourceTemplateId()); err != nil {
		if strings.Contains(err.Error(), "source_template_id") {
			if _, fbErr := s.pool.Exec(dbCtx, `
				INSERT INTO workflows (id, name, description, version, graph_json, owner_subject)
				VALUES ($1,$2,$3,$4,$5::jsonb,$6)
				ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, version = EXCLUDED.version, graph_json = EXCLUDED.graph_json, updated_at = now()`,
				wf.GetId(), wf.GetName(), wf.GetDescription(), wf.GetVersion(), string(raw), wf.GetOwnerSubject()); fbErr != nil {
				slog.Warn("persist workflow", "workflow_id", wf.GetId(), "err", fbErr)
			}
			return
		}
		slog.Warn("persist workflow", "workflow_id", wf.GetId(), "err", err)
	}
}

func (s *Server) persistTemplate(ctx context.Context, tpl *secflowv1.WorkflowTemplate) {
	if s.pool == nil || tpl == nil {
		return
	}
	raw, err := protojson.Marshal(tpl.GetSanitizedGraph())
	if err != nil {
		slog.Warn("marshal template graph", "template_id", tpl.GetId(), "err", err)
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(dbCtx, `
		INSERT INTO workflow_templates (id, slug, name, description, problem_solved, graph_json, is_builtin, clone_count)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, problem_solved = EXCLUDED.problem_solved, graph_json = EXCLUDED.graph_json, clone_count = EXCLUDED.clone_count`,
		tpl.GetId(), tpl.GetSlug(), tpl.GetName(), tpl.GetDescription(), tpl.GetProblemSolved(), string(raw), tpl.GetIsBuiltin(), tpl.GetCloneCount()); err != nil {
		if strings.Contains(err.Error(), "clone_count") {
			if _, fbErr := s.pool.Exec(dbCtx, `
				INSERT INTO workflow_templates (id, slug, name, description, problem_solved, graph_json, is_builtin)
				VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
				ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, problem_solved = EXCLUDED.problem_solved, graph_json = EXCLUDED.graph_json`,
				tpl.GetId(), tpl.GetSlug(), tpl.GetName(), tpl.GetDescription(), tpl.GetProblemSolved(), string(raw), tpl.GetIsBuiltin()); fbErr != nil {
				slog.Warn("persist template", "template_id", tpl.GetId(), "err", fbErr)
			}
			return
		}
		slog.Warn("persist template", "template_id", tpl.GetId(), "err", err)
	}
}

func (s *Server) loadWorkflows(ctx context.Context) {
	if s.pool == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `SELECT id, name, description, version, graph_json, owner_subject FROM workflows`)
	if err != nil {
		slog.Warn("load workflows", "err", err)
		return
	}
	defer rows.Close()
	var loaded []*secflowv1.Workflow
	for rows.Next() {
		var wfID, name, description, owner string
		var version int32
		var graph []byte
		if err := rows.Scan(&wfID, &name, &description, &version, &graph, &owner); err != nil {
			slog.Warn("scan workflow", "err", err)
			continue
		}
		wf := &secflowv1.Workflow{Id: wfID, Name: name, Description: description, Version: version, OwnerSubject: owner, WebhookPath: "/webhooks/git/" + wfID, Graph: &secflowv1.WorkflowGraph{}}
		if err := protojson.Unmarshal(graph, wf.Graph); err != nil {
			slog.Warn("unmarshal workflow graph", "workflow_id", wfID, "err", err)
		}
		applyTriggerMetadata(wf)
		loaded = append(loaded, wf)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate workflows", "err", err)
	}
	s.wfMu.Lock()
	for _, wf := range loaded {
		if _, exists := s.workflows[wf.GetId()]; !exists {
			s.workflows[wf.GetId()] = wf
		}
	}
	s.wfMu.Unlock()
}

func (s *Server) loadTemplates(ctx context.Context) {
	if s.pool == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `SELECT id, slug, name, description, problem_solved, graph_json, is_builtin FROM workflow_templates`)
	if err != nil {
		slog.Warn("load templates", "err", err)
		return
	}
	defer rows.Close()
	var loaded []*secflowv1.WorkflowTemplate
	for rows.Next() {
		var tplID, slugVal, name, desc, problem string
		var graphRaw []byte
		var builtin bool
		if err := rows.Scan(&tplID, &slugVal, &name, &desc, &problem, &graphRaw, &builtin); err != nil {
			slog.Warn("scan template", "err", err)
			continue
		}
		g := &secflowv1.WorkflowGraph{}
		if err := protojson.Unmarshal(graphRaw, g); err != nil {
			slog.Warn("unmarshal template graph", "template_id", tplID, "err", err)
		}
		loaded = append(loaded, &secflowv1.WorkflowTemplate{
			Id: tplID, Slug: slugVal, Name: name, Description: desc, ProblemSolved: problem,
			IsBuiltin: builtin, SanitizedGraph: g,
		})
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate templates", "err", err)
	}
	s.wfMu.Lock()
	for _, tpl := range loaded {
		if _, exists := s.templates[tpl.GetId()]; !exists {
			s.templates[tpl.GetId()] = tpl
		}
	}
	s.wfMu.Unlock()
}
