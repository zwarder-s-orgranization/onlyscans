package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

type mcpTestRunClient struct {
	secflowv1.RunServiceClient
	runs        map[string]*secflowv1.Run
	lastStart   *secflowv1.StartRunRequest
	lastFind    *secflowv1.ListFindingsRequest
	lastSbom    *secflowv1.GetSbomRequest
	lastReport  *secflowv1.GetReadableReportRequest
	startErr    error
	findings    []*secflowv1.Finding
	aiReport    *secflowv1.AIReport
	submission  []byte
	readableMD  []byte
	sbomRef     *secflowv1.SbomRef
	sbomContent []byte
}

func (m *mcpTestRunClient) StartRun(_ context.Context, req *secflowv1.StartRunRequest, _ ...grpc.CallOption) (*secflowv1.StartRunResponse, error) {
	m.lastStart = req
	if m.startErr != nil {
		return nil, m.startErr
	}
	return &secflowv1.StartRunResponse{
		Run: &secflowv1.Run{
			Id:         "run_mcp_1",
			WorkflowId: req.GetWorkflowId(),
			Status:     secflowv1.RunStatus_RUN_STATUS_QUEUED,
			TraceId:    "trace-mcp-999",
		},
	}, nil
}

func (m *mcpTestRunClient) GetRun(_ context.Context, req *secflowv1.GetRunRequest, _ ...grpc.CallOption) (*secflowv1.GetRunResponse, error) {
	r, ok := m.runs[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	return &secflowv1.GetRunResponse{Run: r}, nil
}

func (m *mcpTestRunClient) ListFindings(_ context.Context, req *secflowv1.ListFindingsRequest, _ ...grpc.CallOption) (*secflowv1.ListFindingsResponse, error) {
	m.lastFind = req
	return &secflowv1.ListFindingsResponse{Findings: m.findings}, nil
}

func (m *mcpTestRunClient) GetAIReport(_ context.Context, _ *secflowv1.GetAIReportRequest, _ ...grpc.CallOption) (*secflowv1.GetAIReportResponse, error) {
	return &secflowv1.GetAIReportResponse{Report: m.aiReport}, nil
}

func (m *mcpTestRunClient) GetSubmissionReport(_ context.Context, _ *secflowv1.GetSubmissionReportRequest, _ ...grpc.CallOption) (*secflowv1.GetSubmissionReportResponse, error) {
	return &secflowv1.GetSubmissionReportResponse{SubmissionJson: m.submission}, nil
}

func (m *mcpTestRunClient) GetReadableReport(_ context.Context, req *secflowv1.GetReadableReportRequest, _ ...grpc.CallOption) (*secflowv1.GetReadableReportResponse, error) {
	m.lastReport = req
	return &secflowv1.GetReadableReportResponse{Content: m.readableMD}, nil
}

func (m *mcpTestRunClient) GetSbom(_ context.Context, req *secflowv1.GetSbomRequest, _ ...grpc.CallOption) (*secflowv1.GetSbomResponse, error) {
	m.lastSbom = req
	resp := &secflowv1.GetSbomResponse{Sbom: m.sbomRef}
	if req.GetIncludeContent() {
		resp.CyclonedxJson = m.sbomContent
	}
	return resp, nil
}

type mcpTestWorkflowClient struct {
	secflowv1.WorkflowServiceClient
	workflows []*secflowv1.Workflow
	templates []*secflowv1.WorkflowTemplate
}

func (m *mcpTestWorkflowClient) ListWorkflows(_ context.Context, _ *secflowv1.ListWorkflowsRequest, _ ...grpc.CallOption) (*secflowv1.ListWorkflowsResponse, error) {
	return &secflowv1.ListWorkflowsResponse{Workflows: m.workflows}, nil
}

func (m *mcpTestWorkflowClient) ListTemplates(_ context.Context, _ *secflowv1.ListTemplatesRequest, _ ...grpc.CallOption) (*secflowv1.ListTemplatesResponse, error) {
	return &secflowv1.ListTemplatesResponse{Templates: m.templates}, nil
}

func (m *mcpTestWorkflowClient) CloneTemplate(_ context.Context, req *secflowv1.CloneTemplateRequest, _ ...grpc.CallOption) (*secflowv1.CloneTemplateResponse, error) {
	return &secflowv1.CloneTemplateResponse{
		Workflow: &secflowv1.Workflow{
			Id:   "wf_cloned_1",
			Name: req.GetNewWorkflowName(),
		},
	}, nil
}

func newMCPTestGateway() (*gateway, *mcpTestRunClient) {
	now := timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	line := int32(42)
	runClient := &mcpTestRunClient{
		runs: map[string]*secflowv1.Run{
			"run_1": {
				Id:         "run_1",
				WorkflowId: "wf_1",
				Status:     secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
				GateResult: &secflowv1.GateResult{Status: secflowv1.GateStatus_GATE_STATUS_FAIL, Reason: "HIGH finding", NodeId: "gate_1"},
				FindingsStats: &secflowv1.EnvelopeStats{
					Total:       1,
					High:        1,
					SastCount:   1,
					MaxSeverity: secflowv1.Severity_SEVERITY_HIGH,
				},
				NodeRuns: []*secflowv1.NodeRun{
					{NodeRunId: "nr_1", RunId: "run_1", NodeId: "sast_1", PluginId: "scan.sast.kotlin", Status: secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED},
				},
				CreatedAt: now,
			},
			"run_2": {
				Id:         "run_2",
				WorkflowId: "wf_2",
				Status:     secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
				CreatedAt:  now,
			},
		},
		findings: []*secflowv1.Finding{
			{
				FindingId:    "f_1",
				Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
				Severity:     secflowv1.Severity_SEVERITY_HIGH,
				Path:         "src/Controller.kt",
				Line:         &line,
				FindingClass: "SQL_INJECTION",
			},
		},
		aiReport: &secflowv1.AIReport{
			Quality:                        secflowv1.AIQuality_AI_QUALITY_VERIFIED,
			ReleaseDecision:                secflowv1.ReleaseDecision_RELEASE_DECISION_BLOCK,
			ExecutiveSummary:               "1 high SAST finding detected.",
			ModelId:                        "gpt-4o-mini",
			ProviderMode:                   secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
			PrivacyMode:                    secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET,
			StrippedHallucinatedAdvisories: 2,
			Groups: []*secflowv1.AIReportGroup{
				{Title: "Injection", MaxSeverity: secflowv1.Severity_SEVERITY_HIGH, FindingIds: []string{"f_1"}, Summary: "SQL injection risk"},
			},
			Items: []*secflowv1.AIReportItem{
				{
					FindingId:            "f_1",
					PriorityRank:         1,
					PlainLanguageRisk:    "Unsanitized query",
					BusinessImpact:       "Data exposure",
					RemediationSteps:     []string{"Use parameterized query"},
					ReferencedAdvisories: []string{},
					Finding:              &secflowv1.GroundedFindingSummary{Category: secflowv1.FindingCategory_FINDING_CATEGORY_SAST, Path: "src/Controller.kt", Line: &line},
				},
			},
			CreatedAt: now,
		},
		submission: []byte(`{"findings":[{"category":"SAST","path":"src/Controller.kt","line":42}]}`),
		readableMD: []byte("# SecFlow Report\n\n- SQL_INJECTION in src/Controller.kt:42\n"),
		sbomRef: &secflowv1.SbomRef{
			Digest:             "sha256:1234",
			SpecVersion:        "1.6",
			ComponentCount:     12,
			VulnerabilityCount: 1,
			GeneratedAt:        now,
		},
		sbomContent: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"jackson-databind"}]}`),
	}

	gw := &gateway{
		secret: []byte("mcp-test-secret"),
		secs: &fakeSecretClient{
			tokens: map[string]*secflowv1.ActorContext{
				"sf_mcp_read":  {Subject: "tok_r", Scopes: []string{"mcp:read"}, ScopedWorkflowId: "wf_1"},
				"sf_mcp_run":   {Subject: "tok_run", Scopes: []string{"mcp:run"}, ScopedWorkflowId: "wf_1"},
				"sf_mcp_write": {Subject: "tok_w", Scopes: []string{"mcp:write"}},
				"sf_ci_start":  {Subject: "tok_ci", Scopes: []string{"ci:startRun"}, ScopedWorkflowId: "wf_1"},
			},
		},
		wf: &mcpTestWorkflowClient{
			workflows: []*secflowv1.Workflow{
				{Id: "wf_1", Name: "Kotlin Gate", Description: "Main gate", Version: 2, UpdatedAt: now},
				{Id: "wf_2", Name: "Other Workflow", Description: "Other", Version: 1, UpdatedAt: now},
			},
			templates: []*secflowv1.WorkflowTemplate{
				{Id: "tpl_1", Slug: "kotlin-gate", Name: "Kotlin Gate", Tags: []string{"kotlin", "sast"}, IsBuiltin: true, CreatedAt: now, UpdatedAt: now},
				{Id: "tpl_2", Slug: "sca-only", Name: "SCA Audit", Tags: []string{"sca"}, IsBuiltin: true, CreatedAt: now, UpdatedAt: now},
			},
		},
		runs: runClient,
		ai:   &stubAIClientRich{rationale: "Deterministic preview"},
		plugs: &stubPluginClient{
			plugins: []*secflowv1.RegisteredPlugin{
				{Manifest: &secflowv1.PluginManifest{PluginId: "scan.sast.kotlin", DisplayName: "Kotlin SAST"}, Status: secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE},
			},
		},
	}
	return gw, runClient
}

func TestMCPServer_GETSSEAndSessionHeaders(t *testing.T) {
	gw, _ := newMCPTestGateway()

	t.Run("GET /mcp rejects unauthenticated with 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		gw.mcpServerHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want 401", rec.Code)
		}
	})

	t.Run("GET /mcp rejects missing Mcp-Session-Id with 400", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer sf_mcp_read")
		gw.mcpServerHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("GET /mcp streams SSE headers, endpoint frame, session id, and exits cleanly on cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer sf_mcp_read")
		req.Header.Set("Mcp-Session-Id", "sess_custom_42")
		rec := httptest.NewRecorder()

		done := make(chan struct{})
		go func() {
			defer close(done)
			gw.mcpServerHTTP(rec, req)
		}()

		time.Sleep(25 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("GET /mcp SSE handler did not exit after context cancellation")
		}

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
			t.Fatalf("Content-Type = %q, want text/event-stream", got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("Cache-Control = %q, want no-cache", got)
		}
		if got := rec.Header().Get("Mcp-Session-Id"); got != "sess_custom_42" {
			t.Fatalf("Mcp-Session-Id = %q, want sess_custom_42", got)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "event: endpoint\ndata: /mcp\n\n") || !strings.Contains(body, ": keepalive") {
			t.Fatalf("unexpected SSE body: %q", body)
		}
	})

	t.Run("POST initialize generates Mcp-Session-Id and subsequent requests echo it", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`))
		req.Header.Set("Authorization", "Bearer sf_mcp_read")
		gw.mcpServerHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("initialize status=%d body=%s", rec.Code, rec.Body.String())
		}
		sid := rec.Header().Get("Mcp-Session-Id")
		if !strings.HasPrefix(sid, "mcp_") {
			t.Fatalf("expected generated Mcp-Session-Id, got %q", sid)
		}

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"ping"}`))
		req2.Header.Set("Authorization", "Bearer sf_mcp_read")
		req2.Header.Set("Mcp-Session-Id", sid)
		gw.mcpServerHTTP(rec2, req2)
		if rec2.Code != http.StatusOK || rec2.Header().Get("Mcp-Session-Id") != sid {
			t.Fatalf("ping status=%d sid=%q want %q", rec2.Code, rec2.Header().Get("Mcp-Session-Id"), sid)
		}

		// notifications/initialized -> 202 Accepted
		rec3 := httptest.NewRecorder()
		req3 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
		req3.Header.Set("Authorization", "Bearer sf_mcp_read")
		req3.Header.Set("Mcp-Session-Id", sid)
		gw.mcpServerHTTP(rec3, req3)
		if rec3.Code != http.StatusAccepted {
			t.Fatalf("notifications/initialized status=%d, want 202", rec3.Code)
		}
	})
}

func TestMCPServer_AllTenToolsSchemasPayloadsAndRBAC(t *testing.T) {
	gw, runClient := newMCPTestGateway()

	call := func(token, method string, params map[string]any) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(raw)))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		gw.mcpServerHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	toolTextJSON := func(t *testing.T, resp map[string]any) map[string]any {
		t.Helper()
		content := asList(asMap(resp["result"])["content"])
		if len(content) == 0 {
			t.Fatalf("empty tool content: %+v", resp)
		}
		txt := asString(asMap(content[0])["text"])
		var parsed map[string]any
		if err := json.Unmarshal([]byte(txt), &parsed); err != nil {
			t.Fatalf("tool text not JSON (%q): %v", txt, err)
		}
		return parsed
	}

	t.Run("zero anonymous access on all methods", func(t *testing.T) {
		for _, m := range []string{"initialize", "tools/list", "resources/list", "resources/read", "tools/call"} {
			rec, _ := call("", m, map[string]any{"name": "list_workflows"})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous %s status=%d, want 401", m, rec.Code)
			}
		}
	})

	t.Run("tools/list returns real inputSchemas with properties and required fields for all 10 tools", func(t *testing.T) {
		rec, resp := call("sf_mcp_read", "tools/list", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("tools/list status=%d body=%s", rec.Code, rec.Body.String())
		}
		tools := asList(asMap(resp["result"])["tools"])
		if len(tools) != 10 {
			t.Fatalf("got %d tools, want 10", len(tools))
		}
		wantRequired := map[string][]string{
			"list_workflows":            nil,
			"list_templates":            nil,
			"clone_template":            {"templateId", "newWorkflowName"},
			"generate_workflow_preview": {"prompt"},
			"run_workflow":              {"workflowId"},
			"get_run_status":            {"runId"},
			"get_findings":              {"runId"},
			"get_ai_report":             {"runId"},
			"export_submission_json":    {"runId"},
			"get_sbom":                  {"runId"},
		}
		seen := map[string]bool{}
		for _, rawTool := range tools {
			tm := asMap(rawTool)
			name := asString(tm["name"])
			seen[name] = true
			schema := asMap(tm["inputSchema"])
			props := asMap(schema["properties"])
			if len(props) == 0 {
				t.Fatalf("tool %q has empty inputSchema properties", name)
			}
			reqs := asStringSlice(schema["required"])
			for _, wantReq := range wantRequired[name] {
				found := false
				for _, gotReq := range reqs {
					if gotReq == wantReq {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("tool %q inputSchema missing required field %q (got %v)", name, wantReq, reqs)
				}
			}
		}
		for name := range wantRequired {
			if !seen[name] {
				t.Fatalf("missing tool %q in tools/list", name)
			}
		}
	})

	t.Run("run_workflow forwards overrides and returns runId, status, traceId", func(t *testing.T) {
		rec, resp := call("sf_mcp_run", "tools/call", map[string]any{
			"name": "run_workflow",
			"arguments": map[string]any{
				"workflowId":        "wf_1",
				"sourceIdOverride":  "src_1",
				"repoUrlOverride":   "https://github.com/org/allowed-repo",
				"gitRefOverride":    "main",
				"commitShaOverride": "abc123",
			},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("run_workflow status=%d body=%s", rec.Code, rec.Body.String())
		}
		if runClient.lastStart.GetSourceIdOverride() != "src_1" ||
			runClient.lastStart.GetRepoUrlOverride() != "https://github.com/org/allowed-repo" ||
			runClient.lastStart.GetGitRefOverride() != "main" ||
			runClient.lastStart.GetCommitShaOverride() != "abc123" {
			t.Fatalf("overrides not forwarded: %+v", runClient.lastStart)
		}
		out := toolTextJSON(t, resp)
		if out["runId"] != "run_mcp_1" || out["status"] != "QUEUED" || out["traceId"] != "trace-mcp-999" {
			t.Fatalf("unexpected run_workflow output: %+v", out)
		}

		// Non-allowlisted repoUrlOverride returns 403 ALLOWLIST_DENIED.
		runClient.startErr = status.Error(codes.PermissionDenied, "ALLOWLIST_DENIED")
		defer func() { runClient.startErr = nil }()
		recDenied, respDenied := call("sf_mcp_run", "tools/call", map[string]any{
			"name":      "run_workflow",
			"arguments": map[string]any{"workflowId": "wf_1", "repoUrlOverride": "https://evil.example.com/repo"},
		})
		if recDenied.Code != http.StatusForbidden || asMap(respDenied["error"])["message"] != "ALLOWLIST_DENIED" {
			t.Fatalf("expected 403 ALLOWLIST_DENIED, got status=%d resp=%+v", recDenied.Code, respDenied)
		}
	})

	t.Run("get_ai_report returns full grounded AIReport fields", func(t *testing.T) {
		rec, resp := call("sf_mcp_read", "tools/call", map[string]any{
			"name":      "get_ai_report",
			"arguments": map[string]any{"runId": "run_1"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("get_ai_report status=%d body=%s", rec.Code, rec.Body.String())
		}
		out := toolTextJSON(t, resp)
		for _, field := range []string{
			"quality", "releaseDecision", "executiveSummary", "modelId",
			"providerMode", "privacyMode", "strippedHallucinatedAdvisories", "groups", "items",
		} {
			if _, ok := out[field]; !ok {
				t.Fatalf("get_ai_report missing field %q: %+v", field, out)
			}
		}
		if out["quality"] != "VERIFIED" || out["releaseDecision"] != "BLOCK" || asInt(out["strippedHallucinatedAdvisories"], 0) != 2 {
			t.Fatalf("unexpected AI report values: %+v", out)
		}
		if len(asList(out["groups"])) != 1 || len(asList(out["items"])) != 1 {
			t.Fatalf("expected 1 group and 1 item: %+v", out)
		}
	})

	t.Run("get_sbom respects includeContent and returns metadata + cyclonedxJson", func(t *testing.T) {
		rec1, resp1 := call("sf_mcp_read", "tools/call", map[string]any{
			"name":      "get_sbom",
			"arguments": map[string]any{"runId": "run_1", "includeContent": false},
		})
		if rec1.Code != http.StatusOK {
			t.Fatalf("get_sbom false status=%d body=%s", rec1.Code, rec1.Body.String())
		}
		out1 := toolTextJSON(t, resp1)
		if out1["digest"] != "sha256:1234" || out1["specVersion"] != "1.6" || out1["cyclonedxJson"] != nil {
			t.Fatalf("get_sbom(includeContent=false) unexpected: %+v", out1)
		}

		rec2, resp2 := call("sf_mcp_read", "tools/call", map[string]any{
			"name":      "get_sbom",
			"arguments": map[string]any{"runId": "run_1", "includeContent": true},
		})
		if rec2.Code != http.StatusOK {
			t.Fatalf("get_sbom true status=%d body=%s", rec2.Code, rec2.Body.String())
		}
		out2 := toolTextJSON(t, resp2)
		if !runClient.lastSbom.GetIncludeContent() {
			t.Fatal("expected IncludeContent=true forwarded to RunService.GetSbom")
		}
		cdx := asMap(out2["cyclonedxJson"])
		if cdx["bomFormat"] != "CycloneDX" || asMap(out2["sbom"])["digest"] != "sha256:1234" {
			t.Fatalf("get_sbom(includeContent=true) unexpected: %+v", out2)
		}
	})

	t.Run("list_workflows, list_templates, clone_template, generate_workflow_preview, get_run_status, get_findings, export_submission_json", func(t *testing.T) {
		// list_workflows filters by scopedWorkflowId (wf_1 only)
		_, respWF := call("sf_mcp_read", "tools/call", map[string]any{"name": "list_workflows", "arguments": map[string]any{"limit": 10}})
		wfs := asList(toolTextJSON(t, respWF)["workflows"])
		if len(wfs) != 1 || asMap(wfs[0])["id"] != "wf_1" {
			t.Fatalf("scoped list_workflows = %+v, want only wf_1", wfs)
		}

		// list_templates filters by tags
		_, respTpl := call("sf_mcp_read", "tools/call", map[string]any{"name": "list_templates", "arguments": map[string]any{"tags": []string{"kotlin"}}})
		tpls := asList(toolTextJSON(t, respTpl)["templates"])
		if len(tpls) != 1 || asMap(tpls[0])["slug"] != "kotlin-gate" {
			t.Fatalf("list_templates(tags=kotlin) = %+v", tpls)
		}

		// clone_template requires mcp:write
		recClone, respClone := call("sf_mcp_write", "tools/call", map[string]any{"name": "clone_template", "arguments": map[string]any{"templateId": "tpl_1", "newWorkflowName": "My Clone"}})
		if recClone.Code != http.StatusOK || toolTextJSON(t, respClone)["workflowId"] != "wf_cloned_1" {
			t.Fatalf("clone_template status=%d resp=%+v", recClone.Code, respClone)
		}

		// generate_workflow_preview
		recGen, respGen := call("sf_mcp_read", "tools/call", map[string]any{"name": "generate_workflow_preview", "arguments": map[string]any{"prompt": "scan kotlin", "locale": "en"}})
		if recGen.Code != http.StatusOK || toolTextJSON(t, respGen)["suggestedName"] != "Kotlin Gate" {
			t.Fatalf("generate_workflow_preview status=%d resp=%+v", recGen.Code, respGen)
		}

		// get_run_status
		recStatus, respStatus := call("sf_mcp_read", "tools/call", map[string]any{"name": "get_run_status", "arguments": map[string]any{"runId": "run_1"}})
		statusOut := toolTextJSON(t, respStatus)
		if recStatus.Code != http.StatusOK || statusOut["runId"] != "run_1" || len(asList(statusOut["nodeStatuses"])) != 1 {
			t.Fatalf("get_run_status status=%d out=%+v", recStatus.Code, statusOut)
		}

		// get_findings
		recFind, respFind := call("sf_mcp_read", "tools/call", map[string]any{"name": "get_findings", "arguments": map[string]any{"runId": "run_1", "category": "SAST", "minSeverity": "HIGH", "limit": 10}})
		findOut := toolTextJSON(t, respFind)
		if recFind.Code != http.StatusOK || len(asList(findOut["findings"])) != 1 || asMap(findOut["pageInfo"])["totalCount"] == nil {
			t.Fatalf("get_findings status=%d out=%+v", recFind.Code, findOut)
		}

		// export_submission_json returns exact UTF-8 submission JSON
		recSub, respSub := call("sf_mcp_read", "tools/call", map[string]any{"name": "export_submission_json", "arguments": map[string]any{"runId": "run_1"}})
		if recSub.Code != http.StatusOK {
			t.Fatalf("export_submission_json status=%d", recSub.Code)
		}
		subText := asString(asMap(asList(asMap(respSub["result"])["content"])[0])["text"])
		if subText != string(runClient.submission) {
			t.Fatalf("submission text = %q, want %q", subText, string(runClient.submission))
		}
	})

	t.Run("RBAC and scopedWorkflowId enforcement", func(t *testing.T) {
		// CI scoped token cannot call MCP tools.
		if rec, _ := call("sf_ci_start", "tools/call", map[string]any{"name": "run_workflow", "arguments": map[string]any{"workflowId": "wf_1"}}); rec.Code != http.StatusForbidden {
			t.Fatalf("ci:startRun on MCP status=%d, want 403", rec.Code)
		}
		// mcp:read cannot call run_workflow, clone_template, or cross-workflow run_2.
		for _, tc := range []struct {
			name string
			args map[string]any
		}{
			{"run_workflow", map[string]any{"workflowId": "wf_1"}},
			{"clone_template", map[string]any{"templateId": "tpl_1", "newWorkflowName": "X"}},
			{"get_run_status", map[string]any{"runId": "run_2"}},
			{"get_findings", map[string]any{"runId": "run_2"}},
			{"get_ai_report", map[string]any{"runId": "run_2"}},
			{"export_submission_json", map[string]any{"runId": "run_2"}},
			{"get_sbom", map[string]any{"runId": "run_2"}},
		} {
			if rec, _ := call("sf_mcp_read", "tools/call", map[string]any{"name": tc.name, "arguments": tc.args}); rec.Code != http.StatusForbidden {
				t.Fatalf("mcp:read %s(%v) status=%d, want 403", tc.name, tc.args, rec.Code)
			}
		}
		// mcp:run scoped to wf_1 cannot run wf_2.
		if rec, _ := call("sf_mcp_run", "tools/call", map[string]any{"name": "run_workflow", "arguments": map[string]any{"workflowId": "wf_2"}}); rec.Code != http.StatusForbidden {
			t.Fatalf("mcp:run wf_2 status=%d, want 403", rec.Code)
		}
	})
}

func TestMCPServer_AllFiveResourcesAndRBAC(t *testing.T) {
	gw, _ := newMCPTestGateway()

	readRes := func(token, uri string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "resources/read",
			"params":  map[string]any{"uri": uri},
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer "+token)
		gw.mcpServerHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	cases := []struct {
		uri      string
		wantMIME string
		wantSub  string
	}{
		{"secflow://plugins", "application/json", "scan.sast.kotlin"},
		{"secflow://templates", "application/json", "kotlin-gate"},
		{"secflow://runs/run_1/submission.json", "application/json", "src/Controller.kt"},
		{"secflow://runs/run_1/report.md", "text/markdown", "# SecFlow Report"},
		{"secflow://runs/run_1/sbom.cdx.json", "application/vnd.cyclonedx+json", "CycloneDX"},
	}
	for _, tc := range cases {
		t.Run("read/"+tc.uri, func(t *testing.T) {
			rec, resp := readRes("sf_mcp_read", tc.uri)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			contents := asList(asMap(resp["result"])["contents"])
			if len(contents) != 1 {
				t.Fatalf("expected 1 content item, got %+v", contents)
			}
			item := asMap(contents[0])
			if item["mimeType"] != tc.wantMIME {
				t.Fatalf("mimeType = %q, want %q", item["mimeType"], tc.wantMIME)
			}
			if !strings.Contains(asString(item["text"]), tc.wantSub) {
				t.Fatalf("text %q missing %q", asString(item["text"]), tc.wantSub)
			}
		})
	}

	// Cross-workflow run_2 resources must be 403 FORBIDDEN for wf_1-scoped token.
	for _, uri := range []string{
		"secflow://runs/run_2/submission.json",
		"secflow://runs/run_2/report.md",
		"secflow://runs/run_2/sbom.cdx.json",
	} {
		t.Run("forbidden/"+uri, func(t *testing.T) {
			rec, _ := readRes("sf_mcp_read", uri)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("cross-workflow %s status=%d, want 403", uri, rec.Code)
			}
		})
	}

	// mcp:run token without mcp:read cannot read any resource.
	if rec, _ := readRes("sf_mcp_run", "secflow://plugins"); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp:run reading plugins status=%d, want 403", rec.Code)
	}
}
