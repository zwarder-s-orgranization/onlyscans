package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/report"
)

func TestBuiltinTemplates_ValidDAGSchemasAndNoEmptySecretBindings(t *testing.T) {
	t.Parallel()
	templates := builtinTemplateGraphs()
	if len(templates) != 7 {
		t.Fatalf("expected 7 built-in templates, got %d", len(templates))
	}

	bySlug := make(map[string]builtinTemplate, len(templates))
	for _, tpl := range templates {
		bySlug[tpl.slug] = tpl
		t.Run(tpl.slug, func(t *testing.T) {
			t.Parallel()
			metaBlob := strings.ToLower(tpl.name + " " + tpl.description + " " + tpl.problem)
			for _, forbidden := range []string{"сценарий", "сценария", "scenario", "pipeline"} {
				if strings.Contains(metaBlob, forbidden) {
					t.Fatalf("glossary drift (%q) in template %s metadata: %q", forbidden, tpl.slug, metaBlob)
				}
			}

			g := tpl.graph
			if g == nil || g.GetSchemaVersion() != 1 || len(g.GetNodes()) < 3 {
				t.Fatalf("template %s has invalid graph", tpl.slug)
			}

			for _, n := range g.GetNodes() {
				for _, b := range n.GetSecretBindings() {
					if strings.TrimSpace(b.GetSecretRef()) == "" {
						t.Fatalf("template %s node %s emitted empty SecretBinding (violates workflow-graph.schema.json)", tpl.slug, n.GetId())
					}
				}
				params := map[string]any{}
				if len(n.GetParamsJson()) > 0 {
					if err := json.Unmarshal(n.GetParamsJson(), &params); err != nil {
						t.Fatalf("template %s node %s invalid params JSON: %v", tpl.slug, n.GetId(), err)
					}
				}
				if err := paramschema.Check(n.GetPluginId(), params); err != nil {
					t.Fatalf("template %s node %s (%s) failed paramschema.Check: %v", tpl.slug, n.GetId(), n.GetPluginId(), err)
				}
			}

			for _, issue := range engine.Validate(toEngine(g)) {
				if issue.Code == engine.CodeMissingSecret {
					continue
				}
				t.Fatalf("template %s failed engine.Validate: %+v", tpl.slug, issue)
			}
			for _, issue := range extraGraphIssues(g) {
				t.Fatalf("template %s failed extraGraphIssues: %+v", tpl.slug, issue)
			}
		})
	}

	// Verify severity-escalation-router has real outgoing edges on all 4 maxSeverity ports.
	swTpl := bySlug["severity-escalation-router"]
	switchPorts := map[string]string{}
	nodePlugin := map[string]string{}
	for _, n := range swTpl.graph.GetNodes() {
		nodePlugin[n.GetId()] = n.GetPluginId()
	}
	for _, e := range swTpl.graph.GetEdges() {
		if nodePlugin[e.GetSourceNodeId()] == "logic.switch" {
			switchPorts[e.GetSourceHandle()] = nodePlugin[e.GetTargetNodeId()]
		}
	}
	wantSwitch := map[string]string{
		"CRITICAL":   "ai.explain",
		"HIGH":       "notify.smtp",
		"MEDIUM_LOW": "report.export",
		"CLEAN":      "report.export",
	}
	for port, wantTarget := range wantSwitch {
		if switchPorts[port] != wantTarget {
			t.Fatalf("severity-escalation-router port %s -> %q, want %q", port, switchPorts[port], wantTarget)
		}
	}

	// Verify fast-pr-ci-gate uses trigger expressions and no hardcoded training repo URL.
	prTpl := bySlug["fast-pr-ci-gate"]
	checkedGit := false
	for _, n := range prTpl.graph.GetNodes() {
		if n.GetPluginId() != "source.git" {
			continue
		}
		checkedGit = true
		var params map[string]any
		_ = json.Unmarshal(n.GetParamsJson(), &params)
		if params["repoUrl"] != "{{ $trigger.repoUrl }}" || params["gitRef"] != "{{ $trigger.commitSha }}" {
			t.Fatalf("fast-pr-ci-gate source.git params = %+v, want trigger expressions", params)
		}
	}
	if !checkedGit {
		t.Fatal("fast-pr-ci-gate missing source.git node")
	}

	// Verify regression-new-findings wires logic.compare(true) -> logic.filter(onlyNewVsBaseline:true) -> ai.explain.
	regTpl := bySlug["regression-new-findings"]
	regPlugins := map[string]string{}
	for _, n := range regTpl.graph.GetNodes() {
		regPlugins[n.GetId()] = n.GetPluginId()
	}
	foundCompareToFilter := false
	for _, e := range regTpl.graph.GetEdges() {
		if regPlugins[e.GetSourceNodeId()] == "logic.compare" && e.GetSourceHandle() == "true" && regPlugins[e.GetTargetNodeId()] == "logic.filter" {
			foundCompareToFilter = true
		}
	}
	if !foundCompareToFilter {
		t.Fatal("regression-new-findings missing logic.compare(true) -> logic.filter edge")
	}
}

func TestSanitizeGraph_OmitsEmptySecretBindingsAndStripsInternalURLs(t *testing.T) {
	t.Parallel()
	in := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{
				Id:             "src1",
				PluginId:       "source.git",
				ParamsJson:     []byte(`{"repoUrl":"http://127.0.0.1:3000/private/repo","gitRef":"main","gitToken":"ghp_leaked"}`),
				SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "gitToken", SecretRef: "sec_git_1"}},
			},
			{
				Id:             "ai1",
				PluginId:       "ai.explain",
				ParamsJson:     []byte(`{"baseUrl":"http://ollama:11434","model":"llama3.2","llmApiKey":"sk-leaked"}`),
				SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "llmApiKey", SecretRef: "sec_llm_1"}},
			},
			{
				Id:             "wh1",
				PluginId:       "notify.webhook",
				ParamsJson:     []byte(`{"url":"http://localhost:8080/webhooks/inspector/dev","hmacSecret":"whsec_leaked"}`),
				SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "hmacSecret", SecretRef: "sec_wh_1"}},
			},
			{
				Id:             "smtp1",
				PluginId:       "notify.smtp",
				ParamsJson:     []byte(`{"to":["appsec@example.com"],"subject":"Alert","smtpAddr":"mailpit:1025","smtpPassword":"pw"}`),
				SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "smtpPassword", SecretRef: "sec_smtp_1"}},
			},
			{
				Id:         "srcPublic",
				PluginId:   "source.git",
				ParamsJson: []byte(`{"repoUrl":"https://github.com/TBagirov/training","gitRef":"{{ $trigger.commitSha }}"}`),
			},
		},
	}

	out := sanitizeGraph(in)
	for _, n := range out.GetNodes() {
		if len(n.GetSecretBindings()) != 0 {
			t.Fatalf("node %s must not keep secret bindings or empty slots: %+v", n.GetId(), n.GetSecretBindings())
		}
		var params map[string]any
		_ = json.Unmarshal(n.GetParamsJson(), &params)
		switch n.GetId() {
		case "src1":
			if _, ok := params["repoUrl"]; ok {
				t.Fatalf("local loopback repoUrl should be stripped: %+v", params)
			}
			if _, ok := params["gitToken"]; ok {
				t.Fatalf("inline gitToken should be stripped: %+v", params)
			}
		case "ai1":
			if _, ok := params["baseUrl"]; ok {
				t.Fatalf("internal ollama baseUrl should be stripped: %+v", params)
			}
			if _, ok := params["llmApiKey"]; ok {
				t.Fatalf("inline llmApiKey should be stripped: %+v", params)
			}
		case "wh1":
			if _, ok := params["url"]; ok {
				t.Fatalf("localhost webhook url should be stripped: %+v", params)
			}
		case "smtp1":
			if _, ok := params["smtpAddr"]; ok {
				t.Fatalf("internal mailpit smtpAddr should be stripped: %+v", params)
			}
		case "srcPublic":
			if params["repoUrl"] != "https://github.com/TBagirov/training" {
				t.Fatalf("public repoUrl should be preserved: %+v", params)
			}
		}
	}
}

func TestAIReportFromPayload_MatchesByFingerprintAfterFilterAndPopulatesLines(t *testing.T) {
	t.Parallel()
	authoritative := []report.Finding{
		{
			Category:    "SECRET",
			Class:       "password",
			Severity:    "CRITICAL",
			Path:        "src/main/resources/application.yml",
			Line:        12,
			EndLine:     12,
			Description: "Hardcoded DB password",
		},
		{
			Category:    "SAST",
			Class:       "sql-injection",
			Severity:    "HIGH",
			Path:        "src/main/kotlin/OrderController.kt",
			Line:        42,
			EndLine:     45,
			Description: "Unsanitized SQL interpolation",
		},
		{
			Category:    "SCA",
			Severity:    "CRITICAL",
			Path:        "build.gradle.kts",
			Group:       "org.apache.commons",
			Artifact:    "commons-text",
			Version:     "1.9",
			AdvisoryID:  "CVE-2022-42889",
			Description: "Text4Shell RCE",
		},
	}

	// Simulate logic.filter keeping only the 2nd (SAST) and 3rd (SCA) findings,
	// so branch-local ai.explain numbered them F-001 and F-002!
	payload, err := json.Marshal(map[string]any{
		"quality":          "VERIFIED",
		"modelId":          "llama3.2",
		"providerMode":     "OLLAMA",
		"privacyMode":      "REDACTED_SNIPPET",
		"cached":           true,
		"tokensIn":         200,
		"tokensOut":        110,
		"latencyMs":        420,
		"releaseDecision":  "BLOCK",
		"executiveSummary": "Критичные находки в фильтрованной ветке.",
		"groups": []map[string]any{
			{"title": "Filtered Critical/High", "maxSeverity": "CRITICAL", "findingIds": []string{"F-001", "F-002"}, "summary": "SAST + SCA"},
		},
		"items": []map[string]any{
			{
				"findingId":            "F-001",
				"fingerprint":          "SAST|src/main/kotlin/OrderController.kt|sql-injection|||",
				"priorityRank":         1,
				"plainLanguageRisk":    "SQL-инъекция позволяет читать чужие данные.",
				"businessImpact":       "Утечка базы данных.",
				"remediationSteps":     []string{"Используйте параметризованные запросы."},
				"referencedAdvisories": []string{},
			},
			{
				"findingId":            "F-002",
				"fingerprint":          "SCA|build.gradle.kts||org.apache.commons|commons-text|CVE-2022-42889",
				"priorityRank":         2,
				"plainLanguageRisk":    "Text4Shell CVE-2022-42889.",
				"businessImpact":       "RCE на сервере.",
				"remediationSteps":     []string{"Обновите commons-text до 1.10.0."},
				"referencedAdvisories": []string{"CVE-2022-42889"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	rep := aiReportFromPayload(authoritative, payload)
	if len(rep.GetItems()) != 2 {
		t.Fatalf("expected 2 mapped items, got %d", len(rep.GetItems()))
	}
	if !rep.GetCached() || rep.GetTokensIn() != 200 || rep.GetTokensOut() != 110 || rep.GetLatencyMs() != 420 {
		t.Fatalf("telemetry fields not preserved: %+v", rep)
	}

	// Branch F-001 must map to authoritative F-002 (SAST OrderController.kt:42-45), NOT F-001 (SECRET)!
	it0 := rep.GetItems()[0]
	if it0.GetFindingId() != "F-002" {
		t.Fatalf("item[0] findingId = %q, want F-002", it0.GetFindingId())
	}
	if it0.GetFinding().GetFindingClass() != "sql-injection" || it0.GetFinding().GetLine() != 42 || it0.GetFinding().GetEndLine() != 45 {
		t.Fatalf("item[0] grounded finding mismatch: %+v", it0.GetFinding())
	}

	// Branch F-002 must map to authoritative F-003 (SCA commons-text).
	it1 := rep.GetItems()[1]
	if it1.GetFindingId() != "F-003" || it1.GetFinding().GetArtifact() != "commons-text" || it1.GetFinding().GetAdvisoryId() != "CVE-2022-42889" {
		t.Fatalf("item[1] grounded finding mismatch: %+v", it1)
	}

	// Group findingIds must also be remapped to authoritative IDs F-002, F-003.
	if len(rep.GetGroups()) != 1 || strings.Join(rep.GetGroups()[0].GetFindingIds(), ",") != "F-002,F-003" {
		t.Fatalf("group findingIds not remapped: %+v", rep.GetGroups())
	}
}

func TestReadableReport_IncludesAISummaryAndCompleteFindingDetails(t *testing.T) {
	t.Parallel()
	findings := []report.Finding{
		{
			Category:    "SECRET",
			Class:       "password",
			Severity:    "CRITICAL",
			Path:        "src/main/resources/application.yml",
			Line:        12,
			EndLine:     13,
			Description: "Hardcoded credential <script>alert(1)</script>",
			Remediation: "Move password to SecretStore.",
		},
		{
			Category:    "SCA",
			Severity:    "HIGH",
			Path:        "build.gradle.kts",
			Group:       "org.apache.commons",
			Artifact:    "commons-text",
			Version:     "1.9",
			AdvisoryID:  "CVE-2022-42889",
			Description: "Text4Shell vulnerability",
			Remediation: "Upgrade commons-text to >= 1.10.0.",
		},
	}
	ai := &secflowv1.AIReport{
		Quality:          secflowv1.AIQuality_AI_QUALITY_VERIFIED,
		ReleaseDecision:  secflowv1.ReleaseDecision_RELEASE_DECISION_BLOCK,
		ExecutiveSummary: "Release blocked due to hardcoded password and CVE-2022-42889.",
		ModelId:          "gpt-4o-mini",
		Items: []*secflowv1.AIReportItem{
			{PriorityRank: 1, RemediationSteps: []string{"Rotate leaked password immediately."}},
			{PriorityRank: 2, RemediationSteps: []string{"Bump commons-text to 1.10.0."}},
		},
	}

	md := string(readable(findings, secflowv1.ReportFormat_REPORT_FORMAT_MARKDOWN, ai))
	for _, want := range []string{
		"BLOCK",
		"VERIFIED",
		"Release blocked due to hardcoded password and CVE-2022-42889.",
		"Rotate leaked password immediately.",
		"Bump commons-text to 1.10.0.",
		"[CRITICAL] [SECRET]",
		"password",
		"src/main/resources/application.yml:12-13",
		"Move password to SecretStore.",
		"org.apache.commons:commons-text:1.9 (CVE-2022-42889)",
		"Upgrade commons-text to >= 1.10.0.",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown report missing %q:\n%s", want, md)
		}
	}

	htmlOut := string(readable(findings, secflowv1.ReportFormat_REPORT_FORMAT_HTML, ai))
	if strings.Contains(htmlOut, "<script>alert(1)</script>") {
		t.Fatalf("HTML report failed to escape script tag:\n%s", htmlOut)
	}
	for _, want := range []string{
		"BLOCK",
		"VERIFIED",
		"Release blocked due to hardcoded password and CVE-2022-42889.",
		"Rotate leaked password immediately.",
		"src/main/resources/application.yml:12-13",
		"org.apache.commons:commons-text:1.9 (CVE-2022-42889)",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
	} {
		if !strings.Contains(htmlOut, want) {
			t.Fatalf("HTML report missing %q:\n%s", want, htmlOut)
		}
	}
}

func TestAIReportFromPayload_DisambiguatesDuplicateClassFindingsByLine(t *testing.T) {
	t.Parallel()
	authoritative := []report.Finding{
		{Category: "SAST", Class: "sql-injection", Severity: "HIGH", Path: "OrderController.kt", Line: 15, EndLine: 15},
		{Category: "SAST", Class: "sql-injection", Severity: "HIGH", Path: "OrderController.kt", Line: 42, EndLine: 44},
	}
	payload, err := json.Marshal(map[string]any{
		"quality":          "VERIFIED",
		"releaseDecision":  "BLOCK",
		"executiveSummary": "Две SQL-инъекции в одном файле.",
		"items": []map[string]any{
			{
				"findingId":         "F-001",
				"fingerprint":       "SAST|OrderController.kt|sql-injection|||",
				"priorityRank":      1,
				"plainLanguageRisk": "Первая SQLi.",
				"finding":           map[string]any{"category": "SAST", "path": "OrderController.kt", "line": 15, "findingClass": "sql-injection"},
			},
			{
				"findingId":         "F-002",
				"fingerprint":       "SAST|OrderController.kt|sql-injection|||",
				"priorityRank":      2,
				"plainLanguageRisk": "Вторая SQLi.",
				"finding":           map[string]any{"category": "SAST", "path": "OrderController.kt", "line": 42, "findingClass": "sql-injection"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	rep := aiReportFromPayload(authoritative, payload)
	if len(rep.GetItems()) != 2 {
		t.Fatalf("expected 2 items, got %d", len(rep.GetItems()))
	}
	if rep.GetItems()[0].GetFindingId() != "F-001" || rep.GetItems()[0].GetFinding().GetLine() != 15 {
		t.Fatalf("item[0] = %+v, want F-001 line 15", rep.GetItems()[0])
	}
	if rep.GetItems()[1].GetFindingId() != "F-002" || rep.GetItems()[1].GetFinding().GetLine() != 42 {
		t.Fatalf("item[1] = %+v, want F-002 line 42", rep.GetItems()[1])
	}
}

func TestExtractExplainFromTaskPayload_SupportsTraceAndLegacyEnvelope(t *testing.T) {
	t.Parallel()
	explainJSON := `{"quality":"VERIFIED","releaseDecision":"WARN","executiveSummary":"OK"}`

	traceRaw, _ := json.Marshal(engine.NodeTrace{
		Output: engine.Envelope{
			Vars: map[string]string{"explain": explainJSON},
		},
		Ports: []string{"default"},
	})
	if got := string(extractExplainFromTaskPayload(traceRaw)); got != explainJSON {
		t.Fatalf("from NodeTrace = %q, want %q", got, explainJSON)
	}

	legacyEnvRaw, _ := json.Marshal(engine.Envelope{
		Vars: map[string]string{"explain": explainJSON},
	})
	if got := string(extractExplainFromTaskPayload(legacyEnvRaw)); got != explainJSON {
		t.Fatalf("from legacy Envelope = %q, want %q", got, explainJSON)
	}
}

func TestRerunFromNode_AuthorizesSecretDuringRerun(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx := context.Background()

	secResp, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Name:           "openrouter-key",
		Kind:           secflowv1.SecretKind_SECRET_KIND_LLM_API_KEY,
		PlaintextValue: "sk-or-v1-test-secret",
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	keyRef := secResp.GetSecret().GetSecretRef()

	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "AI Rerun Secret Test",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{
					Id:         "ai",
					PluginId:   "ai.explain",
					ParamsJson: []byte(`{"baseUrl":"https://openrouter.ai/api/v1","model":"openai/gpt-4o-mini"}`),
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "llmApiKey", SecretRef: keyRef},
					},
				},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "ai", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	wf := wfResp.GetWorkflow()

	// Seed a finished source run in memory.
	prevRunID := "run_prev_secret_test"
	s.runMu.Lock()
	s.runs[prevRunID] = &runState{
		run: &secflowv1.Run{
			Id:         prevRunID,
			WorkflowId: wf.GetId(),
			Status:     secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
		},
		graph: toEngine(wf.GetGraph()),
		payloads: map[string][]byte{
			"in:ai": []byte(`{"trigger":{"type":"MANUAL"},"findings":[],"vars":{}}`),
		},
		done:     map[string]engine.NodeTrace{},
		skipped:  map[string]bool{},
		queued:   map[string]bool{},
		finished: true,
	}
	s.runMu.Unlock()

	// Register a mock ai.explain worker that resolves the node's llmApiKey secret mid-rerun
	// and returns a grounded AI payload + redacted preview JSON.
	var resolvedSecret string
	var secretErr error
	link := &workerLink{
		instanceID: "ai-rerun-test",
		plugins:    []string{"ai.explain"},
		send: func(msg *secflowv1.ConnectResponse) error {
			task := msg.GetDispatchTask()
			if task == nil {
				return nil
			}
			go func() {
				secOut, err := s.ResolveScopedSecret(ctx, &secflowv1.ResolveScopedSecretRequest{
					SecretRef: keyRef,
					Scope: &secflowv1.ResolveScopedSecretRequest_NodeTask{
						NodeTask: &secflowv1.NodeTaskSecretScope{
							RunId:          task.GetRunId(),
							NodeRunId:      task.GetNodeRunId(),
							NodeId:         task.GetNodeId(),
							PluginId:       task.GetPluginId(),
							TaskLeaseToken: task.GetTaskLeaseToken(),
						},
					},
				})
				secretErr = err
				if secOut != nil {
					resolvedSecret = secOut.GetPlaintextValue()
				}
				patch := []byte(`{"quality":"FALLBACK","releaseDecision":"PASS","executiveSummary":"Ошибка ИИ-анализа (HTTP 400): bad model\nНаходок нет.","modelId":"template-fallback-v1","providerMode":"TEMPLATE_FALLBACK","privacyMode":"METADATA_ONLY","items":[],"groups":[]}`)
				preview := []byte(`{"quality":"FALLBACK","errorStatus":400,"errorCode":"HTTP_400","errorMessage":"HTTP 400: bad model"}`)
				s.deliver(&secflowv1.NodeResult{
					NodeRunId:           task.GetNodeRunId(),
					RunId:               task.GetRunId(),
					NodeId:              task.GetNodeId(),
					PluginId:            task.GetPluginId(),
					Status:              secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
					EnvelopePatchJson:   patch,
					RedactedPreviewJson: preview,
					ActiveOutputPorts:   []string{"default"},
				})
			}()
			return nil
		},
	}
	s.plugMu.Lock()
	s.workers["ai.explain"] = []*workerLink{link}
	s.plugMu.Unlock()

	rerunResp, err := s.RerunFromNode(ctx, &secflowv1.RerunFromNodeRequest{
		SourceRunId: prevRunID,
		NodeId:      "ai",
	})
	if err != nil {
		t.Fatalf("RerunFromNode: %v", err)
	}
	if secretErr != nil {
		t.Fatalf("ResolveScopedSecret during RerunFromNode failed: %v", secretErr)
	}
	if resolvedSecret != "sk-or-v1-test-secret" {
		t.Fatalf("resolvedSecret = %q, want sk-or-v1-test-secret", resolvedSecret)
	}
	newRun := rerunResp.GetRun()
	if newRun.GetAiReport() == nil || !strings.Contains(newRun.GetAiReport().GetExecutiveSummary(), "HTTP 400") {
		t.Fatalf("rerun AiReport missing error summary: %+v", newRun.GetAiReport())
	}
	if len(newRun.GetNodeRuns()) != 1 || !strings.Contains(string(newRun.GetNodeRuns()[0].GetRedactedPreviewJson()), `"errorStatus":400`) {
		t.Fatalf("rerun NodeRun missing RedactedPreviewJson: %+v", newRun.GetNodeRuns())
	}
}

func TestStripGoose_HandlesCRLF(t *testing.T) {
	t.Parallel()
	raw := "-- +goose Up\r\nCREATE TABLE runs (id text);\r\n-- +goose Down\r\nDROP TABLE runs;\r\n"
	got := stripGoose(raw)
	if !strings.Contains(got, "CREATE TABLE runs") {
		t.Fatalf("expected Up SQL to be preserved, got %q", got)
	}
	if strings.Contains(got, "DROP TABLE") {
		t.Fatalf("expected CRLF Down section to be stripped, got %q", got)
	}
}
