package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/report"
)

func TestWorkflowSecrets_VaultBindingsAndSanitizedTemplates(t *testing.T) {
	ctx := context.Background()
	s := newServer()

	// 1. Create vault secrets bound by reference via SecretBindings (never inline in paramsJson).
	tgResp, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Name:           "profile-telegram-bot",
		Kind:           secflowv1.SecretKind_SECRET_KIND_TELEGRAM_BOT_TOKEN,
		PlaintextValue: "999:vault-token",
	})
	if err != nil {
		t.Fatalf("CreateSecret telegram: %v", err)
	}
	tgRef := tgResp.GetSecret().GetSecretRef()

	aiResp, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Name:           "profile-llm-key",
		Kind:           secflowv1.SecretKind_SECRET_KIND_LLM_API_KEY,
		PlaintextValue: "sk-vault-456",
	})
	if err != nil {
		t.Fatalf("CreateSecret llm: %v", err)
	}
	aiKeyRef := aiResp.GetSecret().GetSecretRef()

	gitResp, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Name:           "profile-git-token",
		Kind:           secflowv1.SecretKind_SECRET_KIND_GIT_TOKEN,
		PlaintextValue: "ghp_vault_123",
	})
	if err != nil {
		t.Fatalf("CreateSecret git: %v", err)
	}
	gitKeyRef := gitResp.GetSecret().GetSecretRef()

	// 2. Create workflow using SecretBindings only.
	createResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Vault Secret Flow",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{
					Id:             "src",
					PluginId:       "source.git",
					ParamsJson:     []byte(`{"repoUrl":"https://github.com/TBagirov/training","gitRef":"main"}`),
					SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "gitToken", SecretRef: gitKeyRef}},
				},
				{
					Id:             "ai",
					PluginId:       "ai.explain",
					ParamsJson:     []byte(`{"baseUrl":"https://api.openai.com/v1","model":"gpt-4o-mini"}`),
					SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "llmApiKey", SecretRef: aiKeyRef}},
				},
				{
					Id:             "tg",
					PluginId:       "notify.telegram",
					ParamsJson:     []byte(`{"chatId":"-1001"}`),
					SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "botToken", SecretRef: tgRef}},
				},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "src", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "ai", TargetHandle: "default"},
				{Id: "e3", SourceNodeId: "ai", SourceHandle: "default", TargetNodeId: "tg", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	wf := createResp.GetWorkflow()
	if len(wf.GetValidationIssues()) != 0 {
		t.Fatalf("unexpected validation issues: %+v", wf.GetValidationIssues())
	}

	// 3. Updating non-secret fields without re-entering secrets preserves existing bindings.
	updResp, err := s.UpdateWorkflow(ctx, &secflowv1.UpdateWorkflowRequest{
		WorkflowId: wf.GetId(),
		Name:       wf.GetName(),
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "src", PluginId: "source.git", ParamsJson: []byte(`{"repoUrl":"https://github.com/TBagirov/training","gitRef":"develop"}`)},
				{Id: "ai", PluginId: "ai.explain", ParamsJson: []byte(`{"baseUrl":"https://openrouter.ai/api/v1","model":"openai/gpt-4o-mini"}`)},
				{Id: "tg", PluginId: "notify.telegram", ParamsJson: []byte(`{"chatId":"-1002"}`)},
			},
			Edges: wf.GetGraph().GetEdges(),
		},
	})
	if err != nil {
		t.Fatalf("UpdateWorkflow: %v", err)
	}
	for _, n := range updResp.GetWorkflow().GetGraph().GetNodes() {
		switch n.GetId() {
		case "ai":
			if len(n.GetSecretBindings()) != 1 || n.GetSecretBindings()[0].GetSecretRef() != aiKeyRef {
				t.Fatalf("ai llmApiKey binding lost on update: %+v", n.GetSecretBindings())
			}
		case "tg":
			if len(n.GetSecretBindings()) != 1 || n.GetSecretBindings()[0].GetSecretRef() != tgRef {
				t.Fatalf("telegram vault binding lost on update: %+v", n.GetSecretBindings())
			}
		case "src":
			if len(n.GetSecretBindings()) != 1 || n.GetSecretBindings()[0].GetSecretRef() != gitKeyRef {
				t.Fatalf("git token binding lost on update: %+v", n.GetSecretBindings())
			}
		}
	}

	// 4. Publishing as template strips all secret refs.
	tplResp, err := s.PublishTemplate(ctx, &secflowv1.PublishTemplateRequest{
		WorkflowId: wf.GetId(),
		Name:       "Sanitized Template",
	})
	if err != nil {
		t.Fatalf("PublishTemplate: %v", err)
	}
	for _, n := range tplResp.GetTemplate().GetSanitizedGraph().GetNodes() {
		for _, b := range n.GetSecretBindings() {
			if b.GetSecretRef() != "" {
				t.Fatalf("template leaked secretRef %q on node %s", b.GetSecretRef(), n.GetId())
			}
		}
	}
}

func TestGetAIReport_UsesGroundedWorkerPayload(t *testing.T) {
	ctx := context.Background()
	s := newServer()

	aiPayload, _ := json.Marshal(map[string]any{
		"quality":                        "VERIFIED",
		"modelId":                        "gpt-4o-mini",
		"providerMode":                   "CLOUD",
		"privacyMode":                    "REDACTED_SNIPPET",
		"strippedHallucinatedAdvisories": 0,
		"releaseDecision":                "BLOCK",
		"executiveSummary":               "Обнаружена критичная уязвимость CVE-2022-42889.",
		"groups": []map[string]any{
			{"title": "SCA", "maxSeverity": "CRITICAL", "findingIds": []string{"F-001"}, "summary": "Обновите commons-text."},
		},
		"items": []map[string]any{
			{
				"findingId":            "F-001",
				"priorityRank":         1,
				"plainLanguageRisk":    "Удалённое выполнение кода через StringSubstitutor.",
				"businessImpact":       "Компрометация бэкенда.",
				"remediationSteps":     []string{"Обновите commons-text до 1.10.0."},
				"referencedAdvisories": []string{"CVE-2022-42889"},
			},
		},
	})
	s.runs["run_ai"] = &runState{
		run: &secflowv1.Run{Id: "run_ai", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
		findings: []report.Finding{
			{Category: "SCA", Path: "build.gradle.kts", Severity: "CRITICAL", Group: "org.apache.commons", Artifact: "commons-text", Version: "1.9", AdvisoryID: "CVE-2022-42889"},
		},
		payloads: map[string][]byte{"ai_report": aiPayload},
	}

	resp, err := s.GetAIReport(ctx, &secflowv1.GetAIReportRequest{RunId: "run_ai"})
	if err != nil {
		t.Fatalf("GetAIReport: %v", err)
	}
	rep := resp.GetReport()
	if rep.GetQuality() != secflowv1.AIQuality_AI_QUALITY_VERIFIED || rep.GetModelId() != "gpt-4o-mini" {
		t.Fatalf("unexpected report meta: quality=%v model=%q", rep.GetQuality(), rep.GetModelId())
	}
	if !strings.Contains(rep.GetExecutiveSummary(), "CVE-2022-42889") || len(rep.GetItems()) != 1 {
		t.Fatalf("unexpected report body: %+v", rep)
	}
	if rep.GetItems()[0].GetFinding().GetArtifact() != "commons-text" {
		t.Fatalf("deterministic finding metadata not re-attached: %+v", rep.GetItems()[0].GetFinding())
	}
}

func TestGenerateCiConfig_PollsAndFailsOnCritical(t *testing.T) {
	ctx := context.Background()
	s := newServer()
	for _, prov := range []secflowv1.CiProvider{secflowv1.CiProvider_CI_PROVIDER_GITHUB_ACTIONS, secflowv1.CiProvider_CI_PROVIDER_GITLAB_CI} {
		resp, err := s.GenerateCiConfig(ctx, &secflowv1.GenerateCiConfigRequest{
			WorkflowId:     "wf_123",
			Provider:       prov,
			SecflowBaseUrl: "https://secflow.local",
		})
		if err != nil {
			t.Fatalf("GenerateCiConfig(%v): %v", prov, err)
		}
		yml := resp.GetYamlContent()
		for _, want := range []string{"startRun", "submission.json", "CRITICAL", "exit 1"} {
			if !strings.Contains(yml, want) {
				t.Fatalf("CI config (%v) missing %q:\n%s", prov, want, yml)
			}
		}
	}
}

func TestNodeHasMcpSecret_AllowsConnectionAuthSecret(t *testing.T) {
	ctx := context.Background()
	s := newServer()
	secResp, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Name:           "mcp-auth",
		Kind:           secflowv1.SecretKind_SECRET_KIND_MCP_AUTH_HEADER,
		PlaintextValue: "Bearer secret",
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	secRef := secResp.GetSecret().GetSecretRef()
	s.mcps["mcp_1"] = &secflowv1.MCPConnection{
		Id:      "mcp_1",
		Enabled: true,
		Config:  &secflowv1.MCPConnectionConfig{Name: "github", EndpointUrl: "https://mcp.example.com", AuthSecretRef: secRef},
	}
	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "MCP Flow",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "m1", PluginId: "mcp.tool", ParamsJson: []byte(`{"connectionId":"mcp_1","toolName":"create_issue","arguments":{}}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "m1", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	s.runs["run_mcp"] = &runState{run: &secflowv1.Run{Id: "run_mcp", WorkflowId: wfResp.GetWorkflow().GetId()}}
	if !s.nodeHasMcpSecret("run_mcp", "m1", secRef) {
		t.Fatal("expected mcp.tool node to authorize its connection authSecretRef")
	}
	if s.nodeHasMcpSecret("run_mcp", "m1", "sec_unrelated") {
		t.Fatal("unrelated secretRef must be rejected")
	}
}
