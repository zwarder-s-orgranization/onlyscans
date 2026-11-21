package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

type fakePluginRegistryServer struct {
	secflowv1.UnimplementedPluginRegistryServiceServer
	plugins []*secflowv1.RegisteredPlugin
}

func (f *fakePluginRegistryServer) ListPlugins(_ context.Context, _ *secflowv1.ListPluginsRequest) (*secflowv1.ListPluginsResponse, error) {
	return &secflowv1.ListPluginsResponse{Plugins: f.plugins}, nil
}

func TestGenerateWorkflowFromPrompt_UsesLLMAndValidatesPlugins(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		draft := map[string]any{
			"suggestedName":        "PR Kotlin Security Workflow",
			"suggestedDescription": "Проверка PR на секреты и SAST с уведомлением в Telegram.",
			"nodes": []map[string]any{
				{"id": "t1", "pluginId": "trigger.webhook", "label": "PR Webhook", "params": map[string]any{"gitProvider": "GITHUB", "webhookSecret": "should-be-stripped"}},
				{"id": "s1", "pluginId": "source.git", "label": "Git Clone", "params": map[string]any{"repoUrl": "https://github.com/TBagirov/training"}},
				{"id": "a1", "pluginId": "scan.sast.kotlin", "label": "Kotlin SAST", "params": map[string]any{}},
				{"id": "n1", "pluginId": "notify.telegram", "label": "Telegram", "params": map[string]any{"chatId": "123", "botToken": "should-be-stripped"}},
			},
			"edges": []map[string]any{
				{"source": "t1", "target": "s1", "sourceHandle": "default"},
				{"source": "s1", "target": "a1", "sourceHandle": "default"},
				{"source": "a1", "target": "n1", "sourceHandle": "default"},
			},
		}
		raw, _ := json.Marshal(draft)
		resp, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": string(raw)}}},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	cfg := llmConfig{BaseURL: srv.URL + "/v1", APIKey: "sk-test", Model: "wf-model"}
	resp, usedLLM, model, mode := generateWorkflowFromPrompt(context.Background(), cfg, "Проверяй PR на SAST и шли в Telegram")
	if !usedLLM || model != "wf-model" || mode != secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD {
		t.Fatalf("got usedLLM=%v model=%q mode=%v", usedLLM, model, mode)
	}
	if resp.GetSuggestedName() != "PR Kotlin Security Workflow" {
		t.Fatalf("name = %q", resp.GetSuggestedName())
	}
	if len(resp.GetGraph().GetNodes()) != 4 {
		t.Fatalf("nodes = %d, want 4", len(resp.GetGraph().GetNodes()))
	}
	for _, n := range resp.GetGraph().GetNodes() {
		if len(n.GetSecretBindings()) != 0 {
			t.Fatalf("preview node %s must not emit empty secret bindings: %+v", n.GetId(), n.GetSecretBindings())
		}
		params := map[string]any{}
		_ = json.Unmarshal(n.GetParamsJson(), &params)
		if _, leaked := params["webhookSecret"]; leaked {
			t.Fatal("draft leaked webhookSecret")
		}
		if _, leaked := params["botToken"]; leaked {
			t.Fatal("draft leaked botToken")
		}
	}
	if len(resp.GetMissingFields()) == 0 {
		t.Fatal("expected MissingFields to highlight unbound required secrets")
	}
}

func TestGenerateWorkflow_QueriesLivePluginRegistryAndValidatesStructure(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	baseCatalog := defaultPluginCatalog()
	var registered []*secflowv1.RegisteredPlugin
	for _, pid := range baseCatalog.order {
		registered = append(registered, &secflowv1.RegisteredPlugin{
			Manifest: baseCatalog.get(pid),
			Status:   secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE,
		})
	}
	registered = append(registered, &secflowv1.RegisteredPlugin{
		Manifest: &secflowv1.PluginManifest{
			PluginId:    "scan.spring-config",
			DisplayName: "Spring Config Hardening",
			Category:    secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
			OutputPorts: []*secflowv1.PortDefinition{{Id: "default"}},
			IsExternal:  true,
		},
		Status: secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE,
	})
	secflowv1.RegisterPluginRegistryServiceServer(gs, &fakePluginRegistryServer{plugins: registered})
	go func() { _ = gs.Serve(lis) }()
	defer gs.GracefulStop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		draft := map[string]any{
			"suggestedName":        "Spring Hardening Workflow",
			"suggestedDescription": "Проверка конфигурации Spring внешним плагином.",
			"nodes": []map[string]any{
				{"id": "t1", "pluginId": "trigger.manual", "label": "Manual", "params": map[string]any{}},
				{"id": "s1", "pluginId": "source.upload", "label": "Upload", "params": map[string]any{"sourceId": "pending-upload"}},
				{"id": "ext1", "pluginId": "scan.spring-config", "label": "Spring Config", "params": map[string]any{}},
			},
			"edges": []map[string]any{
				{"source": "t1", "target": "s1", "sourceHandle": "default"},
				{"source": "s1", "target": "ext1", "sourceHandle": "default"},
			},
		}
		raw, _ := json.Marshal(draft)
		resp, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": string(raw)}}},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	liveCatalog := fetchLivePluginCatalog(t.Context(), lis.Addr().String())
	if !liveCatalog.has("scan.spring-config") {
		t.Fatal("expected live plugin registry to include external scan.spring-config plugin")
	}
	cfg := llmConfig{BaseURL: srv.URL + "/v1", APIKey: "sk-test", Model: "wf-model"}
	resp, meta := generateWorkflowWithCatalog(t.Context(), cfg, "Проверь Spring конфиги", "ru", liveCatalog)
	if !meta.UsedLLM {
		t.Fatal("expected LLM draft with live external plugin to pass validation")
	}
	foundExternal := false
	for _, n := range resp.GetGraph().GetNodes() {
		if n.GetPluginId() == "scan.spring-config" {
			foundExternal = true
		}
	}
	if !foundExternal {
		t.Fatal("external plugin scan.spring-config missing from generated Workflow")
	}
}

func TestGenerateWorkflow_RejectsInvalidStructureAndFallsBackWithoutGlossaryDrift(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Invalid DAG: analyzer without source node before it + cycle.
		badDraft := map[string]any{
			"suggestedName": "Broken",
			"nodes": []map[string]any{
				{"id": "t1", "pluginId": "trigger.manual", "label": "Manual", "params": map[string]any{}},
				{"id": "a1", "pluginId": "scan.secrets", "label": "Secrets", "params": map[string]any{}},
			},
			"edges": []map[string]any{
				{"source": "t1", "target": "a1", "sourceHandle": "default"},
				{"source": "a1", "target": "t1", "sourceHandle": "default"},
			},
		}
		raw, _ := json.Marshal(badDraft)
		resp, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": string(raw)}}},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	cfg := llmConfig{BaseURL: srv.URL + "/v1", APIKey: "sk-test", Model: "wf-model"}
	resp, meta := generateWorkflowWithCatalog(t.Context(), cfg, "Проверь секреты", "ru", defaultPluginCatalog())
	if meta.UsedLLM {
		t.Fatal("expected structurally invalid LLM draft to fall back")
	}
	blob := strings.ToLower(resp.GetSuggestedName() + " " + resp.GetSuggestedDescription() + " " + resp.GetRationale())
	for _, forbidden := range []string{"сценарий", "сценария", "scenario", "pipeline"} {
		if strings.Contains(blob, forbidden) {
			t.Fatalf("glossary drift detected (%q) in generated metadata: %q", forbidden, blob)
		}
	}
	for _, n := range resp.GetGraph().GetNodes() {
		if len(n.GetSecretBindings()) != 0 {
			t.Fatalf("fallback node %s must not emit empty SecretBinding: %+v", n.GetId(), n.GetSecretBindings())
		}
	}
}

func TestFallbackWorkflowFromPrompt_AdaptsToKeywords(t *testing.T) {
	resp := fallbackWorkflowFromPrompt("Запускай каждый день сканирование SCA и SBOM по git и отправляй AI отчёт в Telegram")
	plugins := map[string]bool{}
	for _, n := range resp.GetGraph().GetNodes() {
		plugins[n.GetPluginId()] = true
		if len(n.GetSecretBindings()) != 0 {
			t.Fatalf("node %s emitted unbound secret bindings: %+v", n.GetId(), n.GetSecretBindings())
		}
	}
	for _, want := range []string{"trigger.schedule", "source.git", "scan.sca", "sbom.generate", "ai.explain", "notify.telegram"} {
		if !plugins[want] {
			t.Fatalf("expected plugin %s in generated fallback graph, got %+v", want, plugins)
		}
	}
}
