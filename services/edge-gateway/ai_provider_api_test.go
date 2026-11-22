package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeProviderBaseURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		mode string
		want string
	}{
		{"https://openrouter.ai", "openai-compatible", "https://openrouter.ai/api/v1"},
		{"https://openrouter.ai/api", "openai-compatible", "https://openrouter.ai/api/v1"},
		{"https://llm.skbkit.ru", "openai-compatible", "https://llm.skbkit.ru/v1"},
		{"https://llm.skbkit.ru/v1/", "openai-compatible", "https://llm.skbkit.ru/v1"},
		{"http://ollama:11434/", "local-ollama", "http://ollama:11434"},
	}
	for _, tc := range cases {
		if got := normalizeProviderBaseURL(tc.raw, tc.mode); got != tc.want {
			t.Errorf("normalizeProviderBaseURL(%q, %q) = %q, want %q", tc.raw, tc.mode, got, tc.want)
		}
	}
}

func TestParseModelsPayload_OpenAIAndOllama(t *testing.T) {
	t.Parallel()
	openai := []byte(`{"data":[{"id":"Qwen3.6-35B","owned_by":"vllm","context_length":131072},{"id":"gpt-4o-mini","owned_by":"openai"},{"id":"Qwen3.6-35B"}]}`)
	got := parseModelsPayload(openai)
	if len(got) != 2 || got[0].ID != "gpt-4o-mini" || got[1].ID != "Qwen3.6-35B" || got[1].ContextLength != 131072 {
		t.Fatalf("unexpected OpenAI models: %+v", got)
	}

	ollama := []byte(`{"models":[{"name":"llama3.2:latest","model":"llama3.2:latest"},{"name":"qwen2.5-coder:7b"}]}`)
	gotOllama := parseModelsPayload(ollama)
	if len(gotOllama) != 2 || gotOllama[0].ID != "llama3.2:latest" || gotOllama[1].ID != "qwen2.5-coder:7b" {
		t.Fatalf("unexpected Ollama models: %+v", gotOllama)
	}
}

func TestAIProviderHTTPAPI_SaveLoadModelsAndTest(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/models":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"message":"Not Found"}}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"Qwen3.6-35B","owned_by":"vllm"},{"id":"deepseek-r1","owned_by":"vllm"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	secret := []byte("test-jwt-secret")
	gw := &gateway{secret: secret}
	ownerTok := signTestToken(t, secret, "owner")
	viewerTok := signTestToken(t, secret, "viewer")

	// 1. POST /api/ai/models with /api/v1 auto-falls back to /v1 and suggests baseUrl.
	modelsReq := httptest.NewRequest(http.MethodPost, "/api/ai/models", bytes.NewBufferString(`{"baseUrl":"`+srv.URL+`/api/v1","mode":"openai-compatible"}`))
	modelsReq.Header.Set("Authorization", "Bearer "+ownerTok)
	rec := httptest.NewRecorder()
	gw.aiProviderModels(rec, modelsReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("models status = %d body = %s", rec.Code, rec.Body.String())
	}
	var mResp aiModelsResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &mResp); err != nil {
		t.Fatalf("unmarshal models resp: %v", err)
	}
	if !mResp.OK || len(mResp.Models) != 2 || mResp.SuggestedBaseURL != srv.URL+"/v1" {
		t.Fatalf("unexpected models response: %+v", mResp)
	}

	// 2. Viewer is forbidden from saving AI provider settings.
	savePayload := `{"mode":"openai-compatible","endpointUrl":"` + srv.URL + `/v1","model":"Qwen3.6-35B","timeoutSec":60,"allowTextToWorkflow":true}`
	viewerSave := httptest.NewRequest(http.MethodPost, "/api/ai/provider", bytes.NewBufferString(savePayload))
	viewerSave.Header.Set("Authorization", "Bearer "+viewerTok)
	rec = httptest.NewRecorder()
	gw.aiProviderConfig(rec, viewerSave)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer save status = %d, want 403", rec.Code)
	}

	// 3. Owner saves and reloads AI provider settings.
	ownerSave := httptest.NewRequest(http.MethodPost, "/api/ai/provider", bytes.NewBufferString(savePayload))
	ownerSave.Header.Set("Authorization", "Bearer "+ownerTok)
	rec = httptest.NewRecorder()
	gw.aiProviderConfig(rec, ownerSave)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner save status = %d body = %s", rec.Code, rec.Body.String())
	}
	var saved aiProviderConfigDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatalf("unmarshal saved: %v", err)
	}
	if saved.Status != "HEALTHY" || saved.Model != "Qwen3.6-35B" || saved.EndpointURL != srv.URL+"/v1" {
		t.Fatalf("unexpected saved config: %+v", saved)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/ai/provider", nil)
	getReq.Header.Set("Authorization", "Bearer "+viewerTok)
	rec = httptest.NewRecorder()
	gw.aiProviderConfig(rec, getReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("get config status = %d body = %s", rec.Code, rec.Body.String())
	}
	var loaded aiProviderConfigDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &loaded); err != nil {
		t.Fatalf("unmarshal loaded: %v", err)
	}
	if loaded.EndpointURL != srv.URL+"/v1" || loaded.Model != "Qwen3.6-35B" {
		t.Fatalf("loaded mismatch: %+v", loaded)
	}

	// 4. Test connection reports modelFound=true for existing model and false for missing model.
	testReq := httptest.NewRequest(http.MethodPost, "/api/ai/provider/test", bytes.NewBufferString(`{"mode":"openai-compatible","endpointUrl":"`+srv.URL+`/v1","model":"missing-model"}`))
	testReq.Header.Set("Authorization", "Bearer "+ownerTok)
	rec = httptest.NewRecorder()
	gw.aiProviderTest(rec, testReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("test status = %d body = %s", rec.Code, rec.Body.String())
	}
	var testResp aiModelsResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &testResp); err != nil {
		t.Fatalf("unmarshal test resp: %v", err)
	}
	if !testResp.OK || testResp.ModelFound == nil || *testResp.ModelFound {
		t.Fatalf("expected ok=true modelFound=false, got %+v", testResp)
	}
}
