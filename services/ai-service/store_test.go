package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

func TestResolveLLMConfig(t *testing.T) {
	t.Setenv("AI_PROVIDER", "")
	t.Setenv("LLM_BASE_URL", "https://env.example.com/v1")
	t.Setenv("LLM_API_KEY", "sk-env")
	t.Setenv("LLM_MODEL", "env-model")
	t.Setenv("OLLAMA_URL", "")
	t.Setenv("OLLAMA_MODEL", "")

	tests := []struct {
		name        string
		params      map[string]any
		boundAPIKey string
		want        llmConfig
	}{
		{
			name:        "node params and bound vault key override env",
			params:      map[string]any{"baseUrl": "https://node.example.com/v1", "model": "gpt-4.1-mini"},
			boundAPIKey: "sk-vault",
			want:        llmConfig{BaseURL: "https://node.example.com/v1", APIKey: "sk-vault", Model: "gpt-4.1-mini"},
		},
		{
			name:   "inline apiKey in params is ignored without vault binding",
			params: map[string]any{"baseUrl": "https://node.example.com/v1", "apiKey": "sk-inline", "llmApiKey": "sk-inline-2"},
			want:   llmConfig{BaseURL: "https://node.example.com/v1", APIKey: "sk-env", Model: "env-model"},
		},
		{
			name:   "falls back to env when node params omitted",
			params: map[string]any{},
			want:   llmConfig{BaseURL: "https://env.example.com/v1", APIKey: "sk-env", Model: "env-model"},
		},
		{
			name:        "openrouter api root is normalized to /api/v1",
			params:      map[string]any{"baseUrl": "https://openrouter.ai/api/", "model": "demo-model"},
			boundAPIKey: "sk-vault",
			want:        llmConfig{BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-vault", Model: "demo-model"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveLLMConfig(tt.params, tt.boundAPIKey)
			if got != tt.want {
				t.Fatalf("resolveLLMConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResolveLLMConfig_TemplateFallbackStillUsesNodeEndpoint(t *testing.T) {
	t.Setenv("AI_PROVIDER", "template_fallback")
	t.Setenv("LLM_BASE_URL", "")
	t.Setenv("LLM_API_KEY", "")
	t.Setenv("OLLAMA_URL", "http://ollama:11434")
	got := resolveLLMConfig(map[string]any{
		"baseUrl": "https://openrouter.ai/api",
		"model":   "demo-model",
	}, "sk-vault")
	want := llmConfig{BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-vault", Model: "demo-model"}
	if got != want {
		t.Fatalf("resolveLLMConfig() = %+v, want %+v", got, want)
	}
}

func TestAskModel(t *testing.T) {
	var gotAuth, gotPath, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		var reqBody struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		gotModel = reqBody.Model
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"grounded explanation"}}]}`))
	}))
	defer srv.Close()

	tests := []struct {
		name      string
		ollamaEnv string
		allowPriv string
		cfg       llmConfig
		wantPath  string
		wantAuth  string
		wantModel string
		wantMode  secflowv1.AIProviderMode
		wantErr   bool
	}{
		{
			name:      "base url appends chat completions",
			allowPriv: "1",
			cfg:       llmConfig{BaseURL: srv.URL + "/v1", APIKey: "sk-node", Model: "custom-llm"},
			wantPath:  "/v1/chat/completions",
			wantAuth:  "Bearer sk-node",
			wantModel: "custom-llm",
			wantMode:  secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
		},
		{
			name:      "full chat completions url not duplicated",
			allowPriv: "1",
			cfg:       llmConfig{BaseURL: srv.URL + "/v1/chat/completions", APIKey: "sk-node2", Model: "m2"},
			wantPath:  "/v1/chat/completions",
			wantAuth:  "Bearer sk-node2",
			wantModel: "m2",
			wantMode:  secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
		},
		{
			name:      "trusted OLLAMA_URL without /v1 calls OpenAI-compatible /v1/chat/completions even with private disabled",
			ollamaEnv: srv.URL,
			cfg:       llmConfig{BaseURL: srv.URL, Model: "llama3.2"},
			wantPath:  "/v1/chat/completions",
			wantAuth:  "",
			wantModel: "llama3.2",
			wantMode:  secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA,
		},
		{
			name:      "trusted OLLAMA_URL ending with /v1 does not duplicate /v1",
			ollamaEnv: srv.URL + "/v1",
			cfg:       llmConfig{BaseURL: srv.URL + "/v1", Model: "qwen2.5-coder"},
			wantPath:  "/v1/chat/completions",
			wantAuth:  "",
			wantModel: "qwen2.5-coder",
			wantMode:  secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA,
		},
		{
			name:    "blocks cloud metadata endpoint",
			cfg:     llmConfig{BaseURL: "http://169.254.169.254/latest/meta-data", APIKey: "sk-x"},
			wantErr: true,
		},
		{
			name:    "blocks loopback ssrf when private disabled",
			cfg:     llmConfig{BaseURL: srv.URL + "/v1", APIKey: "sk-x"},
			wantErr: true,
		},
		{
			name:      "blocks arbitrary private url even when OLLAMA_URL is configured elsewhere",
			ollamaEnv: "http://ollama:11434",
			cfg:       llmConfig{BaseURL: srv.URL + "/v1", APIKey: "sk-x"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MCP_ALLOW_PRIVATE", tt.allowPriv)
			t.Setenv("OLLAMA_URL", tt.ollamaEnv)
			gotAuth, gotPath, gotModel = "", "", ""
			reply, model, mode, err := askModel(t.Context(), tt.cfg, "test prompt")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("askModel() error = %v", err)
			}
			if reply != "grounded explanation" {
				t.Fatalf("reply = %q", reply)
			}
			if gotPath != tt.wantPath || gotAuth != tt.wantAuth || gotModel != tt.wantModel {
				t.Fatalf("got path=%q auth=%q model=%q, want path=%q auth=%q model=%q", gotPath, gotAuth, gotModel, tt.wantPath, tt.wantAuth, tt.wantModel)
			}
			if model != tt.wantModel || mode != tt.wantMode {
				t.Fatalf("returned model=%q mode=%v, want model=%q mode=%v", model, mode, tt.wantModel, tt.wantMode)
			}
		})
	}
}

func TestGetProviderStatus(t *testing.T) {
	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" || r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer healthySrv.Close()

	unhealthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthySrv.Close()

	svc := &aiSvc{}

	t.Run("template fallback mode", func(t *testing.T) {
		t.Setenv("AI_PROVIDER", "template_fallback")
		t.Setenv("LLM_BASE_URL", "")
		t.Setenv("OLLAMA_URL", "")
		t.Setenv("AI_DEFAULT_PRIVACY_MODE", "")

		resp, err := svc.GetProviderStatus(t.Context(), &secflowv1.GetProviderStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetProviderMode() != secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK || !resp.GetClosedLoop() || !resp.GetHealthy() || resp.GetModelId() != "template-fallback" {
			t.Fatalf("unexpected fallback status: %+v", resp)
		}
	})

	t.Run("AI_PROVIDER=template selects TEMPLATE_FALLBACK healthy without dialing Ollama", func(t *testing.T) {
		dialed := false
		neverDialSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			dialed = true
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer neverDialSrv.Close()

		t.Setenv("AI_PROVIDER", "template")
		t.Setenv("LLM_BASE_URL", "")
		t.Setenv("OLLAMA_URL", "http://ollama:11434")
		t.Setenv("AI_DEFAULT_PRIVACY_MODE", "")

		if cfg := resolveLLMConfig(nil, ""); cfg.BaseURL != "" {
			t.Fatalf("resolveLLMConfig with AI_PROVIDER=template fell through to BaseURL=%q", cfg.BaseURL)
		}

		resp, err := svc.GetProviderStatus(t.Context(), &secflowv1.GetProviderStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetProviderMode() != secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK || !resp.GetClosedLoop() || !resp.GetHealthy() || resp.GetModelId() != "template-fallback" || resp.GetEndpointHost() != "local" {
			t.Fatalf("unexpected AI_PROVIDER=template status: %+v", resp)
		}

		t.Setenv("OLLAMA_URL", neverDialSrv.URL)
		resp2, err := svc.GetProviderStatus(t.Context(), &secflowv1.GetProviderStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if dialed {
			t.Fatal("AI_PROVIDER=template unexpectedly dialed OLLAMA_URL")
		}
		if resp2.GetProviderMode() != secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK || !resp2.GetHealthy() {
			t.Fatalf("unexpected AI_PROVIDER=template status with local ollama url: %+v", resp2)
		}
	})

	t.Run("ollama closed-loop healthy", func(t *testing.T) {
		t.Setenv("AI_PROVIDER", "ollama")
		t.Setenv("OLLAMA_URL", healthySrv.URL)
		t.Setenv("OLLAMA_MODEL", "llama3.2:3b")
		t.Setenv("LLM_BASE_URL", "")
		t.Setenv("LLM_API_KEY", "")
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		t.Setenv("AI_DEFAULT_PRIVACY_MODE", "")

		resp, err := svc.GetProviderStatus(t.Context(), &secflowv1.GetProviderStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetProviderMode() != secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA || !resp.GetClosedLoop() || !resp.GetHealthy() {
			t.Fatalf("unexpected ollama status: %+v", resp)
		}
		if resp.GetModelId() != "llama3.2:3b" || resp.GetEndpointHost() != "127.0.0.1" {
			t.Fatalf("unexpected model/host: model=%q host=%q", resp.GetModelId(), resp.GetEndpointHost())
		}
		if resp.GetDefaultPrivacyMode() != secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET {
			t.Fatalf("expected REDACTED_SNIPPET default for ollama, got %v", resp.GetDefaultPrivacyMode())
		}
	})

	t.Run("cloud mode reports closedLoop false and sanitizes credentials from host", func(t *testing.T) {
		t.Setenv("AI_PROVIDER", "cloud")
		t.Setenv("LLM_BASE_URL", healthySrv.URL+"/v1")
		t.Setenv("LLM_API_KEY", "sk-secret-key")
		t.Setenv("LLM_MODEL", "gpt-4o-mini")
		t.Setenv("OLLAMA_URL", "")
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		t.Setenv("AI_DEFAULT_PRIVACY_MODE", "")

		resp, err := svc.GetProviderStatus(t.Context(), &secflowv1.GetProviderStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetProviderMode() != secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD || resp.GetClosedLoop() || !resp.GetHealthy() {
			t.Fatalf("unexpected cloud status: %+v", resp)
		}
		if resp.GetEndpointHost() != "127.0.0.1" || resp.GetModelId() != "gpt-4o-mini" {
			t.Fatalf("unexpected cloud host/model: %+v", resp)
		}
		if resp.GetDefaultPrivacyMode() != secflowv1.PrivacyMode_PRIVACY_MODE_METADATA_ONLY {
			t.Fatalf("expected METADATA_ONLY default for cloud, got %v", resp.GetDefaultPrivacyMode())
		}
	})

	t.Run("unhealthy provider detected", func(t *testing.T) {
		t.Setenv("AI_PROVIDER", "ollama")
		t.Setenv("OLLAMA_URL", unhealthySrv.URL)
		t.Setenv("OLLAMA_MODEL", "llama3.2")

		resp, err := svc.GetProviderStatus(t.Context(), &secflowv1.GetProviderStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetHealthy() {
			t.Fatalf("expected unhealthy status for 503 endpoint: %+v", resp)
		}
	})
}

func TestPostChatCompletionRetriesClosedConnection(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("response does not support hijack")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"releaseDecision\":\"PASS\"}"}}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	}))
	defer srv.Close()

	resp, err := postChatCompletion(t.Context(), llmConfig{BaseURL: srv.URL + "/v1", APIKey: "sk-test", Model: "retry-model"}, []chatMessage{{Role: "user", Content: "hi"}}, true)
	if err != nil {
		t.Fatalf("postChatCompletion() error = %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected a retry after the closed connection, calls=%d", calls)
	}
	if resp.Model != "retry-model" || resp.TokensOut != 4 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
