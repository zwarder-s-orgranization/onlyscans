package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/secretclient"
	"github.com/secflow/secflow/services/internal/urlguard"
)

type aiProviderConfigDTO struct {
	Mode                string `json:"mode"`
	EndpointURL         string `json:"endpointUrl"`
	Model               string `json:"model"`
	SecretRef           string `json:"secretRef"`
	TimeoutSec          int    `json:"timeoutSec"`
	StrictGrounding     bool   `json:"strictGrounding"`
	AllowTextToWorkflow bool   `json:"allowTextToWorkflow"`
	Status              string `json:"status"`
	LastLatencyMs       int64  `json:"lastLatencyMs"`
	LastCheckedAt       string `json:"lastCheckedAt"`
	ErrorMessage        string `json:"errorMessage,omitempty"`
}

type aiModelOptionDTO struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	OwnedBy       string `json:"ownedBy,omitempty"`
	ContextLength int    `json:"contextLength,omitempty"`
}

type aiModelsResponseDTO struct {
	OK                bool               `json:"ok"`
	StatusCode        int                `json:"statusCode"`
	LatencyMs         int64              `json:"latencyMs"`
	NormalizedBaseURL string             `json:"normalizedBaseUrl"`
	SuggestedBaseURL  string             `json:"suggestedBaseUrl,omitempty"`
	Models            []aiModelOptionDTO `json:"models"`
	ModelFound        *bool              `json:"modelFound,omitempty"`
	Error             string             `json:"error,omitempty"`
}

var aiProbeHTTPClient = newAIProbeHTTPClient()

func newAIProbeHTTPClient() *http.Client {
	client := urlguard.NewSafeClient(12 * time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return client
	}
	cloned := transport.Clone()
	cloned.ForceAttemptHTTP2 = false
	cloned.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	cloned.TLSHandshakeTimeout = 8 * time.Second
	cloned.ResponseHeaderTimeout = 10 * time.Second
	cloned.DisableKeepAlives = true
	client.Transport = cloned
	client.Timeout = 12 * time.Second
	return client
}

func normalizeAIProviderMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "openai-compatible", "cloud":
		return "openai-compatible"
	case "local-ollama", "ollama":
		return "local-ollama"
	case "deterministic-only", "template_fallback", "template", "fallback":
		return "deterministic-only"
	default:
		return ""
	}
}

func normalizeProviderBaseURL(raw, mode string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return raw
	}
	host := strings.ToLower(u.Hostname())
	trimmedPath := strings.TrimRight(u.Path, "/")
	if host == "openrouter.ai" || host == "www.openrouter.ai" {
		if trimmedPath == "" || trimmedPath == "/api" {
			u.Path = "/api/v1"
			u.RawPath = ""
			return strings.TrimRight(u.String(), "/")
		}
		return strings.TrimRight(raw, "/")
	}
	if mode != "local-ollama" && trimmedPath == "" {
		u.Path = "/v1"
		u.RawPath = ""
		return strings.TrimRight(u.String(), "/")
	}
	return strings.TrimRight(raw, "/")
}

func providerModelsURL(baseURL string, isOllama bool) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return ""
	}
	if strings.HasSuffix(base, "/models") {
		return base
	}
	if strings.HasSuffix(base, "/chat/completions") {
		return strings.TrimSuffix(base, "/chat/completions") + "/models"
	}
	if u, err := url.Parse(base); err == nil {
		p := strings.TrimRight(u.Path, "/")
		if p == "" {
			return base + "/v1/models"
		}
		if isOllama && strings.HasSuffix(p, "/api") {
			return u.Scheme + "://" + u.Host + "/v1/models"
		}
	}
	return base + "/models"
}

func isTrustedOllamaProbeURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "ollama" || strings.HasPrefix(host, "ollama.") {
		return true
	}
	if envOllama := strings.TrimSpace(os.Getenv("OLLAMA_URL")); envOllama != "" {
		if u2, err2 := url.Parse(envOllama); err2 == nil && strings.EqualFold(u.Host, u2.Host) {
			return true
		}
	}
	return false
}

func validateProviderProbeURL(ctx context.Context, rawURL, mode string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("укажите корректный URL эндпоинта (http:// или https://)")
	}
	host := strings.ToLower(u.Hostname())
	if host == "169.254.169.254" || host == "metadata.google.internal" {
		return errors.New("адрес метаданных заблокирован политикой безопасности")
	}
	if urlguard.Denied(rawURL) {
		return errors.New("адрес заблокирован политикой denylist")
	}
	if mode == "local-ollama" && isTrustedOllamaProbeURL(rawURL) {
		return nil
	}
	if err := urlguard.CheckCtx(ctx, rawURL); err != nil {
		return fmt.Errorf("URL заблокирован SSRF-защитой: %w", err)
	}
	return nil
}

func probeHTTPClientFor(baseURL, mode string) *http.Client {
	if mode == "local-ollama" && isTrustedOllamaProbeURL(baseURL) {
		return &http.Client{Timeout: 10 * time.Second}
	}
	return aiProbeHTTPClient
}

func (g *gateway) ensureAIProviderSettingsTable(ctx context.Context) {
	if g.pool == nil {
		return
	}
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := g.pool.Exec(dbCtx, `
		CREATE TABLE IF NOT EXISTS ai_provider_settings (
			id text PRIMARY KEY DEFAULT 'default',
			mode text NOT NULL DEFAULT 'template_fallback',
			base_url text NOT NULL DEFAULT '',
			model text NOT NULL DEFAULT '',
			secret_ref text NOT NULL DEFAULT '',
			timeout_sec int NOT NULL DEFAULT 60,
			allow_text_to_workflow boolean NOT NULL DEFAULT true,
			updated_by text NOT NULL DEFAULT '',
			updated_at timestamptz NOT NULL DEFAULT now()
		)`)
	if err != nil {
		slog.WarnContext(ctx, "ensure ai_provider_settings table", "err", err)
	}
}

func (g *gateway) loadAIProviderConfig(ctx context.Context) aiProviderConfigDTO {
	if g.pool != nil {
		g.ensureAIProviderSettingsTable(ctx)
		dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var mode, baseURL, model, secretRef string
		var timeoutSec int
		var allowT2W bool
		var updatedAt time.Time
		err := g.pool.QueryRow(dbCtx, `
			SELECT mode, base_url, model, secret_ref, timeout_sec, allow_text_to_workflow, updated_at
			FROM ai_provider_settings
			WHERE id = 'default'`).Scan(
			&mode, &baseURL, &model, &secretRef, &timeoutSec, &allowT2W, &updatedAt,
		)
		if err == nil {
			normMode := normalizeAIProviderMode(mode)
			if normMode == "" {
				normMode = "deterministic-only"
			}
			if timeoutSec < 5 || timeoutSec > 180 {
				timeoutSec = 60
			}
			statusStr := "DISABLED"
			if normMode != "deterministic-only" {
				statusStr = "DEGRADED"
				if baseURL != "" {
					statusStr = "HEALTHY"
				}
			}
			return aiProviderConfigDTO{
				Mode:                normMode,
				EndpointURL:         baseURL,
				Model:               model,
				SecretRef:           secretRef,
				TimeoutSec:          timeoutSec,
				StrictGrounding:     true,
				AllowTextToWorkflow: allowT2W,
				Status:              statusStr,
				LastCheckedAt:       updatedAt.UTC().Format(time.RFC3339),
			}
		}
	}

	g.mu.Lock()
	memCfg := g.aiCfg
	g.mu.Unlock()
	if memCfg != nil {
		return *memCfg
	}

	cfg := aiProviderConfigDTO{
		Mode:                "deterministic-only",
		EndpointURL:         "",
		Model:               "",
		SecretRef:           "",
		TimeoutSec:          60,
		StrictGrounding:     true,
		AllowTextToWorkflow: true,
		Status:              "DISABLED",
		LastCheckedAt:       "—",
	}
	if g.ai != nil {
		stCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		if st, err := g.ai.GetProviderStatus(stCtx, &secflowv1.GetProviderStatusRequest{}); err == nil && st != nil {
			switch st.GetProviderMode() {
			case secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD:
				cfg.Mode = "openai-compatible"
			case secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA:
				cfg.Mode = "local-ollama"
			default:
				cfg.Mode = "deterministic-only"
			}
			if host := strings.TrimSpace(st.GetEndpointHost()); host != "" && host != "local" && host != "unknown" {
				if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
					cfg.EndpointURL = host
				} else if cfg.Mode == "local-ollama" {
					cfg.EndpointURL = "http://" + host + ":11434"
				} else {
					cfg.EndpointURL = "https://" + host
				}
			}
			if m := strings.TrimSpace(st.GetModelId()); m != "" && m != "template-fallback" {
				cfg.Model = m
			}
			if cfg.Mode == "deterministic-only" {
				cfg.Status = "DISABLED"
			} else if st.GetHealthy() {
				cfg.Status = "HEALTHY"
			} else {
				cfg.Status = "DEGRADED"
			}
			cfg.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	return cfg
}

func (g *gateway) saveAIProviderConfig(ctx context.Context, cfg aiProviderConfigDTO, updatedBy string) error {
	now := time.Now().UTC()
	cfg.StrictGrounding = true
	cfg.LastCheckedAt = now.Format(time.RFC3339)
	if g.pool != nil {
		g.ensureAIProviderSettingsTable(ctx)
		dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err := g.pool.Exec(dbCtx, `
			INSERT INTO ai_provider_settings (
				id, mode, base_url, model, secret_ref, timeout_sec,
				allow_text_to_workflow, updated_by, updated_at
			)
			VALUES ('default', $1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET
				mode = EXCLUDED.mode,
				base_url = EXCLUDED.base_url,
				model = EXCLUDED.model,
				secret_ref = EXCLUDED.secret_ref,
				timeout_sec = EXCLUDED.timeout_sec,
				allow_text_to_workflow = EXCLUDED.allow_text_to_workflow,
				updated_by = EXCLUDED.updated_by,
				updated_at = EXCLUDED.updated_at`,
			cfg.Mode, cfg.EndpointURL, cfg.Model, cfg.SecretRef, cfg.TimeoutSec,
			cfg.AllowTextToWorkflow, updatedBy, now)
		if err != nil {
			return fmt.Errorf("persist ai provider settings: %w", err)
		}
	}
	g.mu.Lock()
	cp := cfg
	g.aiCfg = &cp
	g.mu.Unlock()
	return nil
}

func (g *gateway) resolveAISecret(ctx context.Context, secretRef string) (string, error) {
	ref := strings.TrimSpace(secretRef)
	if ref == "" || g.secs == nil {
		return "", nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := g.secs.ResolveScopedSecret(reqCtx, &secflowv1.ResolveScopedSecretRequest{
		SecretRef:    ref,
		ServiceToken: g.serviceToken,
		Scope: &secflowv1.ResolveScopedSecretRequest_McpDiscovery{
			McpDiscovery: &secflowv1.MCPDiscoverySecretScope{
				McpConnectionId: secretclient.AIProviderScopeID,
			},
		},
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.GetPlaintextValue()), nil
}

func parseModelsPayload(raw []byte) []aiModelOptionDTO {
	seen := map[string]bool{}
	var out []aiModelOptionDTO
	add := func(id, name, ownedBy string, ctxLen int) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		opt := aiModelOptionDTO{
			ID:            id,
			OwnedBy:       strings.TrimSpace(ownedBy),
			ContextLength: ctxLen,
		}
		if n := strings.TrimSpace(name); n != "" && n != id {
			opt.Name = n
		}
		out = append(out, opt)
	}

	var openAI struct {
		Data []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			OwnedBy       string `json:"owned_by"`
			ContextLength int    `json:"context_length"`
		} `json:"data"`
		Models []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if json.Unmarshal(raw, &openAI) == nil {
		for _, m := range openAI.Data {
			add(m.ID, m.Name, m.OwnedBy, m.ContextLength)
		}
		for _, m := range openAI.Models {
			id := strings.TrimSpace(m.ID)
			if id == "" {
				id = strings.TrimSpace(m.Model)
			}
			if id == "" {
				id = strings.TrimSpace(m.Name)
			}
			add(id, m.Name, "ollama", 0)
		}
	}
	if len(out) == 0 {
		var bareObjs []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			OwnedBy string `json:"owned_by"`
		}
		if json.Unmarshal(raw, &bareObjs) == nil {
			for _, m := range bareObjs {
				id := strings.TrimSpace(m.ID)
				if id == "" {
					id = strings.TrimSpace(m.Name)
				}
				add(id, m.Name, m.OwnedBy, 0)
			}
		}
	}
	if len(out) == 0 {
		var bareStrings []string
		if json.Unmarshal(raw, &bareStrings) == nil {
			for _, s := range bareStrings {
				add(s, "", "", 0)
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].ID) < strings.ToLower(out[j].ID)
	})
	if len(out) > 500 {
		out = out[:500]
	}
	return out
}

func extractProviderHTTPError(statusCode int, raw []byte) string {
	var doc struct {
		Error *struct {
			Message  string `json:"message"`
			Metadata *struct {
				Raw          string `json:"raw"`
				ProviderName string `json:"provider_name"`
			} `json:"metadata"`
		} `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	msg := ""
	if json.Unmarshal(raw, &doc) == nil {
		if doc.Error != nil {
			msg = strings.TrimSpace(doc.Error.Message)
			if doc.Error.Metadata != nil {
				if rawMeta := strings.TrimSpace(doc.Error.Metadata.Raw); rawMeta != "" {
					msg = rawMeta
				}
				if prov := strings.TrimSpace(doc.Error.Metadata.ProviderName); prov != "" && !strings.Contains(strings.ToLower(msg), strings.ToLower(prov)) {
					msg = fmt.Sprintf("[%s] %s", prov, msg)
				}
			}
		}
		if msg == "" {
			msg = first(strings.TrimSpace(doc.Message), strings.TrimSpace(doc.Detail))
		}
	}
	if msg == "" {
		msg = strings.Join(strings.Fields(string(raw)), " ")
	}
	if msg == "" {
		msg = http.StatusText(statusCode)
	}
	if len(msg) > 320 {
		msg = msg[:320] + "…"
	}
	return fmt.Sprintf("HTTP %d: %s", statusCode, msg)
}

func fetchProviderModels(ctx context.Context, rawBaseURL, apiKey, mode string) aiModelsResponseDTO {
	normBase := normalizeProviderBaseURL(rawBaseURL, mode)
	res := aiModelsResponseDTO{
		NormalizedBaseURL: normBase,
		Models:            []aiModelOptionDTO{},
	}
	if err := validateProviderProbeURL(ctx, normBase, mode); err != nil {
		res.Error = err.Error()
		return res
	}
	isOllama := mode == "local-ollama"
	client := probeHTTPClientFor(normBase, mode)

	doGet := func(target string) (int, []byte, int64, error) {
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
		if err != nil {
			return 0, nil, 0, err
		}
		req.Header.Set("Accept", "application/json")
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
		if strings.Contains(strings.ToLower(target), "openrouter.ai") {
			req.Header.Set("HTTP-Referer", "https://secflow.local")
			req.Header.Set("X-Title", "SecFlow")
		}
		started := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(started).Milliseconds()
		if err != nil {
			return 0, nil, elapsed, err
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if readErr != nil {
			return resp.StatusCode, nil, elapsed, readErr
		}
		return resp.StatusCode, body, elapsed, nil
	}

	target := providerModelsURL(normBase, isOllama)
	code, body, elapsed, err := doGet(target)
	res.StatusCode = code
	res.LatencyMs = elapsed
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if code >= 200 && code < 300 {
		models := parseModelsPayload(body)
		if len(models) > 0 || !isOllama {
			res.OK = true
			res.Models = models
			return res
		}
	}

	// Ollama fallback: /api/tags
	if isOllama {
		if u, uErr := url.Parse(normBase); uErr == nil && u.Scheme != "" && u.Host != "" {
			tagsURL := u.Scheme + "://" + u.Host + "/api/tags"
			if tCode, tBody, tElapsed, tErr := doGet(tagsURL); tErr == nil && tCode >= 200 && tCode < 300 {
				res.OK = true
				res.StatusCode = tCode
				res.LatencyMs = tElapsed
				res.Models = parseModelsPayload(tBody)
				return res
			}
		}
	}

	// Smart hint when user enters /api/v1 on a provider that serves /v1 (e.g. llm.skbkit.ru).
	if code == http.StatusNotFound && !isOllama {
		if u, uErr := url.Parse(normBase); uErr == nil && strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/api/v1") {
			altBase := u.Scheme + "://" + u.Host + "/v1"
			if aCode, aBody, aElapsed, aErr := doGet(altBase + "/models"); aErr == nil {
				if aCode >= 200 && aCode < 300 {
					res.OK = true
					res.StatusCode = aCode
					res.LatencyMs = aElapsed
					res.SuggestedBaseURL = altBase
					res.NormalizedBaseURL = altBase
					res.Models = parseModelsPayload(aBody)
					return res
				}
				if aCode == http.StatusUnauthorized || aCode == http.StatusForbidden {
					res.SuggestedBaseURL = altBase
				}
			}
		}
	}

	res.Error = extractProviderHTTPError(code, body)
	return res
}

func (g *gateway) aiProviderConfig(w http.ResponseWriter, r *http.Request) {
	ctx := withTraceparent(r.Context(), r)
	switch r.Method {
	case http.MethodGet:
		if _, ok := g.requireRank(w, r, 1); !ok {
			return
		}
		cfg := g.loadAIProviderConfig(ctx)
		writeJSON(w, http.StatusOK, cfg)
		return

	case http.MethodPost, http.MethodPut:
		claims, ok := g.requireRank(w, r, 2)
		if !ok {
			return
		}
		var in struct {
			Mode                string `json:"mode"`
			EndpointURL         string `json:"endpointUrl"`
			Model               string `json:"model"`
			SecretRef           string `json:"secretRef"`
			TimeoutSec          int    `json:"timeoutSec"`
			AllowTextToWorkflow *bool  `json:"allowTextToWorkflow"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid json body")
			return
		}
		mode := normalizeAIProviderMode(in.Mode)
		if mode == "" {
			writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "некорректный режим работы AI-провайдера")
			return
		}
		timeoutSec := in.TimeoutSec
		if timeoutSec <= 0 {
			timeoutSec = 60
		}
		if timeoutSec < 5 {
			timeoutSec = 5
		}
		if timeoutSec > 180 {
			timeoutSec = 180
		}
		allowT2W := true
		if in.AllowTextToWorkflow != nil {
			allowT2W = *in.AllowTextToWorkflow
		}
		endpointURL := normalizeProviderBaseURL(in.EndpointURL, mode)
		model := strings.TrimSpace(in.Model)
		secretRef := strings.TrimSpace(in.SecretRef)

		cfg := aiProviderConfigDTO{
			Mode:                mode,
			EndpointURL:         endpointURL,
			Model:               model,
			SecretRef:           secretRef,
			TimeoutSec:          timeoutSec,
			StrictGrounding:     true,
			AllowTextToWorkflow: allowT2W && mode != "deterministic-only",
			Status:              "DISABLED",
		}

		if mode != "deterministic-only" {
			if err := validateProviderProbeURL(ctx, endpointURL, mode); err != nil {
				writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
				return
			}
			if len(model) < 2 {
				writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "укажите идентификатор модели LLM")
				return
			}
			apiKey, secErr := g.resolveAISecret(ctx, secretRef)
			if secErr != nil && secretRef != "" {
				writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "не удалось прочитать выбранный секрет (убедитесь, что тип секрета LLM_API_KEY или GENERIC)")
				return
			}
			probe := fetchProviderModels(ctx, endpointURL, apiKey, mode)
			if probe.SuggestedBaseURL != "" && probe.OK {
				cfg.EndpointURL = probe.SuggestedBaseURL
			}
			cfg.LastLatencyMs = probe.LatencyMs
			if probe.OK {
				cfg.Status = "HEALTHY"
			} else {
				cfg.Status = "DEGRADED"
				cfg.ErrorMessage = probe.Error
			}
		}

		if err := g.saveAIProviderConfig(ctx, cfg, claims.Subject); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "INTERNAL", "не удалось сохранить настройки AI-провайдера")
			return
		}
		cfg.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, cfg)
		return

	default:
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
	}
}

func (g *gateway) aiProviderTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	if _, ok := g.requireRank(w, r, 2); !ok {
		return
	}
	ctx := withTraceparent(r.Context(), r)
	var in struct {
		Mode        string `json:"mode"`
		EndpointURL string `json:"endpointUrl"`
		BaseURL     string `json:"baseUrl"`
		Model       string `json:"model"`
		SecretRef   string `json:"secretRef"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid json body")
		return
	}
	mode := normalizeAIProviderMode(in.Mode)
	if mode == "" {
		mode = "openai-compatible"
	}
	if mode == "deterministic-only" {
		writeJSON(w, http.StatusOK, aiModelsResponseDTO{
			OK:     true,
			Models: []aiModelOptionDTO{},
		})
		return
	}
	rawURL := first(strings.TrimSpace(in.EndpointURL), strings.TrimSpace(in.BaseURL))
	apiKey, err := g.resolveAISecret(ctx, in.SecretRef)
	if err != nil && strings.TrimSpace(in.SecretRef) != "" {
		writeJSON(w, http.StatusOK, aiModelsResponseDTO{
			OK:                false,
			NormalizedBaseURL: normalizeProviderBaseURL(rawURL, mode),
			Models:            []aiModelOptionDTO{},
			Error:             "не удалось прочитать секрет (выберите секрет с типом LLM_API_KEY или GENERIC)",
		})
		return
	}
	res := fetchProviderModels(ctx, rawURL, apiKey, mode)
	if res.OK && strings.TrimSpace(in.Model) != "" && len(res.Models) > 0 {
		found := false
		want := strings.TrimSpace(in.Model)
		for _, m := range res.Models {
			if strings.EqualFold(m.ID, want) {
				found = true
				break
			}
		}
		res.ModelFound = &found
	}
	writeJSON(w, http.StatusOK, res)
}

func (g *gateway) aiProviderModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	claims, ok := g.requireRank(w, r, 1)
	if !ok {
		return
	}
	ctx := withTraceparent(r.Context(), r)
	var in struct {
		Mode        string `json:"mode"`
		BaseURL     string `json:"baseUrl"`
		EndpointURL string `json:"endpointUrl"`
		SecretRef   string `json:"secretRef"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid json body")
		return
	}
	mode := normalizeAIProviderMode(in.Mode)
	if mode == "" {
		mode = "openai-compatible"
	}
	rawURL := first(strings.TrimSpace(in.BaseURL), strings.TrimSpace(in.EndpointURL))
	if rawURL == "" {
		writeJSON(w, http.StatusOK, aiModelsResponseDTO{
			OK:     false,
			Models: []aiModelOptionDTO{},
			Error:  "укажите base_url",
		})
		return
	}
	var apiKey string
	secretRef := strings.TrimSpace(in.SecretRef)
	if secretRef != "" && roleRank(claims.Role) >= 2 {
		key, err := g.resolveAISecret(ctx, secretRef)
		if err != nil {
			writeJSON(w, http.StatusOK, aiModelsResponseDTO{
				OK:                false,
				NormalizedBaseURL: normalizeProviderBaseURL(rawURL, mode),
				Models:            []aiModelOptionDTO{},
				Error:             "не удалось прочитать секрет (выберите секрет с типом LLM_API_KEY или GENERIC)",
			})
			return
		}
		apiKey = key
	}
	res := fetchProviderModels(ctx, rawURL, apiKey, mode)
	writeJSON(w, http.StatusOK, res)
}
