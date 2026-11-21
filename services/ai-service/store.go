package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/urlguard"
)

const defaultExplainCacheTTL = 15 * time.Minute

var llmHTTPClient = newLLMHTTPClient()

func newLLMHTTPClient() *http.Client {
	client := urlguard.NewSafeClient(65 * time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return client
	}
	cloned := transport.Clone()
	// HTTP/2 through the SSRF dialer is closed by some edges with EOF before any status.
	cloned.ForceAttemptHTTP2 = false
	cloned.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	cloned.TLSHandshakeTimeout = 20 * time.Second
	cloned.ResponseHeaderTimeout = 55 * time.Second
	cloned.DisableKeepAlives = true
	client.Transport = cloned
	client.Timeout = 65 * time.Second
	return client
}

type explainCache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration)
	Close() error
}

type redisExplainCache struct {
	client *redis.Client
}

func newRedisExplainCache(ctx context.Context) explainCache {
	addr := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if addr == "" {
		return nil
	}
	dbNum := 0
	if rawDB := strings.TrimSpace(os.Getenv("REDIS_DB")); rawDB != "" {
		if parsed, err := strconv.Atoi(rawDB); err == nil && parsed >= 0 {
			dbNum = parsed
		}
	}
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           dbNum,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		slog.WarnContext(ctx, "redis explain cache unavailable at startup; will retry lazily", "addr", addr, "err", err)
	}
	return &redisExplainCache{client: client}
}

func (c *redisExplainCache) Get(ctx context.Context, key string) ([]byte, bool) {
	if c == nil || c.client == nil {
		return nil, false
	}
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	raw, err := c.client.Get(opCtx, "secflow:ai:explain:"+key).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			slog.WarnContext(ctx, "redis explain cache get failed", "err", err)
		}
		return nil, false
	}
	return raw, len(raw) > 0
}

func (c *redisExplainCache) Set(ctx context.Context, key string, val []byte, ttl time.Duration) {
	if c == nil || c.client == nil || len(val) == 0 {
		return
	}
	if ttl <= 0 {
		ttl = defaultExplainCacheTTL
	}
	opCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := c.client.Set(opCtx, "secflow:ai:explain:"+key, val, ttl).Err(); err != nil {
		slog.WarnContext(ctx, "redis explain cache set failed", "err", err)
	}
}

func (c *redisExplainCache) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

func explainCacheTTL() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("AI_CACHE_TTL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return defaultExplainCacheTTL
}

func (a *aiSvc) openCache(ctx context.Context) {
	if a.cache != nil {
		return
	}
	a.cache = newRedisExplainCache(ctx)
}

func (a *aiSvc) closeCache() {
	if a.cache != nil {
		if err := a.cache.Close(); err != nil {
			slog.Warn("close ai explain cache", "err", err)
		}
	}
}

func (a *aiSvc) openDB(ctx context.Context) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		slog.Error("open ai audit db", "err", err)
		return
	}
	a.pool = pool
	rows, err := pool.Query(ctx, `
		SELECT
			id,
			COALESCE(run_id, ''),
			COALESCE(node_run_id, ''),
			operation,
			model_id,
			COALESCE(provider_mode, ''),
			COALESCE(privacy_mode, ''),
			prompt_hash,
			COALESCE(tokens_in, 0),
			COALESCE(tokens_out, 0),
			COALESCE(latency_ms, 0),
			quality,
			COALESCE(stripped_hallucinated_advisories, 0),
			COALESCE(cache_hit, false),
			created_at
		FROM ai_audit_logs
		ORDER BY created_at`)
	if err != nil {
		slog.Warn("load ai audit logs", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var idVal, runID, nodeRunID, op, model, providerMode, privacyMode, hash, quality string
		var tokensIn, tokensOut, stripped int32
		var latencyMs int64
		var cacheHit bool
		var createdAt time.Time
		if err := rows.Scan(
			&idVal, &runID, &nodeRunID, &op, &model, &providerMode, &privacyMode,
			&hash, &tokensIn, &tokensOut, &latencyMs, &quality, &stripped, &cacheHit, &createdAt,
		); err != nil {
			slog.Warn("scan ai audit log", "err", err)
			continue
		}
		a.logs = append(a.logs, &secflowv1.AIAuditLogEntry{
			Id:                             idVal,
			RunId:                          runID,
			NodeRunId:                      nodeRunID,
			Operation:                      secflowv1.AIOperation(secflowv1.AIOperation_value[op]),
			ModelId:                        model,
			ProviderMode:                   secflowv1.AIProviderMode(secflowv1.AIProviderMode_value[providerMode]),
			PrivacyMode:                    secflowv1.PrivacyMode(secflowv1.PrivacyMode_value[privacyMode]),
			PromptHash:                     hash,
			TokensIn:                       tokensIn,
			TokensOut:                      tokensOut,
			LatencyMs:                      latencyMs,
			Quality:                        secflowv1.AIQuality(secflowv1.AIQuality_value[quality]),
			StrippedHallucinatedAdvisories: stripped,
			CacheHit:                       cacheHit,
			CreatedAt:                      timestamppb.New(createdAt),
		})
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate ai audit logs", "err", err)
	}
}

func (a *aiSvc) closeDB() {
	if a.pool != nil {
		a.pool.Close()
	}
}

func (a *aiSvc) persist(ctx context.Context, entry *secflowv1.AIAuditLogEntry) {
	if a.pool == nil || entry == nil {
		return
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := a.pool.Exec(writeCtx, `
		INSERT INTO ai_audit_logs (
			id, run_id, node_run_id, operation, model_id,
			provider_mode, privacy_mode, prompt_hash,
			tokens_in, tokens_out, latency_ms, quality,
			stripped_hallucinated_advisories, cache_hit
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO NOTHING`,
		entry.GetId(),
		entry.GetRunId(),
		entry.GetNodeRunId(),
		entry.GetOperation().String(),
		entry.GetModelId(),
		entry.GetProviderMode().String(),
		entry.GetPrivacyMode().String(),
		entry.GetPromptHash(),
		entry.GetTokensIn(),
		entry.GetTokensOut(),
		entry.GetLatencyMs(),
		entry.GetQuality().String(),
		entry.GetStrippedHallucinatedAdvisories(),
		entry.GetCacheHit(),
	); err != nil {
		slog.Warn("persist ai audit log", "id", entry.GetId(), "err", err)
	}
}

type llmConfig struct {
	BaseURL string
	APIKey  string
	Model   string
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type llmResponse struct {
	Content   string
	Model     string
	Mode      secflowv1.AIProviderMode
	TokensIn  int32
	TokensOut int32
	LatencyMs int64
}

func resolveLLMConfig(params map[string]any, boundAPIKey string) llmConfig {
	nodeBase := normalizeLLMBaseURL(strings.TrimSpace(asString(params["baseUrl"])))
	nodeModel := strings.TrimSpace(asString(params["model"]))
	nodeKey := strings.TrimSpace(boundAPIKey)

	provider := strings.ToLower(strings.TrimSpace(os.Getenv("AI_PROVIDER")))
	switch provider {
	case "ollama":
		return llmConfig{
			BaseURL: normalizeLLMBaseURL(firstNonEmpty(nodeBase, strings.TrimSpace(os.Getenv("OLLAMA_URL")), strings.TrimSpace(os.Getenv("LLM_BASE_URL")))),
			APIKey:  nodeKey,
			Model:   firstNonEmpty(nodeModel, strings.TrimSpace(os.Getenv("OLLAMA_MODEL")), strings.TrimSpace(os.Getenv("LLM_MODEL"))),
		}
	case "template", "template_fallback", "fallback":
		if nodeBase == "" {
			return llmConfig{Model: nodeModel}
		}
	}

	return llmConfig{
		BaseURL: normalizeLLMBaseURL(firstNonEmpty(nodeBase, strings.TrimSpace(os.Getenv("LLM_BASE_URL")), strings.TrimSpace(os.Getenv("OLLAMA_URL")))),
		APIKey:  firstNonEmpty(nodeKey, strings.TrimSpace(os.Getenv("LLM_API_KEY"))),
		Model:   firstNonEmpty(nodeModel, strings.TrimSpace(os.Getenv("LLM_MODEL")), strings.TrimSpace(os.Getenv("OLLAMA_MODEL"))),
	}
}

// normalizeLLMBaseURL turns the OpenRouter root the inspector often stores
// (https://openrouter.ai/api) into the OpenAI-compatible prefix /api/v1.
func normalizeLLMBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	host := strings.ToLower(u.Hostname())
	if host != "openrouter.ai" && host != "www.openrouter.ai" {
		return raw
	}
	switch strings.TrimRight(u.Path, "/") {
	case "", "/api":
		u.Path = "/api/v1"
		u.RawPath = ""
		return u.String()
	default:
		return raw
	}
}

func effectiveModel(cfg llmConfig) string {
	if isOllamaEndpoint(cfg) {
		return firstNonEmpty(cfg.Model, "llama3.2")
	}
	return firstNonEmpty(cfg.Model, "gpt-4o-mini")
}

func isTrustedOllamaURL(rawURL string) bool {
	envOllama := strings.TrimSpace(os.Getenv("OLLAMA_URL"))
	if envOllama == "" {
		return false
	}
	u1, err1 := url.Parse(strings.TrimRight(strings.TrimSpace(rawURL), "/"))
	u2, err2 := url.Parse(strings.TrimRight(envOllama, "/"))
	if err1 != nil || err2 != nil {
		return false
	}
	if !strings.EqualFold(u1.Scheme, u2.Scheme) || !strings.EqualFold(u1.Host, u2.Host) {
		return false
	}
	p1 := strings.TrimRight(u1.Path, "/")
	p2 := strings.TrimRight(u2.Path, "/")
	return p1 == p2 || strings.HasPrefix(p1, p2+"/")
}

func validateLLMBaseURL(ctx context.Context, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("invalid llm base url")
	}
	host := strings.ToLower(u.Hostname())
	if host == "169.254.169.254" || host == "metadata.google.internal" {
		return errors.New("blocked metadata host")
	}
	if urlguard.Denied(raw) {
		return urlguard.ErrDenylistBlocked
	}
	if isTrustedOllamaURL(raw) {
		return nil
	}
	if err := urlguard.CheckCtx(ctx, raw); err != nil {
		return fmt.Errorf("llm endpoint blocked by ssrf guard: %w", err)
	}
	return nil
}

func isOllamaEndpoint(cfg llmConfig) bool {
	if cfg.APIKey != "" {
		return false
	}
	if isTrustedOllamaURL(cfg.BaseURL) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("AI_PROVIDER")), "ollama") && cfg.BaseURL != "" {
		return true
	}
	trimmed := strings.ToLower(strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"))
	return strings.Contains(trimmed, "ollama") || strings.Contains(trimmed, ":11434")
}

func hasEmptyURLPath(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	return strings.TrimRight(u.Path, "/") == ""
}

func chatCompletionsURL(baseURL string, ollama bool) string {
	endpoint := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(endpoint, "/chat/completions") {
		return endpoint
	}
	if ollama && !strings.HasSuffix(endpoint, "/v1") {
		return endpoint + "/v1/chat/completions"
	}
	if !ollama && hasEmptyURLPath(endpoint) {
		return endpoint + "/v1/chat/completions"
	}
	return endpoint + "/chat/completions"
}

func modelsProbeURL(baseURL string, ollama bool) string {
	endpoint := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	endpoint = strings.TrimSuffix(endpoint, "/chat/completions")
	if ollama && !strings.HasSuffix(endpoint, "/v1") {
		return endpoint + "/v1/models"
	}
	if !ollama && hasEmptyURLPath(endpoint) {
		return endpoint + "/v1/models"
	}
	return endpoint + "/models"
}

type llmAPIError struct {
	StatusCode int
	Code       string
	Message    string
	Provider   string
}

func (e *llmAPIError) Error() string {
	if e == nil {
		return ""
	}
	detail := strings.TrimSpace(e.Message)
	if detail == "" {
		detail = http.StatusText(e.StatusCode)
	}
	if e.Provider != "" && !strings.Contains(strings.ToLower(detail), strings.ToLower(e.Provider)) {
		detail = fmt.Sprintf("[%s] %s", e.Provider, detail)
	}
	return fmt.Sprintf("llm status %d: %s", e.StatusCode, detail)
}

func parseLLMAPIError(statusCode int, raw []byte) *llmAPIError {
	apiErr := &llmAPIError{
		StatusCode: statusCode,
		Code:       fmt.Sprintf("HTTP_%d", statusCode),
	}
	var envelope struct {
		Error *struct {
			Message  string `json:"message"`
			Type     string `json:"type"`
			Code     any    `json:"code"`
			Metadata *struct {
				Raw          string `json:"raw"`
				ProviderName string `json:"provider_name"`
			} `json:"metadata"`
		} `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal(raw, &envelope) == nil {
		if envelope.Error != nil {
			msg := strings.TrimSpace(envelope.Error.Message)
			if envelope.Error.Metadata != nil {
				apiErr.Provider = strings.TrimSpace(envelope.Error.Metadata.ProviderName)
				if rawDetail := extractNestedErrorMessage(envelope.Error.Metadata.Raw); rawDetail != "" {
					if msg == "" || strings.EqualFold(msg, "Provider returned error") {
						msg = rawDetail
					} else if !strings.Contains(msg, rawDetail) {
						msg = msg + " — " + rawDetail
					}
				}
			}
			apiErr.Message = msg
			switch c := envelope.Error.Code.(type) {
			case string:
				if trimmed := strings.TrimSpace(c); trimmed != "" {
					apiErr.Code = trimmed
				}
			case float64:
				if c > 0 {
					apiErr.Code = fmt.Sprintf("HTTP_%d", int(c))
				}
			}
			if apiErr.Code == fmt.Sprintf("HTTP_%d", statusCode) && strings.TrimSpace(envelope.Error.Type) != "" {
				apiErr.Code = strings.TrimSpace(envelope.Error.Type)
			}
		} else if msg := firstNonEmpty(strings.TrimSpace(envelope.Message), strings.TrimSpace(envelope.Detail)); msg != "" {
			apiErr.Message = msg
		}
	}
	if apiErr.Message == "" {
		apiErr.Message = strings.Join(strings.Fields(string(raw)), " ")
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(statusCode)
	}
	apiErr.Message = truncateRunes(redactSensitive(apiErr.Message), 400)
	return apiErr
}

func extractNestedErrorMessage(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var inner struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal([]byte(trimmed), &inner) == nil {
		if inner.Error != nil && strings.TrimSpace(inner.Error.Message) != "" {
			return strings.TrimSpace(inner.Error.Message)
		}
		if msg := firstNonEmpty(strings.TrimSpace(inner.Message), strings.TrimSpace(inner.Detail)); msg != "" {
			return msg
		}
	}
	return strings.Join(strings.Fields(trimmed), " ")
}

func classifyLLMError(err error) (status int, code, message string) {
	if err == nil {
		return 0, "", ""
	}
	var apiErr *llmAPIError
	if errors.As(err, &apiErr) {
		msg := strings.TrimSpace(apiErr.Message)
		if apiErr.Provider != "" && !strings.Contains(strings.ToLower(msg), strings.ToLower(apiErr.Provider)) {
			msg = fmt.Sprintf("[%s] %s", apiErr.Provider, msg)
		}
		return apiErr.StatusCode, firstNonEmpty(apiErr.Code, fmt.Sprintf("HTTP_%d", apiErr.StatusCode)), fmt.Sprintf("HTTP %d: %s", apiErr.StatusCode, msg)
	}
	rawMsg := truncateRunes(redactSensitive(strings.TrimSpace(err.Error())), 400)
	low := strings.ToLower(rawMsg)
	switch {
	case strings.Contains(low, "no model configured"):
		return 0, "NO_MODEL_CONFIGURED", "LLM endpoint не настроен (укажите baseUrl и model в параметрах узла ai.explain)"
	case strings.Contains(low, "ssrf guard") || strings.Contains(low, "allowlist_denied") || strings.Contains(low, "blocked metadata host"):
		return 0, "SSRF_BLOCKED", rawMsg
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(low, "deadline exceeded") || strings.Contains(low, "timeout"):
		return 0, "LLM_TIMEOUT", rawMsg
	case strings.Contains(low, "empty completion"):
		return 0, "LLM_EMPTY_COMPLETION", rawMsg
	default:
		return 0, "LLM_REQUEST_FAILED", rawMsg
	}
}

func shouldRetryWithoutJSONMode(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *llmAPIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity:
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "llm status 400") ||
		strings.Contains(msg, "llm status 404") ||
		strings.Contains(msg, "llm status 422") ||
		strings.Contains(msg, "empty completion")
}

func retryDelay(attempt int, retryAfterHeader string) time.Duration {
	if raw := strings.TrimSpace(retryAfterHeader); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			d := time.Duration(secs) * time.Second
			if d > 5*time.Second {
				d = 5 * time.Second
			}
			return d
		}
	}
	d := time.Duration(attempt) * 700 * time.Millisecond
	if d > 3*time.Second {
		d = 3 * time.Second
	}
	return d
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func askModel(ctx context.Context, cfg llmConfig, prompt string) (string, string, secflowv1.AIProviderMode, error) {
	resp, err := askModelMessages(ctx, cfg, []chatMessage{{Role: "user", Content: prompt}})
	if err != nil {
		return "", "", secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, err
	}
	return resp.Content, resp.Model, resp.Mode, nil
}

func askModelMessages(ctx context.Context, cfg llmConfig, messages []chatMessage) (llmResponse, error) {
	jsonMode := !isOllamaEndpoint(cfg)
	resp, err := postChatCompletion(ctx, cfg, messages, jsonMode)
	if err != nil && jsonMode && shouldRetryWithoutJSONMode(err) {
		slog.WarnContext(ctx, "retrying llm call without response_format json_object", "model", effectiveModel(cfg), "err", err)
		return postChatCompletion(ctx, cfg, messages, false)
	}
	return resp, err
}

func postChatCompletion(ctx context.Context, cfg llmConfig, messages []chatMessage, jsonMode bool) (llmResponse, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK}, errors.New("no model configured")
	}
	if err := validateLLMBaseURL(ctx, cfg.BaseURL); err != nil {
		return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK}, err
	}
	ollama := isOllamaEndpoint(cfg)
	model := effectiveModel(cfg)
	mode := secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD
	if ollama {
		mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA
	}

	safeMessages := make([]chatMessage, 0, len(messages))
	for _, msg := range messages {
		safeMessages = append(safeMessages, chatMessage{
			Role:    msg.Role,
			Content: truncateRunes(msg.Content, 48000),
		})
	}

	payload := map[string]any{
		"model":       model,
		"messages":    safeMessages,
		"temperature": 0.1,
	}
	if jsonMode && !ollama {
		payload["response_format"] = map[string]string{"type": "json_object"}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK}, fmt.Errorf("marshal llm request: %w", err)
	}

	endpoint := chatCompletionsURL(cfg.BaseURL, ollama)
	attemptTimeout := 55 * time.Second
	if ollama {
		attemptTimeout = 85 * time.Second
	}
	var (
		raw       []byte
		latencyMs int64
		resp      *http.Response
	)
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("call llm endpoint: %w", err)
		}
		reqCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if reqErr != nil {
			cancel()
			return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK}, fmt.Errorf("create llm request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Close = true
		if cfg.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		}
		if strings.Contains(strings.ToLower(cfg.BaseURL), "openrouter.ai") {
			req.Header.Set("HTTP-Referer", "https://secflow.local")
			req.Header.Set("X-Title", "SecFlow")
		}
		start := time.Now()
		resp, err = httpClientForLLM(cfg.BaseURL).Do(req)
		latencyMs += time.Since(start).Milliseconds()
		if err != nil {
			cancel()
			isTimeout := errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout")
			maxForErr := maxAttempts
			if isTimeout {
				maxForErr = 2
			}
			if attempt < maxForErr && transientLLMError(err) {
				slog.Warn("llm call retry", "attempt", attempt, "err", err)
				if sErr := sleepContext(ctx, retryDelay(attempt, "")); sErr != nil {
					return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("call llm endpoint: %w", sErr)
				}
				continue
			}
			return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("call llm endpoint: %w", err)
		}
		raw, err = io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		cancel()
		if err != nil {
			if attempt < maxAttempts && transientLLMError(err) {
				slog.Warn("llm read retry", "attempt", attempt, "err", err)
				if sErr := sleepContext(ctx, retryDelay(attempt, "")); sErr != nil {
					return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("read llm response: %w", sErr)
				}
				continue
			}
			return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("read llm response: %w", err)
		}
		if (resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt < maxAttempts {
			slog.Warn("llm status retry", "attempt", attempt, "status", resp.StatusCode)
			if sErr := sleepContext(ctx, retryDelay(attempt, resp.Header.Get("Retry-After"))); sErr != nil {
				return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, parseLLMAPIError(resp.StatusCode, raw)
			}
			continue
		}
		break
	}
	if resp.StatusCode >= 300 {
		return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, parseLLMAPIError(resp.StatusCode, raw)
	}

	var doc struct {
		Choices []struct {
			Message struct {
				Content          json.RawMessage `json:"content"`
				Reasoning        string          `json:"reasoning"`
				ReasoningContent string          `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int32 `json:"prompt_tokens"`
			CompletionTokens int32 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("decode llm response: %w", err)
	}
	if len(doc.Choices) == 0 {
		return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("empty completion (%s)", responseShape(raw))
	}
	text := assistantText(doc.Choices[0].Message.Content, doc.Choices[0].Message.Reasoning, doc.Choices[0].Message.ReasoningContent)
	if strings.TrimSpace(text) == "" {
		return llmResponse{Mode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK, LatencyMs: latencyMs}, fmt.Errorf("empty completion (%s)", responseShape(raw))
	}
	return llmResponse{
		Content:   text,
		Model:     model,
		Mode:      mode,
		TokensIn:  doc.Usage.PromptTokens,
		TokensOut: doc.Usage.CompletionTokens,
		LatencyMs: latencyMs,
	}, nil
}

func transientLLMError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"eof", "connection reset", "broken pipe", "timeout", "temporary", "server misbehaving", "tls handshake"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func assistantText(content json.RawMessage, reasoning, reasoningContent string) string {
	text := contentToString(content)
	reason := strings.TrimSpace(firstNonEmpty(reasoning, reasoningContent))
	if strings.TrimSpace(text) == "" {
		return reason
	}
	if !strings.Contains(text, "{") && (strings.Contains(reason, "releaseDecision") || strings.Contains(reason, "release_decision")) {
		return reason
	}
	return text
}

func responseShape(raw []byte) string {
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		return "undecodable"
	}
	keys := make([]string, 0, len(top))
	for key := range top {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("top=")
	b.WriteString(strings.Join(keys, ","))
	if errObj, ok := top["error"].(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok {
			msg = strings.Join(strings.Fields(msg), " ")
			if len(msg) > 160 {
				msg = msg[:160]
			}
			b.WriteString(" error=")
			b.WriteString(msg)
		}
	}
	choices, _ := top["choices"].([]any)
	b.WriteString(fmt.Sprintf(" choices=%d", len(choices)))
	if len(choices) == 0 {
		return b.String()
	}
	choice, _ := choices[0].(map[string]any)
	if reason, ok := choice["finish_reason"].(string); ok && reason != "" {
		b.WriteString(" finish=")
		b.WriteString(reason)
	}
	msg, _ := choice["message"].(map[string]any)
	mkeys := make([]string, 0, len(msg))
	for key := range msg {
		mkeys = append(mkeys, key)
	}
	sort.Strings(mkeys)
	b.WriteString(" message=")
	b.WriteString(strings.Join(mkeys, ","))
	switch content := msg["content"].(type) {
	case nil:
		b.WriteString(" content=null")
	case string:
		b.WriteString(fmt.Sprintf(" content=string:%d", len(content)))
	case []any:
		b.WriteString(fmt.Sprintf(" content=array:%d", len(content)))
		if len(content) > 0 {
			if part, ok := content[0].(map[string]any); ok {
				if kind, ok := part["type"].(string); ok {
					b.WriteString(" part=")
					b.WriteString(kind)
				}
			}
		}
	default:
		b.WriteString(" content=other")
	}
	return b.String()
}

func contentToString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	if raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			return text
		}
	}
	if raw[0] == '[' {
		var parts []struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &parts); err == nil {
			var b strings.Builder
			for _, part := range parts {
				part.Text = strings.TrimSpace(part.Text)
				if part.Text == "" {
					continue
				}
				if b.Len() > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(part.Text)
			}
			return b.String()
		}
	}
	return ""
}

func httpClientForLLM(rawURL string) *http.Client {
	if isTrustedOllamaURL(rawURL) {
		return &http.Client{
			Timeout: 90 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects")
				}
				return validateLLMBaseURL(req.Context(), req.URL.String())
			},
		}
	}
	return llmHTTPClient
}

func detectProviderStatus(ctx context.Context) *secflowv1.GetProviderStatusResponse {
	providerEnv := strings.ToLower(strings.TrimSpace(os.Getenv("AI_PROVIDER")))
	ollamaURL := strings.TrimSpace(os.Getenv("OLLAMA_URL"))
	llmBaseURL := strings.TrimSpace(os.Getenv("LLM_BASE_URL"))
	apiKey := strings.TrimSpace(os.Getenv("LLM_API_KEY"))

	mode := secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK
	var activeURL string
	switch providerEnv {
	case "cloud":
		mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD
		activeURL = llmBaseURL
	case "ollama":
		mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA
		activeURL = firstNonEmpty(ollamaURL, llmBaseURL)
	case "template", "template_fallback", "fallback":
		mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK
	default:
		if llmBaseURL != "" {
			mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD
			activeURL = llmBaseURL
		} else if ollamaURL != "" {
			mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA
			activeURL = ollamaURL
		}
	}

	defaultPrivacy := defaultPrivacyForMode(mode)
	if mode == secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK || activeURL == "" {
		return &secflowv1.GetProviderStatusResponse{
			ProviderMode:       mode,
			ModelId:            "template-fallback",
			EndpointHost:       "local",
			ClosedLoop:         mode != secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
			DefaultPrivacyMode: defaultPrivacy,
			Healthy:            mode == secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK,
		}
	}

	activeURL = normalizeLLMBaseURL(activeURL)
	host := sanitizedHostname(activeURL)
	closedLoop := mode != secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD
	var modelID string
	if mode == secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA {
		modelID = firstNonEmpty(strings.TrimSpace(os.Getenv("OLLAMA_MODEL")), strings.TrimSpace(os.Getenv("LLM_MODEL")), "llama3.2")
	} else {
		modelID = firstNonEmpty(strings.TrimSpace(os.Getenv("LLM_MODEL")), "gpt-4o-mini")
	}

	healthy := probeLLMHealth(ctx, activeURL, apiKey, mode)
	return &secflowv1.GetProviderStatusResponse{
		ProviderMode:       mode,
		ModelId:            modelID,
		EndpointHost:       host,
		ClosedLoop:         closedLoop,
		DefaultPrivacyMode: defaultPrivacy,
		Healthy:            healthy,
	}
}

func defaultPrivacyForMode(mode secflowv1.AIProviderMode) secflowv1.PrivacyMode {
	switch strings.ToUpper(strings.TrimSpace(os.Getenv("AI_DEFAULT_PRIVACY_MODE"))) {
	case "METADATA_ONLY":
		return secflowv1.PrivacyMode_PRIVACY_MODE_METADATA_ONLY
	case "REDACTED_SNIPPET":
		return secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET
	}
	if mode == secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD {
		return secflowv1.PrivacyMode_PRIVACY_MODE_METADATA_ONLY
	}
	return secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET
}

func sanitizedHostname(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return "unknown"
	}
	return u.Hostname()
}

func probeLLMHealth(ctx context.Context, baseURL, apiKey string, mode secflowv1.AIProviderMode) bool {
	if mode == secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD && apiKey == "" {
		return false
	}
	if err := validateLLMBaseURL(ctx, baseURL); err != nil {
		return false
	}
	ollama := mode == secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA
	probeURL := modelsProbeURL(normalizeLLMBaseURL(baseURL), ollama)

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		return false
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := httpClientForLLM(baseURL).Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true
	}
	if ollama {
		// Fallback probe for Ollama /api/tags when /v1/models is not routed.
		u, parseErr := url.Parse(strings.TrimSpace(baseURL))
		if parseErr == nil && u.Scheme != "" && u.Host != "" {
			tagsURL := u.Scheme + "://" + u.Host + "/api/tags"
			req2, err2 := http.NewRequestWithContext(probeCtx, http.MethodGet, tagsURL, nil)
			if err2 == nil {
				if resp2, err2 := httpClientForLLM(baseURL).Do(req2); err2 == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(resp2.Body, 4096))
					_ = resp2.Body.Close()
					return resp2.StatusCode >= 200 && resp2.StatusCode < 400
				}
			}
		}
	}
	return false
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
