package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jackc/pgx/v5/pgxpool"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/secretclient"
	"github.com/secflow/secflow/services/internal/workerclient"
)

var advisory = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`)

func main() {
	obs.SetupLogger("ai-service")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "ai-service")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}
	lis, err := net.Listen("tcp", envutil.Get("GRPC_ADDR", ":50053"))
	if err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
	orchAddr := envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051")
	gs := grpc.NewServer(obs.GRPCServerOptions("ai-service")...)
	svc := &aiSvc{orchAddr: orchAddr}
	svc.openDB(ctx)
	defer svc.closeDB()
	svc.openCache(ctx)
	defer svc.closeCache()
	secflowv1.RegisterAIServiceServer(gs, svc)
	httpserver.Start(ctx, envutil.Get("HTTP_ADDR", ":8086"))
	go func() {
		if err := gs.Serve(lis); err != nil {
			slog.Error("grpc", "err", err)
			os.Exit(1)
		}
	}()
	go func() {
		m := aiExplainManifest()
		if err := workerclient.Run(ctx, orchAddr, "ai-service", []*secflowv1.PluginManifest{m}, func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
			return svc.handleExplainTask(taskCtx, orchAddr, task)
		}); err != nil && ctx.Err() == nil {
			slog.Error("ai worker stopped", "err", err)
		}
	}()
	<-ctx.Done()
	gs.GracefulStop()
}

func aiExplainManifest() *secflowv1.PluginManifest {
	if spec, ok := manifest.LookupBuiltin("ai.explain"); ok {
		rawSchema, _ := paramschema.RawDef("ai.explain")
		return spec.ToProto(string(rawSchema))
	}
	return manifest.One("ai.explain", "AI Explain", secflowv1.PluginCategory_PLUGIN_CATEGORY_AI_REPORT, []string{"ai"}, false)
}

func (a *aiSvc) handleExplainTask(taskCtx context.Context, orchAddr string, task *secflowv1.NodeTask) *secflowv1.NodeResult {
	params := map[string]any{}
	if len(task.GetParamsJson()) > 0 {
		if err := json.Unmarshal(task.GetParamsJson(), &params); err != nil {
			slog.WarnContext(taskCtx, "unmarshal ai.explain params", "err", err)
		}
	}
	var boundAPIKey string
	for _, b := range task.GetSecretBindings() {
		if (b.GetParamKey() != "llmApiKey" && b.GetParamKey() != "apiKey") || b.GetSecretRef() == "" {
			continue
		}
		plain, err := secretclient.ResolveNodeSecret(taskCtx, orchAddr, task, b.GetSecretRef())
		if err != nil {
			return &secflowv1.NodeResult{
				NodeRunId:         task.GetNodeRunId(),
				RunId:             task.GetRunId(),
				NodeId:            task.GetNodeId(),
				PluginId:          "ai.explain",
				Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
				ErrorCode:         "SECRET_SCOPE_DENIED",
				ErrorMessage:      "llmApiKey secret unavailable",
				ActiveOutputPorts: []string{"default"},
			}
		}
		boundAPIKey = plain
		break
	}
	cfg := resolveLLMConfig(params, boundAPIKey)
	explained, stripped, usedLLM, usedModel, usedMode := explainFindingsWithCache(taskCtx, cfg, params, task.GetEnvelopeJson(), a.cache)
	a.recordAudit(taskCtx, auditMeta{
		RunID:        task.GetRunId(),
		NodeRunID:    task.GetNodeRunId(),
		Operation:    secflowv1.AIOperation_AI_OPERATION_AI_EXPLAIN,
		PromptHash:   explained.PromptHash,
		UsedLLM:      usedLLM,
		ModelID:      usedModel,
		ProviderMode: usedMode,
		PrivacyMode:  parsePrivacyMode(explained.PrivacyMode),
		TokensIn:     explained.TokensIn,
		TokensOut:    explained.TokensOut,
		LatencyMs:    explained.LatencyMs,
		Stripped:     stripped,
		CacheHit:     explained.Cached,
	})
	patch, err := json.Marshal(explained)
	if err != nil {
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "ai.explain",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			ErrorMessage:      "marshal ai explanation failed",
			ActiveOutputPorts: []string{"default"},
		}
	}
	previewMap := map[string]any{
		"quality":      explained.Quality,
		"modelId":      explained.ModelID,
		"providerMode": explained.ProviderMode,
		"itemsCount":   len(explained.Items),
	}
	if explained.AttemptedModelID != "" {
		previewMap["attemptedModelId"] = explained.AttemptedModelID
	}
	if explained.FallbackErrorStatus > 0 {
		previewMap["errorStatus"] = explained.FallbackErrorStatus
	}
	if explained.FallbackErrorCode != "" {
		previewMap["errorCode"] = explained.FallbackErrorCode
	}
	if explained.FallbackErrorMessage != "" {
		previewMap["errorMessage"] = explained.FallbackErrorMessage
	}
	previewJSON, _ := json.Marshal(previewMap)
	return &secflowv1.NodeResult{
		NodeRunId:           task.GetNodeRunId(),
		RunId:               task.GetRunId(),
		NodeId:              task.GetNodeId(),
		PluginId:            "ai.explain",
		Status:              secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		ActiveOutputPorts:   []string{"default"},
		EnvelopePatchJson:   patch,
		RedactedPreviewJson: previewJSON,
	}
}

type aiSvc struct {
	secflowv1.UnimplementedAIServiceServer
	mu       sync.Mutex
	logs     []*secflowv1.AIAuditLogEntry
	pool     *pgxpool.Pool
	cache    explainCache
	orchAddr string
}

type auditMeta struct {
	RunID        string
	NodeRunID    string
	Operation    secflowv1.AIOperation
	PromptHash   string
	UsedLLM      bool
	ModelID      string
	ProviderMode secflowv1.AIProviderMode
	PrivacyMode  secflowv1.PrivacyMode
	TokensIn     int32
	TokensOut    int32
	LatencyMs    int64
	Stripped     int
	CacheHit     bool
}

func (a *aiSvc) recordAudit(ctx context.Context, meta auditMeta) {
	promptHash := meta.PromptHash
	if promptHash == "" {
		sum := sha256.Sum256([]byte(meta.RunID + "|" + meta.NodeRunID + "|" + meta.Operation.String()))
		promptHash = hex.EncodeToString(sum[:])
	}
	quality := secflowv1.AIQuality_AI_QUALITY_FALLBACK
	model := "template-fallback"
	mode := secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK
	if meta.UsedLLM {
		quality = secflowv1.AIQuality_AI_QUALITY_VERIFIED
		if meta.Stripped > 0 {
			quality = secflowv1.AIQuality_AI_QUALITY_DEGRADED
		}
		model = firstNonEmpty(meta.ModelID, envutil.Get("LLM_MODEL", envutil.Get("OLLAMA_MODEL", "llama3.2")))
		if meta.ProviderMode != secflowv1.AIProviderMode_AI_PROVIDER_MODE_UNSPECIFIED {
			mode = meta.ProviderMode
		} else {
			mode = secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD
		}
	}
	privacy := meta.PrivacyMode
	if privacy == secflowv1.PrivacyMode_PRIVACY_MODE_UNSPECIFIED {
		privacy = secflowv1.PrivacyMode_PRIVACY_MODE_METADATA_ONLY
	}
	entry := &secflowv1.AIAuditLogEntry{
		Id:                             newAuditID(),
		RunId:                          meta.RunID,
		NodeRunId:                      meta.NodeRunID,
		Operation:                      meta.Operation,
		ModelId:                        model,
		ProviderMode:                   mode,
		PrivacyMode:                    privacy,
		PromptHash:                     promptHash,
		TokensIn:                       meta.TokensIn,
		TokensOut:                      meta.TokensOut,
		LatencyMs:                      meta.LatencyMs,
		Quality:                        quality,
		StrippedHallucinatedAdvisories: int32(meta.Stripped),
		CacheHit:                       meta.CacheHit,
		CreatedAt:                      timestamppb.Now(),
	}
	a.mu.Lock()
	a.logs = append(a.logs, entry)
	a.mu.Unlock()
	a.persist(ctx, entry)
}

func (a *aiSvc) GenerateWorkflow(ctx context.Context, req *secflowv1.GenerateWorkflowRequest) (*secflowv1.GenerateWorkflowResponse, error) {
	catalog := fetchLivePluginCatalog(ctx, a.orchAddr)
	resp, meta := generateWorkflowWithCatalog(ctx, resolveLLMConfig(nil, ""), req.GetPrompt(), req.GetLocale(), catalog)
	a.recordAudit(ctx, auditMeta{
		Operation:    secflowv1.AIOperation_AI_OPERATION_GENERATE_WORKFLOW,
		PromptHash:   meta.PromptHash,
		UsedLLM:      meta.UsedLLM,
		ModelID:      meta.ModelID,
		ProviderMode: meta.Mode,
		PrivacyMode:  secflowv1.PrivacyMode_PRIVACY_MODE_METADATA_ONLY,
		TokensIn:     meta.TokensIn,
		TokensOut:    meta.TokensOut,
		LatencyMs:    meta.LatencyMs,
	})
	return resp, nil
}

func (a *aiSvc) GetProviderStatus(ctx context.Context, _ *secflowv1.GetProviderStatusRequest) (*secflowv1.GetProviderStatusResponse, error) {
	return detectProviderStatus(ctx), nil
}

func (a *aiSvc) ListAuditLogs(_ context.Context, req *secflowv1.ListAuditLogsRequest) (*secflowv1.ListAuditLogsResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var items []*secflowv1.AIAuditLogEntry
	for _, entry := range a.logs {
		if req.GetRunId() == "" || entry.GetRunId() == req.GetRunId() {
			items = append(items, entry)
		}
	}
	return &secflowv1.ListAuditLogsResponse{Entries: items, PageInfo: &secflowv1.PageInfo{TotalCount: int64(len(items))}}, nil
}

// StripUnknownAdvisories removes CVE/GHSA identifiers that are not in the SCA allowlist (case-insensitive).
func StripUnknownAdvisories(text string, allow map[string]struct{}) (string, int) {
	norm := make(map[string]struct{}, len(allow))
	for k := range allow {
		if trimmed := strings.TrimSpace(k); trimmed != "" {
			norm[strings.ToUpper(trimmed)] = struct{}{}
		}
	}
	stripped := 0
	out := advisory.ReplaceAllStringFunc(text, func(matched string) string {
		if _, ok := norm[strings.ToUpper(matched)]; ok {
			return matched
		}
		stripped++
		return "[removed-advisory]"
	})
	return out, stripped
}

func parsePrivacyMode(raw string) secflowv1.PrivacyMode {
	name := strings.ToUpper(strings.TrimSpace(raw))
	if !strings.HasPrefix(name, "PRIVACY_MODE_") {
		name = "PRIVACY_MODE_" + name
	}
	if v, ok := secflowv1.PrivacyMode_value[name]; ok {
		return secflowv1.PrivacyMode(v)
	}
	return secflowv1.PrivacyMode_PRIVACY_MODE_METADATA_ONLY
}

func newAuditID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
