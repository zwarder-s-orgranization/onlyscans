package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
)

const mcpSessionHeader = "Mcp-Session-Id"

type mcpRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
}

func (g *gateway) mcpServerHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := withTraceparent(r.Context(), r)
	r = r.WithContext(ctx)

	switch r.Method {
	case http.MethodGet:
		g.mcpServerSSE(w, r)
		return
	case http.MethodDelete:
		claims, err := g.bearer(r)
		if err != nil || claims == nil {
			writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication required")
			return
		}
		if sid := strings.TrimSpace(r.Header.Get(mcpSessionHeader)); sid != "" {
			w.Header().Set(mcpSessionHeader, sid)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
		g.mcpServerPOST(w, r)
		return
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
	}
}

func (g *gateway) mcpServerSSE(w http.ResponseWriter, r *http.Request) {
	claims, err := g.bearer(r)
	if err != nil || claims == nil {
		writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication required")
		return
	}
	if g.limited(r.Context(), claims.Subject) {
		writeProblem(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
		return
	}
	sessionID := strings.TrimSpace(r.Header.Get(mcpSessionHeader))
	if sessionID == "" {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Mcp-Session-Id header is required")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set(mcpSessionHeader, sessionID)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	if _, err := io.WriteString(w, "event: endpoint\ndata: /mcp\n\n: keepalive\n\n"); err != nil {
		return
	}
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (g *gateway) mcpServerPOST(w http.ResponseWriter, r *http.Request) {
	var req mcpRPCRequest
	decErr := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)

	claims, err := g.bearer(r)
	if err != nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error":   map[string]any{"code": -32001, "message": "UNAUTHENTICATED"},
		})
		return
	}
	if decErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"jsonrpc": "2.0",
			"id":      nil,
			"error":   map[string]any{"code": -32700, "message": "parse error"},
		})
		return
	}
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error":   map[string]any{"code": -32600, "message": "invalid request"},
		})
		return
	}
	if g.limited(r.Context(), claims.Subject) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error":   map[string]any{"code": -32029, "message": "RATE_LIMITED"},
		})
		return
	}

	sessionID := strings.TrimSpace(r.Header.Get(mcpSessionHeader))
	if req.Method == "initialize" {
		if sessionID == "" {
			sessionID = "mcp_" + randomHexID(16)
		}
		w.Header().Set(mcpSessionHeader, sessionID)
	} else if sessionID != "" {
		w.Header().Set(mcpSessionHeader, sessionID)
	}

	// JSON-RPC notifications (no id) acknowledge with 202 Accepted per MCP Streamable HTTP.
	if req.Method == "notifications/initialized" || (strings.HasPrefix(req.Method, "notifications/") && req.ID == nil) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	result, rpcErr := g.mcpServerCall(r, claims, req.Method, req.Params)
	body := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	statusCode := http.StatusOK
	if rpcErr != nil {
		body["error"] = rpcErr
		switch rpcErr["message"] {
		case "UNAUTHENTICATED":
			statusCode = http.StatusUnauthorized
		case "FORBIDDEN", "ALLOWLIST_DENIED", "SECRET_SCOPE_DENIED":
			statusCode = http.StatusForbidden
		case "RATE_LIMITED":
			statusCode = http.StatusTooManyRequests
		}
	} else {
		body["result"] = result
	}
	writeJSON(w, statusCode, body)
}

func mcpServerAllowed(field, requiredScope string, claims *auth.Claims) bool {
	if claims == nil || !allowed(field, claims) {
		return false
	}
	return roleRank(claims.Role) >= 1 || hasScope(claims, requiredScope)
}

func (g *gateway) mcpServerCall(r *http.Request, claims *auth.Claims, method string, params map[string]any) (any, map[string]any) {
	if claims == nil {
		return nil, map[string]any{"code": -32001, "message": "UNAUTHENTICATED"}
	}
	switch method {
	case "initialize":
		protoVer := strings.TrimSpace(asString(params["protocolVersion"]))
		if protoVer == "" {
			protoVer = "2025-03-26"
		}
		return map[string]any{
			"protocolVersion": protoVer,
			"serverInfo":      map[string]any{"name": "secflow", "version": "1.0.0"},
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		if !mcpServerAllowed("workflows", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		return map[string]any{"tools": mcpServerTools()}, nil
	case "resources/list":
		if !mcpServerAllowed("plugins", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		return map[string]any{"resources": mcpServerResources()}, nil
	case "resources/templates/list":
		if !mcpServerAllowed("plugins", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		return map[string]any{"resourceTemplates": mcpServerResourceTemplates()}, nil
	case "tools/call":
		name := asString(params["name"])
		args := asMap(params["arguments"])
		return g.mcpServerTool(r, claims, name, args)
	case "resources/read":
		return g.mcpServerResource(r, claims, asString(params["uri"]))
	default:
		return nil, map[string]any{"code": -32601, "message": "method not found"}
	}
}

func mcpServerErrorFromGRPC(err error) map[string]any {
	st, ok := status.FromError(err)
	if !ok {
		slog.Error("mcp backend error", "err", err)
		return map[string]any{"code": -32000, "message": "INTERNAL"}
	}
	msg := st.Message()
	switch st.Code() {
	case codes.Unauthenticated:
		return map[string]any{"code": -32001, "message": "UNAUTHENTICATED"}
	case codes.PermissionDenied:
		if strings.Contains(msg, "ALLOWLIST") {
			return map[string]any{"code": -32003, "message": "ALLOWLIST_DENIED"}
		}
		if strings.Contains(msg, "SECRET_SCOPE_DENIED") {
			return map[string]any{"code": -32003, "message": "SECRET_SCOPE_DENIED"}
		}
		return map[string]any{"code": -32001, "message": "FORBIDDEN"}
	case codes.FailedPrecondition:
		if strings.Contains(msg, "DENYLIST") {
			return map[string]any{"code": -32005, "message": "DENYLIST_BLOCKED"}
		}
		return map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
	case codes.NotFound:
		return map[string]any{"code": -32004, "message": "NOT_FOUND"}
	case codes.InvalidArgument:
		return map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
	case codes.ResourceExhausted:
		return map[string]any{"code": -32029, "message": "RATE_LIMITED"}
	default:
		slog.Error("mcp backend grpc error", "code", st.Code().String(), "err", err)
		return map[string]any{"code": -32000, "message": "INTERNAL"}
	}
}

func mcpPageInfo(paged map[string]any) map[string]any {
	return map[string]any{
		"nextCursor": paged["nextCursor"],
		"hasMore":    paged["hasMore"],
		"totalCount": paged["totalCount"],
	}
}

func (g *gateway) mcpServerTool(r *http.Request, claims *auth.Claims, name string, args map[string]any) (any, map[string]any) {
	if claims == nil {
		return nil, map[string]any{"code": -32001, "message": "UNAUTHENTICATED"}
	}
	ctx := r.Context()
	actor := g.actorOf(claims)
	var payload any
	var rawText string
	var err error

	switch name {
	case "list_workflows":
		if !mcpServerAllowed("workflows", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.wf == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		search := asString(args["search"])
		limit := asInt(args["limit"], 25)
		cursor := asString(args["cursor"])
		resp, e := g.wf.ListWorkflows(ctx, &secflowv1.ListWorkflowsRequest{
			Actor:  actor,
			Search: search,
			Page:   pageReq(limit, cursor),
		})
		err = e
		if err == nil {
			searchLower := strings.ToLower(strings.TrimSpace(search))
			items := make([]any, 0, len(resp.GetWorkflows()))
			for _, wf := range resp.GetWorkflows() {
				if claims.Wf != "" && wf.GetId() != claims.Wf {
					continue
				}
				if searchLower != "" && !strings.Contains(strings.ToLower(wf.GetName()), searchLower) {
					continue
				}
				items = append(items, workflowMap(wf))
			}
			paged := paginate(items, limit, cursor, resp.GetPageInfo())
			payload = map[string]any{
				"workflows": paged["items"],
				"pageInfo":  mcpPageInfo(paged),
			}
		}

	case "list_templates":
		if !mcpServerAllowed("templates", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.wf == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		search := asString(args["search"])
		tags := asStringSlice(args["tags"])
		limit := asInt(args["limit"], 25)
		cursor := asString(args["cursor"])
		resp, e := g.wf.ListTemplates(ctx, &secflowv1.ListTemplatesRequest{
			Actor:  actor,
			Search: search,
			Tags:   tags,
			Page:   pageReq(limit, cursor),
		})
		err = e
		if err == nil {
			items := make([]any, 0, len(resp.GetTemplates()))
			for _, tpl := range resp.GetTemplates() {
				if !templateHasAllTags(tpl.GetTags(), tags) {
					continue
				}
				items = append(items, templateMap(tpl))
			}
			paged := paginate(items, limit, cursor, resp.GetPageInfo())
			payload = map[string]any{
				"templates": paged["items"],
				"pageInfo":  mcpPageInfo(paged),
			}
		}

	case "clone_template":
		if !mcpServerAllowed("cloneTemplate", "mcp:write", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.wf == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		templateID := strings.TrimSpace(asString(args["templateId"]))
		newName := strings.TrimSpace(asString(args["newWorkflowName"]))
		if templateID == "" || newName == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		resp, e := g.wf.CloneTemplate(ctx, &secflowv1.CloneTemplateRequest{
			Actor:           actor,
			TemplateId:      templateID,
			NewWorkflowName: newName,
		})
		err = e
		if err == nil {
			wf := workflowMap(resp.GetWorkflow())
			wf["workflowId"] = resp.GetWorkflow().GetId()
			payload = wf
		}

	case "generate_workflow_preview":
		if !mcpServerAllowed("generateWorkflowFromText", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.ai == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		prompt := strings.TrimSpace(asString(args["prompt"]))
		if prompt == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		locale := strings.TrimSpace(asString(args["locale"]))
		if locale == "" {
			locale = "ru"
		}
		resp, e := g.ai.GenerateWorkflow(ctx, &secflowv1.GenerateWorkflowRequest{
			Actor:  actor,
			Prompt: prompt,
			Locale: locale,
		})
		err = e
		if err == nil {
			payload = map[string]any{
				"suggestedName":        resp.GetSuggestedName(),
				"suggestedDescription": resp.GetSuggestedDescription(),
				"rationale":            resp.GetRationale(),
				"graph":                graphMap(resp.GetGraph()),
				"missingFields":        issuesMap(resp.GetMissingFields()),
				"modelId":              resp.GetModelId(),
				"providerMode":         first(trimEnum(resp.GetProviderMode().String(), "AI_PROVIDER_MODE_"), "TEMPLATE_FALLBACK"),
			}
		}

	case "run_workflow":
		if !mcpServerAllowed("startRun", "mcp:run", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.runs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		wfID := strings.TrimSpace(asString(args["workflowId"]))
		if wfID == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		if scopeErr := g.checkScopedWorkflow(claims, wfID); scopeErr != nil {
			return nil, mcpServerErrorFromGRPC(scopeErr)
		}
		resp, e := g.runs.StartRun(ctx, &secflowv1.StartRunRequest{
			Actor:             actor,
			WorkflowId:        wfID,
			TriggerType:       secflowv1.TriggerType_TRIGGER_TYPE_MCP,
			SourceIdOverride:  asString(args["sourceIdOverride"]),
			RepoUrlOverride:   asString(args["repoUrlOverride"]),
			GitRefOverride:    asString(args["gitRefOverride"]),
			CommitShaOverride: asString(args["commitShaOverride"]),
		})
		err = e
		if err == nil {
			run := resp.GetRun()
			traceID := first(run.GetTraceId(), traceIDFromRequest(r))
			if traceID == "" {
				traceID = run.GetId()
			}
			payload = map[string]any{
				"runId":   run.GetId(),
				"status":  first(trimEnum(run.GetStatus().String(), "RUN_STATUS_"), "QUEUED"),
				"traceId": traceID,
			}
		}

	case "get_run_status":
		if !mcpServerAllowed("run", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.runs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		runID := strings.TrimSpace(asString(args["runId"]))
		if runID == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		resp, e := g.runs.GetRun(ctx, &secflowv1.GetRunRequest{Actor: actor, RunId: runID})
		err = e
		if err == nil {
			run := resp.GetRun()
			if scopeErr := g.checkScopedWorkflow(claims, run.GetWorkflowId()); scopeErr != nil {
				return nil, mcpServerErrorFromGRPC(scopeErr)
			}
			mapped := runMap(run)
			mapped["runId"] = run.GetId()
			mapped["nodeStatuses"] = mapped["nodeRuns"]
			payload = mapped
		}

	case "get_findings":
		if !mcpServerAllowed("findings", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.runs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		runID := strings.TrimSpace(asString(args["runId"]))
		if runID == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		if _, scopeErr := g.checkScopedRun(ctx, claims, actor, runID); scopeErr != nil {
			return nil, mcpServerErrorFromGRPC(scopeErr)
		}
		limit := asInt(args["limit"], 25)
		cursor := asString(args["cursor"])
		resp, e := g.runs.ListFindings(ctx, &secflowv1.ListFindingsRequest{
			Actor:       actor,
			RunId:       runID,
			Category:    findingCategory(asString(args["category"])),
			MinSeverity: severityProto(asString(args["minSeverity"])),
			Page:        pageReq(limit, cursor),
		})
		err = e
		if err == nil {
			items := make([]any, 0, len(resp.GetFindings()))
			for _, f := range resp.GetFindings() {
				items = append(items, findingMap(f))
			}
			stats := statsFrom(resp.GetFindings())
			if resp.GetStats() != nil {
				stats = envelopeStatsMap(resp.GetStats())
			}
			paged := paginate(items, limit, cursor, resp.GetPageInfo())
			payload = map[string]any{
				"findings": paged["items"],
				"stats":    stats,
				"pageInfo": mcpPageInfo(paged),
			}
		}

	case "get_ai_report":
		if !mcpServerAllowed("aiReport", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.runs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		runID := strings.TrimSpace(asString(args["runId"]))
		if runID == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		if _, scopeErr := g.checkScopedRun(ctx, claims, actor, runID); scopeErr != nil {
			return nil, mcpServerErrorFromGRPC(scopeErr)
		}
		resp, e := g.runs.GetAIReport(ctx, &secflowv1.GetAIReportRequest{Actor: actor, RunId: runID})
		err = e
		if err == nil {
			if resp.GetReport() == nil {
				return nil, map[string]any{"code": -32004, "message": "NOT_FOUND"}
			}
			payload = aiReportMap(resp.GetReport())
		}

	case "export_submission_json":
		if !mcpServerAllowed("submission", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.runs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		runID := strings.TrimSpace(asString(args["runId"]))
		if runID == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		if _, scopeErr := g.checkScopedRun(ctx, claims, actor, runID); scopeErr != nil {
			return nil, mcpServerErrorFromGRPC(scopeErr)
		}
		resp, e := g.runs.GetSubmissionReport(ctx, &secflowv1.GetSubmissionReportRequest{Actor: actor, RunId: runID})
		err = e
		if err == nil {
			raw := resp.GetSubmissionJson()
			if len(raw) == 0 {
				rawText = `{"findings":[]}`
			} else {
				rawText = string(raw)
			}
		}

	case "get_sbom":
		if !mcpServerAllowed("sbom", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.runs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		runID := strings.TrimSpace(asString(args["runId"]))
		if runID == "" {
			return nil, map[string]any{"code": -32602, "message": "VALIDATION_FAILED"}
		}
		if _, scopeErr := g.checkScopedRun(ctx, claims, actor, runID); scopeErr != nil {
			return nil, mcpServerErrorFromGRPC(scopeErr)
		}
		includeContent := asBool(args["includeContent"])
		resp, e := g.runs.GetSbom(ctx, &secflowv1.GetSbomRequest{
			Actor:          actor,
			RunId:          runID,
			IncludeContent: includeContent,
		})
		err = e
		if err == nil {
			meta := sbomMap(resp.GetSbom(), runID)
			out := map[string]any{
				"sbom":               meta,
				"digest":             meta["digest"],
				"specVersion":        meta["specVersion"],
				"componentCount":     meta["componentCount"],
				"vulnerabilityCount": meta["vulnerabilityCount"],
				"downloadUrl":        meta["downloadUrl"],
				"generatedAt":        meta["generatedAt"],
			}
			if includeContent && len(resp.GetCyclonedxJson()) > 0 {
				var decoded any
				if json.Unmarshal(resp.GetCyclonedxJson(), &decoded) == nil {
					out["cyclonedxJson"] = decoded
				} else {
					out["cyclonedxJson"] = string(resp.GetCyclonedxJson())
				}
			}
			payload = out
		}

	default:
		return nil, map[string]any{"code": -32601, "message": "unknown tool"}
	}

	if err != nil {
		return nil, mcpServerErrorFromGRPC(err)
	}
	if rawText == "" {
		raw, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			slog.Error("marshal mcp tool response", "tool", name, "err", marshalErr)
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		rawText = string(raw)
	}
	return map[string]any{
		"content": []map[string]string{{"type": "text", "text": rawText}},
	}, nil
}

func (g *gateway) mcpServerResource(r *http.Request, claims *auth.Claims, uri string) (any, map[string]any) {
	if claims == nil {
		return nil, map[string]any{"code": -32001, "message": "UNAUTHENTICATED"}
	}
	ctx := r.Context()
	actor := g.actorOf(claims)
	switch {
	case uri == "secflow://plugins":
		if !mcpServerAllowed("plugins", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.plugs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		resp, err := g.plugs.ListPlugins(ctx, &secflowv1.ListPluginsRequest{Actor: actor})
		if err != nil {
			return nil, mcpServerErrorFromGRPC(err)
		}
		items := make([]any, 0, len(resp.GetPlugins()))
		for _, p := range resp.GetPlugins() {
			items = append(items, pluginMap(p))
		}
		raw, _ := json.Marshal(items)
		return map[string]any{"contents": []any{map[string]any{
			"uri":      uri,
			"mimeType": "application/json",
			"text":     string(raw),
		}}}, nil

	case uri == "secflow://templates":
		if !mcpServerAllowed("templates", "mcp:read", claims) {
			return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
		}
		if g.wf == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		resp, err := g.wf.ListTemplates(ctx, &secflowv1.ListTemplatesRequest{Actor: actor})
		if err != nil {
			return nil, mcpServerErrorFromGRPC(err)
		}
		items := make([]any, 0, len(resp.GetTemplates()))
		for _, tpl := range resp.GetTemplates() {
			items = append(items, templateMap(tpl))
		}
		raw, _ := json.Marshal(items)
		return map[string]any{"contents": []any{map[string]any{
			"uri":      uri,
			"mimeType": "application/json",
			"text":     string(raw),
		}}}, nil

	case strings.HasPrefix(uri, "secflow://runs/"):
		if g.runs == nil {
			return nil, map[string]any{"code": -32000, "message": "INTERNAL"}
		}
		rest := strings.TrimPrefix(uri, "secflow://runs/")
		runID, artifact, ok := strings.Cut(rest, "/")
		if !ok || runID == "" || strings.Contains(artifact, "/") {
			return nil, map[string]any{"code": -32602, "message": "invalid resource uri"}
		}
		switch artifact {
		case "submission.json":
			if !mcpServerAllowed("submission", "mcp:read", claims) {
				return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
			}
			if _, scopeErr := g.checkScopedRun(ctx, claims, actor, runID); scopeErr != nil {
				return nil, mcpServerErrorFromGRPC(scopeErr)
			}
			resp, err := g.runs.GetSubmissionReport(ctx, &secflowv1.GetSubmissionReportRequest{Actor: actor, RunId: runID})
			if err != nil {
				return nil, mcpServerErrorFromGRPC(err)
			}
			return map[string]any{"contents": []any{map[string]any{
				"uri":      uri,
				"mimeType": "application/json",
				"text":     string(resp.GetSubmissionJson()),
			}}}, nil

		case "report.md":
			if !mcpServerAllowed("readableReport", "mcp:read", claims) {
				return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
			}
			if _, scopeErr := g.checkScopedRun(ctx, claims, actor, runID); scopeErr != nil {
				return nil, mcpServerErrorFromGRPC(scopeErr)
			}
			resp, err := g.runs.GetReadableReport(ctx, &secflowv1.GetReadableReportRequest{
				Actor:  actor,
				RunId:  runID,
				Format: secflowv1.ReportFormat_REPORT_FORMAT_MARKDOWN,
			})
			if err != nil {
				return nil, mcpServerErrorFromGRPC(err)
			}
			return map[string]any{"contents": []any{map[string]any{
				"uri":      uri,
				"mimeType": "text/markdown",
				"text":     string(resp.GetContent()),
			}}}, nil

		case "sbom.cdx.json":
			if !mcpServerAllowed("sbom", "mcp:read", claims) {
				return nil, map[string]any{"code": -32001, "message": "FORBIDDEN"}
			}
			if _, scopeErr := g.checkScopedRun(ctx, claims, actor, runID); scopeErr != nil {
				return nil, mcpServerErrorFromGRPC(scopeErr)
			}
			resp, err := g.runs.GetSbom(ctx, &secflowv1.GetSbomRequest{
				Actor:          actor,
				RunId:          runID,
				IncludeContent: true,
			})
			if err != nil {
				return nil, mcpServerErrorFromGRPC(err)
			}
			return map[string]any{"contents": []any{map[string]any{
				"uri":      uri,
				"mimeType": "application/vnd.cyclonedx+json",
				"text":     string(resp.GetCyclonedxJson()),
			}}}, nil

		default:
			return nil, map[string]any{"code": -32602, "message": "unknown resource"}
		}

	default:
		return nil, map[string]any{"code": -32602, "message": "unknown resource"}
	}
}

func mcpServerResources() []any {
	return []any{
		map[string]any{
			"uri":         "secflow://plugins",
			"name":        "SecFlow Plugin Registry",
			"description": "Registered workflow plugins and active worker status",
			"mimeType":    "application/json",
		},
		map[string]any{
			"uri":         "secflow://templates",
			"name":        "SecFlow Workflow Templates",
			"description": "Built-in and published sanitized workflow templates",
			"mimeType":    "application/json",
		},
		map[string]any{
			"uri":         "secflow://runs/{runId}/submission.json",
			"name":        "Run Submission JSON",
			"description": "Canonical UTF-8 submission findings JSON for a run",
			"mimeType":    "application/json",
		},
		map[string]any{
			"uri":         "secflow://runs/{runId}/report.md",
			"name":        "Run Markdown Report",
			"description": "Human-readable Markdown security report for a run",
			"mimeType":    "text/markdown",
		},
		map[string]any{
			"uri":         "secflow://runs/{runId}/sbom.cdx.json",
			"name":        "Run CycloneDX SBOM",
			"description": "CycloneDX 1.6 JSON SBOM generated for a run",
			"mimeType":    "application/vnd.cyclonedx+json",
		},
	}
}

func mcpServerResourceTemplates() []any {
	return []any{
		map[string]any{
			"uriTemplate": "secflow://runs/{runId}/submission.json",
			"name":        "Run Submission JSON",
			"mimeType":    "application/json",
		},
		map[string]any{
			"uriTemplate": "secflow://runs/{runId}/report.md",
			"name":        "Run Markdown Report",
			"mimeType":    "text/markdown",
		},
		map[string]any{
			"uriTemplate": "secflow://runs/{runId}/sbom.cdx.json",
			"name":        "Run CycloneDX SBOM",
			"mimeType":    "application/vnd.cyclonedx+json",
		},
	}
}

func mcpServerTools() []any {
	return []any{
		map[string]any{
			"name":        "list_workflows",
			"description": "List SecFlow security workflows visible to the caller",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"search": map[string]any{"type": "string", "description": "Optional workflow name substring filter"},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
					"cursor": map[string]any{"type": "string", "description": "Pagination cursor"},
				},
			},
		},
		map[string]any{
			"name":        "list_templates",
			"description": "List built-in and published workflow templates",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"search": map[string]any{"type": "string", "description": "Optional template search query"},
					"tags":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Required template tags"},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
					"cursor": map[string]any{"type": "string", "description": "Pagination cursor"},
				},
			},
		},
		map[string]any{
			"name":        "clone_template",
			"description": "Clone a sanitized workflow template into a new workflow",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"templateId", "newWorkflowName"},
				"properties": map[string]any{
					"templateId":      map[string]any{"type": "string", "minLength": 1, "description": "Template ID or slug to clone"},
					"newWorkflowName": map[string]any{"type": "string", "minLength": 1, "description": "Name for the cloned workflow"},
				},
			},
		},
		map[string]any{
			"name":        "generate_workflow_preview",
			"description": "Generate a non-persisted workflow DAG preview from natural language",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"prompt"},
				"properties": map[string]any{
					"prompt": map[string]any{"type": "string", "minLength": 1, "description": "Natural language description of the workflow"},
					"locale": map[string]any{"type": "string", "enum": []string{"ru", "en"}, "default": "ru"},
				},
			},
		},
		map[string]any{
			"name":        "run_workflow",
			"description": "Start a security workflow run with optional allowlisted source overrides",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"workflowId"},
				"properties": map[string]any{
					"workflowId":        map[string]any{"type": "string", "minLength": 1, "description": "Workflow ID to run"},
					"sourceIdOverride":  map[string]any{"type": "string", "description": "Optional uploaded source ID override"},
					"repoUrlOverride":   map[string]any{"type": "string", "description": "Optional allowlisted repository URL override"},
					"gitRefOverride":    map[string]any{"type": "string", "description": "Optional Git ref override"},
					"commitShaOverride": map[string]any{"type": "string", "description": "Optional Git commit SHA override"},
				},
			},
		},
		map[string]any{
			"name":        "get_run_status",
			"description": "Get run status, gate result, findings stats, and node statuses",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"runId"},
				"properties": map[string]any{
					"runId": map[string]any{"type": "string", "minLength": 1, "description": "Run ID"},
				},
			},
		},
		map[string]any{
			"name":        "get_findings",
			"description": "List immutable Run Findings with optional category, severity, and pagination filters",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"runId"},
				"properties": map[string]any{
					"runId":       map[string]any{"type": "string", "minLength": 1, "description": "Run ID"},
					"category":    map[string]any{"type": "string", "enum": []string{"SECRET", "SAST", "SCA"}},
					"minSeverity": map[string]any{"type": "string", "enum": []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}},
					"limit":       map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
					"cursor":      map[string]any{"type": "string", "description": "Pagination cursor"},
				},
			},
		},
		map[string]any{
			"name":        "get_ai_report",
			"description": "Retrieve the grounded AI explanation report for a run",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"runId"},
				"properties": map[string]any{
					"runId": map[string]any{"type": "string", "minLength": 1, "description": "Run ID"},
				},
			},
		},
		map[string]any{
			"name":        "export_submission_json",
			"description": "Export canonical UTF-8 submission JSON report from immutable Run Findings",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"runId"},
				"properties": map[string]any{
					"runId": map[string]any{"type": "string", "minLength": 1, "description": "Run ID"},
				},
			},
		},
		map[string]any{
			"name":        "get_sbom",
			"description": "Get CycloneDX 1.6 SBOM metadata and optional full JSON content for a run",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"runId"},
				"properties": map[string]any{
					"runId":          map[string]any{"type": "string", "minLength": 1, "description": "Run ID"},
					"includeContent": map[string]any{"type": "boolean", "default": false, "description": "Include full CycloneDX JSON content"},
				},
			},
		},
	}
}
