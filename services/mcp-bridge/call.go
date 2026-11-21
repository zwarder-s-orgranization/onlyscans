package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/secretclient"
	"github.com/secflow/secflow/services/internal/urlguard"
)

const (
	mcpDiscoverRunID       = "__mcp_discover__"
	mcpDiscoverNodeID      = "__mcp_discover__"
	defaultMCPOutputVarKey = "mcpToolResult"
)

var (
	safeHTTP             = urlguard.NewSafeClient(10 * time.Second)
	errSecretScopeDenied = errors.New("SECRET_SCOPE_DENIED")
)

type bridge struct {
	httpClient        *http.Client
	fetchConnection   func(ctx context.Context, connectionID string) (*secflowv1.MCPConnection, error)
	resolveNodeSecret func(ctx context.Context, task *secflowv1.NodeTask, secretRef string) (string, error)
	resolveDiscSecret func(ctx context.Context, connectionID, secretRef string) (string, error)
	serviceToken      string
}

type mcpEnvelopePatch struct {
	Vars map[string]string `json:"vars"`
}

func newDefaultBridge() *bridge {
	orchAddr := envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051")
	serviceTok := envutil.Get("SERVICE_TOKEN", "dev-service-token")
	return &bridge{
		httpClient:      safeHTTP,
		fetchConnection: fetchConnectionFromOrchestrator,
		resolveNodeSecret: func(ctx context.Context, task *secflowv1.NodeTask, secretRef string) (string, error) {
			return secretclient.ResolveNodeSecret(ctx, orchAddr, task, secretRef)
		},
		resolveDiscSecret: func(ctx context.Context, connectionID, secretRef string) (string, error) {
			return secretclient.ResolveMCPDiscoverySecret(ctx, orchAddr, serviceTok, connectionID, secretRef)
		},
		serviceToken: serviceTok,
	}
}

func callTool(ctx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
	return newDefaultBridge().callTool(ctx, task)
}

func (b *bridge) client() *http.Client {
	if b != nil && b.httpClient != nil {
		return b.httpClient
	}
	return safeHTTP
}

func (b *bridge) callTool(ctx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
	base := &secflowv1.NodeResult{
		NodeRunId:         task.GetNodeRunId(),
		RunId:             task.GetRunId(),
		NodeId:            task.GetNodeId(),
		PluginId:          "mcp.tool",
		ActiveOutputPorts: []string{"default"},
	}
	params := map[string]any{}
	if len(task.GetParamsJson()) > 0 {
		if err := json.Unmarshal(task.GetParamsJson(), &params); err != nil {
			base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
			base.ErrorCode = "INVALID_PARAMS"
			base.ErrorMessage = "invalid mcp params"
			return base
		}
	}

	// Orchestrator-initiated Pull gRPC discovery uses reserved sentinel run/node IDs.
	// Normal workflow tasks with any other run/node ID ignore __secflow_action.
	if action, _ := params["__secflow_action"].(string); task.GetRunId() == mcpDiscoverRunID && task.GetNodeId() == mcpDiscoverNodeID && action == "discover" {
		return b.handleDiscoverTask(ctx, task, base)
	}

	blob := string(task.GetParamsJson())
	if urlguard.Denied(blob) {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DENYLIST_BLOCKED"
		base.ErrorMessage = "scanner tool is blocked"
		return base
	}
	connID, _ := params["connectionId"].(string)
	connID = strings.TrimSpace(connID)
	tool, _ := params["toolName"].(string)
	tool = strings.TrimSpace(tool)
	if urlguard.Denied(tool) {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DENYLIST_BLOCKED"
		base.ErrorMessage = "scanner tool is blocked"
		return base
	}
	if connID == "" || tool == "" {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DELIVERY_FAILED"
		base.ErrorMessage = "mcp connection or tool missing"
		return base
	}
	if b.fetchConnection == nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DELIVERY_FAILED"
		base.ErrorMessage = "mcp connection registry unavailable"
		return base
	}
	conn, err := b.fetchConnection(ctx, connID)
	if err != nil || conn == nil || conn.GetConfig() == nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DELIVERY_FAILED"
		base.ErrorMessage = "mcp connection unavailable"
		return base
	}
	if !conn.GetEnabled() {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "MCP_CONNECTION_DISABLED"
		base.ErrorMessage = "mcp connection is disabled"
		return base
	}
	cfg := conn.GetConfig()
	endpoint := strings.TrimSpace(cfg.GetEndpointUrl())
	if urlguard.Denied(endpoint) || urlguard.Denied(cfg.GetName()+" "+cfg.GetDescription()) || urlguard.Denied(tool) {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DENYLIST_BLOCKED"
		base.ErrorMessage = "scanner tool or endpoint is blocked"
		return base
	}
	if err := urlguard.CheckCtx(ctx, endpoint); err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = err.Error()
		base.ErrorMessage = "endpoint rejected"
		return base
	}
	if len(cfg.GetAllowedTools()) > 0 && !matchesAnyTool(tool, cfg.GetAllowedTools()) {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "TOOL_NOT_ALLOWED"
		base.ErrorMessage = "tool is not in connection allowlist"
		return base
	}
	if matchesAnyTool(tool, cfg.GetDeniedTools()) {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "TOOL_DENIED"
		base.ErrorMessage = "tool is denied by connection policy"
		return base
	}

	authToken := ""
	if authRef := strings.TrimSpace(cfg.GetAuthSecretRef()); authRef != "" {
		if b.resolveNodeSecret == nil {
			base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
			base.ErrorCode = "SECRET_SCOPE_DENIED"
			base.ErrorMessage = "mcp auth secret resolver unavailable"
			return base
		}
		authToken, err = b.resolveNodeSecret(ctx, task, authRef)
		if err != nil {
			base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
			base.ErrorCode = "SECRET_SCOPE_DENIED"
			base.ErrorMessage = "mcp auth secret unavailable"
			return base
		}
	}

	arguments := params["arguments"]
	if arguments == nil {
		arguments = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": arguments,
		},
	})
	if err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "INVALID_PARAMS"
		base.ErrorMessage = "marshal mcp request"
		return base
	}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "ALLOWLIST_DENIED"
		base.ErrorMessage = "bad endpoint"
		return base
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	applyAuthHeader(req, cfg.GetAuthHeaderName(), authToken)

	resp, err := b.client().Do(req)
	if err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		if errors.Is(err, urlguard.ErrDenylistBlocked) {
			base.ErrorCode = "DENYLIST_BLOCKED"
		} else if errors.Is(err, urlguard.ErrAllowlistDenied) {
			base.ErrorCode = "ALLOWLIST_DENIED"
		} else {
			base.ErrorCode = "DELIVERY_FAILED"
		}
		base.ErrorMessage = "mcp call failed"
		return base
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DELIVERY_FAILED"
		base.ErrorMessage = "mcp read failed"
		return base
	}
	if resp.StatusCode >= 300 {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DELIVERY_FAILED"
		base.ErrorMessage = fmt.Sprintf("mcp status %d", resp.StatusCode)
		return base
	}
	if authToken != "" && len(authToken) >= 4 {
		raw = bytes.ReplaceAll(raw, []byte(authToken), []byte("[REDACTED]"))
	}

	outputVarKey, _ := params["outputVarKey"].(string)
	outputVarKey = strings.TrimSpace(outputVarKey)
	if outputVarKey == "" {
		outputVarKey = defaultMCPOutputVarKey
	}
	patch, err := json.Marshal(mcpEnvelopePatch{
		Vars: map[string]string{
			outputVarKey: string(raw),
		},
	})
	if err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DELIVERY_FAILED"
		base.ErrorMessage = "marshal mcp envelope patch"
		return base
	}
	base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED
	base.EnvelopePatchJson = patch
	return base
}

type discoverRequest struct {
	ConnectionID   string   `json:"connectionId"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	EndpointURL    string   `json:"endpointUrl"`
	AuthSecretRef  string   `json:"authSecretRef"`
	AuthHeaderName string   `json:"authHeaderName"`
	AllowedTools   []string `json:"allowedTools"`
	DeniedTools    []string `json:"deniedTools"`
}

type discoverTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type discoverResponse struct {
	Tools            []discoverTool `json:"tools"`
	BlockedToolCount int            `json:"blockedToolCount"`
	ServerName       string         `json:"serverName,omitempty"`
	ServerVersion    string         `json:"serverVersion,omitempty"`
	Code             string         `json:"code,omitempty"`
	Message          string         `json:"message,omitempty"`
}

func (b *bridge) handleDiscoverTask(ctx context.Context, task *secflowv1.NodeTask, base *secflowv1.NodeResult) *secflowv1.NodeResult {
	var req discoverRequest
	if err := json.Unmarshal(task.GetParamsJson(), &req); err != nil {
		payload, _ := json.Marshal(discoverResponse{
			Code:    "VALIDATION_FAILED",
			Message: "invalid discovery params",
		})
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "VALIDATION_FAILED"
		base.ErrorMessage = "invalid discovery params"
		base.EnvelopePatchJson = payload
		return base
	}
	resp, err := b.discoverTools(ctx, req)
	if err != nil {
		code := "DELIVERY_FAILED"
		msg := err.Error()
		switch {
		case errors.Is(err, urlguard.ErrDenylistBlocked):
			code = "DENYLIST_BLOCKED"
			msg = "DENYLIST_BLOCKED"
		case errors.Is(err, urlguard.ErrAllowlistDenied):
			code = "ALLOWLIST_DENIED"
			msg = "ALLOWLIST_DENIED"
		case errors.Is(err, errSecretScopeDenied):
			code = "SECRET_SCOPE_DENIED"
			msg = "SECRET_SCOPE_DENIED"
		}
		payload, _ := json.Marshal(discoverResponse{
			Code:    code,
			Message: msg,
		})
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = code
		base.ErrorMessage = msg
		base.EnvelopePatchJson = payload
		return base
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		base.ErrorCode = "DELIVERY_FAILED"
		base.ErrorMessage = "marshal discover response"
		return base
	}
	base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED
	base.EnvelopePatchJson = payload
	return base
}

func (b *bridge) discoverTools(ctx context.Context, req discoverRequest) (*discoverResponse, error) {
	endpoint := strings.TrimSpace(req.EndpointURL)
	if urlguard.Denied(req.Name + " " + req.Description + " " + endpoint) {
		return nil, urlguard.ErrDenylistBlocked
	}
	if err := urlguard.CheckCtx(ctx, endpoint); err != nil {
		return nil, err
	}

	authToken := ""
	if authRef := strings.TrimSpace(req.AuthSecretRef); authRef != "" {
		if b.resolveDiscSecret == nil {
			return nil, fmt.Errorf("%w: resolver unavailable", errSecretScopeDenied)
		}
		tok, err := b.resolveDiscSecret(ctx, req.ConnectionID, authRef)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errSecretScopeDenied, err)
		}
		authToken = tok
	}

	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tools/list: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create tools/list request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	applyAuthHeader(httpReq, req.AuthHeaderName, authToken)

	resp, err := b.client().Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("discover mcp tools: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read tools/list response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mcp status %d", resp.StatusCode)
	}

	var doc struct {
		Result struct {
			ServerInfo struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode tools/list response: %w", err)
	}

	out := &discoverResponse{
		Tools:         make([]discoverTool, 0, len(doc.Result.Tools)),
		ServerName:    doc.Result.ServerInfo.Name,
		ServerVersion: doc.Result.ServerInfo.Version,
	}
	for _, tool := range doc.Result.Tools {
		if urlguard.Denied(tool.Name + " " + tool.Description) {
			out.BlockedToolCount++
			continue
		}
		if len(req.AllowedTools) > 0 && !matchesAnyTool(tool.Name, req.AllowedTools) {
			out.BlockedToolCount++
			continue
		}
		if matchesAnyTool(tool.Name, req.DeniedTools) {
			out.BlockedToolCount++
			continue
		}
		schema := tool.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		out.Tools = append(out.Tools, discoverTool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: schema,
		})
	}
	return out, nil
}

func applyAuthHeader(req *http.Request, headerName, token string) {
	if req == nil || token == "" {
		return
	}
	name := strings.TrimSpace(headerName)
	if name == "" {
		name = "Authorization"
	}
	val := token
	if strings.EqualFold(name, "Authorization") && !strings.Contains(val, " ") {
		val = "Bearer " + val
	}
	req.Header.Set(name, val)
}

func matchesAnyTool(tool string, patterns []string) bool {
	target := strings.ToLower(strings.TrimSpace(tool))
	if target == "" {
		return false
	}
	for _, raw := range patterns {
		pat := strings.ToLower(strings.TrimSpace(raw))
		if pat == "" {
			continue
		}
		if pat == target {
			return true
		}
		if strings.ContainsAny(pat, "*?") {
			if ok, err := path.Match(pat, target); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func fetchConnectionFromOrchestrator(ctx context.Context, id string) (*secflowv1.MCPConnection, error) {
	conn, err := grpc.NewClient(envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"), grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
	if err != nil {
		return nil, fmt.Errorf("dial mcp registry: %w", err)
	}
	defer conn.Close()
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := secflowv1.NewMCPRegistryServiceClient(conn).GetConnection(reqCtx, &secflowv1.GetConnectionRequest{ConnectionId: id})
	if err != nil {
		return nil, fmt.Errorf("get mcp connection: %w", err)
	}
	if resp.GetConnection() == nil || resp.GetConnection().GetConfig() == nil {
		return nil, errors.New("missing mcp connection config")
	}
	return resp.GetConnection(), nil
}
