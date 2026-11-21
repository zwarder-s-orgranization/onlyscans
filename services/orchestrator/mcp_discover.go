package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/urlguard"
)

var mcpDiscoverHTTP = urlguard.NewSafeClient(8 * time.Second)

type bridgeDiscoverRequest struct {
	Action         string   `json:"__secflow_action,omitempty"`
	ConnectionID   string   `json:"connectionId"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	EndpointURL    string   `json:"endpointUrl"`
	AuthSecretRef  string   `json:"authSecretRef"`
	AuthHeaderName string   `json:"authHeaderName"`
	AllowedTools   []string `json:"allowedTools"`
	DeniedTools    []string `json:"deniedTools"`
}

type bridgeDiscoverTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type bridgeDiscoverResponse struct {
	Tools            []bridgeDiscoverTool `json:"tools"`
	BlockedToolCount int                  `json:"blockedToolCount"`
	ServerName       string               `json:"serverName"`
	ServerVersion    string               `json:"serverVersion"`
	Code             string               `json:"code"`
	Message          string               `json:"message"`
}

func (s *Server) discoverTools(ctx context.Context, conn *secflowv1.MCPConnection) ([]*secflowv1.MCPToolDescriptor, int, string, string, error) {
	if conn == nil || conn.GetConfig() == nil {
		return nil, 0, "", "", status.Error(codes.InvalidArgument, "missing mcp connection config")
	}
	cfg := conn.GetConfig()
	endpoint := strings.TrimSpace(cfg.GetEndpointUrl())
	if urlguard.Denied(cfg.GetName() + " " + cfg.GetDescription() + " " + endpoint) {
		return nil, 0, "", "", urlguard.ErrDenylistBlocked
	}
	if err := endpointAllowed(ctx, endpoint); err != nil {
		return nil, 0, "", "", err
	}

	if s.hasWorker("mcp.tool") {
		return s.discoverViaWorker(ctx, conn)
	}

	authToken := ""
	if authRef := strings.TrimSpace(cfg.GetAuthSecretRef()); authRef != "" {
		res, err := s.ResolveScopedSecret(ctx, &secflowv1.ResolveScopedSecretRequest{
			SecretRef:    authRef,
			ServiceToken: s.serviceTK,
			Scope: &secflowv1.ResolveScopedSecretRequest_McpDiscovery{
				McpDiscovery: &secflowv1.MCPDiscoverySecretScope{
					McpConnectionId: conn.GetId(),
				},
			},
		})
		if err != nil {
			return nil, 0, "", "", fmt.Errorf("resolve mcp discovery secret: %w", err)
		}
		authToken = res.GetPlaintextValue()
	}

	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	if err != nil {
		return nil, 0, "", "", fmt.Errorf("marshal tools/list: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", "", fmt.Errorf("create tools/list request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	applyMCPAuthHeader(req, cfg.GetAuthHeaderName(), authToken)

	resp, err := mcpDiscoverHTTP.Do(req)
	if err != nil {
		return nil, 0, "", "", fmt.Errorf("discover mcp tools: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, "", "", fmt.Errorf("read tools/list response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, 0, "", "", fmt.Errorf("mcp status %d", resp.StatusCode)
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
		return nil, 0, "", "", fmt.Errorf("decode tools/list response: %w", err)
	}

	tools := make([]*secflowv1.MCPToolDescriptor, 0, len(doc.Result.Tools))
	blocked := 0
	for _, tool := range doc.Result.Tools {
		if !mcpToolAllowed(tool.Name, tool.Description, cfg.GetAllowedTools(), cfg.GetDeniedTools()) {
			blocked++
			continue
		}
		schema := tool.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		tools = append(tools, &secflowv1.MCPToolDescriptor{
			Name:            tool.Name,
			Description:     tool.Description,
			InputSchemaJson: schema,
		})
	}
	return tools, blocked, doc.Result.ServerInfo.Name, doc.Result.ServerInfo.Version, nil
}

func (s *Server) discoverViaWorker(ctx context.Context, conn *secflowv1.MCPConnection) ([]*secflowv1.MCPToolDescriptor, int, string, string, error) {
	cfg := conn.GetConfig()
	payload, err := json.Marshal(bridgeDiscoverRequest{
		Action:         "discover",
		ConnectionID:   conn.GetId(),
		Name:           cfg.GetName(),
		Description:    cfg.GetDescription(),
		EndpointURL:    cfg.GetEndpointUrl(),
		AuthSecretRef:  cfg.GetAuthSecretRef(),
		AuthHeaderName: cfg.GetAuthHeaderName(),
		AllowedTools:   cfg.GetAllowedTools(),
		DeniedTools:    cfg.GetDeniedTools(),
	})
	if err != nil {
		return nil, 0, "", "", fmt.Errorf("marshal bridge discover request: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	task := &secflowv1.NodeTask{
		RunId:              "__mcp_discover__",
		NodeId:             "__mcp_discover__",
		NodeRunId:          id("nr"),
		PluginId:           "mcp.tool",
		ParamsJson:         payload,
		LeaseSeconds:       30,
		HardTimeoutSeconds: 15,
		Attempt:            1,
	}
	res, ok := s.dispatchWorkerTask(callCtx, "mcp.tool", task)
	if !ok || res == nil {
		return nil, 0, "", "", fmt.Errorf("mcp-bridge worker unavailable")
	}

	var doc bridgeDiscoverResponse
	if len(res.GetEnvelopePatchJson()) > 0 {
		_ = json.Unmarshal(res.GetEnvelopePatchJson(), &doc)
	}
	errCode := strings.TrimSpace(doc.Code)
	if errCode == "" {
		errCode = strings.TrimSpace(res.GetErrorCode())
	}
	errMsg := strings.TrimSpace(doc.Message)
	if errMsg == "" {
		errMsg = strings.TrimSpace(res.GetErrorMessage())
	}
	if res.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || errCode != "" {
		switch errCode {
		case "DENYLIST_BLOCKED":
			return nil, 0, "", "", urlguard.ErrDenylistBlocked
		case "ALLOWLIST_DENIED":
			return nil, 0, "", "", urlguard.ErrAllowlistDenied
		case "SECRET_SCOPE_DENIED":
			return nil, 0, "", "", status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
		default:
			if errMsg != "" {
				return nil, 0, "", "", fmt.Errorf("mcp-bridge discover: %s", errMsg)
			}
			return nil, 0, "", "", fmt.Errorf("mcp-bridge discover failed")
		}
	}

	tools := make([]*secflowv1.MCPToolDescriptor, 0, len(doc.Tools))
	blocked := doc.BlockedToolCount
	for _, tool := range doc.Tools {
		if !mcpToolAllowed(tool.Name, tool.Description, cfg.GetAllowedTools(), cfg.GetDeniedTools()) {
			blocked++
			continue
		}
		schema := tool.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		tools = append(tools, &secflowv1.MCPToolDescriptor{
			Name:            tool.Name,
			Description:     tool.Description,
			InputSchemaJson: schema,
		})
	}
	return tools, blocked, doc.ServerName, doc.ServerVersion, nil
}

func applyMCPAuthHeader(req *http.Request, headerName, token string) {
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

func mcpToolAllowed(name, description string, allowedTools, deniedTools []string) bool {
	if urlguard.Denied(name + " " + description) {
		return false
	}
	if len(allowedTools) > 0 && !mcpToolMatchesAny(name, allowedTools) {
		return false
	}
	if mcpToolMatchesAny(name, deniedTools) {
		return false
	}
	return true
}

func mcpToolMatchesAny(tool string, patterns []string) bool {
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

func endpointAllowed(ctx context.Context, raw string) error {
	return urlguard.CheckCtx(ctx, raw)
}
