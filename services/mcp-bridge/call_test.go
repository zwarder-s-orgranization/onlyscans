package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

func TestCallToolPolicyEnforcement(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")

	var gotAuthHeader string
	var gotCustomHeader string
	var gotMethod string
	var gotToolName string

	extMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotCustomHeader = r.Header.Get("X-API-Key")
		var body struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMethod = body.Method
		gotToolName = body.Params.Name
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true,"echo":"secret-raw-val"}}`))
	}))
	defer extMCP.Close()

	makeTask := func(connID, tool string) *secflowv1.NodeTask {
		raw, _ := json.Marshal(map[string]any{
			"connectionId": connID,
			"toolName":     tool,
			"arguments":    map[string]any{"title": "Security Alert"},
		})
		return &secflowv1.NodeTask{
			RunId:      "run_1",
			NodeRunId:  "nr_1",
			NodeId:     "n_mcp",
			PluginId:   "mcp.tool",
			ParamsJson: raw,
		}
	}

	t.Run("disabled connection rejected fail-closed", func(t *testing.T) {
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: false,
					Config: &secflowv1.MCPConnectionConfig{
						Name:        "GitHub Issues",
						EndpointUrl: extMCP.URL,
					},
				}, nil
			},
		}
		res := b.callTool(t.Context(), makeTask("conn_1", "create_issue"))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "MCP_CONNECTION_DISABLED" {
			t.Fatalf("got status=%v code=%q, want FAILED/MCP_CONNECTION_DISABLED", res.GetStatus(), res.GetErrorCode())
		}
	})

	t.Run("allowedTools blocks unlisted tool", func(t *testing.T) {
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: true,
					Config: &secflowv1.MCPConnectionConfig{
						Name:         "GitHub Issues",
						EndpointUrl:  extMCP.URL,
						AllowedTools: []string{"create_issue"},
					},
				}, nil
			},
		}
		res := b.callTool(t.Context(), makeTask("conn_1", "delete_repo"))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "TOOL_NOT_ALLOWED" {
			t.Fatalf("got status=%v code=%q, want FAILED/TOOL_NOT_ALLOWED", res.GetStatus(), res.GetErrorCode())
		}
	})

	t.Run("deniedTools blocks denied tool even when listed in allowedTools", func(t *testing.T) {
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: true,
					Config: &secflowv1.MCPConnectionConfig{
						Name:         "GitHub Issues",
						EndpointUrl:  extMCP.URL,
						AllowedTools: []string{"create_issue", "delete_repo"},
						DeniedTools:  []string{"delete_*"},
					},
				}, nil
			},
		}
		res := b.callTool(t.Context(), makeTask("conn_1", "delete_repo"))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "TOOL_DENIED" {
			t.Fatalf("got status=%v code=%q, want FAILED/TOOL_DENIED", res.GetStatus(), res.GetErrorCode())
		}
	})

	t.Run("secret resolution failure fails closed", func(t *testing.T) {
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: true,
					Config: &secflowv1.MCPConnectionConfig{
						Name:          "GitHub Issues",
						EndpointUrl:   extMCP.URL,
						AuthSecretRef: "sec_missing",
					},
				}, nil
			},
			resolveNodeSecret: func(_ context.Context, _ *secflowv1.NodeTask, _ string) (string, error) {
				return "", errors.New("SECRET_SCOPE_DENIED")
			},
		}
		res := b.callTool(t.Context(), makeTask("conn_1", "create_issue"))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "SECRET_SCOPE_DENIED" {
			t.Fatalf("got status=%v code=%q, want FAILED/SECRET_SCOPE_DENIED", res.GetStatus(), res.GetErrorCode())
		}
	})

	t.Run("custom AuthHeaderName sends raw value without Bearer, redacts response, and defaults outputVarKey", func(t *testing.T) {
		gotAuthHeader = ""
		gotCustomHeader = ""
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: true,
					Config: &secflowv1.MCPConnectionConfig{
						Name:           "Jira MCP",
						EndpointUrl:    extMCP.URL,
						AuthSecretRef:  "sec_api_key",
						AuthHeaderName: "X-API-Key",
						AllowedTools:   []string{"create_issue"},
					},
				}, nil
			},
			resolveNodeSecret: func(_ context.Context, _ *secflowv1.NodeTask, ref string) (string, error) {
				if ref != "sec_api_key" {
					t.Fatalf("unexpected secretRef %q", ref)
				}
				return "secret-raw-val", nil
			},
		}
		res := b.callTool(t.Context(), makeTask("conn_1", "create_issue"))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			t.Fatalf("got status=%v err=%s/%s, want SUCCEEDED", res.GetStatus(), res.GetErrorCode(), res.GetErrorMessage())
		}
		if gotCustomHeader != "secret-raw-val" {
			t.Fatalf("X-API-Key = %q, want %q", gotCustomHeader, "secret-raw-val")
		}
		if gotAuthHeader != "" {
			t.Fatalf("Authorization header should be empty for custom header, got %q", gotAuthHeader)
		}
		if gotMethod != "tools/call" || gotToolName != "create_issue" {
			t.Fatalf("got method=%q tool=%q", gotMethod, gotToolName)
		}
		if strings.Contains(string(res.GetEnvelopePatchJson()), "secret-raw-val") {
			t.Fatalf("secret leaked in response: %s", string(res.GetEnvelopePatchJson()))
		}
		var patch mcpEnvelopePatch
		if err := json.Unmarshal(res.GetEnvelopePatchJson(), &patch); err != nil {
			t.Fatalf("unmarshal patch: %v", err)
		}
		val, ok := patch.Vars["mcpToolResult"]
		if !ok || !strings.Contains(val, "[REDACTED]") {
			t.Fatalf("expected redacted result in vars[mcpToolResult], got %+v", patch.Vars)
		}
	})

	t.Run("honors custom outputVarKey and ignores __secflow_action on normal tasks", func(t *testing.T) {
		gotMethod = ""
		gotToolName = ""
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: true,
					Config: &secflowv1.MCPConnectionConfig{
						Name:        "Jira MCP",
						EndpointUrl: extMCP.URL,
					},
				}, nil
			},
		}
		raw, _ := json.Marshal(map[string]any{
			"__secflow_action": "discover",
			"connectionId":     "conn_1",
			"toolName":         "create_issue",
			"outputVarKey":     "jiraTicketResponse",
			"arguments":        map[string]any{"title": "Security Alert"},
		})
		res := b.callTool(t.Context(), &secflowv1.NodeTask{
			RunId:      "run_normal",
			NodeRunId:  "nr_normal",
			NodeId:     "n_mcp_1",
			PluginId:   "mcp.tool",
			ParamsJson: raw,
		})
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			t.Fatalf("got status=%v err=%s/%s, want SUCCEEDED", res.GetStatus(), res.GetErrorCode(), res.GetErrorMessage())
		}
		if gotMethod != "tools/call" || gotToolName != "create_issue" {
			t.Fatalf("normal task should invoke tools/call and ignore __secflow_action, got method=%q tool=%q", gotMethod, gotToolName)
		}
		var patch mcpEnvelopePatch
		if err := json.Unmarshal(res.GetEnvelopePatchJson(), &patch); err != nil {
			t.Fatalf("unmarshal patch: %v", err)
		}
		if _, hasDefault := patch.Vars["mcpToolResult"]; hasDefault {
			t.Fatalf("expected custom key only, got default key in %+v", patch.Vars)
		}
		if got := patch.Vars["jiraTicketResponse"]; !strings.Contains(got, `"ok":true`) {
			t.Fatalf("vars[jiraTicketResponse] = %q, want tool call JSON", got)
		}
	})

	t.Run("default Authorization header prefixes Bearer only when token has no space", func(t *testing.T) {
		gotAuthHeader = ""
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: true,
					Config: &secflowv1.MCPConnectionConfig{
						Name:          "GitHub MCP",
						EndpointUrl:   extMCP.URL,
						AuthSecretRef: "sec_tok",
					},
				}, nil
			},
			resolveNodeSecret: func(_ context.Context, _ *secflowv1.NodeTask, _ string) (string, error) {
				return "tok_abc123", nil
			},
		}
		res := b.callTool(t.Context(), makeTask("conn_1", "create_issue"))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			t.Fatalf("got status=%v err=%s", res.GetStatus(), res.GetErrorMessage())
		}
		if gotAuthHeader != "Bearer tok_abc123" {
			t.Fatalf("Authorization = %q, want %q", gotAuthHeader, "Bearer tok_abc123")
		}
	})

	t.Run("all 13 prohibited scanners blocked in toolName or endpoint", func(t *testing.T) {
		scanners := []string{
			"semgrep", "gitleaks", "trivy", "detekt", "osv-scanner", "osv_scanner",
			"grype", "syft", "snyk", "bandit", "sonarqube", "checkmarx", "codeql", "trufflehog",
		}
		b := &bridge{
			httpClient: extMCP.Client(),
			fetchConnection: func(_ context.Context, _ string) (*secflowv1.MCPConnection, error) {
				return &secflowv1.MCPConnection{
					Id:      "conn_1",
					Enabled: true,
					Config:  &secflowv1.MCPConnectionConfig{Name: "Safe", EndpointUrl: extMCP.URL},
				}, nil
			},
		}
		for _, sc := range scanners {
			t.Run(sc, func(t *testing.T) {
				res := b.callTool(t.Context(), makeTask("conn_1", "run_"+sc))
				if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "DENYLIST_BLOCKED" {
					t.Fatalf("scanner %q: got status=%v code=%q, want FAILED/DENYLIST_BLOCKED", sc, res.GetStatus(), res.GetErrorCode())
				}
			})
		}
	})
}

func TestDiscoverPullGRPCBoundary(t *testing.T) {
	var gotHeader string
	extMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-MCP-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"jsonrpc": "2.0",
			"id": 1,
			"result": {
				"serverInfo": {"name": "tracker-mcp", "version": "1.2.0"},
				"tools": [
					{"name": "create_issue", "description": "Create issue", "inputSchema": {"type":"object","properties":{"title":{"type":"string"}}}},
					{"name": "delete_issue", "description": "Delete issue", "inputSchema": {"type":"object"}},
					{"name": "list_projects", "description": "List projects", "inputSchema": {"type":"object"}},
					{"name": "run_trufflehog", "description": "Scan secrets", "inputSchema": {"type":"object"}},
					{"name": "audit_helper", "description": "Runs osv_scanner under the hood", "inputSchema": {"type":"object"}}
				]
			}
		}`))
	}))
	defer extMCP.Close()

	b := &bridge{
		httpClient:   extMCP.Client(),
		serviceToken: "svc-secret",
		resolveDiscSecret: func(_ context.Context, connID, ref string) (string, error) {
			if connID != "mcp_1" || ref != "sec_mcp" {
				return "", errors.New("unexpected scope")
			}
			return "raw-mcp-token", nil
		},
	}

	makeDiscoverTask := func(params map[string]any) *secflowv1.NodeTask {
		params["__secflow_action"] = "discover"
		raw, _ := json.Marshal(params)
		return &secflowv1.NodeTask{
			RunId:      mcpDiscoverRunID,
			NodeRunId:  "nr_disc_1",
			NodeId:     mcpDiscoverNodeID,
			PluginId:   "mcp.tool",
			ParamsJson: raw,
		}
	}

	t.Run("discovers tools over Pull gRPC with custom header, 13-scanner filter, and allow/deny policy", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		gotHeader = ""
		res := b.callTool(t.Context(), makeDiscoverTask(map[string]any{
			"connectionId":   "mcp_1",
			"name":           "Tracker",
			"endpointUrl":    extMCP.URL,
			"authSecretRef":  "sec_mcp",
			"authHeaderName": "X-MCP-Key",
			"allowedTools":   []string{"create_issue", "delete_issue", "run_trufflehog"},
			"deniedTools":    []string{"delete_issue"},
		}))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			t.Fatalf("status=%v err=%s/%s body=%s", res.GetStatus(), res.GetErrorCode(), res.GetErrorMessage(), string(res.GetEnvelopePatchJson()))
		}
		if gotHeader != "raw-mcp-token" {
			t.Fatalf("X-MCP-Key = %q, want %q", gotHeader, "raw-mcp-token")
		}
		var out discoverResponse
		if err := json.Unmarshal(res.GetEnvelopePatchJson(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out.Tools) != 1 || out.Tools[0].Name != "create_issue" {
			t.Fatalf("got tools=%+v, want only [create_issue]", out.Tools)
		}
		// Blocked: delete_issue (denied), list_projects (not allowed), run_trufflehog (denylist), audit_helper (denylist in description) = 4
		if out.BlockedToolCount != 4 {
			t.Fatalf("blockedToolCount = %d, want 4", out.BlockedToolCount)
		}
		if out.ServerName != "tracker-mcp" || out.ServerVersion != "1.2.0" {
			t.Fatalf("serverInfo = %s/%s", out.ServerName, out.ServerVersion)
		}
	})

	t.Run("returns DENYLIST_BLOCKED for forbidden scanner connection", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		res := b.callTool(t.Context(), makeDiscoverTask(map[string]any{
			"connectionId": "mcp_deny",
			"name":         "Semgrep Wrapper",
			"endpointUrl":  extMCP.URL,
		}))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "DENYLIST_BLOCKED" {
			t.Fatalf("got status=%v code=%q, want FAILED/DENYLIST_BLOCKED", res.GetStatus(), res.GetErrorCode())
		}
		var out discoverResponse
		if err := json.Unmarshal(res.GetEnvelopePatchJson(), &out); err != nil || out.Code != "DENYLIST_BLOCKED" {
			t.Fatalf("patch=%s err=%v, want code=DENYLIST_BLOCKED", string(res.GetEnvelopePatchJson()), err)
		}
	})

	t.Run("returns ALLOWLIST_DENIED for private SSRF endpoint when private disabled", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		res := b.callTool(t.Context(), makeDiscoverTask(map[string]any{
			"connectionId": "mcp_ssrf",
			"name":         "Internal",
			"endpointUrl":  "http://169.254.169.254/latest/meta-data",
		}))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "ALLOWLIST_DENIED" {
			t.Fatalf("got status=%v code=%q, want FAILED/ALLOWLIST_DENIED", res.GetStatus(), res.GetErrorCode())
		}
		var out discoverResponse
		if err := json.Unmarshal(res.GetEnvelopePatchJson(), &out); err != nil || out.Code != "ALLOWLIST_DENIED" {
			t.Fatalf("patch=%s err=%v, want code=ALLOWLIST_DENIED", string(res.GetEnvelopePatchJson()), err)
		}
	})

	t.Run("fails closed with SECRET_SCOPE_DENIED when discovery secret resolution fails", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		res := b.callTool(t.Context(), makeDiscoverTask(map[string]any{
			"connectionId":  "mcp_1",
			"name":          "Tracker",
			"endpointUrl":   extMCP.URL,
			"authSecretRef": "sec_other",
		}))
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED || res.GetErrorCode() != "SECRET_SCOPE_DENIED" {
			t.Fatalf("got status=%v code=%q, want FAILED/SECRET_SCOPE_DENIED", res.GetStatus(), res.GetErrorCode())
		}
		var out discoverResponse
		if err := json.Unmarshal(res.GetEnvelopePatchJson(), &out); err != nil || out.Code != "SECRET_SCOPE_DENIED" {
			t.Fatalf("patch=%s err=%v, want code=SECRET_SCOPE_DENIED", string(res.GetEnvelopePatchJson()), err)
		}
	})
}

func TestMCPToolManifest_RichMetadata(t *testing.T) {
	m := mcpToolManifest()
	if m.GetPluginId() != "mcp.tool" {
		t.Fatalf("PluginId = %q, want mcp.tool", m.GetPluginId())
	}
	if strings.TrimSpace(m.GetDescription()) == "" {
		t.Fatal("Description must be non-empty")
	}
	if m.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
		t.Fatalf("SandboxProfile = %v, want EGRESS_EXTERNAL", m.GetSandboxProfile())
	}
	if m.GetCategory() != secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION {
		t.Fatalf("Category = %v, want ACTION", m.GetCategory())
	}
	if !slices.Contains(m.GetCapabilities(), "mcp") {
		t.Fatalf("Capabilities = %v, want mcp", m.GetCapabilities())
	}
}
