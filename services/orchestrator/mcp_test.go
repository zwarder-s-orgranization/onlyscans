package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

func TestMCPConnectionValidation_DenylistAndSSRF(t *testing.T) {
	srv := newServer()

	t.Run("RegisterConnection blocks all 13 scanners across endpoint, name, and description", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		scanners := []string{
			"semgrep", "gitleaks", "trivy", "detekt", "osv-scanner", "osv_scanner",
			"grype", "syft", "snyk", "bandit", "sonarqube", "checkmarx", "codeql", "trufflehog",
		}
		for _, sc := range scanners {
			t.Run("endpoint/"+sc, func(t *testing.T) {
				_, err := srv.RegisterConnection(t.Context(), &secflowv1.RegisterConnectionRequest{
					Config: &secflowv1.MCPConnectionConfig{
						Name:        "Safe Name",
						EndpointUrl: "https://mcp.example.com/" + sc,
					},
				})
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "DENYLIST_BLOCKED") {
					t.Fatalf("endpoint %q: got err=%v, want FailedPrecondition/DENYLIST_BLOCKED", sc, err)
				}
			})
			t.Run("name/"+sc, func(t *testing.T) {
				_, err := srv.RegisterConnection(t.Context(), &secflowv1.RegisterConnectionRequest{
					Config: &secflowv1.MCPConnectionConfig{
						Name:        "My " + strings.ToUpper(sc) + " Server",
						EndpointUrl: "https://mcp.example.com/v1",
					},
				})
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "DENYLIST_BLOCKED") {
					t.Fatalf("name %q: got err=%v, want FailedPrecondition/DENYLIST_BLOCKED", sc, err)
				}
			})
			t.Run("description/"+sc, func(t *testing.T) {
				_, err := srv.RegisterConnection(t.Context(), &secflowv1.RegisterConnectionRequest{
					Config: &secflowv1.MCPConnectionConfig{
						Name:        "Custom Tool",
						Description: "Wrapper around " + sc + " CLI",
						EndpointUrl: "https://mcp.example.com/v1",
					},
				})
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "DENYLIST_BLOCKED") {
					t.Fatalf("description %q: got err=%v, want FailedPrecondition/DENYLIST_BLOCKED", sc, err)
				}
			})
		}
	})

	t.Run("RegisterConnection blocks SSRF targets when MCP_ALLOW_PRIVATE is unset", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		for _, rawURL := range []string{
			"http://127.0.0.1:8080/mcp",
			"http://169.254.169.254/latest/meta-data",
			"http://10.0.0.2/mcp",
			"http://localhost:9090/mcp",
			"file:///etc/passwd",
		} {
			_, err := srv.RegisterConnection(t.Context(), &secflowv1.RegisterConnectionRequest{
				Config: &secflowv1.MCPConnectionConfig{
					Name:        "Internal",
					EndpointUrl: rawURL,
				},
			})
			if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "ALLOWLIST_DENIED") {
				t.Fatalf("url %q: got err=%v, want PermissionDenied/ALLOWLIST_DENIED", rawURL, err)
			}
		}
	})

	t.Run("UpdateConnection enforces denylist and SSRF without mutating existing connection", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		reg, err := srv.RegisterConnection(t.Context(), &secflowv1.RegisterConnectionRequest{
			Actor: &secflowv1.ActorContext{Subject: "owner@secflow.local"},
			Config: &secflowv1.MCPConnectionConfig{
				Name:        "GitHub Issues",
				Description: "Issue tracker",
				EndpointUrl: "http://127.0.0.1:9999/mcp",
			},
		})
		if err != nil {
			t.Fatalf("register valid connection: %v", err)
		}
		connID := reg.GetConnection().GetId()

		// Denylist in description rejected on UpdateConnection.
		_, err = srv.UpdateConnection(t.Context(), &secflowv1.UpdateConnectionRequest{
			ConnectionId: connID,
			Enabled:      true,
			Config: &secflowv1.MCPConnectionConfig{
				Name:        "GitHub Issues",
				Description: "Now invokes trufflehog",
				EndpointUrl: "http://127.0.0.1:9999/mcp",
			},
		})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "DENYLIST_BLOCKED") {
			t.Fatalf("update denylist err=%v, want FailedPrecondition/DENYLIST_BLOCKED", err)
		}

		// SSRF rejected on UpdateConnection when private disallowed.
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		_, err = srv.UpdateConnection(t.Context(), &secflowv1.UpdateConnectionRequest{
			ConnectionId: connID,
			Enabled:      true,
			Config: &secflowv1.MCPConnectionConfig{
				Name:        "GitHub Issues",
				EndpointUrl: "http://169.254.169.254/latest/meta-data",
			},
		})
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "ALLOWLIST_DENIED") {
			t.Fatalf("update ssrf err=%v, want PermissionDenied/ALLOWLIST_DENIED", err)
		}

		// Valid update and delete succeed.
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		upd, err := srv.UpdateConnection(t.Context(), &secflowv1.UpdateConnectionRequest{
			ConnectionId: connID,
			Enabled:      false,
			Config: &secflowv1.MCPConnectionConfig{
				Name:           "GitHub Issues Updated",
				EndpointUrl:    "http://127.0.0.1:9999/mcp",
				AuthHeaderName: "X-API-Key",
			},
		})
		if err != nil {
			t.Fatalf("valid update failed: %v", err)
		}
		if upd.GetConnection().GetEnabled() || upd.GetConnection().GetConfig().GetName() != "GitHub Issues Updated" {
			t.Fatalf("unexpected updated connection: %+v", upd.GetConnection())
		}

		delResp, err := srv.DeleteConnection(t.Context(), &secflowv1.DeleteConnectionRequest{ConnectionId: connID})
		if err != nil || !delResp.GetDeleted() {
			t.Fatalf("delete connection failed: resp=%+v err=%v", delResp, err)
		}
		if _, err := srv.GetConnection(t.Context(), &secflowv1.GetConnectionRequest{ConnectionId: connID}); status.Code(err) != codes.NotFound {
			t.Fatalf("expected NotFound after delete, got %v", err)
		}
	})
}

func TestMCPDiscovery_AuthHeaderAllowDenyAndBridgeRouting(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")
	t.Setenv("MCP_BRIDGE_ADDR", "")

	var gotAPIKey string
	var gotAuth string
	extMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"jsonrpc": "2.0",
			"id": 1,
			"result": {
				"serverInfo": {"name": "jira-mcp", "version": "2.0.0"},
				"tools": [
					{"name": "create_ticket", "description": "Create Jira ticket", "inputSchema": {"type":"object","properties":{"summary":{"type":"string"}}}},
					{"name": "delete_ticket", "description": "Delete Jira ticket", "inputSchema": {"type":"object"}},
					{"name": "list_boards", "description": "List boards", "inputSchema": {"type":"object"}},
					{"name": "codeql_scan", "description": "Run CodeQL", "inputSchema": {"type":"object"}},
					{"name": "helper", "description": "Delegates to Checkmarx scanner", "inputSchema": {"type":"object"}}
				]
			}
		}`))
	}))
	defer extMCP.Close()

	srv := newServer()
	secResp, err := srv.CreateSecret(t.Context(), &secflowv1.CreateSecretRequest{
		Actor:          &secflowv1.ActorContext{Subject: "owner"},
		Name:           "jira-api-key",
		Kind:           secflowv1.SecretKind_SECRET_KIND_MCP_AUTH_HEADER,
		PlaintextValue: "jira-secret-999",
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	secretRef := secResp.GetSecret().GetSecretRef()

	reg, err := srv.RegisterConnection(t.Context(), &secflowv1.RegisterConnectionRequest{
		Config: &secflowv1.MCPConnectionConfig{
			Name:           "Jira",
			EndpointUrl:    extMCP.URL,
			AuthSecretRef:  secretRef,
			AuthHeaderName: "X-API-Key",
			AllowedTools:   []string{"create_ticket", "delete_ticket"},
			DeniedTools:    []string{"delete_*"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterConnection: %v", err)
	}
	connID := reg.GetConnection().GetId()

	t.Run("local discovery resolves scoped secret, uses custom AuthHeaderName, and enforces filters", func(t *testing.T) {
		resp, err := srv.ListConnectionTools(t.Context(), &secflowv1.ListConnectionToolsRequest{ConnectionId: connID})
		if err != nil {
			t.Fatalf("ListConnectionTools: %v", err)
		}
		if gotAPIKey != "jira-secret-999" {
			t.Fatalf("X-API-Key = %q, want %q", gotAPIKey, "jira-secret-999")
		}
		if gotAuth != "" {
			t.Fatalf("Authorization should be empty for X-API-Key, got %q", gotAuth)
		}
		if len(resp.GetTools()) != 1 || resp.GetTools()[0].GetName() != "create_ticket" {
			t.Fatalf("tools = %+v, want [create_ticket]", resp.GetTools())
		}
		// Blocked: delete_ticket (denied), list_boards (not in allowlist), codeql_scan (denylist), helper (checkmarx in desc) = 4
		if resp.GetBlockedToolCount() != 4 {
			t.Fatalf("blocked_tool_count = %d, want 4", resp.GetBlockedToolCount())
		}

		testResp, err := srv.TestConnection(t.Context(), &secflowv1.TestConnectionRequest{ConnectionId: connID})
		if err != nil || !testResp.GetOk() || testResp.GetServerName() != "jira-mcp" || testResp.GetAvailableToolCount() != 1 || testResp.GetBlockedToolCount() != 4 {
			t.Fatalf("TestConnection = (%+v, %v)", testResp, err)
		}
	})

	t.Run("routes discovery over Pull gRPC WorkerService stream when mcp.tool worker is connected", func(t *testing.T) {
		var bridgeReq bridgeDiscoverRequest
		registerFakeWorker(srv, "mcp.tool", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
			_ = json.Unmarshal(task.GetParamsJson(), &bridgeReq)
			return &secflowv1.NodeResult{
				NodeRunId: task.GetNodeRunId(),
				RunId:     task.GetRunId(),
				NodeId:    task.GetNodeId(),
				PluginId:  "mcp.tool",
				Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
				EnvelopePatchJson: []byte(`{
					"tools": [
						{"name": "create_ticket", "description": "Create Jira ticket", "inputSchema": {"type":"object"}},
						{"name": "sneaky_snyk", "description": "Should still be filtered by orchestrator", "inputSchema": {"type":"object"}}
					],
					"blockedToolCount": 3,
					"serverName": "bridge-jira",
					"serverVersion": "3.0.0"
				}`),
			}
		})
		defer func() {
			srv.plugMu.Lock()
			delete(srv.workers, "mcp.tool")
			srv.plugMu.Unlock()
		}()

		resp, err := srv.ListConnectionTools(t.Context(), &secflowv1.ListConnectionToolsRequest{ConnectionId: connID})
		if err != nil {
			t.Fatalf("ListConnectionTools via gRPC worker: %v", err)
		}
		if bridgeReq.Action != "discover" {
			t.Fatalf("bridge action = %q, want discover", bridgeReq.Action)
		}
		if bridgeReq.ConnectionID != connID || bridgeReq.AuthSecretRef != secretRef || bridgeReq.AuthHeaderName != "X-API-Key" {
			t.Fatalf("unexpected bridge request: %+v", bridgeReq)
		}
		if len(resp.GetTools()) != 1 || resp.GetTools()[0].GetName() != "create_ticket" {
			t.Fatalf("tools via worker = %+v, want [create_ticket]", resp.GetTools())
		}
		// 3 from bridge + 1 sneaky_snyk filtered in orchestrator defense-in-depth = 4
		if resp.GetBlockedToolCount() != 4 {
			t.Fatalf("blocked_tool_count = %d, want 4", resp.GetBlockedToolCount())
		}
	})
}
