package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/lease"
	"github.com/secflow/secflow/services/internal/secretbox"
)

func TestIssueAndVerifyScopedToken(t *testing.T) {
	ctx := t.Context()
	s := newServer()

	// Issue two tokens and verify randomness (never derived from TokenId).
	t1, err := s.IssueScopedToken(ctx, &secflowv1.IssueScopedTokenRequest{
		Name:       "ci-1",
		Scopes:     []string{"ci:startRun", "ci:readRun"},
		WorkflowId: "wf_1",
		ExpiresAt:  timestamppb.New(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("IssueScopedToken #1: %v", err)
	}
	t2, err := s.IssueScopedToken(ctx, &secflowv1.IssueScopedTokenRequest{
		Name:       "ci-2",
		Scopes:     []string{"ci:startRun"},
		WorkflowId: "wf_1",
	})
	if err != nil {
		t.Fatalf("IssueScopedToken #2: %v", err)
	}
	if strings.Contains(t1.GetPlaintextToken(), t1.GetMetadata().GetTokenId()) {
		t.Fatalf("plaintext token must not derive from tokenId: %q contains %q", t1.GetPlaintextToken(), t1.GetMetadata().GetTokenId())
	}
	if t1.GetPlaintextToken() == t2.GetPlaintextToken() {
		t.Fatal("two issued scoped tokens must differ")
	}
	// Prefix + 64 hex chars (32 random bytes).
	trimmed := strings.TrimPrefix(t1.GetPlaintextToken(), t1.GetMetadata().GetTokenPrefix())
	if len(trimmed) != 64 {
		t.Fatalf("random token hex length = %d, want 64", len(trimmed))
	}

	// Valid non-expired token verifies and returns workflow scope.
	ver, err := s.VerifyScopedToken(ctx, &secflowv1.VerifyScopedTokenRequest{PlaintextToken: t1.GetPlaintextToken()})
	if err != nil || !ver.GetValid() {
		t.Fatalf("VerifyScopedToken valid = (%v, %v)", ver, err)
	}
	if ver.GetActor().GetScopedWorkflowId() != "wf_1" {
		t.Fatalf("scopedWorkflowId = %q, want wf_1", ver.GetActor().GetScopedWorkflowId())
	}

	// Revoked token is rejected.
	if _, err := s.RevokeScopedToken(ctx, &secflowv1.RevokeScopedTokenRequest{TokenId: t1.GetMetadata().GetTokenId()}); err != nil {
		t.Fatalf("RevokeScopedToken: %v", err)
	}
	verRevoked, err := s.VerifyScopedToken(ctx, &secflowv1.VerifyScopedTokenRequest{PlaintextToken: t1.GetPlaintextToken()})
	if err != nil || verRevoked.GetValid() {
		t.Fatalf("revoked token should be invalid: %+v, %v", verRevoked, err)
	}

	// Expired token is rejected.
	expired, err := s.IssueScopedToken(ctx, &secflowv1.IssueScopedTokenRequest{
		Name:      "expired",
		Scopes:    []string{"mcp:read"},
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
	})
	if err != nil {
		t.Fatalf("IssueScopedToken expired: %v", err)
	}
	verExpired, err := s.VerifyScopedToken(ctx, &secflowv1.VerifyScopedTokenRequest{PlaintextToken: expired.GetPlaintextToken()})
	if err != nil || verExpired.GetValid() {
		t.Fatalf("expired token should be invalid: %+v, %v", verExpired, err)
	}
}

func TestResolveScopedSecret_LeastPrivilegeScopes(t *testing.T) {
	ctx := t.Context()
	s := newServer()

	createSec := func(name, val string, kind secflowv1.SecretKind) string {
		t.Helper()
		resp, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{Name: name, Kind: kind, PlaintextValue: val})
		if err != nil {
			t.Fatalf("CreateSecret(%s): %v", name, err)
		}
		return resp.GetSecret().GetSecretRef()
	}

	whRef := createSec("wh", "whsec_real", secflowv1.SecretKind_SECRET_KIND_GIT_WEBHOOK_SECRET)
	gitStatusRef := createSec("gs", "ghp_status_real", secflowv1.SecretKind_SECRET_KIND_GIT_TOKEN)
	botRef := createSec("tg", "123:bot-token", secflowv1.SecretKind_SECRET_KIND_TELEGRAM_BOT_TOKEN)
	otherRef := createSec("other", "other-secret", secflowv1.SecretKind_SECRET_KIND_GENERIC)

	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Webhook Flow",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{
					Id:         "trig_wh",
					PluginId:   "trigger.webhook",
					ParamsJson: []byte(`{"gitProvider":"GITHUB"}`),
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "webhookSecret", SecretRef: whRef},
						{ParamKey: "gitStatusToken", SecretRef: gitStatusRef},
					},
				},
				{
					Id:             "notify_tg",
					PluginId:       "notify.telegram",
					ParamsJson:     []byte(`{"chatId":"100"}`),
					SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "botToken", SecretRef: botRef}},
				},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "trig_wh", SourceHandle: "default", TargetNodeId: "notify_tg", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	wfID := wfResp.GetWorkflow().GetId()
	s.runs["run_match"] = &runState{run: &secflowv1.Run{Id: "run_match", WorkflowId: wfID}}
	s.runs["run_other_wf"] = &runState{run: &secflowv1.Run{Id: "run_other_wf", WorkflowId: "wf_different"}}

	validLease, err := lease.Sign(s.leaseKey, "run_match", "nr_1", "notify_tg", "notify.telegram", time.Minute)
	if err != nil {
		t.Fatalf("lease.Sign valid: %v", err)
	}
	scanLease, err := lease.Sign(s.leaseKey, "run_match", "nr_2", "notify_tg", "scan.secrets", time.Minute)
	if err != nil {
		t.Fatalf("lease.Sign scan: %v", err)
	}

	tests := []struct {
		name      string
		req       *secflowv1.ResolveScopedSecretRequest
		wantPlain string
		wantCode  codes.Code
	}{
		{
			name: "webhook scope valid trigger_node_id",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef:    whRef,
				ServiceToken: s.serviceTK,
				Scope: &secflowv1.ResolveScopedSecretRequest_WorkflowWebhook{
					WorkflowWebhook: &secflowv1.WorkflowWebhookSecretScope{WorkflowId: wfID, TriggerNodeId: "trig_wh"},
				},
			},
			wantPlain: "whsec_real",
		},
		{
			name: "webhook scope rejects empty trigger_node_id",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef:    whRef,
				ServiceToken: s.serviceTK,
				Scope: &secflowv1.ResolveScopedSecretRequest_WorkflowWebhook{
					WorkflowWebhook: &secflowv1.WorkflowWebhookSecretScope{WorkflowId: wfID, TriggerNodeId: ""},
				},
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "webhook scope rejects wrong trigger_node_id",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef:    whRef,
				ServiceToken: s.serviceTK,
				Scope: &secflowv1.ResolveScopedSecretRequest_WorkflowWebhook{
					WorkflowWebhook: &secflowv1.WorkflowWebhookSecretScope{WorkflowId: wfID, TriggerNodeId: "wrong_node"},
				},
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "webhook scope rejects wrong service token",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef:    whRef,
				ServiceToken: "bad-service-token",
				Scope: &secflowv1.ResolveScopedSecretRequest_WorkflowWebhook{
					WorkflowWebhook: &secflowv1.WorkflowWebhookSecretScope{WorkflowId: wfID, TriggerNodeId: "trig_wh"},
				},
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "commit status scope valid run and trigger_node_id",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef:    gitStatusRef,
				ServiceToken: s.serviceTK,
				Scope: &secflowv1.ResolveScopedSecretRequest_CommitStatus{
					CommitStatus: &secflowv1.CommitStatusSecretScope{RunId: "run_match", WorkflowId: wfID, TriggerNodeId: "trig_wh"},
				},
			},
			wantPlain: "ghp_status_real",
		},
		{
			name: "commit status scope rejects run from other workflow",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef:    gitStatusRef,
				ServiceToken: s.serviceTK,
				Scope: &secflowv1.ResolveScopedSecretRequest_CommitStatus{
					CommitStatus: &secflowv1.CommitStatusSecretScope{RunId: "run_other_wf", WorkflowId: wfID, TriggerNodeId: "trig_wh"},
				},
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "commit status scope rejects empty trigger_node_id",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef:    gitStatusRef,
				ServiceToken: s.serviceTK,
				Scope: &secflowv1.ResolveScopedSecretRequest_CommitStatus{
					CommitStatus: &secflowv1.CommitStatusSecretScope{RunId: "run_match", WorkflowId: wfID, TriggerNodeId: ""},
				},
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "node task scope valid leased notify node",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef: botRef,
				Scope: &secflowv1.ResolveScopedSecretRequest_NodeTask{
					NodeTask: &secflowv1.NodeTaskSecretScope{
						RunId: "run_match", NodeRunId: "nr_1", NodeId: "notify_tg", PluginId: "notify.telegram", TaskLeaseToken: validLease,
					},
				},
			},
			wantPlain: "123:bot-token",
		},
		{
			name: "node task scope denies analyzer plugin even with lease",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef: botRef,
				Scope: &secflowv1.ResolveScopedSecretRequest_NodeTask{
					NodeTask: &secflowv1.NodeTaskSecretScope{
						RunId: "run_match", NodeRunId: "nr_2", NodeId: "notify_tg", PluginId: "scan.secrets", TaskLeaseToken: scanLease,
					},
				},
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "node task scope denies unbound secret",
			req: &secflowv1.ResolveScopedSecretRequest{
				SecretRef: otherRef,
				Scope: &secflowv1.ResolveScopedSecretRequest_NodeTask{
					NodeTask: &secflowv1.NodeTaskSecretScope{
						RunId: "run_match", NodeRunId: "nr_1", NodeId: "notify_tg", PluginId: "notify.telegram", TaskLeaseToken: validLease,
					},
				},
			},
			wantCode: codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := s.ResolveScopedSecret(ctx, tt.req)
			if tt.wantCode != codes.OK {
				if status.Code(err) != tt.wantCode {
					t.Fatalf("ResolveScopedSecret err = %v, want code %v", err, tt.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveScopedSecret unexpected err = %v", err)
			}
			if resp.GetPlaintextValue() != tt.wantPlain {
				t.Fatalf("PlaintextValue = %q, want %q", resp.GetPlaintextValue(), tt.wantPlain)
			}
		})
	}
}

func TestRejectInlineSecretsInWorkflowParams(t *testing.T) {
	ctx := t.Context()
	s := newServer()

	badGraph := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
			{Id: "ai", PluginId: "ai.explain", ParamsJson: []byte(`{"baseUrl":"https://api.openai.com/v1","apiKey":"sk-plaintext"}`)},
		},
		Edges: []*secflowv1.WorkflowEdge{{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "ai", TargetHandle: "default"}},
	}
	if _, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{Name: "Bad", Graph: badGraph}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CreateWorkflow with inline secret err = %v, want InvalidArgument", err)
	}

	goodGraph := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
			{Id: "tg", PluginId: "notify.telegram", ParamsJson: []byte(`{"chatId":"100"}`), SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "botToken", SecretRef: "sec_1"}}},
		},
		Edges: []*secflowv1.WorkflowEdge{{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "tg", TargetHandle: "default"}},
	}
	created, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{Name: "Good", Graph: goodGraph})
	if err != nil {
		t.Fatalf("CreateWorkflow clean graph: %v", err)
	}

	badUpdate := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
			{Id: "tg", PluginId: "notify.telegram", ParamsJson: []byte(`{"chatId":"100","botToken":"123:inline"}`)},
		},
	}
	if _, err := s.UpdateWorkflow(ctx, &secflowv1.UpdateWorkflowRequest{WorkflowId: created.GetWorkflow().GetId(), Name: "Good", Graph: badUpdate}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("UpdateWorkflow with inline secret err = %v, want InvalidArgument", err)
	}
}

func TestSecretService_VaultBackendMetadataAndResolve(t *testing.T) {
	var (
		mu      sync.Mutex
		storage = map[string]string{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "vault-tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/secret/data/secflow/") {
			ref := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/secflow/")
			var req struct {
				Data map[string]string `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			storage[ref] = req.Data["value"]
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/secflow/") {
			ref := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/secflow/")
			mu.Lock()
			val, ok := storage[ref]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]string{"value": val}},
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	vaultStore, err := secretbox.NewVaultStore(secretbox.VaultConfig{Addr: srv.URL, Token: "vault-tok", Mount: "secret"})
	if err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}

	ctx := t.Context()
	s := newServer()
	s.setSecretStore(vaultStore)

	created, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Name:           "vault-wh",
		Kind:           secflowv1.SecretKind_SECRET_KIND_GIT_WEBHOOK_SECRET,
		PlaintextValue: "vault-webhook-secret",
	})
	if err != nil {
		t.Fatalf("CreateSecret vault: %v", err)
	}
	if created.GetSecret().GetBackend() != secflowv1.SecretStoreBackend_SECRET_STORE_BACKEND_VAULT {
		t.Fatalf("Backend = %v, want VAULT", created.GetSecret().GetBackend())
	}

	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Vault WF",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{
					Id:             "trig",
					PluginId:       "trigger.webhook",
					ParamsJson:     []byte(`{"gitProvider":"GITHUB"}`),
					SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "webhookSecret", SecretRef: created.GetSecret().GetSecretRef()}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	resolved, err := s.ResolveScopedSecret(ctx, &secflowv1.ResolveScopedSecretRequest{
		SecretRef:    created.GetSecret().GetSecretRef(),
		ServiceToken: s.serviceTK,
		Scope: &secflowv1.ResolveScopedSecretRequest_WorkflowWebhook{
			WorkflowWebhook: &secflowv1.WorkflowWebhookSecretScope{
				WorkflowId:    wfResp.GetWorkflow().GetId(),
				TriggerNodeId: "trig",
			},
		},
	})
	if err != nil {
		t.Fatalf("ResolveScopedSecret vault: %v", err)
	}
	if resolved.GetPlaintextValue() != "vault-webhook-secret" {
		t.Fatalf("PlaintextValue = %q, want vault-webhook-secret", resolved.GetPlaintextValue())
	}
}
