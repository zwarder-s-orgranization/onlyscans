package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

type stubWebhookSecretClient struct {
	secflowv1.SecretServiceClient
	values map[string]string
}

func (s *stubWebhookSecretClient) ResolveScopedSecret(_ context.Context, req *secflowv1.ResolveScopedSecretRequest, _ ...grpc.CallOption) (*secflowv1.ResolveScopedSecretResponse, error) {
	val, ok := s.values[req.GetSecretRef()]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return &secflowv1.ResolveScopedSecretResponse{SecretRef: req.GetSecretRef(), PlaintextValue: val}, nil
}

type stubWebhookRunClient struct {
	secflowv1.RunServiceClient
	calls   []*secflowv1.StartRunFromWebhookRequest
	seen    map[string]bool
	watchFn func()
}

func (s *stubWebhookRunClient) StartRunFromWebhook(_ context.Context, req *secflowv1.StartRunFromWebhookRequest, _ ...grpc.CallOption) (*secflowv1.StartRunFromWebhookResponse, error) {
	s.calls = append(s.calls, req)
	if key := req.GetIdempotencyKey(); key != "" {
		if s.seen == nil {
			s.seen = map[string]bool{}
		}
		if s.seen[key] {
			return nil, status.Error(codes.AlreadyExists, "DUPLICATE_DELIVERY: duplicate webhook delivery")
		}
		s.seen[key] = true
	}
	return &secflowv1.StartRunFromWebhookResponse{
		Run: &secflowv1.Run{
			Id:         "run_wh_1",
			WorkflowId: req.GetWorkflowId(),
			Status:     secflowv1.RunStatus_RUN_STATUS_QUEUED,
			Trigger:    req.GetTrigger(),
		},
	}, nil
}

func (s *stubWebhookRunClient) WatchRun(_ context.Context, _ *secflowv1.WatchRunRequest, _ ...grpc.CallOption) (secflowv1.RunService_WatchRunClient, error) {
	if s.watchFn != nil {
		s.watchFn()
	}
	return nil, status.Error(codes.Unimplemented, "WatchRun must not be called synchronously by webhook handler")
}

type stubWebhookIngestClient struct {
	secflowv1.SourceIngesterServiceClient
	allowed map[string]bool
}

func (s *stubWebhookIngestClient) CheckRepoAllowlist(_ context.Context, req *secflowv1.CheckRepoAllowlistRequest, _ ...grpc.CallOption) (*secflowv1.CheckRepoAllowlistResponse, error) {
	if s.allowed[req.GetRepoUrl()] {
		return &secflowv1.CheckRepoAllowlistResponse{Allowed: true}, nil
	}
	return &secflowv1.CheckRepoAllowlistResponse{Allowed: false, Reason: "repo not in allowlist"}, nil
}

type stubCiWorkflowClient struct {
	secflowv1.WorkflowServiceClient
	workflows map[string]*secflowv1.Workflow
	lastCiReq *secflowv1.GenerateCiConfigRequest
}

func (s *stubCiWorkflowClient) GetWorkflow(_ context.Context, req *secflowv1.GetWorkflowRequest, _ ...grpc.CallOption) (*secflowv1.GetWorkflowResponse, error) {
	wf, ok := s.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	return &secflowv1.GetWorkflowResponse{Workflow: wf}, nil
}

func (s *stubCiWorkflowClient) GenerateCiConfig(_ context.Context, req *secflowv1.GenerateCiConfigRequest, _ ...grpc.CallOption) (*secflowv1.GenerateCiConfigResponse, error) {
	s.lastCiReq = req
	return &secflowv1.GenerateCiConfigResponse{
		Provider:          req.GetProvider(),
		Filename:          ".github/workflows/secflow-security.yml",
		YamlContent:       "name: secflow-security\n",
		RequiredCiSecrets: []string{"SECFLOW_CI_TOKEN"},
	}, nil
}

func signHMACSHA256(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookGit_PingAllowlistFilteringAsync202And409(t *testing.T) {
	wfGH := &secflowv1.Workflow{
		Id: "wf_gh",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{
					Id:         "trig_1",
					PluginId:   "trigger.webhook",
					ParamsJson: []byte(`{"gitProvider":"GITHUB","events":["push"],"branchFilter":"main,release/*","reportCommitStatus":true}`),
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "webhookSecret", SecretRef: "sec_gh"},
					},
				},
			},
		},
	}
	wfGL := &secflowv1.Workflow{
		Id: "wf_gl",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{
					Id:         "trig_gl",
					PluginId:   "trigger.webhook",
					ParamsJson: []byte(`{"gitProvider":"GITLAB","events":["merge_request"],"branchFilter":"feat/*"}`),
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "webhookSecret", SecretRef: "sec_gl"},
					},
				},
			},
		},
	}

	watchCalled := false
	runStub := &stubWebhookRunClient{
		watchFn: func() { watchCalled = true },
	}
	gw := &gateway{
		serviceToken: "svc-token",
		wf: &stubCiWorkflowClient{
			workflows: map[string]*secflowv1.Workflow{"wf_gh": wfGH, "wf_gl": wfGL},
		},
		secs: &stubWebhookSecretClient{
			values: map[string]string{"sec_gh": "gh-secret", "sec_gl": "gl-token"},
		},
		ingest: &stubWebhookIngestClient{
			allowed: map[string]bool{
				"https://github.com/TBagirov/training":       true,
				"https://gitlab.example.org/edu/repair-desk": true,
			},
		},
		runs: runStub,
	}

	t.Run("GitHub ping returns 200 ok without starting run", func(t *testing.T) {
		body := []byte(`{"zen":"Keep it logically awesome."}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gh", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "ping")
		req.Header.Set("X-Hub-Signature-256", signHMACSHA256("gh-secret", body))
		gw.webhook(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("ping status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out["ok"] != true {
			t.Fatalf("ping body=%+v, want {ok: true}", out)
		}
		if len(runStub.calls) != 0 {
			t.Fatalf("ping must not start a run, got %d calls", len(runStub.calls))
		}
	})

	t.Run("rejects invalid HMAC with 401 ProblemDetails", func(t *testing.T) {
		body := []byte(`{"ref":"refs/heads/main"}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gh", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
		gw.webhook(rec, req)

		if rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("bad hmac status=%d ct=%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
	})

	t.Run("rejects unauthorized repo URL with 403 ALLOWLIST_DENIED", func(t *testing.T) {
		body := []byte(`{"ref":"refs/heads/main","after":"1111","repository":{"html_url":"https://github.com/evil/corp","full_name":"evil/corp"}}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gh", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", "del-unauth")
		req.Header.Set("X-Hub-Signature-256", signHMACSHA256("gh-secret", body))
		gw.webhook(rec, req)

		if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("allowlist status=%d ct=%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"ALLOWLIST_DENIED"`) {
			t.Fatalf("expected ALLOWLIST_DENIED, got %s", rec.Body.String())
		}
		if len(runStub.calls) != 0 {
			t.Fatalf("allowlist rejection must not start a run")
		}
	})

	t.Run("ignores non-matching event with 200 ignored", func(t *testing.T) {
		body := []byte(`{"number":7,"pull_request":{"head":{"ref":"main","sha":"2222"}},"repository":{"html_url":"https://github.com/TBagirov/training","full_name":"TBagirov/training"}}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gh", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "pull_request")
		req.Header.Set("X-GitHub-Delivery", "del-ev-filtered")
		req.Header.Set("X-Hub-Signature-256", signHMACSHA256("gh-secret", body))
		gw.webhook(rec, req)

		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ignored":true`) {
			t.Fatalf("event filter status=%d body=%s", rec.Code, rec.Body.String())
		}
		if len(runStub.calls) != 0 {
			t.Fatalf("filtered event must not start a run")
		}
	})

	t.Run("ignores non-matching branch with 200 ignored", func(t *testing.T) {
		body := []byte(`{"ref":"refs/heads/feature/nope","after":"3333","repository":{"html_url":"https://github.com/TBagirov/training","full_name":"TBagirov/training"}}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gh", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", "del-branch-filtered")
		req.Header.Set("X-Hub-Signature-256", signHMACSHA256("gh-secret", body))
		gw.webhook(rec, req)

		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ignored":true`) {
			t.Fatalf("branch filter status=%d body=%s", rec.Code, rec.Body.String())
		}
		if len(runStub.calls) != 0 {
			t.Fatalf("filtered branch must not start a run")
		}
	})

	t.Run("matching push returns non-blocking 202 and duplicate deliveryId returns 409 DUPLICATE_DELIVERY", func(t *testing.T) {
		body := []byte(`{
			"ref":"refs/heads/release/2.0",
			"after":"abc987654321",
			"sender":{"login":"octocat"},
			"repository":{
				"html_url":"https://github.com/TBagirov/training",
				"full_name":"TBagirov/training",
				"statuses_url":"https://api.github.com/repos/TBagirov/training/statuses/{sha}"
			}
		}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gh", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", "delivery-100")
		req.Header.Set("X-Hub-Signature-256", signHMACSHA256("gh-secret", body))
		req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		gw.webhook(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("status=%d, want 202, body=%s", rec.Code, rec.Body.String())
		}
		if watchCalled {
			t.Fatal("webhook handler must NOT synchronously call WatchRun")
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["runId"] != "run_wh_1" || out["status"] != "QUEUED" || out["deliveryId"] != "delivery-100" || out["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Fatalf("unexpected 202 response: %+v", out)
		}
		if len(runStub.calls) != 1 {
			t.Fatalf("expected 1 StartRunFromWebhook call, got %d", len(runStub.calls))
		}
		tr := runStub.calls[0].GetTrigger()
		if tr.GetType() != secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK ||
			tr.GetGitProvider() != secflowv1.GitProvider_GIT_PROVIDER_GITHUB ||
			tr.GetRepoUrl() != "https://github.com/TBagirov/training" ||
			tr.GetBranch() != "release/2.0" ||
			tr.GetCommitSha() != "abc987654321" ||
			tr.GetDeliveryId() != "delivery-100" ||
			tr.GetTriggeredBy() != "octocat" ||
			tr.GetCommitStatusUrl() != "https://api.github.com/repos/TBagirov/training/statuses/abc987654321" {
			t.Fatalf("TriggerMetadata mismatch: %+v", tr)
		}

		// Second delivery with identical deliveryId MUST return 409 Conflict with code=CONFLICT.
		recDup := httptest.NewRecorder()
		reqDup := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gh", bytes.NewReader(body))
		reqDup.Header.Set("X-GitHub-Event", "push")
		reqDup.Header.Set("X-GitHub-Delivery", "delivery-100")
		reqDup.Header.Set("X-Hub-Signature-256", signHMACSHA256("gh-secret", body))
		gw.webhook(recDup, reqDup)

		if recDup.Code != http.StatusConflict || recDup.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("duplicate delivery status=%d ct=%q body=%s", recDup.Code, recDup.Header().Get("Content-Type"), recDup.Body.String())
		}
		var dupProb map[string]any
		if err := json.Unmarshal(recDup.Body.Bytes(), &dupProb); err != nil {
			t.Fatal(err)
		}
		if dupProb["code"] != "CONFLICT" || !strings.Contains(asString(dupProb["detail"]), "duplicate delivery") {
			t.Fatalf("expected code=CONFLICT with duplicate delivery detail, got %s", recDup.Body.String())
		}
	})

	t.Run("GitLab merge_request extracts PR number and GitLab commit status URL", func(t *testing.T) {
		body := []byte(`{
			"object_kind":"merge_request",
			"user":{"username":"alice"},
			"project":{"id":99,"web_url":"https://gitlab.example.org/edu/repair-desk"},
			"object_attributes":{"iid":14,"source_branch":"feat/sast","last_commit":{"id":"glsha123"}}
		}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/git/wf_gl", bytes.NewReader(body))
		req.Header.Set("X-Gitlab-Event", "Merge Request Hook")
		req.Header.Set("X-Gitlab-Event-UUID", "gl-uuid-1")
		req.Header.Set("X-Gitlab-Token", "gl-token")
		gw.webhook(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("gitlab webhook status=%d body=%s", rec.Code, rec.Body.String())
		}
		last := runStub.calls[len(runStub.calls)-1]
		tr := last.GetTrigger()
		if tr.GetGitProvider() != secflowv1.GitProvider_GIT_PROVIDER_GITLAB ||
			tr.GetPrNumber() != 14 ||
			tr.GetBranch() != "feat/sast" ||
			tr.GetCommitSha() != "glsha123" ||
			tr.GetCommitStatusUrl() != "https://gitlab.example.org/api/v4/projects/99/statuses/glsha123" {
			t.Fatalf("unexpected GitLab TriggerMetadata: %+v", tr)
		}
	})
}

func TestWebhookInspector_RealHMACVerification(t *testing.T) {
	gw := &gateway{
		insp:        map[string][]inspectorEntry{},
		inspUpdated: map[string]time.Time{},
		subs:        map[string][]chan map[string]any{},
	}

	payload := []byte(`{"runId":"run_1","critical":2}`)

	t.Run("unsigned request sets hmacValid=false", func(t *testing.T) {
		t.Setenv("INSPECTOR_HMAC_SECRET", "top-secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/inspector/ch-unsigned", bytes.NewReader(payload))
		gw.inspector(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", rec.Code)
		}
		items := gw.listInspectorDeliveries("ch-unsigned", 5)
		if len(items) != 1 || asMap(items[0])["hmacValid"] != false {
			t.Fatalf("unsigned delivery must have hmacValid=false, got %+v", items)
		}
	})

	t.Run("mismatched signature sets hmacValid=false", func(t *testing.T) {
		t.Setenv("INSPECTOR_HMAC_SECRET", "top-secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/inspector/ch-bad", bytes.NewReader(payload))
		req.Header.Set("X-SecFlow-Signature-256", "sha256=0000")
		gw.inspector(rec, req)
		items := gw.listInspectorDeliveries("ch-bad", 5)
		if len(items) != 1 || asMap(items[0])["hmacValid"] != false {
			t.Fatalf("bad hmac delivery must have hmacValid=false, got %+v", items)
		}
	})

	t.Run("valid signature against INSPECTOR_HMAC_SECRET sets hmacValid=true", func(t *testing.T) {
		t.Setenv("INSPECTOR_HMAC_SECRET", "top-secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/inspector/ch-good", bytes.NewReader(payload))
		req.Header.Set("X-SecFlow-Signature-256", signHMACSHA256("top-secret", payload))
		gw.inspector(rec, req)
		items := gw.listInspectorDeliveries("ch-good", 5)
		if len(items) != 1 || asMap(items[0])["hmacValid"] != true {
			t.Fatalf("valid hmac delivery must have hmacValid=true, got %+v", items)
		}
	})

	t.Run("valid signature against X-SecFlow-Test-Secret strips test secret header", func(t *testing.T) {
		t.Setenv("INSPECTOR_HMAC_SECRET", "")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks/inspector/ch-test-secret", bytes.NewReader(payload))
		req.Header.Set("X-SecFlow-Test-Secret", "ephemeral-key")
		req.Header.Set("X-SecFlow-Signature-256", signHMACSHA256("ephemeral-key", payload))
		gw.inspector(rec, req)
		items := gw.listInspectorDeliveries("ch-test-secret", 5)
		if len(items) != 1 {
			t.Fatalf("expected 1 delivery, got %d", len(items))
		}
		item := asMap(items[0])
		if item["hmacValid"] != true {
			t.Fatalf("expected hmacValid=true, got %+v", item)
		}
		if _, leaked := asMap(item["headers"])["X-Secflow-Test-Secret"]; leaked {
			t.Fatalf("X-SecFlow-Test-Secret must not be stored in inspector headers: %+v", item["headers"])
		}
	})
}

func TestCatalogUpload_SchemaValidation(t *testing.T) {
	secret := []byte("test-secret")
	editorTok := signTestToken(t, secret, "editor")
	cats := &stubCatalogClient{}
	gw := &gateway{secret: secret, cats: cats}

	postCatalog := func(payload []byte, fields map[string]string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "catalog.json")
		_, _ = fw.Write(payload)
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		_ = mw.Close()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/catalogs/upload", &buf)
		req.Header.Set("Authorization", "Bearer "+editorTok)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		gw.catalogUpload(rec, req)
		return rec
	}

	invalidCases := []struct {
		name    string
		payload string
	}{
		{"malformed json", `{broken`},
		{"empty object", `{}`},
		{"advisories empty array", `{"schemaVersion":"1.0","snapshotDate":"2026-05-01","advisories":[]}`},
		{"advisories missing schemaVersion", `{"snapshotDate":"2026-05-01","advisories":[{"id":"CVE-1","group":"g","artifact":"a","severity":"HIGH","affectedRanges":[{"upper":"2.0"}]}]}`},
		{"advisories missing snapshotDate", `{"schemaVersion":"1.0","advisories":[{"id":"CVE-1","group":"g","artifact":"a","severity":"HIGH","affectedRanges":[{"upper":"2.0"}]}]}`},
		{"advisories missing group", `{"schemaVersion":"1.0","snapshotDate":"2026-05-01","advisories":[{"id":"CVE-1","artifact":"a","severity":"HIGH","affectedRanges":[{"upper":"2.0"}]}]}`},
		{"advisories invalid severity", `{"schemaVersion":"1.0","snapshotDate":"2026-05-01","advisories":[{"id":"CVE-1","group":"g","artifact":"a","severity":"SEVERE","affectedRanges":[{"upper":"2.0"}]}]}`},
		{"advisories missing affectedRanges", `{"schemaVersion":"1.0","snapshotDate":"2026-05-01","advisories":[{"id":"CVE-1","group":"g","artifact":"a","severity":"HIGH","affectedRanges":[]}]}`},
		{"mentor format incomplete header", `{"formatVersion":1,"vulnerabilities":[{"id":"GHSA-27xj-rqx5-2255"}]}`},
		{"minimal vulnerabilities without snapshotDate", `{"vulnerabilities":[{"id":"CVE-2026-0001"}]}`},
	}

	for _, tc := range invalidCases {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			rec := postCatalog([]byte(tc.payload), map[string]string{"name": "Bad Catalog"})
			if rec.Code != http.StatusUnprocessableEntity || rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("case=%q status=%d ct=%q body=%s", tc.name, rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"VALIDATION_FAILED"`) {
				t.Fatalf("case=%q expected VALIDATION_FAILED, got %s", tc.name, rec.Body.String())
			}
		})
	}

	t.Run("accepts valid advisories schema", func(t *testing.T) {
		validAdv := `{"schemaVersion":"1.0","snapshotDate":"2026-06-01","advisories":[{"id":"CVE-2022-42889","group":"org.apache.commons","artifact":"commons-text","severity":"CRITICAL","affectedRanges":[{"lower":"1.5","upper":"1.10.0"}]}]}`
		rec := postCatalog([]byte(validAdv), map[string]string{"name": "Custom Advisories", "setAsDefault": "true"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if cats.lastReq.GetName() != "Custom Advisories" || !cats.lastReq.GetSetAsDefault() || cats.lastReq.GetSnapshotDate() != "2026-06-01" || cats.lastReq.GetAdvisoryCount() != 1 {
			t.Fatalf("unexpected RegisterCatalogRequest: %+v", cats.lastReq)
		}
	})

	t.Run("accepts real mentor vulnerability database JSON", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "data", "repos", "mentor-training", "vulnerability-database", "vulnerabilities.json"))
		if err != nil {
			t.Skipf("optional mentor vulnerabilities.json not present: %v", err)
		}
		rec := postCatalog(raw, map[string]string{"name": "Mentor Catalog", "setAsDefault": "false"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("mentor catalog status=%d body=%s", rec.Code, rec.Body.String())
		}
		if cats.lastReq.GetAdvisoryCount() == 0 || cats.lastReq.GetSnapshotDate() == "" {
			t.Fatalf("unexpected mentor RegisterCatalogRequest: %+v", cats.lastReq)
		}
	})

	t.Run("fails closed with 503 when blobstore is configured and Put fails", func(t *testing.T) {
		failS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "storage down", http.StatusInternalServerError)
		}))
		defer failS3.Close()
		t.Setenv("GARAGE_ENDPOINT", failS3.URL)
		t.Setenv("GARAGE_ACCESS_KEY", "ak-test")
		t.Setenv("GARAGE_SECRET_KEY", "sk-test")

		cats.lastReq = nil
		validAdv := `{"schemaVersion":"1.0","snapshotDate":"2026-06-01","advisories":[{"id":"CVE-2022-42889","group":"org.apache.commons","artifact":"commons-text","severity":"CRITICAL","affectedRanges":[{"lower":"1.5","upper":"1.10.0"}]}]}`
		rec := postCatalog([]byte(validAdv), map[string]string{"name": "Fail Storage"})
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("storage fail status=%d ct=%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"INTERNAL"`) {
			t.Fatalf("expected INTERNAL problem code, got %s", rec.Body.String())
		}
		if cats.lastReq != nil {
			t.Fatalf("RegisterCatalog must not be called when blobstore Put fails")
		}
	})

	t.Run("returns non-empty snapshotDate even when backend omits it", func(t *testing.T) {
		t.Setenv("GARAGE_ENDPOINT", "")
		t.Setenv("GARAGE_ACCESS_KEY", "")
		t.Setenv("GARAGE_SECRET_KEY", "")

		cats.resp = &secflowv1.RegisterCatalogResponse{
			Catalog: &secflowv1.VulnerabilityCatalog{
				Id:            "cat_no_date",
				Name:          "No Date Echo",
				AdvisoryCount: 1,
			},
		}
		defer func() { cats.resp = nil }()

		validAdv := `{"schemaVersion":"1.0","snapshotDate":"2026-07-10","advisories":[{"id":"CVE-2022-42889","group":"org.apache.commons","artifact":"commons-text","severity":"CRITICAL","affectedRanges":[{"lower":"1.5","upper":"1.10.0"}]}]}`
		rec := postCatalog([]byte(validAdv), map[string]string{"name": "No Date Echo"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["snapshotDate"] != "2026-07-10" {
			t.Fatalf("snapshotDate = %v, want 2026-07-10", out["snapshotDate"])
		}
	})
}

func TestGenerateCiConfig_ForwardsFailOnSeverityAndPolicyGate(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("test-secret")
	viewerTok := signTestToken(t, secret, "viewer")
	wfStub := &stubCiWorkflowClient{}
	gw := &gateway{schema: schema, secret: secret, wf: wfStub}

	query := `mutation { generateCiConfig(input: {workflowId: "wf_1", provider: GITLAB_CI, secflowBaseUrl: "https://secflow.local", failOnSeverity: MEDIUM, failOnPolicyGate: false}) { provider filename yamlContent requiredCiSecrets } }`
	body, _ := json.Marshal(map[string]any{"query": query})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+viewerTok)
	req.Header.Set("Content-Type", "application/json")
	gw.graphql(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if wfStub.lastCiReq == nil {
		t.Fatal("GenerateCiConfig was not called")
	}
	if wfStub.lastCiReq.GetFailOnSeverity() != secflowv1.Severity_SEVERITY_MEDIUM {
		t.Fatalf("FailOnSeverity = %v, want MEDIUM", wfStub.lastCiReq.GetFailOnSeverity())
	}
	if wfStub.lastCiReq.GetFailOnPolicyGate() {
		t.Fatalf("FailOnPolicyGate = true, want false")
	}
	if wfStub.lastCiReq.GetProvider() != secflowv1.CiProvider_CI_PROVIDER_GITLAB_CI {
		t.Fatalf("Provider = %v, want GITLAB_CI", wfStub.lastCiReq.GetProvider())
	}
}
