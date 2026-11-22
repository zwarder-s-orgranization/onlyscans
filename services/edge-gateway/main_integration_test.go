package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	gorilla "github.com/gorilla/websocket"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const integrationTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

// -----------------------------------------------------------------------------
// 1. HTTP Health, Readiness & Prometheus Metrics
// -----------------------------------------------------------------------------

func TestIntegration_HTTPHealthReadyAndMetrics(t *testing.T) {
	t.Parallel()
	env := newGatewayTestEnv(t)

	t.Run("healthz GET HEAD and 405", func(t *testing.T) {
		code, hdr, raw := env.doRequest(t, http.MethodGet, "/healthz", "", nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /healthz status=%d body=%s", code, string(raw))
		}
		if body := decodeJSONMap(t, raw); body["status"] != "ok" {
			t.Fatalf("GET /healthz body=%#v", body)
		}
		if ct := hdr.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("GET /healthz content-type=%q", ct)
		}
		if headCode, _, _ := env.doRequest(t, http.MethodHead, "/healthz", "", nil, nil); headCode != http.StatusOK {
			t.Fatalf("HEAD /healthz status=%d", headCode)
		}
		postCode, postHdr, postRaw := env.doRequest(t, http.MethodPost, "/healthz", "", nil, nil)
		if postCode != http.StatusMethodNotAllowed || !strings.Contains(postHdr.Get("Content-Type"), "application/problem+json") {
			t.Fatalf("POST /healthz status=%d ct=%q body=%s", postCode, postHdr.Get("Content-Type"), string(postRaw))
		}
	})

	t.Run("readyz healthy degraded and 405", func(t *testing.T) {
		code, _, raw := env.doRequest(t, http.MethodGet, "/readyz", "", nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /readyz status=%d body=%s", code, string(raw))
		}
		body := decodeJSONMap(t, raw)
		checks := mustMap(t, body["checks"], "readyz.checks")
		if body["status"] != "ready" || checks["postgres"] != "ok" || checks["orchestratorGrpc"] != "ok" || checks["garage"] != "ok" {
			t.Fatalf("unexpected readyz payload=%#v", body)
		}
		if workers, ok := checks["activeWorkerStreams"].(float64); !ok || int(workers) != 2 {
			t.Fatalf("expected activeWorkerStreams=2, got %v", checks["activeWorkerStreams"])
		}
		if headCode, _, _ := env.doRequest(t, http.MethodHead, "/readyz", "", nil, nil); headCode != http.StatusOK {
			t.Fatalf("HEAD /readyz status=%d", headCode)
		}
		if postCode, _, _ := env.doRequest(t, http.MethodPost, "/readyz", "", nil, nil); postCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST /readyz status=%d", postCode)
		}

		env.gw.pgPing = func(context.Context) error { return errors.New("pg down") }
		env.backend.mu.Lock()
		env.backend.failListPlugins = status.Error(codes.Unavailable, "orchestrator down")
		env.backend.mu.Unlock()
		defer func() {
			env.gw.pgPing = func(context.Context) error { return nil }
			env.backend.mu.Lock()
			env.backend.failListPlugins = nil
			env.backend.mu.Unlock()
		}()

		degCode, _, degRaw := env.doRequest(t, http.MethodGet, "/readyz", "", nil, nil)
		if degCode != http.StatusServiceUnavailable || decodeJSONMap(t, degRaw)["status"] != "not_ready" {
			t.Fatalf("degraded /readyz status=%d body=%s", degCode, string(degRaw))
		}
	})

	t.Run("metrics exposes prometheus counters after requests", func(t *testing.T) {
		code, _, raw := env.doRequest(t, http.MethodGet, "/metrics", "", nil, nil)
		if code != http.StatusOK || !strings.Contains(string(raw), "secflow_http_requests_total") {
			t.Fatalf("GET /metrics status=%d missing secflow_http_requests_total", code)
		}
	})
}

// -----------------------------------------------------------------------------
// 2. HTTP Binary Uploads: POST /upload and POST /catalogs/upload
// -----------------------------------------------------------------------------

func TestIntegration_HTTPUploads(t *testing.T) {
	t.Parallel()
	env := newGatewayTestEnv(t)

	t.Run("POST /upload success dedup traceparent and error cases", func(t *testing.T) {
		testHTTPUploadSource(t, env)
	})
	t.Run("POST /catalogs/upload registers catalog visible in GraphQL", func(t *testing.T) {
		testHTTPUploadCatalog(t, env)
	})
}

func testHTTPUploadSource(t *testing.T, env *gatewayTestEnv) {
	t.Helper()
	zipBytes := []byte("PK\x03\x04dummy-kotlin-project-archive")
	code, _, raw := env.doMultipart(
		t, "/upload", env.editorToken, "repairdesk.zip", zipBytes,
		map[string]string{"repoName": "repairdesk"},
		map[string]string{"traceparent": integrationTraceparent},
	)
	if code != http.StatusCreated {
		t.Fatalf("POST /upload status=%d body=%s", code, string(raw))
	}
	res := decodeJSONMap(t, raw)
	if res["sourceId"] == "" || res["repoName"] != "repairdesk" || res["deduplicatedHit"] != false {
		t.Fatalf("unexpected upload response: %#v", res)
	}
	if gotTP := env.backend.lastTraceparent("IngestUpload"); !strings.Contains(gotTP, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("expected traceparent forwarded to IngestUpload gRPC, got %q", gotTP)
	}

	code2, _, raw2 := env.doMultipart(t, "/upload", env.ownerToken, "repairdesk.zip", zipBytes, nil, nil)
	if code2 != http.StatusCreated || decodeJSONMap(t, raw2)["deduplicatedHit"] != true {
		t.Fatalf("second POST /upload status=%d body=%s", code2, string(raw2))
	}

	errCases := []struct {
		name       string
		method     string
		token      string
		content    []byte
		wantStatus int
		wantCode   string
	}{
		{name: "method not allowed", method: http.MethodGet, token: env.ownerToken, wantStatus: http.StatusMethodNotAllowed, wantCode: "VALIDATION_FAILED"},
		{name: "unauthenticated", method: http.MethodPost, token: "", content: zipBytes, wantStatus: http.StatusUnauthorized, wantCode: "UNAUTHENTICATED"},
		{name: "viewer forbidden", method: http.MethodPost, token: env.viewerToken, content: zipBytes, wantStatus: http.StatusForbidden, wantCode: "FORBIDDEN"},
		{name: "empty payload", method: http.MethodPost, token: env.editorToken, content: nil, wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_FAILED"},
		{name: "zip bomb rejected 413", method: http.MethodPost, token: env.editorToken, content: []byte("ZIP_BOMB_MARKER"), wantStatus: http.StatusRequestEntityTooLarge, wantCode: "ZIP_BOMB_DETECTED"},
		{name: "zip slip rejected 422", method: http.MethodPost, token: env.editorToken, content: []byte("ZIP_SLIP_MARKER"), wantStatus: http.StatusUnprocessableEntity, wantCode: "ZIP_SLIP_DETECTED"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			var c int
			var r []byte
			if tc.method != http.MethodPost {
				c, _, r = env.doRequest(t, tc.method, "/upload", tc.token, nil, nil)
			} else {
				c, _, r = env.doMultipart(t, "/upload", tc.token, "sample.zip", tc.content, nil, nil)
			}
			if c != tc.wantStatus || decodeJSONMap(t, r)["code"] != tc.wantCode {
				t.Fatalf("status=%d (want %d) body=%s (want code %s)", c, tc.wantStatus, string(r), tc.wantCode)
			}
		})
	}
}

func testHTTPUploadCatalog(t *testing.T, env *gatewayTestEnv) {
	t.Helper()
	validCatalog := []byte(`{
		"schemaVersion": "1.0",
		"snapshotDate": "2026-06-01",
		"advisories": [
			{
				"id": "CVE-2026-9999",
				"group": "org.example",
				"artifact": "demo-lib",
				"severity": "HIGH",
				"affectedRanges": [{"upper": "2.0.0"}]
			}
		]
	}`)
	code, _, raw := env.doMultipart(
		t, "/catalogs/upload", env.editorToken, "catalog.json", validCatalog,
		map[string]string{"name": "Eval 2026", "setAsDefault": "true"},
		nil,
	)
	if code != http.StatusCreated {
		t.Fatalf("POST /catalogs/upload status=%d body=%s", code, string(raw))
	}
	created := decodeJSONMap(t, raw)
	if created["name"] != "Eval 2026" || created["isDefault"] != true || created["advisoryCount"] != float64(1) {
		t.Fatalf("unexpected catalog upload response: %#v", created)
	}

	gqlData := env.mustGraphQL(t, env.viewerToken, `{ catalogs { id name advisoryCount isDefault } }`, nil)
	cats := mustSlice(t, gqlData["catalogs"], "catalogs")
	found := false
	for _, item := range cats {
		if mustMap(t, item, "catalog")["name"] == "Eval 2026" {
			found = true
		}
	}
	if !found {
		t.Fatalf("uploaded catalog not visible in GraphQL catalogs: %#v", cats)
	}

	if badCode, _, _ := env.doMultipart(t, "/catalogs/upload", env.editorToken, "bad.json", []byte(`{"advisories":[]}`), nil, nil); badCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid catalog status=%d, want 422", badCode)
	}
	if vCode, _, _ := env.doMultipart(t, "/catalogs/upload", env.viewerToken, "c.json", validCatalog, nil, nil); vCode != http.StatusForbidden {
		t.Fatalf("viewer catalog upload status=%d, want 403", vCode)
	}
	if uCode, _, _ := env.doMultipart(t, "/catalogs/upload", "", "c.json", validCatalog, nil, nil); uCode != http.StatusUnauthorized {
		t.Fatalf("unauth catalog upload status=%d, want 401", uCode)
	}
	if mCode, _, _ := env.doRequest(t, http.MethodGet, "/catalogs/upload", env.ownerToken, nil, nil); mCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /catalogs/upload status=%d, want 405", mCode)
	}
	if eCode, _, _ := env.doRequest(t, http.MethodPost, "/catalogs/upload", env.editorToken, nil, nil); eCode != http.StatusBadRequest {
		t.Fatalf("empty POST /catalogs/upload status=%d, want 400", eCode)
	}
}

// -----------------------------------------------------------------------------
// 3. HTTP Run Artifact Downloads: /runs/{runId}/{submission.json,sbom.cdx.json,report.md,report.html}
// -----------------------------------------------------------------------------

func TestIntegration_HTTPRunArtifactDownloads(t *testing.T) {
	t.Parallel()
	env := newGatewayTestEnv(t)

	tokData := env.mustGraphQL(t, env.ownerToken, `
		mutation($in: CreateScopedTokenInput!) {
			createScopedToken(input: $in) { plaintextToken metadata { tokenId } }
		}`, map[string]any{
		"in": map[string]any{"name": "ci-read-seed", "scopes": []string{"ci:readRun"}, "workflowId": "wf_seed"},
	})
	scopedReadTok := mustString(t, mustMap(t, tokData["createScopedToken"], "createScopedToken")["plaintextToken"], "plaintextToken")

	artifacts := []struct {
		name        string
		path        string
		wantCT      string
		wantFile    string
		wantContain string
	}{
		{name: "submission.json", path: "/runs/run_seed/submission.json", wantCT: "application/json; charset=utf-8", wantFile: "submission-run_seed.json", wantContain: `"class":"sql-injection"`},
		{name: "sbom.cdx.json", path: "/runs/run_seed/sbom.cdx.json", wantCT: "application/vnd.cyclonedx+json; charset=utf-8", wantFile: "sbom-run_seed.cdx.json", wantContain: `"bomFormat":"CycloneDX"`},
		{name: "report.md", path: "/runs/run_seed/report.md", wantCT: "text/markdown; charset=utf-8", wantFile: "report-run_seed.md", wantContain: "# SecFlow Report"},
		{name: "report.html", path: "/runs/run_seed/report.html", wantCT: "text/html; charset=utf-8", wantFile: "report-run_seed.html", wantContain: "<h1>SecFlow Report</h1>"},
	}

	for _, tc := range artifacts {
		t.Run("GET and HEAD "+tc.name, func(t *testing.T) {
			code, hdr, raw := env.doRequest(t, http.MethodGet, tc.path, env.viewerToken, nil, nil)
			if code != http.StatusOK || hdr.Get("Content-Type") != tc.wantCT || !strings.Contains(hdr.Get("Content-Disposition"), tc.wantFile) || len(hdr.Get("X-SecFlow-Sha256")) != 64 || !strings.Contains(string(raw), tc.wantContain) {
				t.Fatalf("GET %s status=%d ct=%q disp=%q sha=%q body=%s", tc.path, code, hdr.Get("Content-Type"), hdr.Get("Content-Disposition"), hdr.Get("X-SecFlow-Sha256"), string(raw))
			}
			if scCode, _, _ := env.doRequest(t, http.MethodGet, tc.path, scopedReadTok, nil, nil); scCode != http.StatusOK {
				t.Fatalf("scoped token GET %s status=%d, want 200", tc.path, scCode)
			}
			if hCode, _, _ := env.doRequest(t, http.MethodHead, tc.path, env.viewerToken, nil, nil); hCode != http.StatusOK {
				t.Fatalf("HEAD %s status=%d, want 200", tc.path, hCode)
			}
		})
	}

	t.Run("auth scope 404 and 405 enforcement", func(t *testing.T) {
		cases := []struct {
			name       string
			method     string
			path       string
			token      string
			wantStatus int
		}{
			{name: "unauthenticated", method: http.MethodGet, path: "/runs/run_seed/submission.json", token: "", wantStatus: http.StatusUnauthorized},
			{name: "scoped token denied on other workflow run", method: http.MethodGet, path: "/runs/run_other/submission.json", token: scopedReadTok, wantStatus: http.StatusForbidden},
			{name: "unknown artifact name", method: http.MethodGet, path: "/runs/run_seed/unknown.txt", token: env.viewerToken, wantStatus: http.StatusNotFound},
			{name: "missing artifact path segment", method: http.MethodGet, path: "/runs/run_seed", token: env.viewerToken, wantStatus: http.StatusNotFound},
			{name: "unknown run id", method: http.MethodGet, path: "/runs/run_missing/submission.json", token: env.viewerToken, wantStatus: http.StatusNotFound},
			{name: "POST method not allowed", method: http.MethodPost, path: "/runs/run_seed/submission.json", token: env.ownerToken, wantStatus: http.StatusMethodNotAllowed},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if code, _, raw := env.doRequest(t, tc.method, tc.path, tc.token, nil, nil); code != tc.wantStatus {
					t.Fatalf("status=%d, want %d, body=%s", code, tc.wantStatus, string(raw))
				}
			})
		}
	})
}

// -----------------------------------------------------------------------------
// 4. HTTP Webhooks: POST /webhooks/git/{workflowId} & POST /webhooks/inspector/{channelKey}
// -----------------------------------------------------------------------------

func TestIntegration_HTTPWebhooksGitAndInspector(t *testing.T) {
	t.Parallel()
	env := newGatewayTestEnv(t)

	ghSecRef := createWebhookSecret(t, env, "gh-wh-secret", "gh-hmac-key")
	ghWfID := createWebhookWorkflow(t, env, "GitHub Webhook Pipeline", "GITHUB", []string{"push", "pull_request"}, "main,release/*", ghSecRef)
	glWfID := createWebhookWorkflow(t, env, "GitLab Webhook Pipeline", "GITLAB", []string{"merge_request"}, "", ghSecRef)

	t.Run("GitHub ping push duplicate ignore allowlist and errors", func(t *testing.T) {
		testGitHubWebhookEndpoint(t, env, ghWfID)
	})
	t.Run("GitLab merge request webhook", func(t *testing.T) {
		glBody := []byte(`{"object_kind":"merge_request","user":{"username":"gluser"},"object_attributes":{"iid":17,"source_branch":"feat/auth","last_commit":{"id":"glsha1"}},"project":{"id":42,"git_http_url":"https://gitlab.com/org/repo.git","web_url":"https://gitlab.com/org/repo"}}`)
		code, _, raw := env.doRequest(t, http.MethodPost, "/webhooks/git/"+glWfID, "", map[string]string{
			"X-Gitlab-Event":      "Merge Request Hook",
			"X-Gitlab-Event-UUID": "gl-deliv-1",
			"X-Gitlab-Token":      "gh-hmac-key",
		}, bytes.NewReader(glBody))
		if code != http.StatusAccepted {
			t.Fatalf("gitlab webhook status=%d body=%s", code, string(raw))
		}
	})
	t.Run("POST /webhooks/inspector/{channelKey} records deliveries for GraphQL", func(t *testing.T) {
		testWebhookInspectorHTTP(t, env)
	})
}

func createWebhookSecret(t *testing.T, env *gatewayTestEnv, name, value string) string {
	t.Helper()
	res := env.mustGraphQL(t, env.editorToken, `mutation($in: CreateSecretInput!) { createSecret(input: $in) { secretRef } }`, map[string]any{
		"in": map[string]any{"name": name, "kind": "GIT_WEBHOOK_SECRET", "plaintextValue": value},
	})
	return mustString(t, mustMap(t, res["createSecret"], "createSecret")["secretRef"], "secretRef")
}

func createWebhookWorkflow(t *testing.T, env *gatewayTestEnv, name, provider string, events []string, branchFilter, secretRef string) string {
	t.Helper()
	params := map[string]any{"gitProvider": provider, "events": events}
	if branchFilter != "" {
		params["branchFilter"] = branchFilter
	}
	res := env.mustGraphQL(t, env.editorToken, `mutation($in: SaveWorkflowInput!) { saveWorkflow(input: $in) { id } }`, map[string]any{
		"in": map[string]any{
			"name": name,
			"graph": map[string]any{
				"schemaVersion": 1,
				"nodes": []any{map[string]any{
					"id":             "trig_wh",
					"pluginId":       "trigger.webhook",
					"label":          name,
					"position":       map[string]any{"x": 0, "y": 0},
					"params":         params,
					"secretBindings": []any{map[string]any{"paramKey": "webhookSecret", "secretRef": secretRef}},
				}},
				"edges": []any{},
			},
		},
	})
	return mustString(t, mustMap(t, res["saveWorkflow"], "saveWorkflow")["id"], "workflowId")
}

func testGitHubWebhookEndpoint(t *testing.T, env *gatewayTestEnv, ghWfID string) {
	t.Helper()
	pingBody := []byte(`{"zen":"keep it simple"}`)
	code, _, raw := env.doRequest(t, http.MethodPost, "/webhooks/git/"+ghWfID, "", map[string]string{
		"X-GitHub-Event":      "ping",
		"X-Hub-Signature-256": signSHA256Header(pingBody, "gh-hmac-key"),
	}, bytes.NewReader(pingBody))
	if code != http.StatusOK || decodeJSONMap(t, raw)["ok"] != true {
		t.Fatalf("ping status=%d body=%s", code, string(raw))
	}

	pushBody := []byte(`{"ref":"refs/heads/main","after":"abc123def","repository":{"html_url":"https://github.com/org/repo","full_name":"org/repo"},"sender":{"login":"dev1"}}`)
	sig := signSHA256Header(pushBody, "gh-hmac-key")
	code, _, raw = env.doRequest(t, http.MethodPost, "/webhooks/git/"+ghWfID, "", map[string]string{
		"X-GitHub-Event":      "push",
		"X-GitHub-Delivery":   "deliv-100",
		"X-Hub-Signature-256": sig,
		"traceparent":         integrationTraceparent,
	}, bytes.NewReader(pushBody))
	if code != http.StatusAccepted {
		t.Fatalf("push status=%d body=%s", code, string(raw))
	}
	accepted := decodeJSONMap(t, raw)
	runID := mustString(t, accepted["runId"], "webhook.runId")
	if accepted["workflowId"] != ghWfID || accepted["status"] != "QUEUED" {
		t.Fatalf("unexpected 202 payload: %#v", accepted)
	}
	runData := env.mustGraphQL(t, env.viewerToken, `query($id: ID!) { run(id: $id) { id trigger { type branch commitSha deliveryId } } }`, map[string]any{"id": runID})
	trig := mustMap(t, mustMap(t, runData["run"], "run")["trigger"], "trigger")
	if trig["type"] != "WEBHOOK" || trig["branch"] != "main" || trig["deliveryId"] != "deliv-100" {
		t.Fatalf("unexpected webhook run trigger: %#v", trig)
	}

	// Duplicate deliveryId -> 409 Conflict.
	dupCode, _, dupRaw := env.doRequest(t, http.MethodPost, "/webhooks/git/"+ghWfID, "", map[string]string{
		"X-GitHub-Event": "push", "X-GitHub-Delivery": "deliv-100", "X-Hub-Signature-256": sig,
	}, bytes.NewReader(pushBody))
	if dupCode != http.StatusConflict || decodeJSONMap(t, dupRaw)["code"] != "CONFLICT" {
		t.Fatalf("duplicate delivery status=%d body=%s", dupCode, string(dupRaw))
	}

	// Ignored branch -> 200 ignored.
	featBody := []byte(`{"ref":"refs/heads/feature/x","after":"111","repository":{"html_url":"https://github.com/org/repo"}}`)
	ignCode, _, ignRaw := env.doRequest(t, http.MethodPost, "/webhooks/git/"+ghWfID, "", map[string]string{
		"X-GitHub-Event": "push", "X-Hub-Signature-256": signSHA256Header(featBody, "gh-hmac-key"),
	}, bytes.NewReader(featBody))
	if ignCode != http.StatusOK || decodeJSONMap(t, ignRaw)["ignored"] != true {
		t.Fatalf("ignored branch status=%d body=%s", ignCode, string(ignRaw))
	}

	// Disallowed repository URL -> 403 ALLOWLIST_DENIED.
	evilBody := []byte(`{"ref":"refs/heads/main","after":"222","repository":{"html_url":"https://evil.example/org/repo"}}`)
	forbCode, _, forbRaw := env.doRequest(t, http.MethodPost, "/webhooks/git/"+ghWfID, "", map[string]string{
		"X-GitHub-Event": "push", "X-Hub-Signature-256": signSHA256Header(evilBody, "gh-hmac-key"),
	}, bytes.NewReader(evilBody))
	if forbCode != http.StatusForbidden || decodeJSONMap(t, forbRaw)["code"] != "ALLOWLIST_DENIED" {
		t.Fatalf("disallowed repo status=%d body=%s", forbCode, string(forbRaw))
	}

	if c, _, _ := env.doRequest(t, http.MethodPost, "/webhooks/git/"+ghWfID, "", map[string]string{"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=deadbeef"}, bytes.NewReader(pushBody)); c != http.StatusUnauthorized {
		t.Fatalf("invalid HMAC status=%d, want 401", c)
	}
	if c, _, _ := env.doRequest(t, http.MethodPost, "/webhooks/git/wf_missing", "", nil, bytes.NewReader(pushBody)); c != http.StatusNotFound {
		t.Fatalf("unknown workflow webhook status=%d, want 404", c)
	}
	if c, _, _ := env.doRequest(t, http.MethodGet, "/webhooks/git/"+ghWfID, "", nil, nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("GET webhook status=%d, want 405", c)
	}
}

func testWebhookInspectorHTTP(t *testing.T, env *gatewayTestEnv) {
	t.Helper()
	body := []byte(`{"event":"run.completed","severity":"HIGH"}`)
	code, _, raw := env.doRequest(t, http.MethodPost, "/webhooks/inspector/demo_chan_1", "", map[string]string{
		"Content-Type":            "application/json",
		"X-SecFlow-Test-Secret":   "insp-secret",
		"X-SecFlow-Signature-256": signSHA256Header(body, "insp-secret"),
	}, bytes.NewReader(body))
	if code != http.StatusOK {
		t.Fatalf("POST /webhooks/inspector status=%d body=%s", code, string(raw))
	}
	ack := decodeJSONMap(t, raw)
	if ack["deliveryId"] == "" || ack["receivedAt"] == "" {
		t.Fatalf("unexpected inspector ack: %#v", ack)
	}

	data := env.mustGraphQL(t, env.viewerToken, `
		query($ch: String!) {
			webhookInspectorDeliveries(channelKey: $ch, limit: 10) {
				id channelKey method hmacValid headers body receivedAt
			}
		}`, map[string]any{"ch": "demo_chan_1"})
	list := mustSlice(t, data["webhookInspectorDeliveries"], "webhookInspectorDeliveries")
	if len(list) != 1 {
		t.Fatalf("expected 1 inspector delivery, got %d", len(list))
	}
	item := mustMap(t, list[0], "delivery")
	if item["hmacValid"] != true || item["channelKey"] != "demo_chan_1" {
		t.Fatalf("unexpected inspector delivery item: %#v", item)
	}
	hdrs := mustMap(t, item["headers"], "delivery.headers")
	if hdrs["X-Secflow-Test-Secret"] != nil || hdrs["X-SecFlow-Test-Secret"] != nil {
		t.Fatalf("test secret header must be stripped: %#v", hdrs)
	}

	if c, _, _ := env.doRequest(t, http.MethodPost, "/webhooks/inspector/ab", "", nil, bytes.NewReader(body)); c != http.StatusBadRequest {
		t.Fatalf("invalid channelKey status=%d, want 400", c)
	}
	if c, _, _ := env.doRequest(t, http.MethodGet, "/webhooks/inspector/demo_chan_1", "", nil, nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("GET inspector status=%d, want 405", c)
	}
}

// -----------------------------------------------------------------------------
// 5. Inbound MCP Streamable HTTP: POST / GET (SSE) / DELETE / 405 on /mcp
// -----------------------------------------------------------------------------

func TestIntegration_HTTPMCPStreamableEndpoint(t *testing.T) {
	t.Parallel()
	env := newGatewayTestEnv(t)

	code, hdr, initResp := env.postMCP(t, env.ownerToken, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]any{"protocolVersion": "2025-03-26"},
	})
	if code != http.StatusOK || initResp["error"] != nil {
		t.Fatalf("mcp initialize status=%d resp=%#v", code, initResp)
	}
	sessionID := hdr.Get(mcpSessionHeader)
	if !strings.HasPrefix(sessionID, "mcp_") {
		t.Fatalf("expected Mcp-Session-Id header, got %q", sessionID)
	}

	t.Run("notifications ping tools/list resources/list and templates", func(t *testing.T) {
		testMCPLifecycleAndDiscovery(t, env, sessionID)
	})
	t.Run("all 10 MCP tools over POST /mcp", func(t *testing.T) {
		testMCPAllTenTools(t, env, sessionID)
	})
	t.Run("all 5 MCP resources over POST /mcp", func(t *testing.T) {
		testMCPAllFiveResources(t, env, sessionID)
	})
	t.Run("GET SSE stream DELETE session and HTTP/JSON-RPC error codes", func(t *testing.T) {
		testMCPSSEDeleteAndErrors(t, env, sessionID)
	})
}

func testMCPLifecycleAndDiscovery(t *testing.T, env *gatewayTestEnv, sessionID string) {
	t.Helper()
	if c, _, _ := env.postMCP(t, env.ownerToken, sessionID, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); c != http.StatusAccepted {
		t.Fatalf("notifications/initialized status=%d, want 202", c)
	}
	if c, _, r := env.postMCP(t, env.ownerToken, sessionID, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "ping"}); c != http.StatusOK || r["error"] != nil {
		t.Fatalf("mcp ping status=%d resp=%#v", c, r)
	}
	tlCode, _, tlResp := env.postMCP(t, env.ownerToken, sessionID, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
	if tlCode != http.StatusOK {
		t.Fatalf("tools/list status=%d", tlCode)
	}
	tools := mustSlice(t, mustMap(t, tlResp["result"], "tools/list.result")["tools"], "tools")
	if len(tools) != 10 {
		t.Fatalf("expected 10 MCP tools, got %d", len(tools))
	}
	if c, _, r := env.postMCP(t, env.ownerToken, sessionID, map[string]any{"jsonrpc": "2.0", "id": 4, "method": "resources/list"}); c != http.StatusOK || r["error"] != nil {
		t.Fatalf("resources/list status=%d resp=%#v", c, r)
	}
	if c, _, r := env.postMCP(t, env.ownerToken, sessionID, map[string]any{"jsonrpc": "2.0", "id": 5, "method": "resources/templates/list"}); c != http.StatusOK || r["error"] != nil {
		t.Fatalf("resources/templates/list status=%d resp=%#v", c, r)
	}
}

func testMCPAllTenTools(t *testing.T, env *gatewayTestEnv, sessionID string) {
	t.Helper()
	toolCalls := []struct {
		name string
		args map[string]any
	}{
		{name: "list_workflows", args: map[string]any{"limit": 10}},
		{name: "list_templates", args: map[string]any{"tags": []string{"kotlin"}}},
		{name: "clone_template", args: map[string]any{"templateId": "tpl_seed", "newWorkflowName": "MCP Cloned"}},
		{name: "generate_workflow_preview", args: map[string]any{"prompt": "scan kotlin repo", "locale": "ru"}},
		{name: "run_workflow", args: map[string]any{"workflowId": "wf_seed"}},
		{name: "get_run_status", args: map[string]any{"runId": "run_seed"}},
		{name: "get_findings", args: map[string]any{"runId": "run_seed", "minSeverity": "HIGH"}},
		{name: "get_ai_report", args: map[string]any{"runId": "run_seed"}},
		{name: "export_submission_json", args: map[string]any{"runId": "run_seed"}},
		{name: "get_sbom", args: map[string]any{"runId": "run_seed", "includeContent": true}},
	}
	for i, tc := range toolCalls {
		t.Run(tc.name, func(t *testing.T) {
			c, _, resp := env.postMCP(t, env.editorToken, sessionID, map[string]any{
				"jsonrpc": "2.0",
				"id":      100 + i,
				"method":  "tools/call",
				"params":  map[string]any{"name": tc.name, "arguments": tc.args},
			})
			if c != http.StatusOK || resp["error"] != nil {
				t.Fatalf("tool %s status=%d resp=%#v", tc.name, c, resp)
			}
		})
	}
}

func testMCPAllFiveResources(t *testing.T, env *gatewayTestEnv, sessionID string) {
	t.Helper()
	uris := []string{
		"secflow://plugins",
		"secflow://templates",
		"secflow://runs/run_seed/submission.json",
		"secflow://runs/run_seed/report.md",
		"secflow://runs/run_seed/sbom.cdx.json",
	}
	for i, uri := range uris {
		t.Run(uri, func(t *testing.T) {
			c, _, resp := env.postMCP(t, env.viewerToken, sessionID, map[string]any{
				"jsonrpc": "2.0",
				"id":      200 + i,
				"method":  "resources/read",
				"params":  map[string]any{"uri": uri},
			})
			if c != http.StatusOK || resp["error"] != nil {
				t.Fatalf("resource %s status=%d resp=%#v", uri, c, resp)
			}
		})
	}
	c, _, resp := env.postMCP(t, env.viewerToken, sessionID, map[string]any{
		"jsonrpc": "2.0", "id": 299, "method": "resources/read",
		"params": map[string]any{"uri": "secflow://unknown/item"},
	})
	if c != http.StatusOK || resp["error"] == nil {
		t.Fatalf("unknown resource expected JSON-RPC error, got status=%d resp=%#v", c, resp)
	}
}

func testMCPSSEDeleteAndErrors(t *testing.T, env *gatewayTestEnv, sessionID string) {
	t.Helper()
	sseCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(sseCtx, http.MethodGet, env.server.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("new SSE request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.viewerToken)
	req.Header.Set(mcpSessionHeader, sessionID)
	resp, err := env.client.Do(req)
	if err != nil {
		t.Fatalf("GET /mcp SSE: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		_ = resp.Body.Close()
		t.Fatalf("GET /mcp SSE status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	line, readErr := bufio.NewReader(resp.Body).ReadString('\n')
	cancel()
	_ = resp.Body.Close()
	if readErr != nil || !strings.Contains(line, "event: endpoint") {
		t.Fatalf("expected SSE endpoint event, got line=%q err=%v", line, readErr)
	}

	if c, _, _ := env.doRequest(t, http.MethodGet, "/mcp", env.viewerToken, nil, nil); c != http.StatusBadRequest {
		t.Fatalf("GET /mcp without session header status=%d, want 400", c)
	}
	if c, h, _ := env.doRequest(t, http.MethodDelete, "/mcp", env.viewerToken, map[string]string{mcpSessionHeader: sessionID}, nil); c != http.StatusNoContent || h.Get(mcpSessionHeader) != sessionID {
		t.Fatalf("DELETE /mcp status=%d sid=%q", c, h.Get(mcpSessionHeader))
	}
	if c, h, _ := env.doRequest(t, http.MethodPut, "/mcp", env.ownerToken, nil, nil); c != http.StatusMethodNotAllowed || h.Get("Allow") != "GET, POST, DELETE" {
		t.Fatalf("PUT /mcp status=%d allow=%q", c, h.Get("Allow"))
	}
	if c, _, _ := env.postMCP(t, "", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); c != http.StatusUnauthorized {
		t.Fatalf("unauth POST /mcp status=%d, want 401", c)
	}
	if c, _, _ := env.doRequest(t, http.MethodPost, "/mcp", env.ownerToken, map[string]string{"Content-Type": "application/json"}, strings.NewReader("{bad json")); c != http.StatusBadRequest {
		t.Fatalf("malformed POST /mcp status=%d, want 400", c)
	}
	if c, _, _ := env.postMCP(t, env.viewerToken, sessionID, map[string]any{
		"jsonrpc": "2.0", "id": 99, "method": "tools/call",
		"params": map[string]any{"name": "run_workflow", "arguments": map[string]any{"workflowId": "wf_seed"}},
	}); c != http.StatusForbidden {
		t.Fatalf("viewer run_workflow over MCP status=%d, want 403", c)
	}
}

// -----------------------------------------------------------------------------
// 6. GraphQL: ALL 22 Queries + ALL 18 Mutations + Protocol/RBAC/Tracing
// -----------------------------------------------------------------------------

var coveredGraphQLOps = struct {
	queries       []string
	mutations     []string
	subscriptions []string
}{
	queries: []string{
		"me",
		"workflow", "workflows", "validateWorkflow",
		"run", "runs", "findings", "nodeRunPayload", "sbom", "readableReport",
		"plugins", "plugin",
		"pluginInstallations", "pluginInstallation", "pluginPresets",
		"declarativePluginBlueprints", "savedNodes",
		"templates", "template",
		"catalogs",
		"aiProviderStatus", "aiAuditLogs",
		"secrets", "scopedTokens",
		"mcpConnections", "mcpConnectionTools",
		"webhookInspectorDeliveries",
	},
	mutations: []string{
		"login",
		"saveWorkflow", "deleteWorkflow",
		"startRun", "rerunFromNode", "cancelRun",
		"publishTemplate", "cloneTemplate",
		"generateCiConfig", "generateWorkflowFromText",
		"createSecret", "deleteSecret",
		"createScopedToken", "revokeScopedToken",
		"registerMcpConnection", "updateMcpConnection", "deleteMcpConnection", "testMcpConnection",
		"installPlugin", "approvePluginInstallation", "updatePluginInstallation",
		"setPluginInstallationEnabled", "deletePluginInstallation",
		"testDeclarativePlugin", "saveNode", "updateSavedNode", "deleteSavedNode",
	},
	subscriptions: []string{
		"runEvents",
		"pluginRegistryEvents",
		"pluginInstallationEvents",
		"webhookInspectorEvents",
	},
}

func TestIntegration_GraphQLAllQueriesAndMutations(t *testing.T) {
	t.Parallel()
	env := newGatewayTestEnv(t)

	t.Run("auth login me introspection OPTIONS and error mapping", func(t *testing.T) {
		testGraphQLAuthAndProtocol(t, env)
	})
	t.Run("workflows CRUD and validation", func(t *testing.T) {
		wfID := testGraphQLWorkflowsCRUD(t, env)
		testGraphQLTemplatesCIAndAI(t, env, wfID)
	})
	t.Run("runs findings payload sbom readableReport rerun cancel and plugins", func(t *testing.T) {
		testGraphQLRunsAndPlugins(t, env)
	})
	t.Run("secrets and scopedTokens lifecycle", func(t *testing.T) {
		testGraphQLSecretsAndScopedTokens(t, env)
	})
	t.Run("plugin installations presets RBAC lifecycle and includeDisabled", func(t *testing.T) {
		testGraphQLPluginInstallations(t, env)
	})
	t.Run("outbound MCP connections CRUD and discovery", func(t *testing.T) {
		testGraphQLOutboundMCP(t, env)
	})
}

func testGraphQLAuthAndProtocol(t *testing.T, env *gatewayTestEnv) {
	t.Helper()
	code, gql := env.postGraphQL(t, "", `mutation { login(input: {email: "owner@secflow.local", password: "wrong"}) { accessToken } }`, nil, nil)
	if code != http.StatusUnauthorized || firstErrorCode(gql.Errors) != "UNAUTHENTICATED" {
		t.Fatalf("bad login status=%d errs=%#v", code, gql.Errors)
	}

	meData := env.mustGraphQL(t, env.ownerToken, `{ __typename me { subject email role authMode scopes } }`, nil)
	me := mustMap(t, meData["me"], "me")
	if meData["__typename"] != "Query" || me["role"] != "OWNER" || me["authMode"] != "LOCAL" {
		t.Fatalf("unexpected me response: %#v", meData)
	}

	uCode, uGQL := env.postGraphQL(t, "", `{ me { subject } }`, nil, nil)
	if uCode != http.StatusUnauthorized || firstErrorCode(uGQL.Errors) != "UNAUTHENTICATED" {
		t.Fatalf("unauth me status=%d errs=%#v", uCode, uGQL.Errors)
	}

	intro := env.mustGraphQL(t, "", `{ __schema { queryType { name } } __type(name: "Run") { name kind } }`, nil)
	if mustMap(t, intro["__type"], "__type")["name"] != "Run" {
		t.Fatalf("unexpected introspection response: %#v", intro)
	}

	if optCode, _, _ := env.doRequest(t, http.MethodOptions, "/graphql", "", nil, nil); optCode != http.StatusOK && optCode != http.StatusNoContent {
		t.Fatalf("OPTIONS /graphql status=%d", optCode)
	}
	if badCode, badGQL := env.postGraphQL(t, env.ownerToken, `{ nonExistentField }`, nil, nil); badCode != http.StatusBadRequest || len(badGQL.Errors) == 0 {
		t.Fatalf("expected 400 validation error, got status=%d errs=%#v", badCode, badGQL.Errors)
	}

	tpCode, tpGQL := env.postGraphQL(t, env.viewerToken, `{ catalogs { id } }`, nil, map[string]string{"traceparent": integrationTraceparent})
	if tpCode != http.StatusOK || len(tpGQL.Errors) > 0 {
		t.Fatalf("catalogs with traceparent status=%d errs=%#v", tpCode, tpGQL.Errors)
	}
	if got := env.backend.lastTraceparent("ListCatalogs"); !strings.Contains(got, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("expected traceparent forwarded to ListCatalogs gRPC, got %q", got)
	}
}

func testGraphQLWorkflowsCRUD(t *testing.T, env *gatewayTestEnv) string {
	t.Helper()
	validGraph := map[string]any{
		"schemaVersion": 1,
		"nodes": []any{map[string]any{
			"id": "t1", "pluginId": "trigger.manual", "label": "Manual",
			"position": map[string]any{"x": 0, "y": 0}, "params": map[string]any{},
		}},
		"edges": []any{},
	}

	valOK := env.mustGraphQL(t, env.viewerToken, `query($g: WorkflowGraphInput!) { validateWorkflow(graph: $g) { valid issues { code } } }`, map[string]any{"g": validGraph})
	if mustMap(t, valOK["validateWorkflow"], "validateWorkflow")["valid"] != true {
		t.Fatalf("expected valid=true, got %#v", valOK)
	}
	valBad := env.mustGraphQL(t, env.viewerToken, `query($g: WorkflowGraphInput!) { validateWorkflow(graph: $g) { valid issues { code severity } } }`, map[string]any{
		"g": map[string]any{"schemaVersion": 1, "nodes": []any{}, "edges": []any{}},
	})
	if mustMap(t, valBad["validateWorkflow"], "validateWorkflow")["valid"] != false {
		t.Fatalf("expected valid=false for empty graph, got %#v", valBad)
	}

	if c, g := env.postGraphQL(t, env.viewerToken, `mutation($in: SaveWorkflowInput!) { saveWorkflow(input: $in) { id } }`, map[string]any{
		"in": map[string]any{"name": "Denied", "graph": validGraph},
	}, nil); c != http.StatusForbidden || firstErrorCode(g.Errors) != "FORBIDDEN" {
		t.Fatalf("viewer saveWorkflow status=%d errs=%#v", c, g.Errors)
	}

	created := env.mustGraphQL(t, env.editorToken, `mutation($in: SaveWorkflowInput!) { saveWorkflow(input: $in) { id version name } }`, map[string]any{
		"in": map[string]any{"name": "Integration WF", "description": "v1", "graph": validGraph},
	})
	wfID := mustString(t, mustMap(t, created["saveWorkflow"], "saveWorkflow")["id"], "wfID")

	updated := env.mustGraphQL(t, env.editorToken, `mutation($in: SaveWorkflowInput!) { saveWorkflow(input: $in) { id version name } }`, map[string]any{
		"in": map[string]any{"id": wfID, "expectedVersion": 1, "name": "Integration WF v2", "graph": validGraph},
	})
	if mustMap(t, updated["saveWorkflow"], "saveWorkflow")["version"] != float64(2) {
		t.Fatalf("expected version 2, got %#v", updated)
	}
	if _, g := env.postGraphQL(t, env.editorToken, `mutation($in: SaveWorkflowInput!) { saveWorkflow(input: $in) { id } }`, map[string]any{
		"in": map[string]any{"id": wfID, "expectedVersion": 1, "name": "Stale", "graph": validGraph},
	}, nil); firstErrorCode(g.Errors) != "CONFLICT" {
		t.Fatalf("expected CONFLICT on stale expectedVersion, got %#v", g.Errors)
	}

	gotWF := env.mustGraphQL(t, env.viewerToken, `query($id: ID!) { workflow(id: $id) { id name version } }`, map[string]any{"id": wfID})
	if mustMap(t, gotWF["workflow"], "workflow")["name"] != "Integration WF v2" {
		t.Fatalf("unexpected workflow: %#v", gotWF)
	}
	listedWFs := env.mustGraphQL(t, env.viewerToken, `{ workflows(search: "Integration WF", limit: 10) { items { id name } totalCount hasMore } }`, nil)
	if len(mustSlice(t, mustMap(t, listedWFs["workflows"], "workflows")["items"], "workflows.items")) != 1 {
		t.Fatalf("expected 1 filtered workflow, got %#v", listedWFs)
	}
	return wfID
}

func testGraphQLTemplatesCIAndAI(t *testing.T, env *gatewayTestEnv, wfID string) {
	t.Helper()
	pub := env.mustGraphQL(t, env.editorToken, `mutation($in: PublishTemplateInput!) { publishTemplate(input: $in) { id slug name tags } }`, map[string]any{
		"in": map[string]any{"workflowId": wfID, "name": "Published Guard", "description": "desc", "problemSolved": "solves ci", "tags": []string{"kotlin", "custom"}},
	})
	tplID := mustString(t, mustMap(t, pub["publishTemplate"], "publishTemplate")["id"], "tplID")

	tpls := env.mustGraphQL(t, env.viewerToken, `{ templates(tags: ["custom"], limit: 10) { items { id name } totalCount } }`, nil)
	if len(mustSlice(t, mustMap(t, tpls["templates"], "templates")["items"], "templates.items")) != 1 {
		t.Fatalf("expected 1 custom template, got %#v", tpls)
	}
	singleTpl := env.mustGraphQL(t, env.viewerToken, `query($id: ID!) { template(id: $id) { id slug sanitizedGraph { schemaVersion } } }`, map[string]any{"id": tplID})
	if mustMap(t, singleTpl["template"], "template")["id"] != tplID {
		t.Fatalf("unexpected template: %#v", singleTpl)
	}
	cloned := env.mustGraphQL(t, env.editorToken, `mutation($in: CloneTemplateInput!) { cloneTemplate(input: $in) { id name sourceTemplateId } }`, map[string]any{
		"in": map[string]any{"templateId": tplID, "newWorkflowName": "Cloned From Published"},
	})
	clonedID := mustString(t, mustMap(t, cloned["cloneTemplate"], "cloneTemplate")["id"], "clonedID")

	ciGH := env.mustGraphQL(t, env.viewerToken, `mutation($in: GenerateCiConfigInput!) { generateCiConfig(input: $in) { provider filename yamlContent requiredCiSecrets } }`, map[string]any{
		"in": map[string]any{"workflowId": wfID, "provider": "GITHUB_ACTIONS", "secflowBaseUrl": "https://secflow.local", "failOnSeverity": "CRITICAL", "failOnPolicyGate": false},
	})
	if mustMap(t, ciGH["generateCiConfig"], "generateCiConfig")["filename"] != ".github/workflows/secflow.yml" {
		t.Fatalf("unexpected github ci config: %#v", ciGH)
	}
	ciGL := env.mustGraphQL(t, env.viewerToken, `mutation($in: GenerateCiConfigInput!) { generateCiConfig(input: $in) { provider filename } }`, map[string]any{
		"in": map[string]any{"workflowId": wfID, "provider": "GITLAB_CI", "secflowBaseUrl": "https://secflow.local"},
	})
	if mustMap(t, ciGL["generateCiConfig"], "generateCiConfig")["filename"] != ".gitlab-ci.yml" {
		t.Fatalf("unexpected gitlab ci config: %#v", ciGL)
	}

	aiPrev := env.mustGraphQL(t, env.viewerToken, `mutation($in: GenerateWorkflowFromTextInput!) { generateWorkflowFromText(input: $in) { suggestedName rationale modelId providerMode missingFields { code } graph { schemaVersion } } }`, map[string]any{
		"in": map[string]any{"prompt": "scan kotlin spring app", "locale": "ru"},
	})
	if mustMap(t, aiPrev["generateWorkflowFromText"], "generateWorkflowFromText")["providerMode"] != "CLOUD" {
		t.Fatalf("unexpected generateWorkflowFromText: %#v", aiPrev)
	}
	aiStatus := env.mustGraphQL(t, env.viewerToken, `{ aiProviderStatus { providerMode modelId endpointHost closedLoop defaultPrivacyMode healthy } }`, nil)
	if mustMap(t, aiStatus["aiProviderStatus"], "aiProviderStatus")["closedLoop"] != true {
		t.Fatalf("unexpected aiProviderStatus: %#v", aiStatus)
	}
	aiAudit := env.mustGraphQL(t, env.viewerToken, `{ aiAuditLogs(runId: "run_seed", limit: 10) { items { id operation modelId quality } totalCount } }`, nil)
	if len(mustSlice(t, mustMap(t, aiAudit["aiAuditLogs"], "aiAuditLogs")["items"], "aiAuditLogs.items")) != 1 {
		t.Fatalf("unexpected aiAuditLogs: %#v", aiAudit)
	}
	cats := env.mustGraphQL(t, env.viewerToken, `{ catalogs { id name ecosystem snapshotDate advisoryCount isDefault } }`, nil)
	if len(mustSlice(t, cats["catalogs"], "catalogs")) == 0 {
		t.Fatalf("expected seeded catalogs, got %#v", cats)
	}

	del := env.mustGraphQL(t, env.editorToken, `mutation($id: ID!) { deleteWorkflow(id: $id) }`, map[string]any{"id": clonedID})
	if del["deleteWorkflow"] != true {
		t.Fatalf("expected deleteWorkflow=true, got %#v", del)
	}
	if _, g := env.postGraphQL(t, env.viewerToken, `query($id: ID!) { workflow(id: $id) { id } }`, map[string]any{"id": clonedID}, nil); firstErrorCode(g.Errors) != "NOT_FOUND" {
		t.Fatalf("expected NOT_FOUND after deleteWorkflow, got %#v", g.Errors)
	}
}

func testGraphQLRunsAndPlugins(t *testing.T, env *gatewayTestEnv) {
	t.Helper()
	started := env.mustGraphQL(t, env.editorToken, `mutation($in: StartRunInput!) { startRun(input: $in) { id workflowId status trigger { type repoUrl } } }`, map[string]any{
		"in": map[string]any{"workflowId": "wf_seed", "repoUrlOverride": "https://github.com/org/repo", "idempotencyKey": "k-1"},
	})
	startObj := mustMap(t, started["startRun"], "startRun")
	startedID := mustString(t, startObj["id"], "startedID")
	if startObj["status"] != "QUEUED" {
		t.Fatalf("unexpected startRun: %#v", started)
	}

	rerun := env.mustGraphQL(t, env.editorToken, `mutation($in: RerunFromNodeInput!) { rerunFromNode(input: $in) { id parentRunId rerunFromNodeId trigger { type } } }`, map[string]any{
		"in": map[string]any{"sourceRunId": "run_seed", "nodeId": "scan_1", "updatedParams": map[string]any{"strict": true}, "persistWorkflowChanges": false},
	})
	if mustMap(t, rerun["rerunFromNode"], "rerunFromNode")["parentRunId"] != "run_seed" {
		t.Fatalf("unexpected rerunFromNode: %#v", rerun)
	}

	cancelled := env.mustGraphQL(t, env.editorToken, `mutation($id: ID!) { cancelRun(runId: $id, reason: "operator stop") { id status errorMessage } }`, map[string]any{"id": startedID})
	if mustMap(t, cancelled["cancelRun"], "cancelRun")["status"] != "CANCELLED" {
		t.Fatalf("unexpected cancelRun: %#v", cancelled)
	}

	runRes := env.mustGraphQL(t, env.viewerToken, `{
		run(id: "run_seed") {
			id workflowName status traceId
			gateResult { status reason nodeId }
			findingsStats { total critical high sastCount scaCount maxSeverity }
			sbom { digest specVersion componentCount downloadUrl }
			aiReport { quality releaseDecision executiveSummary items { findingId finding { path line } } }
			nodeRuns { nodeRunId nodeId pluginId status }
			submissionDownloadUrl markdownReportDownloadUrl htmlReportDownloadUrl
		}
	}`, nil)
	rObj := mustMap(t, runRes["run"], "run")
	if rObj["aiReport"] == nil || rObj["sbom"] == nil || mustMap(t, rObj["findingsStats"], "findingsStats")["total"] != float64(2) {
		t.Fatalf("expected decorated run with stats/aiReport/sbom, got %#v", rObj)
	}

	runsRes := env.mustGraphQL(t, env.viewerToken, `{ runs(workflowId: "wf_seed", status: SUCCEEDED, limit: 10) { items { id status } totalCount } }`, nil)
	if len(mustSlice(t, mustMap(t, runsRes["runs"], "runs")["items"], "runs.items")) != 1 {
		t.Fatalf("expected 1 SUCCEEDED run for wf_seed, got %#v", runsRes)
	}
	fndRes := env.mustGraphQL(t, env.viewerToken, `{ findings(runId: "run_seed", category: SAST, minSeverity: HIGH, limit: 10) { items { findingId category findingClass line } stats { total high } totalCount } }`, nil)
	if len(mustSlice(t, mustMap(t, fndRes["findings"], "findings")["items"], "findings.items")) != 1 {
		t.Fatalf("expected 1 SAST HIGH finding, got %#v", fndRes)
	}
	plRes := env.mustGraphQL(t, env.viewerToken, `{ nodeRunPayload(runId: "run_seed", nodeId: "scan_1", sourceHandle: "default") { runId nodeId pluginId status inputEnvelope outputEnvelope activeOutputPorts portOutputs { sourceHandle outputEnvelope } } }`, nil)
	if mustMap(t, plRes["nodeRunPayload"], "nodeRunPayload")["pluginId"] != "scan.sast.kotlin" {
		t.Fatalf("unexpected nodeRunPayload: %#v", plRes)
	}
	sbomRes := env.mustGraphQL(t, env.viewerToken, `{ sbom(runId: "run_seed") { digest specVersion componentCount vulnerabilityCount downloadUrl } }`, nil)
	if mustMap(t, sbomRes["sbom"], "sbom")["downloadUrl"] != "/runs/run_seed/sbom.cdx.json" {
		t.Fatalf("unexpected sbom: %#v", sbomRes)
	}
	mdRes := env.mustGraphQL(t, env.viewerToken, `{ readableReport(runId: "run_seed", format: MARKDOWN) { format content findingCount downloadUrl } }`, nil)
	if mustMap(t, mdRes["readableReport"], "readableReport")["downloadUrl"] != "/runs/run_seed/report.md" {
		t.Fatalf("unexpected markdown readableReport: %#v", mdRes)
	}
	htmlRes := env.mustGraphQL(t, env.viewerToken, `{ readableReport(runId: "run_seed", format: HTML) { format content downloadUrl } }`, nil)
	if mustMap(t, htmlRes["readableReport"], "readableReport")["format"] != "HTML" {
		t.Fatalf("unexpected html readableReport: %#v", htmlRes)
	}

	onlinePlugs := env.mustGraphQL(t, env.viewerToken, `{ plugins(includeOffline: false) { pluginId status } }`, nil)
	if len(mustSlice(t, onlinePlugs["plugins"], "plugins")) != 1 {
		t.Fatalf("expected 1 online plugin, got %#v", onlinePlugs)
	}
	allPlugs := env.mustGraphQL(t, env.viewerToken, `{ plugins(includeOffline: true) { pluginId status } }`, nil)
	if len(mustSlice(t, allPlugs["plugins"], "plugins")) != 2 {
		t.Fatalf("expected 2 total plugins with includeOffline=true, got %#v", allPlugs)
	}
	onePlug := env.mustGraphQL(t, env.viewerToken, `{ plugin(pluginId: "scan.sast.kotlin") { pluginId displayName category paramsJsonSchema } }`, nil)
	if mustMap(t, onePlug["plugin"], "plugin")["category"] != "ANALYZER" {
		t.Fatalf("unexpected plugin: %#v", onePlug)
	}
}

func testGraphQLSecretsAndScopedTokens(t *testing.T, env *gatewayTestEnv) {
	t.Helper()
	if c, _ := env.postGraphQL(t, env.viewerToken, `{ secrets { secretRef } }`, nil, nil); c != http.StatusForbidden {
		t.Fatalf("viewer secrets status=%d, want 403", c)
	}
	crSec := env.mustGraphQL(t, env.editorToken, `mutation($in: CreateSecretInput!) { createSecret(input: $in) { secretRef name kind maskedPreview backend } }`, map[string]any{
		"in": map[string]any{"name": "tg-token", "kind": "TELEGRAM_BOT_TOKEN", "plaintextValue": "123456:RAW_SECRET_VALUE"},
	})
	secObj := mustMap(t, crSec["createSecret"], "createSecret")
	secRef := mustString(t, secObj["secretRef"], "secretRef")
	if strings.Contains(mustString(t, secObj["maskedPreview"], "maskedPreview"), "RAW_SECRET_VALUE") {
		t.Fatalf("plaintext secret leaked in maskedPreview: %#v", crSec)
	}
	listSec := env.mustGraphQL(t, env.editorToken, `{ secrets(kind: TELEGRAM_BOT_TOKEN) { secretRef name } }`, nil)
	if len(mustSlice(t, listSec["secrets"], "secrets")) != 1 {
		t.Fatalf("expected 1 TELEGRAM_BOT_TOKEN secret, got %#v", listSec)
	}
	if del := env.mustGraphQL(t, env.editorToken, `mutation($ref: ID!) { deleteSecret(secretRef: $ref) }`, map[string]any{"ref": secRef}); del["deleteSecret"] != true {
		t.Fatalf("expected deleteSecret=true, got %#v", del)
	}

	if c, _ := env.postGraphQL(t, env.editorToken, `{ scopedTokens { tokenId } }`, nil, nil); c != http.StatusForbidden {
		t.Fatalf("editor scopedTokens status=%d, want 403", c)
	}
	issued := env.mustGraphQL(t, env.ownerToken, `mutation($in: CreateScopedTokenInput!) { createScopedToken(input: $in) { plaintextToken metadata { tokenId name scopes workflowId } } }`, map[string]any{
		"in": map[string]any{
			"name": "ci-e2e-token", "scopes": []string{"ci:startRun", "ci:readRun"},
			"workflowId": "wf_seed", "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	})
	tokObj := mustMap(t, issued["createScopedToken"], "createScopedToken")
	plainTok := mustString(t, tokObj["plaintextToken"], "plaintextToken")
	tokID := mustString(t, mustMap(t, tokObj["metadata"], "metadata")["tokenId"], "tokenId")

	ciRun := env.mustGraphQL(t, plainTok, `mutation { startRun(input: {workflowId: "wf_seed"}) { id trigger { type } } }`, nil)
	if mustMap(t, mustMap(t, ciRun["startRun"], "startRun")["trigger"], "trigger")["type"] != "CI_API" {
		t.Fatalf("expected CI_API trigger for ci:startRun token, got %#v", ciRun)
	}
	if c, _ := env.postGraphQL(t, plainTok, `mutation { startRun(input: {workflowId: "wf_other"}) { id } }`, nil, nil); c != http.StatusForbidden {
		t.Fatalf("scoped token cross-workflow startRun status=%d, want 403", c)
	}
	listTok := env.mustGraphQL(t, env.ownerToken, `{ scopedTokens { tokenId name } }`, nil)
	if len(mustSlice(t, listTok["scopedTokens"], "scopedTokens")) == 0 {
		t.Fatalf("expected issued scoped token in list")
	}
	if rev := env.mustGraphQL(t, env.ownerToken, `mutation($id: ID!) { revokeScopedToken(tokenId: $id) }`, map[string]any{"id": tokID}); rev["revokeScopedToken"] != true {
		t.Fatalf("expected revokeScopedToken=true")
	}
	if c, _ := env.postGraphQL(t, plainTok, `{ me { subject } }`, nil, nil); c != http.StatusUnauthorized {
		t.Fatalf("revoked token status=%d, want 401", c)
	}
}

func testGraphQLOutboundMCP(t *testing.T, env *gatewayTestEnv) {
	t.Helper()
	if c, _ := env.postGraphQL(t, env.editorToken, `mutation { deleteMcpConnection(id: "mcp_seed") }`, nil, nil); c != http.StatusForbidden {
		t.Fatalf("editor deleteMcpConnection status=%d, want 403", c)
	}
	regMCP := env.mustGraphQL(t, env.ownerToken, `mutation($in: RegisterMCPConnectionInput!) { registerMcpConnection(input: $in) { id enabled config { name endpointUrl } } }`, map[string]any{
		"in": map[string]any{"config": map[string]any{"name": "Slack MCP", "endpointUrl": "https://mcp.example.local/slack", "allowedTools": []string{"notify_ticket"}}},
	})
	mcpID := mustString(t, mustMap(t, regMCP["registerMcpConnection"], "registerMcpConnection")["id"], "mcpID")

	conns := env.mustGraphQL(t, env.viewerToken, `{ mcpConnections { id enabled config { name } } }`, nil)
	if len(mustSlice(t, conns["mcpConnections"], "mcpConnections")) < 2 {
		t.Fatalf("expected >= 2 mcpConnections, got %#v", conns)
	}
	connTools := env.mustGraphQL(t, env.viewerToken, `query($id: ID!) { mcpConnectionTools(connectionId: $id, forceRefresh: true) { connectionId blockedToolCount tools { name inputSchema } } }`, map[string]any{"id": mcpID})
	if mustMap(t, connTools["mcpConnectionTools"], "mcpConnectionTools")["connectionId"] != mcpID {
		t.Fatalf("unexpected mcpConnectionTools: %#v", connTools)
	}
	testRes := env.mustGraphQL(t, env.ownerToken, `mutation($id: ID!) { testMcpConnection(id: $id) { ok serverName serverVersion availableToolCount blockedToolCount } }`, map[string]any{"id": mcpID})
	if mustMap(t, testRes["testMcpConnection"], "testMcpConnection")["ok"] != true {
		t.Fatalf("unexpected testMcpConnection: %#v", testRes)
	}
	updMCP := env.mustGraphQL(t, env.ownerToken, `mutation($in: UpdateMCPConnectionInput!) { updateMcpConnection(input: $in) { id enabled config { name } } }`, map[string]any{
		"in": map[string]any{"id": mcpID, "enabled": false, "config": map[string]any{"name": "Slack MCP Updated", "endpointUrl": "https://mcp.example.local/slack"}},
	})
	if mustMap(t, updMCP["updateMcpConnection"], "updateMcpConnection")["enabled"] != false {
		t.Fatalf("unexpected updateMcpConnection: %#v", updMCP)
	}
	if del := env.mustGraphQL(t, env.ownerToken, `mutation($id: ID!) { deleteMcpConnection(id: $id) }`, map[string]any{"id": mcpID}); del["deleteMcpConnection"] != true {
		t.Fatalf("expected deleteMcpConnection=true")
	}
}

// -----------------------------------------------------------------------------
// 7. GraphQL Subscriptions (WS /graphql): ALL 3 Subscription fields + Auth + Rate Limit
// -----------------------------------------------------------------------------

func TestIntegration_GraphQLAllSubscriptions(t *testing.T) {
	t.Parallel()
	env := newGatewayTestEnv(t)

	t.Run("runEvents streams gRPC WatchRun events and enforces scoped workflow", func(t *testing.T) {
		conn := env.openGraphQLWS(t, map[string]any{"Authorization": "Bearer " + env.viewerToken, "traceparent": integrationTraceparent})
		if err := conn.WriteJSON(map[string]any{
			"id": "sub-run-1", "type": "subscribe",
			"payload": map[string]any{"query": `subscription { runEvents(runId: "run_seed", afterSeq: 1) { seqId runId eventType nodeId nodeStatus message } }`},
		}); err != nil {
			t.Fatalf("subscribe runEvents: %v", err)
		}
		msg := readWSJSON(t, conn)
		if msg["type"] != "next" {
			t.Fatalf("expected next frame for runEvents, got %#v", msg)
		}
		ev := mustMap(t, mustMap(t, mustMap(t, msg["payload"], "payload")["data"], "data")["runEvents"], "runEvents")
		if ev["seqId"] != float64(2) || ev["eventType"] != "NODE_STATUS_CHANGED" || ev["nodeId"] != "scan_1" {
			t.Fatalf("unexpected runEvents payload: %#v", ev)
		}
		if done := readWSJSON(t, conn); done["type"] != "complete" {
			t.Fatalf("expected complete frame after stream ends, got %#v", done)
		}

		tokData := env.mustGraphQL(t, env.ownerToken, `mutation($in: CreateScopedTokenInput!) { createScopedToken(input: $in) { plaintextToken } }`, map[string]any{
			"in": map[string]any{"name": "ws-ci", "scopes": []string{"ci:readRun"}, "workflowId": "wf_seed"},
		})
		scTok := mustString(t, mustMap(t, tokData["createScopedToken"], "createScopedToken")["plaintextToken"], "plaintextToken")
		scConn := env.openGraphQLWS(t, map[string]any{"Authorization": "Bearer " + scTok})
		if err := scConn.WriteJSON(map[string]any{
			"id": "sub-denied", "type": "subscribe",
			"payload": map[string]any{"query": `subscription { runEvents(runId: "run_other") { seqId } }`},
		}); err != nil {
			t.Fatalf("subscribe denied runEvents: %v", err)
		}
		if errMsg := readWSJSON(t, scConn); errMsg["type"] != "error" {
			t.Fatalf("expected WS error for cross-workflow scoped token, got %#v", errMsg)
		}
	})

	t.Run("pluginRegistryEvents streams gRPC WatchPlugins events", func(t *testing.T) {
		conn := env.openGraphQLWS(t, map[string]any{"Authorization": "Bearer " + env.viewerToken})
		if err := conn.WriteJSON(map[string]any{
			"id": "sub-plug-1", "type": "subscribe",
			"payload": map[string]any{"query": `subscription { pluginRegistryEvents { eventType occurredAt plugin { pluginId displayName isExternal status installationId enabled approvalPending } } }`},
		}); err != nil {
			t.Fatalf("subscribe pluginRegistryEvents: %v", err)
		}
		msg := readWSJSON(t, conn)
		if msg["type"] != "next" {
			t.Fatalf("expected next frame for pluginRegistryEvents, got %#v", msg)
		}
		ev := mustMap(t, mustMap(t, mustMap(t, msg["payload"], "payload")["data"], "data")["pluginRegistryEvents"], "pluginRegistryEvents")
		plug := mustMap(t, ev["plugin"], "plugin")
		if ev["eventType"] != "REGISTERED" || plug["pluginId"] != "sandbox.hotplug" {
			t.Fatalf("unexpected pluginRegistryEvents payload: %#v", ev)
		}
	})

	t.Run("pluginInstallationEvents streams gRPC WatchPluginInstallations events", func(t *testing.T) {
		instData := env.mustGraphQL(t, env.ownerToken, `
			mutation {
				installPlugin(input: { name: "ws-inst", sourceMode: EXTERNAL_PULL, sandboxProfile: INTERNAL_ONLY }) {
					installation { id status }
					plaintextPluginToken
				}
			}`, nil)
		instID := mustString(t, mustMap(t, mustMap(t, instData["installPlugin"], "installPlugin")["installation"], "installation")["id"], "id")

		conn := env.openGraphQLWS(t, map[string]any{"Authorization": "Bearer " + env.viewerToken})
		if err := conn.WriteJSON(map[string]any{
			"id": "sub-inst-1", "type": "subscribe",
			"payload": map[string]any{
				"query": `subscription($id: ID) { pluginInstallationEvents(installationId: $id) { eventType occurredAt installation { id name status } } }`,
				"variables": map[string]any{
					"id": instID,
				},
			},
		}); err != nil {
			t.Fatalf("subscribe pluginInstallationEvents: %v", err)
		}
		msg := readWSJSON(t, conn)
		if msg["type"] != "next" {
			t.Fatalf("expected next frame for pluginInstallationEvents, got %#v", msg)
		}
		ev := mustMap(t, mustMap(t, mustMap(t, msg["payload"], "payload")["data"], "data")["pluginInstallationEvents"], "pluginInstallationEvents")
		inst := mustMap(t, ev["installation"], "installation")
		if ev["eventType"] != "CREATED" || inst["id"] != instID {
			t.Fatalf("unexpected pluginInstallationEvents payload: %#v", ev)
		}
	})

	t.Run("webhookInspectorEvents receives live HTTP POST delivery over WS", func(t *testing.T) {
		conn := env.openGraphQLWS(t, map[string]any{"Authorization": "Bearer " + env.viewerToken})
		if err := conn.WriteJSON(map[string]any{
			"id": "sub-insp-1", "type": "subscribe",
			"payload": map[string]any{"query": `subscription { webhookInspectorEvents(channelKey: "live_chan_99") { id channelKey method body hmacValid } }`},
		}); err != nil {
			t.Fatalf("subscribe webhookInspectorEvents: %v", err)
		}

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			env.gw.mu.Lock()
			n := len(env.gw.subs["live_chan_99"])
			env.gw.mu.Unlock()
			if n > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		if postCode, _, postRaw := env.doRequest(t, http.MethodPost, "/webhooks/inspector/live_chan_99", "", map[string]string{
			"Content-Type": "application/json",
		}, bytes.NewReader([]byte(`{"ping":"live"}`))); postCode != http.StatusOK {
			t.Fatalf("POST live inspector status=%d body=%s", postCode, string(postRaw))
		}
		msg := readWSJSON(t, conn)
		if msg["type"] != "next" {
			t.Fatalf("expected next frame for webhookInspectorEvents, got %#v", msg)
		}
		ev := mustMap(t, mustMap(t, mustMap(t, msg["payload"], "payload")["data"], "data")["webhookInspectorEvents"], "webhookInspectorEvents")
		if ev["channelKey"] != "live_chan_99" || mustMap(t, ev["body"], "body")["ping"] != "live" {
			t.Fatalf("unexpected live webhookInspectorEvents payload: %#v", ev)
		}
	})

	t.Run("unauthenticated WS subscription fails and rate-limited endpoints return 429", func(t *testing.T) {
		conn := env.openGraphQLWS(t, map[string]any{})
		if err := conn.WriteJSON(map[string]any{
			"id": "sub-unauth", "type": "subscribe",
			"payload": map[string]any{"query": `subscription { pluginRegistryEvents { eventType } }`},
		}); err != nil {
			t.Fatalf("subscribe unauth: %v", err)
		}
		if msg := readWSJSON(t, conn); msg["type"] != "error" {
			t.Fatalf("expected error for unauthenticated subscription, got %#v", msg)
		}

		rlEnv := newGatewayTestEnv(t)
		rlEnv.gw.rateLimitCheck = func(context.Context, string) bool { return true }

		if c, g := rlEnv.postGraphQL(t, rlEnv.viewerToken, `{ me { subject } }`, nil, nil); c != http.StatusTooManyRequests || firstErrorCode(g.Errors) != "RATE_LIMITED" {
			t.Fatalf("rate limited POST /graphql status=%d errs=%#v", c, g.Errors)
		}

		wsURL := "ws" + strings.TrimPrefix(rlEnv.server.URL, "http") + "/graphql"
		_, resp, err := gorilla.DefaultDialer.DialContext(t.Context(), wsURL, http.Header{
			"Authorization": []string{"Bearer " + rlEnv.viewerToken},
		})
		if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected 429 on rate-limited WS handshake, got resp=%#v err=%v", resp, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		mcpCode, _, mcpResp := rlEnv.postMCP(t, rlEnv.viewerToken, "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"})
		if mcpCode != http.StatusTooManyRequests {
			t.Fatalf("rate limited POST /mcp status=%d resp=%#v", mcpCode, mcpResp)
		}
		var errObj map[string]any
		if rawErr, ok := mcpResp["error"]; ok {
			b, _ := json.Marshal(rawErr)
			_ = json.Unmarshal(b, &errObj)
		}
		if errObj["message"] != "RATE_LIMITED" {
			t.Fatalf("expected RATE_LIMITED MCP error, got %#v", mcpResp)
		}
	})
}

// -----------------------------------------------------------------------------
// 8. Exhaustive Schema Parity Guard: fails if any schema operation is untested
// -----------------------------------------------------------------------------

func testGraphQLPluginInstallations(t *testing.T, env *gatewayTestEnv) {
	t.Helper()

	presetsData := env.mustGraphQL(t, env.viewerToken, `{ pluginPresets { id name imageRef category sandboxProfile pluginIds autoApproveSupported } }`, nil)
	presets := mustSlice(t, presetsData["pluginPresets"], "pluginPresets")
	if len(presets) == 0 || mustMap(t, presets[0], "preset[0]")["id"] != "spring-config-hardening" {
		t.Fatalf("unexpected pluginPresets: %#v", presets)
	}

	// RBAC: EDITOR and VIEWER cannot mutate plugin installations.
	for _, tok := range []string{env.viewerToken, env.editorToken} {
		_, g := env.postGraphQL(t, tok, `mutation { installPlugin(input: { name: "denied", sourceMode: EXTERNAL_PULL }) { installation { id } } }`, nil, nil)
		if firstErrorCode(g.Errors) != "FORBIDDEN" {
			t.Fatalf("expected FORBIDDEN for non-owner installPlugin, got %#v", g.Errors)
		}
	}

	// OWNER creates an EXTERNAL_PULL installation and receives one-time plaintextPluginToken.
	created := env.mustGraphQL(t, env.ownerToken, `
		mutation {
			installPlugin(input: {
				name: "spring-ext",
				sourceMode: EXTERNAL_PULL,
				sandboxProfile: INTERNAL_ONLY,
				desiredReplicas: 1
			}) {
				installation { id name sourceMode status sandboxProfile desiredReplicas }
				plaintextPluginToken
			}
		}`, nil)
	installPayload := mustMap(t, created["installPlugin"], "installPlugin")
	inst := mustMap(t, installPayload["installation"], "installation")
	instID := mustString(t, inst["id"], "id")
	if !strings.HasPrefix(mustString(t, installPayload["plaintextPluginToken"], "plaintextPluginToken"), "sf_plg_") {
		t.Fatalf("expected sf_plg_ token, got %#v", installPayload["plaintextPluginToken"])
	}

	// VIEWER can read list & single installation.
	listData := env.mustGraphQL(t, env.viewerToken, `{ pluginInstallations { id name status runtimeDiagnostics { phase readyReplicas } } }`, nil)
	if len(mustSlice(t, listData["pluginInstallations"], "pluginInstallations")) == 0 {
		t.Fatalf("expected non-empty pluginInstallations")
	}
	getData := env.mustGraphQL(t, env.viewerToken, `query($id: ID!) { pluginInstallation(id: $id) { id name status } }`, map[string]any{"id": instID})
	if mustMap(t, getData["pluginInstallation"], "pluginInstallation")["id"] != instID {
		t.Fatalf("unexpected pluginInstallation: %#v", getData)
	}

	// OWNER approves installation -> plugin appears in Query.plugins with installationId & enabled=true.
	approved := env.mustGraphQL(t, env.ownerToken, `mutation($id: ID!) { approvePluginInstallation(input: { installationId: $id }) { id status approvedBy } }`, map[string]any{"id": instID})
	if mustMap(t, approved["approvePluginInstallation"], "approve")["status"] != "ACTIVE" {
		t.Fatalf("expected ACTIVE after approve, got %#v", approved)
	}

	// OWNER updates installation and rotates token.
	updated := env.mustGraphQL(t, env.ownerToken, `mutation($id: ID!) { updatePluginInstallation(input: { installationId: $id, desiredReplicas: 2, rotateToken: true }) { installation { id desiredReplicas } plaintextPluginToken } }`, map[string]any{"id": instID})
	updPayload := mustMap(t, updated["updatePluginInstallation"], "updatePluginInstallation")
	if !strings.HasPrefix(mustString(t, updPayload["plaintextPluginToken"], "rotatedToken"), "sf_plg_") {
		t.Fatalf("expected rotated plaintext token, got %#v", updPayload)
	}

	// OWNER disables installation -> plugin hidden by default, visible with includeDisabled: true.
	disabled := env.mustGraphQL(t, env.ownerToken, `mutation($id: ID!) { setPluginInstallationEnabled(input: { installationId: $id, enabled: false, reason: "maintenance" }) { id status statusReason } }`, map[string]any{"id": instID})
	if mustMap(t, disabled["setPluginInstallationEnabled"], "disabled")["status"] != "DISABLED" {
		t.Fatalf("expected DISABLED, got %#v", disabled)
	}
	defaultPlugs := mustSlice(t, env.mustGraphQL(t, env.viewerToken, `{ plugins { pluginId enabled installationId } }`, nil)["plugins"], "plugins")
	for _, raw := range defaultPlugs {
		if mustMap(t, raw, "plugin")["pluginId"] == "scan.spring-config" {
			t.Fatalf("disabled plugin must not appear in default plugins query")
		}
	}
	allPlugs := mustSlice(t, env.mustGraphQL(t, env.viewerToken, `{ plugins(includeDisabled: true) { pluginId enabled installationId approvalPending } }`, nil)["plugins"], "plugins")
	foundDisabled := false
	for _, raw := range allPlugs {
		pm := mustMap(t, raw, "plugin")
		if pm["pluginId"] == "scan.spring-config" && pm["enabled"] == false && pm["installationId"] == instID {
			foundDisabled = true
		}
	}
	if !foundDisabled {
		t.Fatalf("expected disabled plugin in plugins(includeDisabled: true), got %#v", allPlugs)
	}

	// OWNER deletes installation.
	delData := env.mustGraphQL(t, env.ownerToken, `mutation($id: ID!) { deletePluginInstallation(id: $id, reason: "cleanup") }`, map[string]any{"id": instID})
	if delData["deletePluginInstallation"] != true {
		t.Fatalf("expected deletePluginInstallation=true, got %#v", delData)
	}
}

func TestIntegration_GraphQLSchemaExhaustiveCoverage(t *testing.T) {
	t.Parallel()
	schema, err := loadSchema()
	if err != nil {
		t.Fatalf("loadSchema: %v", err)
	}

	assertAllFieldsCovered := func(kind string, schemaFields []string, tested []string) {
		t.Helper()
		seen := make(map[string]bool, len(tested))
		for _, f := range tested {
			seen[f] = true
		}
		var missing []string
		for _, f := range schemaFields {
			if strings.HasPrefix(f, "__") {
				continue
			}
			if !seen[f] {
				missing = append(missing, f)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s fields missing from integration tests: %v", kind, missing)
		}
	}

	collectNames := func(typeName string) []string {
		def := schema.Types[typeName]
		if def == nil {
			t.Fatalf("schema missing root type %s", typeName)
		}
		out := make([]string, 0, len(def.Fields))
		for _, f := range def.Fields {
			out = append(out, f.Name)
		}
		return out
	}

	assertAllFieldsCovered("Query", collectNames("Query"), coveredGraphQLOps.queries)
	assertAllFieldsCovered("Mutation", collectNames("Mutation"), coveredGraphQLOps.mutations)
	assertAllFieldsCovered("Subscription", collectNames("Subscription"), coveredGraphQLOps.subscriptions)
}
