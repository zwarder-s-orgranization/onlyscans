package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
	"github.com/secflow/secflow/services/internal/oidc"
)

type fakeSecretClient struct {
	secflowv1.SecretServiceClient
	tokens map[string]*secflowv1.ActorContext
}

func (f *fakeSecretClient) VerifyScopedToken(_ context.Context, req *secflowv1.VerifyScopedTokenRequest, _ ...grpc.CallOption) (*secflowv1.VerifyScopedTokenResponse, error) {
	actor, ok := f.tokens[req.GetPlaintextToken()]
	if !ok {
		return &secflowv1.VerifyScopedTokenResponse{Valid: false}, nil
	}
	return &secflowv1.VerifyScopedTokenResponse{Valid: true, TokenId: actor.GetSubject(), Actor: actor}, nil
}

type fakeWorkflowClient struct {
	secflowv1.WorkflowServiceClient
	workflows map[string]*secflowv1.Workflow
}

func (f *fakeWorkflowClient) GetWorkflow(_ context.Context, req *secflowv1.GetWorkflowRequest, _ ...grpc.CallOption) (*secflowv1.GetWorkflowResponse, error) {
	wf, ok := f.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return &secflowv1.GetWorkflowResponse{Workflow: wf}, nil
}

func (f *fakeWorkflowClient) ListWorkflows(_ context.Context, _ *secflowv1.ListWorkflowsRequest, _ ...grpc.CallOption) (*secflowv1.ListWorkflowsResponse, error) {
	var out []*secflowv1.Workflow
	for _, wf := range f.workflows {
		out = append(out, wf)
	}
	return &secflowv1.ListWorkflowsResponse{Workflows: out}, nil
}

func (f *fakeWorkflowClient) ListTemplates(_ context.Context, _ *secflowv1.ListTemplatesRequest, _ ...grpc.CallOption) (*secflowv1.ListTemplatesResponse, error) {
	return &secflowv1.ListTemplatesResponse{Templates: []*secflowv1.WorkflowTemplate{{Id: "tpl_1", Slug: "s1", Name: "T1"}}}, nil
}

func (f *fakeWorkflowClient) CloneTemplate(_ context.Context, req *secflowv1.CloneTemplateRequest, _ ...grpc.CallOption) (*secflowv1.CloneTemplateResponse, error) {
	return &secflowv1.CloneTemplateResponse{Workflow: &secflowv1.Workflow{Id: "wf_cloned", Name: req.GetNewWorkflowName()}}, nil
}

type fakeRunClient struct {
	secflowv1.RunServiceClient
	runs map[string]*secflowv1.Run
}

func (f *fakeRunClient) StartRun(_ context.Context, req *secflowv1.StartRunRequest, _ ...grpc.CallOption) (*secflowv1.StartRunResponse, error) {
	return &secflowv1.StartRunResponse{Run: &secflowv1.Run{Id: "run_new", WorkflowId: req.GetWorkflowId(), Status: secflowv1.RunStatus_RUN_STATUS_QUEUED}}, nil
}

func (f *fakeRunClient) GetRun(_ context.Context, req *secflowv1.GetRunRequest, _ ...grpc.CallOption) (*secflowv1.GetRunResponse, error) {
	r, ok := f.runs[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	return &secflowv1.GetRunResponse{Run: r}, nil
}

func (f *fakeRunClient) ListRuns(_ context.Context, req *secflowv1.ListRunsRequest, _ ...grpc.CallOption) (*secflowv1.ListRunsResponse, error) {
	var out []*secflowv1.Run
	for _, r := range f.runs {
		if req.GetWorkflowId() == "" || r.GetWorkflowId() == req.GetWorkflowId() {
			out = append(out, r)
		}
	}
	return &secflowv1.ListRunsResponse{Runs: out}, nil
}

func (f *fakeRunClient) ListFindings(_ context.Context, _ *secflowv1.ListFindingsRequest, _ ...grpc.CallOption) (*secflowv1.ListFindingsResponse, error) {
	return &secflowv1.ListFindingsResponse{}, nil
}

func (f *fakeRunClient) GetAIReport(_ context.Context, _ *secflowv1.GetAIReportRequest, _ ...grpc.CallOption) (*secflowv1.GetAIReportResponse, error) {
	return &secflowv1.GetAIReportResponse{Report: &secflowv1.AIReport{ExecutiveSummary: "ok"}}, nil
}

func (f *fakeRunClient) GetSubmissionReport(_ context.Context, _ *secflowv1.GetSubmissionReportRequest, _ ...grpc.CallOption) (*secflowv1.GetSubmissionReportResponse, error) {
	return &secflowv1.GetSubmissionReportResponse{SubmissionJson: []byte(`{"findings":[]}`)}, nil
}

func (f *fakeRunClient) GetSbom(_ context.Context, _ *secflowv1.GetSbomRequest, _ ...grpc.CallOption) (*secflowv1.GetSbomResponse, error) {
	return &secflowv1.GetSbomResponse{Sbom: &secflowv1.SbomRef{Digest: "sha256:abc", SpecVersion: "1.6"}, CyclonedxJson: []byte(`{"bomFormat":"CycloneDX"}`)}, nil
}

func (f *fakeRunClient) GetReadableReport(_ context.Context, _ *secflowv1.GetReadableReportRequest, _ ...grpc.CallOption) (*secflowv1.GetReadableReportResponse, error) {
	return &secflowv1.GetReadableReportResponse{Content: []byte("# Report")}, nil
}

type fakeAIClient struct {
	secflowv1.AIServiceClient
}

func (fakeAIClient) GenerateWorkflow(_ context.Context, _ *secflowv1.GenerateWorkflowRequest, _ ...grpc.CallOption) (*secflowv1.GenerateWorkflowResponse, error) {
	return &secflowv1.GenerateWorkflowResponse{SuggestedName: "Preview", Graph: &secflowv1.WorkflowGraph{SchemaVersion: 1}}, nil
}

type fakePluginClient struct {
	secflowv1.PluginRegistryServiceClient
}

func (fakePluginClient) ListPlugins(_ context.Context, _ *secflowv1.ListPluginsRequest, _ ...grpc.CallOption) (*secflowv1.ListPluginsResponse, error) {
	return &secflowv1.ListPluginsResponse{}, nil
}

func TestGraphQLAuthAndSchema(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{schema: schema, secret: []byte("test-secret")}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ workflows { totalCount } }"}`))
	gw.graphql(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ missingField }"}`))
	gw.graphql(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "errors") {
		t.Fatalf("validation status %d body %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"mutation { login(input: {email: \"owner@secflow.local\", password: \"secflow\"}) { accessToken tokenType actor { role } } }"}`))
	gw.graphql(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "accessToken") {
		t.Fatalf("login status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestValidateGatewayConfig(t *testing.T) {
	tests := []struct {
		name         string
		secflowEnv   string
		authMode     string
		jwtSecret    string
		serviceToken string
		wantErr      bool
	}{
		{name: "dev allows defaults", secflowEnv: "development", authMode: "local", wantErr: false},
		{name: "prod missing jwt secret fails in local mode", secflowEnv: "production", authMode: "local", serviceToken: "svc", wantErr: true},
		{name: "prod missing service token fails", secflowEnv: "production", authMode: "local", jwtSecret: "jwt", wantErr: true},
		{name: "prod oidc allows empty jwt secret with service token", secflowEnv: "production", authMode: "oidc", serviceToken: "svc", wantErr: false},
		{name: "prod local with both secrets succeeds", secflowEnv: "production", authMode: "local", jwtSecret: "jwt", serviceToken: "svc", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGatewayConfig(tt.secflowEnv, tt.authMode, tt.jwtSecret, tt.serviceToken)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateGatewayConfig() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLocalLogin_DBUsersAndProductionNoDefault(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}

	// Production without AUTH_USERS must NOT fall back to hardcoded owner@secflow.local.
	t.Setenv("SECFLOW_ENV", "production")
	t.Setenv("AUTH_USERS", "")
	gwProd := &gateway{schema: schema, secret: []byte("prod-secret")}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"mutation { login(input: {email: \"owner@secflow.local\", password: \"secflow\"}) { accessToken } }"}`))
	gwProd.graphql(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("prod default login status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}

	// DB users lookup verifies sha256 password hash via constant-time compare.
	sum := sha256.Sum256([]byte("salt1:s3cr3t"))
	storedHash := "sha256:salt1:" + hex.EncodeToString(sum[:])
	gwDB := &gateway{
		schema: schema,
		secret: []byte("prod-secret"),
		userLookup: func(_ context.Context, email string) (string, string, bool, error) {
			if email == "alice@secflow.local" {
				return storedHash, "editor", true, nil
			}
			return "", "", false, nil
		},
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"mutation { login(input: {email: \"alice@secflow.local\", password: \"s3cr3t\"}) { accessToken actor { role } } }"}`))
	gwDB.graphql(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"EDITOR"`) {
		t.Fatalf("db login status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"mutation { login(input: {email: \"alice@secflow.local\", password: \"wrong\"}) { accessToken } }"}`))
	gwDB.graphql(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("db bad password status=%d, want 401", rec.Code)
	}

	// Salted hash helper generates a hash accepted by verifyPasswordHash and rejected for wrong password.
	salted, err := hashPasswordSalted("s3cr3t")
	if err != nil || !strings.HasPrefix(salted, "sha256:") {
		t.Fatalf("hashPasswordSalted = (%q, %v)", salted, err)
	}
	if !verifyPasswordHash(salted, "s3cr3t") || verifyPasswordHash(salted, "wrong") {
		t.Fatalf("verifyPasswordHash mismatch for salted hash %q", salted)
	}

	// When DB returns not found (pgx.ErrNoRows equivalent) in local mode, fall back to configured env user
	// while still strictly verifying the configured password.
	t.Setenv("SECFLOW_ENV", "development")
	t.Setenv("AUTH_MODE", "local")
	t.Setenv("AUTH_USERS", "owner@secflow.local:secflow:owner,alice@secflow.local:envpass:owner")
	if role, ok := gwDB.checkUser(t.Context(), "owner@secflow.local", "secflow"); !ok || role != "owner" {
		t.Fatalf("expected fallback to configured local user on DB not-found, got (%q, %v)", role, ok)
	}
	if _, ok := gwDB.checkUser(t.Context(), "owner@secflow.local", "wrong"); ok {
		t.Fatal("fallback to configured local user must reject wrong password")
	}
	// If the user EXISTS in DB with a different password, NEVER fall back to env password.
	if _, ok := gwDB.checkUser(t.Context(), "alice@secflow.local", "envpass"); ok {
		t.Fatal("existing DB user with wrong password must not fall back to env user")
	}

	// Missing users table error falls back in dev, but fails closed in production.
	gwMissingTable := &gateway{
		schema: schema,
		secret: []byte("dev-secret"),
		userLookup: func(_ context.Context, _ string) (string, string, bool, error) {
			return "", "", false, errors.New(`ERROR: relation "users" does not exist (SQLSTATE 42P01)`)
		},
	}
	if role, ok := gwMissingTable.checkUser(t.Context(), "owner@secflow.local", "secflow"); !ok || role != "owner" {
		t.Fatalf("expected dev fallback on missing users table, got (%q, %v)", role, ok)
	}
	t.Setenv("SECFLOW_ENV", "production")
	if _, ok := gwMissingTable.checkUser(t.Context(), "owner@secflow.local", "secflow"); ok {
		t.Fatal("production must not fall back when users table query errors")
	}
}

func TestBearer_OIDCNeverAcceptsLocalHS256AndVerifiesScopedToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwksDoc, err := oidc.PublicJWK("k1", &rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksDoc)
	}))
	defer jwksSrv.Close()

	t.Setenv("AUTH_MODE", "oidc")
	t.Setenv("OIDC_JWKS_URL", jwksSrv.URL)

	gw := &gateway{
		secret: []byte("local-hs256-secret"),
		secs: &fakeSecretClient{
			tokens: map[string]*secflowv1.ActorContext{
				"sf_ci_validtoken": {
					Subject:          "tok_1",
					Scopes:           []string{"ci:startRun"},
					ScopedWorkflowId: "wf_1",
					AuthMode:         secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN,
				},
			},
		},
	}

	// Local HS256 JWT MUST be rejected when AUTH_MODE=oidc.
	localJWT, err := auth.Sign(gw.secret, auth.Claims{Subject: "owner", Role: "owner", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	reqLocal := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	reqLocal.Header.Set("Authorization", "Bearer "+localJWT)
	if _, err := gw.bearer(reqLocal); err == nil {
		t.Fatal("OIDC mode must reject local HS256 JWT")
	}

	// RS256 OIDC JWT MUST be accepted.
	payload, _ := json.Marshal(map[string]any{"sub": "oidc-user", "email": "u@corp", "role": "editor", "exp": time.Now().Add(time.Hour).Unix()})
	oidcJWT, err := oidc.SignForTest("k1", rsaKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	reqOIDC := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	reqOIDC.Header.Set("Authorization", "Bearer "+oidcJWT)
	claims, err := gw.bearer(reqOIDC)
	if err != nil || claims.Subject != "oidc-user" || claims.Role != "editor" {
		t.Fatalf("OIDC jwt bearer = (%+v, %v)", claims, err)
	}

	// Scoped token MUST be accepted via SecretService.VerifyScopedToken even in OIDC mode.
	reqScoped := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	reqScoped.Header.Set("Authorization", "Bearer sf_ci_validtoken")
	sc, err := gw.bearer(reqScoped)
	if err != nil || sc.Subject != "tok_1" || sc.Wf != "wf_1" || len(sc.Scopes) != 1 || sc.Scopes[0] != "ci:startRun" {
		t.Fatalf("scoped bearer = (%+v, %v)", sc, err)
	}
}

func TestRBACMatrix(t *testing.T) {
	ciStart := &auth.Claims{Subject: "tok_ci_s", Scopes: []string{"ci:startRun"}, Wf: "wf_1"}
	ciRead := &auth.Claims{Subject: "tok_ci_r", Scopes: []string{"ci:readRun"}, Wf: "wf_1"}
	mcpRead := &auth.Claims{Subject: "tok_mcp_r", Scopes: []string{"mcp:read"}}
	mcpRun := &auth.Claims{Subject: "tok_mcp_run", Scopes: []string{"mcp:run"}}
	mcpWrite := &auth.Claims{Subject: "tok_mcp_w", Scopes: []string{"mcp:write"}}
	viewer := &auth.Claims{Subject: "v", Role: "viewer"}
	editor := &auth.Claims{Subject: "e", Role: "editor"}
	owner := &auth.Claims{Subject: "o", Role: "owner"}

	forbiddenForAllScoped := []string{
		"mcpConnections", "mcpConnectionTools", "aiAuditLogs", "webhookInspectorDeliveries",
		"generateCiConfig", "secrets", "scopedTokens", "createSecret", "deleteSecret",
		"createScopedToken", "revokeScopedToken", "createWorkflow", "updateWorkflow",
		"saveWorkflow", "deleteWorkflow", "publishTemplate",
		"registerMcpConnection", "updateMcpConnection", "deleteMcpConnection", "testMcpConnection",
		"rerunFromNode", "cancelRun",
	}
	for _, c := range []*auth.Claims{ciStart, ciRead, mcpRead, mcpRun, mcpWrite} {
		for _, field := range forbiddenForAllScoped {
			if allowed(field, c) {
				t.Errorf("scoped token %v MUST NOT access %q", c.Scopes, field)
			}
		}
	}

	tests := []struct {
		name   string
		field  string
		claims *auth.Claims
		want   bool
	}{
		{"ci:startRun allows startRun", "startRun", ciStart, true},
		{"ci:startRun denies run", "run", ciStart, false},
		{"ci:readRun allows run", "run", ciRead, true},
		{"ci:readRun allows runs", "runs", ciRead, true},
		{"ci:readRun allows findings", "findings", ciRead, true},
		{"ci:readRun allows submission", "submission", ciRead, true},
		{"ci:readRun allows sbom", "sbom", ciRead, true},
		{"ci:readRun allows aiReport", "aiReport", ciRead, true},
		{"ci:readRun allows readableReport", "readableReport", ciRead, true},
		{"ci:readRun denies workflows", "workflows", ciRead, false},
		{"ci:readRun denies startRun", "startRun", ciRead, false},
		{"mcp:read allows workflows", "workflows", mcpRead, true},
		{"mcp:read allows workflow", "workflow", mcpRead, true},
		{"mcp:read allows templates", "templates", mcpRead, true},
		{"mcp:read allows template", "template", mcpRead, true},
		{"mcp:read allows plugins", "plugins", mcpRead, true},
		{"mcp:read allows plugin", "plugin", mcpRead, true},
		{"mcp:read allows nodePayload", "nodePayload", mcpRead, true},
		{"mcp:read allows nodeRunPayload", "nodeRunPayload", mcpRead, true},
		{"mcp:read allows validateWorkflow", "validateWorkflow", mcpRead, true},
		{"mcp:read allows generateWorkflowFromText", "generateWorkflowFromText", mcpRead, true},
		{"mcp:read denies startRun", "startRun", mcpRead, false},
		{"mcp:read denies cloneTemplate", "cloneTemplate", mcpRead, false},
		{"mcp:run allows startRun", "startRun", mcpRun, true},
		{"mcp:run denies workflows", "workflows", mcpRun, false},
		{"mcp:write allows cloneTemplate", "cloneTemplate", mcpWrite, true},
		{"mcp:write denies generateWorkflowFromText", "generateWorkflowFromText", mcpWrite, false},
		{"mcp:write denies validateWorkflow", "validateWorkflow", mcpWrite, false},
		{"mcp:write denies startRun", "startRun", mcpWrite, false},
		{"viewer reads mcpConnections", "mcpConnections", viewer, true},
		{"viewer allows validateWorkflow", "validateWorkflow", viewer, true},
		{"viewer allows generateWorkflowFromText", "generateWorkflowFromText", viewer, true},
		{"viewer denied secrets", "secrets", viewer, false},
		{"editor reads secrets", "secrets", editor, true},
		{"editor denied scopedTokens", "scopedTokens", editor, false},
		{"owner accesses scopedTokens", "scopedTokens", owner, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allowed(tt.field, tt.claims); got != tt.want {
				t.Fatalf("allowed(%q, %+v) = %v, want %v", tt.field, tt.claims, got, tt.want)
			}
		})
	}
}

func TestScopedWorkflowEnforcement_GraphQLAndHTTP(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{
		schema: schema,
		secret: []byte("test-secret"),
		secs: &fakeSecretClient{
			tokens: map[string]*secflowv1.ActorContext{
				"sf_ci_wf1": {
					Subject:          "tok_wf1",
					Scopes:           []string{"ci:startRun", "ci:readRun"},
					ScopedWorkflowId: "wf_1",
				},
			},
		},
		wf: &fakeWorkflowClient{
			workflows: map[string]*secflowv1.Workflow{
				"wf_1": {Id: "wf_1", Name: "WF 1"},
				"wf_2": {Id: "wf_2", Name: "WF 2"},
			},
		},
		runs: &fakeRunClient{
			runs: map[string]*secflowv1.Run{
				"run_1": {Id: "run_1", WorkflowId: "wf_1", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
				"run_2": {Id: "run_2", WorkflowId: "wf_2", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
			},
		},
	}

	doGQL := func(query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]string{"query": query})
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer sf_ci_wf1")
		gw.graphql(rec, req)
		return rec
	}

	// startRun on wf_1 allowed, wf_2 forbidden.
	if rec := doGQL(`mutation { startRun(input: {workflowId: "wf_1"}) { id } }`); rec.Code != http.StatusOK {
		t.Fatalf("startRun wf_1 status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := doGQL(`mutation { startRun(input: {workflowId: "wf_2"}) { id } }`); rec.Code != http.StatusForbidden {
		t.Fatalf("startRun wf_2 status=%d, want 403, body=%s", rec.Code, rec.Body.String())
	}

	// run/findings/sbom/readableReport on run_2 (belongs to wf_2) forbidden, run_1 allowed.
	for _, q := range []string{
		`{ run(id: "run_2") { id } }`,
		`{ runs(workflowId: "wf_2") { totalCount } }`,
		`{ findings(runId: "run_2") { totalCount } }`,
		`{ sbom(runId: "run_2") { digest } }`,
		`{ readableReport(runId: "run_2") { content } }`,
	} {
		if rec := doGQL(q); rec.Code != http.StatusForbidden {
			t.Fatalf("query %s status=%d, want 403, body=%s", q, rec.Code, rec.Body.String())
		}
	}
	if rec := doGQL(`{ run(id: "run_1") { id } }`); rec.Code != http.StatusOK {
		t.Fatalf("run_1 status=%d body=%s", rec.Code, rec.Body.String())
	}

	// HTTP /runs/{id}/submission.json enforces scopedWorkflowId.
	recOther := httptest.NewRecorder()
	reqOther := httptest.NewRequest(http.MethodGet, "/runs/run_2/submission.json", nil)
	reqOther.Header.Set("Authorization", "Bearer sf_ci_wf1")
	gw.runFile(recOther, reqOther)
	if recOther.Code != http.StatusForbidden {
		t.Fatalf("/runs/run_2/submission.json status=%d, want 403", recOther.Code)
	}

	recOwn := httptest.NewRecorder()
	reqOwn := httptest.NewRequest(http.MethodGet, "/runs/run_1/submission.json", nil)
	reqOwn.Header.Set("Authorization", "Bearer sf_ci_wf1")
	gw.runFile(recOwn, reqOwn)
	if recOwn.Code != http.StatusOK {
		t.Fatalf("/runs/run_1/submission.json status=%d, want 200", recOwn.Code)
	}
}

func TestMCPAuthAndAllTenTools(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{
		schema: schema,
		secret: []byte("test-secret"),
		secs: &fakeSecretClient{
			tokens: map[string]*secflowv1.ActorContext{
				"sf_mcp_read":  {Subject: "t_r", Scopes: []string{"mcp:read"}, ScopedWorkflowId: "wf_1"},
				"sf_mcp_run":   {Subject: "t_run", Scopes: []string{"mcp:run"}, ScopedWorkflowId: "wf_1"},
				"sf_mcp_write": {Subject: "t_w", Scopes: []string{"mcp:write"}},
				"sf_ci_start":  {Subject: "t_ci", Scopes: []string{"ci:startRun"}, ScopedWorkflowId: "wf_1"},
			},
		},
		wf: &fakeWorkflowClient{
			workflows: map[string]*secflowv1.Workflow{
				"wf_1": {Id: "wf_1", Name: "WF 1"},
				"wf_2": {Id: "wf_2", Name: "WF 2"},
			},
		},
		runs: &fakeRunClient{
			runs: map[string]*secflowv1.Run{
				"run_1": {Id: "run_1", WorkflowId: "wf_1", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
				"run_2": {Id: "run_2", WorkflowId: "wf_2", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
			},
		},
		ai:    fakeAIClient{},
		plugs: fakePluginClient{},
	}

	callMCP := func(token, method string, params map[string]any) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body)))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		gw.mcpHTTP(rec, req)
		return rec
	}

	// Zero anonymous access on any MCP method or tool.
	for _, m := range []string{"initialize", "tools/list", "resources/list", "resources/read", "tools/call"} {
		if rec := callMCP("", m, map[string]any{"name": "list_templates"}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous /mcp %s status=%d, want 401", m, rec.Code)
		}
	}

	// mcp:read can call tools/list, resources/list, resources/read, and all 8 read/preview tools.
	for _, m := range []string{"tools/list", "resources/list"} {
		if rec := callMCP("sf_mcp_read", m, nil); rec.Code != http.StatusOK {
			t.Fatalf("mcp:read %s status=%d body=%s", m, rec.Code, rec.Body.String())
		}
	}
	if rec := callMCP("sf_mcp_read", "resources/read", map[string]any{"uri": "secflow://plugins"}); rec.Code != http.StatusOK {
		t.Fatalf("mcp:read resources/read status=%d body=%s", rec.Code, rec.Body.String())
	}
	readTools := []struct {
		name string
		args map[string]any
	}{
		{"list_workflows", nil},
		{"list_templates", nil},
		{"generate_workflow_preview", map[string]any{"prompt": "scan kotlin"}},
		{"get_run_status", map[string]any{"runId": "run_1"}},
		{"get_findings", map[string]any{"runId": "run_1"}},
		{"get_ai_report", map[string]any{"runId": "run_1"}},
		{"export_submission_json", map[string]any{"runId": "run_1"}},
		{"get_sbom", map[string]any{"runId": "run_1"}},
	}
	for _, rt := range readTools {
		if rec := callMCP("sf_mcp_read", "tools/call", map[string]any{"name": rt.name, "arguments": rt.args}); rec.Code != http.StatusOK {
			t.Fatalf("mcp:read tool %s status=%d body=%s", rt.name, rec.Code, rec.Body.String())
		}
	}

	// mcp:read is FORBIDDEN on run_2 (different workflow), clone_template, run_workflow.
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"get_run_status", map[string]any{"runId": "run_2"}},
		{"get_findings", map[string]any{"runId": "run_2"}},
		{"get_ai_report", map[string]any{"runId": "run_2"}},
		{"export_submission_json", map[string]any{"runId": "run_2"}},
		{"get_sbom", map[string]any{"runId": "run_2"}},
		{"clone_template", map[string]any{"templateId": "tpl_1", "newWorkflowName": "X"}},
		{"run_workflow", map[string]any{"workflowId": "wf_1"}},
	} {
		if rec := callMCP("sf_mcp_read", "tools/call", map[string]any{"name": tc.name, "arguments": tc.args}); rec.Code != http.StatusForbidden {
			t.Fatalf("mcp:read tool %s(%v) status=%d, want 403, body=%s", tc.name, tc.args, rec.Code, rec.Body.String())
		}
	}

	// mcp:run allows run_workflow on wf_1, denies wf_2 and read/write tools.
	if rec := callMCP("sf_mcp_run", "tools/call", map[string]any{"name": "run_workflow", "arguments": map[string]any{"workflowId": "wf_1"}}); rec.Code != http.StatusOK {
		t.Fatalf("mcp:run run_workflow wf_1 status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := callMCP("sf_mcp_run", "tools/call", map[string]any{"name": "run_workflow", "arguments": map[string]any{"workflowId": "wf_2"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp:run run_workflow wf_2 status=%d, want 403", rec.Code)
	}
	if rec := callMCP("sf_mcp_run", "tools/call", map[string]any{"name": "list_workflows"}); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp:run list_workflows status=%d, want 403", rec.Code)
	}

	// mcp:write allows clone_template, denies run_workflow.
	if rec := callMCP("sf_mcp_write", "tools/call", map[string]any{"name": "clone_template", "arguments": map[string]any{"templateId": "tpl_1", "newWorkflowName": "Copy"}}); rec.Code != http.StatusOK {
		t.Fatalf("mcp:write clone_template status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := callMCP("sf_mcp_write", "tools/call", map[string]any{"name": "run_workflow", "arguments": map[string]any{"workflowId": "wf_1"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp:write run_workflow status=%d, want 403", rec.Code)
	}

	// CI scoped token cannot invoke MCP tools.
	if rec := callMCP("sf_ci_start", "tools/call", map[string]any{"name": "run_workflow", "arguments": map[string]any{"workflowId": "wf_1"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("ci:startRun on /mcp status=%d, want 403", rec.Code)
	}
}

func TestWebSocketScopedTokenAuth(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{
		schema: schema,
		secret: []byte("test-secret"),
		secs: &fakeSecretClient{
			tokens: map[string]*secflowv1.ActorContext{
				"sf_ci_ws": {
					Subject:          "tok_ws",
					Scopes:           []string{"ci:readRun"},
					ScopedWorkflowId: "wf_1",
				},
			},
		},
		runs: &fakeRunClient{
			runs: map[string]*secflowv1.Run{
				"run_2": {Id: "run_2", WorkflowId: "wf_2"},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(gw.sockets))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, err := websocket.Dial(wsURL, "", "http://localhost:3000")
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	defer conn.Close()

	// Authenticate with scoped token via connection_init.
	if err := websocket.JSON.Send(conn, map[string]any{
		"type":    "connection_init",
		"payload": map[string]any{"Authorization": "Bearer sf_ci_ws"},
	}); err != nil {
		t.Fatalf("send init: %v", err)
	}
	var ack map[string]any
	if err := websocket.JSON.Receive(conn, &ack); err != nil || ack["type"] != "connection_ack" {
		t.Fatalf("ack = %+v, err=%v", ack, err)
	}

	// Subscribing to run_2 (belongs to wf_2) must be rejected with FORBIDDEN.
	if err := websocket.JSON.Send(conn, map[string]any{
		"type":    "subscribe",
		"id":      "sub-1",
		"payload": map[string]any{"query": `subscription { runEvents(runId: "run_2") { seqId } }`},
	}); err != nil {
		t.Fatalf("send sub: %v", err)
	}
	var resp map[string]any
	if err := websocket.JSON.Receive(conn, &resp); err != nil {
		t.Fatalf("recv error: %v", err)
	}
	if resp["type"] != "error" {
		t.Fatalf("expected error for cross-workflow subscription, got %+v", resp)
	}
}

func TestGraphQLErrMapping(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{"denylist marker maps to DENYLIST_BLOCKED", status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: trivy"), "DENYLIST_BLOCKED"},
		{"scanner blocked marker maps to DENYLIST_BLOCKED", status.Error(codes.FailedPrecondition, "scanner blocked by policy"), "DENYLIST_BLOCKED"},
		{"generic failed precondition does not map to DENYLIST_BLOCKED", status.Error(codes.FailedPrecondition, "local login disabled"), "FAILED_PRECONDITION"},
		{"already exists maps to CONFLICT", status.Error(codes.AlreadyExists, "duplicate key"), "CONFLICT"},
		{"aborted maps to CONFLICT", status.Error(codes.Aborted, "version mismatch"), "CONFLICT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ge := graphqlErr(tt.err)
			if got := asString(ge.Extensions["code"]); got != tt.wantCode {
				t.Fatalf("graphqlErr(%v) code = %q, want %q", tt.err, got, tt.wantCode)
			}
		})
	}
}

func TestWebSocketRateLimitBeforeUpgrade(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{
		schema: schema,
		secret: []byte("test-secret"),
		rateLimitCheck: func(_ context.Context, _ string) bool {
			return true
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	gw.graphql(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited WS upgrade status = %d, want 429, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"RATE_LIMITED"`) {
		t.Fatalf("expected RATE_LIMITED body, got %s", rec.Body.String())
	}
}
