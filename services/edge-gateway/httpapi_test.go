package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gorilla "github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
)

type stubIngestClient struct {
	secflowv1.SourceIngesterServiceClient
	fn func(ctx context.Context, req *secflowv1.IngestUploadRequest) (*secflowv1.IngestUploadResponse, error)
}

func (s *stubIngestClient) IngestUpload(ctx context.Context, req *secflowv1.IngestUploadRequest, _ ...grpc.CallOption) (*secflowv1.IngestUploadResponse, error) {
	return s.fn(ctx, req)
}

type stubCatalogClient struct {
	secflowv1.CatalogServiceClient
	lastReq *secflowv1.RegisterCatalogRequest
	resp    *secflowv1.RegisterCatalogResponse
	err     error
}

func (s *stubCatalogClient) RegisterCatalog(_ context.Context, req *secflowv1.RegisterCatalogRequest, _ ...grpc.CallOption) (*secflowv1.RegisterCatalogResponse, error) {
	s.lastReq = req
	if s.err != nil {
		return nil, s.err
	}
	if s.resp != nil {
		return s.resp, nil
	}
	return &secflowv1.RegisterCatalogResponse{
		Catalog: &secflowv1.VulnerabilityCatalog{
			Id:            "cat_1",
			Name:          req.GetName(),
			Ecosystem:     "Maven",
			VersionFormat: "numeric-dot-separated",
			S3Key:         req.GetS3Key(),
			Sha256:        req.GetSha256(),
			SnapshotDate:  req.GetSnapshotDate(),
			AdvisoryCount: req.GetAdvisoryCount(),
			IsDefault:     req.GetSetAsDefault(),
			UploadedBy:    req.GetActor().GetSubject(),
			CreatedAt:     timestamppb.Now(),
		},
	}, nil
}

type stubPluginClient struct {
	secflowv1.PluginRegistryServiceClient
	plugins []*secflowv1.RegisteredPlugin
	err     error
	lastReq *secflowv1.ListPluginsRequest
}

func (s *stubPluginClient) ListPlugins(_ context.Context, req *secflowv1.ListPluginsRequest, _ ...grpc.CallOption) (*secflowv1.ListPluginsResponse, error) {
	s.lastReq = req
	if s.err != nil {
		return nil, s.err
	}
	return &secflowv1.ListPluginsResponse{Plugins: s.plugins}, nil
}

type stubWorkflowClientRich struct {
	secflowv1.WorkflowServiceClient
	workflows        map[string]*secflowv1.Workflow
	templates        []*secflowv1.WorkflowTemplate
	validateResp     *secflowv1.ValidateWorkflowResponse
	lastPublishReq   *secflowv1.PublishTemplateRequest
	lastValidateReq  *secflowv1.ValidateWorkflowRequest
	lastTemplatesReq *secflowv1.ListTemplatesRequest
}

func (s *stubWorkflowClientRich) GetWorkflow(_ context.Context, req *secflowv1.GetWorkflowRequest, _ ...grpc.CallOption) (*secflowv1.GetWorkflowResponse, error) {
	wf, ok := s.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return &secflowv1.GetWorkflowResponse{Workflow: wf}, nil
}

func (s *stubWorkflowClientRich) ListTemplates(_ context.Context, req *secflowv1.ListTemplatesRequest, _ ...grpc.CallOption) (*secflowv1.ListTemplatesResponse, error) {
	s.lastTemplatesReq = req
	return &secflowv1.ListTemplatesResponse{Templates: s.templates}, nil
}

func (s *stubWorkflowClientRich) PublishTemplate(_ context.Context, req *secflowv1.PublishTemplateRequest, _ ...grpc.CallOption) (*secflowv1.PublishTemplateResponse, error) {
	s.lastPublishReq = req
	return &secflowv1.PublishTemplateResponse{
		Template: &secflowv1.WorkflowTemplate{
			Id:            "tpl_pub",
			Slug:          "pub",
			Name:          req.GetName(),
			Description:   req.GetDescription(),
			ProblemSolved: req.GetProblemSolved(),
			Tags:          req.GetTags(),
			CreatedAt:     timestamppb.Now(),
			UpdatedAt:     timestamppb.Now(),
		},
	}, nil
}

func (s *stubWorkflowClientRich) ValidateWorkflow(_ context.Context, req *secflowv1.ValidateWorkflowRequest, _ ...grpc.CallOption) (*secflowv1.ValidateWorkflowResponse, error) {
	s.lastValidateReq = req
	if s.validateResp != nil {
		return s.validateResp, nil
	}
	return &secflowv1.ValidateWorkflowResponse{Valid: true}, nil
}

type stubRunClientRich struct {
	secflowv1.RunServiceClient
	runs         []*secflowv1.Run
	runByID      map[string]*secflowv1.Run
	startReq     *secflowv1.StartRunRequest
	rerunReq     *secflowv1.RerunFromNodeRequest
	listRunsReq  *secflowv1.ListRunsRequest
	getRunErr    error
	findingsResp *secflowv1.ListFindingsResponse
	aiReportResp *secflowv1.GetAIReportResponse
	sbomResp     *secflowv1.GetSbomResponse
}

func (s *stubRunClientRich) StartRun(_ context.Context, req *secflowv1.StartRunRequest, _ ...grpc.CallOption) (*secflowv1.StartRunResponse, error) {
	s.startReq = req
	return &secflowv1.StartRunResponse{
		Run: &secflowv1.Run{Id: "run_started", WorkflowId: req.GetWorkflowId(), Status: secflowv1.RunStatus_RUN_STATUS_QUEUED},
	}, nil
}

func (s *stubRunClientRich) RerunFromNode(_ context.Context, req *secflowv1.RerunFromNodeRequest, _ ...grpc.CallOption) (*secflowv1.RerunFromNodeResponse, error) {
	s.rerunReq = req
	return &secflowv1.RerunFromNodeResponse{
		Run: &secflowv1.Run{Id: "run_rerun", WorkflowId: "wf_1", ParentRunId: req.GetSourceRunId(), RerunFromNodeId: req.GetNodeId(), Status: secflowv1.RunStatus_RUN_STATUS_QUEUED},
	}, nil
}

func (s *stubRunClientRich) GetRun(_ context.Context, req *secflowv1.GetRunRequest, _ ...grpc.CallOption) (*secflowv1.GetRunResponse, error) {
	if s.getRunErr != nil {
		return nil, s.getRunErr
	}
	if r, ok := s.runByID[req.GetRunId()]; ok {
		return &secflowv1.GetRunResponse{Run: r}, nil
	}
	return nil, status.Error(codes.NotFound, "run not found")
}

func (s *stubRunClientRich) ListRuns(_ context.Context, req *secflowv1.ListRunsRequest, _ ...grpc.CallOption) (*secflowv1.ListRunsResponse, error) {
	s.listRunsReq = req
	return &secflowv1.ListRunsResponse{Runs: s.runs}, nil
}

func (s *stubRunClientRich) ListFindings(_ context.Context, _ *secflowv1.ListFindingsRequest, _ ...grpc.CallOption) (*secflowv1.ListFindingsResponse, error) {
	if s.findingsResp != nil {
		return s.findingsResp, nil
	}
	return &secflowv1.ListFindingsResponse{}, nil
}

func (s *stubRunClientRich) GetAIReport(_ context.Context, _ *secflowv1.GetAIReportRequest, _ ...grpc.CallOption) (*secflowv1.GetAIReportResponse, error) {
	if s.aiReportResp != nil {
		return s.aiReportResp, nil
	}
	return &secflowv1.GetAIReportResponse{}, nil
}

func (s *stubRunClientRich) GetSbom(_ context.Context, _ *secflowv1.GetSbomRequest, _ ...grpc.CallOption) (*secflowv1.GetSbomResponse, error) {
	if s.sbomResp != nil {
		return s.sbomResp, nil
	}
	return &secflowv1.GetSbomResponse{}, nil
}

type stubSecretClientRich struct {
	secflowv1.SecretServiceClient
	secrets []*secflowv1.SecretMetadata
	lastReq *secflowv1.ListMaskedSecretsRequest
}

func (s *stubSecretClientRich) ListMaskedSecrets(_ context.Context, req *secflowv1.ListMaskedSecretsRequest, _ ...grpc.CallOption) (*secflowv1.ListMaskedSecretsResponse, error) {
	s.lastReq = req
	return &secflowv1.ListMaskedSecretsResponse{Secrets: s.secrets}, nil
}

type stubAIClientRich struct {
	secflowv1.AIServiceClient
	rationale string
}

func (s *stubAIClientRich) GenerateWorkflow(_ context.Context, _ *secflowv1.GenerateWorkflowRequest, _ ...grpc.CallOption) (*secflowv1.GenerateWorkflowResponse, error) {
	return &secflowv1.GenerateWorkflowResponse{
		SuggestedName:        "Kotlin Gate",
		SuggestedDescription: "Auto generated",
		Rationale:            s.rationale,
		Graph:                &secflowv1.WorkflowGraph{SchemaVersion: 1},
		ModelId:              "gpt-4o-mini",
		ProviderMode:         secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
	}, nil
}

func signTestToken(t *testing.T, secret []byte, role string) string {
	t.Helper()
	tok, err := auth.Sign(secret, auth.Claims{
		Subject: role + "@secflow.local",
		Email:   role + "@secflow.local",
		Role:    role,
		Exp:     time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("auth.Sign: %v", err)
	}
	return tok
}

func TestGraphQLFragmentsIntrospectionAndErrors(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("test-secret")
	now := timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	started := timestamppb.New(time.Date(2026, 5, 1, 12, 0, 5, 0, time.UTC))
	finished := timestamppb.New(time.Date(2026, 5, 1, 12, 1, 0, 0, time.UTC))

	runStub := &stubRunClientRich{
		runByID: map[string]*secflowv1.Run{
			"run_full": {
				Id:              "run_full",
				WorkflowId:      "wf_1",
				WorkflowVersion: 3,
				Status:          secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
				Trigger: &secflowv1.TriggerMetadata{
					Type:        secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
					RepoUrl:     "https://github.com/org/repo",
					Branch:      "main",
					CommitSha:   "deadbeef",
					GitProvider: secflowv1.GitProvider_GIT_PROVIDER_GITHUB,
					TriggeredAt: now,
				},
				SourceRef: &secflowv1.SourceRef{
					SourceId:  "src_1",
					Sha256:    strings.Repeat("a", 64),
					RepoName:  "demo-repo",
					SizeBytes: 1024,
					FileCount: 12,
				},
				GateResult: &secflowv1.GateResult{
					Status: secflowv1.GateStatus_GATE_STATUS_FAIL,
					Reason: "CRITICAL finding detected",
					NodeId: "gate_1",
				},
				Sbom: &secflowv1.SbomRef{
					Digest:             "sha256:sbom",
					SpecVersion:        "1.6",
					ComponentCount:     42,
					VulnerabilityCount: 2,
					GeneratedAt:        now,
				},
				AiReport: &secflowv1.AIReport{
					Quality:          secflowv1.AIQuality_AI_QUALITY_VERIFIED,
					ReleaseDecision:  secflowv1.ReleaseDecision_RELEASE_DECISION_BLOCK,
					ExecutiveSummary: "Block release",
					ModelId:          "gpt-4o-mini",
					ProviderMode:     secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
					PrivacyMode:      secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET,
					PromptHash:       "phash",
					CreatedAt:        now,
				},
				NodeRuns: []*secflowv1.NodeRun{
					{
						NodeRunId:         "nr_1",
						RunId:             "run_full",
						NodeId:            "scan_1",
						PluginId:          "scan.secrets",
						Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
						Attempt:           1,
						ActiveOutputPorts: []string{"default"},
						FindingsEmitted:   3,
						DurationMs:        250,
						StartedAt:         started,
						FinishedAt:        finished,
					},
				},
				TraceId:      "trace-abc",
				ErrorMessage: "partial warning",
				LastSeqId:    17,
				CreatedAt:    now,
				StartedAt:    started,
				FinishedAt:   finished,
			},
		},
	}

	wfStub := &stubWorkflowClientRich{
		workflows: map[string]*secflowv1.Workflow{
			"wf_1": {Id: "wf_1", Name: "Primary AppSec Gate"},
		},
		validateResp: &secflowv1.ValidateWorkflowResponse{
			Valid: false,
			Issues: []*secflowv1.ValidationIssue{
				{
					Code:      "UNKNOWN_PLUGIN",
					Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
					Message:   `плагин "bad.plugin" не зарегистрирован в реестре`,
					NodeId:    "n1",
					FieldPath: "pluginId",
				},
			},
		},
	}

	gw := &gateway{
		schema: schema,
		secret: secret,
		runs:   runStub,
		wf:     wfStub,
		ai:     &stubAIClientRich{rationale: "Custom rationale from ai-service"},
	}
	editorTok := signTestToken(t, secret, "editor")

	t.Run("FragmentSpread and InlineFragment and Aliases and Real Run Projections", func(t *testing.T) {
		query := `
			fragment GateFields on GateResult {
				__typename
				gateStatus: status
				reason
				nodeId
			}
			query GetRun($id: ID!) {
				__typename
				targetRun: run(id: $id) {
					__typename
					id
					workflowName
					traceId
					lastSeqId
					errorMessage
					startedAt
					finishedAt
					trigger { type branch commitSha gitProvider }
					sourceRef { sourceId repoName fileCount }
					gateResult { ...GateFields }
					sbom { digest componentCount }
					aiReport { quality releaseDecision executiveSummary }
					... on Run {
						nodeRuns { nodeRunId pluginId status findingsEmitted durationMs }
					}
				}
			}
		`
		body, _ := json.Marshal(map[string]any{
			"query":     query,
			"variables": map[string]any{"id": "run_full"},
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		req.Header.Set("Content-Type", "application/json")
		gw.graphql(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out["errors"] != nil {
			t.Fatalf("unexpected errors: %v", out["errors"])
		}
		data := asMap(out["data"])
		if data["__typename"] != "Query" {
			t.Fatalf("root __typename = %v", data["__typename"])
		}
		run := asMap(data["targetRun"])
		if run["workflowName"] != "Primary AppSec Gate" {
			t.Fatalf("workflowName = %v, want Primary AppSec Gate", run["workflowName"])
		}
		if run["traceId"] != "trace-abc" || asInt(run["lastSeqId"], 0) != 17 {
			t.Fatalf("traceId/lastSeqId mismatch: %+v", run)
		}
		if run["errorMessage"] != "partial warning" {
			t.Fatalf("errorMessage = %v", run["errorMessage"])
		}
		gate := asMap(run["gateResult"])
		if gate["gateStatus"] != "FAIL" || gate["__typename"] != "GateResult" {
			t.Fatalf("fragment projection failed: %+v", gate)
		}
		sbom := asMap(run["sbom"])
		if sbom["digest"] != "sha256:sbom" || asInt(sbom["componentCount"], 0) != 42 {
			t.Fatalf("sbom projection failed: %+v", run["sbom"])
		}
		aiRep := asMap(run["aiReport"])
		if aiRep["quality"] != "VERIFIED" || aiRep["releaseDecision"] != "BLOCK" || aiRep["executiveSummary"] != "Block release" {
			t.Fatalf("aiReport projection failed: %+v", run["aiReport"])
		}
		nodeRuns := asList(run["nodeRuns"])
		if len(nodeRuns) != 1 || asMap(nodeRuns[0])["pluginId"] != "scan.secrets" {
			t.Fatalf("inline fragment nodeRuns failed: %+v", nodeRuns)
		}
	})

	t.Run("Query.run hydrates aiReport and sbom when absent on Run proto but nodes succeeded", func(t *testing.T) {
		runStub.runByID["run_hydrate"] = &secflowv1.Run{
			Id:         "run_hydrate",
			WorkflowId: "wf_1",
			Status:     secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
			NodeRuns: []*secflowv1.NodeRun{
				{NodeRunId: "nr_sbom", RunId: "run_hydrate", NodeId: "n_sbom", PluginId: "sbom.generate", Status: secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED},
				{NodeRunId: "nr_ai", RunId: "run_hydrate", NodeId: "n_ai", PluginId: "ai.explain", Status: secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED},
			},
			CreatedAt: now,
		}
		runStub.sbomResp = &secflowv1.GetSbomResponse{
			Sbom: &secflowv1.SbomRef{
				Digest:             "sha256:hydrated",
				SpecVersion:        "1.6",
				ComponentCount:     17,
				VulnerabilityCount: 3,
				GeneratedAt:        now,
			},
		}
		runStub.aiReportResp = &secflowv1.GetAIReportResponse{
			Report: &secflowv1.AIReport{
				Quality:          secflowv1.AIQuality_AI_QUALITY_VERIFIED,
				ReleaseDecision:  secflowv1.ReleaseDecision_RELEASE_DECISION_WARN,
				ExecutiveSummary: "Hydrated AI summary",
				ModelId:          "gpt-4o-mini",
				ProviderMode:     secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
				PrivacyMode:      secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET,
				PromptHash:       "h1",
				CreatedAt:        now,
			},
		}
		defer func() {
			delete(runStub.runByID, "run_hydrate")
			runStub.sbomResp = nil
			runStub.aiReportResp = nil
		}()

		body, _ := json.Marshal(map[string]any{
			"query": `{ run(id: "run_hydrate") { id sbom { digest specVersion componentCount vulnerabilityCount downloadUrl } aiReport { quality releaseDecision executiveSummary modelId } } }`,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.graphql(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["errors"] != nil {
			t.Fatalf("unexpected errors: %v", out["errors"])
		}
		run := asMap(asMap(out["data"])["run"])
		sbom := asMap(run["sbom"])
		if sbom["digest"] != "sha256:hydrated" || asInt(sbom["componentCount"], 0) != 17 || sbom["downloadUrl"] != "/runs/run_hydrate/sbom.cdx.json" {
			t.Fatalf("hydrated sbom mismatch: %+v", run["sbom"])
		}
		aiRep := asMap(run["aiReport"])
		if aiRep["executiveSummary"] != "Hydrated AI summary" || aiRep["releaseDecision"] != "WARN" {
			t.Fatalf("hydrated aiReport mismatch: %+v", run["aiReport"])
		}
	})

	t.Run("Query.findings maps sourceNodeId pluginId isNewVsBaseline stats and backend pagination", func(t *testing.T) {
		line := int32(19)
		runStub.findingsResp = &secflowv1.ListFindingsResponse{
			Findings: []*secflowv1.Finding{
				{
					FindingId:       "f_99",
					Fingerprint:     "fp_99",
					SourceNodeId:    "node_sast_1",
					PluginId:        "scan.sast.kotlin",
					Category:        secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
					Path:            "src/Main.kt",
					FindingClass:    "SQL_INJECTION",
					Line:            &line,
					Severity:        secflowv1.Severity_SEVERITY_HIGH,
					IsNewVsBaseline: true,
				},
			},
			Stats: &secflowv1.EnvelopeStats{
				Total:       3,
				NewCount:    1,
				High:        2,
				SastCount:   3,
				MaxSeverity: secflowv1.Severity_SEVERITY_HIGH,
			},
			PageInfo: &secflowv1.PageInfo{
				HasMore:    false,
				NextCursor: "",
				TotalCount: 3,
			},
		}
		defer func() { runStub.findingsResp = nil }()

		body, _ := json.Marshal(map[string]any{
			"query": `query($c: String) { findings(runId: "run_full", limit: 2, cursor: $c) { items { findingId sourceNodeId pluginId isNewVsBaseline } stats { total newCount high maxSeverity } nextCursor hasMore totalCount } }`,
			"variables": map[string]any{
				"c": encodeOffsetCursor(2),
			},
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.graphql(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("findings status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["errors"] != nil {
			t.Fatalf("unexpected findings errors: %v", out["errors"])
		}
		conn := asMap(asMap(out["data"])["findings"])
		items := asList(conn["items"])
		if len(items) != 1 {
			t.Fatalf("expected 1 finding on backend-paginated final page, got %+v", conn)
		}
		firstItem := asMap(items[0])
		if firstItem["sourceNodeId"] != "node_sast_1" || firstItem["pluginId"] != "scan.sast.kotlin" || firstItem["isNewVsBaseline"] != true {
			t.Fatalf("finding fields mismatch: %+v", firstItem)
		}
		stats := asMap(conn["stats"])
		if asInt(stats["total"], 0) != 3 || asInt(stats["newCount"], 0) != 1 || stats["maxSeverity"] != "HIGH" {
			t.Fatalf("findings stats mismatch: %+v", stats)
		}
		if conn["hasMore"] != false || asInt(conn["totalCount"], 0) != 3 {
			t.Fatalf("findings pageInfo mismatch: %+v", conn)
		}
	})

	t.Run("Introspection __schema and __type without panics", func(t *testing.T) {
		query := `
			fragment TypeRef on __Type {
				kind
				name
				ofType { kind name }
			}
			query {
				__schema {
					queryType { name }
					mutationType { name }
					subscriptionType { name }
					types { ...TypeRef }
				}
				__type(name: "ValidationIssue") {
					name
					kind
					fields {
						name
						type { ...TypeRef }
					}
				}
			}
		`
		body, _ := json.Marshal(map[string]any{"query": query})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		gw.graphql(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("introspection status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"fieldPath"`) || !strings.Contains(rec.Body.String(), `"Query"`) {
			t.Fatalf("introspection body missing expected schema metadata: %s", rec.Body.String())
		}
	})

	t.Run("generateWorkflowFromText returns backend rationale", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"query": `mutation { generateWorkflowFromText(input: {prompt: "scan kotlin"}) { suggestedName rationale modelId } }`,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.graphql(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"Custom rationale from ai-service"`) {
			t.Fatalf("rationale mismatch: status=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("validateWorkflow maps UNKNOWN_PLUGIN and fieldPath", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"query": `query { validateWorkflow(graph: {schemaVersion: 1, nodes: [], edges: []}) { valid issues { code nodeId fieldPath } } }`,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.graphql(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"UNKNOWN_PLUGIN"`) || !strings.Contains(rec.Body.String(), `"pluginId"`) {
			t.Fatalf("expected UNKNOWN_PLUGIN and fieldPath=pluginId, got %s", rec.Body.String())
		}
	})

	t.Run("Internal backend error is sanitized and never fabricated", func(t *testing.T) {
		runStub.getRunErr = status.Error(codes.Internal, "pq: secret internal stacktrace password=xyz")
		defer func() { runStub.getRunErr = nil }()

		body, _ := json.Marshal(map[string]any{
			"query": `{ run(id: "run_full") { id } }`,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.graphql(rec, req)

		if strings.Contains(rec.Body.String(), "password=xyz") || strings.Contains(rec.Body.String(), "stacktrace") {
			t.Fatalf("internal error leaked to client: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"INTERNAL"`) {
			t.Fatalf("expected INTERNAL error extension, got %s", rec.Body.String())
		}
	})
}

func TestGraphQLPaginationFiltersAndMutationArgs(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("test-secret")
	editorTok := signTestToken(t, secret, "editor")

	wfStub := &stubWorkflowClientRich{
		templates: []*secflowv1.WorkflowTemplate{
			{Id: "tpl_1", Slug: "a", Name: "Kotlin SAST", Tags: []string{"kotlin", "sast"}},
			{Id: "tpl_2", Slug: "b", Name: "SCA Audit", Tags: []string{"sca", "sbom"}},
			{Id: "tpl_3", Slug: "c", Name: "Full Kotlin", Tags: []string{"kotlin", "sca"}},
		},
	}
	runStub := &stubRunClientRich{
		runs: []*secflowv1.Run{
			{Id: "r1", WorkflowId: "wf_1", WorkflowName: "WF1", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
			{Id: "r2", WorkflowId: "wf_1", WorkflowName: "WF1", Status: secflowv1.RunStatus_RUN_STATUS_FAILED},
			{Id: "r3", WorkflowId: "wf_1", WorkflowName: "WF1", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
		},
	}
	plugStub := &stubPluginClient{
		plugins: []*secflowv1.RegisteredPlugin{
			{Manifest: &secflowv1.PluginManifest{PluginId: "scan.sca", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER}, Status: secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE},
			{Manifest: &secflowv1.PluginManifest{PluginId: "scan.old", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER}, Status: secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE},
			{Manifest: &secflowv1.PluginManifest{PluginId: "logic.if", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC}, Status: secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE},
		},
	}
	secStub := &stubSecretClientRich{
		secrets: []*secflowv1.SecretMetadata{
			{SecretRef: "s1", Name: "tg", Kind: secflowv1.SecretKind_SECRET_KIND_TELEGRAM_BOT_TOKEN},
			{SecretRef: "s2", Name: "git", Kind: secflowv1.SecretKind_SECRET_KIND_GIT_TOKEN},
		},
	}
	gw := &gateway{
		schema: schema,
		secret: secret,
		wf:     wfStub,
		runs:   runStub,
		plugs:  plugStub,
		secs:   secStub,
	}

	do := func(query string, vars map[string]any) map[string]any {
		t.Helper()
		payload := map[string]any{"query": query}
		if vars != nil {
			payload["variables"] = vars
		}
		raw, _ := json.Marshal(payload)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.graphql(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("query failed status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["errors"] != nil {
			t.Fatalf("unexpected graphql errors: %v", out["errors"])
		}
		return asMap(out["data"])
	}

	// runs(status: SUCCEEDED, limit: 1) + cursor pagination
	page1 := asMap(do(`{ runs(status: SUCCEEDED, limit: 1) { items { id status } nextCursor hasMore totalCount } }`, nil)["runs"])
	if len(asList(page1["items"])) != 1 || page1["hasMore"] != true || asInt(page1["totalCount"], 0) != 2 {
		t.Fatalf("runs page1 unexpected: %+v", page1)
	}
	page2 := asMap(do(`query($c: String) { runs(status: SUCCEEDED, limit: 1, cursor: $c) { items { id } hasMore } }`, map[string]any{"c": page1["nextCursor"]})["runs"])
	if len(asList(page2["items"])) != 1 || page2["hasMore"] != false {
		t.Fatalf("runs page2 unexpected: %+v", page2)
	}

	// templates(tags: ["kotlin"])
	tplData := asMap(do(`{ templates(tags: ["kotlin"]) { items { id } totalCount } }`, nil)["templates"])
	if asInt(tplData["totalCount"], 0) != 2 {
		t.Fatalf("templates tags filter got %+v", tplData)
	}

	// plugins(category: ANALYZER, includeOffline: false) vs true
	plugOnline := asList(do(`{ plugins(category: ANALYZER, includeOffline: false) { pluginId } }`, nil)["plugins"])
	if len(plugOnline) != 1 || asMap(plugOnline[0])["pluginId"] != "scan.sca" {
		t.Fatalf("plugins online filter got %+v", plugOnline)
	}
	plugAll := asList(do(`{ plugins(category: ANALYZER, includeOffline: true) { pluginId } }`, nil)["plugins"])
	if len(plugAll) != 2 {
		t.Fatalf("plugins includeOffline=true got %+v", plugAll)
	}

	// secrets(kind: GIT_TOKEN)
	secItems := asList(do(`{ secrets(kind: GIT_TOKEN) { secretRef } }`, nil)["secrets"])
	if len(secItems) != 1 || asMap(secItems[0])["secretRef"] != "s2" {
		t.Fatalf("secrets kind filter got %+v", secItems)
	}

	// startRun overrides
	do(`mutation { startRun(input: {workflowId: "wf_1", repoUrlOverride: "https://github.com/org/repo", gitRefOverride: "v1.0", commitShaOverride: "abc123"}) { id } }`, nil)
	if runStub.startReq.GetRepoUrlOverride() != "https://github.com/org/repo" ||
		runStub.startReq.GetGitRefOverride() != "v1.0" ||
		runStub.startReq.GetCommitShaOverride() != "abc123" {
		t.Fatalf("startRun overrides not forwarded: %+v", runStub.startReq)
	}

	// rerunFromNode updatedSecretBindings
	do(`mutation { rerunFromNode(input: {sourceRunId: "r1", nodeId: "n2", updatedSecretBindings: [{paramKey: "botToken", secretRef: "sec_9"}]}) { id } }`, nil)
	if len(runStub.rerunReq.GetUpdatedSecretBindings()) != 1 || runStub.rerunReq.GetUpdatedSecretBindings()[0].GetSecretRef() != "sec_9" {
		t.Fatalf("rerunFromNode updatedSecretBindings not forwarded: %+v", runStub.rerunReq.GetUpdatedSecretBindings())
	}

	// publishTemplate tags
	do(`mutation { publishTemplate(input: {workflowId: "wf_1", name: "My Tpl", description: "d", problemSolved: "p", tags: ["kotlin", "ci"]}) { id tags } }`, nil)
	if len(wfStub.lastPublishReq.GetTags()) != 2 || wfStub.lastPublishReq.GetTags()[0] != "kotlin" {
		t.Fatalf("publishTemplate tags not forwarded: %+v", wfStub.lastPublishReq.GetTags())
	}
}

func TestOpenAPIUploadsAndProblemDetails(t *testing.T) {
	secret := []byte("test-secret")
	editorTok := signTestToken(t, secret, "editor")
	viewerTok := signTestToken(t, secret, "viewer")

	t.Run("POST /upload 201 flat JSON and 413/422 ProblemDetails", func(t *testing.T) {
		gw := &gateway{
			secret: secret,
			ingest: &stubIngestClient{
				fn: func(_ context.Context, req *secflowv1.IngestUploadRequest) (*secflowv1.IngestUploadResponse, error) {
					switch string(req.GetArchiveZip()) {
					case "bomb":
						return nil, status.Error(codes.ResourceExhausted, "ZIP_BOMB_DETECTED")
					case "slip":
						return nil, status.Error(codes.InvalidArgument, "ZIP_SLIP_DETECTED")
					case "boom":
						return nil, errors.New("dial tcp 10.0.0.5:50052: go-git internal panic")
					default:
						return &secflowv1.IngestUploadResponse{
							SourceRef: &secflowv1.SourceRef{
								SourceId:  "src_123",
								Bucket:    "secflow-sources",
								Key:       "abc.tar.gz",
								Sha256:    strings.Repeat("b", 64),
								RepoName:  req.GetRepoName(),
								SizeBytes: 512,
								FileCount: 7,
							},
							DeduplicatedHit: true,
							IngestedAt:      timestamppb.Now(),
						}, nil
					}
				},
			},
		}

		// 201 flat JSON
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "demo.zip")
		_, _ = fw.Write([]byte("PK-valid-zip"))
		_ = mw.WriteField("repoName", "demo-service")
		_ = mw.Close()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
		req.Header.Set("Authorization", "Bearer "+editorTok)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		gw.upload(rec, req)

		if rec.Code != http.StatusCreated {
			t.Fatalf("upload status=%d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if _, hasWrapper := out["data"]; hasWrapper {
			t.Fatalf("upload response must be flat JSON without data wrapper: %s", rec.Body.String())
		}
		for _, k := range []string{"sourceId", "bucket", "key", "sha256", "repoName", "sizeBytes", "fileCount", "deduplicatedHit", "ingestedAt"} {
			if _, ok := out[k]; !ok {
				t.Fatalf("upload response missing %q: %s", k, rec.Body.String())
			}
		}

		// 413 ZIP_BOMB_DETECTED
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("bomb"))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		gw.upload(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("zip bomb status=%d ct=%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"ZIP_BOMB_DETECTED"`) || !strings.Contains(rec.Body.String(), `"4bf92f3577b34da6a3ce929d0e0e4736"`) {
			t.Fatalf("zip bomb problem body unexpected: %s", rec.Body.String())
		}

		// 422 ZIP_SLIP_DETECTED
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("slip"))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.upload(rec, req)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"ZIP_SLIP_DETECTED"`) {
			t.Fatalf("zip slip status=%d body=%s", rec.Code, rec.Body.String())
		}

		// 500 sanitized internal error (never leaks internal details)
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("boom"))
		req.Header.Set("Authorization", "Bearer "+editorTok)
		gw.upload(rec, req)
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "go-git") || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Fatalf("internal error leaked or wrong status: status=%d body=%s", rec.Code, rec.Body.String())
		}

		// 403 viewer forbidden with application/problem+json
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("ok"))
		req.Header.Set("Authorization", "Bearer "+viewerTok)
		gw.upload(rec, req)
		if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("viewer upload status=%d ct=%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
	})

	t.Run("POST /catalogs/upload 201 flat JSON reads name/setAsDefault/snapshotDate", func(t *testing.T) {
		cats := &stubCatalogClient{}
		gw := &gateway{secret: secret, cats: cats}

		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "catalog.json")
		_, _ = fw.Write([]byte(`{"vulnerabilities":[{"id":"CVE-2026-0001"}]}`))
		_ = mw.WriteField("name", "Final Eval 2026")
		_ = mw.WriteField("setAsDefault", "true")
		_ = mw.WriteField("snapshotDate", "2026-04-15")
		_ = mw.Close()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/catalogs/upload", &buf)
		req.Header.Set("Authorization", "Bearer "+editorTok)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		gw.catalogUpload(rec, req)

		if rec.Code != http.StatusCreated {
			t.Fatalf("catalog upload status=%d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		if cats.lastReq.GetName() != "Final Eval 2026" || !cats.lastReq.GetSetAsDefault() || cats.lastReq.GetSnapshotDate() != "2026-04-15" {
			t.Fatalf("catalog form fields not passed: %+v", cats.lastReq)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if _, hasWrapper := out["data"]; hasWrapper {
			t.Fatalf("catalog upload must be flat JSON: %s", rec.Body.String())
		}
		if out["name"] != "Final Eval 2026" || out["isDefault"] != true {
			t.Fatalf("unexpected catalog response: %+v", out)
		}
	})
}

func TestRunFileHeadersAndAuth(t *testing.T) {
	secret := []byte("test-secret")
	viewerTok := signTestToken(t, secret, "viewer")
	gw := &gateway{
		secret: secret,
		secs: &fakeSecretClient{
			tokens: map[string]*secflowv1.ActorContext{
				"sf_ci_start_only": {Subject: "ci_s", Scopes: []string{"ci:startRun"}, ScopedWorkflowId: "wf_1"},
			},
		},
		runs: &fakeRunClient{
			runs: map[string]*secflowv1.Run{
				"run_1": {Id: "run_1", WorkflowId: "wf_1"},
			},
		},
	}

	// 401 when unauthenticated
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/runs/run_1/submission.json", nil)
	gw.runFile(rec, req)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unauth status=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}

	// 403 when authenticated without permission (ci:startRun cannot download artifacts)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/runs/run_1/submission.json", nil)
	req.Header.Set("Authorization", "Bearer sf_ci_start_only")
	gw.runFile(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("forbidden status=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}

	cases := []struct {
		path        string
		wantCT      string
		wantDisp    string
		wantContent string
	}{
		{"/runs/run_1/submission.json", "application/json; charset=utf-8", `attachment; filename="submission-run_1.json"`, `{"findings":[]}`},
		{"/runs/run_1/sbom.cdx.json", "application/vnd.cyclonedx+json; charset=utf-8", `attachment; filename="sbom-run_1.cdx.json"`, `{"bomFormat":"CycloneDX"}`},
		{"/runs/run_1/report.md", "text/markdown; charset=utf-8", `attachment; filename="report-run_1.md"`, "# Report"},
		{"/runs/run_1/report.html", "text/html; charset=utf-8", `attachment; filename="report-run_1.html"`, "# Report"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+viewerTok)
			gw.runFile(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != tc.wantCT {
				t.Fatalf("Content-Type = %q, want %q", got, tc.wantCT)
			}
			if got := rec.Header().Get("Content-Disposition"); got != tc.wantDisp {
				t.Fatalf("Content-Disposition = %q, want %q", got, tc.wantDisp)
			}
			sum := sha256.Sum256([]byte(tc.wantContent))
			wantSha := hex.EncodeToString(sum[:])
			if got := rec.Header().Get("X-SecFlow-Sha256"); got != wantSha {
				t.Fatalf("X-SecFlow-Sha256 = %q, want %q", got, wantSha)
			}
		})
	}
}

func TestHealthzAndReadyz(t *testing.T) {
	t.Run("healthz returns JSON ok", func(t *testing.T) {
		gw := &gateway{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		gw.healthz(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("healthz status=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
		}
		if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
			t.Fatalf("healthz body=%s", rec.Body.String())
		}
	})

	t.Run("readyz returns 200 when all checks pass", func(t *testing.T) {
		gw := &gateway{
			pgPing:      func(context.Context) error { return nil },
			garageCheck: func(context.Context) error { return nil },
			plugs: &stubPluginClient{
				plugins: []*secflowv1.RegisteredPlugin{
					{ActiveWorkers: 2},
					{ActiveWorkers: 1},
				},
			},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		gw.readyz(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("readyz status=%d body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out["status"] != "ready" {
			t.Fatalf("status=%v", out["status"])
		}
		checks := asMap(out["checks"])
		if checks["postgres"] != "ok" || checks["orchestratorGrpc"] != "ok" || checks["garage"] != "ok" || asInt(checks["activeWorkerStreams"], 0) != 3 {
			t.Fatalf("unexpected checks: %+v", checks)
		}
	})

	t.Run("readyz returns 503 when dependency fails", func(t *testing.T) {
		gw := &gateway{
			pgPing: func(context.Context) error { return errors.New("db down") },
			plugs:  &stubPluginClient{err: status.Error(codes.Unavailable, "orch down")},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		gw.readyz(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("readyz status=%d, want 503, body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"not_ready"`) {
			t.Fatalf("readyz body=%s", rec.Body.String())
		}
	})
}

func TestWebhookInspectorLiveStreamAndBounds(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("test-secret")
	viewerTok := signTestToken(t, secret, "viewer")
	gw := &gateway{
		schema:      schema,
		secret:      secret,
		insp:        map[string][]inspectorEntry{},
		inspUpdated: map[string]time.Time{},
		subs:        map[string][]chan map[string]any{},
	}

	// 0. Enforce 4 <= len(channelKey) <= 64 per OpenAPI.
	for _, badKey := range []string{"abc", strings.Repeat("a", 65)} {
		recBad := httptest.NewRecorder()
		reqBad := httptest.NewRequest(http.MethodPost, "/webhooks/inspector/"+badKey, strings.NewReader(`{"seq":0}`))
		gw.inspector(recBad, reqBad)
		if recBad.Code != http.StatusBadRequest {
			t.Fatalf("invalid channelKey %q status=%d, want 400", badKey, recBad.Code)
		}
	}

	// 1. Seed an initial delivery via POST /webhooks/inspector/demo-chan -> 200 flat JSON.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/inspector/demo-chan", strings.NewReader(`{"seq":1}`))
	gw.inspector(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inspector status=%d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var inspResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &inspResp); err != nil {
		t.Fatal(err)
	}
	if inspResp["deliveryId"] == nil || inspResp["receivedAt"] == nil {
		t.Fatalf("inspector flat response missing deliveryId/receivedAt: %s", rec.Body.String())
	}

	// 2. Open graphql-transport-ws subscription to webhookInspectorEvents.
	srv := httptest.NewServer(http.HandlerFunc(gw.graphql))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/graphql"
	dialer := gorilla.Dialer{Subprotocols: []string{"graphql-transport-ws"}}
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()
	if resp.Header.Get("Sec-WebSocket-Protocol") != "graphql-transport-ws" {
		t.Fatalf("negotiated subprotocol = %q, want graphql-transport-ws", resp.Header.Get("Sec-WebSocket-Protocol"))
	}

	if err := conn.WriteJSON(map[string]any{
		"type":    "connection_init",
		"payload": map[string]any{"Authorization": "Bearer " + viewerTok},
	}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ack map[string]any
	if err := conn.ReadJSON(&ack); err != nil || ack["type"] != "connection_ack" {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}

	if err := conn.WriteJSON(map[string]any{
		"type": "subscribe",
		"id":   "insp-1",
		"payload": map[string]any{
			"query": `subscription { webhookInspectorEvents(channelKey: "demo-chan") { id channelKey body } }`,
		},
	}); err != nil {
		t.Fatal(err)
	}

	// First event: initial buffered delivery seq=1.
	var ev1 map[string]any
	if err := conn.ReadJSON(&ev1); err != nil {
		t.Fatalf("read ev1: %v", err)
	}
	if ev1["type"] != "next" {
		t.Fatalf("ev1 = %+v, want next", ev1)
	}

	// Push a second live delivery AFTER subscription is active -> must arrive in real time!
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/webhooks/inspector/demo-chan", strings.NewReader(`{"seq":2}`))
	gw.inspector(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second inspector POST status=%d, want 200", rec2.Code)
	}

	var ev2 map[string]any
	if err := conn.ReadJSON(&ev2); err != nil {
		t.Fatalf("read live ev2: %v", err)
	}
	if ev2["type"] != "next" {
		t.Fatalf("ev2 = %+v, want next", ev2)
	}
	ev2Body := asMap(asMap(asMap(asMap(ev2["payload"])["data"])["webhookInspectorEvents"])["body"])
	if asInt(ev2Body["seq"], 0) != 2 {
		t.Fatalf("expected live seq=2 delivery, got %+v", ev2)
	}

	// Send complete and verify subscriber is cleaned up.
	_ = conn.WriteJSON(map[string]any{"type": "complete", "id": "insp-1"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		gw.mu.Lock()
		nSubs := len(gw.subs["demo-chan"])
		gw.mu.Unlock()
		if nSubs == 0 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	gw.mu.Lock()
	if nSubs := len(gw.subs["demo-chan"]); nSubs != 0 {
		gw.mu.Unlock()
		t.Fatalf("expected subscriber cleanup after complete, still have %d", nSubs)
	}
	gw.mu.Unlock()

	// 3. Verify bounded inspector memory (max 50 channels, max 100 deliveries/channel).
	for i := 0; i < 65; i++ {
		ch := fmt.Sprintf("chan-%03d", i)
		gw.recordInspectorDelivery(ch, map[string]any{"id": ch})
	}
	for i := 0; i < 120; i++ {
		gw.recordInspectorDelivery("chan-064", map[string]any{"id": fmt.Sprintf("d-%d", i)})
	}
	gw.mu.Lock()
	numChannels := len(gw.insp)
	numDeliveries := len(gw.insp["chan-064"])
	gw.mu.Unlock()
	if numChannels > maxInspectorChannels {
		t.Fatalf("channels = %d, exceeds max %d", numChannels, maxInspectorChannels)
	}
	if numDeliveries > maxInspectorDeliveriesPerChannel {
		t.Fatalf("deliveries = %d, exceeds max %d", numDeliveries, maxInspectorDeliveriesPerChannel)
	}

	// 4. Verify TTL eviction.
	gwTTL := &gateway{
		insp:        map[string][]inspectorEntry{},
		inspUpdated: map[string]time.Time{},
		inspTTL:     10 * time.Millisecond,
	}
	gwTTL.recordInspectorDelivery("ttl-chan", map[string]any{"id": "old"})
	time.Sleep(25 * time.Millisecond)
	if got := gwTTL.listInspectorDeliveries("ttl-chan", 10); len(got) != 0 {
		t.Fatalf("expected TTL-evicted inspector entries to be empty, got %+v", got)
	}
}

func TestEventMapRealProjections(t *testing.T) {
	ev := &secflowv1.RunEvent{
		SeqId:        42,
		RunId:        "run_99",
		EventType:    secflowv1.RunEventType_RUN_EVENT_TYPE_GATE_EVALUATED,
		RunStatus:    secflowv1.RunStatus_RUN_STATUS_RUNNING,
		NodeId:       "gate_1",
		NodeRunId:    "nr_42",
		NodeStatus:   secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		EdgeId:       "e_9",
		SourceHandle: "FAIL",
		Stats: &secflowv1.EnvelopeStats{
			Total:       5,
			Critical:    1,
			High:        2,
			MaxSeverity: secflowv1.Severity_SEVERITY_CRITICAL,
		},
		GateResult: &secflowv1.GateResult{
			Status: secflowv1.GateStatus_GATE_STATUS_FAIL,
			Reason: "threshold exceeded",
			NodeId: "gate_1",
		},
		RedactedPreviewJson: []byte(`{"summary":"5 findings"}`),
		Message:             "gate evaluated",
		CreatedAt:           timestamppb.Now(),
	}
	m := eventMap(ev)
	if m["nodeStatus"] != "SUCCEEDED" || m["nodeId"] != "gate_1" || m["nodeRunId"] != "nr_42" || m["edgeId"] != "e_9" || m["sourceHandle"] != "FAIL" {
		t.Fatalf("unexpected eventMap fields: %+v", m)
	}
	stats := asMap(m["stats"])
	if asInt(stats["total"], 0) != 5 || stats["maxSeverity"] != "CRITICAL" {
		t.Fatalf("unexpected eventMap stats: %+v", stats)
	}
	gate := asMap(m["gateResult"])
	if gate["status"] != "FAIL" || gate["reason"] != "threshold exceeded" {
		t.Fatalf("unexpected eventMap gateResult: %+v", gate)
	}
	preview := asMap(m["redactedPreview"])
	if preview["summary"] != "5 findings" {
		t.Fatalf("unexpected eventMap redactedPreview: %+v", preview)
	}
}
