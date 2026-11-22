package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gorilla "github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/obs"
)

const integrationServiceToken = "integration-service-token"

type integrationBackend struct {
	secflowv1.UnimplementedWorkflowServiceServer
	secflowv1.UnimplementedRunServiceServer
	secflowv1.UnimplementedPluginRegistryServiceServer
	secflowv1.UnimplementedSecretServiceServer
	secflowv1.UnimplementedCatalogServiceServer
	secflowv1.UnimplementedMCPRegistryServiceServer
	secflowv1.UnimplementedSourceIngesterServiceServer
	secflowv1.UnimplementedAIServiceServer

	mu sync.Mutex

	workflows      map[string]*secflowv1.Workflow
	templates      map[string]*secflowv1.WorkflowTemplate
	runs           map[string]*secflowv1.Run
	runByIdemp     map[string]string
	findingsByRun  map[string][]*secflowv1.Finding
	payloadsByKey  map[string]*secflowv1.GetNodePayloadResponse
	sbomsByRun     map[string]*secflowv1.GetSbomResponse
	aiReportsByRun map[string]*secflowv1.AIReport
	reportsByKey   map[string][]byte
	plugins        map[string]*secflowv1.RegisteredPlugin
	installations  map[string]*secflowv1.PluginInstallation
	savedNodes     map[string]*secflowv1.SavedNode
	presets        []*secflowv1.PluginPreset
	secrets        map[string]*secflowv1.SecretMetadata
	secretValues   map[string]string
	scopedTokens   map[string]*secflowv1.ScopedTokenMetadata
	tokenActors    map[string]*secflowv1.ActorContext
	tokenByID      map[string]string
	catalogs       []*secflowv1.VulnerabilityCatalog
	mcpConns       map[string]*secflowv1.MCPConnection
	mcpToolsByConn map[string][]*secflowv1.MCPToolDescriptor
	sourcesBySHA   map[string]*secflowv1.SourceRef
	auditLogs      []*secflowv1.AIAuditLogEntry

	runEventsStream          map[string][]*secflowv1.RunEvent
	pluginEventsStream       []*secflowv1.PluginRegistryEvent
	installationEventsStream []*secflowv1.PluginInstallationEvent
	traceparents             map[string]string

	nextSeq         int
	failListPlugins error
	failStartRun    error
	failWebhookRun  error
}

func newIntegrationBackend() *integrationBackend {
	now := timestamppb.New(time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC))
	line := int32(42)
	endLine := int32(45)

	defaultGraph := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{
				Id:       "trig_1",
				PluginId: "trigger.manual",
				Label:    "Manual Trigger",
				Position: &secflowv1.Position{X: 0, Y: 0},
			},
			{
				Id:         "src_1",
				PluginId:   "source.upload",
				Label:      "Upload Source",
				Position:   &secflowv1.Position{X: 200, Y: 0},
				ParamsJson: []byte(`{"sourceId":"src_seed"}`),
			},
			{
				Id:       "scan_1",
				PluginId: "scan.sast.kotlin",
				Label:    "Kotlin SAST",
				Position: &secflowv1.Position{X: 400, Y: 0},
			},
		},
		Edges: []*secflowv1.WorkflowEdge{
			{Id: "e1", SourceNodeId: "trig_1", SourceHandle: "default", TargetNodeId: "src_1", TargetHandle: "default"},
			{Id: "e2", SourceNodeId: "src_1", SourceHandle: "default", TargetNodeId: "scan_1", TargetHandle: "default"},
		},
	}

	seedFinding := &secflowv1.Finding{
		FindingId:       "fnd_1",
		Fingerprint:     "fp_1",
		SourceNodeId:    "scan_1",
		PluginId:        "scan.sast.kotlin",
		Category:        secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
		Path:            "src/main/kotlin/App.kt",
		FindingClass:    "sql-injection",
		Line:            &line,
		EndLine:         &endLine,
		Severity:        secflowv1.Severity_SEVERITY_HIGH,
		Description:     "Raw SQL concatenation",
		Remediation:     "Use parameterized queries",
		MaskedSnippet:   `jdbc.query("SELECT * FROM users WHERE id=" + id)`,
		IsNewVsBaseline: true,
	}
	seedSCA := &secflowv1.Finding{
		FindingId:    "fnd_2",
		Fingerprint:  "fp_2",
		SourceNodeId: "scan_2",
		PluginId:     "scan.sca",
		Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SCA,
		Path:         "gradle.lockfile",
		Group:        "org.example",
		Artifact:     "vuln-lib",
		Version:      "1.2.3",
		AdvisoryId:   "CVE-2026-0001",
		Severity:     secflowv1.Severity_SEVERITY_CRITICAL,
		Description:  "Vulnerable dependency",
	}

	seedAIReport := &secflowv1.AIReport{
		Quality:          secflowv1.AIQuality_AI_QUALITY_VERIFIED,
		ReleaseDecision:  secflowv1.ReleaseDecision_RELEASE_DECISION_BLOCK,
		ExecutiveSummary: "Critical SCA and High SAST issues require remediation.",
		Groups: []*secflowv1.AIReportGroup{{
			Title:       "Critical Issues",
			MaxSeverity: secflowv1.Severity_SEVERITY_CRITICAL,
			FindingIds:  []string{"fnd_1", "fnd_2"},
			Summary:     "Two high-priority security findings.",
		}},
		Items: []*secflowv1.AIReportItem{{
			FindingId:            "fnd_1",
			PriorityRank:         1,
			PlainLanguageRisk:    "SQL injection risk",
			BusinessImpact:       "Data exposure",
			RemediationSteps:     []string{"Switch to prepared statements"},
			ReferencedAdvisories: []string{"CVE-2026-0001"},
			Finding: &secflowv1.GroundedFindingSummary{
				Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
				Path:         "src/main/kotlin/App.kt",
				Line:         &line,
				EndLine:      &endLine,
				FindingClass: "sql-injection",
				Severity:     secflowv1.Severity_SEVERITY_HIGH,
			},
		}},
		ModelId:      "gpt-4o-mini",
		ProviderMode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
		PrivacyMode:  secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET,
		PromptHash:   "ph_seed_01",
		TokensIn:     320,
		TokensOut:    180,
		LatencyMs:    410,
		CreatedAt:    now,
	}

	seedSbomRef := &secflowv1.SbomRef{
		Digest:             "sha256:seed-sbom",
		SpecVersion:        "1.6",
		ComponentCount:     12,
		VulnerabilityCount: 1,
		GeneratedAt:        now,
	}

	seedRun := &secflowv1.Run{
		Id:              "run_seed",
		WorkflowId:      "wf_seed",
		WorkflowVersion: 1,
		WorkflowName:    "Seed Kotlin Pipeline",
		Status:          secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
		Trigger: &secflowv1.TriggerMetadata{
			Type:        secflowv1.TriggerType_TRIGGER_TYPE_MANUAL,
			TriggeredBy: "owner@secflow.local",
			TriggeredAt: now,
		},
		SourceRef: &secflowv1.SourceRef{
			SourceId:  "src_seed",
			Sha256:    strings.Repeat("a", 64),
			RepoName:  "training-project",
			SizeBytes: 4096,
			FileCount: 18,
		},
		GateResult: &secflowv1.GateResult{
			Status: secflowv1.GateStatus_GATE_STATUS_FAIL,
			Reason: "Critical finding detected",
			NodeId: "gate_1",
		},
		NodeRuns: []*secflowv1.NodeRun{
			{
				NodeRunId:         "nr_1",
				RunId:             "run_seed",
				NodeId:            "scan_1",
				PluginId:          "scan.sast.kotlin",
				Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
				Attempt:           1,
				WorkerId:          "worker-kotlin-1",
				ActiveOutputPorts: []string{"default"},
				FindingsEmitted:   2,
				DurationMs:        240,
				StartedAt:         now,
				FinishedAt:        now,
			},
			{
				NodeRunId: "nr_2",
				RunId:     "run_seed",
				NodeId:    "ai_1",
				PluginId:  "ai.explain",
				Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
				Attempt:   1,
			},
			{
				NodeRunId: "nr_3",
				RunId:     "run_seed",
				NodeId:    "sbom_1",
				PluginId:  "sbom.generate",
				Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
				Attempt:   1,
			},
		},
		TraceId:    "4bf92f3577b34da6a3ce929d0e0e4736",
		LastSeqId:  2,
		CreatedAt:  now,
		StartedAt:  now,
		FinishedAt: now,
	}

	otherRun := &secflowv1.Run{
		Id:              "run_other",
		WorkflowId:      "wf_other",
		WorkflowVersion: 1,
		WorkflowName:    "Other Pipeline",
		Status:          secflowv1.RunStatus_RUN_STATUS_RUNNING,
		Trigger:         &secflowv1.TriggerMetadata{Type: secflowv1.TriggerType_TRIGGER_TYPE_MANUAL, TriggeredAt: now},
		CreatedAt:       now,
	}

	return &integrationBackend{
		workflows: map[string]*secflowv1.Workflow{
			"wf_seed": {
				Id:             "wf_seed",
				Name:           "Seed Kotlin Pipeline",
				Description:    "Seeded workflow",
				Version:        1,
				Graph:          defaultGraph,
				OwnerSubject:   "owner@secflow.local",
				WebhookEnabled: false,
				WebhookPath:    "/webhooks/git/wf_seed",
				CreatedAt:      now,
				UpdatedAt:      now,
			},
			"wf_other": {
				Id:           "wf_other",
				Name:         "Other Pipeline",
				Description:  "Secondary workflow for scope isolation",
				Version:      1,
				Graph:        defaultGraph,
				OwnerSubject: "owner@secflow.local",
				WebhookPath:  "/webhooks/git/wf_other",
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		templates: map[string]*secflowv1.WorkflowTemplate{
			"tpl_seed": {
				Id:             "tpl_seed",
				Slug:           "kotlin-full-audit",
				Name:           "Kotlin Full Audit",
				Description:    "Full SAST + SCA + SBOM pipeline",
				ProblemSolved:  "Detects secrets, Kotlin SAST, and Maven CVEs",
				Tags:           []string{"kotlin", "ci"},
				IsBuiltin:      true,
				SanitizedGraph: defaultGraph,
				AuthorSubject:  "system",
				CloneCount:     3,
				CreatedAt:      now,
				UpdatedAt:      now,
			},
		},
		runs: map[string]*secflowv1.Run{
			"run_seed":  seedRun,
			"run_other": otherRun,
		},
		runByIdemp: map[string]string{},
		findingsByRun: map[string][]*secflowv1.Finding{
			"run_seed": {seedFinding, seedSCA},
		},
		payloadsByKey: map[string]*secflowv1.GetNodePayloadResponse{
			"run_seed:scan_1": {
				RunId:              "run_seed",
				NodeId:             "scan_1",
				PluginId:           "scan.sast.kotlin",
				Status:             secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
				InputEnvelopeJson:  []byte(`{"sourceId":"src_seed","findings":[]}`),
				OutputEnvelopeJson: []byte(`{"sourceId":"src_seed","findings":[{"class":"sql-injection"}]}`),
				ActiveOutputPorts:  []string{"default"},
				PortOutputs: []*secflowv1.PortEnvelopeOutput{{
					SourceHandle:       "default",
					OutputEnvelopeJson: []byte(`{"findings":[{"class":"sql-injection"}]}`),
				}},
			},
		},
		sbomsByRun: map[string]*secflowv1.GetSbomResponse{
			"run_seed": {
				Sbom:          seedSbomRef,
				CyclonedxJson: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`),
			},
		},
		aiReportsByRun: map[string]*secflowv1.AIReport{
			"run_seed": seedAIReport,
		},
		reportsByKey: map[string][]byte{
			"run_seed:MARKDOWN": []byte("# SecFlow Report\n\n- sql-injection (HIGH)\n"),
			"run_seed:HTML":     []byte("<!doctype html><html><body><h1>SecFlow Report</h1></body></html>"),
		},
		plugins: map[string]*secflowv1.RegisteredPlugin{
			"scan.sast.kotlin": {
				Manifest: &secflowv1.PluginManifest{
					PluginId:         "scan.sast.kotlin",
					Version:          "1.0.0",
					DisplayName:      "Kotlin PSI SAST",
					Description:      "Deterministic Kotlin PSI analyzer",
					Category:         secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
					Capabilities:     []string{"analyzer"},
					ParamsJsonSchema: []byte(`{"type":"object","properties":{"rules":{"type":"array"}}}`),
					InputPorts:       []*secflowv1.PortDefinition{{Id: "default", Label: "Source"}},
					OutputPorts:      []*secflowv1.PortDefinition{{Id: "default", Label: "Envelope"}},
					RuntimeLanguage:  "kotlin",
					SandboxProfile:   secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
				},
				Status:        secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE,
				ActiveWorkers: 2,
				QueueDepth:    0,
				RegisteredAt:  now,
				LastSeenAt:    now,
				Enabled:       true,
			},
			"sandbox.offline": {
				Manifest: &secflowv1.PluginManifest{
					PluginId:        "sandbox.offline",
					Version:         "0.1.0",
					DisplayName:     "Offline Sandbox Plugin",
					Category:        secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
					IsExternal:      true,
					RuntimeLanguage: "go",
				},
				Status:        secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE,
				ActiveWorkers: 0,
				RegisteredAt:  now,
				LastSeenAt:    now,
				Enabled:       true,
			},
		},
		installations: map[string]*secflowv1.PluginInstallation{},
		presets: []*secflowv1.PluginPreset{
			{
				Id:             "spring-config-hardening",
				Name:           "Spring Config Hardening",
				Description:    "Deterministic Spring Boot config analyzer",
				ImageRef:       "ghcr.io/secflow/demo-spring-config:1.0.0",
				Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
				SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
				PluginIds:      []string{"scan.spring-config"},
				OutputPorts: []*secflowv1.PortDefinition{
					{Id: "default", Label: "Envelope"},
				},
				DefaultResourceLimits: &secflowv1.PluginResourceLimits{
					CpuRequest:    "100m",
					CpuLimit:      "500m",
					MemoryRequest: "128Mi",
					MemoryLimit:   "512Mi",
					MinReplicas:   1,
					MaxReplicas:   2,
				},
				AutoApproveSupported: true,
			},
		},
		secrets: map[string]*secflowv1.SecretMetadata{
			"sec_seed": {
				SecretRef:     "sec_seed",
				Name:          "Seed Webhook Secret",
				Kind:          secflowv1.SecretKind_SECRET_KIND_GIT_WEBHOOK_SECRET,
				MaskedPreview: "whsec_****99",
				Backend:       secflowv1.SecretStoreBackend_SECRET_STORE_BACKEND_PG_AES,
				CreatedBy:     "owner@secflow.local",
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		},
		secretValues: map[string]string{
			"sec_seed": "super-secret-webhook-key",
		},
		scopedTokens: map[string]*secflowv1.ScopedTokenMetadata{},
		tokenActors:  map[string]*secflowv1.ActorContext{},
		tokenByID:    map[string]string{},
		catalogs: []*secflowv1.VulnerabilityCatalog{
			{
				Id:            "cat_seed",
				Name:          "Default Maven Catalog",
				Ecosystem:     "Maven",
				VersionFormat: "numeric-dot-separated",
				S3Key:         "seed.json",
				Sha256:        strings.Repeat("b", 64),
				SnapshotDate:  "2026-05-01",
				AdvisoryCount: 5,
				IsDefault:     true,
				UploadedBy:    "system",
				CreatedAt:     now,
			},
		},
		mcpConns: map[string]*secflowv1.MCPConnection{
			"mcp_seed": {
				Id: "mcp_seed",
				Config: &secflowv1.MCPConnectionConfig{
					Name:           "Jira MCP",
					Description:    "Outbound Jira connector",
					EndpointUrl:    "https://mcp.example.local/jira",
					AuthHeaderName: "Authorization",
					AllowedTools:   []string{"create_ticket"},
					DeniedTools:    []string{"semgrep_scan"},
				},
				Enabled:   true,
				CreatedBy: "owner@secflow.local",
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		mcpToolsByConn: map[string][]*secflowv1.MCPToolDescriptor{
			"mcp_seed": {{
				Name:            "create_ticket",
				Description:     "Create security issue ticket",
				InputSchemaJson: []byte(`{"type":"object","properties":{"title":{"type":"string"}}}`),
			}},
		},
		sourcesBySHA: map[string]*secflowv1.SourceRef{},
		auditLogs: []*secflowv1.AIAuditLogEntry{
			{
				Id:                             "aud_1",
				RunId:                          "run_seed",
				NodeRunId:                      "nr_2",
				Operation:                      secflowv1.AIOperation_AI_OPERATION_AI_EXPLAIN,
				ModelId:                        "gpt-4o-mini",
				ProviderMode:                   secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
				PrivacyMode:                    secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET,
				PromptHash:                     "ph_seed_01",
				TokensIn:                       320,
				TokensOut:                      180,
				LatencyMs:                      410,
				Quality:                        secflowv1.AIQuality_AI_QUALITY_VERIFIED,
				StrippedHallucinatedAdvisories: 0,
				CacheHit:                       false,
				CreatedAt:                      now,
			},
		},
		runEventsStream: map[string][]*secflowv1.RunEvent{
			"run_seed": {
				{
					SeqId:     1,
					RunId:     "run_seed",
					EventType: secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_STARTED,
					RunStatus: secflowv1.RunStatus_RUN_STATUS_RUNNING,
					Message:   "run started",
					CreatedAt: now,
				},
				{
					SeqId:      2,
					RunId:      "run_seed",
					EventType:  secflowv1.RunEventType_RUN_EVENT_TYPE_NODE_STATUS_CHANGED,
					RunStatus:  secflowv1.RunStatus_RUN_STATUS_RUNNING,
					NodeId:     "scan_1",
					NodeRunId:  "nr_1",
					NodeStatus: secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
					Message:    "node succeeded",
					CreatedAt:  now,
				},
			},
		},
		pluginEventsStream: []*secflowv1.PluginRegistryEvent{
			{
				EventType: secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED,
				Plugin: &secflowv1.RegisteredPlugin{
					Manifest: &secflowv1.PluginManifest{
						PluginId:    "sandbox.hotplug",
						Version:     "1.0.0",
						DisplayName: "Hot-Plug Sandbox",
						Category:    secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
						IsExternal:  true,
					},
					Status:        secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE,
					ActiveWorkers: 1,
					RegisteredAt:  now,
					LastSeenAt:    now,
				},
				OccurredAt: now,
			},
		},
		traceparents: map[string]string{},
	}
}

func (b *integrationBackend) recordTraceparent(ctx context.Context, method string) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("traceparent"); len(vals) > 0 {
			b.mu.Lock()
			b.traceparents[method] = vals[0]
			b.mu.Unlock()
		}
	}
}

func (b *integrationBackend) lastTraceparent(method string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.traceparents[method]
}

func (b *integrationBackend) nextID(prefix string) string {
	b.nextSeq++
	return fmt.Sprintf("%s_%d", prefix, b.nextSeq)
}

// --- WorkflowServiceServer ---

func (b *integrationBackend) CreateWorkflow(ctx context.Context, req *secflowv1.CreateWorkflowRequest) (*secflowv1.CreateWorkflowResponse, error) {
	b.recordTraceparent(ctx, "CreateWorkflow")
	b.mu.Lock()
	defer b.mu.Unlock()

	now := timestamppb.Now()
	id := b.nextID("wf")
	wf := &secflowv1.Workflow{
		Id:           id,
		Name:         req.GetName(),
		Description:  req.GetDescription(),
		Version:      1,
		Graph:        req.GetGraph(),
		OwnerSubject: req.GetActor().GetSubject(),
		WebhookPath:  "/webhooks/git/" + id,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	b.workflows[id] = wf
	return &secflowv1.CreateWorkflowResponse{Workflow: wf}, nil
}

func (b *integrationBackend) UpdateWorkflow(ctx context.Context, req *secflowv1.UpdateWorkflowRequest) (*secflowv1.UpdateWorkflowResponse, error) {
	b.recordTraceparent(ctx, "UpdateWorkflow")
	b.mu.Lock()
	defer b.mu.Unlock()

	wf, ok := b.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	if req.ExpectedVersion != nil && req.GetExpectedVersion() != wf.GetVersion() {
		return nil, status.Error(codes.Aborted, "version conflict")
	}
	wf.Version++
	wf.Name = req.GetName()
	wf.Description = req.GetDescription()
	wf.Graph = req.GetGraph()
	wf.UpdatedAt = timestamppb.Now()
	return &secflowv1.UpdateWorkflowResponse{Workflow: wf}, nil
}

func (b *integrationBackend) GetWorkflow(ctx context.Context, req *secflowv1.GetWorkflowRequest) (*secflowv1.GetWorkflowResponse, error) {
	b.recordTraceparent(ctx, "GetWorkflow")
	b.mu.Lock()
	defer b.mu.Unlock()

	wf, ok := b.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	return &secflowv1.GetWorkflowResponse{Workflow: wf}, nil
}

func (b *integrationBackend) ListWorkflows(ctx context.Context, _ *secflowv1.ListWorkflowsRequest) (*secflowv1.ListWorkflowsResponse, error) {
	b.recordTraceparent(ctx, "ListWorkflows")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]*secflowv1.Workflow, 0, len(b.workflows))
	for _, wf := range b.workflows {
		out = append(out, wf)
	}
	return &secflowv1.ListWorkflowsResponse{Workflows: out}, nil
}

func (b *integrationBackend) DeleteWorkflow(ctx context.Context, req *secflowv1.DeleteWorkflowRequest) (*secflowv1.DeleteWorkflowResponse, error) {
	b.recordTraceparent(ctx, "DeleteWorkflow")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.workflows[req.GetWorkflowId()]; !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	delete(b.workflows, req.GetWorkflowId())
	return &secflowv1.DeleteWorkflowResponse{Deleted: true}, nil
}

func (b *integrationBackend) ValidateWorkflow(ctx context.Context, req *secflowv1.ValidateWorkflowRequest) (*secflowv1.ValidateWorkflowResponse, error) {
	b.recordTraceparent(ctx, "ValidateWorkflow")
	if len(req.GetGraph().GetNodes()) == 0 {
		return &secflowv1.ValidateWorkflowResponse{
			Valid: false,
			Issues: []*secflowv1.ValidationIssue{{
				Code:     "MISSING_TRIGGER",
				Severity: secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
				Message:  "workflow must have a trigger node",
			}},
		}, nil
	}
	return &secflowv1.ValidateWorkflowResponse{Valid: true}, nil
}

func (b *integrationBackend) PublishTemplate(ctx context.Context, req *secflowv1.PublishTemplateRequest) (*secflowv1.PublishTemplateResponse, error) {
	b.recordTraceparent(ctx, "PublishTemplate")
	b.mu.Lock()
	defer b.mu.Unlock()

	wf, ok := b.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	now := timestamppb.Now()
	id := b.nextID("tpl")
	tpl := &secflowv1.WorkflowTemplate{
		Id:             id,
		Slug:           strings.ToLower(strings.ReplaceAll(req.GetName(), " ", "-")),
		Name:           req.GetName(),
		Description:    req.GetDescription(),
		ProblemSolved:  req.GetProblemSolved(),
		Tags:           req.GetTags(),
		IsBuiltin:      false,
		SanitizedGraph: wf.GetGraph(),
		AuthorSubject:  req.GetActor().GetSubject(),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	b.templates[id] = tpl
	return &secflowv1.PublishTemplateResponse{Template: tpl}, nil
}

func (b *integrationBackend) ListTemplates(ctx context.Context, _ *secflowv1.ListTemplatesRequest) (*secflowv1.ListTemplatesResponse, error) {
	b.recordTraceparent(ctx, "ListTemplates")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]*secflowv1.WorkflowTemplate, 0, len(b.templates))
	for _, tpl := range b.templates {
		out = append(out, tpl)
	}
	return &secflowv1.ListTemplatesResponse{Templates: out}, nil
}

func (b *integrationBackend) GetTemplate(ctx context.Context, req *secflowv1.GetTemplateRequest) (*secflowv1.GetTemplateResponse, error) {
	b.recordTraceparent(ctx, "GetTemplate")
	b.mu.Lock()
	defer b.mu.Unlock()

	tpl, ok := b.templates[req.GetTemplateId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	return &secflowv1.GetTemplateResponse{Template: tpl}, nil
}

func (b *integrationBackend) CloneTemplate(ctx context.Context, req *secflowv1.CloneTemplateRequest) (*secflowv1.CloneTemplateResponse, error) {
	b.recordTraceparent(ctx, "CloneTemplate")
	b.mu.Lock()
	defer b.mu.Unlock()

	tpl, ok := b.templates[req.GetTemplateId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	tpl.CloneCount++
	now := timestamppb.Now()
	id := b.nextID("wf_clone")
	wf := &secflowv1.Workflow{
		Id:               id,
		Name:             req.GetNewWorkflowName(),
		Description:      tpl.GetDescription(),
		Version:          1,
		Graph:            tpl.GetSanitizedGraph(),
		OwnerSubject:     req.GetActor().GetSubject(),
		WebhookPath:      "/webhooks/git/" + id,
		SourceTemplateId: tpl.GetId(),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	b.workflows[id] = wf
	return &secflowv1.CloneTemplateResponse{Workflow: wf}, nil
}

func (b *integrationBackend) GenerateCiConfig(ctx context.Context, req *secflowv1.GenerateCiConfigRequest) (*secflowv1.GenerateCiConfigResponse, error) {
	b.recordTraceparent(ctx, "GenerateCiConfig")
	filename := ".github/workflows/secflow.yml"
	if req.GetProvider() == secflowv1.CiProvider_CI_PROVIDER_GITLAB_CI {
		filename = ".gitlab-ci.yml"
	}
	yaml := fmt.Sprintf("workflow: %s\nbase_url: %s\nfail_on: %s\npolicy_gate: %t\n",
		req.GetWorkflowId(), req.GetSecflowBaseUrl(), req.GetFailOnSeverity().String(), req.GetFailOnPolicyGate())
	return &secflowv1.GenerateCiConfigResponse{
		Provider:          req.GetProvider(),
		Filename:          filename,
		YamlContent:       yaml,
		RequiredCiSecrets: []string{"SECFLOW_CI_TOKEN"},
	}, nil
}

// --- RunServiceServer ---

func (b *integrationBackend) StartRun(ctx context.Context, req *secflowv1.StartRunRequest) (*secflowv1.StartRunResponse, error) {
	b.recordTraceparent(ctx, "StartRun")
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.failStartRun != nil {
		return nil, b.failStartRun
	}
	wf, ok := b.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	now := timestamppb.Now()
	id := b.nextID("run")
	run := &secflowv1.Run{
		Id:              id,
		WorkflowId:      wf.GetId(),
		WorkflowVersion: wf.GetVersion(),
		WorkflowName:    wf.GetName(),
		Status:          secflowv1.RunStatus_RUN_STATUS_QUEUED,
		Trigger: &secflowv1.TriggerMetadata{
			Type:        req.GetTriggerType(),
			RepoUrl:     req.GetRepoUrlOverride(),
			Branch:      req.GetGitRefOverride(),
			CommitSha:   req.GetCommitShaOverride(),
			TriggeredBy: req.GetActor().GetSubject(),
			TriggeredAt: now,
		},
		TraceId:   "trace-" + id,
		CreatedAt: now,
	}
	b.runs[id] = run
	return &secflowv1.StartRunResponse{Run: run}, nil
}

func (b *integrationBackend) StartRunFromWebhook(ctx context.Context, req *secflowv1.StartRunFromWebhookRequest) (*secflowv1.StartRunFromWebhookResponse, error) {
	b.recordTraceparent(ctx, "StartRunFromWebhook")
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.failWebhookRun != nil {
		return nil, b.failWebhookRun
	}
	if key := req.GetIdempotencyKey(); key != "" {
		if _, exists := b.runByIdemp[key]; exists {
			return nil, status.Error(codes.AlreadyExists, "DUPLICATE_DELIVERY")
		}
	}
	wf, ok := b.workflows[req.GetWorkflowId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}
	id := b.nextID("run_wh")
	run := &secflowv1.Run{
		Id:              id,
		WorkflowId:      wf.GetId(),
		WorkflowVersion: wf.GetVersion(),
		WorkflowName:    wf.GetName(),
		Status:          secflowv1.RunStatus_RUN_STATUS_QUEUED,
		Trigger:         req.GetTrigger(),
		TraceId:         "trace-" + id,
		CreatedAt:       timestamppb.Now(),
	}
	b.runs[id] = run
	if key := req.GetIdempotencyKey(); key != "" {
		b.runByIdemp[key] = id
	}
	return &secflowv1.StartRunFromWebhookResponse{Run: run}, nil
}

func (b *integrationBackend) RerunFromNode(ctx context.Context, req *secflowv1.RerunFromNodeRequest) (*secflowv1.RerunFromNodeResponse, error) {
	b.recordTraceparent(ctx, "RerunFromNode")
	b.mu.Lock()
	defer b.mu.Unlock()

	src, ok := b.runs[req.GetSourceRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "source run not found")
	}
	id := b.nextID("run_rerun")
	run := &secflowv1.Run{
		Id:              id,
		WorkflowId:      src.GetWorkflowId(),
		WorkflowVersion: src.GetWorkflowVersion(),
		WorkflowName:    src.GetWorkflowName(),
		Status:          secflowv1.RunStatus_RUN_STATUS_QUEUED,
		ParentRunId:     src.GetId(),
		RerunFromNodeId: req.GetNodeId(),
		Trigger: &secflowv1.TriggerMetadata{
			Type:        secflowv1.TriggerType_TRIGGER_TYPE_RERUN,
			TriggeredBy: req.GetActor().GetSubject(),
			TriggeredAt: timestamppb.Now(),
		},
		CreatedAt: timestamppb.Now(),
	}
	b.runs[id] = run
	return &secflowv1.RerunFromNodeResponse{Run: run}, nil
}

func (b *integrationBackend) CancelRun(ctx context.Context, req *secflowv1.CancelRunRequest) (*secflowv1.CancelRunResponse, error) {
	b.recordTraceparent(ctx, "CancelRun")
	b.mu.Lock()
	defer b.mu.Unlock()

	run, ok := b.runs[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	run.Status = secflowv1.RunStatus_RUN_STATUS_CANCELLED
	run.ErrorMessage = req.GetReason()
	return &secflowv1.CancelRunResponse{Run: run}, nil
}

func (b *integrationBackend) GetRun(ctx context.Context, req *secflowv1.GetRunRequest) (*secflowv1.GetRunResponse, error) {
	b.recordTraceparent(ctx, "GetRun")
	b.mu.Lock()
	defer b.mu.Unlock()

	run, ok := b.runs[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	return &secflowv1.GetRunResponse{Run: run}, nil
}

func (b *integrationBackend) ListRuns(ctx context.Context, req *secflowv1.ListRunsRequest) (*secflowv1.ListRunsResponse, error) {
	b.recordTraceparent(ctx, "ListRuns")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]*secflowv1.Run, 0, len(b.runs))
	for _, r := range b.runs {
		if req.GetWorkflowId() != "" && r.GetWorkflowId() != req.GetWorkflowId() {
			continue
		}
		if req.GetStatus() != secflowv1.RunStatus_RUN_STATUS_UNSPECIFIED && r.GetStatus() != req.GetStatus() {
			continue
		}
		out = append(out, r)
	}
	return &secflowv1.ListRunsResponse{Runs: out}, nil
}

func (b *integrationBackend) ListFindings(ctx context.Context, req *secflowv1.ListFindingsRequest) (*secflowv1.ListFindingsResponse, error) {
	b.recordTraceparent(ctx, "ListFindings")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.runs[req.GetRunId()]; !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	all := b.findingsByRun[req.GetRunId()]
	filtered := make([]*secflowv1.Finding, 0, len(all))
	for _, f := range all {
		if req.GetCategory() != secflowv1.FindingCategory_FINDING_CATEGORY_UNSPECIFIED && f.GetCategory() != req.GetCategory() {
			continue
		}
		if req.GetMinSeverity() != secflowv1.Severity_SEVERITY_UNSPECIFIED && f.GetSeverity() < req.GetMinSeverity() {
			continue
		}
		filtered = append(filtered, f)
	}
	return &secflowv1.ListFindingsResponse{Findings: filtered}, nil
}

func (b *integrationBackend) GetSubmissionReport(ctx context.Context, req *secflowv1.GetSubmissionReportRequest) (*secflowv1.GetSubmissionReportResponse, error) {
	b.recordTraceparent(ctx, "GetSubmissionReport")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.runs[req.GetRunId()]; !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	payload := []byte(`{"findings":[{"category":"SAST","path":"src/main/kotlin/App.kt","line":42,"class":"sql-injection"}]}`)
	sum := sha256.Sum256(payload)
	return &secflowv1.GetSubmissionReportResponse{
		SubmissionJson: payload,
		Sha256:         hex.EncodeToString(sum[:]),
	}, nil
}

func (b *integrationBackend) GetSbom(ctx context.Context, req *secflowv1.GetSbomRequest) (*secflowv1.GetSbomResponse, error) {
	b.recordTraceparent(ctx, "GetSbom")
	b.mu.Lock()
	defer b.mu.Unlock()

	resp, ok := b.sbomsByRun[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "sbom not found")
	}
	out := &secflowv1.GetSbomResponse{Sbom: resp.GetSbom()}
	if req.GetIncludeContent() {
		out.CyclonedxJson = resp.GetCyclonedxJson()
	}
	return out, nil
}

func (b *integrationBackend) GetAIReport(ctx context.Context, req *secflowv1.GetAIReportRequest) (*secflowv1.GetAIReportResponse, error) {
	b.recordTraceparent(ctx, "GetAIReport")
	b.mu.Lock()
	defer b.mu.Unlock()

	rep, ok := b.aiReportsByRun[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "ai report not found")
	}
	return &secflowv1.GetAIReportResponse{Report: rep}, nil
}

func (b *integrationBackend) GetReadableReport(ctx context.Context, req *secflowv1.GetReadableReportRequest) (*secflowv1.GetReadableReportResponse, error) {
	b.recordTraceparent(ctx, "GetReadableReport")
	b.mu.Lock()
	defer b.mu.Unlock()

	fmtKey := "MARKDOWN"
	if req.GetFormat() == secflowv1.ReportFormat_REPORT_FORMAT_HTML {
		fmtKey = "HTML"
	}
	raw, ok := b.reportsByKey[req.GetRunId()+":"+fmtKey]
	if !ok {
		return nil, status.Error(codes.NotFound, "report not found")
	}
	return &secflowv1.GetReadableReportResponse{
		Format:       req.GetFormat(),
		Content:      raw,
		FindingCount: int32(len(b.findingsByRun[req.GetRunId()])),
	}, nil
}

func (b *integrationBackend) GetNodePayload(ctx context.Context, req *secflowv1.GetNodePayloadRequest) (*secflowv1.GetNodePayloadResponse, error) {
	b.recordTraceparent(ctx, "GetNodePayload")
	b.mu.Lock()
	defer b.mu.Unlock()

	resp, ok := b.payloadsByKey[req.GetRunId()+":"+req.GetNodeId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "node payload not found")
	}
	return resp, nil
}

func (b *integrationBackend) WatchRun(req *secflowv1.WatchRunRequest, stream grpc.ServerStreamingServer[secflowv1.WatchRunResponse]) error {
	b.mu.Lock()
	events := append([]*secflowv1.RunEvent(nil), b.runEventsStream[req.GetRunId()]...)
	b.mu.Unlock()

	for _, ev := range events {
		if ev.GetSeqId() <= req.GetAfterSeq() {
			continue
		}
		if err := stream.Send(&secflowv1.WatchRunResponse{Event: ev}); err != nil {
			return err
		}
	}
	return nil
}

// --- PluginRegistryServiceServer ---

func (b *integrationBackend) ListPlugins(ctx context.Context, req *secflowv1.ListPluginsRequest) (*secflowv1.ListPluginsResponse, error) {
	b.recordTraceparent(ctx, "ListPlugins")
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.failListPlugins != nil {
		return nil, b.failListPlugins
	}
	out := make([]*secflowv1.RegisteredPlugin, 0, len(b.plugins))
	for _, p := range b.plugins {
		if !req.GetIncludeDisabled() && !p.GetEnabled() {
			continue
		}
		out = append(out, p)
	}
	return &secflowv1.ListPluginsResponse{Plugins: out}, nil
}

func (b *integrationBackend) GetPlugin(ctx context.Context, req *secflowv1.GetPluginRequest) (*secflowv1.GetPluginResponse, error) {
	b.recordTraceparent(ctx, "GetPlugin")
	b.mu.Lock()
	defer b.mu.Unlock()

	p, ok := b.plugins[req.GetPluginId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "plugin not found")
	}
	return &secflowv1.GetPluginResponse{Plugin: p}, nil
}

func (b *integrationBackend) WatchPlugins(_ *secflowv1.WatchPluginsRequest, stream grpc.ServerStreamingServer[secflowv1.WatchPluginsResponse]) error {
	b.mu.Lock()
	events := append([]*secflowv1.PluginRegistryEvent(nil), b.pluginEventsStream...)
	b.mu.Unlock()

	for _, ev := range events {
		if err := stream.Send(&secflowv1.WatchPluginsResponse{Event: ev}); err != nil {
			return err
		}
	}
	return nil
}

func (b *integrationBackend) ListPluginInstallations(ctx context.Context, _ *secflowv1.ListPluginInstallationsRequest) (*secflowv1.ListPluginInstallationsResponse, error) {
	b.recordTraceparent(ctx, "ListPluginInstallations")
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*secflowv1.PluginInstallation, 0, len(b.installations))
	for _, inst := range b.installations {
		out = append(out, inst)
	}
	return &secflowv1.ListPluginInstallationsResponse{Installations: out}, nil
}

func (b *integrationBackend) GetPluginInstallation(ctx context.Context, req *secflowv1.GetPluginInstallationRequest) (*secflowv1.GetPluginInstallationResponse, error) {
	b.recordTraceparent(ctx, "GetPluginInstallation")
	b.mu.Lock()
	defer b.mu.Unlock()
	inst, ok := b.installations[req.GetInstallationId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "plugin installation not found")
	}
	return &secflowv1.GetPluginInstallationResponse{Installation: inst}, nil
}

func (b *integrationBackend) ListPluginPresets(ctx context.Context, _ *secflowv1.ListPluginPresetsRequest) (*secflowv1.ListPluginPresetsResponse, error) {
	b.recordTraceparent(ctx, "ListPluginPresets")
	b.mu.Lock()
	defer b.mu.Unlock()
	out := append([]*secflowv1.PluginPreset(nil), b.presets...)
	return &secflowv1.ListPluginPresetsResponse{Presets: out}, nil
}

func (b *integrationBackend) InstallPlugin(ctx context.Context, req *secflowv1.InstallPluginRequest) (*secflowv1.InstallPluginResponse, error) {
	b.recordTraceparent(ctx, "InstallPlugin")
	b.mu.Lock()
	defer b.mu.Unlock()
	now := timestamppb.Now()
	id := b.nextID("plginst")
	profile := req.GetSandboxProfile()
	if profile == secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED {
		profile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
	}
	replicas := req.GetDesiredReplicas()
	if replicas <= 0 {
		replicas = 1
	}
	rl := req.GetResourceLimits()
	if rl == nil {
		rl = &secflowv1.PluginResourceLimits{CpuRequest: "100m", CpuLimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "512Mi", MinReplicas: 1, MaxReplicas: 2}
	}
	inst := &secflowv1.PluginInstallation{
		Id:              id,
		Name:            req.GetName(),
		SourceMode:      req.GetSourceMode(),
		PresetId:        req.GetPresetId(),
		ImageRef:        req.GetImageRef(),
		SandboxProfile:  profile,
		EgressAllowlist: append([]string(nil), req.GetEgressAllowlist()...),
		ResourceLimits:  rl,
		DesiredReplicas: replicas,
		Status:          secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL,
		AutoApprove:     req.GetAutoApprove(),
		PluginIds:       []string{"scan.spring-config"},
		RuntimeDiagnostics: &secflowv1.PluginRuntimeDiagnostics{
			Phase:           "Pending",
			DesiredReplicas: replicas,
			ReadyReplicas:   0,
			Message:         "awaiting approval",
			UpdatedAt:       now,
		},
		CreatedBy: req.GetActor().GetSubject(),
		CreatedAt: now,
		UpdatedAt: now,
	}
	b.installations[id] = inst
	b.installationEventsStream = append(b.installationEventsStream, &secflowv1.PluginInstallationEvent{
		EventType:    secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED,
		Installation: inst,
		OccurredAt:   now,
	})
	var token string
	if req.GetSourceMode() == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL {
		token = "sf_plg_integration_token_" + id
	}
	return &secflowv1.InstallPluginResponse{Installation: inst, PlaintextPluginToken: token}, nil
}

func (b *integrationBackend) ApprovePluginInstallation(ctx context.Context, req *secflowv1.ApprovePluginInstallationRequest) (*secflowv1.ApprovePluginInstallationResponse, error) {
	b.recordTraceparent(ctx, "ApprovePluginInstallation")
	b.mu.Lock()
	defer b.mu.Unlock()
	inst, ok := b.installations[req.GetInstallationId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "plugin installation not found")
	}
	now := timestamppb.Now()
	inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
	inst.ApprovedBy = req.GetActor().GetSubject()
	inst.ApprovedAt = now
	inst.UpdatedAt = now
	b.plugins["scan.spring-config"] = &secflowv1.RegisteredPlugin{
		Manifest: &secflowv1.PluginManifest{
			PluginId:       "scan.spring-config",
			Version:        "1.0.0",
			DisplayName:    "Spring Config Hardening",
			Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
			IsExternal:     true,
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		},
		Status:         secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE,
		ActiveWorkers:  1,
		InstallationId: inst.GetId(),
		Enabled:        true,
		RegisteredAt:   now,
		LastSeenAt:     now,
	}
	return &secflowv1.ApprovePluginInstallationResponse{Installation: inst}, nil
}

func (b *integrationBackend) UpdatePluginInstallation(ctx context.Context, req *secflowv1.UpdatePluginInstallationRequest) (*secflowv1.UpdatePluginInstallationResponse, error) {
	b.recordTraceparent(ctx, "UpdatePluginInstallation")
	b.mu.Lock()
	defer b.mu.Unlock()
	inst, ok := b.installations[req.GetInstallationId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "plugin installation not found")
	}
	if req.GetImageRef() != "" {
		inst.ImageRef = req.GetImageRef()
	}
	if req.GetDesiredReplicas() > 0 {
		inst.DesiredReplicas = req.GetDesiredReplicas()
	}
	inst.UpdatedAt = timestamppb.Now()
	var token string
	if req.GetRotateToken() && inst.GetSourceMode() == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL {
		token = "sf_plg_rotated_" + inst.GetId()
	}
	return &secflowv1.UpdatePluginInstallationResponse{Installation: inst, PlaintextPluginToken: token}, nil
}

func (b *integrationBackend) SetPluginInstallationEnabled(ctx context.Context, req *secflowv1.SetPluginInstallationEnabledRequest) (*secflowv1.SetPluginInstallationEnabledResponse, error) {
	b.recordTraceparent(ctx, "SetPluginInstallationEnabled")
	b.mu.Lock()
	defer b.mu.Unlock()
	inst, ok := b.installations[req.GetInstallationId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "plugin installation not found")
	}
	if req.GetEnabled() {
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
	} else {
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DISABLED
	}
	inst.StatusReason = req.GetReason()
	inst.UpdatedAt = timestamppb.Now()
	if p, ok := b.plugins["scan.spring-config"]; ok && p.GetInstallationId() == inst.GetId() {
		p.Enabled = req.GetEnabled()
	}
	return &secflowv1.SetPluginInstallationEnabledResponse{Installation: inst}, nil
}

func (b *integrationBackend) DeletePluginInstallation(ctx context.Context, req *secflowv1.DeletePluginInstallationRequest) (*secflowv1.DeletePluginInstallationResponse, error) {
	b.recordTraceparent(ctx, "DeletePluginInstallation")
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.installations[req.GetInstallationId()]; !ok {
		return nil, status.Error(codes.NotFound, "plugin installation not found")
	}
	delete(b.installations, req.GetInstallationId())
	delete(b.plugins, "scan.spring-config")
	return &secflowv1.DeletePluginInstallationResponse{Deleted: true}, nil
}

func (b *integrationBackend) TestDeclarativePlugin(ctx context.Context, req *secflowv1.TestDeclarativePluginRequest) (*secflowv1.TestDeclarativePluginResponse, error) {
	b.recordTraceparent(ctx, "TestDeclarativePlugin")
	return &secflowv1.TestDeclarativePluginResponse{
		Ok:                true,
		ActiveOutputPorts: []string{"default"},
		DurationMs:        12,
		Summary:           "Test bench passed",
	}, nil
}

func (b *integrationBackend) ListSavedNodes(ctx context.Context, _ *secflowv1.ListSavedNodesRequest) (*secflowv1.ListSavedNodesResponse, error) {
	b.recordTraceparent(ctx, "ListSavedNodes")
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*secflowv1.SavedNode, 0, len(b.savedNodes))
	for _, sn := range b.savedNodes {
		out = append(out, sn)
	}
	return &secflowv1.ListSavedNodesResponse{SavedNodes: out}, nil
}

func (b *integrationBackend) SaveNode(ctx context.Context, req *secflowv1.SaveNodeRequest) (*secflowv1.SaveNodeResponse, error) {
	b.recordTraceparent(ctx, "SaveNode")
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.savedNodes == nil {
		b.savedNodes = map[string]*secflowv1.SavedNode{}
	}
	hash := fmt.Sprintf("hash_%s_%x", req.GetPluginId(), sha256.Sum256(req.GetParamsJson()))
	for _, existing := range b.savedNodes {
		if existing.GetPluginId() == req.GetPluginId() && existing.GetCanonicalParamsHash() == hash {
			return nil, status.Errorf(codes.AlreadyExists, "DUPLICATE_SAVED_NODE: already saved")
		}
	}
	now := timestamppb.Now()
	sn := &secflowv1.SavedNode{
		Id:                  fmt.Sprintf("snode_%d", len(b.savedNodes)+1),
		Name:                req.GetName(),
		Description:         req.GetDescription(),
		PluginId:            req.GetPluginId(),
		ParamsJson:          req.GetParamsJson(),
		CanonicalParamsHash: hash,
		CreatedBy:           req.GetActor().GetSubject(),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	b.savedNodes[sn.GetId()] = sn
	return &secflowv1.SaveNodeResponse{SavedNode: sn}, nil
}

func (b *integrationBackend) UpdateSavedNode(ctx context.Context, req *secflowv1.UpdateSavedNodeRequest) (*secflowv1.UpdateSavedNodeResponse, error) {
	b.recordTraceparent(ctx, "UpdateSavedNode")
	b.mu.Lock()
	defer b.mu.Unlock()
	sn := b.savedNodes[req.GetId()]
	if sn == nil {
		return nil, status.Error(codes.NotFound, "saved node not found")
	}
	if req.GetName() != "" {
		sn.Name = req.GetName()
	}
	if len(req.GetParamsJson()) > 0 {
		sn.ParamsJson = req.GetParamsJson()
		sn.CanonicalParamsHash = fmt.Sprintf("hash_%s_%x", sn.GetPluginId(), sha256.Sum256(req.GetParamsJson()))
	}
	sn.UpdatedAt = timestamppb.Now()
	return &secflowv1.UpdateSavedNodeResponse{SavedNode: sn}, nil
}

func (b *integrationBackend) DeleteSavedNode(ctx context.Context, req *secflowv1.DeleteSavedNodeRequest) (*secflowv1.DeleteSavedNodeResponse, error) {
	b.recordTraceparent(ctx, "DeleteSavedNode")
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.savedNodes[req.GetId()] == nil {
		return nil, status.Error(codes.NotFound, "saved node not found")
	}
	delete(b.savedNodes, req.GetId())
	return &secflowv1.DeleteSavedNodeResponse{Deleted: true}, nil
}

func (b *integrationBackend) WatchPluginInstallations(req *secflowv1.WatchPluginInstallationsRequest, stream grpc.ServerStreamingServer[secflowv1.WatchPluginInstallationsResponse]) error {
	b.mu.Lock()
	events := append([]*secflowv1.PluginInstallationEvent(nil), b.installationEventsStream...)
	b.mu.Unlock()
	for _, ev := range events {
		if req.GetInstallationId() != "" && ev.GetInstallation().GetId() != req.GetInstallationId() {
			continue
		}
		if err := stream.Send(&secflowv1.WatchPluginInstallationsResponse{Event: ev}); err != nil {
			return err
		}
	}
	return nil
}

// --- SecretServiceServer ---

func (b *integrationBackend) CreateSecret(ctx context.Context, req *secflowv1.CreateSecretRequest) (*secflowv1.CreateSecretResponse, error) {
	b.recordTraceparent(ctx, "CreateSecret")
	b.mu.Lock()
	defer b.mu.Unlock()

	now := timestamppb.Now()
	ref := b.nextID("sec")
	meta := &secflowv1.SecretMetadata{
		SecretRef:     ref,
		Name:          req.GetName(),
		Kind:          req.GetKind(),
		MaskedPreview: "****" + lastChars(req.GetPlaintextValue(), 2),
		Backend:       secflowv1.SecretStoreBackend_SECRET_STORE_BACKEND_PG_AES,
		CreatedBy:     req.GetActor().GetSubject(),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	b.secrets[ref] = meta
	b.secretValues[ref] = req.GetPlaintextValue()
	return &secflowv1.CreateSecretResponse{Secret: meta}, nil
}

func (b *integrationBackend) ListMaskedSecrets(ctx context.Context, _ *secflowv1.ListMaskedSecretsRequest) (*secflowv1.ListMaskedSecretsResponse, error) {
	b.recordTraceparent(ctx, "ListMaskedSecrets")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]*secflowv1.SecretMetadata, 0, len(b.secrets))
	for _, s := range b.secrets {
		out = append(out, s)
	}
	return &secflowv1.ListMaskedSecretsResponse{Secrets: out}, nil
}

func (b *integrationBackend) DeleteSecret(ctx context.Context, req *secflowv1.DeleteSecretRequest) (*secflowv1.DeleteSecretResponse, error) {
	b.recordTraceparent(ctx, "DeleteSecret")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.secrets[req.GetSecretRef()]; !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	delete(b.secrets, req.GetSecretRef())
	delete(b.secretValues, req.GetSecretRef())
	return &secflowv1.DeleteSecretResponse{Deleted: true}, nil
}

func (b *integrationBackend) ResolveScopedSecret(ctx context.Context, req *secflowv1.ResolveScopedSecretRequest) (*secflowv1.ResolveScopedSecretResponse, error) {
	b.recordTraceparent(ctx, "ResolveScopedSecret")
	b.mu.Lock()
	defer b.mu.Unlock()

	if req.GetServiceToken() != integrationServiceToken {
		return nil, status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
	}
	val, ok := b.secretValues[req.GetSecretRef()]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return &secflowv1.ResolveScopedSecretResponse{PlaintextValue: val}, nil
}

func (b *integrationBackend) IssueScopedToken(ctx context.Context, req *secflowv1.IssueScopedTokenRequest) (*secflowv1.IssueScopedTokenResponse, error) {
	b.recordTraceparent(ctx, "IssueScopedToken")
	b.mu.Lock()
	defer b.mu.Unlock()

	tokenID := b.nextID("tok")
	plain := "sf_int_" + tokenID
	meta := &secflowv1.ScopedTokenMetadata{
		TokenId:     tokenID,
		Name:        req.GetName(),
		TokenPrefix: "sf_int_",
		Scopes:      append([]string(nil), req.GetScopes()...),
		WorkflowId:  req.GetWorkflowId(),
		CreatedBy:   req.GetActor().GetSubject(),
		ExpiresAt:   req.GetExpiresAt(),
		CreatedAt:   timestamppb.Now(),
	}
	b.scopedTokens[tokenID] = meta
	b.tokenByID[tokenID] = plain
	b.tokenActors[plain] = &secflowv1.ActorContext{
		Subject:          "token:" + tokenID,
		Scopes:           append([]string(nil), req.GetScopes()...),
		ScopedWorkflowId: req.GetWorkflowId(),
		AuthMode:         secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN,
	}
	return &secflowv1.IssueScopedTokenResponse{
		Metadata:       meta,
		PlaintextToken: plain,
	}, nil
}

func (b *integrationBackend) ListScopedTokens(ctx context.Context, _ *secflowv1.ListScopedTokensRequest) (*secflowv1.ListScopedTokensResponse, error) {
	b.recordTraceparent(ctx, "ListScopedTokens")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]*secflowv1.ScopedTokenMetadata, 0, len(b.scopedTokens))
	for _, tok := range b.scopedTokens {
		out = append(out, tok)
	}
	return &secflowv1.ListScopedTokensResponse{Tokens: out}, nil
}

func (b *integrationBackend) RevokeScopedToken(ctx context.Context, req *secflowv1.RevokeScopedTokenRequest) (*secflowv1.RevokeScopedTokenResponse, error) {
	b.recordTraceparent(ctx, "RevokeScopedToken")
	b.mu.Lock()
	defer b.mu.Unlock()

	tok, ok := b.scopedTokens[req.GetTokenId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "token not found")
	}
	tok.RevokedAt = timestamppb.Now()
	if plain, exists := b.tokenByID[req.GetTokenId()]; exists {
		delete(b.tokenActors, plain)
	}
	return &secflowv1.RevokeScopedTokenResponse{Revoked: true}, nil
}

func (b *integrationBackend) VerifyScopedToken(_ context.Context, req *secflowv1.VerifyScopedTokenRequest) (*secflowv1.VerifyScopedTokenResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	actor, ok := b.tokenActors[req.GetPlaintextToken()]
	if !ok {
		return &secflowv1.VerifyScopedTokenResponse{Valid: false}, nil
	}
	return &secflowv1.VerifyScopedTokenResponse{
		Valid:   true,
		TokenId: actor.GetSubject(),
		Actor:   actor,
	}, nil
}

// --- CatalogServiceServer ---

func (b *integrationBackend) ListCatalogs(ctx context.Context, _ *secflowv1.ListCatalogsRequest) (*secflowv1.ListCatalogsResponse, error) {
	b.recordTraceparent(ctx, "ListCatalogs")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := append([]*secflowv1.VulnerabilityCatalog(nil), b.catalogs...)
	return &secflowv1.ListCatalogsResponse{Catalogs: out}, nil
}

func (b *integrationBackend) RegisterCatalog(ctx context.Context, req *secflowv1.RegisterCatalogRequest) (*secflowv1.RegisterCatalogResponse, error) {
	b.recordTraceparent(ctx, "RegisterCatalog")
	b.mu.Lock()
	defer b.mu.Unlock()

	cat := &secflowv1.VulnerabilityCatalog{
		Id:            b.nextID("cat"),
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
	}
	b.catalogs = append(b.catalogs, cat)
	return &secflowv1.RegisterCatalogResponse{Catalog: cat}, nil
}

// --- MCPRegistryServiceServer ---

func (b *integrationBackend) ListConnections(ctx context.Context, _ *secflowv1.ListConnectionsRequest) (*secflowv1.ListConnectionsResponse, error) {
	b.recordTraceparent(ctx, "ListConnections")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]*secflowv1.MCPConnection, 0, len(b.mcpConns))
	for _, c := range b.mcpConns {
		out = append(out, c)
	}
	return &secflowv1.ListConnectionsResponse{Connections: out}, nil
}

func (b *integrationBackend) RegisterConnection(ctx context.Context, req *secflowv1.RegisterConnectionRequest) (*secflowv1.RegisterConnectionResponse, error) {
	b.recordTraceparent(ctx, "RegisterConnection")
	b.mu.Lock()
	defer b.mu.Unlock()

	now := timestamppb.Now()
	id := b.nextID("mcp")
	conn := &secflowv1.MCPConnection{
		Id:        id,
		Config:    req.GetConfig(),
		Enabled:   true,
		CreatedBy: req.GetActor().GetSubject(),
		CreatedAt: now,
		UpdatedAt: now,
	}
	b.mcpConns[id] = conn
	b.mcpToolsByConn[id] = []*secflowv1.MCPToolDescriptor{{
		Name:            "notify_ticket",
		Description:     "Send ticket notification",
		InputSchemaJson: []byte(`{"type":"object"}`),
	}}
	return &secflowv1.RegisterConnectionResponse{Connection: conn}, nil
}

func (b *integrationBackend) UpdateConnection(ctx context.Context, req *secflowv1.UpdateConnectionRequest) (*secflowv1.UpdateConnectionResponse, error) {
	b.recordTraceparent(ctx, "UpdateConnection")
	b.mu.Lock()
	defer b.mu.Unlock()

	conn, ok := b.mcpConns[req.GetConnectionId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	conn.Config = req.GetConfig()
	conn.Enabled = req.GetEnabled()
	conn.UpdatedAt = timestamppb.Now()
	return &secflowv1.UpdateConnectionResponse{Connection: conn}, nil
}

func (b *integrationBackend) DeleteConnection(ctx context.Context, req *secflowv1.DeleteConnectionRequest) (*secflowv1.DeleteConnectionResponse, error) {
	b.recordTraceparent(ctx, "DeleteConnection")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.mcpConns[req.GetConnectionId()]; !ok {
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	delete(b.mcpConns, req.GetConnectionId())
	delete(b.mcpToolsByConn, req.GetConnectionId())
	return &secflowv1.DeleteConnectionResponse{Deleted: true}, nil
}

func (b *integrationBackend) ListConnectionTools(ctx context.Context, req *secflowv1.ListConnectionToolsRequest) (*secflowv1.ListConnectionToolsResponse, error) {
	b.recordTraceparent(ctx, "ListConnectionTools")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.mcpConns[req.GetConnectionId()]; !ok {
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	return &secflowv1.ListConnectionToolsResponse{
		ConnectionId:     req.GetConnectionId(),
		Tools:            b.mcpToolsByConn[req.GetConnectionId()],
		BlockedToolCount: 1,
		FetchedAt:        timestamppb.Now(),
	}, nil
}

func (b *integrationBackend) TestConnection(ctx context.Context, req *secflowv1.TestConnectionRequest) (*secflowv1.TestConnectionResponse, error) {
	b.recordTraceparent(ctx, "TestConnection")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.mcpConns[req.GetConnectionId()]; !ok {
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	return &secflowv1.TestConnectionResponse{
		Ok:                 true,
		ServerName:         "jira-mcp",
		ServerVersion:      "1.2.0",
		AvailableToolCount: int32(len(b.mcpToolsByConn[req.GetConnectionId()])),
		BlockedToolCount:   1,
	}, nil
}

// --- SourceIngesterServiceServer ---

func (b *integrationBackend) IngestUpload(ctx context.Context, req *secflowv1.IngestUploadRequest) (*secflowv1.IngestUploadResponse, error) {
	b.recordTraceparent(ctx, "IngestUpload")
	raw := req.GetArchiveZip()
	if bytes.Contains(raw, []byte("ZIP_BOMB_MARKER")) {
		return nil, status.Error(codes.ResourceExhausted, "ZIP_BOMB_DETECTED")
	}
	if bytes.Contains(raw, []byte("ZIP_SLIP_MARKER")) {
		return nil, status.Error(codes.InvalidArgument, "ZIP_SLIP_DETECTED")
	}

	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])

	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.sourcesBySHA[shaHex]; ok {
		return &secflowv1.IngestUploadResponse{
			SourceRef:       existing,
			DeduplicatedHit: true,
			IngestedAt:      timestamppb.Now(),
		}, nil
	}
	ref := &secflowv1.SourceRef{
		SourceId:  b.nextID("src"),
		Bucket:    "secflow-sources",
		Key:       shaHex + ".tar.gz",
		Sha256:    shaHex,
		RepoName:  req.GetRepoName(),
		SizeBytes: int64(len(raw)),
		FileCount: 5,
	}
	b.sourcesBySHA[shaHex] = ref
	return &secflowv1.IngestUploadResponse{
		SourceRef:       ref,
		DeduplicatedHit: false,
		IngestedAt:      timestamppb.Now(),
	}, nil
}

func (b *integrationBackend) CheckRepoAllowlist(ctx context.Context, req *secflowv1.CheckRepoAllowlistRequest) (*secflowv1.CheckRepoAllowlistResponse, error) {
	b.recordTraceparent(ctx, "CheckRepoAllowlist")
	u := strings.ToLower(strings.TrimSpace(req.GetRepoUrl()))
	if strings.Contains(u, "evil.example") {
		return &secflowv1.CheckRepoAllowlistResponse{Allowed: false, Reason: "host not allowlisted"}, nil
	}
	return &secflowv1.CheckRepoAllowlistResponse{Allowed: true}, nil
}

// --- AIServiceServer ---

func (b *integrationBackend) GenerateWorkflow(ctx context.Context, req *secflowv1.GenerateWorkflowRequest) (*secflowv1.GenerateWorkflowResponse, error) {
	b.recordTraceparent(ctx, "GenerateWorkflow")
	return &secflowv1.GenerateWorkflowResponse{
		SuggestedName:        "AI Kotlin Gate (" + req.GetLocale() + ")",
		SuggestedDescription: "Generated from prompt",
		Rationale:            "Includes trigger, source, and Kotlin SAST.",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{{
				Id:       "t1",
				PluginId: "trigger.manual",
				Label:    "Trigger",
				Position: &secflowv1.Position{X: 0, Y: 0},
			}},
		},
		MissingFields: []*secflowv1.ValidationIssue{{
			Code:      "MISSING_PARAM",
			Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING,
			Message:   "Configure repository URL",
			NodeId:    "t1",
			FieldPath: "params.repoUrl",
		}},
		ModelId:      "gpt-4o-mini",
		ProviderMode: secflowv1.AIProviderMode_AI_PROVIDER_MODE_CLOUD,
	}, nil
}

func (b *integrationBackend) GetProviderStatus(ctx context.Context, _ *secflowv1.GetProviderStatusRequest) (*secflowv1.GetProviderStatusResponse, error) {
	b.recordTraceparent(ctx, "GetProviderStatus")
	return &secflowv1.GetProviderStatusResponse{
		ProviderMode:       secflowv1.AIProviderMode_AI_PROVIDER_MODE_OLLAMA,
		ModelId:            "qwen2.5-coder:7b",
		EndpointHost:       "ollama.internal:11434",
		ClosedLoop:         true,
		DefaultPrivacyMode: secflowv1.PrivacyMode_PRIVACY_MODE_REDACTED_SNIPPET,
		Healthy:            true,
	}, nil
}

func (b *integrationBackend) ListAuditLogs(ctx context.Context, req *secflowv1.ListAuditLogsRequest) (*secflowv1.ListAuditLogsResponse, error) {
	b.recordTraceparent(ctx, "ListAuditLogs")
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]*secflowv1.AIAuditLogEntry, 0, len(b.auditLogs))
	for _, entry := range b.auditLogs {
		if req.GetRunId() != "" && entry.GetRunId() != req.GetRunId() {
			continue
		}
		out = append(out, entry)
	}
	return &secflowv1.ListAuditLogsResponse{Entries: out}, nil
}

func lastChars(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// --- Full-Stack Gateway Integration Test Harness ---

type gatewayTestEnv struct {
	server      *httptest.Server
	gw          *gateway
	backend     *integrationBackend
	client      *http.Client
	ownerToken  string
	editorToken string
	viewerToken string
}

func newGatewayTestEnv(t *testing.T) *gatewayTestEnv {
	t.Helper()

	schema, err := loadSchema()
	if err != nil {
		t.Fatalf("loadSchema: %v", err)
	}

	backend := newIntegrationBackend()
	lis := bufconn.Listen(2 << 20)
	grpcServer := grpc.NewServer(obs.GRPCServerOptions("test-backend")...)
	secflowv1.RegisterWorkflowServiceServer(grpcServer, backend)
	secflowv1.RegisterRunServiceServer(grpcServer, backend)
	secflowv1.RegisterPluginRegistryServiceServer(grpcServer, backend)
	secflowv1.RegisterSecretServiceServer(grpcServer, backend)
	secflowv1.RegisterCatalogServiceServer(grpcServer, backend)
	secflowv1.RegisterMCPRegistryServiceServer(grpcServer, backend)
	secflowv1.RegisterSourceIngesterServiceServer(grpcServer, backend)
	secflowv1.RegisterAIServiceServer(grpcServer, backend)

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		obs.GRPCDialOption(),
		grpc.WithUnaryInterceptor(traceparentUnaryInterceptor()),
	)
	if err != nil {
		grpcServer.Stop()
		_ = lis.Close()
		t.Fatalf("grpc.NewClient(bufconn): %v", err)
	}

	users := map[string]struct {
		pass string
		role string
	}{
		"owner@secflow.local":  {pass: "ownerpass", role: "owner"},
		"editor@secflow.local": {pass: "editorpass", role: "editor"},
		"viewer@secflow.local": {pass: "viewerpass", role: "viewer"},
	}

	gw := &gateway{
		schema:       schema,
		secret:       []byte("integration-jwt-secret"),
		serviceToken: integrationServiceToken,
		pgPing:       func(context.Context) error { return nil },
		garageCheck:  func(context.Context) error { return nil },
		userLookup: func(_ context.Context, email string) (string, string, bool, error) {
			u, ok := users[email]
			if !ok {
				return "", "", false, nil
			}
			return u.pass, u.role, true, nil
		},
		insp:        map[string][]inspectorEntry{},
		inspUpdated: map[string]time.Time{},
		subs:        map[string][]chan map[string]any{},
		wf:          secflowv1.NewWorkflowServiceClient(conn),
		runs:        secflowv1.NewRunServiceClient(conn),
		plugs:       secflowv1.NewPluginRegistryServiceClient(conn),
		secs:        secflowv1.NewSecretServiceClient(conn),
		cats:        secflowv1.NewCatalogServiceClient(conn),
		mcp:         secflowv1.NewMCPRegistryServiceClient(conn),
		ingest:      secflowv1.NewSourceIngesterServiceClient(conn),
		ai:          secflowv1.NewAIServiceClient(conn),
	}

	srv := httptest.NewServer(gw.handler())
	t.Cleanup(func() {
		srv.Close()
		_ = conn.Close()
		grpcServer.Stop()
		_ = lis.Close()
	})

	env := &gatewayTestEnv{
		server:  srv,
		gw:      gw,
		backend: backend,
		client:  srv.Client(),
	}
	env.ownerToken = env.loginAs(t, "owner@secflow.local", "ownerpass")
	env.editorToken = env.loginAs(t, "editor@secflow.local", "editorpass")
	env.viewerToken = env.loginAs(t, "viewer@secflow.local", "viewerpass")
	return env
}

func (e *gatewayTestEnv) loginAs(t *testing.T, email, password string) string {
	t.Helper()
	data := e.mustGraphQL(t, "", `mutation($in: LoginInput!) { login(input: $in) { accessToken } }`, map[string]any{
		"in": map[string]any{"email": email, "password": password},
	})
	loginData, ok := data["login"].(map[string]any)
	if !ok {
		t.Fatalf("login response missing login object: %#v", data)
	}
	tok, ok := loginData["accessToken"].(string)
	if !ok || tok == "" {
		t.Fatalf("login response missing accessToken: %#v", loginData)
	}
	return tok
}

func (e *gatewayTestEnv) doRequest(
	t *testing.T,
	method, path, token string,
	headers map[string]string,
	body io.Reader,
) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, e.server.URL+path, body)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response %s %s: %v", method, path, err)
	}
	return resp.StatusCode, resp.Header, raw
}

func (e *gatewayTestEnv) doMultipart(
	t *testing.T,
	path, token, filename string,
	content []byte,
	fields map[string]string,
	headers map[string]string,
) (int, http.Header, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %s: %v", k, err)
		}
	}
	if filename != "" {
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatalf("write file part: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	hdrs := map[string]string{"Content-Type": mw.FormDataContentType()}
	for k, v := range headers {
		hdrs[k] = v
	}
	return e.doRequest(t, http.MethodPost, path, token, hdrs, &buf)
}

type gqlEnvelope struct {
	Data   map[string]any   `json:"data"`
	Errors []map[string]any `json:"errors"`
}

func (e *gatewayTestEnv) postGraphQL(
	t *testing.T,
	token, query string,
	variables map[string]any,
	headers map[string]string,
) (int, gqlEnvelope) {
	t.Helper()
	payload := map[string]any{"query": query}
	if variables != nil {
		payload["variables"] = variables
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal graphql payload: %v", err)
	}
	hdrs := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		hdrs[k] = v
	}
	code, _, rawResp := e.doRequest(t, http.MethodPost, "/graphql", token, hdrs, bytes.NewReader(rawBody))
	var env gqlEnvelope
	if len(rawResp) > 0 {
		if err := json.Unmarshal(rawResp, &env); err != nil {
			t.Fatalf("unmarshal graphql response (status=%d body=%s): %v", code, string(rawResp), err)
		}
	}
	return code, env
}

func (e *gatewayTestEnv) mustGraphQL(t *testing.T, token, query string, variables map[string]any) map[string]any {
	t.Helper()
	code, env := e.postGraphQL(t, token, query, variables, nil)
	if code != http.StatusOK || len(env.Errors) > 0 {
		t.Fatalf("expected GraphQL 200 with no errors, got status=%d errors=%#v data=%#v", code, env.Errors, env.Data)
	}
	return env.Data
}

func (e *gatewayTestEnv) postMCP(
	t *testing.T,
	token, sessionID string,
	rpcBody map[string]any,
) (int, http.Header, map[string]any) {
	t.Helper()
	rawBody, err := json.Marshal(rpcBody)
	if err != nil {
		t.Fatalf("marshal mcp body: %v", err)
	}
	hdrs := map[string]string{"Content-Type": "application/json"}
	if sessionID != "" {
		hdrs[mcpSessionHeader] = sessionID
	}
	code, respHdr, rawResp := e.doRequest(t, http.MethodPost, "/mcp", token, hdrs, bytes.NewReader(rawBody))
	var out map[string]any
	if len(bytes.TrimSpace(rawResp)) > 0 {
		if err := json.Unmarshal(rawResp, &out); err != nil {
			t.Fatalf("unmarshal mcp response (status=%d body=%s): %v", code, string(rawResp), err)
		}
	}
	return code, respHdr, out
}

func (e *gatewayTestEnv) openGraphQLWS(t *testing.T, initPayload map[string]any) *gorilla.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(e.server.URL, "http") + "/graphql"
	dialer := gorilla.Dialer{Subprotocols: []string{"graphql-transport-ws"}}
	conn, resp, err := dialer.DialContext(t.Context(), wsURL, nil)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial graphql ws: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if err := conn.WriteJSON(map[string]any{
		"type":    "connection_init",
		"payload": initPayload,
	}); err != nil {
		t.Fatalf("write connection_init: %v", err)
	}
	msg := readWSJSON(t, conn)
	if msg["type"] != "connection_ack" {
		t.Fatalf("expected connection_ack, got %#v", msg)
	}
	return conn
}

func readWSJSON(t *testing.T, conn *gorilla.Conn) map[string]any {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var msg map[string]any
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read ws json: %v", err)
	}
	return msg
}

func decodeJSONMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal json (%s): %v", string(raw), err)
	}
	return m
}

func signSHA256Header(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func firstErrorCode(errs []map[string]any) string {
	if len(errs) == 0 {
		return ""
	}
	ext, ok := errs[0]["extensions"].(map[string]any)
	if !ok {
		return ""
	}
	code, _ := ext["code"].(string)
	return code
}

func mustMap(t *testing.T, v any, label string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: expected object map, got %T (%#v)", label, v, v)
	}
	return m
}

func mustSlice(t *testing.T, v any, label string) []any {
	t.Helper()
	s, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: expected slice, got %T (%#v)", label, v, v)
	}
	return s
}

func mustString(t *testing.T, v any, label string) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%s: expected string, got %T (%#v)", label, v, v)
	}
	return s
}
