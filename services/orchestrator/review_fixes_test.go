package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/report"
)

func TestMigrationsSchema_ContainsUsersExpiresAtAndCatalogBucket(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("migrations", "001_init.sql"))
	if err != nil {
		t.Fatalf("read 001_init.sql: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS users",
		"password_hash text NOT NULL",
		"ALTER TABLE scoped_tokens ADD COLUMN IF NOT EXISTS expires_at timestamptz;",
		"ALTER TABLE catalogs ADD COLUMN IF NOT EXISTS bucket text NOT NULL DEFAULT 'secflow-catalogs';",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("001_init.sql missing %q", want)
		}
	}
}

func TestListPlugins_SourcePluginsAreOnline(t *testing.T) {
	t.Parallel()
	s := newServer()
	resp, err := s.ListPlugins(t.Context(), &secflowv1.ListPluginsRequest{IncludeOffline: false})
	if err != nil {
		t.Fatalf("ListPlugins: %v", err)
	}
	byID := map[string]*secflowv1.RegisteredPlugin{}
	for _, p := range resp.GetPlugins() {
		byID[p.GetManifest().GetPluginId()] = p
	}
	for _, pid := range []string{"source.upload", "source.git"} {
		rp := byID[pid]
		if rp == nil {
			t.Fatalf("plugin %s missing from ListPlugins", pid)
		}
		if rp.GetStatus() != secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE {
			t.Fatalf("plugin %s status = %v, want ONLINE", pid, rp.GetStatus())
		}
		if rp.GetActiveWorkers() < 1 {
			t.Fatalf("plugin %s activeWorkers = %d, want >= 1", pid, rp.GetActiveWorkers())
		}
	}
}

func TestConnect_MinimalWorkerManifestPreservesCanonicalFields(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	workerCli := secflowv1.NewWorkerServiceClient(conn)
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stream, err := workerCli.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	minimal := manifest.One("notify.telegram", "", secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED, nil, false)
	minimal.Description = ""
	minimal.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED
	minimal.RequiredSecretKeys = nil
	minimal.ParamsJsonSchema = nil
	minimal.InputPorts = nil
	minimal.OutputPorts = nil

	if err := stream.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: "notify-1",
				Manifests:        []*secflowv1.PluginManifest{minimal},
			},
		},
	}); err != nil {
		t.Fatalf("RegisterManifest: %v", err)
	}
	ack, err := stream.Recv()
	if err != nil || !ack.GetManifestAck().GetAccepted() {
		t.Fatalf("ManifestAck failed: %+v err=%v", ack, err)
	}

	got, err := plugCli.GetPlugin(ctx, &secflowv1.GetPluginRequest{PluginId: "notify.telegram"})
	if err != nil {
		t.Fatalf("GetPlugin: %v", err)
	}
	m := got.GetPlugin().GetManifest()
	if m.GetDisplayName() == "" || m.GetDescription() == "" {
		t.Fatalf("canonical displayName/description erased: %+v", m)
	}
	if m.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
		t.Fatalf("SandboxProfile = %v, want EGRESS_EXTERNAL", m.GetSandboxProfile())
	}
	if len(m.GetRequiredSecretKeys()) != 1 || m.GetRequiredSecretKeys()[0] != "botToken" {
		t.Fatalf("RequiredSecretKeys = %v, want [botToken]", m.GetRequiredSecretKeys())
	}
	if len(m.GetParamsJsonSchema()) == 0 {
		t.Fatal("ParamsJsonSchema was erased")
	}
	if m.GetCategory() != secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION {
		t.Fatalf("Category = %v, want ACTION", m.GetCategory())
	}
	if len(m.GetInputPorts()) == 0 || len(m.GetOutputPorts()) == 0 {
		t.Fatalf("ports erased: in=%v out=%v", m.GetInputPorts(), m.GetOutputPorts())
	}
}

func TestRunPopulatesAIReportAndSbomCounts(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	var seenNodeRunIDs sync.Map
	registerFakeWorker(s, "scan.sca", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		seenNodeRunIDs.Store(task.GetNodeId(), task.GetNodeRunId())
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  "scan.sca",
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings: []*secflowv1.Finding{
				{
					Category:   secflowv1.FindingCategory_FINDING_CATEGORY_SCA,
					Path:       "build.gradle.kts",
					Group:      "org.apache.commons",
					Artifact:   "commons-text",
					Version:    "1.9",
					AdvisoryId: "CVE-2022-42889",
					Severity:   secflowv1.Severity_SEVERITY_CRITICAL,
				},
			},
		}
	})
	registerFakeWorker(s, "sbom.generate", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		seenNodeRunIDs.Store(task.GetNodeId(), task.GetNodeRunId())
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  "sbom.generate",
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			EnvelopePatchJson: []byte(`{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"components": [
					{"name": "commons-text", "version": "1.9"},
					{"name": "spring-boot", "version": "3.2.0"}
				],
				"vulnerabilities": [
					{"id": "CVE-2022-42889"}
				]
			}`),
		}
	})
	registerFakeWorker(s, "ai.explain", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		seenNodeRunIDs.Store(task.GetNodeId(), task.GetNodeRunId())
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  "ai.explain",
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			EnvelopePatchJson: []byte(`{
				"quality": "VERIFIED",
				"modelId": "gpt-4o-mini",
				"providerMode": "CLOUD",
				"privacyMode": "METADATA_ONLY",
				"releaseDecision": "BLOCK",
				"executiveSummary": "Critical Text4Shell finding detected.",
				"items": [
					{"findingId": "F-001", "priorityRank": 1, "plainLanguageRisk": "RCE", "remediationSteps": ["Upgrade commons-text"]}
				]
			}`),
		}
	})

	wf := &secflowv1.Workflow{
		Id:      "wf_ai_sbom",
		Name:    "AI and SBOM",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "s1", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "sca1", PluginId: "scan.sca", ParamsJson: []byte(`{}`)},
				{Id: "sbom1", PluginId: "sbom.generate", ParamsJson: []byte(`{}`)},
				{Id: "ai1", PluginId: "ai.explain", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "s1", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "s1", SourceHandle: "default", TargetNodeId: "sca1", TargetHandle: "default"},
				{Id: "e3", SourceNodeId: "sca1", SourceHandle: "default", TargetNodeId: "sbom1", TargetHandle: "default"},
				{Id: "e4", SourceNodeId: "sbom1", SourceHandle: "default", TargetNodeId: "ai1", TargetHandle: "default"},
			},
		},
	}
	s.wfMu.Lock()
	s.workflows[wf.GetId()] = wf
	s.wfMu.Unlock()

	startResp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wf.GetId()})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := startResp.GetRun().GetId()
	waitForRunEvents(t, ctx, s, runID)

	// Verify node_run_id sent to workers matches runID:nodeID (for PG lease renewal).
	for _, nid := range []string{"sca1", "sbom1", "ai1"} {
		gotID, _ := seenNodeRunIDs.Load(nid)
		if gotID != runID+":"+nid {
			t.Fatalf("node %s received nodeRunId=%v, want %q", nid, gotID, runID+":"+nid)
		}
	}

	gotRun, err := s.GetRun(ctx, &secflowv1.GetRunRequest{RunId: runID})
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if gotRun.GetRun().GetAiReport() == nil || gotRun.GetRun().GetAiReport().GetExecutiveSummary() != "Critical Text4Shell finding detected." {
		t.Fatalf("Run.AiReport not populated: %+v", gotRun.GetRun().GetAiReport())
	}
	if gotRun.GetRun().GetSbom() == nil || gotRun.GetRun().GetSbom().GetComponentCount() != 2 || gotRun.GetRun().GetSbom().GetVulnerabilityCount() != 1 {
		t.Fatalf("Run.Sbom counts wrong: %+v", gotRun.GetRun().GetSbom())
	}

	sbomResp, err := s.GetSbom(ctx, &secflowv1.GetSbomRequest{RunId: runID, IncludeContent: true})
	if err != nil {
		t.Fatalf("GetSbom: %v", err)
	}
	if sbomResp.GetSbom().GetComponentCount() != 2 || sbomResp.GetSbom().GetVulnerabilityCount() != 1 {
		t.Fatalf("GetSbom counts wrong: %+v", sbomResp.GetSbom())
	}
}

func TestCallWorker_ContextCancelSendsCancelTaskAndDefaultTimeout(t *testing.T) {
	t.Parallel()
	s := newServer()

	dispatched := make(chan *secflowv1.NodeTask, 1)
	cancelled := make(chan *secflowv1.CancelTask, 1)
	link := &workerLink{
		instanceID: "cancel-test",
		plugins:    []string{"scan.sast.kotlin"},
		send: func(msg *secflowv1.ConnectResponse) error {
			if task := msg.GetDispatchTask(); task != nil {
				dispatched <- task
			}
			if c := msg.GetCancelTask(); c != nil {
				cancelled <- c
			}
			return nil
		},
	}
	s.plugMu.Lock()
	s.workers["scan.sast.kotlin"] = []*workerLink{link}
	s.plugMu.Unlock()

	callCtx, cancel := context.WithCancel(t.Context())
	done := make(chan engine.Result, 1)
	go func() {
		res, _ := s.callWorker(callCtx, "scan.sast.kotlin", engine.Node{ID: "sast1", PluginID: "scan.sast.kotlin"}, engine.Envelope{
			RunID: "run_ctx",
			Vars:  map[string]string{"runId": "run_ctx"},
		})
		done <- res
	}()

	task := <-dispatched
	if task.GetNodeRunId() != "run_ctx:sast1" {
		t.Fatalf("NodeRunId = %q, want run_ctx:sast1", task.GetNodeRunId())
	}
	if task.GetHardTimeoutSeconds() != 120 {
		t.Fatalf("HardTimeoutSeconds = %d, want 120", task.GetHardTimeoutSeconds())
	}
	cancel()

	select {
	case c := <-cancelled:
		if c.GetNodeRunId() != "run_ctx:sast1" {
			t.Fatalf("CancelTask NodeRunId = %q, want run_ctx:sast1", c.GetNodeRunId())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CancelTask on context cancellation")
	}

	res := <-done
	if res.Status != "FAILED" {
		t.Fatalf("expected FAILED after cancel, got %+v", res)
	}
}

func TestListFindings_DistinctIDsFingerprintsMetadataAndPagination(t *testing.T) {
	t.Parallel()
	s := newServer()
	s.runs["run_f"] = &runState{
		run: &secflowv1.Run{Id: "run_f", Status: secflowv1.RunStatus_RUN_STATUS_SUCCEEDED},
		findings: []report.Finding{
			{Category: "SECRET", Path: "src/App.kt", Class: "password", Line: 10, Severity: "CRITICAL"},
			{Category: "SECRET", Path: "src/App.kt", Class: "api-key", Line: 22, Severity: "HIGH"},
			{Category: "SAST", Path: "src/App.kt", Class: "sql-injection", Line: 45, Severity: "HIGH"},
		},
		findingMeta: []findingMeta{
			{sourceNodeID: "sec1", pluginID: "scan.secrets", isNewVsBaseline: true},
			{sourceNodeID: "sec1", pluginID: "scan.secrets", isNewVsBaseline: false},
			{sourceNodeID: "sast1", pluginID: "scan.sast.kotlin", isNewVsBaseline: true},
		},
		payloads: map[string][]byte{},
	}

	resp, err := s.ListFindings(t.Context(), &secflowv1.ListFindingsRequest{
		RunId: "run_f",
		Page:  &secflowv1.PageRequest{Limit: 2},
	})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(resp.GetFindings()) != 2 {
		t.Fatalf("page 1 len = %d, want 2", len(resp.GetFindings()))
	}
	if resp.GetPageInfo().GetTotalCount() != 3 || !resp.GetPageInfo().GetHasMore() || resp.GetPageInfo().GetNextCursor() != "2" {
		t.Fatalf("unexpected PageInfo: %+v", resp.GetPageInfo())
	}
	if resp.GetStats().GetTotal() != 3 || resp.GetStats().GetNewCount() != 2 || resp.GetStats().GetCritical() != 1 {
		t.Fatalf("unexpected Stats: %+v", resp.GetStats())
	}

	f0, f1 := resp.GetFindings()[0], resp.GetFindings()[1]
	if f0.GetFindingId() != "F-001" || f1.GetFindingId() != "F-002" {
		t.Fatalf("findingIds = (%q, %q), want (F-001, F-002)", f0.GetFindingId(), f1.GetFindingId())
	}
	if f0.GetFingerprint() == "" || f1.GetFingerprint() == "" || f0.GetFingerprint() == f1.GetFingerprint() {
		t.Fatalf("fingerprints must be non-empty and distinct: (%q, %q)", f0.GetFingerprint(), f1.GetFingerprint())
	}
	if f0.GetSourceNodeId() != "sec1" || f0.GetPluginId() != "scan.secrets" || !f0.GetIsNewVsBaseline() {
		t.Fatalf("f0 metadata missing: %+v", f0)
	}
}

func TestMcpTool_RespectsCustomOutputVarKey(t *testing.T) {
	t.Parallel()
	s := newServer()

	var seenParams map[string]any
	registerFakeWorker(s, "mcp.tool", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		_ = json.Unmarshal(task.GetParamsJson(), &seenParams)
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "mcp.tool",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			EnvelopePatchJson: []byte(`{"ticket":"SEC-42"}`),
		}
	})

	res, ok := s.callWorker(t.Context(), "mcp.tool", engine.Node{
		ID:       "m1",
		PluginID: "mcp.tool",
		Params:   map[string]any{"connectionId": "c1", "toolName": "create_ticket", "outputVarKey": "jiraTicket"},
	}, engine.Envelope{RunID: "r1", Vars: map[string]string{"runId": "r1"}})
	if !ok || res.Status != "SUCCEEDED" {
		t.Fatalf("callWorker mcp.tool failed: ok=%v res=%+v", ok, res)
	}
	if seenParams["outputVarKey"] != "jiraTicket" {
		t.Fatalf("worker did not receive outputVarKey=jiraTicket: %+v", seenParams)
	}
	if res.Envelope.Vars["jiraTicket"] != `{"ticket":"SEC-42"}` {
		t.Fatalf("result not stored under env.Vars[jiraTicket]: %+v", res.Envelope.Vars)
	}
}

func TestRegisterCatalog_MetadataDefaultBucketAndClearsOlderDefault(t *testing.T) {
	t.Parallel()
	s := newServer()
	actor := &secflowv1.ActorContext{Subject: "owner@secflow.local"}

	first, err := s.RegisterCatalog(t.Context(), &secflowv1.RegisterCatalogRequest{
		Actor:         actor,
		Name:          "v1",
		S3Key:         "v1.json",
		Sha256:        "aaa",
		SnapshotDate:  "2026-01-01",
		AdvisoryCount: 5,
		SetAsDefault:  true,
	})
	if err != nil {
		t.Fatalf("RegisterCatalog v1: %v", err)
	}
	if first.GetCatalog().GetBucket() != "secflow-catalogs" || first.GetCatalog().GetSnapshotDate() != "2026-01-01" || first.GetCatalog().GetUploadedBy() != "owner@secflow.local" || !first.GetCatalog().GetIsDefault() {
		t.Fatalf("unexpected v1 catalog: %+v", first.GetCatalog())
	}

	second, err := s.RegisterCatalog(t.Context(), &secflowv1.RegisterCatalogRequest{
		Actor:         actor,
		Name:          "v2",
		Bucket:        "custom-bucket",
		S3Key:         "v2.json",
		Sha256:        "bbb",
		SnapshotDate:  "2026-02-01",
		AdvisoryCount: 10,
		SetAsDefault:  true,
	})
	if err != nil {
		t.Fatalf("RegisterCatalog v2: %v", err)
	}
	if second.GetCatalog().GetBucket() != "custom-bucket" || !second.GetCatalog().GetIsDefault() {
		t.Fatalf("unexpected v2 catalog: %+v", second.GetCatalog())
	}

	gotFirst, err := s.GetCatalog(t.Context(), &secflowv1.GetCatalogRequest{CatalogId: first.GetCatalog().GetId()})
	if err != nil {
		t.Fatalf("GetCatalog v1: %v", err)
	}
	if gotFirst.GetCatalog().GetIsDefault() {
		t.Fatal("v1 IsDefault should have been cleared when v2 was set as default")
	}
}

type captureSourceIngester struct {
	mu           sync.Mutex
	gitURLs      []string
	getSourceIDs []string
}

func (c *captureSourceIngester) IngestGit(_ context.Context, req *secflowv1.IngestGitRequest, _ ...grpc.CallOption) (*secflowv1.IngestGitResponse, error) {
	c.mu.Lock()
	c.gitURLs = append(c.gitURLs, req.GetRepoUrl())
	c.mu.Unlock()
	return &secflowv1.IngestGitResponse{SourceRef: &secflowv1.SourceRef{SourceId: "src_git", RepoUrl: req.GetRepoUrl()}}, nil
}

func (c *captureSourceIngester) IngestUpload(context.Context, *secflowv1.IngestUploadRequest, ...grpc.CallOption) (*secflowv1.IngestUploadResponse, error) {
	return &secflowv1.IngestUploadResponse{}, nil
}

func (c *captureSourceIngester) GetSource(_ context.Context, req *secflowv1.GetSourceRequest, _ ...grpc.CallOption) (*secflowv1.GetSourceResponse, error) {
	c.mu.Lock()
	c.getSourceIDs = append(c.getSourceIDs, req.GetSourceId())
	c.mu.Unlock()
	return &secflowv1.GetSourceResponse{SourceRef: &secflowv1.SourceRef{SourceId: req.GetSourceId()}}, nil
}

func (c *captureSourceIngester) CheckRepoAllowlist(context.Context, *secflowv1.CheckRepoAllowlistRequest, ...grpc.CallOption) (*secflowv1.CheckRepoAllowlistResponse, error) {
	return &secflowv1.CheckRepoAllowlistResponse{Allowed: true}, nil
}

func TestStartRun_RepoAllowlistValidationAndOverrides(t *testing.T) {
	t.Parallel()
	s := newServer()
	ing := &captureSourceIngester{}
	s.ingest = ing

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	wfGit := &secflowv1.Workflow{
		Id:      "wf_git_ov",
		Name:    "Git Override",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "s1", PluginId: "source.git", ParamsJson: []byte(`{"repoUrl":"https://github.com/TBagirov/training","gitRef":"main"}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "s1", TargetHandle: "default"}},
		},
	}
	wfUp := &secflowv1.Workflow{
		Id:      "wf_up_ov",
		Name:    "Upload Override",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "s1", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"old-src"}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "s1", TargetHandle: "default"}},
		},
	}
	s.wfMu.Lock()
	s.workflows[wfGit.GetId()] = wfGit
	s.workflows[wfUp.GetId()] = wfUp
	s.wfMu.Unlock()

	// Disallowed repoUrlOverride must fail synchronously BEFORE creating a run.
	_, err := s.StartRun(ctx, &secflowv1.StartRunRequest{
		WorkflowId:      wfGit.GetId(),
		RepoUrlOverride: "https://evil.example.com/org/repo",
	})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "ALLOWLIST_DENIED") {
		t.Fatalf("disallowed repoUrlOverride err=%v, want PermissionDenied/ALLOWLIST_DENIED", err)
	}
	runsResp, _ := s.ListRuns(ctx, &secflowv1.ListRunsRequest{})
	if len(runsResp.GetRuns()) != 0 {
		t.Fatalf("rejected StartRun should not have created a run, got %d", len(runsResp.GetRuns()))
	}

	// Valid repoUrlOverride overrides node repoUrl.
	rGit, err := s.StartRun(ctx, &secflowv1.StartRunRequest{
		WorkflowId:      wfGit.GetId(),
		RepoUrlOverride: "https://github.com/TBagirov/training.git",
	})
	if err != nil {
		t.Fatalf("StartRun git override: %v", err)
	}
	waitForRunEvents(t, ctx, s, rGit.GetRun().GetId())

	// Valid sourceIdOverride overrides source.upload node sourceId.
	rUp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{
		WorkflowId:       wfUp.GetId(),
		SourceIdOverride: "src_override_99",
	})
	if err != nil {
		t.Fatalf("StartRun upload override: %v", err)
	}
	waitForRunEvents(t, ctx, s, rUp.GetRun().GetId())

	ing.mu.Lock()
	defer ing.mu.Unlock()
	if len(ing.gitURLs) != 1 || ing.gitURLs[0] != "https://github.com/TBagirov/training.git" {
		t.Fatalf("gitURLs = %v, want override URL", ing.gitURLs)
	}
	if len(ing.getSourceIDs) != 1 || ing.getSourceIDs[0] != "src_override_99" {
		t.Fatalf("getSourceIDs = %v, want [src_override_99]", ing.getSourceIDs)
	}
}

func TestPolish_FailRunEventRerunPersistSecretBindingsAndNodePayloadStatus(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	// 1. failRun emits RUN_EVENT_TYPE_RUN_FAILED.
	stFail := &runState{run: &secflowv1.Run{Id: "run_failed_ev", Status: secflowv1.RunStatus_RUN_STATUS_FAILED}}
	s.failRun(ctx, stFail, "boom")
	if len(stFail.events) != 1 || stFail.events[0].GetEventType() != secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_FAILED {
		t.Fatalf("failRun emitted %+v, want RUN_EVENT_TYPE_RUN_FAILED", stFail.events)
	}

	// 2. RerunFromNode with persistWorkflowChanges=true persists BOTH params AND secretBindings.
	registerFakeWorker(s, "notify.telegram", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  "notify.telegram",
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		}
	})
	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Persist Rerun",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{
					Id:             "tg1",
					PluginId:       "notify.telegram",
					ParamsJson:     []byte(`{"chatId":"100"}`),
					SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "botToken", SecretRef: "sec_old"}},
				},
			},
			Edges: []*secflowv1.WorkflowEdge{{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "tg1", TargetHandle: "default"}},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	wfID := wfResp.GetWorkflow().GetId()
	startResp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wfID})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	origRunID := startResp.GetRun().GetId()
	waitForRunEvents(t, ctx, s, origRunID)

	rerunResp, err := s.RerunFromNode(ctx, &secflowv1.RerunFromNodeRequest{
		SourceRunId:            origRunID,
		NodeId:                 "tg1",
		UpdatedParamsJson:      []byte(`{"chatId":"200"}`),
		UpdatedSecretBindings:  []*secflowv1.SecretBinding{{ParamKey: "botToken", SecretRef: "sec_new"}},
		PersistWorkflowChanges: true,
	})
	if err != nil {
		t.Fatalf("RerunFromNode: %v", err)
	}

	gotWf, err := s.GetWorkflow(ctx, &secflowv1.GetWorkflowRequest{WorkflowId: wfID})
	if err != nil {
		t.Fatalf("GetWorkflow: %v", err)
	}
	for _, n := range gotWf.GetWorkflow().GetGraph().GetNodes() {
		if n.GetId() != "tg1" {
			continue
		}
		if !strings.Contains(string(n.GetParamsJson()), `"200"`) {
			t.Fatalf("persisted params missing 200: %s", string(n.GetParamsJson()))
		}
		if len(n.GetSecretBindings()) != 1 || n.GetSecretBindings()[0].GetSecretRef() != "sec_new" {
			t.Fatalf("persisted secretBindings not updated: %+v", n.GetSecretBindings())
		}
	}

	// 3. GetNodePayload sets real PluginId and actual NodeRunStatus.
	np, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{
		RunId:  rerunResp.GetRun().GetId(),
		NodeId: "tg1",
	})
	if err != nil {
		t.Fatalf("GetNodePayload: %v", err)
	}
	if np.GetPluginId() != "notify.telegram" || np.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
		t.Fatalf("GetNodePayload plugin/status = (%q, %v), want (notify.telegram, SUCCEEDED)", np.GetPluginId(), np.GetStatus())
	}

	// 4. Cloning prevents mutation of internal server state.
	gotWf.GetWorkflow().Name = "MUTATED_BY_CALLER"
	gotWfAgain, _ := s.GetWorkflow(ctx, &secflowv1.GetWorkflowRequest{WorkflowId: wfID})
	if gotWfAgain.GetWorkflow().GetName() == "MUTATED_BY_CALLER" {
		t.Fatal("GetWorkflow returned live pointer instead of clone")
	}
}

func TestDeterministicListOrdering(t *testing.T) {
	t.Parallel()
	s := newServer()

	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	// ListRuns: CreatedAt DESC, tie-break Id DESC.
	s.runMu.Lock()
	s.runs["run_a"] = &runState{run: &secflowv1.Run{Id: "run_a", WorkflowId: "wf_1", CreatedAt: timestamppb.New(t2)}}
	s.runs["run_c"] = &runState{run: &secflowv1.Run{Id: "run_c", WorkflowId: "wf_1", CreatedAt: timestamppb.New(t2)}}
	s.runs["run_old"] = &runState{run: &secflowv1.Run{Id: "run_old", WorkflowId: "wf_1", CreatedAt: timestamppb.New(t1)}}
	s.runs["run_new"] = &runState{run: &secflowv1.Run{Id: "run_new", WorkflowId: "wf_1", CreatedAt: timestamppb.New(t3)}}
	s.runMu.Unlock()

	runsResp, err := s.ListRuns(t.Context(), &secflowv1.ListRunsRequest{WorkflowId: "wf_1"})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	wantRunIDs := []string{"run_new", "run_c", "run_a", "run_old"}
	if len(runsResp.GetRuns()) != len(wantRunIDs) {
		t.Fatalf("ListRuns count = %d, want %d", len(runsResp.GetRuns()), len(wantRunIDs))
	}
	for i, want := range wantRunIDs {
		if got := runsResp.GetRuns()[i].GetId(); got != want {
			t.Fatalf("ListRuns[%d] = %q, want %q", i, got, want)
		}
	}

	// ListWorkflows: UpdatedAt DESC, tie-break Id ASC.
	s.wfMu.Lock()
	s.workflows = map[string]*secflowv1.Workflow{
		"wf_b":   {Id: "wf_b", Name: "Beta", UpdatedAt: timestamppb.New(t2)},
		"wf_a":   {Id: "wf_a", Name: "Alpha", UpdatedAt: timestamppb.New(t2)},
		"wf_old": {Id: "wf_old", Name: "Old", UpdatedAt: timestamppb.New(t1)},
		"wf_new": {Id: "wf_new", Name: "New", UpdatedAt: timestamppb.New(t3)},
	}
	s.templates = map[string]*secflowv1.WorkflowTemplate{
		"tpl_u2": {Id: "tpl_u2", Name: "Zeta Custom", IsBuiltin: false},
		"tpl_b2": {Id: "tpl_b2", Name: "Kotlin SAST", IsBuiltin: true},
		"tpl_u1": {Id: "tpl_u1", Name: "Alpha Custom", IsBuiltin: false},
		"tpl_b1": {Id: "tpl_b1", Name: "Android Pipeline", IsBuiltin: true},
	}
	s.wfMu.Unlock()

	wfResp, err := s.ListWorkflows(t.Context(), &secflowv1.ListWorkflowsRequest{})
	if err != nil {
		t.Fatalf("ListWorkflows: %v", err)
	}
	wantWfIDs := []string{"wf_new", "wf_a", "wf_b", "wf_old"}
	if len(wfResp.GetWorkflows()) != len(wantWfIDs) {
		t.Fatalf("ListWorkflows count = %d, want %d", len(wfResp.GetWorkflows()), len(wantWfIDs))
	}
	for i, want := range wantWfIDs {
		if got := wfResp.GetWorkflows()[i].GetId(); got != want {
			t.Fatalf("ListWorkflows[%d] = %q, want %q", i, got, want)
		}
	}

	// ListTemplates: IsBuiltin DESC, Name ASC.
	tplResp, err := s.ListTemplates(t.Context(), &secflowv1.ListTemplatesRequest{})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	wantTplIDs := []string{"tpl_b1", "tpl_b2", "tpl_u1", "tpl_u2"}
	if len(tplResp.GetTemplates()) != len(wantTplIDs) {
		t.Fatalf("ListTemplates count = %d, want %d", len(tplResp.GetTemplates()), len(wantTplIDs))
	}
	for i, want := range wantTplIDs {
		if got := tplResp.GetTemplates()[i].GetId(); got != want {
			t.Fatalf("ListTemplates[%d] = %q, want %q", i, got, want)
		}
	}
}
