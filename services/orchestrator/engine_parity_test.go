package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/report"
)

type fakeIngester struct {
	mu      sync.Mutex
	gitReqs []*secflowv1.IngestGitRequest
}

func (f *fakeIngester) IngestGit(_ context.Context, in *secflowv1.IngestGitRequest, _ ...grpc.CallOption) (*secflowv1.IngestGitResponse, error) {
	f.mu.Lock()
	f.gitReqs = append(f.gitReqs, in)
	f.mu.Unlock()
	return &secflowv1.IngestGitResponse{
		SourceRef: &secflowv1.SourceRef{
			SourceId:  "src_git_1",
			Bucket:    "secflow-sources",
			Key:       "deadbeef.tar.gz",
			Sha256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			RepoName:  "repair-desk",
			RepoUrl:   in.GetRepoUrl(),
			GitRef:    in.GetGitRef(),
			CommitSha: in.GetGitRef(),
		},
	}, nil
}

func (f *fakeIngester) IngestUpload(context.Context, *secflowv1.IngestUploadRequest, ...grpc.CallOption) (*secflowv1.IngestUploadResponse, error) {
	return &secflowv1.IngestUploadResponse{}, nil
}

func (f *fakeIngester) GetSource(context.Context, *secflowv1.GetSourceRequest, ...grpc.CallOption) (*secflowv1.GetSourceResponse, error) {
	return &secflowv1.GetSourceResponse{}, nil
}

func (f *fakeIngester) CheckRepoAllowlist(context.Context, *secflowv1.CheckRepoAllowlistRequest, ...grpc.CallOption) (*secflowv1.CheckRepoAllowlistResponse, error) {
	return &secflowv1.CheckRepoAllowlistResponse{Allowed: true}, nil
}

func registerFakeWorker(s *Server, pluginID string, fn func(task *secflowv1.NodeTask) *secflowv1.NodeResult) {
	link := &workerLink{
		instanceID: "fake-" + pluginID,
		plugins:    []string{pluginID},
		send: func(msg *secflowv1.ConnectResponse) error {
			task := msg.GetDispatchTask()
			if task == nil {
				return nil
			}
			go func() {
				s.deliver(fn(task))
			}()
			return nil
		},
	}
	s.plugMu.Lock()
	s.workers[pluginID] = append(s.workers[pluginID], link)
	s.plugMu.Unlock()
}

func waitForRunEvents(t *testing.T, ctx context.Context, s *Server, runID string) []*secflowv1.RunEvent {
	t.Helper()
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	wc := &watchCollector{ctx: watchCtx, cancel: watchCancel, events: make(chan *secflowv1.RunEvent, 64)}
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.WatchRun(&secflowv1.WatchRunRequest{RunId: runID}, wc)
	}()

	var events []*secflowv1.RunEvent
	for {
		select {
		case ev := <-wc.events:
			events = append(events, ev)
			if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_COMPLETED {
				return events
			}
		case err := <-errCh:
			if err != nil {
				t.Fatalf("WatchRun(%s): %v", runID, err)
			}
		case <-ctx.Done():
			t.Fatalf("run %s did not finish before timeout (events=%d)", runID, len(events))
		}
	}
}

func TestOrchestrator_RegexSplitEnvelopeAndPolicyGateEvent(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	registerFakeWorker(s, "scan.secrets", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  task.GetPluginId(),
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings: []*secflowv1.Finding{
				{
					FindingId:    "F-1",
					Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SECRET,
					Path:         "src/App.kt",
					FindingClass: "password",
					Severity:     secflowv1.Severity_SEVERITY_CRITICAL,
				},
				{
					FindingId:    "F-2",
					Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
					Path:         "docs/Example.kt",
					FindingClass: "tls-verification",
					Severity:     secflowv1.Severity_SEVERITY_LOW,
				},
			},
		}
	})

	wf := &secflowv1.Workflow{
		Id:      "wf_split_gate",
		Name:    "Split and Gate",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "s1", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "scan1", PluginId: "scan.secrets", ParamsJson: []byte(`{}`)},
				{Id: "rx1", PluginId: "logic.regex", ParamsJson: []byte(`{"field":"path","pattern":"^src/","splitEnvelope":true}`)},
				{Id: "gate_match", PluginId: "gate.policy", ParamsJson: []byte(`{"failOnSeverity":"HIGH","warnOnSeverity":"MEDIUM","failOnAnySecret":true}`)},
				{Id: "rep_nomatch", PluginId: "report.export", ParamsJson: []byte(`{"title":"NoMatch total={{ $envelope.stats.total }}","notes":"max={{ $envelope.stats.maxSeverity }}"}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "s1", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "s1", SourceHandle: "default", TargetNodeId: "scan1", TargetHandle: "default"},
				{Id: "e3", SourceNodeId: "scan1", SourceHandle: "default", TargetNodeId: "rx1", TargetHandle: "default"},
				{Id: "e4", SourceNodeId: "rx1", SourceHandle: "match", TargetNodeId: "gate_match", TargetHandle: "default"},
				{Id: "e5", SourceNodeId: "rx1", SourceHandle: "nomatch", TargetNodeId: "rep_nomatch", TargetHandle: "default"},
			},
		},
	}
	s.wfMu.Lock()
	s.workflows[wf.GetId()] = wf
	s.wfMu.Unlock()

	resp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wf.GetId()})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := resp.GetRun().GetId()
	events := waitForRunEvents(t, ctx, s, runID)

	var gateEv *secflowv1.RunEvent
	for _, ev := range events {
		if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_GATE_EVALUATED {
			gateEv = ev
		}
	}
	if gateEv == nil || gateEv.GetGateResult().GetStatus() != secflowv1.GateStatus_GATE_STATUS_FAIL {
		t.Fatalf("expected RUN_EVENT_TYPE_GATE_EVALUATED with FAIL, got %+v", gateEv)
	}

	gotRun, err := s.GetRun(ctx, &secflowv1.GetRunRequest{RunId: runID})
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if gotRun.GetRun().GetGateResult().GetStatus() != secflowv1.GateStatus_GATE_STATUS_FAIL {
		t.Fatalf("run.GateResult = %+v, want FAIL", gotRun.GetRun().GetGateResult())
	}

	// Verify logic.regex splitEnvelope delivered only matching finding to gate_match
	// and only non-matching finding to rep_nomatch.
	gatePayload, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "gate_match"})
	if err != nil {
		t.Fatalf("GetNodePayload(gate_match): %v", err)
	}
	var gateIn engine.Envelope
	if err := json.Unmarshal(gatePayload.GetInputEnvelopeJson(), &gateIn); err != nil {
		t.Fatalf("unmarshal gateIn: %v", err)
	}
	if len(gateIn.Findings) != 1 || gateIn.Findings[0].Path != "src/App.kt" {
		t.Fatalf("gate_match input findings = %+v, want only src/App.kt", gateIn.Findings)
	}

	repPayload, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "rep_nomatch"})
	if err != nil {
		t.Fatalf("GetNodePayload(rep_nomatch): %v", err)
	}
	var repOut engine.Envelope
	if err := json.Unmarshal(repPayload.GetOutputEnvelopeJson(), &repOut); err != nil {
		t.Fatalf("unmarshal repOut: %v", err)
	}
	if len(repOut.Findings) != 1 || repOut.Findings[0].Path != "docs/Example.kt" {
		t.Fatalf("rep_nomatch findings = %+v, want only docs/Example.kt", repOut.Findings)
	}
	if repOut.Vars["reportTitle"] != "NoMatch total=1" || repOut.Vars["reportNotes"] != "max=LOW" {
		t.Fatalf("report.export expressions not resolved: title=%q notes=%q", repOut.Vars["reportTitle"], repOut.Vars["reportNotes"])
	}

	// Verify GetNodePayload(sourceHandle="nomatch") returns port-specific envelope.
	rxNoMatch, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "rx1", SourceHandle: "nomatch"})
	if err != nil {
		t.Fatalf("GetNodePayload(rx1, nomatch): %v", err)
	}
	var rxNoMatchEnv engine.Envelope
	if err := json.Unmarshal(rxNoMatch.GetOutputEnvelopeJson(), &rxNoMatchEnv); err != nil {
		t.Fatalf("unmarshal rxNoMatch: %v", err)
	}
	if len(rxNoMatchEnv.Findings) != 1 || rxNoMatchEnv.Findings[0].Path != "docs/Example.kt" {
		t.Fatalf("rx1 nomatch port findings = %+v", rxNoMatchEnv.Findings)
	}
}

func TestOrchestrator_BaselineDiffFromPreviousSucceededRun(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	wf := &secflowv1.Workflow{
		Id:      "wf_baseline",
		Name:    "Baseline Diff",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "s1", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "scan1", PluginId: "scan.sast.kotlin", ParamsJson: []byte(`{}`)},
				{Id: "cmp1", PluginId: "logic.compare", ParamsJson: []byte(`{"mode":"baselineDiff","minNewFindingsForTrue":1}`)},
				{Id: "rep_new", PluginId: "report.export", ParamsJson: []byte(`{"title":"New={{ $envelope.stats.newCount }}"}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "s1", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "s1", SourceHandle: "default", TargetNodeId: "scan1", TargetHandle: "default"},
				{Id: "e3", SourceNodeId: "scan1", SourceHandle: "default", TargetNodeId: "cmp1", TargetHandle: "default"},
				{Id: "e4", SourceNodeId: "cmp1", SourceHandle: "true", TargetNodeId: "rep_new", TargetHandle: "default"},
			},
		},
	}
	s.wfMu.Lock()
	s.workflows[wf.GetId()] = wf
	s.wfMu.Unlock()

	// Seed a previous SUCCEEDED run with one existing finding.
	prevFinished := timestamppb.New(time.Now().Add(-10 * time.Minute))
	s.runMu.Lock()
	s.runs["run_prev_ok"] = &runState{
		run: &secflowv1.Run{
			Id:         "run_prev_ok",
			WorkflowId: wf.GetId(),
			Status:     secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
			FinishedAt: prevFinished,
		},
		findings: []report.Finding{
			{Category: "SAST", Path: "src/Old.kt", Class: "sql-injection", Severity: "HIGH"},
		},
		payloads: map[string][]byte{},
		finished: true,
	}
	s.runMu.Unlock()

	registerFakeWorker(s, "scan.sast.kotlin", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  task.GetPluginId(),
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings: []*secflowv1.Finding{
				{FindingId: "F-1", Category: secflowv1.FindingCategory_FINDING_CATEGORY_SAST, Path: "src/Old.kt", FindingClass: "sql-injection", Severity: secflowv1.Severity_SEVERITY_HIGH},
				{FindingId: "F-2", Category: secflowv1.FindingCategory_FINDING_CATEGORY_SAST, Path: "src/New.kt", FindingClass: "object-authorization", Severity: secflowv1.Severity_SEVERITY_CRITICAL},
			},
		}
	})

	resp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wf.GetId()})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := resp.GetRun().GetId()
	waitForRunEvents(t, ctx, s, runID)

	cmpPayload, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "cmp1"})
	if err != nil {
		t.Fatalf("GetNodePayload(cmp1): %v", err)
	}
	var cmpOut engine.Envelope
	if err := json.Unmarshal(cmpPayload.GetOutputEnvelopeJson(), &cmpOut); err != nil {
		t.Fatalf("unmarshal cmpOut: %v", err)
	}
	if cmpOut.Stats.Total != 2 || cmpOut.Stats.NewCount != 1 {
		t.Fatalf("cmp1 stats = %+v, want total=2 newCount=1", cmpOut.Stats)
	}
	repPayload, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "rep_new"})
	if err != nil {
		t.Fatalf("GetNodePayload(rep_new): %v", err)
	}
	var repOut engine.Envelope
	if err := json.Unmarshal(repPayload.GetOutputEnvelopeJson(), &repOut); err != nil {
		t.Fatalf("unmarshal repOut: %v", err)
	}
	if repOut.Vars["reportTitle"] != "New=1" {
		t.Fatalf("expected reportTitle=New=1, got %q", repOut.Vars["reportTitle"])
	}
}

func TestOrchestrator_SourceGitExpressionResolutionAndUnresolvedError(t *testing.T) {
	t.Parallel()
	s := newServer()
	ing := &fakeIngester{}
	s.ingest = ing

	// 1. Valid {{ $trigger.repoUrl }} and {{ $trigger.commitSha }} resolve cleanly.
	env := engine.Envelope{
		Trigger: engine.TriggerInfo{
			Type:      "WEBHOOK",
			RepoURL:   "https://github.com/TBagirov/training",
			CommitSHA: "abc123def",
		},
		Vars: map[string]string{"runId": "run_expr_1"},
	}
	res := s.ingestSource(engine.Node{
		ID:       "src1",
		PluginID: "source.git",
		Params: map[string]any{
			"repoUrl": "{{ $trigger.repoUrl }}",
			"gitRef":  "{{ $trigger.commitSha }}",
		},
	}, env, true)
	if res.Status != "SUCCEEDED" {
		t.Fatalf("ingestSource resolved expr failed: %s (%s)", res.Status, res.Err)
	}
	if len(ing.gitReqs) != 1 || ing.gitReqs[0].GetRepoUrl() != "https://github.com/TBagirov/training" || ing.gitReqs[0].GetGitRef() != "abc123def" {
		t.Fatalf("IngestGit requests = %+v", ing.gitReqs)
	}
	if res.Envelope.SourceRef == nil || res.Envelope.SourceRef.SourceID != "src_git_1" {
		t.Fatalf("SourceRef not populated on Envelope: %+v", res.Envelope.SourceRef)
	}

	// 2. Unresolved {{ $trigger.missing }} fails loudly instead of silent no-op.
	badRes := s.ingestSource(engine.Node{
		ID:       "src2",
		PluginID: "source.git",
		Params: map[string]any{
			"repoUrl": "{{ $trigger.missing }}",
			"gitRef":  "main",
		},
	}, env, true)
	if badRes.Status != "FAILED" || !strings.Contains(badRes.Err, "unresolved expression") {
		t.Fatalf("expected FAILED on unresolved expression, got status=%s err=%q", badRes.Status, badRes.Err)
	}
}

func TestOrchestrator_McpToolExpressionEvaluation(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	var gotParams map[string]any
	registerFakeWorker(s, "mcp.tool", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		_ = json.Unmarshal(task.GetParamsJson(), &gotParams)
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          task.GetPluginId(),
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			EnvelopePatchJson: []byte(`{"issueUrl":"https://github.com/org/repo/issues/99"}`),
		}
	})

	wf := &secflowv1.Workflow{
		Id:      "wf_mcp_expr",
		Name:    "MCP Expr",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.webhook", ParamsJson: []byte(`{"gitProvider":"GITHUB"}`), SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "webhookSecret", SecretRef: "sec_wh"}}},
				{Id: "m1", PluginId: "mcp.tool", ParamsJson: []byte(`{"connectionId":"conn_1","toolName":"create_issue","arguments":{"title":"PR on {{ $trigger.branch }}","sha":"{{ $trigger.commitSha }}"}}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "m1", TargetHandle: "default"},
			},
		},
	}
	s.wfMu.Lock()
	s.workflows[wf.GetId()] = wf
	s.wfMu.Unlock()

	resp, err := s.StartRunFromWebhook(ctx, &secflowv1.StartRunFromWebhookRequest{
		WorkflowId: wf.GetId(),
		Trigger: &secflowv1.TriggerMetadata{
			Type:      secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
			Branch:    "feature/sec",
			CommitSha: "cafebabe",
			RepoUrl:   "https://github.com/TBagirov/training",
		},
	})
	if err != nil {
		t.Fatalf("StartRunFromWebhook: %v", err)
	}
	waitForRunEvents(t, ctx, s, resp.GetRun().GetId())

	args, _ := gotParams["arguments"].(map[string]any)
	if args["title"] != "PR on feature/sec" || args["sha"] != "cafebabe" {
		t.Fatalf("mcp.tool arguments were not evaluated: %#v", args)
	}
}

func TestOrchestrator_RerunFromNodeUsesCachedInputAndRunsDownstream(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.startPump(ctx)

	scanCalls := 0
	registerFakeWorker(s, "scan.secrets", func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		scanCalls++
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  task.GetPluginId(),
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings: []*secflowv1.Finding{
				{FindingId: "F-1", Category: secflowv1.FindingCategory_FINDING_CATEGORY_SECRET, Path: "a.kt", FindingClass: "password", Severity: secflowv1.Severity_SEVERITY_CRITICAL},
				{FindingId: "F-2", Category: secflowv1.FindingCategory_FINDING_CATEGORY_SAST, Path: "b.kt", FindingClass: "tls-verification", Severity: secflowv1.Severity_SEVERITY_LOW},
			},
		}
	})

	wf := &secflowv1.Workflow{
		Id:      "wf_rerun_downstream",
		Name:    "Rerun Downstream",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "s1", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "scan1", PluginId: "scan.secrets", ParamsJson: []byte(`{}`)},
				// Filter narrows branch to LOW-only SAST (drops CRITICAL SECRET), while Run Findings keeps both!
				{Id: "flt1", PluginId: "logic.filter", ParamsJson: []byte(`{"categories":["SAST"]}`)},
				{Id: "gate1", PluginId: "gate.policy", ParamsJson: []byte(`{"failOnSeverity":"HIGH","warnOnSeverity":"LOW","failOnAnySecret":true}`)},
				{Id: "rep_warn", PluginId: "report.export", ParamsJson: []byte(`{"title":"Warn count={{ $envelope.stats.total }}"}`)},
				{Id: "rep_pass", PluginId: "report.export", ParamsJson: []byte(`{"title":"Pass count={{ $envelope.stats.total }}"}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "s1", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "s1", SourceHandle: "default", TargetNodeId: "scan1", TargetHandle: "default"},
				{Id: "e3", SourceNodeId: "scan1", SourceHandle: "default", TargetNodeId: "flt1", TargetHandle: "default"},
				{Id: "e4", SourceNodeId: "flt1", SourceHandle: "default", TargetNodeId: "gate1", TargetHandle: "default"},
				{Id: "e5", SourceNodeId: "gate1", SourceHandle: "WARN", TargetNodeId: "rep_warn", TargetHandle: "default"},
				{Id: "e6", SourceNodeId: "gate1", SourceHandle: "PASS", TargetNodeId: "rep_pass", TargetHandle: "default"},
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
	origRunID := startResp.GetRun().GetId()
	waitForRunEvents(t, ctx, s, origRunID)
	if scanCalls != 1 {
		t.Fatalf("scanCalls = %d, want 1", scanCalls)
	}

	// Now RerunFromNode starting at gate1 with warnOnSeverity raised to MEDIUM.
	// If RerunFromNode erroneously used global prev.findings (which contains CRITICAL SECRET),
	// gate1 would FAIL! Using cached in:gate1 (only LOW SAST) MUST produce PASS and run rep_pass downstream!
	rerunResp, err := s.RerunFromNode(ctx, &secflowv1.RerunFromNodeRequest{
		SourceRunId:       origRunID,
		NodeId:            "gate1",
		UpdatedParamsJson: []byte(`{"failOnSeverity":"HIGH","warnOnSeverity":"MEDIUM","failOnAnySecret":true}`),
	})
	if err != nil {
		t.Fatalf("RerunFromNode: %v", err)
	}
	if scanCalls != 1 {
		t.Fatalf("upstream analyzer re-executed during rerun: scanCalls=%d", scanCalls)
	}
	rerunID := rerunResp.GetRun().GetId()
	if rerunResp.GetRun().GetGateResult().GetStatus() != secflowv1.GateStatus_GATE_STATUS_PASS {
		t.Fatalf("rerun GateResult = %+v, want PASS (cached filtered in.json should have excluded SECRET)", rerunResp.GetRun().GetGateResult())
	}

	// Verify downstream rep_pass executed with resolved expressions.
	passPayload, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: rerunID, NodeId: "rep_pass"})
	if err != nil {
		t.Fatalf("GetNodePayload(rep_pass): %v", err)
	}
	var passOut engine.Envelope
	if err := json.Unmarshal(passPayload.GetOutputEnvelopeJson(), &passOut); err != nil {
		t.Fatalf("unmarshal rep_pass: %v", err)
	}
	if passOut.Vars["reportTitle"] != "Pass count=1" {
		t.Fatalf("downstream rep_pass did not execute properly: vars=%+v", passOut.Vars)
	}

	// Verify authoritative submission.json on rerun still preserves BOTH original findings (ADR-0004).
	subResp, err := s.GetSubmissionReport(ctx, &secflowv1.GetSubmissionReportRequest{RunId: rerunID})
	if err != nil {
		t.Fatalf("GetSubmissionReport: %v", err)
	}
	if subResp.GetFindingCount() != 2 {
		t.Fatalf("authoritative submission findingCount = %d, want 2", subResp.GetFindingCount())
	}
}
