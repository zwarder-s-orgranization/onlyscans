package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/protoconv"
	"github.com/secflow/secflow/services/internal/report"
	"github.com/secflow/secflow/services/internal/urlguard"
)

func (s *Server) StartRun(ctx context.Context, req *secflowv1.StartRunRequest) (*secflowv1.StartRunResponse, error) {
	run, _, err := s.startRunWithTrigger(ctx, req, nil, false)
	if err != nil {
		return nil, err
	}
	return &secflowv1.StartRunResponse{Run: run}, nil
}

func (s *Server) hasPersistedIdempotencyKey(ctx context.Context, key string) bool {
	if s.pool == nil || key == "" {
		return false
	}
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var exists bool
	if err := s.pool.QueryRow(dbCtx, `SELECT EXISTS(SELECT 1 FROM runs WHERE idempotency_key = $1)`, key).Scan(&exists); err != nil {
		slog.Warn("check idempotency key in db", "err", err)
		return false
	}
	return exists
}

func (s *Server) startRunWithTrigger(ctx context.Context, req *secflowv1.StartRunRequest, explicitTrig *secflowv1.TriggerMetadata, rejectDuplicate bool) (*secflowv1.Run, string, error) {
	idemKey := strings.TrimSpace(req.GetIdempotencyKey())
	if idemKey != "" {
		s.runMu.Lock()
		prev, ok := s.idem[idemKey]
		var st *runState
		if ok {
			st = s.runs[prev]
		}
		s.runMu.Unlock()
		if ok {
			if rejectDuplicate {
				return nil, "", status.Error(codes.AlreadyExists, "DUPLICATE_DELIVERY: duplicate webhook delivery")
			}
			if st != nil {
				s.runMu.Lock()
				snap := cloneRun(st.run)
				tr := st.trace
				s.runMu.Unlock()
				return snap, tr, nil
			}
		}
		if rejectDuplicate && s.hasPersistedIdempotencyKey(ctx, idemKey) {
			return nil, "", status.Error(codes.AlreadyExists, "DUPLICATE_DELIVERY: duplicate webhook delivery")
		}
	}
	repoOverride := strings.TrimSpace(req.GetRepoUrlOverride())
	if repoOverride != "" {
		if ok, _, reason := urlguard.RepoAllowed(repoOverride, os.Getenv("REPO_ALLOWLIST")); !ok {
			if reason == "" {
				reason = "repoUrlOverride is outside allowlist"
			}
			return nil, "", status.Errorf(codes.PermissionDenied, "ALLOWLIST_DENIED: %s", reason)
		}
	}
	wf := s.mustWorkflow(req.GetWorkflowId())
	if wf == nil {
		return nil, "", status.Error(codes.NotFound, "workflow not found")
	}
	if issues := s.validateGraph(ctx, req.GetActor(), wf.GetGraph()); hasProtoValidationError(issues) {
		for _, iss := range issues {
			if iss.GetSeverity() == secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR {
				if iss.GetNodeId() != "" {
					return nil, "", status.Errorf(codes.InvalidArgument, "%s (node %s): %s", iss.GetCode(), iss.GetNodeId(), iss.GetMessage())
				}
				return nil, "", status.Errorf(codes.InvalidArgument, "%s: %s", iss.GetCode(), iss.GetMessage())
			}
		}
	}
	runID := id("run")
	tp := obs.InjectTraceparent(ctx)
	if tp == "" {
		if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("traceparent")) > 0 {
			tp = md.Get("traceparent")[0]
		}
	}
	tid := obs.TraceIDFromContext(ctx)
	if tid == "" {
		tid = traceID(tp)
	}
	now := timestamppb.Now()
	trig := explicitTrig
	if trig == nil && (req.GetTriggerType() != secflowv1.TriggerType_TRIGGER_TYPE_UNSPECIFIED || req.GetRepoUrlOverride() != "" || req.GetGitRefOverride() != "" || req.GetCommitShaOverride() != "") {
		trig = &secflowv1.TriggerMetadata{
			Type:        req.GetTriggerType(),
			RepoUrl:     req.GetRepoUrlOverride(),
			Branch:      req.GetGitRefOverride(),
			CommitSha:   req.GetCommitShaOverride(),
			TriggeredBy: subject(req.GetActor()),
			TriggeredAt: now,
		}
	}
	if trig == nil {
		trig = &secflowv1.TriggerMetadata{
			Type:        secflowv1.TriggerType_TRIGGER_TYPE_MANUAL,
			TriggeredBy: subject(req.GetActor()),
			TriggeredAt: now,
		}
	}
	if trig.TriggeredAt == nil {
		trig.TriggeredAt = now
	}
	payloads := map[string][]byte{}
	if baseline := s.latestBaselineFingerprints(ctx, wf.GetId(), runID); len(baseline) > 0 {
		if raw, err := json.Marshal(baseline); err == nil {
			payloads["_baseline_fingerprints"] = raw
		}
	}
	run := &secflowv1.Run{
		Id:              runID,
		WorkflowId:      wf.GetId(),
		WorkflowVersion: wf.GetVersion(),
		WorkflowName:    wf.GetName(),
		Status:          secflowv1.RunStatus_RUN_STATUS_QUEUED,
		Trigger:         trig,
		CreatedAt:       now,
		TraceId:         tid,
	}
	st := &runState{
		run:            run,
		idempotencyKey: idemKey,
		payloads:       payloads,
		graph:          toEngine(wf.GetGraph()),
		sourceID:       strings.TrimSpace(req.GetSourceIdOverride()),
		repoURL:        repoOverride,
		trace:          tp,
		done:           map[string]engine.NodeTrace{},
		skipped:        map[string]bool{},
		queued:         map[string]bool{},
	}
	s.runMu.Lock()
	if idemKey != "" {
		if prev, exists := s.idem[idemKey]; exists {
			existing := s.runs[prev]
			var snap *secflowv1.Run
			var tr string
			if existing != nil {
				snap = cloneRun(existing.run)
				tr = existing.trace
			}
			s.runMu.Unlock()
			if rejectDuplicate {
				return nil, "", status.Error(codes.AlreadyExists, "DUPLICATE_DELIVERY: duplicate webhook delivery")
			}
			if snap != nil {
				return snap, tr, nil
			}
		}
		s.idem[idemKey] = runID
	}
	s.runs[runID] = st
	toPersist := s.enqueueReadyLocked(st)
	runSnap := cloneRun(run)
	s.runMu.Unlock()
	s.persistQueuedTasks(ctx, toPersist)
	s.persistRun(ctx, st)
	s.pushEvent(ctx, st, secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_STARTED, secflowv1.RunStatus_RUN_STATUS_QUEUED, "run queued")
	s.kick()
	return runSnap, tp, nil
}

func cloneRun(r *secflowv1.Run) *secflowv1.Run {
	if r == nil {
		return nil
	}
	cp, _ := proto.Clone(r).(*secflowv1.Run)
	return cp
}

func (s *Server) latestBaselineFingerprints(ctx context.Context, workflowID, excludeRunID string) []string {
	var bestFindings []report.Finding
	var bestTime time.Time
	found := false

	s.runMu.Lock()
	for _, st := range s.runs {
		if st == nil || st.run == nil {
			continue
		}
		if st.run.GetWorkflowId() != workflowID || st.run.GetId() == excludeRunID {
			continue
		}
		if st.run.GetStatus() != secflowv1.RunStatus_RUN_STATUS_SUCCEEDED {
			continue
		}
		ts := st.run.GetFinishedAt().AsTime()
		if st.run.GetFinishedAt() == nil && st.run.GetCreatedAt() != nil {
			ts = st.run.GetCreatedAt().AsTime()
		}
		if !found || ts.After(bestTime) {
			bestTime = ts
			bestFindings = slices.Clone(st.findings)
			found = true
		}
	}
	s.runMu.Unlock()

	if !found && s.pool != nil {
		dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var raw []byte
		err := s.pool.QueryRow(dbCtx, `
			SELECT findings_json FROM runs
			WHERE workflow_id = $1 AND status = 'RUN_STATUS_SUCCEEDED' AND id <> $2
			ORDER BY COALESCE(finished_at, created_at) DESC
			LIMIT 1`, workflowID, excludeRunID).Scan(&raw)
		if err == nil && len(raw) > 0 {
			if json.Unmarshal(raw, &bestFindings) == nil {
				found = true
			}
		}
	}

	if !found || len(bestFindings) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(bestFindings))
	out := make([]string, 0, len(bestFindings))
	for _, f := range bestFindings {
		fp := engine.FindingFingerprint(engine.Finding{
			Category:   f.Category,
			Path:       f.Path,
			Class:      f.Class,
			Group:      f.Group,
			Artifact:   f.Artifact,
			AdvisoryID: f.AdvisoryID,
		})
		if fp != "" && !seen[fp] {
			seen[fp] = true
			out = append(out, fp)
		}
	}
	slices.Sort(out)
	return out
}

func (s *Server) StartRunFromWebhook(ctx context.Context, req *secflowv1.StartRunFromWebhookRequest) (*secflowv1.StartRunFromWebhookResponse, error) {
	idemKey := strings.TrimSpace(req.GetIdempotencyKey())
	src := req.GetTrigger()
	if idemKey == "" && src != nil {
		idemKey = strings.TrimSpace(src.GetDeliveryId())
	}
	trig := &secflowv1.TriggerMetadata{
		Type:        secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
		DeliveryId:  idemKey,
		TriggeredAt: timestamppb.Now(),
	}
	if src != nil {
		trig.RepoUrl = src.GetRepoUrl()
		trig.Branch = src.GetBranch()
		trig.CommitSha = src.GetCommitSha()
		trig.PrNumber = src.PrNumber
		trig.GitProvider = src.GetGitProvider()
		trig.TriggeredBy = src.GetTriggeredBy()
		trig.CommitStatusUrl = src.GetCommitStatusUrl()
		if src.GetDeliveryId() != "" {
			trig.DeliveryId = src.GetDeliveryId()
		}
		if src.GetTriggeredAt() != nil {
			trig.TriggeredAt = src.GetTriggeredAt()
		}
		if src.GetType() != secflowv1.TriggerType_TRIGGER_TYPE_UNSPECIFIED {
			trig.Type = src.GetType()
		}
	}
	run, tp, err := s.startRunWithTrigger(ctx, &secflowv1.StartRunRequest{
		WorkflowId:        req.GetWorkflowId(),
		TriggerType:       secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
		RepoUrlOverride:   trig.GetRepoUrl(),
		GitRefOverride:    trig.GetBranch(),
		CommitShaOverride: trig.GetCommitSha(),
		IdempotencyKey:    idemKey,
	}, trig, true)
	if err != nil {
		return nil, err
	}
	s.dispatchCommitStatus(ctx, run, tp, secflowv1.CommitStatusState_COMMIT_STATUS_STATE_PENDING, "SecFlow security scan in progress")
	return &secflowv1.StartRunFromWebhookResponse{Run: run}, nil
}

func (s *Server) RerunFromNode(ctx context.Context, req *secflowv1.RerunFromNodeRequest) (*secflowv1.RerunFromNodeResponse, error) {
	s.runMu.Lock()
	prev, ok := s.runs[req.GetSourceRunId()]
	var prevWfID, prevRunID, prevSourceID, prevRepoURL, prevTrace string
	var prevTrig *secflowv1.TriggerMetadata
	var prevFindings []report.Finding
	var prevMeta []findingMeta
	var prevDoneIn *engine.Envelope
	payloads := map[string][]byte{}
	if ok {
		prevWfID = prev.run.GetWorkflowId()
		prevRunID = prev.run.GetId()
		prevSourceID = prev.sourceID
		prevRepoURL = prev.repoURL
		prevTrace = prev.trace
		if prev.run.GetTrigger() != nil {
			prevTrig, _ = proto.Clone(prev.run.GetTrigger()).(*secflowv1.TriggerMetadata)
		}
		prevFindings = slices.Clone(prev.findings)
		prevMeta = slices.Clone(prev.findingMeta)
		for k, v := range prev.payloads {
			payloads[k] = slices.Clone(v)
		}
		if tr, exists := prev.done[req.GetNodeId()]; exists {
			cp := tr.Input.Normalize()
			prevDoneIn = &cp
		}
	}
	s.runMu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	wf := s.mustWorkflow(prevWfID)
	if wf == nil {
		return nil, status.Error(codes.NotFound, "workflow not found")
	}

	// Load target node's actual cached in.json from payloads or Garage before falling back.
	nodeID := req.GetNodeId()
	inRaw := payloads["in:"+nodeID]
	if len(inRaw) == 0 && blobstore.Configured() {
		key := fmt.Sprintf("runs/%s/nodes/%s/in.json", prevRunID, nodeID)
		if raw, err := blobstore.Get(ctx, "secflow-artifacts", key); err == nil && len(raw) > 0 {
			inRaw = raw
		}
	}
	var cached engine.Envelope
	loadedCached := false
	if len(inRaw) > 0 {
		if err := json.Unmarshal(inRaw, &cached); err == nil {
			loadedCached = true
		}
	}
	if !loadedCached && prevDoneIn != nil {
		cached = *prevDoneIn
		loadedCached = true
	}
	if !loadedCached {
		cached = engine.Envelope{
			Trigger:  triggerInfoFromProto(prevTrig),
			Findings: make([]engine.Finding, 0, len(prevFindings)),
			Vars:     map[string]string{},
		}
		for _, f := range prevFindings {
			cached.Findings = append(cached.Findings, engine.Finding{
				ID: f.Path + ":" + f.Class, Class: f.Class, Category: f.Category, Severity: f.Severity,
				Path: f.Path, Line: f.Line, EndLine: f.EndLine, Group: f.Group, Artifact: f.Artifact,
				Version: f.Version, AdvisoryID: f.AdvisoryID, Description: f.Description, Remediation: f.Remediation,
			})
		}
	}
	if cached.Trigger.Type == "" && prevTrig != nil {
		cached.Trigger = triggerInfoFromProto(prevTrig)
	}
	if rawBase := payloads["_baseline_fingerprints"]; len(rawBase) > 0 && len(cached.BaselineFingerprints) == 0 {
		var fps []string
		if json.Unmarshal(rawBase, &fps) == nil && len(fps) > 0 {
			cached.BaselineFingerprints = make(map[string]bool, len(fps))
			for _, fp := range fps {
				cached.BaselineFingerprints[fp] = true
			}
		}
	}

	graph := toEngine(wf.GetGraph())
	var cleanedJSON []byte
	if len(req.GetUpdatedParamsJson()) > 0 {
		var params map[string]any
		if err := json.Unmarshal(req.GetUpdatedParamsJson(), &params); err != nil {
			return nil, status.Error(codes.InvalidArgument, "updated params")
		}
		var targetPlugin string
		for i := range graph.Nodes {
			if graph.Nodes[i].ID == nodeID {
				targetPlugin = graph.Nodes[i].PluginID
			}
		}
		for key := range inlineSecretKeys(targetPlugin) {
			if raw, exists := params[key]; exists {
				if val, _ := raw.(string); strings.TrimSpace(val) != "" {
					return nil, status.Errorf(codes.InvalidArgument, "plaintext secret %q is forbidden in node params; use secretBindings", key)
				}
			}
		}
		var err error
		cleanedJSON, err = json.Marshal(params)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal params")
		}
		for i := range graph.Nodes {
			if graph.Nodes[i].ID == nodeID {
				graph.Nodes[i].Params = params
			}
		}
	}
	for _, b := range req.GetUpdatedSecretBindings() {
		for i := range graph.Nodes {
			if graph.Nodes[i].ID == nodeID {
				if graph.Nodes[i].Secrets == nil {
					graph.Nodes[i].Secrets = map[string]string{}
				}
				graph.Nodes[i].Secrets[b.GetParamKey()] = b.GetSecretRef()
			}
		}
	}
	if req.GetPersistWorkflowChanges() && (len(cleanedJSON) > 0 || len(req.GetUpdatedSecretBindings()) > 0) {
		var wfSnap *secflowv1.Workflow
		s.wfMu.Lock()
		if liveWf, exists := s.workflows[prevWfID]; exists && liveWf != nil {
			for _, n := range liveWf.GetGraph().GetNodes() {
				if n.GetId() != nodeID {
					continue
				}
				if len(cleanedJSON) > 0 {
					n.ParamsJson = slices.Clone(cleanedJSON)
				}
				for _, b := range req.GetUpdatedSecretBindings() {
					upsertSecretBinding(n, b.GetParamKey(), b.GetSecretRef())
				}
			}
			liveWf.UpdatedAt = timestamppb.Now()
			wfSnap = cloneWorkflow(liveWf)
		}
		s.wfMu.Unlock()
		if wfSnap != nil {
			wf = wfSnap
			s.persistWorkflow(ctx, wfSnap)
		}
	}

	newRunID := id("run")
	rerunTP := obs.InjectTraceparent(ctx)
	if rerunTP == "" {
		rerunTP = prevTrace
	}
	cached = cached.Normalize()
	cached.RunID = newRunID
	cached.Vars["runId"] = newRunID
	if rerunTP != "" {
		cached.Vars["traceparent"] = rerunTP
	}

	startedAt := time.Now()
	s.runMu.Lock()
	s.runs[newRunID] = &runState{
		run: &secflowv1.Run{
			Id:              newRunID,
			WorkflowId:      wf.GetId(),
			WorkflowVersion: wf.GetVersion(),
			WorkflowName:    wf.GetName(),
			Status:          secflowv1.RunStatus_RUN_STATUS_RUNNING,
			Trigger:         prevTrig,
			ParentRunId:     prevRunID,
			RerunFromNodeId: nodeID,
			CreatedAt:       timestamppb.New(startedAt),
			StartedAt:       timestamppb.New(startedAt),
		},
		graph:    graph,
		payloads: map[string][]byte{},
		done:     map[string]engine.NodeTrace{},
		skipped:  map[string]bool{},
		queued:   map[string]bool{},
	}
	s.runMu.Unlock()

	traces, skipped, err := engine.Rerun(graph, nodeID, cached, wrapHandlersWithExpr(s.handlersCtx(ctx, prevSourceID, prevRepoURL)))
	if err != nil {
		s.runMu.Lock()
		delete(s.runs, newRunID)
		s.runMu.Unlock()
		slog.WarnContext(ctx, "rerun from node failed", "source_run_id", prevRunID, "node_id", nodeID, "err", err)
		return nil, status.Error(codes.InvalidArgument, "invalid rerun request")
	}
	finishedAt := time.Now()
	rerunTraceID := obs.TraceIDFromContext(ctx)
	if rerunTraceID == "" {
		rerunTraceID = traceID(rerunTP)
	}

	run := &secflowv1.Run{
		Id:              newRunID,
		WorkflowId:      wf.GetId(),
		WorkflowVersion: wf.GetVersion(),
		WorkflowName:    wf.GetName(),
		Status:          secflowv1.RunStatus_RUN_STATUS_SUCCEEDED,
		Trigger:         prevTrig,
		ParentRunId:     prevRunID,
		RerunFromNodeId: nodeID,
		TraceId:         rerunTraceID,
		CreatedAt:       timestamppb.New(startedAt),
		StartedAt:       timestamppb.New(startedAt),
		FinishedAt:      timestamppb.New(finishedAt),
	}

	nodeByID := make(map[string]engine.Node, len(graph.Nodes))
	for _, n := range graph.Nodes {
		nodeByID[n.ID] = n
	}

	findings := slices.Clone(prevFindings)
	doneMap := make(map[string]engine.NodeTrace, len(traces))
	var gateRes *secflowv1.GateResult
	var gateNodeID string

	st := &runState{
		run:         run,
		findings:    findings,
		findingMeta: prevMeta,
		payloads:    payloads,
		graph:       graph,
		sourceID:    prevSourceID,
		repoURL:     prevRepoURL,
		trace:       prevTrace,
		done:        doneMap,
		skipped:     skipped,
		queued:      map[string]bool{},
		finished:    true,
	}

	for nid, tr := range traces {
		doneMap[nid] = tr
		s.storeTraceLocked(st, nid, tr)
		n := nodeByID[nid]
		findingsEmitted := 0
		if s.isAnalyzerPlugin(n.PluginID) && len(tr.Output.Findings) > 0 {
			findingsEmitted = len(tr.Output.Findings)
		}
		if n.PluginID == "gate.policy" || (tr.Output.Gate != nil && tr.Output.Gate.NodeID == nid && s.pluginCategory(n.PluginID) == secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC) {
			fallbackPort := ""
			if len(tr.Ports) > 0 {
				fallbackPort = tr.Ports[0]
			}
			gateRes = gateResultFromInfo(nid, tr.Output.Gate, fallbackPort)
			gateNodeID = nid
			run.GateResult = gateRes
		}
		s.recordNodeRunLocked(st, newRunID+":"+nid, n, secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED, tr.Ports, findingsEmitted, "", tr.RedactedPreview, startedAt, finishedAt, finishedAt.Sub(startedAt).Milliseconds())
	}
	for nid := range skipped {
		n := nodeByID[nid]
		s.recordNodeRunLocked(st, newRunID+":"+nid, n, secflowv1.NodeRunStatus_NODE_RUN_STATUS_SKIPPED, nil, 0, "", nil, startedAt, finishedAt, 0)
	}
	if sbomRaw := st.payloads["sbom"]; len(sbomRaw) > 0 && run.Sbom == nil {
		run.Sbom = sbomRefFromJSON(newRunID, sbomRaw)
	}
	if aiRaw := st.payloads["ai_report"]; len(aiRaw) > 0 && run.AiReport == nil {
		run.AiReport = aiReportFromPayload(st.findings, aiRaw)
	}
	run.FindingsStats = envelopeStatsProto(st.findings)
	if sub, err := report.SubmissionJSON(st.findings); err == nil {
		st.payloads["submission"] = sub
	}

	s.runMu.Lock()
	s.runs[run.GetId()] = st
	runSnap := cloneRun(run)
	s.runMu.Unlock()

	for nid, tr := range traces {
		s.persistNodeArtifacts(ctx, newRunID, nid, tr)
	}
	if gateRes != nil {
		s.emitEvent(ctx, st, &secflowv1.RunEvent{
			EventType:  secflowv1.RunEventType_RUN_EVENT_TYPE_GATE_EVALUATED,
			RunStatus:  secflowv1.RunStatus_RUN_STATUS_RUNNING,
			NodeId:     gateNodeID,
			NodeRunId:  newRunID + ":" + gateNodeID,
			GateResult: gateRes,
			Message:    gateRes.GetReason(),
		})
	}
	s.recordRunTerminal("SUCCEEDED")
	s.pushEvent(ctx, st, secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_COMPLETED, secflowv1.RunStatus_RUN_STATUS_SUCCEEDED, "rerun completed")
	s.persistRun(ctx, st)
	s.persistPayloads(ctx, st, wf.GetGraph())
	return &secflowv1.RerunFromNodeResponse{Run: runSnap}, nil
}

func (s *Server) CancelRun(ctx context.Context, req *secflowv1.CancelRunRequest) (*secflowv1.CancelRunResponse, error) {
	runID := req.GetRunId()
	reason := req.GetReason()
	if reason == "" {
		reason = "run cancelled"
	}
	type cancelTarget struct {
		nrID   string
		task   activeTask
		result chan *secflowv1.NodeResult
	}
	var toCancel []cancelTarget

	s.runMu.Lock()
	st, ok := s.runs[runID]
	if !ok {
		s.runMu.Unlock()
		return nil, status.Error(codes.NotFound, "run not found")
	}
	st.run.Status = secflowv1.RunStatus_RUN_STATUS_CANCELLED
	st.run.ErrorMessage = reason
	st.run.FinishedAt = timestamppb.Now()
	st.finished = true
	run := cloneRun(st.run)
	for nrID, at := range s.activeTasks {
		if at.runID != runID {
			continue
		}
		ch := s.results[nrID]
		delete(s.activeTasks, nrID)
		delete(s.results, nrID)
		toCancel = append(toCancel, cancelTarget{nrID: nrID, task: at, result: ch})
	}
	s.runMu.Unlock()

	s.cancelQueued(ctx, runID)
	for _, item := range toCancel {
		if item.task.worker != nil {
			if err := item.task.worker.Send(&secflowv1.ConnectResponse{
				Payload: &secflowv1.ConnectResponse_CancelTask{
					CancelTask: &secflowv1.CancelTask{
						NodeRunId: item.nrID,
						Reason:    reason,
					},
				},
			}); err != nil {
				slog.Warn("send cancel task to worker", "run_id", runID, "node_run_id", item.nrID, "err", err)
			}
		}
		if item.result != nil {
			select {
			case item.result <- &secflowv1.NodeResult{
				NodeRunId:    item.nrID,
				RunId:        runID,
				NodeId:       item.task.nodeID,
				PluginId:     item.task.pluginID,
				Status:       secflowv1.NodeRunStatus_NODE_RUN_STATUS_CANCELLED,
				ErrorCode:    "RUN_CANCELLED",
				ErrorMessage: reason,
			}:
			default:
			}
		}
	}
	s.recordRunTerminal("CANCELLED")
	s.persistRun(ctx, st)
	s.pushEvent(ctx, st, secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_CANCELLED, secflowv1.RunStatus_RUN_STATUS_CANCELLED, reason)
	s.dispatchTerminalCommitStatus(ctx, st)
	return &secflowv1.CancelRunResponse{Run: run}, nil
}

func (s *Server) GetRun(_ context.Context, req *secflowv1.GetRunRequest) (*secflowv1.GetRunResponse, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	st, ok := s.runs[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	return &secflowv1.GetRunResponse{Run: cloneRun(st.run)}, nil
}

func (s *Server) ListRuns(_ context.Context, req *secflowv1.ListRunsRequest) (*secflowv1.ListRunsResponse, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	var items []*secflowv1.Run
	for _, st := range s.runs {
		if req.GetWorkflowId() == "" || st.run.GetWorkflowId() == req.GetWorkflowId() {
			items = append(items, cloneRun(st.run))
		}
	}
	runCreatedAt := func(r *secflowv1.Run) time.Time {
		if ts := r.GetCreatedAt(); ts != nil {
			return ts.AsTime()
		}
		return time.Time{}
	}
	slices.SortFunc(items, func(a, b *secflowv1.Run) int {
		if c := runCreatedAt(b).Compare(runCreatedAt(a)); c != 0 {
			return c
		}
		return strings.Compare(b.GetId(), a.GetId())
	})
	return &secflowv1.ListRunsResponse{Runs: items, PageInfo: &secflowv1.PageInfo{TotalCount: int64(len(items))}}, nil
}

func defaultPluginForCategory(category string) string {
	switch strings.ToUpper(strings.TrimSpace(category)) {
	case "SECRET":
		return "scan.secrets"
	case "SAST":
		return "scan.sast.kotlin"
	case "SCA":
		return "scan.sca"
	default:
		return ""
	}
}

func uniqueFindingFingerprint(f report.Finding) string {
	pkg := ""
	if f.Group != "" || f.Artifact != "" {
		pkg = f.Group + ":" + f.Artifact
	}
	ruleID := nonEmpty(f.Class, f.AdvisoryID)
	return fmt.Sprintf("%s|%s|%s|%d|%s|%s", ruleID, f.Category, f.Path, f.Line, pkg, f.Version)
}

func (s *Server) ListFindings(_ context.Context, req *secflowv1.ListFindingsRequest) (*secflowv1.ListFindingsResponse, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	st, ok := s.runs[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	baselineSet := baselineSetFromPayloads(st.payloads)
	matched := make([]*secflowv1.Finding, 0, len(st.findings))
	matchedEngine := make([]engine.Finding, 0, len(st.findings))
	for i, f := range st.findings {
		if req.GetCategory() != secflowv1.FindingCategory_FINDING_CATEGORY_UNSPECIFIED && protoconv.CategoryProto(f.Category) != req.GetCategory() {
			continue
		}
		if req.GetMinSeverity() != secflowv1.Severity_SEVERITY_UNSPECIFIED && protoconv.SeverityRank(f.Severity) < protoconv.SeverityRank(protoconv.SeverityName(req.GetMinSeverity())) {
			continue
		}
		var meta findingMeta
		if i < len(st.findingMeta) {
			meta = st.findingMeta[i]
		}
		pluginID := meta.pluginID
		if pluginID == "" {
			pluginID = defaultPluginForCategory(f.Category)
		}
		isNew := meta.isNewVsBaseline
		if !isNew && len(baselineSet) > 0 {
			bfp := engine.FindingFingerprint(engine.Finding{
				Category: f.Category, Path: f.Path, Class: f.Class,
				Group: f.Group, Artifact: f.Artifact, AdvisoryID: f.AdvisoryID,
			})
			if bfp != "" && !baselineSet[bfp] {
				isNew = true
			}
		}
		item := &secflowv1.Finding{
			FindingId:       fmt.Sprintf("F-%03d", i+1),
			Fingerprint:     uniqueFindingFingerprint(f),
			SourceNodeId:    meta.sourceNodeID,
			PluginId:        pluginID,
			Category:        protoconv.CategoryProto(f.Category),
			Path:            f.Path,
			FindingClass:    f.Class,
			Severity:        protoconv.SeverityProto(f.Severity),
			Description:     f.Description,
			Remediation:     f.Remediation,
			Group:           f.Group,
			Artifact:        f.Artifact,
			Version:         f.Version,
			AdvisoryId:      f.AdvisoryID,
			MaskedSnippet:   meta.maskedSnippet,
			IsNewVsBaseline: isNew,
		}
		if f.Line > 0 {
			line := int32(f.Line)
			item.Line = &line
		}
		if f.EndLine > 0 {
			end := int32(f.EndLine)
			item.EndLine = &end
		}
		matched = append(matched, item)
		matchedEngine = append(matchedEngine, engine.Finding{
			Category:        f.Category,
			Severity:        f.Severity,
			Path:            f.Path,
			Class:           f.Class,
			IsNewVsBaseline: isNew,
		})
	}

	engStats := engine.ComputeStats(matchedEngine)
	statsProto := &secflowv1.EnvelopeStats{
		Total:       int32(engStats.Total),
		NewCount:    int32(engStats.NewCount),
		Critical:    int32(engStats.Critical),
		High:        int32(engStats.High),
		Medium:      int32(engStats.Medium),
		Low:         int32(engStats.Low),
		SecretCount: int32(engStats.SecretCount),
		SastCount:   int32(engStats.SastCount),
		ScaCount:    int32(engStats.ScaCount),
		MaxSeverity: protoconv.SeverityProto(engStats.MaxSeverity),
	}

	total := len(matched)
	start := 0
	if cur := strings.TrimSpace(req.GetPage().GetCursor()); cur != "" {
		if parsed, err := strconv.Atoi(cur); err == nil && parsed > 0 {
			start = parsed
		}
	}
	if start > total {
		start = total
	}
	end := total
	if limit := int(req.GetPage().GetLimit()); limit > 0 && start+limit < end {
		end = start + limit
	}
	pageInfo := &secflowv1.PageInfo{
		TotalCount: int64(total),
		HasMore:    end < total,
	}
	if pageInfo.HasMore {
		pageInfo.NextCursor = strconv.Itoa(end)
	}
	return &secflowv1.ListFindingsResponse{
		Findings: matched[start:end],
		Stats:    statsProto,
		PageInfo: pageInfo,
	}, nil
}

func (s *Server) GetSubmissionReport(_ context.Context, req *secflowv1.GetSubmissionReportRequest) (*secflowv1.GetSubmissionReportResponse, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	st, ok := s.runs[req.GetRunId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	raw := slices.Clone(st.payloads["submission"])
	sum := sha256.Sum256(raw)
	return &secflowv1.GetSubmissionReportResponse{SubmissionJson: raw, Sha256: hex.EncodeToString(sum[:]), FindingCount: int32(len(st.findings))}, nil
}

func (s *Server) GetSbom(ctx context.Context, req *secflowv1.GetSbomRequest) (*secflowv1.GetSbomResponse, error) {
	runID := req.GetRunId()
	s.runMu.Lock()
	st, ok := s.runs[runID]
	var body []byte
	var existingSbom *secflowv1.SbomRef
	if ok {
		body = slices.Clone(st.payloads["sbom"])
		if st.run != nil && st.run.GetSbom() != nil {
			existingSbom, _ = proto.Clone(st.run.GetSbom()).(*secflowv1.SbomRef)
		}
	}
	s.runMu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	sbomKey := fmt.Sprintf("runs/%s/sbom.cdx.json", runID)
	if len(body) == 0 && blobstore.Configured() {
		if raw, err := blobstore.Get(ctx, "secflow-sbom", sbomKey); err == nil && len(raw) > 0 {
			body = raw
		}
	}
	if len(body) == 0 {
		body = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`)
	}
	sbomRef := sbomRefFromJSON(runID, body)
	if existingSbom != nil && existingSbom.GetDigest() == sbomRef.GetDigest() && existingSbom.GetGeneratedAt() != nil {
		sbomRef.GeneratedAt = existingSbom.GetGeneratedAt()
	}
	resp := &secflowv1.GetSbomResponse{
		Sbom: sbomRef,
	}
	if req.GetIncludeContent() {
		resp.CyclonedxJson = body
	}
	return resp, nil
}

func (s *Server) GetAIReport(_ context.Context, req *secflowv1.GetAIReportRequest) (*secflowv1.GetAIReportResponse, error) {
	s.runMu.Lock()
	st, ok := s.runs[req.GetRunId()]
	var aiRaw []byte
	var findings []report.Finding
	if ok {
		aiRaw = slices.Clone(st.payloads["ai_report"])
		findings = slices.Clone(st.findings)
	}
	s.runMu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	return &secflowv1.GetAIReportResponse{Report: aiReportFromPayload(findings, aiRaw)}, nil
}

func (s *Server) GetReadableReport(_ context.Context, req *secflowv1.GetReadableReportRequest) (*secflowv1.GetReadableReportResponse, error) {
	s.runMu.Lock()
	st, ok := s.runs[req.GetRunId()]
	var findings []report.Finding
	var aiRaw []byte
	if ok {
		findings = slices.Clone(st.findings)
		aiRaw = slices.Clone(st.payloads["ai_report"])
	}
	s.runMu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	var aiRep *secflowv1.AIReport
	if len(aiRaw) > 0 {
		aiRep = aiReportFromPayload(findings, aiRaw)
	}
	body := readable(findings, req.GetFormat(), aiRep)
	ctype := "text/markdown"
	if req.GetFormat() == secflowv1.ReportFormat_REPORT_FORMAT_HTML {
		ctype = "text/html"
	}
	return &secflowv1.GetReadableReportResponse{Format: req.GetFormat(), ContentType: ctype, Content: body, FindingCount: int32(len(findings))}, nil
}

func (s *Server) GetNodePayload(ctx context.Context, req *secflowv1.GetNodePayloadRequest) (*secflowv1.GetNodePayloadResponse, error) {
	runID := req.GetRunId()
	nodeID := req.GetNodeId()
	s.runMu.Lock()
	st, ok := s.runs[runID]
	var outBlob, inBlob, portsRaw []byte
	var pluginID string
	nodeStatus := secflowv1.NodeRunStatus_NODE_RUN_STATUS_UNSPECIFIED
	portBlobs := map[string][]byte{}
	if ok {
		outBlob = slices.Clone(st.payloads["node:"+nodeID])
		inBlob = slices.Clone(st.payloads["in:"+nodeID])
		portsRaw = slices.Clone(st.payloads["ports:"+nodeID])
		portPrefix := "port:" + nodeID + ":"
		for k, v := range st.payloads {
			if strings.HasPrefix(k, portPrefix) {
				portBlobs[strings.TrimPrefix(k, portPrefix)] = slices.Clone(v)
			}
		}
		if st.run != nil {
			for _, nr := range st.run.GetNodeRuns() {
				if nr.GetNodeId() == nodeID {
					pluginID = nr.GetPluginId()
					nodeStatus = nr.GetStatus()
					break
				}
			}
		}
		if pluginID == "" {
			for _, n := range st.graph.Nodes {
				if n.ID == nodeID {
					pluginID = n.PluginID
					break
				}
			}
		}
		if nodeStatus == secflowv1.NodeRunStatus_NODE_RUN_STATUS_UNSPECIFIED {
			switch {
			case st.skipped[nodeID]:
				nodeStatus = secflowv1.NodeRunStatus_NODE_RUN_STATUS_SKIPPED
			case st.queued[nodeID]:
				nodeStatus = secflowv1.NodeRunStatus_NODE_RUN_STATUS_PENDING
			default:
				if _, done := st.done[nodeID]; done || len(outBlob) > 0 {
					nodeStatus = secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED
				}
			}
		}
	}
	s.runMu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "run not found")
	}
	if blobstore.Configured() {
		prefix := fmt.Sprintf("runs/%s/nodes/%s", runID, nodeID)
		if len(inBlob) == 0 {
			if raw, err := blobstore.Get(ctx, "secflow-artifacts", prefix+"/in.json"); err == nil && len(raw) > 0 {
				inBlob = raw
			}
		}
		if len(outBlob) == 0 {
			if raw, err := blobstore.Get(ctx, "secflow-artifacts", prefix+"/out.json"); err == nil && len(raw) > 0 {
				outBlob = raw
			}
		}
	}
	if len(inBlob) == 0 {
		inBlob = []byte(`{}`)
	}
	if nodeStatus == secflowv1.NodeRunStatus_NODE_RUN_STATUS_UNSPECIFIED && len(outBlob) > 0 {
		nodeStatus = secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED
	}
	ports := []string{"default"}
	if len(portsRaw) > 0 {
		if err := json.Unmarshal(portsRaw, &ports); err != nil {
			slog.Warn("unmarshal node ports", "run_id", runID, "node_id", nodeID, "err", err)
		}
	}
	resolvePortBlob := func(handle string) []byte {
		if pb := portBlobs[handle]; len(pb) > 0 {
			return pb
		}
		if blobstore.Configured() {
			key := fmt.Sprintf("runs/%s/nodes/%s/out.%s.json", runID, nodeID, handle)
			if raw, err := blobstore.Get(ctx, "secflow-artifacts", key); err == nil && len(raw) > 0 {
				return raw
			}
		}
		return outBlob
	}
	selected := outBlob
	if handle := req.GetSourceHandle(); handle != "" {
		if !containsPort(ports, handle) {
			selected = []byte(`{}`)
		} else {
			selected = resolvePortBlob(handle)
		}
	}
	var outputs []*secflowv1.PortEnvelopeOutput
	for _, port := range ports {
		outputs = append(outputs, &secflowv1.PortEnvelopeOutput{SourceHandle: port, OutputEnvelopeJson: resolvePortBlob(port)})
	}
	return &secflowv1.GetNodePayloadResponse{
		RunId:              runID,
		NodeId:             nodeID,
		PluginId:           pluginID,
		Status:             nodeStatus,
		InputEnvelopeJson:  inBlob,
		OutputEnvelopeJson: selected,
		ActiveOutputPorts:  ports,
		PortOutputs:        outputs,
	}, nil
}

func runEventsChannel(runID string) string {
	var b strings.Builder
	b.WriteString("run_events_")
	for _, r := range runID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	ch := b.String()
	if len(ch) > 63 {
		ch = ch[:63]
	}
	return ch
}

func unmarshalRunEvent(seqID int64, runID, eventType string, payload []byte) *secflowv1.RunEvent {
	ev := &secflowv1.RunEvent{}
	if len(payload) > 0 {
		unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
		if err := unmarshaler.Unmarshal(payload, ev); err != nil {
			var legacy struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(payload, &legacy) == nil {
				ev.Message = legacy.Message
			}
		}
	}
	if seqID > 0 {
		ev.SeqId = seqID
	}
	if ev.GetRunId() == "" {
		ev.RunId = runID
	}
	if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_UNSPECIFIED && eventType != "" {
		ev.EventType = secflowv1.RunEventType(secflowv1.RunEventType_value[eventType])
	}
	return ev
}

func (s *Server) WatchRun(req *secflowv1.WatchRunRequest, stream secflowv1.RunService_WatchRunServer) error {
	if s.pool != nil {
		return s.watchRunPG(req, stream)
	}
	s.runMu.Lock()
	st, ok := s.runs[req.GetRunId()]
	if !ok {
		s.runMu.Unlock()
		return status.Error(codes.NotFound, "run not found")
	}
	ch := make(chan *secflowv1.RunEvent, 32)
	st.watchers = append(st.watchers, ch)
	events := slices.Clone(st.events)
	s.runMu.Unlock()
	defer func() {
		s.runMu.Lock()
		kept := st.watchers[:0]
		for _, w := range st.watchers {
			if w != ch {
				kept = append(kept, w)
			}
		}
		st.watchers = kept
		s.runMu.Unlock()
	}()
	sent := req.GetAfterSeq()
	send := func(ev *secflowv1.RunEvent) error {
		if ev.GetSeqId() <= sent {
			return nil
		}
		sent = ev.GetSeqId()
		return stream.Send(&secflowv1.WatchRunResponse{Event: ev})
	}
	for _, ev := range events {
		if err := send(ev); err != nil {
			return err
		}
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-ch:
			if err := send(ev); err != nil {
				return err
			}
		}
	}
}

func (s *Server) watchRunPG(req *secflowv1.WatchRunRequest, stream secflowv1.RunService_WatchRunServer) error {
	ctx := stream.Context()
	runID := req.GetRunId()
	s.runMu.Lock()
	_, inMem := s.runs[runID]
	s.runMu.Unlock()
	if !inMem {
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM runs WHERE id = $1)`, runID).Scan(&exists); err != nil {
			return status.Errorf(codes.Internal, "lookup run: %v", err)
		}
		if !exists {
			return status.Error(codes.NotFound, "run not found")
		}
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable, "acquire listen conn: %v", err)
	}
	defer conn.Release()

	channel := runEventsChannel(runID)
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return status.Errorf(codes.Internal, "listen %s: %v", channel, err)
	}
	defer func() {
		unlistenCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlistenCtx, "UNLISTEN "+pgx.Identifier{channel}.Sanitize())
	}()

	sent := req.GetAfterSeq()
	send := func(ev *secflowv1.RunEvent) error {
		if ev == nil || ev.GetSeqId() <= sent {
			return nil
		}
		sent = ev.GetSeqId()
		return stream.Send(&secflowv1.WatchRunResponse{Event: ev})
	}

	replay := func(afterSeq int64) error {
		rows, qErr := s.pool.Query(ctx, `
			SELECT seq_id, event_type, payload_json
			FROM run_events
			WHERE run_id = $1 AND seq_id > $2
			ORDER BY seq_id ASC`, runID, afterSeq)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()
		for rows.Next() {
			var seqID int64
			var evType string
			var payload []byte
			if scanErr := rows.Scan(&seqID, &evType, &payload); scanErr != nil {
				return scanErr
			}
			ev := unmarshalRunEvent(seqID, runID, evType, payload)
			if sendErr := send(ev); sendErr != nil {
				return sendErr
			}
		}
		return rows.Err()
	}

	if err := replay(sent); err != nil {
		return status.Errorf(codes.Internal, "replay run_events: %v", err)
	}

	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	for {
		notif, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return nil
			}
			return status.Errorf(codes.Unavailable, "wait for notification: %v", err)
		}
		ev := &secflowv1.RunEvent{}
		if err := unmarshaler.Unmarshal([]byte(notif.Payload), ev); err != nil || ev.GetSeqId() <= 0 {
			if rErr := replay(sent); rErr != nil {
				return status.Errorf(codes.Internal, "replay after notify: %v", rErr)
			}
			continue
		}
		if err := send(ev); err != nil {
			return err
		}
	}
}

func (s *Server) pushEvent(ctx context.Context, st *runState, typ secflowv1.RunEventType, runStatus secflowv1.RunStatus, msg string) {
	s.emitEvent(ctx, st, &secflowv1.RunEvent{
		EventType: typ,
		RunStatus: runStatus,
		Message:   msg,
	})
}

func (s *Server) pushNodeEvent(ctx context.Context, st *runState, nodeID, nodeRunID string, nodeStatus secflowv1.NodeRunStatus, runStatus secflowv1.RunStatus, msg string, preview []byte) {
	s.emitEvent(ctx, st, &secflowv1.RunEvent{
		EventType:           secflowv1.RunEventType_RUN_EVENT_TYPE_NODE_STATUS_CHANGED,
		RunStatus:           runStatus,
		NodeId:              nodeID,
		NodeRunId:           nodeRunID,
		NodeStatus:          nodeStatus,
		RedactedPreviewJson: preview,
		Message:             msg,
	})
}

func (s *Server) emitEvent(ctx context.Context, st *runState, ev *secflowv1.RunEvent) {
	if st == nil || st.run == nil || ev == nil {
		return
	}
	s.runMu.Lock()
	runID := st.run.GetId()
	s.runMu.Unlock()

	ev.RunId = runID
	if ev.CreatedAt == nil {
		ev.CreatedAt = timestamppb.Now()
	}

	if s.pool != nil {
		if seqID, ok := s.persistAndNotifyEvent(ctx, ev); ok {
			ev.SeqId = seqID
		}
	}

	s.runMu.Lock()
	if ev.SeqId <= 0 {
		ev.SeqId = int64(len(st.events) + 1)
	}
	st.events = append(st.events, ev)
	if ev.SeqId > st.run.LastSeqId {
		st.run.LastSeqId = ev.SeqId
	}
	watchers := slices.Clone(st.watchers)
	s.runMu.Unlock()

	for _, ch := range watchers {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Server) persistAndNotifyEvent(ctx context.Context, ev *secflowv1.RunEvent) (int64, bool) {
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	tx, err := s.pool.Begin(dbCtx)
	if err != nil {
		slog.Warn("begin run_event tx", "run_id", ev.GetRunId(), "err", err)
		return 0, false
	}
	defer func() {
		_ = tx.Rollback(dbCtx)
	}()

	var seqID int64
	if err := tx.QueryRow(dbCtx, `SELECT nextval(pg_get_serial_sequence('run_events', 'seq_id'))`).Scan(&seqID); err != nil {
		slog.Warn("nextval run_events seq_id", "run_id", ev.GetRunId(), "err", err)
		return 0, false
	}
	ev.SeqId = seqID
	raw, err := protojson.Marshal(ev)
	if err != nil {
		slog.Warn("marshal run_event", "run_id", ev.GetRunId(), "err", err)
		return 0, false
	}
	if _, err := tx.Exec(dbCtx, `
		INSERT INTO run_events (seq_id, run_id, event_type, payload_json)
		VALUES ($1, $2, $3, $4::jsonb)`,
		seqID, ev.GetRunId(), ev.GetEventType().String(), string(raw)); err != nil {
		slog.Warn("insert run_event", "run_id", ev.GetRunId(), "err", err)
		return 0, false
	}

	notifyPayload := string(raw)
	if len(notifyPayload) > 7500 {
		slim := &secflowv1.RunEvent{
			SeqId:        ev.GetSeqId(),
			RunId:        ev.GetRunId(),
			EventType:    ev.GetEventType(),
			RunStatus:    ev.GetRunStatus(),
			NodeId:       ev.GetNodeId(),
			NodeRunId:    ev.GetNodeRunId(),
			NodeStatus:   ev.GetNodeStatus(),
			EdgeId:       ev.GetEdgeId(),
			SourceHandle: ev.GetSourceHandle(),
			Message:      ev.GetMessage(),
			CreatedAt:    ev.GetCreatedAt(),
		}
		if slimRaw, mErr := protojson.Marshal(slim); mErr == nil {
			notifyPayload = string(slimRaw)
		}
	}
	if _, err := tx.Exec(dbCtx, `SELECT pg_notify($1, $2)`, runEventsChannel(ev.GetRunId()), notifyPayload); err != nil {
		slog.Warn("pg_notify run_event", "run_id", ev.GetRunId(), "err", err)
		return 0, false
	}
	if err := tx.Commit(dbCtx); err != nil {
		slog.Warn("commit run_event tx", "run_id", ev.GetRunId(), "err", err)
		return 0, false
	}
	return seqID, true
}

func (s *Server) persistNodeArtifacts(ctx context.Context, runID, nodeID string, tr engine.NodeTrace) {
	if !blobstore.Configured() || runID == "" || nodeID == "" {
		return
	}
	artCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	prefix := fmt.Sprintf("runs/%s/nodes/%s", runID, nodeID)
	if inBlob, err := json.Marshal(tr.Input); err == nil {
		if err := blobstore.Put(artCtx, "secflow-artifacts", prefix+"/in.json", inBlob); err != nil {
			slog.Warn("put node input artifact", "run_id", runID, "node_id", nodeID, "err", err)
		}
	}
	if outBlob, err := json.Marshal(tr.Output); err == nil {
		if err := blobstore.Put(artCtx, "secflow-artifacts", prefix+"/out.json", outBlob); err != nil {
			slog.Warn("put node output artifact", "run_id", runID, "node_id", nodeID, "err", err)
		}
		for _, handle := range tr.Ports {
			if handle == "" {
				continue
			}
			portBlob := outBlob
			if tr.PortOutputs != nil {
				if pe, exists := tr.PortOutputs[handle]; exists {
					if pb, pErr := json.Marshal(pe); pErr == nil {
						portBlob = pb
					}
				}
			}
			if err := blobstore.Put(artCtx, "secflow-artifacts", fmt.Sprintf("%s/out.%s.json", prefix, handle), portBlob); err != nil {
				slog.Warn("put node port artifact", "run_id", runID, "node_id", nodeID, "handle", handle, "err", err)
			}
		}
	}
	if tr.Output.Vars != nil && tr.Output.Vars["sbom"] != "" {
		if err := blobstore.Put(artCtx, "secflow-sbom", fmt.Sprintf("runs/%s/sbom.cdx.json", runID), []byte(tr.Output.Vars["sbom"])); err != nil {
			slog.Warn("put run sbom artifact", "run_id", runID, "err", err)
		}
	}
	if tr.ArtifactKey != "" && len(tr.ArtifactContent) > 0 {
		if err := blobstore.Put(artCtx, "secflow-artifacts", tr.ArtifactKey, tr.ArtifactContent); err != nil {
			slog.Warn("put external report artifact", "run_id", runID, "node_id", nodeID, "key", tr.ArtifactKey, "err", err)
		}
	}
}

func marshalNodeRunsJSON(runs []*secflowv1.NodeRun) string {
	if len(runs) == 0 {
		return "[]"
	}
	items := make([]json.RawMessage, 0, len(runs))
	for _, nr := range runs {
		if nr == nil {
			continue
		}
		if b, err := protojson.Marshal(nr); err == nil {
			items = append(items, json.RawMessage(b))
		}
	}
	if len(items) == 0 {
		return "[]"
	}
	out, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(out)
}

func unmarshalNodeRunsJSON(raw []byte) []*secflowv1.NodeRun {
	if len(raw) == 0 || string(raw) == "[]" {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	out := make([]*secflowv1.NodeRun, 0, len(items))
	for _, item := range items {
		nr := &secflowv1.NodeRun{}
		if unmarshaler.Unmarshal(item, nr) == nil && nr.GetNodeId() != "" {
			out = append(out, nr)
		}
	}
	return out
}

// extractExplainFromTaskPayload recovers raw AI report JSON from a node_tasks.payload_json
// row whether it was persisted as engine.NodeTrace or (legacy) raw engine.Envelope.
func extractExplainFromTaskPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	var tr engine.NodeTrace
	if json.Unmarshal(payload, &tr) == nil {
		if tr.Output.Vars != nil && strings.TrimSpace(tr.Output.Vars["explain"]) != "" {
			return []byte(tr.Output.Vars["explain"])
		}
		if tr.Output.AIReport != nil && strings.TrimSpace(tr.Output.AIReport.ExecutiveSummary) != "" {
			if raw, err := json.Marshal(tr.Output.AIReport); err == nil {
				return raw
			}
		}
	}
	var env engine.Envelope
	if json.Unmarshal(payload, &env) == nil {
		if env.Vars != nil && strings.TrimSpace(env.Vars["explain"]) != "" {
			return []byte(env.Vars["explain"])
		}
		if env.AIReport != nil && strings.TrimSpace(env.AIReport.ExecutiveSummary) != "" {
			if raw, err := json.Marshal(env.AIReport); err == nil {
				return raw
			}
		}
	}
	return nil
}

func isMissingColumnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "42703") || strings.Contains(msg, "does not exist")
}

func (s *Server) persistPayloads(ctx context.Context, st *runState, g *secflowv1.WorkflowGraph) {
	if st == nil || st.run == nil {
		return
	}
	s.runMu.Lock()
	runID := st.run.GetId()
	snapshot := make(map[string][]byte, len(st.payloads))
	for k, v := range st.payloads {
		snapshot[k] = slices.Clone(v)
	}
	doneSnap := make(map[string]engine.NodeTrace, len(st.done))
	for nid, tr := range st.done {
		doneSnap[nid] = tr
	}
	graphPluginOf := make(map[string]string, len(st.graph.Nodes))
	for _, n := range st.graph.Nodes {
		if n.ID != "" && n.PluginID != "" {
			graphPluginOf[n.ID] = n.PluginID
		}
	}
	s.runMu.Unlock()

	if blobstore.Configured() {
		artCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		for key, blob := range snapshot {
			switch {
			case strings.HasPrefix(key, "in:"):
				nodeID := strings.TrimPrefix(key, "in:")
				_ = blobstore.Put(artCtx, "secflow-artifacts", fmt.Sprintf("runs/%s/nodes/%s/in.json", runID, nodeID), blob)
			case strings.HasPrefix(key, "node:"):
				nodeID := strings.TrimPrefix(key, "node:")
				_ = blobstore.Put(artCtx, "secflow-artifacts", fmt.Sprintf("runs/%s/nodes/%s/out.json", runID, nodeID), blob)
				if portsRaw := snapshot["ports:"+nodeID]; len(portsRaw) > 0 {
					var ports []string
					if json.Unmarshal(portsRaw, &ports) == nil {
						for _, handle := range ports {
							if handle != "" {
								portBlob := blob
								if pb := snapshot["port:"+nodeID+":"+handle]; len(pb) > 0 {
									portBlob = pb
								}
								_ = blobstore.Put(artCtx, "secflow-artifacts", fmt.Sprintf("runs/%s/nodes/%s/out.%s.json", runID, nodeID, handle), portBlob)
							}
						}
					}
				}
			case key == "sbom" && len(blob) > 0:
				_ = blobstore.Put(artCtx, "secflow-sbom", fmt.Sprintf("runs/%s/sbom.cdx.json", runID), blob)
			}
		}
		cancel()
	}

	if s.pool == nil {
		return
	}
	pluginOf := graphPluginOf
	if g != nil {
		for _, n := range g.GetNodes() {
			if n.GetId() != "" && n.GetPluginId() != "" {
				pluginOf[n.GetId()] = n.GetPluginId()
			}
		}
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	for key, blob := range snapshot {
		if !strings.HasPrefix(key, "node:") {
			continue
		}
		nodeID := strings.TrimPrefix(key, "node:")
		taskPayload := blob
		if tr, ok := doneSnap[nodeID]; ok {
			if trRaw, err := json.Marshal(tr); err == nil {
				taskPayload = trRaw
			}
		}
		if _, err := s.pool.Exec(dbCtx, `
			INSERT INTO node_tasks (node_run_id, run_id, node_id, plugin_id, status, payload_json)
			VALUES ($1,$2,$3,$4,$5,$6::jsonb)
			ON CONFLICT (node_run_id) DO UPDATE SET
				plugin_id = COALESCE(NULLIF(EXCLUDED.plugin_id, ''), node_tasks.plugin_id),
				payload_json = EXCLUDED.payload_json,
				status = EXCLUDED.status`,
			runID+":"+nodeID, runID, nodeID, pluginOf[nodeID], "SUCCEEDED", string(taskPayload)); err != nil {
			slog.Warn("persist node payload", "run_id", runID, "node_id", nodeID, "err", err)
		}
	}
	if raw := snapshot["sbom"]; len(raw) > 0 && json.Valid(raw) {
		if _, err := s.pool.Exec(dbCtx, `UPDATE runs SET sbom_json = $2::jsonb WHERE id = $1`, runID, string(raw)); err != nil {
			slog.Warn("persist run sbom", "run_id", runID, "err", err)
		}
	}
	if raw := snapshot["ai_report"]; len(raw) > 0 && json.Valid(raw) {
		if _, err := s.pool.Exec(dbCtx, `UPDATE runs SET ai_report_json = $2::jsonb WHERE id = $1`, runID, string(raw)); err != nil && !isMissingColumnErr(err) {
			slog.Warn("persist run ai_report", "run_id", runID, "err", err)
		}
	}
}

func (s *Server) persistRun(ctx context.Context, st *runState) {
	if s.pool == nil || st == nil || st.run == nil {
		return
	}
	s.runMu.Lock()
	runID := st.run.GetId()
	wfID := st.run.GetWorkflowId()
	wfVer := st.run.GetWorkflowVersion()
	if wfVer <= 0 {
		wfVer = 1
	}
	statusStr := st.run.GetStatus().String()
	parentID := st.run.GetParentRunId()
	rerunNode := st.run.GetRerunFromNodeId()
	trace := st.run.GetTraceId()
	errMsg := st.run.GetErrorMessage()
	idemKey := st.idempotencyKey
	triggerMsg, _ := proto.Clone(st.run.GetTrigger()).(*secflowv1.TriggerMetadata)
	sourceRefMsg, _ := proto.Clone(st.run.GetSourceRef()).(*secflowv1.SourceRef)
	gateMsg, _ := proto.Clone(st.run.GetGateResult()).(*secflowv1.GateResult)
	aiReportRaw := slices.Clone(st.payloads["ai_report"])
	nodeRunsSnap := make([]*secflowv1.NodeRun, 0, len(st.run.GetNodeRuns()))
	for _, nr := range st.run.GetNodeRuns() {
		if cp, ok := proto.Clone(nr).(*secflowv1.NodeRun); ok {
			nodeRunsSnap = append(nodeRunsSnap, cp)
		}
	}
	var startedAt, finishedAt *time.Time
	if ts := st.run.GetStartedAt(); ts != nil {
		t := ts.AsTime()
		startedAt = &t
	}
	if ts := st.run.GetFinishedAt(); ts != nil {
		t := ts.AsTime()
		finishedAt = &t
	}
	findings := slices.Clone(st.findings)
	s.runMu.Unlock()

	raw, err := json.Marshal(findings)
	if err != nil {
		slog.Warn("marshal run findings", "run_id", runID, "err", err)
		return
	}
	trigJSON := "{}"
	if triggerMsg != nil {
		if b, mErr := protojson.Marshal(triggerMsg); mErr == nil {
			trigJSON = string(b)
		}
	}
	srcJSON := "{}"
	if sourceRefMsg != nil {
		if b, mErr := protojson.Marshal(sourceRefMsg); mErr == nil {
			srcJSON = string(b)
		}
	}
	gateJSON := "{}"
	if gateMsg != nil {
		if b, mErr := protojson.Marshal(gateMsg); mErr == nil {
			gateJSON = string(b)
		}
	}
	aiReportJSON := "{}"
	if len(aiReportRaw) > 0 && json.Valid(aiReportRaw) {
		aiReportJSON = string(aiReportRaw)
	}
	nodeRunsJSON := marshalNodeRunsJSON(nodeRunsSnap)
	var idemPtr *string
	if idemKey != "" {
		idemPtr = &idemKey
	}

	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err = s.pool.Exec(dbCtx, `
		INSERT INTO runs (
			id, workflow_id, workflow_version, status, parent_run_id, rerun_from_node_id,
			findings_json, trace_id, idempotency_key, trigger_json, source_ref_json,
			gate_result_json, error_message, started_at, finished_at,
			ai_report_json, node_runs_json
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14,$15,$16::jsonb,$17::jsonb)
		ON CONFLICT (id) DO UPDATE SET
			workflow_version = EXCLUDED.workflow_version,
			status = EXCLUDED.status,
			findings_json = EXCLUDED.findings_json,
			trace_id = EXCLUDED.trace_id,
			trigger_json = EXCLUDED.trigger_json,
			source_ref_json = EXCLUDED.source_ref_json,
			gate_result_json = EXCLUDED.gate_result_json,
			error_message = EXCLUDED.error_message,
			started_at = COALESCE(EXCLUDED.started_at, runs.started_at),
			finished_at = COALESCE(EXCLUDED.finished_at, runs.finished_at),
			ai_report_json = CASE WHEN EXCLUDED.ai_report_json <> '{}'::jsonb THEN EXCLUDED.ai_report_json ELSE runs.ai_report_json END,
			node_runs_json = CASE WHEN EXCLUDED.node_runs_json <> '[]'::jsonb THEN EXCLUDED.node_runs_json ELSE runs.node_runs_json END`,
		runID, wfID, wfVer, statusStr, parentID, rerunNode,
		string(raw), trace, idemPtr, trigJSON, srcJSON,
		gateJSON, errMsg, startedAt, finishedAt,
		aiReportJSON, nodeRunsJSON)
	if isMissingColumnErr(err) {
		_, err = s.pool.Exec(dbCtx, `
			INSERT INTO runs (
				id, workflow_id, workflow_version, status, parent_run_id, rerun_from_node_id,
				findings_json, trace_id, idempotency_key, trigger_json, source_ref_json,
				gate_result_json, error_message, started_at, finished_at
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14,$15)
			ON CONFLICT (id) DO UPDATE SET
				workflow_version = EXCLUDED.workflow_version,
				status = EXCLUDED.status,
				findings_json = EXCLUDED.findings_json,
				trace_id = EXCLUDED.trace_id,
				trigger_json = EXCLUDED.trigger_json,
				source_ref_json = EXCLUDED.source_ref_json,
				gate_result_json = EXCLUDED.gate_result_json,
				error_message = EXCLUDED.error_message,
				started_at = COALESCE(EXCLUDED.started_at, runs.started_at),
				finished_at = COALESCE(EXCLUDED.finished_at, runs.finished_at)`,
			runID, wfID, wfVer, statusStr, parentID, rerunNode,
			string(raw), trace, idemPtr, trigJSON, srcJSON,
			gateJSON, errMsg, startedAt, finishedAt)
	}
	if err != nil {
		slog.Warn("persist run", "run_id", runID, "err", err)
	}
}

func (s *Server) loadRuns(ctx context.Context) {
	if s.pool == nil {
		return
	}
	hasExtendedCols := true
	rows, err := s.pool.Query(ctx, `
		SELECT
			id, workflow_id, workflow_version, status,
			COALESCE(parent_run_id, ''), COALESCE(rerun_from_node_id, ''),
			COALESCE(trace_id, ''), COALESCE(idempotency_key, ''),
			findings_json, COALESCE(sbom_json, '{}'::jsonb),
			COALESCE(trigger_json, '{}'::jsonb), COALESCE(source_ref_json, '{}'::jsonb),
			COALESCE(gate_result_json, '{}'::jsonb), COALESCE(error_message, ''),
			created_at, started_at, finished_at,
			COALESCE(ai_report_json, '{}'::jsonb), COALESCE(node_runs_json, '[]'::jsonb)
		FROM runs`)
	if isMissingColumnErr(err) {
		hasExtendedCols = false
		rows, err = s.pool.Query(ctx, `
			SELECT
				id, workflow_id, workflow_version, status,
				COALESCE(parent_run_id, ''), COALESCE(rerun_from_node_id, ''),
				COALESCE(trace_id, ''), COALESCE(idempotency_key, ''),
				findings_json, COALESCE(sbom_json, '{}'::jsonb),
				COALESCE(trigger_json, '{}'::jsonb), COALESCE(source_ref_json, '{}'::jsonb),
				COALESCE(gate_result_json, '{}'::jsonb), COALESCE(error_message, ''),
				created_at, started_at, finished_at
			FROM runs`)
	}
	if err != nil {
		slog.Warn("load runs", "err", err)
		return
	}
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	var loaded []*runState
	for rows.Next() {
		var runID, workflowID, statusName, parent, rerun, trace, idemKey, errMsg string
		var wfVer int32
		var raw, sbom, trigRaw, srcRaw, gateRaw, aiRaw, nodeRunsRaw []byte
		var createdAt time.Time
		var startedAt, finishedAt *time.Time
		var scanErr error
		if hasExtendedCols {
			scanErr = rows.Scan(
				&runID, &workflowID, &wfVer, &statusName,
				&parent, &rerun, &trace, &idemKey,
				&raw, &sbom, &trigRaw, &srcRaw, &gateRaw, &errMsg,
				&createdAt, &startedAt, &finishedAt,
				&aiRaw, &nodeRunsRaw,
			)
		} else {
			scanErr = rows.Scan(
				&runID, &workflowID, &wfVer, &statusName,
				&parent, &rerun, &trace, &idemKey,
				&raw, &sbom, &trigRaw, &srcRaw, &gateRaw, &errMsg,
				&createdAt, &startedAt, &finishedAt,
			)
		}
		if scanErr != nil {
			slog.Warn("scan run", "err", scanErr)
			continue
		}
		var findings []report.Finding
		if err := json.Unmarshal(raw, &findings); err != nil {
			slog.Warn("unmarshal run findings", "run_id", runID, "err", err)
		}
		run := &secflowv1.Run{
			Id:              runID,
			WorkflowId:      workflowID,
			WorkflowVersion: wfVer,
			Status:          secflowv1.RunStatus(secflowv1.RunStatus_value[statusName]),
			ParentRunId:     parent,
			RerunFromNodeId: rerun,
			TraceId:         trace,
			ErrorMessage:    errMsg,
			FindingsStats:   envelopeStatsProto(findings),
			CreatedAt:       timestamppb.New(createdAt),
		}
		if startedAt != nil {
			run.StartedAt = timestamppb.New(*startedAt)
		}
		if finishedAt != nil {
			run.FinishedAt = timestamppb.New(*finishedAt)
		}
		if len(trigRaw) > 0 && string(trigRaw) != "{}" {
			trig := &secflowv1.TriggerMetadata{}
			if unmarshaler.Unmarshal(trigRaw, trig) == nil {
				run.Trigger = trig
			}
		}
		if len(srcRaw) > 0 && string(srcRaw) != "{}" {
			src := &secflowv1.SourceRef{}
			if unmarshaler.Unmarshal(srcRaw, src) == nil {
				run.SourceRef = src
			}
		}
		if len(gateRaw) > 0 && string(gateRaw) != "{}" {
			gate := &secflowv1.GateResult{}
			if unmarshaler.Unmarshal(gateRaw, gate) == nil {
				run.GateResult = gate
			}
		}
		if restoredNodeRuns := unmarshalNodeRunsJSON(nodeRunsRaw); len(restoredNodeRuns) > 0 {
			run.NodeRuns = restoredNodeRuns
		}
		st := &runState{
			run:            run,
			idempotencyKey: idemKey,
			findings:       findings,
			payloads:       map[string][]byte{},
			done:           map[string]engine.NodeTrace{},
			skipped:        map[string]bool{},
			queued:         map[string]bool{},
		}
		if len(sbom) > 0 && string(sbom) != "{}" {
			st.payloads["sbom"] = sbom
			st.run.Sbom = sbomRefFromJSON(runID, sbom)
		}
		if len(aiRaw) > 0 && string(aiRaw) != "{}" {
			st.payloads["ai_report"] = aiRaw
			st.run.AiReport = aiReportFromPayload(findings, aiRaw)
		}
		loaded = append(loaded, st)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate runs", "err", err)
	}
	rows.Close()

	runMap := make(map[string]*runState, len(loaded))
	for _, st := range loaded {
		runMap[st.run.GetId()] = st
	}

	nodeRows, err := s.pool.Query(ctx, `SELECT run_id, node_id, payload_json FROM node_tasks`)
	if err != nil {
		slog.Warn("load node_tasks", "err", err)
	} else {
		for nodeRows.Next() {
			var runID, nodeID string
			var payload []byte
			if err := nodeRows.Scan(&runID, &nodeID, &payload); err != nil {
				slog.Warn("scan node_task", "err", err)
				continue
			}
			st := runMap[runID]
			if st == nil || len(payload) == 0 {
				continue
			}
			st.payloads["node:"+nodeID] = payload
			var tr engine.NodeTrace
			if json.Unmarshal(payload, &tr) == nil && (len(tr.Ports) > 0 || tr.Output.Trigger.Type != "" || len(tr.Output.Vars) > 0 || len(tr.Input.Vars) > 0) {
				st.done[nodeID] = tr
				if inBlob, err := json.Marshal(tr.Input); err == nil {
					st.payloads["in:"+nodeID] = inBlob
				}
				if outBlob, err := json.Marshal(tr.Output); err == nil {
					st.payloads["node:"+nodeID] = outBlob
				}
			}
			if rawAI := extractExplainFromTaskPayload(payload); len(rawAI) > 0 && len(st.payloads["ai_report"]) == 0 {
				st.payloads["ai_report"] = rawAI
				st.run.AiReport = aiReportFromPayload(st.findings, rawAI)
			}
		}
		if err := nodeRows.Err(); err != nil {
			slog.Warn("iterate node_tasks", "err", err)
		}
		nodeRows.Close()
	}

	evRows, err := s.pool.Query(ctx, `SELECT seq_id, run_id, event_type, payload_json FROM run_events ORDER BY seq_id`)
	if err != nil {
		slog.Warn("load run_events", "err", err)
	} else {
		for evRows.Next() {
			var seqID int64
			var runID, typ string
			var payload []byte
			if err := evRows.Scan(&seqID, &runID, &typ, &payload); err != nil {
				slog.Warn("scan run_event", "err", err)
				continue
			}
			st := runMap[runID]
			if st == nil {
				continue
			}
			ev := unmarshalRunEvent(seqID, runID, typ, payload)
			st.events = append(st.events, ev)
			if seqID > st.run.LastSeqId {
				st.run.LastSeqId = seqID
			}
		}
		if err := evRows.Err(); err != nil {
			slog.Warn("iterate run_events", "err", err)
		}
		evRows.Close()
	}

	s.runMu.Lock()
	for runID, st := range runMap {
		if _, exists := s.runs[runID]; !exists {
			s.runs[runID] = st
			if st.idempotencyKey != "" {
				s.idem[st.idempotencyKey] = runID
			}
		}
	}
	s.runMu.Unlock()
}
