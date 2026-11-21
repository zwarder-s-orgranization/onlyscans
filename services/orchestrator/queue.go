package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/report"
)

var (
	notifyClientsMu sync.Mutex
	notifyClients   = map[*Server]secflowv1.NotifyServiceClient{}
)

func (s *Server) setNotifyClient(c secflowv1.NotifyServiceClient) {
	notifyClientsMu.Lock()
	if c == nil {
		delete(notifyClients, s)
	} else {
		notifyClients[s] = c
	}
	notifyClientsMu.Unlock()
}

func (s *Server) injectedNotifyClient() secflowv1.NotifyServiceClient {
	notifyClientsMu.Lock()
	c := notifyClients[s]
	notifyClientsMu.Unlock()
	return c
}

func (s *Server) startPump(ctx context.Context) {
	go func() {
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
				s.drain(ctx)
			case <-tick.C:
				s.drain(ctx)
			}
		}
	}()
}

func (s *Server) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Server) drain(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		runID, nodeID, _, ok := s.claim(ctx)
		if !ok {
			return
		}
		s.runNode(ctx, runID, nodeID)
	}
}

func (s *Server) claim(ctx context.Context) (string, string, string, bool) {
	if s.pool != nil {
		var runID, nodeID, plugin string
		err := s.pool.QueryRow(ctx, `
			UPDATE node_tasks SET status = 'RUNNING', lease_until = now() + interval '30 seconds'
			WHERE node_run_id = (
				SELECT node_run_id FROM node_tasks
				WHERE status = 'QUEUED' AND (lease_until IS NULL OR lease_until < now())
				ORDER BY node_run_id
				FOR UPDATE SKIP LOCKED
				LIMIT 1
			)
			RETURNING run_id, node_id, plugin_id`).Scan(&runID, &nodeID, &plugin)
		if err != nil {
			return "", "", "", false
		}
		return runID, nodeID, plugin, true
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if len(s.memq) == 0 {
		return "", "", "", false
	}
	task := s.memq[0]
	s.memq = s.memq[1:]
	return task.runID, task.nodeID, task.plugin, true
}

func (s *Server) runNode(ctx context.Context, runID, nodeID string) {
	st := s.ensureRun(ctx, runID)
	if st == nil {
		s.settleTask(ctx, runID, nodeID, "CANCELLED", nil)
		return
	}
	s.reloadRunTasks(ctx, st)

	s.runMu.Lock()
	if st.finished || st.run.GetStatus() == secflowv1.RunStatus_RUN_STATUS_CANCELLED {
		s.runMu.Unlock()
		s.settleTask(ctx, runID, nodeID, "CANCELLED", nil)
		return
	}
	var node engine.Node
	found := false
	for _, n := range st.graph.Nodes {
		if n.ID == nodeID {
			node = n
			found = true
			break
		}
	}
	if !found {
		s.runMu.Unlock()
		s.settleTask(ctx, runID, nodeID, "FAILED", nil)
		return
	}
	in := inputFor(st, nodeID)
	sourceID := st.sourceID
	repoURL := st.repoURL
	runTrace := st.trace
	if st.run.Status == secflowv1.RunStatus_RUN_STATUS_QUEUED {
		st.run.Status = secflowv1.RunStatus_RUN_STATUS_RUNNING
	}
	if st.run.StartedAt == nil {
		st.run.StartedAt = timestamppb.Now()
	}
	s.runMu.Unlock()

	nodeRunID := runID + ":" + nodeID
	startedAt := time.Now()
	nodeCtx, nodeSpan := obs.StartTaskSpan(
		ctx,
		runTrace,
		"orchestrator.dispatch",
		attribute.String("secflow.run_id", runID),
		attribute.String("secflow.node_id", nodeID),
		attribute.String("secflow.node_run_id", nodeRunID),
		attribute.String("secflow.plugin_id", node.PluginID),
	)
	defer nodeSpan.End()
	if in.Vars == nil {
		in.Vars = map[string]string{}
	}
	in.RunID = runID
	in.Vars["runId"] = runID
	in.Vars["_nodeRunId"] = nodeRunID
	if activeTP := obs.InjectTraceparent(nodeCtx); activeTP != "" {
		in.Vars["traceparent"] = activeTP
	}

	s.pushNodeEvent(
		nodeCtx,
		st,
		nodeID,
		nodeRunID,
		secflowv1.NodeRunStatus_NODE_RUN_STATUS_RUNNING,
		secflowv1.RunStatus_RUN_STATUS_RUNNING,
		"node started",
		nil,
	)

	execNode := resolveNodeParams(node, in)
	handlers := s.handlersCtx(nodeCtx, sourceID, repoURL)
	result := engine.Step(execNode, in, handlers)
	finishedAt := time.Now()
	duration := finishedAt.Sub(startedAt)
	durationMs := duration.Milliseconds()

	tr := engine.NodeTrace{
		Input:           in,
		Output:          result.Envelope,
		Ports:           slices.Clone(result.ActivePorts),
		PortOutputs:     result.PortEnvelopes,
		RedactedPreview: slices.Clone(result.RedactedPreview),
	}
	if result.Status == "FAILED" {
		nodeSpan.SetStatus(otelcodes.Error, result.Err)
		s.recordNodeDuration(node.PluginID, "FAILED", duration)
		s.runMu.Lock()
		delete(st.queued, nodeID)
		if st.run.GetStatus() == secflowv1.RunStatus_RUN_STATUS_CANCELLED {
			s.runMu.Unlock()
			s.settleTask(nodeCtx, runID, nodeID, "CANCELLED", &tr)
			return
		}
		st.run.Status = secflowv1.RunStatus_RUN_STATUS_FAILED
		st.run.ErrorMessage = result.Err
		st.run.FinishedAt = timestamppb.New(finishedAt)
		st.finished = true
		s.recordNodeRunLocked(st, nodeRunID, node, secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED, tr.Ports, 0, result.Err, result.RedactedPreview, startedAt, finishedAt, durationMs)
		errMsg := st.run.GetErrorMessage()
		s.runMu.Unlock()
		s.persistNodeArtifacts(nodeCtx, runID, nodeID, tr)
		s.pushNodeEvent(
			nodeCtx,
			st,
			nodeID,
			nodeRunID,
			secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			secflowv1.RunStatus_RUN_STATUS_FAILED,
			errMsg,
			result.RedactedPreview,
		)
		s.settleTask(nodeCtx, runID, nodeID, "FAILED", &tr)
		s.failRun(nodeCtx, st, errMsg)
		return
	}

	s.recordNodeDuration(node.PluginID, "SUCCEEDED", duration)

	s.runMu.Lock()
	delete(st.queued, nodeID)
	if st.finished || st.run.GetStatus() == secflowv1.RunStatus_RUN_STATUS_CANCELLED {
		s.runMu.Unlock()
		s.settleTask(ctx, runID, nodeID, "CANCELLED", &tr)
		return
	}
	st.done[nodeID] = tr
	findingsEmitted := 0
	if engine.IsAnalyzer(node.PluginID) {
		baselineSet := baselineSetFromPayloads(st.payloads)
		reported := toReport(result.Findings)
		st.findings = append(st.findings, reported...)
		for _, f := range result.Findings {
			srcNode := f.SourceNodeID
			if srcNode == "" {
				srcNode = nodeID
			}
			plugID := f.PluginID
			if plugID == "" {
				plugID = node.PluginID
			}
			isNew := f.IsNewVsBaseline
			if !isNew && len(baselineSet) > 0 {
				fp := engine.FindingFingerprint(f)
				if fp != "" && !baselineSet[fp] {
					isNew = true
				}
			}
			st.findingMeta = append(st.findingMeta, findingMeta{
				sourceNodeID:    srcNode,
				pluginID:        plugID,
				maskedSnippet:   f.MaskedSnippet,
				isNewVsBaseline: isNew,
			})
		}
		st.run.FindingsStats = envelopeStatsProto(st.findings)
		findingsEmitted = len(result.Findings)
	}
	if node.PluginID == "logic.compare" && len(tr.Output.Findings) > 0 {
		newByFP := map[string]bool{}
		for _, f := range tr.Output.Findings {
			if f.IsNewVsBaseline {
				newByFP[engine.FindingFingerprint(f)] = true
			}
		}
		for i, rf := range st.findings {
			fp := engine.FindingFingerprint(engine.Finding{
				Category: rf.Category, Path: rf.Path, Class: rf.Class,
				Group: rf.Group, Artifact: rf.Artifact, AdvisoryID: rf.AdvisoryID,
			})
			if newByFP[fp] {
				for len(st.findingMeta) <= i {
					st.findingMeta = append(st.findingMeta, findingMeta{})
				}
				st.findingMeta[i].isNewVsBaseline = true
			}
		}
	}
	s.storeTraceLocked(st, nodeID, tr)
	if result.Envelope.SourceRef != nil && st.run.SourceRef == nil {
		st.run.SourceRef = sourceRefProtoFromInfo(result.Envelope.SourceRef)
	}
	var gateRes *secflowv1.GateResult
	if node.PluginID == "gate.policy" {
		fallbackPort := ""
		if len(tr.Ports) > 0 {
			fallbackPort = tr.Ports[0]
		}
		gateRes = gateResultFromInfo(nodeID, result.Envelope.Gate, fallbackPort)
		st.run.GateResult = gateRes
	}
	s.recordNodeRunLocked(st, nodeRunID, node, secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED, tr.Ports, findingsEmitted, "", result.RedactedPreview, startedAt, finishedAt, durationMs)
	aiReportReady := node.PluginID == "ai.explain" && len(st.payloads["ai_report"]) > 0
	wfID := st.run.GetWorkflowId()
	toPersist := s.enqueueReadyLocked(st)
	finishedNow := s.markFinishedIfDoneLocked(st)
	s.runMu.Unlock()

	s.persistNodeArtifacts(ctx, runID, nodeID, tr)
	s.pushNodeEvent(
		ctx,
		st,
		nodeID,
		nodeRunID,
		secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		secflowv1.RunStatus_RUN_STATUS_RUNNING,
		"node completed",
		result.RedactedPreview,
	)
	if aiReportReady {
		s.emitEvent(nodeCtx, st, &secflowv1.RunEvent{
			EventType:           secflowv1.RunEventType_RUN_EVENT_TYPE_AI_REPORT_READY,
			RunStatus:           secflowv1.RunStatus_RUN_STATUS_RUNNING,
			NodeId:              nodeID,
			NodeRunId:           nodeRunID,
			RedactedPreviewJson: slices.Clone(result.RedactedPreview),
			Message:             "ai report ready",
		})
		if !finishedNow {
			s.persistRun(nodeCtx, st)
		}
	}
	if gateRes != nil {
		s.emitEvent(ctx, st, &secflowv1.RunEvent{
			EventType:  secflowv1.RunEventType_RUN_EVENT_TYPE_GATE_EVALUATED,
			RunStatus:  secflowv1.RunStatus_RUN_STATUS_RUNNING,
			NodeId:     nodeID,
			NodeRunId:  nodeRunID,
			GateResult: gateRes,
			Message:    gateRes.GetReason(),
		})
	}
	s.persistQueuedTasks(nodeCtx, toPersist)
	s.settleTask(nodeCtx, runID, nodeID, "SUCCEEDED", &tr)
	if finishedNow {
		s.recordRunTerminal("SUCCEEDED")
		s.pushEvent(nodeCtx, st, secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_COMPLETED, secflowv1.RunStatus_RUN_STATUS_SUCCEEDED, "run finished")
		s.persistRun(nodeCtx, st)
		var wfGraph *secflowv1.WorkflowGraph
		if wf := s.mustWorkflow(wfID); wf != nil {
			wfGraph = wf.GetGraph()
		}
		s.persistPayloads(nodeCtx, st, wfGraph)
		s.dispatchTerminalCommitStatus(nodeCtx, st)
	}
	s.kick()
}

func (s *Server) recordNodeRunLocked(
	st *runState,
	nodeRunID string,
	node engine.Node,
	status secflowv1.NodeRunStatus,
	ports []string,
	findingsEmitted int,
	errMsg string,
	preview []byte,
	startedAt, finishedAt time.Time,
	durationMs int64,
) {
	runID := st.run.GetId()
	nr := &secflowv1.NodeRun{
		NodeRunId:           nodeRunID,
		RunId:               runID,
		NodeId:              node.ID,
		PluginId:            node.PluginID,
		Status:              status,
		Attempt:             1,
		ActiveOutputPorts:   slices.Clone(ports),
		FindingsEmitted:     int32(findingsEmitted),
		ErrorMessage:        errMsg,
		RedactedPreviewJson: slices.Clone(preview),
		DurationMs:          durationMs,
		StartedAt:           timestamppb.New(startedAt),
		FinishedAt:          timestamppb.New(finishedAt),
	}
	if blobstore.Configured() {
		prefix := fmt.Sprintf("runs/%s/nodes/%s", runID, node.ID)
		nr.InputS3Key = prefix + "/in.json"
		nr.OutputS3Key = prefix + "/out.json"
		if len(ports) > 0 {
			nr.PortOutputS3Keys = make(map[string]string, len(ports))
			for _, handle := range ports {
				if handle != "" {
					nr.PortOutputS3Keys[handle] = fmt.Sprintf("%s/out.%s.json", prefix, handle)
				}
			}
		}
	}
	replaced := false
	for i, existing := range st.run.NodeRuns {
		if existing.GetNodeId() == node.ID {
			st.run.NodeRuns[i] = nr
			replaced = true
			break
		}
	}
	if !replaced {
		st.run.NodeRuns = append(st.run.NodeRuns, nr)
	}
}

func (s *Server) failRun(ctx context.Context, st *runState, errMsg string) {
	s.cancelQueued(ctx, st.run.GetId())
	s.recordRunTerminal("FAILED")
	s.pushEvent(ctx, st, secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_FAILED, secflowv1.RunStatus_RUN_STATUS_FAILED, errMsg)
	s.persistRun(ctx, st)
	s.dispatchTerminalCommitStatus(ctx, st)
}

type webhookCommitConfig struct {
	triggerNodeID      string
	reportCommitStatus bool
	statusContext      string
	gitStatusSecretRef string
	gitProvider        secflowv1.GitProvider
}

func webhookCommitStatusConfig(wf *secflowv1.Workflow) webhookCommitConfig {
	cfg := webhookCommitConfig{
		reportCommitStatus: true,
		statusContext:      "secflow/security-gate",
		gitProvider:        secflowv1.GitProvider_GIT_PROVIDER_GITHUB,
	}
	if wf == nil || wf.GetGraph() == nil {
		return cfg
	}
	for _, n := range wf.GetGraph().GetNodes() {
		if n.GetPluginId() != "trigger.webhook" {
			continue
		}
		cfg.triggerNodeID = n.GetId()
		params := map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			_ = json.Unmarshal(n.GetParamsJson(), &params)
		}
		if prov, _ := params["gitProvider"].(string); strings.EqualFold(prov, "GITLAB") {
			cfg.gitProvider = secflowv1.GitProvider_GIT_PROVIDER_GITLAB
		}
		if b, ok := params["reportCommitStatus"].(bool); ok {
			cfg.reportCommitStatus = b
		}
		if ctxStr, _ := params["commitStatusContext"].(string); strings.TrimSpace(ctxStr) != "" {
			cfg.statusContext = strings.TrimSpace(ctxStr)
		}
		for _, b := range n.GetSecretBindings() {
			if b.GetParamKey() == "gitStatusToken" && strings.TrimSpace(b.GetSecretRef()) != "" {
				cfg.gitStatusSecretRef = strings.TrimSpace(b.GetSecretRef())
			}
		}
		break
	}
	return cfg
}

func deriveTerminalCommitStatus(runStatus secflowv1.RunStatus, gate *secflowv1.GateResult) (secflowv1.CommitStatusState, string) {
	switch runStatus {
	case secflowv1.RunStatus_RUN_STATUS_FAILED:
		return secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE, "SecFlow security scan failed"
	case secflowv1.RunStatus_RUN_STATUS_CANCELLED:
		return secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE, "SecFlow security scan cancelled"
	}
	if gate != nil {
		switch gate.GetStatus() {
		case secflowv1.GateStatus_GATE_STATUS_FAIL:
			return secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE, nonEmpty(gate.GetReason(), "SecFlow security gate failed")
		case secflowv1.GateStatus_GATE_STATUS_WARN:
			return secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS, nonEmpty(gate.GetReason(), "SecFlow security gate passed with warnings")
		}
	}
	return secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS, "SecFlow security gate passed"
}

func (s *Server) dispatchTerminalCommitStatus(ctx context.Context, st *runState) {
	if st == nil {
		return
	}
	s.runMu.Lock()
	if st.run == nil {
		s.runMu.Unlock()
		return
	}
	trigSnap, _ := proto.Clone(st.run.GetTrigger()).(*secflowv1.TriggerMetadata)
	gateSnap, _ := proto.Clone(st.run.GetGateResult()).(*secflowv1.GateResult)
	runSnap := &secflowv1.Run{
		Id:         st.run.GetId(),
		WorkflowId: st.run.GetWorkflowId(),
		Status:     st.run.GetStatus(),
		Trigger:    trigSnap,
		GateResult: gateSnap,
	}
	tp := st.trace
	s.runMu.Unlock()
	state, desc := deriveTerminalCommitStatus(runSnap.GetStatus(), runSnap.GetGateResult())
	s.dispatchCommitStatus(ctx, runSnap, tp, state, desc)
}

func (s *Server) dispatchCommitStatus(ctx context.Context, run *secflowv1.Run, traceparent string, state secflowv1.CommitStatusState, desc string) {
	if run == nil {
		return
	}
	trig := run.GetTrigger()
	if trig == nil || trig.GetType() != secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK {
		return
	}
	statusURL := strings.TrimSpace(trig.GetCommitStatusUrl())
	if statusURL == "" {
		return
	}
	cfg := webhookCommitStatusConfig(s.mustWorkflow(run.GetWorkflowId()))
	if !cfg.reportCommitStatus {
		return
	}
	provider := trig.GetGitProvider()
	if provider == secflowv1.GitProvider_GIT_PROVIDER_UNSPECIFIED {
		provider = cfg.gitProvider
	}
	publicBase := strings.TrimRight(strings.TrimSpace(envutil.Get("SECFLOW_PUBLIC_URL", "http://localhost:8080")), "/")
	req := &secflowv1.SendCommitStatusRequest{
		RunId:              run.GetId(),
		WorkflowId:         run.GetWorkflowId(),
		TriggerNodeId:      cfg.triggerNodeID,
		GitProvider:        provider,
		CommitStatusUrl:    statusURL,
		CommitSha:          trig.GetCommitSha(),
		State:              state,
		Context:            cfg.statusContext,
		Description:        desc,
		TargetUrl:          publicBase + "/runs/" + run.GetId(),
		GitStatusSecretRef: cfg.gitStatusSecretRef,
		Traceparent:        traceparent,
	}

	injected := s.injectedNotifyClient()
	addr := strings.TrimSpace(os.Getenv("NOTIFY_ADDR"))
	if injected == nil && addr == "" {
		return
	}
	baseCtx := obs.ExtractTraceparent(context.WithoutCancel(ctx), traceparent)
	go func() {
		callCtx, cancel := context.WithTimeout(baseCtx, 10*time.Second)
		defer cancel()
		client := injected
		if client == nil {
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
			if err != nil {
				slog.WarnContext(callCtx, "dial notify-service for commit status", "run_id", req.GetRunId(), "err", err)
				return
			}
			defer conn.Close()
			client = secflowv1.NewNotifyServiceClient(conn)
		}
		if _, err := client.SendCommitStatus(callCtx, req); err != nil {
			slog.WarnContext(callCtx, "send commit status failed", "run_id", req.GetRunId(), "state", req.GetState().String(), "err", err)
		}
	}()
}

// markFinishedIfDoneLocked transitions st to SUCCEEDED if no pending/queued nodes remain. Caller holds s.runMu.
func (s *Server) markFinishedIfDoneLocked(st *runState) bool {
	if st.finished {
		return false
	}
	if st.run.GetStatus() == secflowv1.RunStatus_RUN_STATUS_FAILED || st.run.GetStatus() == secflowv1.RunStatus_RUN_STATUS_CANCELLED {
		return false
	}
	for _, n := range st.graph.Nodes {
		if st.skipped[n.ID] {
			continue
		}
		if _, ok := st.done[n.ID]; ok {
			continue
		}
		return false
	}
	raw, err := report.SubmissionJSON(st.findings)
	if err == nil {
		st.payloads["submission"] = raw
	}
	if sbomRaw := st.payloads["sbom"]; len(sbomRaw) > 0 && st.run.Sbom == nil {
		st.run.Sbom = sbomRefFromJSON(st.run.GetId(), sbomRaw)
	}
	if aiRaw := st.payloads["ai_report"]; len(aiRaw) > 0 {
		st.run.AiReport = aiReportFromPayload(st.findings, aiRaw)
	}
	st.run.Status = secflowv1.RunStatus_RUN_STATUS_SUCCEEDED
	st.run.FinishedAt = timestamppb.Now()
	st.finished = true
	return true
}

// enqueueReadyLocked marks ready nodes as queued and returns tasks to persist to PostgreSQL outside the lock.
// Caller holds s.runMu.
func (s *Server) enqueueReadyLocked(st *runState) []memTask {
	incoming := map[string][]engine.Edge{}
	for _, e := range st.graph.Edges {
		incoming[e.Target] = append(incoming[e.Target], e)
	}
	var toPersist []memTask
	for {
		progressed := false
		for _, n := range st.graph.Nodes {
			if st.skipped[n.ID] || st.queued[n.ID] {
				continue
			}
			if _, ok := st.done[n.ID]; ok {
				continue
			}
			edges := incoming[n.ID]
			if len(edges) == 0 {
				if t, ok := s.enqueueNodeLocked(st, n); ok {
					toPersist = append(toPersist, t)
				}
				progressed = true
				continue
			}
			ready := true
			active := false
			for _, e := range edges {
				if st.skipped[e.Source] {
					continue
				}
				tr, ok := st.done[e.Source]
				if !ok {
					ready = false
					break
				}
				handle := e.SourceHandle
				if handle == "" {
					handle = "default"
				}
				if containsPort(tr.Ports, handle) {
					active = true
				}
			}
			if !ready {
				continue
			}
			if !active {
				st.skipped[n.ID] = true
				now := time.Now()
				s.recordNodeRunLocked(st, st.run.GetId()+":"+n.ID, n, secflowv1.NodeRunStatus_NODE_RUN_STATUS_SKIPPED, nil, 0, "", nil, now, now, 0)
				progressed = true
				continue
			}
			if t, ok := s.enqueueNodeLocked(st, n); ok {
				toPersist = append(toPersist, t)
			}
			progressed = true
		}
		if !progressed {
			break
		}
	}
	return toPersist
}

func (s *Server) enqueueNodeLocked(st *runState, n engine.Node) (memTask, bool) {
	st.queued[n.ID] = true
	task := memTask{runID: st.run.GetId(), nodeID: n.ID, plugin: n.PluginID, nodeRun: st.run.GetId() + ":" + n.ID}
	s.trackQueuedTaskLocked(task.nodeRun, n.PluginID)
	if s.pool == nil {
		s.memq = append(s.memq, task)
		return memTask{}, false
	}
	return task, true
}

func (s *Server) persistQueuedTasks(ctx context.Context, tasks []memTask) {
	if s.pool == nil || len(tasks) == 0 {
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	for _, t := range tasks {
		if _, err := s.pool.Exec(dbCtx, `INSERT INTO node_tasks (node_run_id, run_id, node_id, plugin_id, status) VALUES ($1,$2,$3,$4,'QUEUED') ON CONFLICT (node_run_id) DO NOTHING`, t.nodeRun, t.runID, t.nodeID, t.plugin); err != nil {
			slog.Warn("enqueue node task", "node_run_id", t.nodeRun, "err", err)
		}
	}
}

func (s *Server) settleTask(ctx context.Context, runID, nodeID, status string, tr *engine.NodeTrace) {
	s.runMu.Lock()
	s.releaseQueuedTaskLocked(runID + ":" + nodeID)
	s.runMu.Unlock()
	if s.pool == nil {
		return
	}
	raw := []byte(`{}`)
	if tr != nil {
		if b, err := json.Marshal(tr); err == nil {
			raw = b
		}
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(dbCtx, `UPDATE node_tasks SET status = $3, payload_json = $4::jsonb, lease_until = NULL WHERE run_id = $1 AND node_id = $2`, runID, nodeID, status, string(raw)); err != nil {
		slog.Warn("settle node task", "run_id", runID, "node_id", nodeID, "err", err)
	}
}

func (s *Server) cancelQueued(ctx context.Context, runID string) {
	s.runMu.Lock()
	kept := s.memq[:0]
	for _, task := range s.memq {
		if task.runID != runID {
			kept = append(kept, task)
		}
	}
	s.memq = kept
	s.releaseQueuedRunLocked(runID)
	s.runMu.Unlock()
	if s.pool != nil {
		dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(dbCtx, `UPDATE node_tasks SET status = 'CANCELLED', lease_until = NULL WHERE run_id = $1 AND status IN ('QUEUED', 'RUNNING')`, runID); err != nil {
			slog.Warn("cancel queued tasks", "run_id", runID, "err", err)
		}
	}
}

func (s *Server) reloadRunTasks(ctx context.Context, st *runState) {
	if s.pool == nil || st == nil {
		return
	}
	s.runMu.Lock()
	runID := st.run.GetId()
	s.runMu.Unlock()

	rows, err := s.pool.Query(ctx, `SELECT node_id, status, payload_json FROM node_tasks WHERE run_id = $1`, runID)
	if err != nil {
		slog.Warn("reload node tasks", "run_id", runID, "err", err)
		return
	}
	type taskRow struct {
		nodeID, status string
		raw            []byte
	}
	var fetched []taskRow
	for rows.Next() {
		var r taskRow
		if err := rows.Scan(&r.nodeID, &r.status, &r.raw); err != nil {
			slog.Warn("scan node task", "run_id", runID, "err", err)
			continue
		}
		fetched = append(fetched, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate node tasks", "run_id", runID, "err", err)
	}
	rows.Close()

	s.runMu.Lock()
	defer s.runMu.Unlock()
	for _, r := range fetched {
		switch r.status {
		case "SUCCEEDED":
			var tr engine.NodeTrace
			if json.Unmarshal(r.raw, &tr) == nil {
				st.done[r.nodeID] = tr
				s.storeTraceLocked(st, r.nodeID, tr)
			}
			delete(st.queued, r.nodeID)
		case "QUEUED", "RUNNING":
			st.queued[r.nodeID] = true
		case "CANCELLED":
			st.skipped[r.nodeID] = true
		}
	}
}

func (s *Server) ensureRun(ctx context.Context, runID string) *runState {
	s.runMu.Lock()
	st := s.runs[runID]
	hasGraph := st != nil && len(st.graph.Nodes) > 0
	s.runMu.Unlock()
	if hasGraph || s.pool == nil {
		return st
	}
	var workflowID, statusName, trace string
	if err := s.pool.QueryRow(ctx, `SELECT workflow_id, status, COALESCE(trace_id, '') FROM runs WHERE id = $1`, runID).Scan(&workflowID, &statusName, &trace); err != nil {
		return st
	}
	wf := s.mustWorkflow(workflowID)
	if wf == nil {
		return st
	}
	graph := toEngine(wf.GetGraph())

	s.runMu.Lock()
	defer s.runMu.Unlock()
	st = s.runs[runID]
	if st == nil {
		st = &runState{
			run:      &secflowv1.Run{Id: runID, WorkflowId: workflowID, TraceId: trace},
			payloads: map[string][]byte{},
			done:     map[string]engine.NodeTrace{},
			skipped:  map[string]bool{},
			queued:   map[string]bool{},
		}
		s.runs[runID] = st
	}
	if len(st.graph.Nodes) == 0 {
		st.graph = graph
	}
	if st.done == nil {
		st.done = map[string]engine.NodeTrace{}
	}
	st.run.Status = secflowv1.RunStatus(secflowv1.RunStatus_value[statusName])
	return st
}

func inputFor(st *runState, nodeID string) engine.Envelope {
	env := engine.Envelope{
		Trigger:  triggerInfoFromProto(st.run.GetTrigger()),
		Findings: []engine.Finding{},
		Vars:     map[string]string{"runId": st.run.GetId(), "traceparent": st.trace},
		RunID:    st.run.GetId(),
	}
	if rawBase := st.payloads["_baseline_fingerprints"]; len(rawBase) > 0 {
		var fps []string
		if json.Unmarshal(rawBase, &fps) == nil && len(fps) > 0 {
			env.BaselineFingerprints = make(map[string]bool, len(fps))
			for _, fp := range fps {
				env.BaselineFingerprints[fp] = true
			}
		}
	}
	dedupe := true
	for _, n := range st.graph.Nodes {
		if n.ID == nodeID && n.PluginID == "logic.merge" && n.Params != nil {
			if b, ok := n.Params["deduplicateByFingerprint"].(bool); ok {
				dedupe = b
			}
			break
		}
	}
	seen := map[string]bool{}
	for _, e := range st.graph.Edges {
		if e.Target != nodeID {
			continue
		}
		tr, ok := st.done[e.Source]
		if !ok {
			continue
		}
		handle := e.SourceHandle
		if handle == "" {
			handle = "default"
		}
		if !containsPort(tr.Ports, handle) {
			continue
		}
		src := tr.Output
		if tr.PortOutputs != nil {
			if portEnv, exists := tr.PortOutputs[handle]; exists {
				src = portEnv
			}
		}
		for k, v := range src.Vars {
			if !strings.HasPrefix(k, "_") {
				env.Vars[k] = v
			}
		}
		if src.SourceRef != nil {
			cp := *src.SourceRef
			env.SourceRef = &cp
		}
		if src.SbomRef != nil {
			cp := *src.SbomRef
			env.SbomRef = &cp
		}
		if src.AIReport != nil {
			cp := *src.AIReport
			env.AIReport = &cp
		}
		if src.Gate != nil {
			cp := *src.Gate
			env.Gate = &cp
		}
		for _, f := range src.Findings {
			key := engine.FindingFingerprint(f)
			if key == "|||||" && f.ID != "" {
				key = f.ID
			}
			if dedupe && key != "" && seen[key] {
				continue
			}
			if key != "" {
				seen[key] = true
			}
			env.Findings = append(env.Findings, f)
		}
	}
	return env.Normalize()
}

func baselineSetFromPayloads(payloads map[string][]byte) map[string]bool {
	rawBase := payloads["_baseline_fingerprints"]
	if len(rawBase) == 0 {
		return nil
	}
	var fps []string
	if json.Unmarshal(rawBase, &fps) != nil || len(fps) == 0 {
		return nil
	}
	out := make(map[string]bool, len(fps))
	for _, fp := range fps {
		out[fp] = true
	}
	return out
}

func (s *Server) storeTraceLocked(st *runState, nodeID string, tr engine.NodeTrace) {
	blob, _ := json.Marshal(tr.Output)
	inBlob, _ := json.Marshal(tr.Input)
	ports, _ := json.Marshal(tr.Ports)
	st.payloads["node:"+nodeID] = blob
	st.payloads["in:"+nodeID] = inBlob
	st.payloads["ports:"+nodeID] = ports
	for handle, portEnv := range tr.PortOutputs {
		if handle == "" {
			continue
		}
		if pb, err := json.Marshal(portEnv); err == nil {
			st.payloads["port:"+nodeID+":"+handle] = pb
		}
	}
	if tr.Output.Vars != nil && tr.Output.Vars["sbom"] != "" {
		rawSbom := []byte(tr.Output.Vars["sbom"])
		st.payloads["sbom"] = rawSbom
		if st.run != nil {
			st.run.Sbom = sbomRefFromJSON(st.run.GetId(), rawSbom)
		}
	}
	if tr.Output.Vars != nil && tr.Output.Vars["explain"] != "" {
		rawAI := []byte(tr.Output.Vars["explain"])
		st.payloads["ai_report"] = rawAI
		if st.run != nil {
			st.run.AiReport = aiReportFromPayload(st.findings, rawAI)
		}
	}
}
