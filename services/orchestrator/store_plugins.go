package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/lease"
)

const (
	defaultWorkerHardTimeout = 120 * time.Second
	aiExplainHardTimeout     = 180 * time.Second
)

func workerHardTimeoutFor(plugin string) time.Duration {
	if plugin == "ai.explain" {
		return aiExplainHardTimeout
	}
	return defaultWorkerHardTimeout
}

func isOrchestratorManagedSourcePlugin(pluginID string) bool {
	return pluginID == "source.upload" || pluginID == "source.git"
}

func clonePluginManifest(m *secflowv1.PluginManifest) *secflowv1.PluginManifest {
	if m == nil {
		return nil
	}
	cp, _ := proto.Clone(m).(*secflowv1.PluginManifest)
	return cp
}

func mergePluginManifest(existing, incoming *secflowv1.PluginManifest) *secflowv1.PluginManifest {
	merged := clonePluginManifest(incoming)
	if merged == nil {
		return clonePluginManifest(existing)
	}
	if existing == nil {
		return merged
	}
	if merged.GetVersion() == "" {
		merged.Version = existing.GetVersion()
	}
	if merged.GetDisplayName() == "" {
		merged.DisplayName = existing.GetDisplayName()
	}
	if merged.GetDescription() == "" {
		merged.Description = existing.GetDescription()
	}
	if merged.GetCategory() == secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED {
		merged.Category = existing.GetCategory()
	}
	if len(merged.GetCapabilities()) == 0 && len(existing.GetCapabilities()) > 0 {
		merged.Capabilities = slices.Clone(existing.GetCapabilities())
	}
	if len(merged.GetParamsJsonSchema()) == 0 && len(existing.GetParamsJsonSchema()) > 0 {
		merged.ParamsJsonSchema = slices.Clone(existing.GetParamsJsonSchema())
	}
	if len(merged.GetInputPorts()) == 0 && len(existing.GetInputPorts()) > 0 {
		merged.InputPorts = make([]*secflowv1.PortDefinition, 0, len(existing.GetInputPorts()))
		for _, p := range existing.GetInputPorts() {
			if cp, ok := proto.Clone(p).(*secflowv1.PortDefinition); ok {
				merged.InputPorts = append(merged.InputPorts, cp)
			}
		}
	}
	if len(merged.GetOutputPorts()) == 0 && len(existing.GetOutputPorts()) > 0 {
		merged.OutputPorts = make([]*secflowv1.PortDefinition, 0, len(existing.GetOutputPorts()))
		for _, p := range existing.GetOutputPorts() {
			if cp, ok := proto.Clone(p).(*secflowv1.PortDefinition); ok {
				merged.OutputPorts = append(merged.OutputPorts, cp)
			}
		}
	}
	if merged.GetRuntimeLanguage() == "" {
		merged.RuntimeLanguage = existing.GetRuntimeLanguage()
	}
	if merged.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED {
		merged.SandboxProfile = existing.GetSandboxProfile()
	}
	if len(merged.GetRequiredSecretKeys()) == 0 && len(existing.GetRequiredSecretKeys()) > 0 {
		merged.RequiredSecretKeys = slices.Clone(existing.GetRequiredSecretKeys())
	}
	if merged.GetMaxConcurrency() <= 0 {
		merged.MaxConcurrency = existing.GetMaxConcurrency()
	}
	return merged
}

func (s *Server) queueDepths(ctx context.Context) map[string]int64 {
	depths := map[string]int64{}
	if s.pool != nil {
		dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		rows, err := s.pool.Query(dbCtx, `SELECT plugin_id, COUNT(*) FROM node_tasks WHERE status = 'QUEUED' GROUP BY plugin_id`)
		if err != nil {
			slog.Warn("query queue depths", "err", err)
			return depths
		}
		defer rows.Close()
		for rows.Next() {
			var pluginID string
			var cnt int64
			if err := rows.Scan(&pluginID, &cnt); err == nil {
				depths[pluginID] = cnt
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("iterate queue depths", "err", err)
		}
		return depths
	}
	s.runMu.Lock()
	for _, task := range s.memq {
		depths[task.plugin]++
	}
	s.runMu.Unlock()
	return depths
}

func (s *Server) activeWorkerCountLocked(pluginID string) int32 {
	var count int32
	for _, w := range s.workers[pluginID] {
		if w != nil && !w.draining.Load() {
			count++
		}
	}
	return count
}

func (s *Server) registeredPluginLocked(m *secflowv1.PluginManifest, queueDepth int64) *secflowv1.RegisteredPlugin {
	pid := m.GetPluginId()
	active := s.activeWorkerCountLocked(pid)
	st := secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE
	if m.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN || isOrchestratorManagedSourcePlugin(pid) {
		st = secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE
		if active == 0 {
			active = 1
		}
	} else if active > 0 {
		st = secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE
	}
	return &secflowv1.RegisteredPlugin{
		Manifest:      clonePluginManifest(m),
		Status:        st,
		ActiveWorkers: active,
		QueueDepth:    queueDepth,
		RegisteredAt:  s.pluginRegisteredAt[pid],
		LastSeenAt:    s.pluginLastSeen[pid],
	}
}

func (s *Server) ListPlugins(ctx context.Context, req *secflowv1.ListPluginsRequest) (*secflowv1.ListPluginsResponse, error) {
	depths := s.queueDepths(ctx)
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	catFilter := req.GetCategory()
	items := make([]*secflowv1.RegisteredPlugin, 0, len(s.plugins))
	for pid, m := range s.plugins {
		if catFilter != secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED && m.GetCategory() != catFilter {
			continue
		}
		items = append(items, s.registeredPluginLocked(m, depths[pid]))
	}
	return &secflowv1.ListPluginsResponse{Plugins: items}, nil
}

func (s *Server) GetPlugin(ctx context.Context, req *secflowv1.GetPluginRequest) (*secflowv1.GetPluginResponse, error) {
	depths := s.queueDepths(ctx)
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	pid := req.GetPluginId()
	m, ok := s.plugins[pid]
	if !ok {
		return nil, status.Error(codes.NotFound, "plugin not found")
	}
	return &secflowv1.GetPluginResponse{Plugin: s.registeredPluginLocked(m, depths[pid])}, nil
}

func (s *Server) WatchPlugins(_ *secflowv1.WatchPluginsRequest, stream secflowv1.PluginRegistryService_WatchPluginsServer) error {
	depths := s.queueDepths(stream.Context())
	s.plugMu.Lock()
	ch := make(chan *secflowv1.PluginRegistryEvent, 32)
	s.pluginWatch = append(s.pluginWatch, ch)
	events := make([]*secflowv1.PluginRegistryEvent, 0, len(s.plugins))
	for pid, m := range s.plugins {
		rp := s.registeredPluginLocked(m, depths[pid])
		events = append(events, &secflowv1.PluginRegistryEvent{
			EventType:  secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED,
			Plugin:     rp,
			OccurredAt: timestamppb.Now(),
		})
	}
	s.plugMu.Unlock()
	defer func() {
		s.plugMu.Lock()
		kept := s.pluginWatch[:0]
		for _, w := range s.pluginWatch {
			if w != ch {
				kept = append(kept, w)
			}
		}
		s.pluginWatch = kept
		s.plugMu.Unlock()
	}()
	for _, ev := range events {
		if err := stream.Send(&secflowv1.WatchPluginsResponse{Event: ev}); err != nil {
			return err
		}
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-ch:
			if err := stream.Send(&secflowv1.WatchPluginsResponse{Event: ev}); err != nil {
				return err
			}
		}
	}
}

func pluginEvent(kind secflowv1.PluginRegistryEventType, rp *secflowv1.RegisteredPlugin) *secflowv1.PluginRegistryEvent {
	return &secflowv1.PluginRegistryEvent{EventType: kind, Plugin: rp, OccurredAt: timestamppb.Now()}
}

// fanoutPlugin delivers to watchers. The caller holds s.plugMu.
func (s *Server) fanoutPlugin(ev *secflowv1.PluginRegistryEvent) {
	for _, ch := range s.pluginWatch {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Server) Connect(stream secflowv1.WorkerService_ConnectServer) error {
	var link *workerLink
	defer func() {
		if link == nil {
			return
		}
		s.plugMu.Lock()
		for _, plugID := range link.plugins {
			list := s.workers[plugID]
			kept := list[:0]
			for _, w := range list {
				if w != link {
					kept = append(kept, w)
				}
			}
			if len(kept) == 0 {
				delete(s.workers, plugID)
			} else {
				s.workers[plugID] = kept
			}
			s.setActiveWorkers(plugID, s.activeWorkerCountLocked(plugID))
			if m := s.plugins[plugID]; m != nil {
				rp := s.registeredPluginLocked(m, 0)
				evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
				if rp.GetStatus() == secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE {
					evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE
				}
				s.fanoutPlugin(pluginEvent(evType, rp))
			}
		}
		s.plugMu.Unlock()

		// Fail any in-flight tasks leased by this disconnected worker immediately.
		s.failWorkerTasks(link, "WORKER_DISCONNECTED", "worker stream disconnected")
	}()
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		switch p := req.GetPayload().(type) {
		case *secflowv1.ConnectRequest_RegisterManifest:
			if denied(p.RegisterManifest) {
				_ = stream.Send(&secflowv1.ConnectResponse{Payload: &secflowv1.ConnectResponse_ManifestAck{ManifestAck: &secflowv1.ManifestAck{Accepted: false, RejectionCode: secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED, RejectionReason: "scanner deny-list"}}})
				return status.Error(codes.FailedPrecondition, "denylist")
			}
			now := timestamppb.Now()
			link = &workerLink{send: stream.Send, instanceID: p.RegisterManifest.GetWorkerInstanceId()}
			s.plugMu.Lock()
			for _, m := range p.RegisterManifest.GetManifests() {
				pid := m.GetPluginId()
				merged := mergePluginManifest(s.plugins[pid], m)
				prevCount := s.activeWorkerCountLocked(pid)
				s.plugins[pid] = merged
				s.workers[pid] = append(s.workers[pid], link)
				s.setActiveWorkers(pid, s.activeWorkerCountLocked(pid))
				link.plugins = append(link.plugins, pid)
				if s.pluginRegisteredAt[pid] == nil {
					s.pluginRegisteredAt[pid] = now
				}
				s.pluginLastSeen[pid] = now
				evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED
				if prevCount > 0 {
					evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
				}
				s.fanoutPlugin(pluginEvent(evType, s.registeredPluginLocked(merged, 0)))
			}
			s.plugMu.Unlock()
			if err := link.Send(&secflowv1.ConnectResponse{Payload: &secflowv1.ConnectResponse_ManifestAck{ManifestAck: &secflowv1.ManifestAck{Accepted: true, HeartbeatIntervalSeconds: 10, DefaultLeaseSeconds: 30}}}); err != nil {
				return err
			}

		case *secflowv1.ConnectRequest_Heartbeat:
			if link != nil {
				now := timestamppb.Now()
				s.plugMu.Lock()
				for _, pid := range link.plugins {
					s.pluginLastSeen[pid] = now
				}
				s.plugMu.Unlock()
				activeIDs := p.Heartbeat.GetActiveNodeRunIds()
				s.renewTaskLeases(stream.Context(), activeIDs)
				var expired []string
				if len(activeIDs) > 0 {
					s.runMu.Lock()
					for _, nrID := range activeIDs {
						if _, ok := s.activeTasks[nrID]; !ok {
							expired = append(expired, nrID)
						}
					}
					s.runMu.Unlock()
				}
				if err := link.Send(&secflowv1.ConnectResponse{Payload: &secflowv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &secflowv1.HeartbeatAck{ServerTime: now, ExpiredNodeRunIds: expired}}}); err != nil {
					return err
				}
			}

		case *secflowv1.ConnectRequest_TaskProgress:
			if p.TaskProgress != nil {
				s.handleTaskProgress(stream.Context(), p.TaskProgress)
			}

		case *secflowv1.ConnectRequest_Drain:
			if link != nil {
				link.draining.Store(true)
				s.plugMu.Lock()
				for _, plugID := range link.plugins {
					s.setActiveWorkers(plugID, s.activeWorkerCountLocked(plugID))
					if m := s.plugins[plugID]; m != nil {
						rp := s.registeredPluginLocked(m, 0)
						evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
						if rp.GetStatus() == secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE {
							evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE
						}
						s.fanoutPlugin(pluginEvent(evType, rp))
					}
				}
				s.plugMu.Unlock()
			}

		case *secflowv1.ConnectRequest_CompleteTask:
			s.deliver(p.CompleteTask)
		default:
		}
	}
}

func (s *Server) renewTaskLeases(ctx context.Context, nodeRunIDs []string) {
	if s.pool == nil || len(nodeRunIDs) == 0 {
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(dbCtx, `
		UPDATE node_tasks
		SET lease_until = now() + interval '30 seconds'
		WHERE node_run_id = ANY($1) AND status = 'RUNNING'`, nodeRunIDs); err != nil {
		slog.Warn("renew task leases", "err", err)
	}
}

func (s *Server) handleTaskProgress(ctx context.Context, prog *secflowv1.WorkerTaskProgress) {
	nrID := prog.GetNodeRunId()
	if nrID == "" {
		return
	}
	s.runMu.Lock()
	at, ok := s.activeTasks[nrID]
	var st *runState
	if ok {
		st = s.runs[at.runID]
	}
	s.runMu.Unlock()
	if !ok || st == nil {
		return
	}
	preview, _ := json.Marshal(map[string]any{
		"percent":       prog.GetPercent(),
		"statusMessage": prog.GetStatusMessage(),
	})
	s.pushNodeEvent(
		ctx,
		st,
		at.nodeID,
		nrID,
		secflowv1.NodeRunStatus_NODE_RUN_STATUS_RUNNING,
		secflowv1.RunStatus_RUN_STATUS_RUNNING,
		prog.GetStatusMessage(),
		preview,
	)
}

func (s *Server) failWorkerTasks(link *workerLink, errCode, errMsg string) {
	if link == nil {
		return
	}
	type pending struct {
		nrID string
		task activeTask
		ch   chan *secflowv1.NodeResult
	}
	var aborted []pending
	s.runMu.Lock()
	for nrID, at := range s.activeTasks {
		if at.worker != link {
			continue
		}
		delete(s.activeTasks, nrID)
		ch := s.results[nrID]
		delete(s.results, nrID)
		aborted = append(aborted, pending{nrID: nrID, task: at, ch: ch})
	}
	s.runMu.Unlock()
	for _, item := range aborted {
		if item.ch != nil {
			select {
			case item.ch <- &secflowv1.NodeResult{
				NodeRunId:    item.nrID,
				RunId:        item.task.runID,
				NodeId:       item.task.nodeID,
				PluginId:     item.task.pluginID,
				Status:       secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
				ErrorCode:    errCode,
				ErrorMessage: errMsg,
			}:
			default:
			}
		}
	}
}

func (s *Server) deliver(res *secflowv1.NodeResult) {
	if res == nil {
		return
	}
	s.runMu.Lock()
	ch := s.results[res.GetNodeRunId()]
	delete(s.results, res.GetNodeRunId())
	delete(s.activeTasks, res.GetNodeRunId())
	s.runMu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
		}
	}
}

func (s *Server) hasWorker(plugin string) bool {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	return s.activeWorkerCountLocked(plugin) > 0
}

func (s *Server) pickWorker(plugin string) *workerLink {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	list := s.workers[plugin]
	if len(list) == 0 {
		return nil
	}
	eligible := make([]*workerLink, 0, len(list))
	for _, w := range list {
		if w != nil && !w.draining.Load() {
			eligible = append(eligible, w)
		}
	}
	if len(eligible) == 0 {
		return nil
	}
	idx := s.workerRR[plugin] % uint64(len(eligible))
	s.workerRR[plugin]++
	return eligible[idx]
}

func (s *Server) cleanupActiveTask(nodeRun string) {
	s.runMu.Lock()
	delete(s.results, nodeRun)
	delete(s.activeTasks, nodeRun)
	s.runMu.Unlock()
}

func (s *Server) dispatchWorkerTask(ctx context.Context, plugin string, task *secflowv1.NodeTask) (*secflowv1.NodeResult, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	w := s.pickWorker(plugin)
	if w == nil {
		return nil, false
	}
	if task == nil {
		task = &secflowv1.NodeTask{}
	}
	nodeRun := task.GetNodeRunId()
	if nodeRun == "" {
		if task.GetRunId() != "" && task.GetNodeId() != "" {
			nodeRun = task.GetRunId() + ":" + task.GetNodeId()
		} else {
			nodeRun = id("nr")
		}
		task.NodeRunId = nodeRun
	}
	if task.GetPluginId() == "" {
		task.PluginId = plugin
	}
	if task.GetLeaseSeconds() <= 0 {
		task.LeaseSeconds = 30
	}
	timeout := defaultWorkerHardTimeout
	if task.GetHardTimeoutSeconds() > 0 {
		timeout = time.Duration(task.GetHardTimeoutSeconds()) * time.Second
	} else {
		task.HardTimeoutSeconds = int64(timeout / time.Second)
	}
	ch := make(chan *secflowv1.NodeResult, 1)
	s.runMu.Lock()
	s.results[nodeRun] = ch
	s.activeTasks[nodeRun] = activeTask{runID: task.GetRunId(), nodeID: task.GetNodeId(), pluginID: plugin, worker: w}
	s.runMu.Unlock()
	if err := w.Send(&secflowv1.ConnectResponse{Payload: &secflowv1.ConnectResponse_DispatchTask{DispatchTask: task}}); err != nil {
		s.cleanupActiveTask(nodeRun)
		return nil, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res, true
	case <-ctx.Done():
		s.cleanupActiveTask(nodeRun)
		_ = w.Send(&secflowv1.ConnectResponse{
			Payload: &secflowv1.ConnectResponse_CancelTask{
				CancelTask: &secflowv1.CancelTask{
					NodeRunId: nodeRun,
					Reason:    "context cancelled",
				},
			},
		})
		return &secflowv1.NodeResult{
			NodeRunId:    nodeRun,
			RunId:        task.GetRunId(),
			NodeId:       task.GetNodeId(),
			PluginId:     plugin,
			Status:       secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			ErrorCode:    "TASK_CANCELLED",
			ErrorMessage: "task cancelled: " + ctx.Err().Error(),
		}, true
	case <-timer.C:
		s.cleanupActiveTask(nodeRun)
		_ = w.Send(&secflowv1.ConnectResponse{
			Payload: &secflowv1.ConnectResponse_CancelTask{
				CancelTask: &secflowv1.CancelTask{
					NodeRunId: nodeRun,
					Reason:    "WORKER_TIMEOUT",
				},
			},
		})
		return &secflowv1.NodeResult{
			NodeRunId:    nodeRun,
			RunId:        task.GetRunId(),
			NodeId:       task.GetNodeId(),
			PluginId:     plugin,
			Status:       secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			ErrorCode:    "WORKER_TIMEOUT",
			ErrorMessage: "WORKER_TIMEOUT: task timed out waiting for worker",
		}, true
	}
}

func (s *Server) callWorker(ctx context.Context, plugin string, n engine.Node, in engine.Envelope) (engine.Result, bool) {
	if !s.hasWorker(plugin) {
		return engine.Result{}, false
	}
	runID := in.RunID
	if runID == "" && in.Vars != nil {
		runID = in.Vars["runId"]
	}
	nodeRun := ""
	if in.Vars != nil {
		nodeRun = in.Vars["_nodeRunId"]
	}
	if nodeRun == "" {
		if runID != "" && n.ID != "" {
			nodeRun = runID + ":" + n.ID
		} else {
			nodeRun = id("nr")
		}
	}
	if runID == "" {
		runID = "inline"
	}
	envJSON, _ := json.Marshal(in)
	paramsMap := n.Params
	if plugin == "mcp.tool" {
		clonedParams := make(map[string]any, len(n.Params)+1)
		maps.Copy(clonedParams, n.Params)
		clonedParams["outputVarKey"] = mcpOutputVarKey(n)
		paramsMap = clonedParams
	}
	params, _ := json.Marshal(paramsMap)
	var binds []*secflowv1.SecretBinding
	for key, ref := range n.Secrets {
		binds = append(binds, &secflowv1.SecretBinding{ParamKey: key, SecretRef: ref})
	}
	hardTimeout := workerHardTimeoutFor(plugin)
	task := &secflowv1.NodeTask{
		RunId:              runID,
		NodeRunId:          nodeRun,
		NodeId:             n.ID,
		PluginId:           plugin,
		ParamsJson:         params,
		EnvelopeJson:       envJSON,
		SecretBindings:     binds,
		Traceparent:        in.Vars["traceparent"],
		Attempt:            1,
		LeaseSeconds:       30,
		HardTimeoutSeconds: int64(hardTimeout / time.Second),
	}
	if !strings.HasPrefix(plugin, "scan.") && plugin != "sbom.generate" {
		if tok, err := lease.Sign(s.leaseKey, task.GetRunId(), nodeRun, n.ID, plugin, hardTimeout+time.Minute); err == nil {
			task.TaskLeaseToken = tok
		}
	}
	res, ok := s.dispatchWorkerTask(ctx, plugin, task)
	if !ok {
		return engine.Result{}, false
	}
	if res.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_CANCELLED {
		return engine.Result{Status: "FAILED", Err: "task cancelled"}, true
	}
	return workerResult(n, in, res), true
}
