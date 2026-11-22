package main

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/lease"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/urlguard"
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

func (s *Server) setPluginEnabled(pluginID string, enabled bool) {
	s.plugMu.Lock()
	if enabled {
		delete(s.pluginDisabled, pluginID)
	} else {
		s.pluginDisabled[pluginID] = true
	}
	if m := s.plugins[pluginID]; m != nil {
		rp := s.registeredPluginLocked(m, 0)
		evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
		if !enabled {
			evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE
		}
		s.fanoutPlugin(pluginEvent(evType, rp))
	}
	s.plugMu.Unlock()
}

func (s *Server) pluginManifestSnapshot(pluginID string) *secflowv1.PluginManifest {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	return clonePluginManifest(s.plugins[pluginID])
}

func (s *Server) pluginRequiredSecretKeys(pluginID string) []string {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	if m := s.plugins[pluginID]; m != nil {
		return slices.Clone(m.GetRequiredSecretKeys())
	}
	return nil
}

func (s *Server) pluginCategory(pluginID string) secflowv1.PluginCategory {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	if m := s.plugins[pluginID]; m != nil {
		return m.GetCategory()
	}
	return secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED
}

func (s *Server) isAnalyzerPlugin(pluginID string) bool {
	if pluginID == "sbom.generate" {
		return false
	}
	if cat := s.pluginCategory(pluginID); cat != secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED {
		return cat == secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER
	}
	return engine.IsAnalyzer(pluginID)
}

func (s *Server) pluginRegistrySnapshot() (map[string]*secflowv1.PluginManifest, map[string]bool) {
	s.plugMu.Lock()
	plugins := make(map[string]*secflowv1.PluginManifest, len(s.plugins))
	for pid, m := range s.plugins {
		plugins[pid] = m
	}
	disabled := make(map[string]bool, len(s.pluginDisabled))
	maps.Copy(disabled, s.pluginDisabled)
	s.plugMu.Unlock()
	return plugins, disabled
}

func pluginLookupFromSnapshot(plugins map[string]*secflowv1.PluginManifest, disabled map[string]bool) engine.PluginLookup {
	snapshot := make(map[string]engine.PluginMeta, len(plugins))
	for pid, m := range plugins {
		ports := make([]string, 0, len(m.GetOutputPorts()))
		for _, p := range m.GetOutputPorts() {
			if portID := strings.TrimSpace(p.GetId()); portID != "" {
				ports = append(ports, portID)
			}
		}
		cat := strings.TrimPrefix(m.GetCategory().String(), "PLUGIN_CATEGORY_")
		if cat == "UNSPECIFIED" {
			cat = ""
		}
		snapshot[pid] = engine.PluginMeta{
			PluginID:           pid,
			Category:           cat,
			OutputPorts:        ports,
			RequiredSecretKeys: slices.Clone(m.GetRequiredSecretKeys()),
			Enabled:            !disabled[pid],
			Registered:         true,
		}
	}
	return func(pluginID string) (engine.PluginMeta, bool) {
		meta, ok := snapshot[pluginID]
		return meta, ok
	}
}

func (s *Server) registeredPluginLocked(m *secflowv1.PluginManifest, queueDepth int64) *secflowv1.RegisteredPlugin {
	pid := m.GetPluginId()
	active := s.activeWorkerCountLocked(pid)
	disabled := s.pluginDisabled[pid]
	st := secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE
	if disabled {
		st = secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE
		active = 0
	} else if m.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN || isOrchestratorManagedSourcePlugin(pid) {
		st = secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE
		if active == 0 {
			active = 1
		}
	} else if active > 0 {
		st = secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE
	} else if s.pool != nil && s.pluginDBWorkers[pid] > 0 {
		active = s.pluginDBWorkers[pid]
		st = secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE
	}
	return &secflowv1.RegisteredPlugin{
		Manifest:        clonePluginManifest(m),
		Status:          st,
		ActiveWorkers:   active,
		QueueDepth:      queueDepth,
		RegisteredAt:    s.pluginRegisteredAt[pid],
		LastSeenAt:      s.pluginLastSeen[pid],
		InstallationId:  s.pluginInstallation[pluginOwnerKey(pid)],
		Enabled:         !disabled,
		ApprovalPending: s.pluginApprovalState[pid] == approvalStatePending,
	}
}

func (s *Server) ListPlugins(ctx context.Context, req *secflowv1.ListPluginsRequest) (*secflowv1.ListPluginsResponse, error) {
	depths := s.queueDepths(ctx)
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	catFilter := req.GetCategory()
	includeDisabled := req.GetIncludeDisabled()
	items := make([]*secflowv1.RegisteredPlugin, 0, len(s.plugins))
	for pid, m := range s.plugins {
		if !includeDisabled && s.pluginDisabled[pid] {
			continue
		}
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
		var touched []string
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
			active := s.activeWorkerCountLocked(plugID)
			s.pluginDBWorkers[plugID] = active
			s.setActiveWorkers(plugID, active)
			if m := s.plugins[plugID]; m != nil {
				touched = append(touched, plugID)
				rp := s.registeredPluginLocked(m, 0)
				evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
				if rp.GetStatus() == secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE {
					evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE
				}
				s.fanoutPlugin(pluginEvent(evType, rp))
			}
		}
		s.plugMu.Unlock()
		for _, pid := range touched {
			s.persistPluginState(stream.Context(), pid)
		}

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
			var regErr error
			link, regErr = s.handleRegisterManifest(stream, p.RegisterManifest, link)
			if regErr != nil {
				return regErr
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
					active := s.activeWorkerCountLocked(plugID)
					s.pluginDBWorkers[plugID] = active
					s.setActiveWorkers(plugID, active)
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

func firstIncomingMeta(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

func sendManifestReject(stream secflowv1.WorkerService_ConnectServer, code secflowv1.ManifestRejectionCode, reason string) {
	_ = stream.Send(&secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_ManifestAck{
			ManifestAck: &secflowv1.ManifestAck{
				Accepted:        false,
				RejectionCode:   code,
				RejectionReason: reason,
			},
		},
	})
}

func (s *Server) handleRegisterManifest(stream secflowv1.WorkerService_ConnectServer, reg *secflowv1.WorkerRegisterManifest, prevLink *workerLink) (*workerLink, error) {
	md, _ := metadata.FromIncomingContext(stream.Context())
	declRuntime := strings.ToLower(firstIncomingMeta(md, "x-declarative-runtime"))
	pluginToken := firstIncomingMeta(md, "x-plugin-token")
	serviceToken := firstIncomingMeta(md, "x-service-token")

	if declRuntime != "" {
		return s.handleRegisterDeclarativeRuntime(stream, reg, prevLink, declRuntime, serviceToken)
	}

	manifests := reg.GetManifests()
	if len(manifests) == 0 {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_INVALID_SCHEMA, "at least one manifest is required")
		return nil, status.Error(codes.InvalidArgument, "at least one manifest is required")
	}

	instID, tokHash, authErr := s.authenticateWorkerHandshake(stream, manifests, pluginToken, serviceToken)
	if authErr != nil {
		return nil, authErr
	}
	if urlguard.Denied(reg.GetWorkerInstanceId() + " " + reg.GetNamespace()) {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED, "scanner deny-list")
		return nil, status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner reference")
	}
	for _, m := range manifests {
		if manifestDenied(m) {
			sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED, "scanner deny-list")
			return nil, status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner reference")
		}
	}

	if instID != "" {
		return s.registerExternalManifest(stream, reg, instID, tokHash)
	}
	return s.registerBuiltinManifest(stream, reg)
}

func (s *Server) handleRegisterDeclarativeRuntime(
	stream secflowv1.WorkerService_ConnectServer,
	reg *secflowv1.WorkerRegisterManifest,
	prevLink *workerLink,
	tier string,
	serviceToken string,
) (*workerLink, error) {
	var wantProfile secflowv1.SandboxProfile
	switch tier {
	case "internal":
		wantProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
	case "action":
		wantProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL
	default:
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH, "unknown declarative runtime tier")
		return nil, status.Errorf(codes.InvalidArgument, "unknown declarative runtime tier %q", tier)
	}
	if serviceToken != "" && !s.validServiceToken(serviceToken) {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "invalid x-service-token")
		return nil, status.Error(codes.Unauthenticated, "invalid x-service-token")
	}
	if serviceToken == "" && (os.Getenv("SECFLOW_ENV") == "production" || os.Getenv("REQUIRE_WORKER_SERVICE_TOKEN") == "1") {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "x-service-token required")
		return nil, status.Error(codes.Unauthenticated, "x-service-token required")
	}
	if urlguard.Denied(reg.GetWorkerInstanceId() + " " + reg.GetNamespace()) {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED, "scanner deny-list")
		return nil, status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner reference")
	}

	now := timestamppb.Now()
	link := prevLink
	if link == nil {
		link = &workerLink{send: stream.Send, instanceID: reg.GetWorkerInstanceId()}
	}
	if mc := manifestMaxConcurrency(reg.GetManifests()); mc > 0 {
		link.maxConcurrency.Store(mc)
	} else {
		link.maxConcurrency.Store(4)
	}

	var touched []string
	s.plugMu.Lock()
	// Detach previous plugin bindings for this live stream before attaching the refreshed set.
	oldPlugins := append([]string(nil), link.plugins...)
	for _, oldPID := range oldPlugins {
		list := s.workers[oldPID]
		kept := list[:0]
		for _, w := range list {
			if w != link {
				kept = append(kept, w)
			}
		}
		if len(kept) == 0 {
			delete(s.workers, oldPID)
		} else {
			s.workers[oldPID] = kept
		}
		active := s.activeWorkerCountLocked(oldPID)
		s.pluginDBWorkers[oldPID] = active
		s.setActiveWorkers(oldPID, active)
		touched = append(touched, oldPID)
	}
	link.plugins = nil

	for _, m := range reg.GetManifests() {
		pid := m.GetPluginId()
		if manifestDenied(m) {
			s.plugMu.Unlock()
			sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED, "scanner deny-list")
			return nil, status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner reference")
		}
		instID := s.pluginInstallation[pluginOwnerKey(pid)]
		rec := s.installations[instID]
		if rec == nil || rec.proto == nil ||
			rec.proto.GetSourceMode() != secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE ||
			rec.proto.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE ||
			rec.proto.GetSandboxProfile() != wantProfile {
			continue
		}
		merged := mergePluginManifest(s.plugins[pid], m)
		prevCount := s.activeWorkerCountLocked(pid)
		s.plugins[pid] = merged
		s.workers[pid] = append(s.workers[pid], link)
		s.notifyWorkerAvailableLocked(pid)
		active := s.activeWorkerCountLocked(pid)
		s.pluginDBWorkers[pid] = active
		s.setActiveWorkers(pid, active)
		link.plugins = append(link.plugins, pid)
		if s.pluginRegisteredAt[pid] == nil {
			s.pluginRegisteredAt[pid] = now
		}
		s.pluginLastSeen[pid] = now
		touched = append(touched, pid)
		evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED
		if prevCount > 0 {
			evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
		}
		s.fanoutPlugin(pluginEvent(evType, s.registeredPluginLocked(merged, 0)))
	}
	s.plugMu.Unlock()

	for _, pid := range touched {
		s.persistPluginState(stream.Context(), pid)
	}
	if err := link.Send(&secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_ManifestAck{
			ManifestAck: &secflowv1.ManifestAck{
				Accepted:                 true,
				HeartbeatIntervalSeconds: 10,
				DefaultLeaseSeconds:      30,
			},
		},
	}); err != nil {
		return nil, err
	}
	return link, nil
}

func (s *Server) authenticateWorkerHandshake(
	stream secflowv1.WorkerService_ConnectServer,
	manifests []*secflowv1.PluginManifest,
	pluginToken string,
	serviceToken string,
) (string, [32]byte, error) {
	var zero [32]byte
	hasExternal := false
	for _, m := range manifests {
		if m.GetIsExternal() {
			hasExternal = true
			break
		}
	}
	if pluginToken != "" {
		tokHash := hashPluginToken(pluginToken)
		s.plugMu.Lock()
		rec := s.findInstallationByTokenLocked(tokHash)
		var instID string
		if rec != nil && rec.proto != nil {
			instID = rec.proto.GetId()
		}
		s.plugMu.Unlock()
		if instID == "" && s.pool != nil {
			if pgRec := s.lookupInstallationByTokenInPG(stream.Context(), tokHash); pgRec != nil && pgRec.proto != nil {
				instID = pgRec.proto.GetId()
				s.plugMu.Lock()
				s.installations[instID] = pgRec
				s.plugMu.Unlock()
			}
		}
		if instID == "" {
			sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "invalid x-plugin-token")
			return "", zero, status.Error(codes.Unauthenticated, "invalid x-plugin-token")
		}
		return instID, tokHash, nil
	}
	if hasExternal {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "x-plugin-token required for external plugins")
		return "", zero, status.Error(codes.Unauthenticated, "x-plugin-token required for external plugins")
	}
	if serviceToken != "" && !s.validServiceToken(serviceToken) {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "invalid x-service-token")
		return "", zero, status.Error(codes.Unauthenticated, "invalid x-service-token")
	}
	if serviceToken == "" && (os.Getenv("SECFLOW_ENV") == "production" || os.Getenv("REQUIRE_WORKER_SERVICE_TOKEN") == "1") {
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "x-service-token required")
		return "", zero, status.Error(codes.Unauthenticated, "x-service-token required")
	}
	return "", zero, nil
}

func (s *Server) registerBuiltinManifest(stream secflowv1.WorkerService_ConnectServer, reg *secflowv1.WorkerRegisterManifest) (*workerLink, error) {
	for _, m := range reg.GetManifests() {
		pid := m.GetPluginId()
		if _, isBuiltin := manifest.LookupBuiltin(pid); !isBuiltin {
			sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "x-plugin-token required for non-builtin plugin")
			return nil, status.Errorf(codes.Unauthenticated, "x-plugin-token required for non-builtin plugin_id %q", pid)
		}
	}
	now := timestamppb.Now()
	link := &workerLink{send: stream.Send, instanceID: reg.GetWorkerInstanceId()}
	link.maxConcurrency.Store(manifestMaxConcurrency(reg.GetManifests()))
	var touched []string
	s.plugMu.Lock()
	for _, m := range reg.GetManifests() {
		pid := m.GetPluginId()
		merged := mergePluginManifest(s.plugins[pid], m)
		prevCount := s.activeWorkerCountLocked(pid)
		s.plugins[pid] = merged
		s.workers[pid] = append(s.workers[pid], link)
		s.notifyWorkerAvailableLocked(pid)
		active := s.activeWorkerCountLocked(pid)
		s.pluginDBWorkers[pid] = active
		s.setActiveWorkers(pid, active)
		link.plugins = append(link.plugins, pid)
		if s.pluginRegisteredAt[pid] == nil {
			s.pluginRegisteredAt[pid] = now
		}
		s.pluginLastSeen[pid] = now
		touched = append(touched, pid)
		evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED
		if prevCount > 0 {
			evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
		}
		s.fanoutPlugin(pluginEvent(evType, s.registeredPluginLocked(merged, 0)))
	}
	s.plugMu.Unlock()
	for _, pid := range touched {
		s.persistPluginState(stream.Context(), pid)
	}
	if err := link.Send(&secflowv1.ConnectResponse{Payload: &secflowv1.ConnectResponse_ManifestAck{ManifestAck: &secflowv1.ManifestAck{Accepted: true, HeartbeatIntervalSeconds: 10, DefaultLeaseSeconds: 30}}}); err != nil {
		return nil, err
	}
	return link, nil
}

func (s *Server) registerExternalManifest(
	stream secflowv1.WorkerService_ConnectServer,
	reg *secflowv1.WorkerRegisterManifest,
	instID string,
	tokHash [32]byte,
) (*workerLink, error) {
	manifests := clonePluginManifests(reg.GetManifests())
	for _, m := range manifests {
		m.IsExternal = true
	}

	s.plugMu.Lock()
	rec := s.installations[instID]
	if rec == nil || rec.proto == nil || !rec.hasToken || !hmac.Equal(rec.tokenHash[:], tokHash[:]) {
		s.plugMu.Unlock()
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "installation token no longer valid")
		return nil, status.Error(codes.Unauthenticated, "installation token no longer valid")
	}
	inst := rec.proto
	if rejCode, valErr := validateExternalManifests(manifests, inst.GetSandboxProfile()); valErr != nil {
		s.plugMu.Unlock()
		sendManifestReject(stream, rejCode, valErr.Error())
		return nil, valErr
	}
	for _, m := range manifests {
		if owner := s.pluginInstallation[pluginOwnerKey(m.GetPluginId())]; owner != "" && owner != instID {
			s.plugMu.Unlock()
			reason := "plugin_id " + m.GetPluginId() + " already registered by another installation"
			sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DUPLICATE_PLUGIN_ID, reason)
			return nil, status.Error(codes.AlreadyExists, reason)
		}
	}

	now := timestamppb.Now()
	switch inst.GetStatus() {
	case secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE:
	case secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DELETING:
		s.plugMu.Unlock()
		sendManifestReject(stream, secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED, "installation is deleting")
		return nil, status.Error(codes.FailedPrecondition, "installation is deleting")

	case secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DISABLED:
		s.plugMu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "installation disabled")

	case secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING,
		secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL,
		secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ERROR:
		inst.PendingManifests = manifests
		if inst.GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING {
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
		}
		inst.UpdatedAt = now
		s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_UPDATED, inst)
		s.plugMu.Unlock()
		s.persistInstallationAndPlugins(stream.Context(), rec, "UPDATED", false)
		return nil, status.Error(codes.FailedPrecondition, "PENDING_APPROVAL: awaiting owner approval")

	case secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_UNSPECIFIED:
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition, "INVALID_STATE_TRANSITION: unsupported installation status %s", inst.GetStatus().String())

	default:
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition, "INVALID_STATE_TRANSITION: unsupported installation status %s", inst.GetStatus().String())
	}

	if inst.GetApprovedManifestDigest() != "" && detectManifestEscalation(rec.approvedManifests, manifests) {
		inst.PendingManifests = manifests
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
		inst.StatusReason = "manifest privilege escalation requires re-approval"
		inst.ApprovedManifestDigest = ""
		inst.ApprovedBy = ""
		inst.ApprovedAt = nil
		rec.approvedManifests = nil
		inst.UpdatedAt = now
		pluginEvents := s.setInstallationPluginsEnabledLocked(instID, false, approvalStatePending)
		linksToDrain := s.markInstallationLinksDrainingLocked(instID)
		s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_STATUS_CHANGED, inst)
		for _, pev := range pluginEvents {
			s.fanoutPlugin(pev)
		}
		s.plugMu.Unlock()
		s.drainWorkerLinks(linksToDrain, "manifest privilege escalation requires re-approval", defaultDrainGraceSec)
		s.persistInstallationAndPlugins(stream.Context(), rec, "STATUS_CHANGED", true)
		return nil, status.Error(codes.FailedPrecondition, "PENDING_APPROVAL: privilege escalation requires re-approval")
	}

	link := &workerLink{send: stream.Send, instanceID: reg.GetWorkerInstanceId(), installationID: instID}
	link.maxConcurrency.Store(manifestMaxConcurrency(manifests))
	inst.Manifests = clonePluginManifests(manifests)
	inst.PluginIds = manifestPluginIDs(manifests)
	if inst.GetApprovedManifestDigest() == "" {
		inst.ApprovedManifestDigest = computeManifestDigest(manifests)
		rec.approvedManifests = clonePluginManifests(manifests)
	}
	inst.UpdatedAt = now

	keep := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		keep[m.GetPluginId()] = true
	}
	pluginEvents := s.pruneStaleInstallationPluginsLocked(instID, keep)
	for _, m := range manifests {
		pid := m.GetPluginId()
		merged := mergePluginManifest(s.plugins[pid], m)
		prevCount := s.activeWorkerCountLocked(pid)
		_, existed := s.plugins[pid]
		s.plugins[pid] = merged
		s.pluginInstallation[pluginOwnerKey(pid)] = instID
		s.pluginApprovalState[pid] = approvalStateApproved
		delete(s.pluginDisabled, pid)
		s.workers[pid] = append(s.workers[pid], link)
		s.notifyWorkerAvailableLocked(pid)
		active := s.activeWorkerCountLocked(pid)
		s.pluginDBWorkers[pid] = active
		s.setActiveWorkers(pid, active)
		link.plugins = append(link.plugins, pid)
		if s.pluginRegisteredAt[pid] == nil {
			s.pluginRegisteredAt[pid] = now
		}
		s.pluginLastSeen[pid] = now
		evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED
		if existed || prevCount > 0 {
			evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
		}
		pluginEvents = append(pluginEvents, pluginEvent(evType, s.registeredPluginLocked(merged, 0)))
	}
	s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_UPDATED, inst)
	for _, pev := range pluginEvents {
		s.fanoutPlugin(pev)
	}
	s.plugMu.Unlock()

	s.persistInstallationAndPlugins(stream.Context(), rec, "UPDATED", true)
	if err := link.Send(&secflowv1.ConnectResponse{Payload: &secflowv1.ConnectResponse_ManifestAck{ManifestAck: &secflowv1.ManifestAck{Accepted: true, HeartbeatIntervalSeconds: 10, DefaultLeaseSeconds: 30}}}); err != nil {
		return nil, err
	}
	return link, nil
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

func manifestMaxConcurrency(manifests []*secflowv1.PluginManifest) int32 {
	var total int32
	for _, m := range manifests {
		if m != nil && m.GetMaxConcurrency() > 0 {
			total += m.GetMaxConcurrency()
		}
	}
	if total <= 0 {
		return 4
	}
	return total
}

func (w *workerLink) capacity() int32 {
	if w == nil {
		return 0
	}
	if c := w.maxConcurrency.Load(); c > 0 {
		return c
	}
	return 4
}

// notifyWorkerAvailableLocked wakes any goroutines waiting for a worker or freed slot on pluginID.
// Caller holds s.plugMu.
func (s *Server) notifyWorkerAvailableLocked(pluginID string) {
	waiters := s.workerWaiters[pluginID]
	if len(waiters) == 0 {
		return
	}
	delete(s.workerWaiters, pluginID)
	for _, ch := range waiters {
		close(ch)
	}
}

func (s *Server) notifyWorkerAvailable(pluginID string) {
	s.plugMu.Lock()
	s.notifyWorkerAvailableLocked(pluginID)
	s.plugMu.Unlock()
}

func (s *Server) activeWorkerCount(plugin string) int32 {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	return s.activeWorkerCountLocked(plugin)
}

func (s *Server) hasWorker(plugin string) bool {
	return s.activeWorkerCount(plugin) > 0
}

// allWorkersBusy reports whether every non-draining worker connected for plugin is at or above
// perWorkerThreshold in-flight tasks (or its declared capacity when perWorkerThreshold <= 0).
func (s *Server) allWorkersBusy(plugin string, perWorkerThreshold int32) bool {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	return s.allWorkersBusyLocked(plugin, perWorkerThreshold)
}

func (s *Server) allWorkersBusyLocked(plugin string, perWorkerThreshold int32) bool {
	var found bool
	for _, w := range s.workers[plugin] {
		if w == nil || w.draining.Load() {
			continue
		}
		found = true
		limit := w.capacity()
		if perWorkerThreshold > 0 && perWorkerThreshold < limit {
			limit = perWorkerThreshold
		}
		if w.inFlight.Load() < limit {
			return false
		}
	}
	return found
}

// waitForWorker blocks until a non-draining worker for plugin connects (and, when
// perWorkerThreshold > 0, at least one worker has inFlight < threshold), or until timeout / ctx cancellation.
func (s *Server) waitForWorker(ctx context.Context, plugin string, timeout time.Duration, perWorkerThreshold int32) bool {
	if timeout <= 0 {
		return s.hasWorker(plugin)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		s.plugMu.Lock()
		active := s.activeWorkerCountLocked(plugin)
		ready := active > 0 && (perWorkerThreshold <= 0 || !s.allWorkersBusyLocked(plugin, perWorkerThreshold))
		if ready {
			s.plugMu.Unlock()
			return true
		}
		ch := make(chan struct{})
		s.workerWaiters[plugin] = append(s.workerWaiters[plugin], ch)
		s.plugMu.Unlock()

		select {
		case <-ch:
		case <-ctx.Done():
			s.removeWorkerWaiter(plugin, ch)
			return false
		case <-timer.C:
			s.removeWorkerWaiter(plugin, ch)
			return s.hasWorker(plugin)
		}
	}
}

func (s *Server) removeWorkerWaiter(plugin string, target chan struct{}) {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	list := s.workerWaiters[plugin]
	if len(list) == 0 {
		return
	}
	kept := list[:0]
	for _, ch := range list {
		if ch != target {
			kept = append(kept, ch)
		}
	}
	if len(kept) == 0 {
		delete(s.workerWaiters, plugin)
	} else {
		s.workerWaiters[plugin] = kept
	}
}

// acquireWorker selects the least-loaded eligible non-draining worker for plugin and
// atomically reserves an in-flight slot under s.plugMu to eliminate TOCTOU races when
// concurrent tasks wake up as newly scaled workers connect.
// When maxPerWorker > 0, workers with inFlight >= maxPerWorker are skipped and (nil, false)
// is returned so the caller can wait for newly scaled replicas or a freed slot.
func (s *Server) acquireWorker(plugin string, maxPerWorker int32) (*workerLink, bool) {
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	list := s.workers[plugin]
	if len(list) == 0 {
		return nil, false
	}
	eligible := make([]*workerLink, 0, len(list))
	for _, w := range list {
		if w != nil && !w.draining.Load() {
			eligible = append(eligible, w)
		}
	}
	if len(eligible) == 0 {
		return nil, false
	}
	start := int(s.workerRR[plugin] % uint64(len(eligible)))
	s.workerRR[plugin]++

	var best *workerLink
	var bestLoad int32
	bestHasCapacity := false
	for offset := range len(eligible) {
		cand := eligible[(start+offset)%len(eligible)]
		load := cand.inFlight.Load()
		limit := cand.capacity()
		if maxPerWorker > 0 && maxPerWorker < limit {
			limit = maxPerWorker
		}
		if maxPerWorker > 0 && load >= limit {
			continue
		}
		hasCap := load < limit
		if best == nil ||
			(hasCap && !bestHasCapacity) ||
			(hasCap == bestHasCapacity && load < bestLoad) {
			best = cand
			bestLoad = load
			bestHasCapacity = hasCap
		}
	}
	if best == nil {
		return nil, false
	}
	best.inFlight.Add(1)
	return best, true
}

func (s *Server) pickWorker(plugin string) *workerLink {
	w, _ := s.acquireWorker(plugin, 0)
	if w != nil {
		w.inFlight.Add(-1)
	}
	return w
}

func (s *Server) cleanupActiveTask(nodeRun string) {
	s.runMu.Lock()
	delete(s.results, nodeRun)
	delete(s.activeTasks, nodeRun)
	s.runMu.Unlock()
}

func (s *Server) dispatchWorkerTask(ctx context.Context, plugin string, task *secflowv1.NodeTask) (*secflowv1.NodeResult, bool) {
	w, ok := s.acquireWorker(plugin, 0)
	if !ok {
		return nil, false
	}
	return s.dispatchToWorker(ctx, plugin, task, w)
}

func (s *Server) dispatchToWorker(ctx context.Context, plugin string, task *secflowv1.NodeTask, w *workerLink) (*secflowv1.NodeResult, bool) {
	if w == nil {
		return nil, false
	}
	defer func() {
		w.inFlight.Add(-1)
		s.notifyWorkerAvailable(plugin)
	}()
	if ctx == nil {
		ctx = context.Background()
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

func (s *Server) acquireWorkerWithScaling(ctx context.Context, plugin string) (*workerLink, bool) {
	if s.workerScaler == nil || !s.workerScaler.Handles(plugin) {
		return s.acquireWorker(plugin, 0)
	}
	pool, _ := s.workerScaler.PoolForPlugin(plugin)
	threshold := pool.tasksPerWorker()
	demand := s.poolDemandForPlugin(ctx, plugin)
	desired, err := s.workerScaler.EnsureCapacity(ctx, plugin, demand)
	if err != nil {
		slog.WarnContext(ctx, "worker scaler ensure capacity failed", "plugin_id", plugin, "demand", demand, "err", err)
	}

	if w, ok := s.acquireWorker(plugin, threshold); ok {
		return w, true
	}

	waitTimeout := s.workerScaler.ScaleWaitTimeout()
	if s.activeWorkerCount(plugin) == 0 {
		waitTimeout = s.workerScaler.ProvisionTimeout()
	} else if desired <= s.activeWorkerCount(plugin) {
		// Pool is already at desired/max replicas; dispatch immediately to least-loaded worker.
		return s.acquireWorker(plugin, 0)
	}

	deadline := time.Now().Add(waitTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if !s.waitForWorker(ctx, plugin, remaining, threshold) {
			break
		}
		if w, ok := s.acquireWorker(plugin, threshold); ok {
			return w, true
		}
		if ctx.Err() != nil {
			return nil, false
		}
	}
	return s.acquireWorker(plugin, 0)
}

func (s *Server) callWorker(ctx context.Context, plugin string, n engine.Node, in engine.Envelope) (engine.Result, bool) {
	w, ok := s.acquireWorkerWithScaling(ctx, plugin)
	if !ok {
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
	plugManifest := s.pluginManifestSnapshot(plugin)
	if s.mayIssueTaskLease(plugin, plugManifest) {
		if tok, err := lease.Sign(s.leaseKey, task.GetRunId(), nodeRun, n.ID, plugin, hardTimeout+time.Minute); err == nil {
			task.TaskLeaseToken = tok
		}
	}
	res, ok := s.dispatchToWorker(ctx, plugin, task, w)
	if !ok {
		return engine.Result{}, false
	}
	if res.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_CANCELLED {
		return engine.Result{Status: "FAILED", Err: "task cancelled"}, true
	}
	return workerResult(n, in, res, plugManifest), true
}
