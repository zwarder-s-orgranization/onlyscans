package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/declarativeplugin"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/manifest"
)

func requireEditorOrOwnerActor(actor *secflowv1.ActorContext) error {
	if actor == nil {
		return status.Error(codes.PermissionDenied, "FORBIDDEN: editor or owner role required")
	}
	if actor.GetAuthMode() == secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN {
		return status.Error(codes.PermissionDenied, "FORBIDDEN: scoped tokens cannot manage plugins or saved nodes")
	}
	switch actor.GetRole() {
	case secflowv1.Role_ROLE_EDITOR, secflowv1.Role_ROLE_OWNER:
		return nil
	default:
		return status.Error(codes.PermissionDenied, "FORBIDDEN: editor or owner role required")
	}
}

func isOwnerActor(actor *secflowv1.ActorContext) bool {
	return actor != nil &&
		actor.GetAuthMode() != secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN &&
		actor.GetRole() == secflowv1.Role_ROLE_OWNER
}

// TestDeclarativePlugin runs the shared pure-Go declarative evaluator synchronously in memory
// (2s timeout, <= 5 files, <= 256 KB, zero S3/network/secret access).
func (s *Server) TestDeclarativePlugin(ctx context.Context, req *secflowv1.TestDeclarativePluginRequest) (*secflowv1.TestDeclarativePluginResponse, error) {
	if err := requireEditorOrOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	start := time.Now()

	spec, err := declarativeplugin.ValidateSpec(req.GetDeclarativeSpecJson())
	if err != nil {
		return &secflowv1.TestDeclarativePluginResponse{
			Ok:               false,
			ValidationErrors: []string{err.Error()},
			DurationMs:       time.Since(start).Milliseconds(),
			Summary:          "Specification validation failed",
		}, nil
	}

	params := map[string]any{}
	if len(req.GetParamsJson()) > 0 {
		if err := json.Unmarshal(req.GetParamsJson(), &params); err != nil {
			return &secflowv1.TestDeclarativePluginResponse{
				Ok:               false,
				ValidationErrors: []string{"invalid params JSON: " + err.Error()},
				DurationMs:       time.Since(start).Milliseconds(),
				Summary:          "Invalid test parameters",
			}, nil
		}
	}

	evalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	switch spec.Category {
	case declarativeplugin.CategoryAnalyzer:
		inFiles := req.GetFiles()
		if len(inFiles) > declarativeplugin.MaxTestBenchFiles {
			return &secflowv1.TestDeclarativePluginResponse{
				Ok:               false,
				ValidationErrors: []string{fmt.Sprintf("fixture exceeds %d files limit", declarativeplugin.MaxTestBenchFiles)},
				DurationMs:       time.Since(start).Milliseconds(),
			}, nil
		}
		totalBytes := 0
		files := make([]declarativeplugin.VirtualFile, 0, len(inFiles))
		for _, f := range inFiles {
			totalBytes += len(f.GetPath()) + len(f.GetContent())
			if totalBytes > declarativeplugin.MaxTestBenchBytes {
				return &secflowv1.TestDeclarativePluginResponse{
					Ok:               false,
					ValidationErrors: []string{fmt.Sprintf("fixture exceeds %d bytes limit", declarativeplugin.MaxTestBenchBytes)},
					DurationMs:       time.Since(start).Milliseconds(),
				}, nil
			}
			files = append(files, declarativeplugin.VirtualFile{Path: f.GetPath(), Content: f.GetContent()})
		}
		findings, evalErr := declarativeplugin.EvaluateAnalyzer(evalCtx, spec, params, files, "test_bench")
		if evalErr != nil {
			return &secflowv1.TestDeclarativePluginResponse{
				Ok:               false,
				ValidationErrors: []string{evalErr.Error()},
				DurationMs:       time.Since(start).Milliseconds(),
			}, nil
		}
		return &secflowv1.TestDeclarativePluginResponse{
			Ok:                true,
			Findings:          findings,
			ActiveOutputPorts: []string{"default"},
			DurationMs:        time.Since(start).Milliseconds(),
			Summary:           fmt.Sprintf("Analyzer completed: %d finding(s) across %d file(s)", len(findings), len(files)),
		}, nil

	case declarativeplugin.CategoryLogic:
		var env engine.Envelope
		if len(req.GetEnvelopeJson()) > 0 {
			if len(req.GetEnvelopeJson()) > declarativeplugin.MaxTestBenchBytes {
				return &secflowv1.TestDeclarativePluginResponse{
					Ok:               false,
					ValidationErrors: []string{fmt.Sprintf("envelope fixture exceeds %d bytes limit", declarativeplugin.MaxTestBenchBytes)},
					DurationMs:       time.Since(start).Milliseconds(),
				}, nil
			}
			if err := json.Unmarshal(req.GetEnvelopeJson(), &env); err != nil {
				return &secflowv1.TestDeclarativePluginResponse{
					Ok:               false,
					ValidationErrors: []string{"invalid envelope JSON: " + err.Error()},
					DurationMs:       time.Since(start).Milliseconds(),
				}, nil
			}
		}
		res, evalErr := declarativeplugin.EvaluateLogic(spec, params, env)
		if evalErr != nil {
			return &secflowv1.TestDeclarativePluginResponse{
				Ok:               false,
				ValidationErrors: []string{evalErr.Error()},
				DurationMs:       time.Since(start).Milliseconds(),
			}, nil
		}
		patchBytes, patchErr := res.EnvelopePatchJSON()
		if patchErr != nil {
			return nil, status.Errorf(codes.Internal, "marshal logic envelope patch: %v", patchErr)
		}
		return &secflowv1.TestDeclarativePluginResponse{
			Ok:                true,
			ActiveOutputPorts: res.ActivePorts,
			EnvelopePatchJson: patchBytes,
			DurationMs:        time.Since(start).Milliseconds(),
			Summary:           fmt.Sprintf("Routed to port %s (route: %s)", strings.Join(res.ActivePorts, ","), res.MatchedRoute),
		}, nil

	case declarativeplugin.CategoryAction:
		var env engine.Envelope
		if len(req.GetEnvelopeJson()) > 0 {
			if err := json.Unmarshal(req.GetEnvelopeJson(), &env); err != nil {
				return &secflowv1.TestDeclarativePluginResponse{
					Ok:               false,
					ValidationErrors: []string{"invalid envelope JSON: " + err.Error()},
					DurationMs:       time.Since(start).Milliseconds(),
				}, nil
			}
		}
		allowDevHTTP := os.Getenv("SECFLOW_ENV") != "production" && os.Getenv("ALLOW_DEV_EGRESS_LOCAL") == "1"
		preview, evalErr := declarativeplugin.DryRunAction(evalCtx, spec, params, env, allowDevHTTP)
		if evalErr != nil {
			return &secflowv1.TestDeclarativePluginResponse{
				Ok:               false,
				ValidationErrors: []string{evalErr.Error()},
				DurationMs:       time.Since(start).Milliseconds(),
			}, nil
		}
		previewBytes, marshalErr := json.Marshal(preview)
		if marshalErr != nil {
			return nil, status.Errorf(codes.Internal, "marshal dry-run preview: %v", marshalErr)
		}
		var valErrs []string
		summary := fmt.Sprintf("Offline dry-run ready: %s %s (allowed by %s)", preview.Method, preview.URL, preview.MatchedHostRule)
		if !preview.Allowed {
			valErrs = append(valErrs, preview.PolicyReason)
			summary = "Offline dry-run blocked by egress policy: " + preview.PolicyReason
		}
		return &secflowv1.TestDeclarativePluginResponse{
			Ok:                preview.Allowed,
			ValidationErrors:  valErrs,
			ActiveOutputPorts: []string{"default"},
			DryRunHttpJson:    previewBytes,
			DurationMs:        time.Since(start).Milliseconds(),
			Summary:           summary,
		}, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported category %q", spec.Category)
	}
}

// ListDeclarativeSpecs returns active DECLARATIVE specs for the matching sandbox runtime pool.
func (s *Server) ListDeclarativeSpecs(ctx context.Context, req *secflowv1.ListDeclarativeSpecsRequest) (*secflowv1.ListDeclarativeSpecsResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	svcTok := firstIncomingMeta(md, "x-service-token")
	if svcTok != "" && !s.validServiceToken(svcTok) {
		return nil, status.Error(codes.Unauthenticated, "invalid x-service-token")
	}
	if svcTok == "" && (os.Getenv("SECFLOW_ENV") == "production" || os.Getenv("REQUIRE_WORKER_SERVICE_TOKEN") == "1") {
		return nil, status.Error(codes.Unauthenticated, "x-service-token required")
	}

	wantProfile := req.GetSandboxProfile()
	s.plugMu.Lock()
	defer s.plugMu.Unlock()

	var out []*secflowv1.DeclarativeSpecRecord
	for _, rec := range s.installations {
		if rec == nil || rec.proto == nil {
			continue
		}
		inst := rec.proto
		if inst.GetSourceMode() != secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE {
			continue
		}
		if inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE {
			continue
		}
		if wantProfile != secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED && inst.GetSandboxProfile() != wantProfile {
			continue
		}
		if len(inst.GetDeclarativeSpecJson()) == 0 || len(inst.GetManifests()) == 0 {
			continue
		}
		m := clonePluginManifest(inst.GetManifests()[0])
		out = append(out, &secflowv1.DeclarativeSpecRecord{
			InstallationId:      inst.GetId(),
			PluginId:            m.GetPluginId(),
			Version:             inst.GetPluginVersion(),
			SandboxProfile:      inst.GetSandboxProfile(),
			EgressAllowlist:     slices.Clone(inst.GetEgressAllowlist()),
			DeclarativeSpecJson: slices.Clone(inst.GetDeclarativeSpecJson()),
			Manifest:            m,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].GetPluginId() < out[j].GetPluginId()
	})
	return &secflowv1.ListDeclarativeSpecsResponse{Specs: out}, nil
}

func (s *Server) populateDeclarativeInstallation(
	inst *secflowv1.PluginInstallation,
	req *secflowv1.InstallPluginRequest,
	now *timestamppb.Timestamp,
) (*secflowv1.PluginInstallation, []*secflowv1.PluginManifest, bool, error) {
	spec, err := declarativeplugin.ValidateSpec(req.GetDeclarativeSpecJson())
	if err != nil {
		return nil, nil, false, status.Error(codes.InvalidArgument, err.Error())
	}
	normalizedJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, nil, false, status.Errorf(codes.Internal, "marshal declarative spec: %v", err)
	}
	m, err := spec.ToPluginManifest()
	if err != nil {
		return nil, nil, false, status.Errorf(codes.InvalidArgument, "build declarative manifest: %v", err)
	}

	inst.SandboxProfile = spec.SandboxProfile()
	inst.EgressAllowlist = slices.Clone(spec.EgressAllowlist)
	if err := validateInstallationSpec(inst.GetName(), "", "", inst.GetSandboxProfile(), inst.GetEgressAllowlist()); err != nil {
		return nil, nil, false, err
	}
	inst.PluginVersion = spec.Version
	inst.PluginIds = []string{m.GetPluginId()}

	manifests := []*secflowv1.PluginManifest{m}
	if req.GetAutoApprove() && isOwnerActor(req.GetActor()) && !req.GetSaveAsDraft() {
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
		inst.DeclarativeSpecJson = normalizedJSON
		inst.PendingDeclarativeSpecJson = nil
		inst.Manifests = manifests
		inst.PendingManifests = nil
		inst.ApprovedManifestDigest = computeManifestDigest(manifests)
		inst.ApprovedBy = subject(req.GetActor())
		inst.ApprovedAt = now
		return inst, clonePluginManifests(manifests), false, nil
	}

	inst.PendingDeclarativeSpecJson = normalizedJSON
	inst.PendingManifests = manifests
	if req.GetSaveAsDraft() {
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DRAFT
		inst.StatusReason = "saved as draft"
	} else {
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
		inst.StatusReason = "awaiting owner approval"
	}
	return inst, nil, false, nil
}

func detectDeclarativeSpecEscalation(prevInst *secflowv1.PluginInstallation, nextSpec declarativeplugin.Spec) bool {
	if prevInst == nil {
		return false
	}
	if prevInst.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY &&
		nextSpec.SandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
		return true
	}
	prevHosts := map[string]bool{}
	for _, h := range prevInst.GetEgressAllowlist() {
		prevHosts[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for _, h := range nextSpec.EgressAllowlist {
		if !prevHosts[strings.ToLower(strings.TrimSpace(h))] {
			return true
		}
	}
	prevSecrets := map[string]bool{}
	for _, m := range prevInst.GetManifests() {
		for _, sk := range m.GetRequiredSecretKeys() {
			prevSecrets[strings.ToLower(strings.TrimSpace(sk))] = true
		}
	}
	for _, sk := range nextSpec.RequiredSecretKeys {
		if !prevSecrets[strings.ToLower(strings.TrimSpace(sk))] {
			return true
		}
	}
	return false
}

func (s *Server) updateDeclarativeInstallation(ctx context.Context, req *secflowv1.UpdatePluginInstallationRequest) (*secflowv1.UpdatePluginInstallationResponse, error) {
	if err := requireEditorOrOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	instID := strings.TrimSpace(req.GetInstallationId())
	now := timestamppb.Now()
	owner := isOwnerActor(req.GetActor())

	s.plugMu.Lock()
	rec := s.installations[instID]
	if rec == nil || rec.proto == nil {
		s.plugMu.Unlock()
		return nil, status.Error(codes.NotFound, errInstallationNotFound)
	}
	inst := rec.proto
	if inst.GetSourceMode() != secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE {
		s.plugMu.Unlock()
		return nil, status.Error(codes.InvalidArgument, "VALIDATION_FAILED: installation is not a DECLARATIVE plugin")
	}
	if inst.GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DELETING {
		s.plugMu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, errInstallationDeleting)
	}

	rawSpec := req.GetDeclarativeSpecJson()
	if len(rawSpec) == 0 {
		rawSpec = inst.GetPendingDeclarativeSpecJson()
	}
	if len(rawSpec) == 0 {
		rawSpec = inst.GetDeclarativeSpecJson()
	}
	spec, err := declarativeplugin.ValidateSpec(rawSpec)
	if err != nil {
		s.plugMu.Unlock()
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Enforce immutable plugin_id after creation.
	if len(inst.GetPluginIds()) > 0 && !strings.EqualFold(inst.GetPluginIds()[0], spec.PluginID) {
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.InvalidArgument, "VALIDATION_FAILED: plugin_id %q is immutable and cannot be changed to %q", inst.GetPluginIds()[0], spec.PluginID)
	}
	if _, isBuiltin := manifest.LookupBuiltin(pluginOwnerKey(spec.PluginID)); isBuiltin {
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.PermissionDenied, "FORBIDDEN: cannot override built-in plugin_id %q", spec.PluginID)
	}
	if ownerInst := s.pluginInstallation[pluginOwnerKey(spec.PluginID)]; ownerInst != "" && ownerInst != instID {
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.AlreadyExists, "DUPLICATE_PLUGIN_ID: plugin_id %q is already owned by installation %s", spec.PluginID, ownerInst)
	}

	// Bump patch version on spec changes.
	if len(req.GetDeclarativeSpecJson()) > 0 {
		spec.Version = declarativeplugin.BumpPatchVersion(inst.GetPluginVersion())
	}
	normalizedJSON, err := json.Marshal(spec)
	if err != nil {
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.Internal, "marshal declarative spec: %v", err)
	}
	m, err := spec.ToPluginManifest()
	if err != nil {
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.InvalidArgument, "build declarative manifest: %v", err)
	}
	manifests := []*secflowv1.PluginManifest{m}
	if err := validateInstallationSpec(inst.GetName(), "", "", spec.SandboxProfile(), spec.EgressAllowlist); err != nil {
		s.plugMu.Unlock()
		return nil, err
	}

	escalated := detectDeclarativeSpecEscalation(inst, spec)
	prevStatus := inst.GetStatus()
	var pluginEvents []*secflowv1.PluginRegistryEvent
	syncPlugins := false

	if owner && req.GetApproveImmediately() && !escalated {
		inst.SandboxProfile = spec.SandboxProfile()
		inst.EgressAllowlist = slices.Clone(spec.EgressAllowlist)
		inst.DeclarativeSpecJson = normalizedJSON
		inst.PendingDeclarativeSpecJson = nil
		inst.Manifests = manifests
		inst.PendingManifests = nil
		inst.PluginIds = []string{m.GetPluginId()}
		inst.PluginVersion = spec.Version
		inst.ApprovedManifestDigest = computeManifestDigest(manifests)
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
		inst.StatusReason = ""
		inst.ApprovedBy = subject(req.GetActor())
		inst.ApprovedAt = now
		rec.approvedManifests = clonePluginManifests(manifests)
		pluginEvents = s.upsertInstallationPluginsLocked(instID, manifests, true, approvalStateApproved, now)
		syncPlugins = true
	} else {
		// Non-destructive staging revision: ACTIVE workflows keep running on inst.DeclarativeSpecJson / inst.Manifests / inst.PluginVersion!
		inst.PendingDeclarativeSpecJson = normalizedJSON
		inst.PendingManifests = manifests
		if prevStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE {
			if escalated {
				inst.StatusReason = "pending revision with privilege escalation awaits owner approval"
			} else {
				inst.StatusReason = "pending revision awaits owner approval"
			}
		} else if req.GetSubmitForApproval() || escalated {
			inst.PluginVersion = spec.Version
			inst.SandboxProfile = spec.SandboxProfile()
			inst.EgressAllowlist = slices.Clone(spec.EgressAllowlist)
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
			if escalated {
				inst.StatusReason = "privilege escalation requires owner approval"
			} else {
				inst.StatusReason = "awaiting owner approval"
			}
		} else if prevStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DRAFT {
			inst.PluginVersion = spec.Version
			inst.SandboxProfile = spec.SandboxProfile()
			inst.EgressAllowlist = slices.Clone(spec.EgressAllowlist)
			inst.StatusReason = "draft updated"
		}
	}
	inst.UpdatedAt = now
	instOut := cloneInstallation(inst)
	s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_UPDATED, instOut)
	for _, pev := range pluginEvents {
		s.fanoutPlugin(pev)
	}
	s.plugMu.Unlock()

	s.persistInstallationAndPlugins(ctx, rec, "UPDATED", syncPlugins)
	return &secflowv1.UpdatePluginInstallationResponse{Installation: instOut}, nil
}

// ============================================================================
// Saved Nodes (Shared secret-stripped Node configurations — ADR-0011, Ticket #39)
// ============================================================================

func cloneSavedNode(in *secflowv1.SavedNode) *secflowv1.SavedNode {
	if in == nil {
		return nil
	}
	cp, _ := proto.Clone(in).(*secflowv1.SavedNode)
	return cp
}

func (s *Server) ListSavedNodes(_ context.Context, _ *secflowv1.ListSavedNodesRequest) (*secflowv1.ListSavedNodesResponse, error) {
	s.savedMu.Lock()
	items := make([]*secflowv1.SavedNode, 0, len(s.savedNodes))
	for _, sn := range s.savedNodes {
		items = append(items, cloneSavedNode(sn))
	}
	s.savedMu.Unlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].GetName() == items[j].GetName() {
			return items[i].GetId() < items[j].GetId()
		}
		return items[i].GetName() < items[j].GetName()
	})
	return &secflowv1.ListSavedNodesResponse{SavedNodes: items}, nil
}

func (s *Server) SaveNode(ctx context.Context, req *secflowv1.SaveNodeRequest) (*secflowv1.SaveNodeResponse, error) {
	if err := requireEditorOrOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	pid := strings.TrimSpace(req.GetPluginId())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "VALIDATION_FAILED: saved node name is required")
	}
	if pid == "" {
		return nil, status.Error(codes.InvalidArgument, "VALIDATION_FAILED: plugin_id is required")
	}
	cleanParams, hash, err := declarativeplugin.SanitizeAndHashParams(req.GetParamsJson())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	now := timestamppb.Now()
	s.savedMu.Lock()
	for _, existing := range s.savedNodes {
		if strings.EqualFold(existing.GetPluginId(), pid) && existing.GetCanonicalParamsHash() == hash {
			s.savedMu.Unlock()
			return nil, status.Errorf(codes.AlreadyExists, "DUPLICATE_SAVED_NODE: identical configuration already saved as %q (%s)", existing.GetName(), existing.GetId())
		}
	}
	sn := &secflowv1.SavedNode{
		Id:                  id("snode"),
		Name:                name,
		Description:         strings.TrimSpace(req.GetDescription()),
		PluginId:            pid,
		ParamsJson:          cleanParams,
		CanonicalParamsHash: hash,
		CreatedBy:           subject(req.GetActor()),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	s.savedNodes[sn.GetId()] = sn
	out := cloneSavedNode(sn)
	s.savedMu.Unlock()

	s.persistSavedNode(ctx, out)
	return &secflowv1.SaveNodeResponse{SavedNode: out}, nil
}

func (s *Server) UpdateSavedNode(ctx context.Context, req *secflowv1.UpdateSavedNodeRequest) (*secflowv1.UpdateSavedNodeResponse, error) {
	if err := requireEditorOrOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	snID := strings.TrimSpace(req.GetId())
	if snID == "" {
		return nil, status.Error(codes.InvalidArgument, "VALIDATION_FAILED: saved node id is required")
	}

	s.savedMu.Lock()
	cur := s.savedNodes[snID]
	if cur == nil {
		s.savedMu.Unlock()
		return nil, status.Error(codes.NotFound, "saved node not found")
	}
	nextName := strings.TrimSpace(req.GetName())
	if nextName == "" {
		nextName = cur.GetName()
	}
	nextDesc := strings.TrimSpace(req.GetDescription())
	if req.GetDescription() == "" {
		nextDesc = cur.GetDescription()
	}
	cleanParams := cur.GetParamsJson()
	hash := cur.GetCanonicalParamsHash()
	if len(req.GetParamsJson()) > 0 {
		var err error
		cleanParams, hash, err = declarativeplugin.SanitizeAndHashParams(req.GetParamsJson())
		if err != nil {
			s.savedMu.Unlock()
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	for _, other := range s.savedNodes {
		if other.GetId() != snID && strings.EqualFold(other.GetPluginId(), cur.GetPluginId()) && other.GetCanonicalParamsHash() == hash {
			s.savedMu.Unlock()
			return nil, status.Errorf(codes.AlreadyExists, "DUPLICATE_SAVED_NODE: identical configuration already saved as %q (%s)", other.GetName(), other.GetId())
		}
	}
	cur.Name = nextName
	cur.Description = nextDesc
	cur.ParamsJson = cleanParams
	cur.CanonicalParamsHash = hash
	cur.UpdatedAt = timestamppb.Now()
	out := cloneSavedNode(cur)
	s.savedMu.Unlock()

	s.persistSavedNode(ctx, out)
	return &secflowv1.UpdateSavedNodeResponse{SavedNode: out}, nil
}

func (s *Server) DeleteSavedNode(ctx context.Context, req *secflowv1.DeleteSavedNodeRequest) (*secflowv1.DeleteSavedNodeResponse, error) {
	if err := requireEditorOrOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	snID := strings.TrimSpace(req.GetId())
	if snID == "" {
		return nil, status.Error(codes.InvalidArgument, "VALIDATION_FAILED: saved node id is required")
	}
	s.savedMu.Lock()
	_, ok := s.savedNodes[snID]
	if !ok {
		s.savedMu.Unlock()
		return nil, status.Error(codes.NotFound, "saved node not found")
	}
	delete(s.savedNodes, snID)
	s.savedMu.Unlock()

	if s.pool != nil {
		dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(dbCtx, `DELETE FROM saved_nodes WHERE id = $1`, snID); err != nil {
			slog.Warn("delete saved_node", "id", snID, "err", err)
		}
	}
	return &secflowv1.DeleteSavedNodeResponse{Deleted: true}, nil
}

func (s *Server) persistSavedNode(ctx context.Context, sn *secflowv1.SavedNode) {
	if s.pool == nil || sn == nil {
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := s.pool.Exec(dbCtx, `
		INSERT INTO saved_nodes (id, name, description, plugin_id, params_json, canonical_params_hash, created_by, updated_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, now())
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			params_json = EXCLUDED.params_json,
			canonical_params_hash = EXCLUDED.canonical_params_hash,
			updated_at = now()`,
		sn.GetId(), sn.GetName(), sn.GetDescription(), sn.GetPluginId(),
		string(sn.GetParamsJson()), sn.GetCanonicalParamsHash(), sn.GetCreatedBy(),
	)
	if err != nil {
		slog.Warn("persist saved_node", "id", sn.GetId(), "err", err)
	}
}

func (s *Server) loadSavedNodes(ctx context.Context) {
	if s.pool == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, plugin_id, params_json, canonical_params_hash, created_by, created_at, updated_at
		FROM saved_nodes`)
	if err != nil {
		slog.Warn("load saved_nodes", "err", err)
		return
	}
	defer rows.Close()

	s.savedMu.Lock()
	defer s.savedMu.Unlock()
	for rows.Next() {
		var snID, name, desc, pid, hash, createdBy string
		var paramsRaw []byte
		var createdAt, updatedAt time.Time
		if scanErr := rows.Scan(&snID, &name, &desc, &pid, &paramsRaw, &hash, &createdBy, &createdAt, &updatedAt); scanErr != nil {
			slog.Warn("scan saved_node", "err", scanErr)
			continue
		}
		s.savedNodes[snID] = &secflowv1.SavedNode{
			Id:                  snID,
			Name:                name,
			Description:         desc,
			PluginId:            pid,
			ParamsJson:          paramsRaw,
			CanonicalParamsHash: hash,
			CreatedBy:           createdBy,
			CreatedAt:           timestamppb.New(createdAt),
			UpdatedAt:           timestamppb.New(updatedAt),
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate saved_nodes rows", "err", err)
	}
}

// checkDraftDeclarativeNodes returns validation issues if a graph references an unsaved or unapproved custom.* plugin.
func (s *Server) checkDraftDeclarativeNodes(g *secflowv1.WorkflowGraph) []*secflowv1.ValidationIssue {
	if g == nil {
		return nil
	}
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	var issues []*secflowv1.ValidationIssue
	for _, n := range g.GetNodes() {
		pid := strings.ToLower(strings.TrimSpace(n.GetPluginId()))
		if !strings.HasPrefix(pid, "custom.") {
			continue
		}
		instID := s.pluginInstallation[pid]
		var rec *installationRec
		if instID != "" {
			rec = s.installations[instID]
		} else {
			for _, cand := range s.installations {
				if cand != nil && cand.proto != nil && slices.Contains(cand.proto.GetPluginIds(), pid) {
					rec = cand
					break
				}
			}
		}
		if rec == nil || rec.proto == nil {
			issues = append(issues, &secflowv1.ValidationIssue{
				Code:      "DECLARATIVE_PLUGIN_UNSAVED",
				Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
				NodeId:    n.GetId(),
				FieldPath: "pluginId",
				Message:   fmt.Sprintf("Декларативный плагин %q не сохранён в библиотеку — нажмите ПКМ по ноде → «Сохранить» и одобрите перед запуском", pid),
			})
			continue
		}
		st := rec.proto.GetStatus()
		if st != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE {
			issues = append(issues, &secflowv1.ValidationIssue{
				Code:      "DECLARATIVE_PLUGIN_NOT_ACTIVE",
				Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
				NodeId:    n.GetId(),
				FieldPath: "pluginId",
				Message:   fmt.Sprintf("Декларативный плагин %q имеет статус %s — требуется сохранение и одобрение OWNER перед запуском", pid, trimInstallStatus(st)),
			})
		}
	}
	return issues
}
