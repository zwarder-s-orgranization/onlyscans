package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

type pluginNotifyPayload struct {
	Origin         string `json:"origin"`
	Entity         string `json:"entity"`
	EventType      string `json:"eventType"`
	InstallationID string `json:"installationId"`
	PluginID       string `json:"pluginId"`
	Status         string `json:"status"`
}

func (s *Server) persistInstallationAndPlugins(ctx context.Context, rec *installationRec, eventType string, syncPlugins bool) {
	if s.pool == nil || rec == nil || rec.proto == nil {
		return
	}
	s.plugMu.Lock()
	inst := cloneInstallation(rec.proto)
	approved := clonePluginManifests(rec.approvedManifests)
	tokHash := rec.tokenHash
	hasTok := rec.hasToken
	tokPrefix := rec.tokenPrefix
	lastErr := rec.lastError
	var pluginSnapshots []*pluginPersistItem
	if syncPlugins {
		for pid, m := range s.plugins {
			if m == nil || s.pluginInstallation[pluginOwnerKey(pid)] != inst.GetId() {
				continue
			}
			rp := s.registeredPluginLocked(m, 0)
			appState := s.pluginApprovalState[pid]
			if appState == "" {
				appState = approvalStateApproved
			}
			pluginSnapshots = append(pluginSnapshots, &pluginPersistItem{
				pluginID:      pid,
				manifest:      clonePluginManifest(m),
				status:        rp.GetStatus().String(),
				instID:        inst.GetId(),
				enabled:       rp.GetEnabled(),
				approvalState: appState,
				activeWorkers: rp.GetActiveWorkers(),
				registeredAt:  rp.GetRegisteredAt(),
				lastSeenAt:    rp.GetLastSeenAt(),
			})
		}
	}
	s.plugMu.Unlock()

	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(dbCtx)
	if err != nil {
		slog.Warn("begin plugin installation tx", "installation_id", inst.GetId(), "err", err)
		return
	}
	defer func() {
		_ = tx.Rollback(dbCtx)
	}()

	if _, err := tx.Exec(dbCtx, `SELECT set_config('secflow.notify_origin', $1, true), set_config('secflow.event_type', $2, true)`, s.serverID, eventType); err != nil {
		slog.Warn("set notify config", "err", err)
		return
	}
	if err := execUpsertInstallationTx(dbCtx, tx, inst, approved, tokHash, hasTok, tokPrefix, lastErr); err != nil {
		slog.Warn("upsert plugin_installation", "installation_id", inst.GetId(), "err", err)
		return
	}
	if syncPlugins {
		keepIDs := make([]string, 0, len(pluginSnapshots))
		for _, p := range pluginSnapshots {
			if err := execUpsertPluginTx(dbCtx, tx, p); err != nil {
				slog.Warn("upsert plugin", "plugin_id", p.pluginID, "err", err)
				return
			}
			keepIDs = append(keepIDs, p.pluginID)
		}
		if err := pruneInstallationPluginsTx(dbCtx, tx, inst.GetId(), keepIDs); err != nil {
			slog.Warn("prune stale installation plugins", "installation_id", inst.GetId(), "err", err)
			return
		}
	}
	if err := tx.Commit(dbCtx); err != nil {
		slog.Warn("commit plugin installation tx", "installation_id", inst.GetId(), "err", err)
	}
}

type pluginPersistItem struct {
	pluginID      string
	manifest      *secflowv1.PluginManifest
	status        string
	instID        string
	enabled       bool
	approvalState string
	activeWorkers int32
	registeredAt  *timestamppb.Timestamp
	lastSeenAt    *timestamppb.Timestamp
}

func (s *Server) persistPluginState(ctx context.Context, pid string) {
	if s.pool == nil || pid == "" {
		return
	}
	s.plugMu.Lock()
	m := s.plugins[pid]
	if m == nil {
		s.plugMu.Unlock()
		return
	}
	rp := s.registeredPluginLocked(m, 0)
	instID := s.pluginInstallation[pluginOwnerKey(pid)]
	appState := s.pluginApprovalState[pid]
	if appState == "" {
		appState = approvalStateApproved
	}
	item := &pluginPersistItem{
		pluginID:      pid,
		manifest:      clonePluginManifest(m),
		status:        rp.GetStatus().String(),
		instID:        instID,
		enabled:       rp.GetEnabled(),
		approvalState: appState,
		activeWorkers: rp.GetActiveWorkers(),
		registeredAt:  rp.GetRegisteredAt(),
		lastSeenAt:    rp.GetLastSeenAt(),
	}
	s.plugMu.Unlock()

	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(dbCtx)
	if err != nil {
		slog.Warn("begin plugin tx", "plugin_id", pid, "err", err)
		return
	}
	defer func() {
		_ = tx.Rollback(dbCtx)
	}()
	if _, err := tx.Exec(dbCtx, `SELECT set_config('secflow.notify_origin', $1, true)`, s.serverID); err != nil {
		slog.Warn("set plugin notify origin", "err", err)
		return
	}
	if err := execUpsertPluginTx(dbCtx, tx, item); err != nil {
		slog.Warn("upsert plugin row", "plugin_id", pid, "err", err)
		return
	}
	if err := tx.Commit(dbCtx); err != nil {
		slog.Warn("commit plugin tx", "plugin_id", pid, "err", err)
	}
}

func execUpsertInstallationTx(
	ctx context.Context,
	tx pgx.Tx,
	inst *secflowv1.PluginInstallation,
	approved []*secflowv1.PluginManifest,
	tokHash [32]byte,
	hasTok bool,
	tokPrefix string,
	lastErr string,
) error {
	limitsRaw := "{}"
	if inst.GetResourceLimits() != nil {
		if b, err := protojson.Marshal(inst.GetResourceLimits()); err == nil {
			limitsRaw = string(b)
		}
	}
	diagRaw := "{}"
	if inst.GetRuntimeDiagnostics() != nil {
		if b, err := protojson.Marshal(inst.GetRuntimeDiagnostics()); err == nil {
			diagRaw = string(b)
		}
	}
	approvedRaw := marshalManifestListJSON(approved)
	pendingRaw := marshalManifestListJSON(inst.GetPendingManifests())
	allowlist := inst.GetEgressAllowlist()
	if allowlist == nil {
		allowlist = []string{}
	}
	var hashSlice []byte
	if hasTok {
		hashSlice = tokHash[:]
	}
	var approvedAt *time.Time
	if inst.GetApprovedAt() != nil {
		t := inst.GetApprovedAt().AsTime()
		approvedAt = &t
	}
	declSpecRaw := "{}"
	if len(inst.GetDeclarativeSpecJson()) > 0 {
		declSpecRaw = string(inst.GetDeclarativeSpecJson())
	}
	pendingDeclRaw := "{}"
	if len(inst.GetPendingDeclarativeSpecJson()) > 0 {
		pendingDeclRaw = string(inst.GetPendingDeclarativeSpecJson())
	}
	pluginVer := inst.GetPluginVersion()
	if pluginVer == "" {
		pluginVer = "1.0.0"
	}
	var declPluginID *string
	if inst.GetSourceMode() == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE && len(inst.GetPluginIds()) > 0 {
		pid := strings.ToLower(strings.TrimSpace(inst.GetPluginIds()[0]))
		if pid != "" {
			declPluginID = &pid
		}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO plugin_installations (
			id, name, source_mode, preset_id, image_ref, sandbox_profile,
			egress_allowlist, resource_limits, desired_replicas, status, auto_approve,
			token_hash, token_prefix, approved_manifest_digest, approved_manifests_json,
			pending_manifests_json, runtime_diagnostics, last_error, status_reason,
			created_by, approved_by, approved_at,
			declarative_spec_json, pending_declarative_spec_json, plugin_version, declarative_plugin_id,
			updated_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8::jsonb, $9, $10, $11,
			$12, $13, $14, $15::jsonb,
			$16::jsonb, $17::jsonb, $18, $19,
			$20, $21, $22,
			$23::jsonb, $24::jsonb, $25, $26,
			now()
		)
		ON CONFLICT (id) DO UPDATE SET
			source_mode = EXCLUDED.source_mode,
			preset_id = EXCLUDED.preset_id,
			image_ref = EXCLUDED.image_ref,
			sandbox_profile = EXCLUDED.sandbox_profile,
			egress_allowlist = EXCLUDED.egress_allowlist,
			resource_limits = EXCLUDED.resource_limits,
			desired_replicas = EXCLUDED.desired_replicas,
			status = EXCLUDED.status,
			auto_approve = EXCLUDED.auto_approve,
			token_hash = COALESCE(EXCLUDED.token_hash, plugin_installations.token_hash),
			token_prefix = CASE WHEN EXCLUDED.token_prefix <> '' THEN EXCLUDED.token_prefix ELSE plugin_installations.token_prefix END,
			approved_manifest_digest = EXCLUDED.approved_manifest_digest,
			approved_manifests_json = EXCLUDED.approved_manifests_json,
			pending_manifests_json = EXCLUDED.pending_manifests_json,
			runtime_diagnostics = EXCLUDED.runtime_diagnostics,
			last_error = EXCLUDED.last_error,
			status_reason = EXCLUDED.status_reason,
			approved_by = EXCLUDED.approved_by,
			approved_at = EXCLUDED.approved_at,
			declarative_spec_json = EXCLUDED.declarative_spec_json,
			pending_declarative_spec_json = EXCLUDED.pending_declarative_spec_json,
			plugin_version = EXCLUDED.plugin_version,
			declarative_plugin_id = EXCLUDED.declarative_plugin_id,
			updated_at = now()`,
		inst.GetId(),
		inst.GetName(),
		trimSourceMode(inst.GetSourceMode()),
		inst.GetPresetId(),
		inst.GetImageRef(),
		trimSandboxProfile(inst.GetSandboxProfile()),
		allowlist,
		limitsRaw,
		inst.GetDesiredReplicas(),
		trimInstallStatus(inst.GetStatus()),
		inst.GetAutoApprove(),
		hashSlice,
		tokPrefix,
		inst.GetApprovedManifestDigest(),
		approvedRaw,
		pendingRaw,
		diagRaw,
		lastErr,
		inst.GetStatusReason(),
		inst.GetCreatedBy(),
		inst.GetApprovedBy(),
		approvedAt,
		declSpecRaw,
		pendingDeclRaw,
		pluginVer,
		declPluginID,
	)
	return err
}

func execUpsertPluginTx(ctx context.Context, tx pgx.Tx, item *pluginPersistItem) error {
	manifestRaw, err := protojson.Marshal(item.manifest)
	if err != nil {
		return err
	}
	var instPtr *string
	if item.instID != "" {
		instPtr = &item.instID
	}
	regAt := time.Now().UTC()
	if item.registeredAt != nil {
		regAt = item.registeredAt.AsTime()
	}
	seenAt := regAt
	if item.lastSeenAt != nil {
		seenAt = item.lastSeenAt.AsTime()
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO plugins (
			plugin_id, manifest_json, status, installation_id,
			enabled, approval_state, active_workers, registered_at, last_seen_at, updated_at
		)
		VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (plugin_id) DO UPDATE SET
			manifest_json = EXCLUDED.manifest_json,
			status = EXCLUDED.status,
			installation_id = EXCLUDED.installation_id,
			enabled = EXCLUDED.enabled,
			approval_state = EXCLUDED.approval_state,
			active_workers = EXCLUDED.active_workers,
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = now()`,
		item.pluginID,
		string(manifestRaw),
		item.status,
		instPtr,
		item.enabled,
		item.approvalState,
		item.activeWorkers,
		regAt,
		seenAt,
	)
	return err
}

func pruneInstallationPluginsTx(ctx context.Context, tx pgx.Tx, instID string, keepIDs []string) error {
	if len(keepIDs) == 0 {
		_, err := tx.Exec(ctx, `DELETE FROM plugins WHERE installation_id = $1`, instID)
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM plugins WHERE installation_id = $1 AND NOT (plugin_id = ANY($2))`, instID, keepIDs)
	return err
}

func (s *Server) deleteInstallationInPG(ctx context.Context, instID, statusReason string) {
	if s.pool == nil {
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(dbCtx)
	if err != nil {
		slog.Warn("begin delete installation tx", "installation_id", instID, "err", err)
		return
	}
	defer func() {
		_ = tx.Rollback(dbCtx)
	}()
	if _, err := tx.Exec(dbCtx, `SELECT set_config('secflow.notify_origin', $1, true), set_config('secflow.event_type', 'DELETED', true)`, s.serverID); err != nil {
		slog.Warn("set delete notify config", "err", err)
		return
	}
	if _, err := tx.Exec(dbCtx, `DELETE FROM plugins WHERE installation_id = $1`, instID); err != nil {
		slog.Warn("delete installation plugins", "installation_id", instID, "err", err)
		return
	}
	if os.Getenv("PLUGIN_PROVISIONER_ENABLED") == "1" {
		if _, err := tx.Exec(dbCtx, `UPDATE plugin_installations SET status = 'DELETING', status_reason = $2, updated_at = now() WHERE id = $1`, instID, statusReason); err != nil {
			slog.Warn("mark installation deleting", "installation_id", instID, "err", err)
			return
		}
	} else {
		if _, err := tx.Exec(dbCtx, `DELETE FROM plugin_installations WHERE id = $1`, instID); err != nil {
			slog.Warn("delete plugin_installation", "installation_id", instID, "err", err)
			return
		}
	}
	if err := tx.Commit(dbCtx); err != nil {
		slog.Warn("commit delete installation tx", "installation_id", instID, "err", err)
	}
}

func (s *Server) loadPluginInstallations(ctx context.Context) {
	if s.pool == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			id, name, source_mode, preset_id, image_ref, sandbox_profile,
			egress_allowlist, resource_limits, desired_replicas, status, auto_approve,
			token_hash, token_prefix, approved_manifest_digest, approved_manifests_json,
			pending_manifests_json, runtime_diagnostics, last_error, status_reason,
			created_by, approved_by, approved_at, created_at, updated_at,
			declarative_spec_json, pending_declarative_spec_json, plugin_version
		FROM plugin_installations`)
	if err != nil {
		slog.Warn("load plugin_installations", "err", err)
		return
	}
	defer rows.Close()

	loaded := map[string]*installationRec{}
	for rows.Next() {
		rec, scanErr := scanInstallationRow(rows)
		if scanErr != nil {
			slog.Warn("scan plugin_installation", "err", scanErr)
			continue
		}
		loaded[rec.proto.GetId()] = rec
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate plugin_installations", "err", err)
	}
	s.plugMu.Lock()
	for instID, rec := range loaded {
		s.installations[instID] = rec
	}
	s.plugMu.Unlock()
}

func (s *Server) loadPlugins(ctx context.Context) {
	if s.pool == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			plugin_id, manifest_json, COALESCE(installation_id, ''),
			enabled, approval_state, active_workers, registered_at, last_seen_at
		FROM plugins`)
	if err != nil {
		slog.Warn("load plugins", "err", err)
		return
	}
	defer rows.Close()

	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	for rows.Next() {
		var pid, instID, appState string
		var manifestRaw []byte
		var enabled bool
		var activeWorkers int32
		var regAt, seenAt time.Time
		if scanErr := rows.Scan(&pid, &manifestRaw, &instID, &enabled, &appState, &activeWorkers, &regAt, &seenAt); scanErr != nil {
			slog.Warn("scan plugin", "err", scanErr)
			continue
		}
		m := &secflowv1.PluginManifest{}
		if err := unmarshaler.Unmarshal(manifestRaw, m); err != nil || m.GetPluginId() == "" {
			continue
		}
		s.plugins[pid] = m
		if instID != "" {
			s.pluginInstallation[pluginOwnerKey(pid)] = instID
		}
		s.pluginApprovalState[pid] = appState
		s.pluginDBWorkers[pid] = activeWorkers
		if enabled {
			delete(s.pluginDisabled, pid)
		} else {
			s.pluginDisabled[pid] = true
		}
		s.pluginRegisteredAt[pid] = timestamppb.New(regAt)
		s.pluginLastSeen[pid] = timestamppb.New(seenAt)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate plugins", "err", err)
	}
}

func (s *Server) lookupInstallationByTokenInPG(ctx context.Context, tokHash [32]byte) *installationRec {
	if s.pool == nil {
		return nil
	}
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	row := s.pool.QueryRow(dbCtx, `
		SELECT
			id, name, source_mode, preset_id, image_ref, sandbox_profile,
			egress_allowlist, resource_limits, desired_replicas, status, auto_approve,
			token_hash, token_prefix, approved_manifest_digest, approved_manifests_json,
			pending_manifests_json, runtime_diagnostics, last_error, status_reason,
			created_by, approved_by, approved_at, created_at, updated_at,
			declarative_spec_json, pending_declarative_spec_json, plugin_version
		FROM plugin_installations
		WHERE token_hash = $1`, tokHash[:])
	rec, err := scanInstallationRow(row)
	if err != nil {
		return nil
	}
	return rec
}

func (s *Server) startPluginListener(ctx context.Context) {
	if s.pool == nil {
		return
	}
	go s.runPluginListener(ctx)
}

func (s *Server) runPluginListener(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.listenPluginEventsOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("plugin_events listener disconnected", "err", err)
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func (s *Server) listenPluginEventsOnce(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `LISTEN plugin_events`); err != nil {
		return err
	}
	defer func() {
		unlistenCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlistenCtx, `UNLISTEN plugin_events`)
	}()

	for {
		notif, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		var payload pluginNotifyPayload
		if err := json.Unmarshal([]byte(notif.Payload), &payload); err != nil {
			continue
		}
		if payload.Origin == s.serverID {
			continue
		}
		s.syncPluginNotification(ctx, payload)
	}
}

func (s *Server) syncPluginNotification(ctx context.Context, payload pluginNotifyPayload) {
	switch payload.Entity {
	case "installation":
		s.syncInstallationFromPG(ctx, payload)
	case "plugin":
		s.syncPluginFromPG(ctx, payload)
	}
}

func (s *Server) syncInstallationFromPG(ctx context.Context, payload pluginNotifyPayload) {
	if payload.InstallationID == "" || s.pool == nil {
		return
	}
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	row := s.pool.QueryRow(dbCtx, `
		SELECT
			id, name, source_mode, preset_id, image_ref, sandbox_profile,
			egress_allowlist, resource_limits, desired_replicas, status, auto_approve,
			token_hash, token_prefix, approved_manifest_digest, approved_manifests_json,
			pending_manifests_json, runtime_diagnostics, last_error, status_reason,
			created_by, approved_by, approved_at, created_at, updated_at,
			declarative_spec_json, pending_declarative_spec_json, plugin_version
		FROM plugin_installations
		WHERE id = $1`, payload.InstallationID)
	rec, err := scanInstallationRow(row)

	var linksToDrain []*workerLink
	s.plugMu.Lock()
	if errors.Is(err, pgx.ErrNoRows) || payload.EventType == "DELETED" {
		prev := s.installations[payload.InstallationID]
		delete(s.installations, payload.InstallationID)
		linksToDrain = s.markInstallationLinksDrainingLocked(payload.InstallationID)
		for _, pev := range s.removeInstallationPluginsLocked(payload.InstallationID) {
			s.fanoutPlugin(pev)
		}
		if prev != nil && prev.proto != nil {
			s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_DELETED, prev.proto)
		}
		s.plugMu.Unlock()
		s.drainWorkerLinks(linksToDrain, "plugin installation deleted", 10)
		return
	}
	if err != nil {
		s.plugMu.Unlock()
		return
	}
	s.installations[rec.proto.GetId()] = rec
	st := rec.proto.GetStatus()
	if st == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DISABLED ||
		st == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DELETING ||
		st == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
		linksToDrain = s.markInstallationLinksDrainingLocked(rec.proto.GetId())
	}
	s.fanoutInstallationLocked(notifyEventTypeToProto(payload.EventType), rec.proto)
	s.plugMu.Unlock()
	s.drainWorkerLinks(linksToDrain, "installation state changed on peer", defaultDrainGraceSec)
}

func (s *Server) syncPluginFromPG(ctx context.Context, payload pluginNotifyPayload) {
	if payload.PluginID == "" || s.pool == nil {
		return
	}
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var manifestRaw []byte
	var instID, appState string
	var enabled bool
	var activeWorkers int32
	var regAt, seenAt time.Time
	err := s.pool.QueryRow(dbCtx, `
		SELECT manifest_json, COALESCE(installation_id, ''), enabled, approval_state, active_workers, registered_at, last_seen_at
		FROM plugins WHERE plugin_id = $1`, payload.PluginID).Scan(
		&manifestRaw, &instID, &enabled, &appState, &activeWorkers, &regAt, &seenAt,
	)

	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	if errors.Is(err, pgx.ErrNoRows) {
		s.removePluginRowLocked(payload.PluginID)
		return
	}
	if err != nil {
		return
	}
	m := &secflowv1.PluginManifest{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(manifestRaw, m); err != nil {
		return
	}
	_, existed := s.plugins[payload.PluginID]
	s.plugins[payload.PluginID] = m
	if instID != "" {
		s.pluginInstallation[pluginOwnerKey(payload.PluginID)] = instID
	} else {
		delete(s.pluginInstallation, pluginOwnerKey(payload.PluginID))
	}
	s.pluginApprovalState[payload.PluginID] = appState
	s.pluginDBWorkers[payload.PluginID] = activeWorkers
	if enabled {
		delete(s.pluginDisabled, payload.PluginID)
	} else {
		s.pluginDisabled[payload.PluginID] = true
	}
	s.pluginRegisteredAt[payload.PluginID] = timestamppb.New(regAt)
	s.pluginLastSeen[payload.PluginID] = timestamppb.New(seenAt)

	evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
	if !existed {
		evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED
	} else if !enabled {
		evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE
	}
	s.fanoutPlugin(pluginEvent(evType, s.registeredPluginLocked(m, 0)))
}

func (s *Server) removePluginRowLocked(pluginID string) {
	if m := s.plugins[pluginID]; m != nil {
		rp := s.registeredPluginLocked(m, 0)
		rp.Status = secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE
		rp.Enabled = false
		rp.ActiveWorkers = 0
		s.fanoutPlugin(pluginEvent(secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE, rp))
	}
	delete(s.plugins, pluginID)
	delete(s.pluginDisabled, pluginID)
	ownerKey := pluginOwnerKey(pluginID)
	stillOwned := false
	for pid := range s.plugins {
		if pluginOwnerKey(pid) == ownerKey {
			stillOwned = true
			break
		}
	}
	if !stillOwned {
		delete(s.pluginInstallation, ownerKey)
	}
	delete(s.pluginApprovalState, pluginID)
	delete(s.pluginDBWorkers, pluginID)
}

func scanInstallationRow(row pgx.Row) (*installationRec, error) {
	var idVal, name, srcMode, presetID, imageRef, profile, tokPrefix, digest, lastErr, reason, createdBy, approvedBy, pluginVer string
	var allowlist []string
	var limitsRaw, approvedRaw, pendingRaw, diagRaw, tokHashBytes, declSpecRaw, pendingDeclRaw []byte
	var desiredReplicas int32
	var statusStr string
	var autoApprove bool
	var approvedAt *time.Time
	var createdAt, updatedAt time.Time

	if err := row.Scan(
		&idVal, &name, &srcMode, &presetID, &imageRef, &profile,
		&allowlist, &limitsRaw, &desiredReplicas, &statusStr, &autoApprove,
		&tokHashBytes, &tokPrefix, &digest, &approvedRaw,
		&pendingRaw, &diagRaw, &lastErr, &reason,
		&createdBy, &approvedBy, &approvedAt, &createdAt, &updatedAt,
		&declSpecRaw, &pendingDeclRaw, &pluginVer,
	); err != nil {
		return nil, err
	}

	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	var limits *secflowv1.PluginResourceLimits
	if len(limitsRaw) > 0 && string(limitsRaw) != "{}" {
		l := &secflowv1.PluginResourceLimits{}
		if unmarshaler.Unmarshal(limitsRaw, l) == nil {
			limits = l
		}
	}
	var diag *secflowv1.PluginRuntimeDiagnostics
	if len(diagRaw) > 0 && string(diagRaw) != "{}" {
		d := &secflowv1.PluginRuntimeDiagnostics{}
		if unmarshaler.Unmarshal(diagRaw, d) == nil {
			diag = d
		}
	}
	approved := unmarshalManifestListJSON(approvedRaw)
	pending := unmarshalManifestListJSON(pendingRaw)
	pluginIDs := manifestPluginIDs(approved)
	if len(pluginIDs) == 0 && len(pending) > 0 {
		pluginIDs = manifestPluginIDs(pending)
	}

	if string(declSpecRaw) == "{}" {
		declSpecRaw = nil
	}
	if string(pendingDeclRaw) == "{}" {
		pendingDeclRaw = nil
	}
	inst := &secflowv1.PluginInstallation{
		Id:                         idVal,
		Name:                       name,
		SourceMode:                 parseSourceMode(srcMode),
		PresetId:                   presetID,
		ImageRef:                   imageRef,
		SandboxProfile:             parseSandboxProfile(profile),
		EgressAllowlist:            slices.Clone(allowlist),
		ResourceLimits:             limits,
		DesiredReplicas:            desiredReplicas,
		Status:                     parseInstallStatus(statusStr),
		AutoApprove:                autoApprove,
		ApprovedManifestDigest:     digest,
		Manifests:                  clonePluginManifests(approved),
		PendingManifests:           pending,
		DeclarativeSpecJson:        declSpecRaw,
		PendingDeclarativeSpecJson: pendingDeclRaw,
		PluginVersion:              pluginVer,
		PluginIds:                  pluginIDs,
		RuntimeDiagnostics:         diag,
		CreatedBy:                  createdBy,
		ApprovedBy:                 approvedBy,
		CreatedAt:                  timestamppb.New(createdAt),
		UpdatedAt:                  timestamppb.New(updatedAt),
		StatusReason:               reason,
	}
	if approvedAt != nil {
		inst.ApprovedAt = timestamppb.New(*approvedAt)
	}
	rec := &installationRec{
		proto:             inst,
		tokenPrefix:       tokPrefix,
		approvedManifests: approved,
		lastError:         lastErr,
	}
	if len(tokHashBytes) == 32 {
		copy(rec.tokenHash[:], tokHashBytes)
		rec.hasToken = true
	}
	return rec, nil
}

func marshalManifestListJSON(manifests []*secflowv1.PluginManifest) string {
	if len(manifests) == 0 {
		return "[]"
	}
	items := make([]json.RawMessage, 0, len(manifests))
	for _, m := range manifests {
		if m == nil {
			continue
		}
		if b, err := protojson.Marshal(m); err == nil {
			items = append(items, json.RawMessage(b))
		}
	}
	out, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(out)
}

func unmarshalManifestListJSON(raw []byte) []*secflowv1.PluginManifest {
	if len(raw) == 0 || string(raw) == "[]" {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	out := make([]*secflowv1.PluginManifest, 0, len(items))
	for _, item := range items {
		m := &secflowv1.PluginManifest{}
		if err := unmarshaler.Unmarshal(item, m); err == nil && m.GetPluginId() != "" {
			out = append(out, m)
		}
	}
	return out
}

func trimSourceMode(v secflowv1.PluginSourceMode) string {
	return strings.TrimPrefix(v.String(), "PLUGIN_SOURCE_MODE_")
}

func parseSourceMode(v string) secflowv1.PluginSourceMode {
	if num, ok := secflowv1.PluginSourceMode_value["PLUGIN_SOURCE_MODE_"+v]; ok {
		return secflowv1.PluginSourceMode(num)
	}
	return secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_UNSPECIFIED
}

func trimSandboxProfile(v secflowv1.SandboxProfile) string {
	return strings.TrimPrefix(v.String(), "SANDBOX_PROFILE_")
}

func parseSandboxProfile(v string) secflowv1.SandboxProfile {
	if num, ok := secflowv1.SandboxProfile_value["SANDBOX_PROFILE_"+v]; ok {
		return secflowv1.SandboxProfile(num)
	}
	return secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED
}

func trimInstallStatus(v secflowv1.PluginInstallationStatus) string {
	return strings.TrimPrefix(v.String(), "PLUGIN_INSTALLATION_STATUS_")
}

func parseInstallStatus(v string) secflowv1.PluginInstallationStatus {
	if num, ok := secflowv1.PluginInstallationStatus_value["PLUGIN_INSTALLATION_STATUS_"+v]; ok {
		return secflowv1.PluginInstallationStatus(num)
	}
	return secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_UNSPECIFIED
}

func notifyEventTypeToProto(ev string) secflowv1.PluginInstallationEventType {
	switch ev {
	case "CREATED", "INSERT":
		return secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED
	case "APPROVED":
		return secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_APPROVED
	case "STATUS_CHANGED":
		return secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_STATUS_CHANGED
	case "DELETED", "DELETE":
		return secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_DELETED
	default:
		return secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_UPDATED
	}
}
