package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// InstallationStore abstracts PostgreSQL persistence for plugin_installations reconciliation.
type InstallationStore interface {
	ListInstallations(ctx context.Context) ([]InstallationSpec, error)
	UpdateDiagnostics(ctx context.Context, installationID string, diag Diagnostics, markError bool) error
	FinalizeDelete(ctx context.Context, installationID string) error
}

// PGStore implements InstallationStore on PostgreSQL using pgxpool.
type PGStore struct {
	pool *pgxpool.Pool
}

func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

func (s *PGStore) ListInstallations(ctx context.Context) ([]InstallationSpec, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, source_mode, preset_id, image_ref, sandbox_profile,
		       egress_allowlist, resource_limits, desired_replicas, status,
		       approved_manifests_json
		FROM plugin_installations
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query plugin_installations: %w", err)
	}
	defer rows.Close()

	var out []InstallationSpec
	for rows.Next() {
		var (
			spec         InstallationSpec
			limitsRaw    []byte
			manifestsRaw []byte
		)
		if err := rows.Scan(
			&spec.ID,
			&spec.Name,
			&spec.SourceMode,
			&spec.PresetID,
			&spec.ImageRef,
			&spec.SandboxProfile,
			&spec.EgressAllowlist,
			&limitsRaw,
			&spec.DesiredReplicas,
			&spec.Status,
			&manifestsRaw,
		); err != nil {
			return nil, fmt.Errorf("scan plugin_installation: %w", err)
		}
		if len(limitsRaw) > 0 {
			spec.ResourceLimits = decodeResourceLimitsJSON(limitsRaw)
		}
		if len(manifestsRaw) > 0 {
			spec.PluginIDs = decodeManifestPluginIDsJSON(manifestsRaw)
		}
		out = append(out, spec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate plugin_installations: %w", err)
	}
	return out, nil
}

// decodeResourceLimitsJSON accepts both protojson camelCase (cpuLimit) and snake_case (cpu_limit).
func decodeResourceLimitsJSON(raw []byte) ResourceLimits {
	var dual struct {
		CPURequestCamel    string `json:"cpuRequest"`
		CPURequestSnake    string `json:"cpu_request"`
		CPULimitCamel      string `json:"cpuLimit"`
		CPULimitSnake      string `json:"cpu_limit"`
		MemoryRequestCamel string `json:"memoryRequest"`
		MemoryRequestSnake string `json:"memory_request"`
		MemoryLimitCamel   string `json:"memoryLimit"`
		MemoryLimitSnake   string `json:"memory_limit"`
		MinReplicasCamel   int32  `json:"minReplicas"`
		MinReplicasSnake   int32  `json:"min_replicas"`
		MaxReplicasCamel   int32  `json:"maxReplicas"`
		MaxReplicasSnake   int32  `json:"max_replicas"`
	}
	if err := json.Unmarshal(raw, &dual); err != nil {
		return ResourceLimits{}
	}
	pickStr := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	pickInt := func(a, b int32) int32 {
		if a != 0 {
			return a
		}
		return b
	}
	return ResourceLimits{
		CPURequest:    pickStr(dual.CPURequestCamel, dual.CPURequestSnake),
		CPULimit:      pickStr(dual.CPULimitCamel, dual.CPULimitSnake),
		MemoryRequest: pickStr(dual.MemoryRequestCamel, dual.MemoryRequestSnake),
		MemoryLimit:   pickStr(dual.MemoryLimitCamel, dual.MemoryLimitSnake),
		MinReplicas:   pickInt(dual.MinReplicasCamel, dual.MinReplicasSnake),
		MaxReplicas:   pickInt(dual.MaxReplicasCamel, dual.MaxReplicasSnake),
	}
}

// decodeManifestPluginIDsJSON accepts both protojson camelCase (pluginId) and snake_case (plugin_id).
func decodeManifestPluginIDsJSON(raw []byte) []string {
	var manifests []struct {
		PluginIDCamel string `json:"pluginId"`
		PluginIDSnake string `json:"plugin_id"`
	}
	if err := json.Unmarshal(raw, &manifests); err != nil {
		return nil
	}
	var out []string
	for _, m := range manifests {
		pid := m.PluginIDCamel
		if pid == "" {
			pid = m.PluginIDSnake
		}
		if pid != "" {
			out = append(out, pid)
		}
	}
	return out
}

func (s *PGStore) UpdateDiagnostics(ctx context.Context, installationID string, diag Diagnostics, markError bool) error {
	raw, err := json.Marshal(diag)
	if err != nil {
		return fmt.Errorf("marshal diagnostics: %w", err)
	}
	if markError {
		_, err = s.pool.Exec(ctx, `
			UPDATE plugin_installations
			SET runtime_diagnostics = $2::jsonb,
			    last_error = $3,
			    status = CASE WHEN status IN ('PROVISIONING', 'ACTIVE') THEN 'ERROR' ELSE status END,
			    status_reason = CASE WHEN $3 <> '' THEN $3 ELSE status_reason END,
			    updated_at = now()
			WHERE id = $1
		`, installationID, string(raw), diag.LastError)
	} else {
		_, err = s.pool.Exec(ctx, `
			UPDATE plugin_installations
			SET runtime_diagnostics = $2::jsonb,
			    last_error = $3,
			    updated_at = now()
			WHERE id = $1
		`, installationID, string(raw), diag.LastError)
	}
	if err != nil {
		return fmt.Errorf("update diagnostics for %s: %w", installationID, err)
	}
	return nil
}

func (s *PGStore) FinalizeDelete(ctx context.Context, installationID string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM plugin_installations WHERE id = $1 AND status = 'DELETING'`, installationID); err != nil {
		return fmt.Errorf("finalize delete %s: %w", installationID, err)
	}
	return nil
}

// Reconciler drives periodic and LISTEN/NOTIFY-triggered reconciliation of Plugin Installations.
type Reconciler struct {
	store       InstallationStore
	provisioner RuntimeProvisioner
	resyncEvery time.Duration
}

func NewReconciler(store InstallationStore, prov RuntimeProvisioner, resyncEvery time.Duration) *Reconciler {
	if resyncEvery <= 0 {
		resyncEvery = 15 * time.Second
	}
	return &Reconciler{
		store:       store,
		provisioner: prov,
		resyncEvery: resyncEvery,
	}
}

// ReconcileAll fetches all desired installations and reconciles each one.
func (r *Reconciler) ReconcileAll(ctx context.Context) error {
	specs, err := r.store.ListInstallations(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, spec := range specs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := r.ReconcileOne(ctx, spec); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ReconcileOne converges a single installation and persists updated diagnostics.
func (r *Reconciler) ReconcileOne(ctx context.Context, spec InstallationSpec) error {
	if spec.Status == StatusDeleting {
		if err := r.provisioner.Delete(ctx, spec.ID); err != nil {
			slog.Warn("delete sandbox resources failed", "installation_id", spec.ID, "err", err)
			return err
		}
		return r.store.FinalizeDelete(ctx, spec.ID)
	}

	diag, err := r.provisioner.Reconcile(ctx, spec)
	markErr := err != nil || diag.Phase == "ImagePullBackOff" || diag.Phase == "ErrImagePull" || diag.Phase == "CrashLoopBackOff" || diag.Phase == "OOMKilled"
	if err != nil {
		slog.Warn("reconcile installation failed", "installation_id", spec.ID, "driver", r.provisioner.Driver(), "err", err)
		if diag.LastError == "" {
			diag.LastError = err.Error()
		}
		if diag.Phase == "" {
			diag.Phase = "Error"
		}
	}
	if uErr := r.store.UpdateDiagnostics(ctx, spec.ID, diag, markErr); uErr != nil {
		return errors.Join(err, uErr)
	}
	return err
}

// Run subscribes to PostgreSQL LISTEN plugin_provision_jobs (when pool != nil) and resyncs periodically.
func (r *Reconciler) Run(ctx context.Context, pool *pgxpool.Pool) {
	trigger := make(chan struct{}, 1)
	signalTrigger := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	signalTrigger()

	if pool != nil {
		go listenProvisionJobs(ctx, pool, signalTrigger)
	}

	ticker := time.NewTicker(r.resyncEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			if err := r.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("reconcile pass error", "err", err)
			}
		case <-ticker.C:
			if err := r.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("periodic resync error", "err", err)
			}
		}
	}
}

func listenProvisionJobs(ctx context.Context, pool *pgxpool.Pool, onEvent func()) {
	backoff := time.Second
	for ctx.Err() == nil {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			slog.Warn("acquire pg listen conn", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, 15*time.Second)
				continue
			}
		}
		backoff = time.Second
		if _, err := conn.Exec(ctx, "LISTEN plugin_provision_jobs"); err != nil {
			conn.Release()
			slog.Warn("LISTEN plugin_provision_jobs failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		for ctx.Err() == nil {
			if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
				if ctx.Err() == nil {
					slog.Warn("pg notification wait error", "err", err)
				}
				break
			}
			onEvent()
		}
		conn.Release()
	}
}
