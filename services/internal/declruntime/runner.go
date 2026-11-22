// Package declruntime runs a hot-reloading Pull SPI worker pool for active
// Declarative Plugins (either INTERNAL_ONLY or EGRESS_EXTERNAL per ADR-0011).
package declruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/declarativeplugin"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/obs"
)

// Tier distinguishes the two physically isolated declarative runtime pools.
type Tier string

const (
	TierInternal Tier = "internal"
	TierAction   Tier = "action"
)

// SpecEntry holds a validated active declarative plugin ready for execution.
type SpecEntry struct {
	Record   *secflowv1.DeclarativeSpecRecord
	Spec     declarativeplugin.Spec
	Manifest *secflowv1.PluginManifest
}

// Config configures a declarative runtime worker pool instance.
type Config struct {
	OrchestratorAddr string
	DialOpts         []grpc.DialOption
	WorkerID         string
	Namespace        string
	ServiceToken     string
	Tier             Tier
	HandleTask       func(ctx context.Context, conn *grpc.ClientConn, entry SpecEntry, task *secflowv1.NodeTask) *secflowv1.NodeResult
	OnSynced         func(pluginIDs []string)
}

// SandboxProfile returns the SandboxProfile enforced by this pool tier.
func (t Tier) SandboxProfile() secflowv1.SandboxProfile {
	if t == TierAction {
		return secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL
	}
	return secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
}

// Run connects to orchestrator, watches PluginInstallation events for <1s hot-reload,
// and serves dispatched NodeTasks until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.WorkerID == "" {
		cfg.WorkerID = "plugin-runtime-" + string(cfg.Tier)
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "secflow-sandbox"
	}
	opts := append([]grpc.DialOption{}, cfg.DialOpts...)
	if len(opts) == 0 {
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			obs.GRPCDialOption(),
		}
	}
	conn, err := grpc.NewClient(cfg.OrchestratorAddr, opts...)
	if err != nil {
		return fmt.Errorf("dial orchestrator: %w", err)
	}
	defer conn.Close()

	backoff := 200 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := runSession(ctx, conn, cfg)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Warn("declarative runtime session ended, reconnecting", "tier", cfg.Tier, "err", err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func outgoingCtx(ctx context.Context, cfg Config) context.Context {
	pairs := []string{"x-declarative-runtime", string(cfg.Tier)}
	if strings.TrimSpace(cfg.ServiceToken) != "" {
		pairs = append(pairs, "x-service-token", strings.TrimSpace(cfg.ServiceToken))
	}
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(pairs...))
}

func runSession(ctx context.Context, conn *grpc.ClientConn, cfg Config) error {
	sessCtx, cancelSess := context.WithCancel(ctx)
	defer cancelSess()

	regClient := secflowv1.NewPluginRegistryServiceClient(conn)
	workerClient := secflowv1.NewWorkerServiceClient(conn)

	stream, err := workerClient.Connect(outgoingCtx(sessCtx, cfg))
	if err != nil {
		return fmt.Errorf("connect worker stream: %w", err)
	}

	var (
		sendMu     sync.Mutex
		specMu     sync.RWMutex
		specsByPID = map[string]SpecEntry{}
		activeMu   sync.Mutex
		active     = map[string]context.CancelFunc{}
	)
	sendReq := func(req *secflowv1.ConnectRequest) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(req)
	}

	syncSpecs := func() error {
		callCtx, cancel := context.WithTimeout(outgoingCtx(sessCtx, cfg), 5*time.Second)
		defer cancel()
		resp, err := regClient.ListDeclarativeSpecs(callCtx, &secflowv1.ListDeclarativeSpecsRequest{
			SandboxProfile: cfg.Tier.SandboxProfile(),
		})
		if err != nil {
			return fmt.Errorf("list declarative specs: %w", err)
		}
		nextMap := make(map[string]SpecEntry, len(resp.GetSpecs()))
		manifests := make([]*secflowv1.PluginManifest, 0, len(resp.GetSpecs()))
		pluginIDs := make([]string, 0, len(resp.GetSpecs()))
		for _, rec := range resp.GetSpecs() {
			parsed, vErr := declarativeplugin.ValidateSpec(rec.GetDeclarativeSpecJson())
			if vErr != nil {
				slog.Warn("skip invalid declarative spec from orchestrator", "plugin_id", rec.GetPluginId(), "err", vErr)
				continue
			}
			m := rec.GetManifest()
			if m == nil {
				m, vErr = parsed.ToPluginManifest()
				if vErr != nil {
					continue
				}
			}
			nextMap[m.GetPluginId()] = SpecEntry{Record: rec, Spec: parsed, Manifest: m}
			manifests = append(manifests, m)
			pluginIDs = append(pluginIDs, m.GetPluginId())
		}

		specMu.Lock()
		specsByPID = nextMap
		specMu.Unlock()

		if err := sendReq(&secflowv1.ConnectRequest{
			Payload: &secflowv1.ConnectRequest_RegisterManifest{
				RegisterManifest: &secflowv1.WorkerRegisterManifest{
					WorkerInstanceId: cfg.WorkerID,
					Namespace:        cfg.Namespace,
					Manifests:        manifests,
				},
			},
		}); err != nil {
			return fmt.Errorf("send register manifest: %w", err)
		}
		if cfg.OnSynced != nil {
			cfg.OnSynced(pluginIDs)
		}
		return nil
	}

	if err := syncSpecs(); err != nil {
		return err
	}

	// Background watcher triggers immediate (<1s) hot-reload on any installation change.
	reloadCh := make(chan struct{}, 1)
	triggerReload := func() {
		select {
		case reloadCh <- struct{}{}:
		default:
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		watchStream, wErr := regClient.WatchPluginInstallations(outgoingCtx(sessCtx, cfg), &secflowv1.WatchPluginInstallationsRequest{})
		if wErr != nil {
			return
		}
		for {
			_, rErr := watchStream.Recv()
			if rErr != nil {
				return
			}
			triggerReload()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-reloadCh:
				if err := syncSpecs(); err != nil && sessCtx.Err() == nil {
					slog.Warn("hot-reload declarative specs failed", "tier", cfg.Tier, "err", err)
				}
			case <-ticker.C:
				activeMu.Lock()
				ids := make([]string, 0, len(active))
				for id := range active {
					ids = append(ids, id)
				}
				activeMu.Unlock()
				if err := sendReq(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_Heartbeat{
						Heartbeat: &secflowv1.WorkerHeartbeat{
							WorkerInstanceId: cfg.WorkerID,
							ActiveNodeRunIds: ids,
							AvailableSlots:   max(0, 4-int32(len(ids))),
						},
					},
				}); err != nil && sessCtx.Err() == nil {
					slog.Warn("declarative runtime heartbeat failed", "tier", cfg.Tier, "err", err)
				}
			}
		}
	}()

	defer func() {
		cancelSess()
		wg.Wait()
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.EOF
			}
			return err
		}
		switch p := msg.GetPayload().(type) {
		case *secflowv1.ConnectResponse_ManifestAck:
			if !p.ManifestAck.GetAccepted() {
				return fmt.Errorf("manifest rejected: %s (%s)", p.ManifestAck.GetRejectionReason(), p.ManifestAck.GetRejectionCode().String())
			}
		case *secflowv1.ConnectResponse_CancelTask:
			activeMu.Lock()
			if cancel, ok := active[p.CancelTask.GetNodeRunId()]; ok {
				cancel()
			}
			activeMu.Unlock()
		case *secflowv1.ConnectResponse_DrainRequest:
			if err := sendReq(&secflowv1.ConnectRequest{
				Payload: &secflowv1.ConnectRequest_Drain{
					Drain: &secflowv1.WorkerDrainNotice{WorkerInstanceId: cfg.WorkerID, Reason: p.DrainRequest.GetReason()},
				},
			}); err != nil {
				slog.Warn("declarative runtime drain ack failed", "tier", cfg.Tier, "err", err)
			}
			return nil
		case *secflowv1.ConnectResponse_DispatchTask:
			task := p.DispatchTask
			wg.Add(1)
			go func() {
				defer wg.Done()
				timeout := time.Duration(task.GetHardTimeoutSeconds()) * time.Second
				if timeout <= 0 || timeout > declarativeplugin.MaxAnalyzerTimeoutSec*time.Second {
					timeout = declarativeplugin.MaxAnalyzerTimeoutSec * time.Second
				}
				tCtx, tCancel := context.WithTimeout(sessCtx, timeout)
				activeMu.Lock()
				active[task.GetNodeRunId()] = tCancel
				activeMu.Unlock()
				defer func() {
					tCancel()
					activeMu.Lock()
					delete(active, task.GetNodeRunId())
					activeMu.Unlock()
				}()

				specMu.RLock()
				entry, ok := specsByPID[task.GetPluginId()]
				specMu.RUnlock()
				var res *secflowv1.NodeResult
				if !ok {
					res = FailedResult(task, "DECLARATIVE_SPEC_MISSING", "declarative plugin is not active in runtime pool")
				} else {
					res = cfg.HandleTask(tCtx, conn, entry, task)
				}
				if err := sendReq(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_CompleteTask{CompleteTask: res},
				}); err != nil && sessCtx.Err() == nil {
					slog.Warn("declarative runtime complete task send failed", "tier", cfg.Tier, "node_run_id", task.GetNodeRunId(), "err", err)
				}
			}()
		}
	}
}

// FailedResult builds a consistent failed NodeResult.
func FailedResult(task *secflowv1.NodeTask, code, msg string) *secflowv1.NodeResult {
	return &secflowv1.NodeResult{
		NodeRunId:         task.GetNodeRunId(),
		RunId:             task.GetRunId(),
		NodeId:            task.GetNodeId(),
		PluginId:          task.GetPluginId(),
		Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
		ErrorCode:         code,
		ErrorMessage:      msg,
		ActiveOutputPorts: []string{"default"},
	}
}

// ParseTaskParams decodes NodeTask params JSON into a map.
func ParseTaskParams(raw []byte) map[string]any {
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			slog.Warn("parse task params failed", "err", err)
		}
	}
	return out
}

// ParseTaskEnvelope decodes NodeTask envelope JSON.
func ParseTaskEnvelope(raw []byte) engine.Envelope {
	var env engine.Envelope
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &env); err != nil {
			slog.Warn("parse task envelope failed", "err", err)
		}
	}
	return env.Normalize()
}

// LoadFilesFromDir walks a materialized Source Snapshot directory safely (<= 1 MB/file, skips .git).
func LoadFilesFromDir(root string) ([]declarativeplugin.VirtualFile, error) {
	var files []declarativeplugin.VirtualFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > declarativeplugin.MaxScannedFileBytes {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		files = append(files, declarativeplugin.VirtualFile{
			Path:    filepath.ToSlash(rel),
			Content: string(raw),
		})
		return nil
	})
	return files, err
}

// HandleInternalTask executes ANALYZER or LOGIC Declarative Plugin tasks inside plugin-runtime-internal.
func HandleInternalTask(
	ctx context.Context,
	entry SpecEntry,
	task *secflowv1.NodeTask,
	resolveSource func(context.Context, []byte) (string, func()),
) *secflowv1.NodeResult {
	params := ParseTaskParams(task.GetParamsJson())
	switch entry.Spec.Category {
	case declarativeplugin.CategoryAnalyzer:
		root, done := resolveSource(ctx, task.GetEnvelopeJson())
		defer done()
		if root == "" {
			return FailedResult(task, "MISSING_SOURCE", "source snapshot root is empty")
		}
		files, err := LoadFilesFromDir(root)
		if err != nil {
			return FailedResult(task, "SOURCE_READ_ERROR", err.Error())
		}
		findings, err := declarativeplugin.EvaluateAnalyzer(ctx, entry.Spec, params, files, task.GetNodeId())
		if err != nil {
			return FailedResult(task, "ANALYZER_ERROR", err.Error())
		}
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          task.GetPluginId(),
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings:          findings,
			ActiveOutputPorts: []string{"default"},
		}
	case declarativeplugin.CategoryLogic:
		env := ParseTaskEnvelope(task.GetEnvelopeJson())
		res, err := declarativeplugin.EvaluateLogic(entry.Spec, params, env)
		if err != nil {
			return FailedResult(task, "LOGIC_ERROR", err.Error())
		}
		patch, err := res.EnvelopePatchJSON()
		if err != nil {
			return FailedResult(task, "LOGIC_SERIALIZE_ERROR", err.Error())
		}
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          task.GetPluginId(),
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			EnvelopePatchJson: patch,
			ActiveOutputPorts: res.ActivePorts,
		}
	default:
		return FailedResult(task, "SANDBOX_PROFILE_MISMATCH", "plugin-runtime-internal only executes ANALYZER and LOGIC plugins")
	}
}

// HandleActionTask executes approved ACTION Declarative Plugin tasks inside plugin-runtime-action.
func HandleActionTask(
	ctx context.Context,
	conn *grpc.ClientConn,
	entry SpecEntry,
	task *secflowv1.NodeTask,
	allowDevHTTP bool,
) *secflowv1.NodeResult {
	if entry.Spec.Category != declarativeplugin.CategoryAction {
		return FailedResult(task, "SANDBOX_PROFILE_MISMATCH", "plugin-runtime-action only executes ACTION plugins")
	}
	params := ParseTaskParams(task.GetParamsJson())
	env := ParseTaskEnvelope(task.GetEnvelopeJson())

	resolvedSecrets := map[string]string{}
	if len(entry.Spec.RequiredSecretKeys) > 0 {
		bindingByKey := map[string]string{}
		for _, b := range task.GetSecretBindings() {
			bindingByKey[b.GetParamKey()] = b.GetSecretRef()
		}
		secClient := secflowv1.NewSecretServiceClient(conn)
		for _, key := range entry.Spec.RequiredSecretKeys {
			ref := bindingByKey[key]
			if ref == "" {
				return FailedResult(task, "MISSING_SECRET_BINDING", fmt.Sprintf("required secret key %q is not bound", key))
			}
			resp, err := secClient.ResolveScopedSecret(ctx, &secflowv1.ResolveScopedSecretRequest{
				SecretRef: ref,
				Scope: &secflowv1.ResolveScopedSecretRequest_NodeTask{
					NodeTask: &secflowv1.NodeTaskSecretScope{
						RunId:          task.GetRunId(),
						NodeRunId:      task.GetNodeRunId(),
						NodeId:         task.GetNodeId(),
						PluginId:       task.GetPluginId(),
						TaskLeaseToken: task.GetTaskLeaseToken(),
					},
				},
			})
			if err != nil {
				return FailedResult(task, "SECRET_SCOPE_DENIED", fmt.Sprintf("resolve secret %q: %v", key, err))
			}
			resolvedSecrets[key] = resp.GetPlaintextValue()
		}
	}

	execRes, err := declarativeplugin.ExecuteAction(ctx, entry.Spec, params, env, resolvedSecrets, allowDevHTTP)
	if err != nil {
		return FailedResult(task, "ACTION_HTTP_ERROR", err.Error())
	}
	patchPayload := map[string]any{
		"statusCode": execRes.StatusCode,
		"vars":       execRes.ExtractedVars,
	}
	patchBytes, err := json.Marshal(patchPayload)
	if err != nil {
		return FailedResult(task, "ACTION_MARSHAL_ERROR", fmt.Sprintf("marshal envelope patch: %v", err))
	}
	previewBytes, err := json.Marshal(map[string]any{
		"statusCode":    execRes.StatusCode,
		"extractedVars": execRes.ExtractedVars,
		"previewBody":   execRes.PreviewBody,
	})
	if err != nil {
		return FailedResult(task, "ACTION_MARSHAL_ERROR", fmt.Sprintf("marshal action preview: %v", err))
	}
	return &secflowv1.NodeResult{
		NodeRunId:           task.GetNodeRunId(),
		RunId:               task.GetRunId(),
		NodeId:              task.GetNodeId(),
		PluginId:            task.GetPluginId(),
		Status:              secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		EnvelopePatchJson:   patchBytes,
		RedactedPreviewJson: previewBytes,
		ActiveOutputPorts:   []string{"default"},
	}
}
