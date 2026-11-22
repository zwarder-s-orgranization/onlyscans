package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/declarativeplugin"
	"github.com/secflow/secflow/services/internal/declruntime"
)

func TestMigrations005_LFOnlyAndContainsDeclarativeAndSavedNodes(t *testing.T) {
	t.Parallel()

	rawBytes, err := os.ReadFile(filepath.Join("migrations", "005_declarative_plugins_and_saved_nodes.sql"))
	if err != nil {
		t.Fatalf("read 005_declarative_plugins_and_saved_nodes.sql: %v", err)
	}
	raw := string(rawBytes)
	if strings.Contains(raw, "\r\n") {
		t.Fatal("005_declarative_plugins_and_saved_nodes.sql contains CRLF; LF only is mandatory")
	}
	for _, want := range []string{
		"'DECLARATIVE'",
		"'DRAFT'",
		"declarative_spec_json",
		"pending_declarative_spec_json",
		"idx_plugin_installations_declarative_plugin_id",
		"CREATE TABLE IF NOT EXISTS saved_nodes",
		"UNIQUE (plugin_id, canonical_params_hash)",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("005 migration missing %q", want)
		}
	}

	files, err := loadMigrationFiles()
	if err != nil {
		t.Fatalf("loadMigrationFiles: %v", err)
	}
	found := false
	for _, mf := range files {
		if mf.version == "005_declarative_plugins_and_saved_nodes" {
			found = true
			if strings.Contains(mf.sql, "DROP TABLE IF EXISTS saved_nodes") {
				t.Fatal("stripGoose did not stop at -- +goose Down")
			}
		}
	}
	if !found {
		t.Fatal("005_declarative_plugins_and_saved_nodes missing from loadMigrationFiles")
	}
}

func TestDeclarativePlugin_EndToEndHotReloadAndRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Create temporary target repository for ANALYZER scan.
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "application.yml"), []byte("management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Start local HTTP target for ACTION plugin (also verifies dry-run never hits it).
	var actionHits atomic.Int32
	var gotAuth atomic.Value
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actionHits.Add(1)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ticket":{"key":"APPSEC-77"}}`))
	}))
	defer httpSrv.Close()

	// Start in-process orchestrator gRPC server.
	srv := newServer()
	srv.startPump(ctx)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	secflowv1.RegisterWorkflowServiceServer(gs, srv)
	secflowv1.RegisterRunServiceServer(gs, srv)
	secflowv1.RegisterPluginRegistryServiceServer(gs, srv)
	secflowv1.RegisterSecretServiceServer(gs, srv)
	secflowv1.RegisterWorkerServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	// Start BOTH live declarative runtime pools BEFORE creating any Declarative Plugins,
	// proving sub-second live hot-reload via WatchPluginInstallations!
	internalSynced := make(chan []string, 16)
	actionSynced := make(chan []string, 16)
	go func() {
		_ = declruntime.Run(ctx, declruntime.Config{
			OrchestratorAddr: lis.Addr().String(),
			WorkerID:         "runtime-internal-1",
			ServiceToken:     srv.serviceTK,
			Tier:             declruntime.TierInternal,
			OnSynced: func(pids []string) {
				select {
				case internalSynced <- pids:
				default:
				}
			},
			HandleTask: func(taskCtx context.Context, _ *grpc.ClientConn, entry declruntime.SpecEntry, task *secflowv1.NodeTask) *secflowv1.NodeResult {
				return declruntime.HandleInternalTask(taskCtx, entry, task, func(context.Context, []byte) (string, func()) {
					return repoDir, func() {}
				})
			},
		})
	}()
	go func() {
		_ = declruntime.Run(ctx, declruntime.Config{
			OrchestratorAddr: lis.Addr().String(),
			WorkerID:         "runtime-action-1",
			ServiceToken:     srv.serviceTK,
			Tier:             declruntime.TierAction,
			OnSynced: func(pids []string) {
				select {
				case actionSynced <- pids:
				default:
				}
			},
			HandleTask: func(taskCtx context.Context, conn *grpc.ClientConn, entry declruntime.SpecEntry, task *secflowv1.NodeTask) *secflowv1.NodeResult {
				return declruntime.HandleActionTask(taskCtx, conn, entry, task, true)
			},
		})
	}()

	// Wait for initial handshake of both pools.
	select {
	case <-internalSynced:
	case <-ctx.Done():
		t.Fatal("timed out waiting for internal runtime sync")
	}
	select {
	case <-actionSynced:
	case <-ctx.Done():
		t.Fatal("timed out waiting for action runtime sync")
	}

	editor := &secflowv1.ActorContext{Subject: "dev@corp", Role: secflowv1.Role_ROLE_EDITOR, AuthMode: secflowv1.AuthMode_AUTH_MODE_LOCAL}
	owner := &secflowv1.ActorContext{Subject: "owner@corp", Role: secflowv1.Role_ROLE_OWNER, AuthMode: secflowv1.AuthMode_AUTH_MODE_LOCAL}
	viewer := &secflowv1.ActorContext{Subject: "view@corp", Role: secflowv1.Role_ROLE_VIEWER, AuthMode: secflowv1.AuthMode_AUTH_MODE_LOCAL}

	// 1. Create ANALYZER draft as EDITOR, verify Test Bench, reject VIEWER, reject duplicate plugin_id.
	analyzerSpec := declarativeplugin.StarterBlueprints()[0].Spec
	analyzerSpecRaw, _ := json.Marshal(analyzerSpec)

	if _, err := srv.TestDeclarativePlugin(ctx, &secflowv1.TestDeclarativePluginRequest{
		Actor:               viewer,
		DeclarativeSpecJson: analyzerSpecRaw,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer TestDeclarativePlugin code = %v, want PermissionDenied", status.Code(err))
	}

	tbResp, err := srv.TestDeclarativePlugin(ctx, &secflowv1.TestDeclarativePluginRequest{
		Actor:               editor,
		DeclarativeSpecJson: analyzerSpecRaw,
		Files: []*secflowv1.VirtualFile{
			{Path: "application.yml", Content: "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n"},
		},
	})
	if err != nil || !tbResp.GetOk() || len(tbResp.GetFindings()) < 1 {
		t.Fatalf("TestDeclarativePlugin analyzer failed: err=%v resp=%+v", err, tbResp)
	}

	instAn, err := srv.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:               editor,
		Name:                "spring-guard-decl",
		SourceMode:          secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE,
		DeclarativeSpecJson: analyzerSpecRaw,
		SaveAsDraft:         true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin analyzer draft: %v", err)
	}
	if instAn.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DRAFT {
		t.Fatalf("status = %v, want DRAFT", instAn.GetInstallation().GetStatus())
	}

	// Duplicate plugin_id must be rejected even while first is DRAFT.
	if _, err := srv.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:               owner,
		Name:                "spring-guard-dup",
		SourceMode:          secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE,
		DeclarativeSpecJson: analyzerSpecRaw,
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate plugin_id code = %v, want AlreadyExists", status.Code(err))
	}

	// ValidateWorkflow must block DRAFT / unsaved custom.* nodes.
	valDraft, err := srv.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{
		Actor: editor,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual"},
				{Id: "s1", PluginId: "source.upload"},
				{Id: "a1", PluginId: analyzerSpec.PluginID},
				{Id: "u1", PluginId: "custom.scan.never-saved"},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", TargetNodeId: "s1"},
				{Id: "e2", SourceNodeId: "s1", TargetNodeId: "a1"},
				{Id: "e3", SourceNodeId: "s1", TargetNodeId: "u1"},
			},
		},
	})
	if err != nil || valDraft.GetValid() {
		t.Fatalf("expected ValidateWorkflow to reject draft/unsaved custom.* nodes: valid=%v issues=%+v", valDraft.GetValid(), valDraft.GetIssues())
	}

	// EDITOR cannot approve, OWNER approves.
	if _, err := srv.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor:          editor,
		InstallationId: instAn.GetInstallation().GetId(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("editor Approve code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := srv.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor:          owner,
		InstallationId: instAn.GetInstallation().GetId(),
	}); err != nil {
		t.Fatalf("owner approve analyzer: %v", err)
	}

	// 2. Create and 1-click activate LOGIC plugin as OWNER.
	logicSpec := declarativeplugin.StarterBlueprints()[1].Spec
	logicSpec.Params[0].Default = 5 // blockThreshold = 5 so 1 HIGH (5 pts) triggers BLOCK!
	logicSpecRaw, _ := json.Marshal(logicSpec)
	if _, err := srv.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:               owner,
		Name:                "weighted-risk-decl",
		SourceMode:          secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE,
		DeclarativeSpecJson: logicSpecRaw,
		AutoApprove:         true,
	}); err != nil {
		t.Fatalf("InstallPlugin logic auto-approve: %v", err)
	}

	// 3. Create secret and ACTION plugin (verify offline dry-run does NOT hit httpSrv).
	secResp, err := srv.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Actor:          owner,
		Name:           "tracker-token",
		Kind:           secflowv1.SecretKind_SECRET_KIND_GENERIC,
		PlaintextValue: "live-tracker-secret-99",
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	actionHost := strings.TrimPrefix(httpSrv.URL, "http://")
	actionSpec := declarativeplugin.Spec{
		PluginID:           "custom.action.notify-tracker",
		Version:            "1.0.0",
		DisplayName:        "Notify Tracker",
		Category:           declarativeplugin.CategoryAction,
		RequiredSecretKeys: []string{"apiToken"},
		EgressAllowlist:    []string{actionHost},
		Action: &declarativeplugin.ActionSpec{
			Method:           "POST",
			URL:              httpSrv.URL + "/tickets",
			Headers:          map[string]string{"Authorization": "Bearer {{ secrets.apiToken }}"},
			BodyTemplate:     `{"findings":"{{ envelope.stats.total }}"}`,
			ExpectedStatuses: []int{201},
			TimeoutSeconds:   10,
			ExtractVars:      map[string]string{"ticketKey": "ticket.key"},
		},
	}
	actionSpecRaw, _ := json.Marshal(actionSpec)
	// Without ALLOW_DEV_EGRESS_LOCAL, offline dry-run and InstallPlugin must both reject loopback/HTTP targets.
	dryBlocked, err := srv.TestDeclarativePlugin(ctx, &secflowv1.TestDeclarativePluginRequest{
		Actor:               editor,
		DeclarativeSpecJson: actionSpecRaw,
	})
	if err != nil || dryBlocked.GetOk() {
		t.Fatalf("expected offline dry-run to reject http://127.0.0.1 without dev flag: err=%v resp=%+v", err, dryBlocked)
	}
	if _, err := srv.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:               owner,
		Name:                "notify-tracker-blocked",
		SourceMode:          secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE,
		DeclarativeSpecJson: actionSpecRaw,
		AutoApprove:         true,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected loopback egress rejection without dev flag, got %v", err)
	}
	t.Setenv("ALLOW_DEV_EGRESS_LOCAL", "1")

	dryAction, err := srv.TestDeclarativePlugin(ctx, &secflowv1.TestDeclarativePluginRequest{
		Actor:               editor,
		DeclarativeSpecJson: actionSpecRaw,
	})
	if err != nil || !dryAction.GetOk() {
		t.Fatalf("TestDeclarativePlugin action dry-run failed: err=%v resp=%+v", err, dryAction)
	}
	if actionHits.Load() != 0 {
		t.Fatalf("offline dry-run must not hit network, got %d hits", actionHits.Load())
	}

	if _, err := srv.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:               owner,
		Name:                "notify-tracker-decl",
		SourceMode:          secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE,
		DeclarativeSpecJson: actionSpecRaw,
		AutoApprove:         true,
	}); err != nil {
		t.Fatalf("InstallPlugin action auto-approve: %v", err)
	}

	// Wait until all 3 declarative plugins are registered as live workers on orchestrator (< 2s).
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if srv.activeWorkerCount(analyzerSpec.PluginID) > 0 &&
			srv.activeWorkerCount(logicSpec.PluginID) > 0 &&
			srv.activeWorkerCount(actionSpec.PluginID) > 0 {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if srv.activeWorkerCount(analyzerSpec.PluginID) == 0 ||
		srv.activeWorkerCount(logicSpec.PluginID) == 0 ||
		srv.activeWorkerCount(actionSpec.PluginID) == 0 {
		t.Fatalf("workers did not hot-reload in time: an=%d log=%d act=%d",
			srv.activeWorkerCount(analyzerSpec.PluginID),
			srv.activeWorkerCount(logicSpec.PluginID),
			srv.activeWorkerCount(actionSpec.PluginID))
	}

	// 4. Execute a real Workflow Run chaining ANALYZER -> LOGIC -> BLOCK(ACTION) vs OK(SKIPPED)!
	srcParams, _ := json.Marshal(map[string]string{"sourceId": repoDir})
	wfResp, err := srv.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Actor: owner,
		Name:  "Declarative E2E",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "trig", PluginId: "trigger.manual"},
				{Id: "src", PluginId: "source.upload", ParamsJson: srcParams},
				{Id: "scan", PluginId: analyzerSpec.PluginID, ParamsJson: []byte(`{"severity":"HIGH","checkSecurityPolicy":true}`)},
				{Id: "route", PluginId: logicSpec.PluginID, ParamsJson: []byte(`{"blockThreshold":5,"reviewThreshold":2}`)},
				{
					Id:             "act_block",
					PluginId:       actionSpec.PluginID,
					SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "apiToken", SecretRef: secResp.GetSecret().GetSecretRef()}},
				},
				{Id: "ok_branch", PluginId: "logic.merge"},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "trig", SourceHandle: "default", TargetNodeId: "src"},
				{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "scan"},
				{Id: "e3", SourceNodeId: "scan", SourceHandle: "default", TargetNodeId: "route"},
				{Id: "e4", SourceNodeId: "route", SourceHandle: "BLOCK", TargetNodeId: "act_block"},
				{Id: "e5", SourceNodeId: "route", SourceHandle: "OK", TargetNodeId: "ok_branch"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	startResp, err := srv.StartRun(ctx, &secflowv1.StartRunRequest{
		Actor:            owner,
		WorkflowId:       wfResp.GetWorkflow().GetId(),
		SourceIdOverride: repoDir,
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}

	runID := startResp.GetRun().GetId()
	var finalRun *secflowv1.Run
	runDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(runDeadline) {
		got, gErr := srv.GetRun(ctx, &secflowv1.GetRunRequest{Actor: owner, RunId: runID})
		if gErr == nil {
			st := got.GetRun().GetStatus()
			if st == secflowv1.RunStatus_RUN_STATUS_SUCCEEDED || st == secflowv1.RunStatus_RUN_STATUS_FAILED {
				finalRun = got.GetRun()
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if finalRun == nil || finalRun.GetStatus() != secflowv1.RunStatus_RUN_STATUS_SUCCEEDED {
		t.Fatalf("run did not succeed: %+v", finalRun)
	}

	// Verify Run Findings + Submission Report contain the ANALYZER findings.
	findingsResp, err := srv.ListFindings(ctx, &secflowv1.ListFindingsRequest{Actor: owner, RunId: runID})
	if err != nil || len(findingsResp.GetFindings()) < 2 {
		t.Fatalf("expected >= 2 Run Findings from declarative ANALYZER, got %d (err=%v)", len(findingsResp.GetFindings()), err)
	}
	subResp, err := srv.GetSubmissionReport(ctx, &secflowv1.GetSubmissionReportRequest{Actor: owner, RunId: runID})
	if err != nil || subResp.GetFindingCount() < 2 || !strings.Contains(string(subResp.GetSubmissionJson()), "SPRING-ACTUATOR-WILDCARD") {
		t.Fatalf("Submission Report missing declarative finding: err=%v count=%d body=%s", err, subResp.GetFindingCount(), string(subResp.GetSubmissionJson()))
	}

	// Verify ACTION fired with resolved secret and OK branch was SKIPPED.
	if actionHits.Load() != 1 {
		t.Fatalf("expected ACTION to fire once, got %d", actionHits.Load())
	}
	if gotAuth.Load() != "Bearer live-tracker-secret-99" {
		t.Fatalf("ACTION Authorization header = %v", gotAuth.Load())
	}
	var okSkipped, actSucceeded bool
	for _, nr := range finalRun.GetNodeRuns() {
		if nr.GetNodeId() == "ok_branch" && nr.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_SKIPPED {
			okSkipped = true
		}
		if nr.GetNodeId() == "act_block" && nr.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			actSucceeded = true
		}
	}
	if !okSkipped || !actSucceeded {
		t.Fatalf("branch routing mismatch: okSkipped=%v actSucceeded=%v", okSkipped, actSucceeded)
	}

	// 5. Non-destructive pending revision when EDITOR edits an ACTIVE Declarative Plugin.
	updatedSpec := analyzerSpec
	updatedSpec.Description = "Updated by editor while ACTIVE"
	updatedSpecRaw, _ := json.Marshal(updatedSpec)
	updResp, err := srv.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
		Actor:               editor,
		InstallationId:      instAn.GetInstallation().GetId(),
		DeclarativeSpecJson: updatedSpecRaw,
	})
	if err != nil {
		t.Fatalf("editor UpdatePluginInstallation: %v", err)
	}
	if updResp.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE {
		t.Fatalf("editor edit should keep ACTIVE plugin running non-destructively, got %v", updResp.GetInstallation().GetStatus())
	}
	if len(updResp.GetInstallation().GetPendingDeclarativeSpecJson()) == 0 {
		t.Fatal("expected pending_declarative_spec_json to be populated")
	}
	if updResp.GetInstallation().GetPluginVersion() != "1.0.0" {
		t.Fatalf("live plugin_version should stay 1.0.0 while pending, got %q", updResp.GetInstallation().GetPluginVersion())
	}
	if len(updResp.GetInstallation().GetPendingManifests()) == 0 || updResp.GetInstallation().GetPendingManifests()[0].GetVersion() != "1.0.1" {
		t.Fatalf("expected pending manifest version 1.0.1, got %v", updResp.GetInstallation().GetPendingManifests())
	}

	// OWNER approves the pending revision cleanly.
	appRev, err := srv.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor:          owner,
		InstallationId: instAn.GetInstallation().GetId(),
	})
	if err != nil {
		t.Fatalf("owner approve pending revision: %v", err)
	}
	if appRev.GetInstallation().GetPluginVersion() != "1.0.1" {
		t.Fatalf("approved plugin_version = %q, want 1.0.1", appRev.GetInstallation().GetPluginVersion())
	}
	if len(appRev.GetInstallation().GetPendingDeclarativeSpecJson()) != 0 {
		t.Fatal("pending_declarative_spec_json should be cleared after approval")
	}
	if !strings.Contains(string(appRev.GetInstallation().GetDeclarativeSpecJson()), "Updated by editor") {
		t.Fatal("active declarative_spec_json was not updated on approval")
	}

	// Ensure non-DECLARATIVE installation cannot be modified by an EDITOR passing declarative_spec_json.
	presetInst, err := srv.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:          owner,
		Name:           "preset-guard-check",
		SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
	})
	if err != nil {
		t.Fatalf("install external pull for rbac check: %v", err)
	}
	if _, err := srv.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
		Actor:               editor,
		InstallationId:      presetInst.GetInstallation().GetId(),
		DeclarativeSpecJson: updatedSpecRaw,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("editor updating non-declarative installation got %v, want PermissionDenied", status.Code(err))
	}

	// Ensure unused dial option import stays clean if needed.
	_ = insecure.NewCredentials
}

func TestSavedNode_CRUDStripSecretsAndDeduplicate(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	srv := newServer()

	editor := &secflowv1.ActorContext{Subject: "dev@corp", Role: secflowv1.Role_ROLE_EDITOR, AuthMode: secflowv1.AuthMode_AUTH_MODE_LOCAL}
	viewer := &secflowv1.ActorContext{Subject: "view@corp", Role: secflowv1.Role_ROLE_VIEWER, AuthMode: secflowv1.AuthMode_AUTH_MODE_LOCAL}
	scoped := &secflowv1.ActorContext{Subject: "ci-bot", AuthMode: secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN}

	if _, err := srv.SaveNode(ctx, &secflowv1.SaveNodeRequest{
		Actor: viewer, Name: "Blocked", PluginId: "logic.filter", ParamsJson: []byte(`{"minSeverity":"HIGH"}`),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer SaveNode code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := srv.SaveNode(ctx, &secflowv1.SaveNodeRequest{
		Actor: scoped, Name: "Blocked", PluginId: "logic.filter", ParamsJson: []byte(`{"minSeverity":"HIGH"}`),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("scoped SaveNode code = %v, want PermissionDenied", status.Code(err))
	}

	saved, err := srv.SaveNode(ctx, &secflowv1.SaveNodeRequest{
		Actor:       editor,
		Name:        "High+Critical Filter",
		Description: "Reusable severity filter",
		PluginId:    "logic.filter",
		ParamsJson:  []byte(`{"minSeverity":"HIGH","webhookSecret":"do-not-save","secretRef":"sec_1"}`),
	})
	if err != nil {
		t.Fatalf("SaveNode: %v", err)
	}
	if strings.Contains(string(saved.GetSavedNode().GetParamsJson()), "do-not-save") ||
		strings.Contains(string(saved.GetSavedNode().GetParamsJson()), "sec_1") {
		t.Fatalf("secrets leaked in saved node params: %s", string(saved.GetSavedNode().GetParamsJson()))
	}

	// Duplicate with identical canonical params (different spacing/key order) MUST fail with AlreadyExists.
	if _, err := srv.SaveNode(ctx, &secflowv1.SaveNodeRequest{
		Actor:      editor,
		Name:       "Duplicate Filter",
		PluginId:   "logic.filter",
		ParamsJson: []byte(`{ "minSeverity": "HIGH" }`),
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate SaveNode code = %v, want AlreadyExists", status.Code(err))
	}

	// Update existing Saved Node cleanly without duplicating.
	updated, err := srv.UpdateSavedNode(ctx, &secflowv1.UpdateSavedNodeRequest{
		Actor:      editor,
		Id:         saved.GetSavedNode().GetId(),
		Name:       "Critical Only Filter",
		ParamsJson: []byte(`{"minSeverity":"CRITICAL"}`),
	})
	if err != nil {
		t.Fatalf("UpdateSavedNode: %v", err)
	}
	if updated.GetSavedNode().GetName() != "Critical Only Filter" {
		t.Fatalf("updated name = %q", updated.GetSavedNode().GetName())
	}

	list, err := srv.ListSavedNodes(ctx, &secflowv1.ListSavedNodesRequest{Actor: viewer})
	if err != nil || len(list.GetSavedNodes()) != 1 {
		t.Fatalf("ListSavedNodes = %d (err=%v), want 1", len(list.GetSavedNodes()), err)
	}

	del, err := srv.DeleteSavedNode(ctx, &secflowv1.DeleteSavedNodeRequest{Actor: editor, Id: saved.GetSavedNode().GetId()})
	if err != nil || !del.GetDeleted() {
		t.Fatalf("DeleteSavedNode failed: %v", err)
	}
}
