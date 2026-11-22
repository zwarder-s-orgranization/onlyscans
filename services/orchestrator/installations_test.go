package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/riskrouter"
	"github.com/secflow/secflow/services/internal/springscan"
	"github.com/secflow/secflow/services/internal/workerclient"
)

func TestMigrations004_LFOnlyAndContainsInstallationsSchema(t *testing.T) {
	t.Parallel()

	rawBytes, err := os.ReadFile(filepath.Join("migrations", "004_plugin_installations.sql"))
	if err != nil {
		t.Fatalf("read 004_plugin_installations.sql: %v", err)
	}
	raw := string(rawBytes)
	if strings.Contains(raw, "\r\n") {
		t.Fatal("004_plugin_installations.sql contains CRLF; LF only is mandatory for stripGoose")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS plugin_installations",
		"token_hash bytea",
		"idx_plugin_installations_token_hash",
		"ALTER TABLE plugins ADD COLUMN IF NOT EXISTS installation_id",
		"ALTER TABLE plugins ADD COLUMN IF NOT EXISTS enabled",
		"ALTER TABLE plugins ADD COLUMN IF NOT EXISTS approval_state",
		"ALTER TABLE plugins ADD COLUMN IF NOT EXISTS active_workers",
		"ALTER TABLE plugins ADD COLUMN IF NOT EXISTS registered_at",
		"pg_notify(\n        'plugin_events'",
		"pg_notify(\n            'plugin_provision_jobs'",
		"secflow.notify_origin",
		"IF TG_OP = 'DELETE' THEN",
		"ELSIF TG_OP = 'INSERT' THEN",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("004_plugin_installations.sql missing %q", want)
		}
	}
	for _, forbidden := range []string{"COALESCE(NEW", "COALESCE(OLD"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("004_plugin_installations.sql must not contain %q (breaks INSERT/DELETE triggers)", forbidden)
		}
	}

	files, err := loadMigrationFiles()
	if err != nil {
		t.Fatalf("loadMigrationFiles: %v", err)
	}
	var m004 *migrationFile
	for i := range files {
		if files[i].version == "004_plugin_installations" {
			m004 = &files[i]
			break
		}
	}
	if m004 == nil {
		t.Fatal("004_plugin_installations missing from loadMigrationFiles")
	}
	if strings.Contains(m004.sql, "DROP TABLE IF EXISTS plugin_installations") {
		t.Fatal("stripGoose did not stop at -- +goose Down")
	}
}

func TestListPluginPresets_SpringConfigHardening(t *testing.T) {
	t.Parallel()
	s := newServer()

	resp, err := s.ListPluginPresets(t.Context(), &secflowv1.ListPluginPresetsRequest{})
	if err != nil {
		t.Fatalf("ListPluginPresets: %v", err)
	}
	var found *secflowv1.PluginPreset
	for _, p := range resp.GetPresets() {
		if p.GetId() == "spring-config-hardening" {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatal("spring-config-hardening preset missing")
	}
	if found.GetCategory() != secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER ||
		found.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY ||
		!found.GetAutoApproveSupported() {
		t.Fatalf("unexpected preset metadata: %+v", found)
	}
	if strings.Contains(found.GetImageRef(), ":latest") || found.GetImageRef() == "" {
		t.Fatalf("preset image_ref must be pinned SemVer, got %q", found.GetImageRef())
	}
	if len(found.GetPluginIds()) != 1 || found.GetPluginIds()[0] != "scan.spring-config" {
		t.Fatalf("preset plugin_ids = %v, want [scan.spring-config]", found.GetPluginIds())
	}
}

func TestInstallPlugin_ModesValidationRBACAndApproval(t *testing.T) {
	t.Parallel()
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	t.Run("RBAC blocks non-owner and scoped token", func(t *testing.T) {
		t.Parallel()
		s := newServer()
		for _, actor := range []*secflowv1.ActorContext{
			{Subject: "viewer@secflow.local", Role: secflowv1.Role_ROLE_VIEWER},
			{Subject: "editor@secflow.local", Role: secflowv1.Role_ROLE_EDITOR},
			{Subject: "ci_tok", AuthMode: secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN, Scopes: []string{"ci:startRun"}},
		} {
			_, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
				Actor:      actor,
				Name:       "denied",
				SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("actor %+v got err=%v, want PermissionDenied", actor, err)
			}
		}
	})

	t.Run("preset auto_approve activates and registers schema-valid plugin", func(t *testing.T) {
		t.Parallel()
		s := newServer()
		resp, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:          owner,
			Name:           "spring-preset",
			SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET,
			PresetId:       "spring-config-hardening",
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
			AutoApprove:    true,
		})
		if err != nil {
			t.Fatalf("InstallPlugin preset: %v", err)
		}
		if resp.GetPlaintextPluginToken() != "" {
			t.Fatalf("preset install must not return plaintext_plugin_token, got %q", resp.GetPlaintextPluginToken())
		}
		inst := resp.GetInstallation()
		if inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE {
			t.Fatalf("status = %v, want ACTIVE", inst.GetStatus())
		}
		plugResp, err := s.GetPlugin(t.Context(), &secflowv1.GetPluginRequest{PluginId: "scan.spring-config"})
		if err != nil {
			t.Fatalf("GetPlugin(scan.spring-config): %v", err)
		}
		rp := plugResp.GetPlugin()
		if !rp.GetEnabled() || rp.GetInstallationId() != inst.GetId() || rp.GetApprovalPending() {
			t.Fatalf("unexpected RegisteredPlugin: %+v", rp)
		}
		if err := paramschema.CheckSchema("scan.spring-config", rp.GetManifest().GetParamsJsonSchema(), map[string]any{}); err != nil {
			t.Fatalf("preset schema check failed: %v", err)
		}
	})

	t.Run("preset mismatch, denylist, SSRF, and OCI auto-approve guard", func(t *testing.T) {
		t.Parallel()
		s := newServer()

		_, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:          owner,
			Name:           "bad-preset-profile",
			SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET,
			PresetId:       "spring-config-hardening",
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SANDBOX_PROFILE_MISMATCH") {
			t.Fatalf("preset profile mismatch err=%v", err)
		}

		_, err = s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:      owner,
			Name:       "semgrep-scanner",
			SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_OCI_IMAGE,
			ImageRef:   "ghcr.io/example/semgrep:1.0.0",
		})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "DENYLIST_BLOCKED") {
			t.Fatalf("denylist install err=%v", err)
		}

		_, err = s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:           owner,
			Name:            "ssrf-egress",
			SourceMode:      secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			SandboxProfile:  secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
			EgressAllowlist: []string{"169.254.169.254"},
		})
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "ALLOWLIST_DENIED") {
			t.Fatalf("ssrf allowlist err=%v", err)
		}

		ociResp, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:          owner,
			Name:           "custom-oci",
			SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_OCI_IMAGE,
			ImageRef:       "ghcr.io/secflow/custom:1.2.3",
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
			AutoApprove:    true,
		})
		if err != nil {
			t.Fatalf("OCI install err=%v", err)
		}
		if ociResp.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
			t.Fatalf("OCI status = %v, want PENDING_APPROVAL (auto_approve must be ignored)", ociResp.GetInstallation().GetStatus())
		}
	})
}

func TestConnect_ExternalHandshakeGuardsAndTokenAuth(t *testing.T) {
	t.Parallel()

	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	internalInst, err := plugCli.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
		Actor:          owner,
		Name:           "ext-internal",
		SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		AutoApprove:    true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	token := internalInst.GetPlaintextPluginToken()
	if !strings.HasPrefix(token, pluginTokenPrefix) {
		t.Fatalf("unexpected token %q", token)
	}

	connectAndSend := func(ctx context.Context, m *secflowv1.PluginManifest) (*secflowv1.ManifestAck, error) {
		t.Helper()
		st, err := workerCli.Connect(ctx)
		if err != nil {
			return nil, err
		}
		if sendErr := st.Send(&secflowv1.ConnectRequest{
			Payload: &secflowv1.ConnectRequest_RegisterManifest{
				RegisterManifest: &secflowv1.WorkerRegisterManifest{
					WorkerInstanceId: "w-guard",
					Namespace:        "secflow-sandbox",
					Manifests:        []*secflowv1.PluginManifest{m},
				},
			},
		}); sendErr != nil && !errors.Is(sendErr, io.EOF) {
			return nil, sendErr
		}
		ackMsg, recvErr := st.Recv()
		if ackMsg != nil && ackMsg.GetManifestAck() != nil {
			_, _ = st.Recv()
			return ackMsg.GetManifestAck(), recvErr
		}
		return nil, recvErr
	}

	validExternal := &secflowv1.PluginManifest{
		PluginId:       "scan.custom-guard",
		Version:        "1.0.0",
		DisplayName:    "Custom Guard",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}

	// 1. Missing x-plugin-token on IsExternal=true.
	ack, err := connectAndSend(t.Context(), validExternal)
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED {
		t.Fatalf("missing token ack=%+v err=%v", ack, err)
	}

	// 2. Wrong x-plugin-token.
	badCtx := metadata.AppendToOutgoingContext(t.Context(), "x-plugin-token", "sf_plg_wrong")
	ack, err = connectAndSend(badCtx, validExternal)
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED {
		t.Fatalf("wrong token ack=%+v err=%v", ack, err)
	}

	authCtx := metadata.AppendToOutgoingContext(t.Context(), "x-plugin-token", token)

	// 3. Built-in override forbidden.
	builtinOverride := &secflowv1.PluginManifest{
		PluginId:       "scan.sca",
		Version:        "1.0.0",
		DisplayName:    "Fake SCA",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	ack, err = connectAndSend(authCtx, builtinOverride)
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_BUILTIN_OVERRIDE_FORBIDDEN {
		t.Fatalf("builtin override ack=%+v err=%v", ack, err)
	}

	// 4. External TRIGGER / SOURCE forbidden.
	for _, cat := range []secflowv1.PluginCategory{secflowv1.PluginCategory_PLUGIN_CATEGORY_TRIGGER, secflowv1.PluginCategory_PLUGIN_CATEGORY_SOURCE} {
		badCat := &secflowv1.PluginManifest{
			PluginId:       "custom.bad-cat",
			Version:        "1.0.0",
			Category:       cat,
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
			IsExternal:     true,
		}
		ack, err = connectAndSend(authCtx, badCat)
		if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNSUPPORTED_CATEGORY {
			t.Fatalf("category %v ack=%+v err=%v", cat, ack, err)
		}
	}

	// 5. ANALYZER with EGRESS_EXTERNAL or RequiredSecretKeys rejected.
	badAnalyzer := &secflowv1.PluginManifest{
		PluginId:       "scan.egress-bad",
		Version:        "1.0.0",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		IsExternal:     true,
	}
	ack, err = connectAndSend(authCtx, badAnalyzer)
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH {
		t.Fatalf("egress analyzer ack=%+v err=%v", ack, err)
	}

	// 6. ACTION with EGRESS_EXTERNAL on INTERNAL_ONLY installation rejected.
	badAction := &secflowv1.PluginManifest{
		PluginId:       "action.egress-bad",
		Version:        "1.0.0",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		IsExternal:     true,
	}
	ack, err = connectAndSend(authCtx, badAction)
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH {
		t.Fatalf("egress action on internal installation ack=%+v err=%v", ack, err)
	}

	// 7. Deny-list scanner rejected.
	deniedManifest := &secflowv1.PluginManifest{
		PluginId:       "scan.trivy-wrapper",
		Version:        "1.0.0",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	ack, err = connectAndSend(authCtx, deniedManifest)
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED {
		t.Fatalf("denylist ack=%+v err=%v", ack, err)
	}
}

func TestInstallationLifecycle_DrainEscalationDisableDeleteAndWatch(t *testing.T) {
	t.Parallel()

	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	wfCli := secflowv1.NewWorkflowServiceClient(conn)
	runCli := secflowv1.NewRunServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	watchStream, err := plugCli.WatchPluginInstallations(ctx, &secflowv1.WatchPluginInstallationsRequest{Actor: owner})
	if err != nil {
		t.Fatalf("WatchPluginInstallations: %v", err)
	}

	// Install EXTERNAL_PULL without auto-approve -> PENDING_APPROVAL.
	instResp, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:          owner,
		Name:           "lifecycle-plugin",
		SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		AutoApprove:    false,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	instID := instResp.GetInstallation().GetId()
	tok := instResp.GetPlaintextPluginToken()

	evCreated, err := watchStream.Recv()
	if err != nil || evCreated.GetEvent().GetEventType() != secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED {
		t.Fatalf("expected CREATED watch event, got %+v err=%v", evCreated, err)
	}

	m := &secflowv1.PluginManifest{
		PluginId:       "scan.lifecycle-check",
		Version:        "1.0.0",
		DisplayName:    "Lifecycle Check",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		Capabilities:   []string{"analyzer"},
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}

	authCtx := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", tok)

	// Worker connect before approval captures pending manifest and returns FailedPrecondition.
	stPending, err := workerCli.Connect(authCtx)
	if err != nil {
		t.Fatalf("Connect pending: %v", err)
	}
	_ = stPending.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: "lc-pending",
				Manifests:        []*secflowv1.PluginManifest{m},
			},
		},
	})
	if _, recvErr := stPending.Recv(); status.Code(recvErr) != codes.FailedPrecondition {
		t.Fatalf("pending Connect recv err = %v, want FailedPrecondition", recvErr)
	}

	// Owner approves installation -> ACTIVE.
	if _, err := plugCli.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor:          owner,
		InstallationId: instID,
	}); err != nil {
		t.Fatalf("ApprovePluginInstallation: %v", err)
	}

	// Worker connects now and stays open; we capture DrainRequest on disable.
	drainCh := make(chan *secflowv1.DrainRequest, 4)
	connectWorkerStream := func(token string) {
		t.Helper()
		wCtx := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", token)
		st, err := workerCli.Connect(wCtx)
		if err != nil {
			t.Fatalf("Connect active: %v", err)
		}
		if err := st.Send(&secflowv1.ConnectRequest{
			Payload: &secflowv1.ConnectRequest_RegisterManifest{
				RegisterManifest: &secflowv1.WorkerRegisterManifest{
					WorkerInstanceId: "lc-active",
					Manifests:        []*secflowv1.PluginManifest{m},
				},
			},
		}); err != nil {
			t.Fatalf("RegisterManifest: %v", err)
		}
		ack, err := st.Recv()
		if err != nil || !ack.GetManifestAck().GetAccepted() {
			t.Fatalf("ManifestAck failed: %+v err=%v", ack, err)
		}
		go func() {
			for {
				msg, rErr := st.Recv()
				if rErr != nil {
					return
				}
				if d := msg.GetDrainRequest(); d != nil {
					drainCh <- d
					return
				}
			}
		}()
	}

	connectWorkerStream(tok)

	// Disable installation -> DrainRequest sent, ListPlugins(include_disabled=false) hides it, ValidateWorkflow/StartRun emit PLUGIN_DISABLED.
	if _, err := plugCli.SetPluginInstallationEnabled(ctx, &secflowv1.SetPluginInstallationEnabledRequest{
		Actor:          owner,
		InstallationId: instID,
		Enabled:        false,
		Reason:         "maintenance",
	}); err != nil {
		t.Fatalf("SetPluginInstallationEnabled(false): %v", err)
	}
	select {
	case d := <-drainCh:
		if d.GetReason() != "maintenance" {
			t.Fatalf("drain reason = %q, want maintenance", d.GetReason())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DrainRequest on disable")
	}

	listNoDisabled, err := plugCli.ListPlugins(ctx, &secflowv1.ListPluginsRequest{IncludeDisabled: false})
	if err != nil {
		t.Fatalf("ListPlugins: %v", err)
	}
	for _, p := range listNoDisabled.GetPlugins() {
		if p.GetManifest().GetPluginId() == "scan.lifecycle-check" {
			t.Fatal("disabled plugin appeared in ListPlugins(include_disabled=false)")
		}
	}
	listWithDisabled, err := plugCli.ListPlugins(ctx, &secflowv1.ListPluginsRequest{IncludeDisabled: true})
	if err != nil {
		t.Fatalf("ListPlugins(include_disabled=true): %v", err)
	}
	var sawDisabledInList bool
	for _, p := range listWithDisabled.GetPlugins() {
		if p.GetManifest().GetPluginId() == "scan.lifecycle-check" && !p.GetEnabled() {
			sawDisabledInList = true
		}
	}
	if !sawDisabledInList {
		t.Fatal("disabled plugin missing or marked enabled in ListPlugins(include_disabled=true)")
	}

	wfGraph := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
			{Id: "src", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
			{Id: "lc", PluginId: "scan.lifecycle-check", ParamsJson: []byte(`{}`)},
		},
		Edges: []*secflowv1.WorkflowEdge{
			{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "src", TargetHandle: "default"},
			{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "lc", TargetHandle: "default"},
		},
	}
	createdWf, err := wfCli.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{Name: "LC Flow", Graph: wfGraph})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	valDis, err := wfCli.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{Graph: wfGraph})
	if err != nil || valDis.GetValid() || len(valDis.GetIssues()) == 0 || valDis.GetIssues()[0].GetCode() != engine.CodePluginDisabled {
		t.Fatalf("expected PLUGIN_DISABLED issue, got %+v err=%v", valDis, err)
	}
	if _, err := runCli.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: createdWf.GetWorkflow().GetId()}); err == nil || !strings.Contains(err.Error(), engine.CodePluginDisabled) {
		t.Fatalf("expected StartRun PLUGIN_DISABLED error, got %v", err)
	}

	// Re-enable -> ACTIVE, rotate token -> old token rejected, new token accepted.
	if _, err := plugCli.SetPluginInstallationEnabled(ctx, &secflowv1.SetPluginInstallationEnabledRequest{
		Actor:          owner,
		InstallationId: instID,
		Enabled:        true,
	}); err != nil {
		t.Fatalf("SetPluginInstallationEnabled(true): %v", err)
	}
	updResp, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
		Actor:          owner,
		InstallationId: instID,
		RotateToken:    true,
	})
	if err != nil || updResp.GetPlaintextPluginToken() == "" || updResp.GetPlaintextPluginToken() == tok {
		t.Fatalf("rotate token failed: resp=%+v err=%v", updResp, err)
	}
	newTok := updResp.GetPlaintextPluginToken()

	// Old token must fail.
	oldSt, _ := workerCli.Connect(authCtx)
	_ = oldSt.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{WorkerInstanceId: "old", Manifests: []*secflowv1.PluginManifest{m}},
		},
	})
	if ackOld, _ := oldSt.Recv(); ackOld.GetManifestAck().GetAccepted() || ackOld.GetManifestAck().GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED {
		t.Fatalf("old token should be rejected after rotation, got %+v", ackOld)
	}

	// New token connects cleanly.
	connectWorkerStream(newTok)

	// Privilege escalation: adding an extra plugin_id forces PENDING_APPROVAL and sends DrainRequest.
	escalated := &secflowv1.PluginManifest{
		PluginId:       "scan.escalated-extra",
		Version:        "1.0.0",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	escCtx := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", newTok)
	escSt, err := workerCli.Connect(escCtx)
	if err != nil {
		t.Fatalf("Connect escalated: %v", err)
	}
	_ = escSt.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: "lc-esc",
				Manifests:        []*secflowv1.PluginManifest{m, escalated},
			},
		},
	})
	if _, recvErr := escSt.Recv(); status.Code(recvErr) != codes.FailedPrecondition {
		t.Fatalf("escalation Connect err = %v, want FailedPrecondition", recvErr)
	}
	select {
	case <-drainCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DrainRequest on privilege escalation")
	}

	getAfterEsc, err := plugCli.GetPluginInstallation(ctx, &secflowv1.GetPluginInstallationRequest{InstallationId: instID})
	if err != nil || getAfterEsc.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
		t.Fatalf("expected PENDING_APPROVAL after escalation, got %+v err=%v", getAfterEsc, err)
	}

	// Delete installation -> removes plugin and causes PLUGIN_UNREGISTERED.
	delResp, err := plugCli.DeletePluginInstallation(ctx, &secflowv1.DeletePluginInstallationRequest{
		Actor:          owner,
		InstallationId: instID,
		Reason:         "cleanup",
	})
	if err != nil || !delResp.GetDeleted() {
		t.Fatalf("DeletePluginInstallation: resp=%+v err=%v", delResp, err)
	}
	valUnreg, err := wfCli.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{Graph: wfGraph})
	if err != nil || valUnreg.GetValid() || len(valUnreg.GetIssues()) == 0 || valUnreg.GetIssues()[0].GetCode() != engine.CodePluginUnregistered {
		t.Fatalf("expected PLUGIN_UNREGISTERED after delete, got %+v err=%v", valUnreg, err)
	}
}

func TestUpdatePluginInstallation_EscalationRulesAndRequiredSecrets(t *testing.T) {
	t.Parallel()

	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	instResp, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:           owner,
		Name:            "action-esc",
		SourceMode:      secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile:  secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		EgressAllowlist: []string{"api.example.com"},
		AutoApprove:     true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	instID := instResp.GetInstallation().GetId()
	tok := instResp.GetPlaintextPluginToken()

	actionManifest := &secflowv1.PluginManifest{
		PluginId:           "action.esc-notify",
		Version:            "1.0.0",
		DisplayName:        "Esc Notify",
		Category:           secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		RequiredSecretKeys: []string{"apiKey"},
		InputPorts:         []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:        []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile:     secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		IsExternal:         true,
	}

	wCtx := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", tok)
	st, err := workerCli.Connect(wCtx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := st.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: "esc-1",
				Manifests:        []*secflowv1.PluginManifest{actionManifest},
			},
		},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if ack, err := st.Recv(); err != nil || !ack.GetManifestAck().GetAccepted() {
		t.Fatalf("ManifestAck failed: %+v err=%v", ack, err)
	}

	// Expanding egress_allowlist triggers PENDING_APPROVAL and DrainRequest.
	updResp, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
		Actor:           owner,
		InstallationId:  instID,
		EgressAllowlist: []string{"api.example.com", "hooks.slack.com"},
	})
	if err != nil {
		t.Fatalf("UpdatePluginInstallation: %v", err)
	}
	if updResp.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
		t.Fatalf("status after allowlist expansion = %v, want PENDING_APPROVAL", updResp.GetInstallation().GetStatus())
	}
	msg, err := st.Recv()
	if err != nil || msg.GetDrainRequest() == nil {
		t.Fatalf("expected DrainRequest on allowlist expansion, got %+v err=%v", msg, err)
	}

	// Re-approve, then test new required_secret_keys escalation on Connect.
	if _, err := plugCli.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor:          owner,
		InstallationId: instID,
	}); err != nil {
		t.Fatalf("ApprovePluginInstallation: %v", err)
	}
	moreSecrets := &secflowv1.PluginManifest{
		PluginId:           "action.esc-notify",
		Version:            "1.0.0",
		DisplayName:        "Esc Notify",
		Category:           secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		RequiredSecretKeys: []string{"apiKey", "extraToken"},
		InputPorts:         []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:        []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile:     secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		IsExternal:         true,
	}
	st2, err := workerCli.Connect(wCtx)
	if err != nil {
		t.Fatalf("Connect 2: %v", err)
	}
	_ = st2.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: "esc-2",
				Manifests:        []*secflowv1.PluginManifest{moreSecrets},
			},
		},
	})
	if _, recvErr := st2.Recv(); status.Code(recvErr) != codes.FailedPrecondition {
		t.Fatalf("new required_secret_keys err = %v, want FailedPrecondition", recvErr)
	}
	gotInst, err := plugCli.GetPluginInstallation(ctx, &secflowv1.GetPluginInstallationRequest{InstallationId: instID})
	if err != nil || gotInst.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
		t.Fatalf("expected PENDING_APPROVAL after secret key escalation, got %+v err=%v", gotInst, err)
	}
}

func TestWorkerClient_ExternalPullWithSpringScanAndDrain(t *testing.T) {
	t.Parallel()

	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s.startPump(ctx)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	gs := grpc.NewServer()
	secflowv1.RegisterWorkerServiceServer(gs, s)
	secflowv1.RegisterPluginRegistryServiceServer(gs, s)
	go func() {
		_ = gs.Serve(lis)
	}()
	defer func() {
		gs.Stop()
		_ = lis.Close()
	}()

	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}
	instResp, err := s.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:          owner,
		Name:           "spring-ext-e2e",
		SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		AutoApprove:    true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	instID := instResp.GetInstallation().GetId()
	tok := instResp.GetPlaintextPluginToken()

	sampleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sampleDir, "application.yml"), []byte("spring:\n  datasource:\n    password: cleartext\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	springManifest := &secflowv1.PluginManifest{
		PluginId:       "scan.spring-config",
		Version:        "1.0.0",
		DisplayName:    "Spring Config Hardening",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		Capabilities:   []string{"analyzer"},
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}

	workerErrCh := make(chan error, 1)
	go func() {
		workerErrCh <- workerclient.RunWithConfig(ctx, workerclient.Config{
			Addr:             lis.Addr().String(),
			WorkerID:         "demo-spring-e2e",
			Namespace:        "secflow-sandbox",
			PluginToken:      tok,
			Manifests:        []*secflowv1.PluginManifest{springManifest},
			InitialBackoff:   10 * time.Millisecond,
			MaxBackoff:       50 * time.Millisecond,
			DefaultHeartbeat: 50 * time.Millisecond,
			Handle: func(_ context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
				if task.GetTaskLeaseToken() != "" {
					t.Errorf("INTERNAL_ONLY analyzer must not receive task_lease_token, got %q", task.GetTaskLeaseToken())
				}
				found := springscan.Scan(sampleDir)
				out := make([]*secflowv1.Finding, 0, len(found))
				for _, f := range found {
					line := int32(f.Line)
					out = append(out, &secflowv1.Finding{
						SourceNodeId: task.GetNodeId(),
						PluginId:     "scan.spring-config",
						Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
						Severity:     secflowv1.Severity_SEVERITY_HIGH,
						Path:         f.Path,
						FindingClass: f.Class,
						Line:         &line,
						Description:  f.Description,
					})
				}
				return &secflowv1.NodeResult{
					NodeRunId:         task.GetNodeRunId(),
					RunId:             task.GetRunId(),
					NodeId:            task.GetNodeId(),
					PluginId:          "scan.spring-config",
					Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
					Findings:          out,
					ActiveOutputPorts: []string{"default"},
				}
			},
		})
	}()

	// Wait until worker is ONLINE.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, gErr := s.GetPlugin(ctx, &secflowv1.GetPluginRequest{PluginId: "scan.spring-config"})
		if gErr == nil && resp.GetPlugin().GetStatus() == secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	gp, err := s.GetPlugin(ctx, &secflowv1.GetPluginRequest{PluginId: "scan.spring-config"})
	if err != nil || gp.GetPlugin().GetStatus() != secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE {
		t.Fatalf("worker did not come ONLINE: gp=%+v err=%v", gp, err)
	}

	// Execute a real run using scan.spring-config.
	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Spring E2E",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "src", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "sc", PluginId: "scan.spring-config", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "src", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "sc", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	runResp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wfResp.GetWorkflow().GetId()})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	waitForRunEvents(t, ctx, s, runResp.GetRun().GetId())

	findingsResp, err := s.ListFindings(ctx, &secflowv1.ListFindingsRequest{RunId: runResp.GetRun().GetId()})
	if err != nil || len(findingsResp.GetFindings()) != 1 || findingsResp.GetFindings()[0].GetFindingClass() != "plaintext-password" {
		t.Fatalf("ListFindings = %+v err=%v, want 1 plaintext-password", findingsResp, err)
	}

	// Disabling installation triggers DrainRequest and clean nil exit of workerclient.RunWithConfig.
	if _, err := s.SetPluginInstallationEnabled(ctx, &secflowv1.SetPluginInstallationEnabledRequest{
		Actor:          owner,
		InstallationId: instID,
		Enabled:        false,
		Reason:         "graceful drain test",
	}); err != nil {
		t.Fatalf("SetPluginInstallationEnabled(false): %v", err)
	}
	select {
	case wErr := <-workerErrCh:
		if wErr != nil {
			t.Fatalf("workerclient.RunWithConfig exited with %v, want nil on drain", wErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for workerclient clean drain exit")
	}
}

func TestInstallPlugin_StrictRBACAndDuplicatePresetOwnership(t *testing.T) {
	t.Parallel()
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	t.Run("nil and ROLE_UNSPECIFIED rejected on all mutating installation RPCs", func(t *testing.T) {
		t.Parallel()
		s := newServer()
		for _, actor := range []*secflowv1.ActorContext{
			nil,
			{Subject: "unknown@secflow.local", Role: secflowv1.Role_ROLE_UNSPECIFIED},
		} {
			if _, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
				Actor: actor, Name: "x", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("InstallPlugin(%+v) = %v, want PermissionDenied", actor, err)
			}
			if _, err := s.ApprovePluginInstallation(t.Context(), &secflowv1.ApprovePluginInstallationRequest{
				Actor: actor, InstallationId: "inst_1",
			}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("ApprovePluginInstallation(%+v) = %v, want PermissionDenied", actor, err)
			}
			if _, err := s.UpdatePluginInstallation(t.Context(), &secflowv1.UpdatePluginInstallationRequest{
				Actor: actor, InstallationId: "inst_1",
			}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("UpdatePluginInstallation(%+v) = %v, want PermissionDenied", actor, err)
			}
			if _, err := s.SetPluginInstallationEnabled(t.Context(), &secflowv1.SetPluginInstallationEnabledRequest{
				Actor: actor, InstallationId: "inst_1", Enabled: false,
			}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("SetPluginInstallationEnabled(%+v) = %v, want PermissionDenied", actor, err)
			}
			if _, err := s.DeletePluginInstallation(t.Context(), &secflowv1.DeletePluginInstallationRequest{
				Actor: actor, InstallationId: "inst_1",
			}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("DeletePluginInstallation(%+v) = %v, want PermissionDenied", actor, err)
			}
		}
	})

	t.Run("duplicate preset with auto_approve=true rejected", func(t *testing.T) {
		t.Parallel()
		s := newServer()
		_, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:       owner,
			Name:        "spring-1",
			SourceMode:  secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET,
			PresetId:    "spring-config-hardening",
			AutoApprove: true,
		})
		if err != nil {
			t.Fatalf("first preset install: %v", err)
		}
		_, err = s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:       owner,
			Name:        "spring-2",
			SourceMode:  secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET,
			PresetId:    "spring-config-hardening",
			AutoApprove: true,
		})
		if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "DUPLICATE_PLUGIN_ID") {
			t.Fatalf("second preset install err = %v, want AlreadyExists DUPLICATE_PLUGIN_ID", err)
		}
	})
}

func TestSSRFAllowlist_SupernetsIPv6MappedAndNonCanonical(t *testing.T) {
	t.Parallel()
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}
	blockedTargets := []string{
		"8.0.0.0/6",
		"172.0.0.0/11",
		"192.0.0.0/8",
		"169.252.0.0/14",
		"f000::/4",
		"[::ffff:127.0.0.1]",
		"[::ffff:169.254.169.254]",
		"http://[::ffff:127.0.0.1]/hook",
		"localhost.",
		"metadata.google.internal.",
		"kubernetes.default.svc.",
		"cluster.local",
		"home.arpa",
		"100.64.0.1",
		"127.0.1",
		"0177.0.0.1",
		"0x7f.0.0.1",
		"ftp://example.com/hook",
		"::127.0.0.1",
		"::169.254.169.254",
		"http://[::127.0.0.1]/hook",
		"::127.0.0.1/128",
	}

	s := newServer()
	for _, target := range blockedTargets {
		t.Run("blocked/"+target, func(t *testing.T) {
			t.Parallel()
			_, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
				Actor:           owner,
				Name:            "ssrf-" + target,
				SourceMode:      secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
				SandboxProfile:  secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
				EgressAllowlist: []string{target},
			})
			if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "ALLOWLIST_DENIED") {
				t.Fatalf("target %q err = %v, want PermissionDenied ALLOWLIST_DENIED", target, err)
			}
		})
	}

	t.Run("public CIDR and domain allowed", func(t *testing.T) {
		t.Parallel()
		_, err := s.InstallPlugin(t.Context(), &secflowv1.InstallPluginRequest{
			Actor:           owner,
			Name:            "valid-egress",
			SourceMode:      secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			SandboxProfile:  secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
			EgressAllowlist: []string{"151.101.0.0/16", "https://api.example.com/webhook", "hooks.slack.com:443"},
		})
		if err != nil {
			t.Fatalf("expected valid egress targets to pass, got %v", err)
		}
	})
}

func TestInstallationStateMachine_HardeningAndDowngrade(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	t.Run("EXTERNAL_PULL PENDING_APPROVAL disable then enable stays PENDING_APPROVAL", func(t *testing.T) {
		inst, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
			Actor:          owner,
			Name:           "ext-pending-bypass",
			SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
			AutoApprove:    false,
		})
		if err != nil {
			t.Fatalf("InstallPlugin: %v", err)
		}
		instID := inst.GetInstallation().GetId()
		if _, err := plugCli.SetPluginInstallationEnabled(ctx, &secflowv1.SetPluginInstallationEnabledRequest{
			Actor: owner, InstallationId: instID, Enabled: false,
		}); err != nil {
			t.Fatalf("disable: %v", err)
		}
		reEnabled, err := plugCli.SetPluginInstallationEnabled(ctx, &secflowv1.SetPluginInstallationEnabledRequest{
			Actor: owner, InstallationId: instID, Enabled: true,
		})
		if err != nil {
			t.Fatalf("enable: %v", err)
		}
		if reEnabled.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
			t.Fatalf("status = %v, want PENDING_APPROVAL", reEnabled.GetInstallation().GetStatus())
		}
	})

	t.Run("UpdatePluginInstallation rejects direct ACTIVE DISABLED DELETING and allows ERROR drain", func(t *testing.T) {
		preset, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
			Actor: owner, Name: "oci-state", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_OCI_IMAGE,
			ImageRef: "ghcr.io/secflow/plugin:1.0.0",
		})
		if err != nil {
			t.Fatalf("InstallPlugin OCI: %v", err)
		}
		ociID := preset.GetInstallation().GetId()
		for _, badStatus := range []secflowv1.PluginInstallationStatus{
			secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE,
			secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DISABLED,
			secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DELETING,
		} {
			_, uErr := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
				Actor: owner, InstallationId: ociID, Status: badStatus,
			})
			if status.Code(uErr) != codes.FailedPrecondition || !strings.Contains(uErr.Error(), "INVALID_STATE_TRANSITION") {
				t.Fatalf("UpdatePluginInstallation(%v) err = %v, want INVALID_STATE_TRANSITION", badStatus, uErr)
			}
		}

		// ERROR escalation resets approval.
		_, err = plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
			Actor: owner, InstallationId: ociID, Status: secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ERROR, StatusReason: "crash",
		})
		if err != nil {
			t.Fatalf("set ERROR: %v", err)
		}
		escResp, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
			Actor: owner, InstallationId: ociID, ImageRef: "ghcr.io/secflow/plugin:2.0.0",
		})
		if err != nil {
			t.Fatalf("escalate ERROR: %v", err)
		}
		if escResp.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
			t.Fatalf("status after ERROR escalation = %v, want PENDING_APPROVAL", escResp.GetInstallation().GetStatus())
		}
	})

	t.Run("PRESET ImageRef change escalates and EGRESS_EXTERNAL downgrade clears allowlist", func(t *testing.T) {
		pr, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
			Actor: owner, Name: "preset-esc", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET,
			PresetId: "spring-config-hardening", AutoApprove: true,
		})
		if err != nil {
			t.Fatalf("InstallPlugin preset: %v", err)
		}
		upd, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
			Actor: owner, InstallationId: pr.GetInstallation().GetId(), ImageRef: "evil.registry.io/backdoor:1.0.0",
		})
		if err != nil {
			t.Fatalf("UpdatePluginInstallation preset image: %v", err)
		}
		if upd.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL ||
			upd.GetInstallation().GetApprovedManifestDigest() != "" {
			t.Fatalf("expected PENDING_APPROVAL and cleared digest, got %+v", upd.GetInstallation())
		}

		ext, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
			Actor: owner, Name: "downgrade-egress", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, EgressAllowlist: []string{"api.example.com"}, AutoApprove: true,
		})
		if err != nil {
			t.Fatalf("InstallPlugin egress: %v", err)
		}
		down, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
			Actor: owner, InstallationId: ext.GetInstallation().GetId(), SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		})
		if err != nil {
			t.Fatalf("downgrade profile: %v", err)
		}
		if len(down.GetInstallation().GetEgressAllowlist()) != 0 {
			t.Fatalf("expected egress_allowlist cleared on downgrade, got %v", down.GetInstallation().GetEgressAllowlist())
		}
	})

	t.Run("ApprovePluginInstallation prunes stale plugin_ids", func(t *testing.T) {
		inst, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
			Actor: owner, Name: "prune-stale", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, AutoApprove: false,
		})
		if err != nil {
			t.Fatalf("InstallPlugin: %v", err)
		}
		instID := inst.GetInstallation().GetId()
		authCtx := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", inst.GetPlaintextPluginToken())
		m1 := &secflowv1.PluginManifest{
			PluginId: "scan.old-one", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
		}
		m2 := &secflowv1.PluginManifest{
			PluginId: "scan.new-one", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
			SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
		}
		st1, _ := workerCli.Connect(authCtx)
		_ = st1.Send(&secflowv1.ConnectRequest{Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{WorkerInstanceId: "p1", Manifests: []*secflowv1.PluginManifest{m1}},
		}})
		_, _ = st1.Recv()
		if _, err := plugCli.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{Actor: owner, InstallationId: instID}); err != nil {
			t.Fatalf("Approve 1: %v", err)
		}
		// Escalate with m2 only (removing m1), then approve.
		st2, _ := workerCli.Connect(authCtx)
		_ = st2.Send(&secflowv1.ConnectRequest{Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{WorkerInstanceId: "p2", Manifests: []*secflowv1.PluginManifest{m2}},
		}})
		_, _ = st2.Recv()
		if _, err := plugCli.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{Actor: owner, InstallationId: instID}); err != nil {
			t.Fatalf("Approve 2: %v", err)
		}
		if _, err := plugCli.GetPlugin(ctx, &secflowv1.GetPluginRequest{PluginId: "scan.old-one"}); status.Code(err) != codes.NotFound {
			t.Fatalf("stale plugin scan.old-one should be pruned, got err=%v", err)
		}
		if _, err := plugCli.GetPlugin(ctx, &secflowv1.GetPluginRequest{PluginId: "scan.new-one"}); err != nil {
			t.Fatalf("new plugin scan.new-one missing: %v", err)
		}
	})
}

func TestConnect_BypassHardeningRegression(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	egressInst, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "egress-hardening", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, EgressAllowlist: []string{"api.example.com"}, AutoApprove: true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	authCtx := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", egressInst.GetPlaintextPluginToken())

	sendReg := func(callCtx context.Context, ns string, m *secflowv1.PluginManifest) (*secflowv1.ManifestAck, error) {
		t.Helper()
		st, err := workerCli.Connect(callCtx)
		if err != nil {
			return nil, err
		}
		_ = st.Send(&secflowv1.ConnectRequest{
			Payload: &secflowv1.ConnectRequest_RegisterManifest{
				RegisterManifest: &secflowv1.WorkerRegisterManifest{
					WorkerInstanceId: "w-reg", Namespace: ns, Manifests: []*secflowv1.PluginManifest{m},
				},
			},
		})
		ackMsg, recvErr := st.Recv()
		if ackMsg != nil && ackMsg.GetManifestAck() != nil {
			return ackMsg.GetManifestAck(), recvErr
		}
		return nil, recvErr
	}

	// 1. ANALYZER on EGRESS_EXTERNAL rejected.
	ack, _ := sendReg(authCtx, "secflow-sandbox", &secflowv1.PluginManifest{
		PluginId: "scan.analyzer-on-egress", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH {
		t.Fatalf("ANALYZER on EGRESS_EXTERNAL ack=%+v, want SANDBOX_PROFILE_MISMATCH", ack)
	}

	// 2. Deny-list via \u0073emgrep, Namespace, RuntimeLanguage, Version, RequiredSecretKeys.
	denylistCases := []struct {
		name string
		ns   string
		m    *secflowv1.PluginManifest
	}{
		{
			name: "json unicode escape in params_json_schema",
			ns:   "secflow-sandbox",
			m: &secflowv1.PluginManifest{
				PluginId: "action.u-escape", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
				SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
				ParamsJsonSchema: []byte(`{"type":"object","description":"\u0073emgrep wrapper"}`),
			},
		},
		{
			name: "namespace denylist",
			ns:   "semgrep",
			m: &secflowv1.PluginManifest{
				PluginId: "action.ns-bad", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
				SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
			},
		},
		{
			name: "runtime language denylist",
			ns:   "secflow-sandbox",
			m: &secflowv1.PluginManifest{
				PluginId: "action.lang-bad", Version: "1.0.0", RuntimeLanguage: "semgrep",
				Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
			},
		},
		{
			name: "version denylist",
			ns:   "secflow-sandbox",
			m: &secflowv1.PluginManifest{
				PluginId: "action.ver-bad", Version: "1.0.0-trivy",
				Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
			},
		},
		{
			name: "required_secret_keys denylist",
			ns:   "secflow-sandbox",
			m: &secflowv1.PluginManifest{
				PluginId: "action.sec-bad", Version: "1.0.0", RequiredSecretKeys: []string{"semgrepApiKey"},
				Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
			},
		},
	}
	for _, tc := range denylistCases {
		ack, _ := sendReg(authCtx, tc.ns, tc.m)
		if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED {
			t.Fatalf("%s ack=%+v, want DENYLIST_BLOCKED", tc.name, ack)
		}
	}

	// 3. Whitespace plugin_id rejected as INVALID_SCHEMA, uppercase built-in rejected as BUILTIN_OVERRIDE_FORBIDDEN.
	ack, _ = sendReg(authCtx, "secflow-sandbox", &secflowv1.PluginManifest{
		PluginId: " action.ws ", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
	})
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_INVALID_SCHEMA {
		t.Fatalf("whitespace plugin_id ack=%+v, want INVALID_SCHEMA", ack)
	}
	ack, _ = sendReg(authCtx, "secflow-sandbox", &secflowv1.PluginManifest{
		PluginId: "SCAN.SCA", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
	})
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_BUILTIN_OVERRIDE_FORBIDDEN {
		t.Fatalf("uppercase builtin ack=%+v, want BUILTIN_OVERRIDE_FORBIDDEN", ack)
	}

	// 4. Unauthenticated IsExternal=false with non-builtin plugin_id rejected.
	ack, err = sendReg(ctx, "secflow-sandbox", &secflowv1.PluginManifest{
		PluginId: "custom.unauth-spoof", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: false,
	})
	if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED {
		t.Fatalf("unauthenticated non-builtin IsExternal=false ack=%+v err=%v, want UNAUTHENTICATED", ack, err)
	}
}

func sendManifestRegister(
	t *testing.T,
	ctx context.Context,
	workerCli secflowv1.WorkerServiceClient,
	workerID string,
	m *secflowv1.PluginManifest,
) (secflowv1.WorkerService_ConnectClient, *secflowv1.ManifestAck, error) {
	t.Helper()
	st, err := workerCli.Connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	if sendErr := st.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: workerID,
				Namespace:        "secflow-sandbox",
				Manifests:        []*secflowv1.PluginManifest{m},
			},
		},
	}); sendErr != nil && !errors.Is(sendErr, io.EOF) {
		return st, nil, sendErr
	}
	ackMsg, recvErr := st.Recv()
	if ackMsg != nil && ackMsg.GetManifestAck() != nil {
		return st, ackMsg.GetManifestAck(), recvErr
	}
	return st, nil, recvErr
}

func TestDenylist_StrayPercentAndMultiPassEncoding(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	for _, tc := range []struct {
		name  string
		iName string
		img   string
	}{
		{name: "stray percent in name", iName: "100% pure %73emgrep", img: "ghcr.io/secflow/ok:1.0.0"},
		{name: "double encoded name", iName: "%2573emgrep", img: "ghcr.io/secflow/ok:1.0.0"},
		{name: "triple encoded name", iName: "%252573emgrep", img: "ghcr.io/secflow/ok:1.0.0"},
		{name: "stray percent in image", iName: "clean-name", img: "ghcr.io/100%/%73emgrep:1.0"},
	} {
		_, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
			Actor:      owner,
			Name:       tc.iName,
			SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_OCI_IMAGE,
			ImageRef:   tc.img,
		})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "DENYLIST_BLOCKED") {
			t.Fatalf("%s err = %v, want FailedPrecondition DENYLIST_BLOCKED", tc.name, err)
		}
	}

	inst, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:          owner,
		Name:           "percent-ok",
		SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		AutoApprove:    true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	authCtx := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", inst.GetPlaintextPluginToken())

	for _, tc := range []struct {
		name string
		m    *secflowv1.PluginManifest
	}{
		{
			name: "stray percent in description with encoded display name",
			m: &secflowv1.PluginManifest{
				PluginId: "scan.pct-1", Version: "1.0.0", DisplayName: "%73emgrep", Description: "100% pure",
				Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
			},
		},
		{
			name: "stray percent and encoded field in params_json_schema",
			m: &secflowv1.PluginManifest{
				PluginId: "scan.pct-2", Version: "1.0.0", DisplayName: "Pct Schema",
				Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
				ParamsJsonSchema: []byte(`{"type":"object","description":"100% deterministic","x_tool":"%73emgrep"}`),
			},
		},
		{
			name: "double encoded display name",
			m: &secflowv1.PluginManifest{
				PluginId: "scan.pct-3", Version: "1.0.0", DisplayName: "%2573emgrep",
				Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
			},
		},
	} {
		_, ack, _ := sendManifestRegister(t, authCtx, workerCli, "w-pct", tc.m)
		if ack.GetAccepted() || ack.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED {
			t.Fatalf("%s ack = %+v, want DENYLIST_BLOCKED", tc.name, ack)
		}
	}

	_, okAck, okErr := sendManifestRegister(t, authCtx, workerCli, "w-pct-ok", &secflowv1.PluginManifest{
		PluginId: "scan.pct-clean", Version: "1.0.0", DisplayName: "Clean Percent", Description: "100% deterministic custom analyzer",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})
	if okErr != nil || !okAck.GetAccepted() {
		t.Fatalf("clean 100%% description rejected: ack=%+v err=%v", okAck, okErr)
	}
}

func TestUpdatePluginInstallation_PendingAndProvisioningDrain(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	// 1. ACTIVE -> Update(PENDING_APPROVAL) clears approval, drains worker, and Disable -> Enable stays PENDING_APPROVAL.
	instA, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "upd-pending", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, AutoApprove: true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin A: %v", err)
	}
	idA := instA.GetInstallation().GetId()
	ctxA := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", instA.GetPlaintextPluginToken())
	stA, ackA, err := sendManifestRegister(t, ctxA, workerCli, "w-a", &secflowv1.PluginManifest{
		PluginId: "scan.upd-pending", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})
	if err != nil || !ackA.GetAccepted() {
		t.Fatalf("register A: ack=%+v err=%v", ackA, err)
	}
	updPend, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
		Actor: owner, InstallationId: idA, Status: secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL,
	})
	if err != nil {
		t.Fatalf("Update PENDING_APPROVAL: %v", err)
	}
	gotA := updPend.GetInstallation()
	if gotA.GetApprovedAt() != nil || gotA.GetApprovedManifestDigest() != "" || len(gotA.GetPendingManifests()) == 0 {
		t.Fatalf("expected cleared approval and populated pending_manifests, got %+v", gotA)
	}
	if msg, rErr := stA.Recv(); rErr != nil || msg.GetDrainRequest() == nil {
		t.Fatalf("expected DrainRequest on ACTIVE->PENDING_APPROVAL, got %+v err=%v", msg, rErr)
	}
	if _, err := plugCli.SetPluginInstallationEnabled(ctx, &secflowv1.SetPluginInstallationEnabledRequest{
		Actor: owner, InstallationId: idA, Enabled: false,
	}); err != nil {
		t.Fatalf("disable A: %v", err)
	}
	reEn, err := plugCli.SetPluginInstallationEnabled(ctx, &secflowv1.SetPluginInstallationEnabledRequest{
		Actor: owner, InstallationId: idA, Enabled: true,
	})
	if err != nil || reEn.GetInstallation().GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
		t.Fatalf("Disable->Enable must stay PENDING_APPROVAL, got %+v err=%v", reEn, err)
	}

	// 2. ACTIVE -> Update(PROVISIONING) disables plugin and drains connected worker.
	instB, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "upd-prov", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, AutoApprove: true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin B: %v", err)
	}
	idB := instB.GetInstallation().GetId()
	ctxB := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", instB.GetPlaintextPluginToken())
	stB, ackB, err := sendManifestRegister(t, ctxB, workerCli, "w-b", &secflowv1.PluginManifest{
		PluginId: "scan.upd-prov", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})
	if err != nil || !ackB.GetAccepted() {
		t.Fatalf("register B: ack=%+v err=%v", ackB, err)
	}
	if _, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
		Actor: owner, InstallationId: idB, Status: secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING,
	}); err != nil {
		t.Fatalf("Update PROVISIONING: %v", err)
	}
	if msg, rErr := stB.Recv(); rErr != nil || msg.GetDrainRequest() == nil {
		t.Fatalf("expected DrainRequest on ACTIVE->PROVISIONING, got %+v err=%v", msg, rErr)
	}
	if gp, gErr := plugCli.GetPlugin(ctx, &secflowv1.GetPluginRequest{PluginId: "scan.upd-prov"}); gErr != nil || gp.GetPlugin().GetEnabled() {
		t.Fatalf("expected plugin disabled on ACTIVE->PROVISIONING, got %+v err=%v", gp, gErr)
	}
}

func TestUpdatePluginInstallation_DowngradeDrainsActiveWorker(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	instC, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "upd-downgrade-drain", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, EgressAllowlist: []string{"api.example.com"}, AutoApprove: true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin C: %v", err)
	}
	idC := instC.GetInstallation().GetId()
	ctxC := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", instC.GetPlaintextPluginToken())
	stC, ackC, err := sendManifestRegister(t, ctxC, workerCli, "w-c", &secflowv1.PluginManifest{
		PluginId: "action.downgrade-drain", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
	})
	if err != nil || !ackC.GetAccepted() {
		t.Fatalf("register C: ack=%+v err=%v", ackC, err)
	}
	if _, err := plugCli.UpdatePluginInstallation(ctx, &secflowv1.UpdatePluginInstallationRequest{
		Actor: owner, InstallationId: idC, SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
	}); err != nil {
		t.Fatalf("downgrade C: %v", err)
	}
	if msg, rErr := stC.Recv(); rErr != nil || msg.GetDrainRequest() == nil {
		t.Fatalf("expected DrainRequest on EGRESS_EXTERNAL->INTERNAL_ONLY downgrade, got %+v err=%v", msg, rErr)
	}
	_, oldAck, _ := sendManifestRegister(t, ctxC, workerCli, "w-c-old", &secflowv1.PluginManifest{
		PluginId: "action.downgrade-drain", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL, IsExternal: true,
	})
	if oldAck.GetAccepted() || oldAck.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH {
		t.Fatalf("expected SANDBOX_PROFILE_MISMATCH after downgrade, got %+v", oldAck)
	}
}

func TestConnect_CaseInsensitiveCrossInstallationOwnership(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
	workerCli := secflowv1.NewWorkerServiceClient(conn)
	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	extA, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "ext-case-a", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, AutoApprove: true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin A: %v", err)
	}
	extB, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "ext-case-b", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, AutoApprove: true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin B: %v", err)
	}
	extC, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "ext-case-c", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, AutoApprove: false,
	})
	if err != nil {
		t.Fatalf("InstallPlugin C: %v", err)
	}

	ctxA := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", extA.GetPlaintextPluginToken())
	ctxB := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", extB.GetPlaintextPluginToken())
	ctxC := metadata.AppendToOutgoingContext(ctx, "x-plugin-token", extC.GetPlaintextPluginToken())

	// extC stages "Scan.Case-Dup" while pending, then extA claims "scan.case-dup" first.
	_, _, _ = sendManifestRegister(t, ctxC, workerCli, "wc", &secflowv1.PluginManifest{
		PluginId: "Scan.Case-Dup", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})

	_, ackA, errA := sendManifestRegister(t, ctxA, workerCli, "wa", &secflowv1.PluginManifest{
		PluginId: "scan.case-dup", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})
	if errA != nil || !ackA.GetAccepted() {
		t.Fatalf("extA register failed: ack=%+v err=%v", ackA, errA)
	}

	_, ackB, _ := sendManifestRegister(t, ctxB, workerCli, "wb", &secflowv1.PluginManifest{
		PluginId: "SCAN.CASE-DUP", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})
	if ackB.GetAccepted() || ackB.GetRejectionCode() != secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DUPLICATE_PLUGIN_ID {
		t.Fatalf("extB uppercase collision ack = %+v, want DUPLICATE_PLUGIN_ID", ackB)
	}

	if _, appErr := plugCli.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor: owner, InstallationId: extC.GetInstallation().GetId(),
	}); status.Code(appErr) != codes.AlreadyExists {
		t.Fatalf("ApprovePluginInstallation(extC) err = %v, want AlreadyExists", appErr)
	}

	// Deleting extA releases case-insensitive ownership.
	if _, err := plugCli.DeletePluginInstallation(ctx, &secflowv1.DeletePluginInstallationRequest{
		Actor: owner, InstallationId: extA.GetInstallation().GetId(),
	}); err != nil {
		t.Fatalf("DeletePluginInstallation(extA): %v", err)
	}
	_, ackBAfter, errBAfter := sendManifestRegister(t, ctxB, workerCli, "wb2", &secflowv1.PluginManifest{
		PluginId: "SCAN.CASE-DUP", Version: "1.0.0", Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, IsExternal: true,
	})
	if errBAfter != nil || !ackBAfter.GetAccepted() {
		t.Fatalf("extB after extA delete ack=%+v err=%v, want accepted", ackBAfter, errBAfter)
	}
}

func TestRemovePluginRowLocked_CaseRenamePreservesOwnership(t *testing.T) {
	t.Parallel()
	s := newServer()
	ownerKey := pluginOwnerKey("scan.case-dup")

	s.plugMu.Lock()
	s.plugins["scan.case-dup"] = &secflowv1.PluginManifest{PluginId: "scan.case-dup", Version: "1.0.0"}
	s.plugins["SCAN.CASE-DUP"] = &secflowv1.PluginManifest{PluginId: "SCAN.CASE-DUP", Version: "1.0.0"}
	s.pluginInstallation[ownerKey] = "inst-case"
	s.removePluginRowLocked("scan.case-dup")
	gotAfterFirst := s.pluginInstallation[ownerKey]
	_, hasUpper := s.plugins["SCAN.CASE-DUP"]
	s.removePluginRowLocked("SCAN.CASE-DUP")
	gotAfterSecond := s.pluginInstallation[ownerKey]
	s.plugMu.Unlock()

	if !hasUpper || gotAfterFirst != "inst-case" {
		t.Fatalf("after deleting lowercase alias: hasUpper=%v owner=%q, want true/\"inst-case\"", hasUpper, gotAfterFirst)
	}
	if gotAfterSecond != "" {
		t.Fatalf("after deleting final alias: owner=%q, want empty", gotAfterSecond)
	}
}

func TestTwoTierSecretScope_InternalOnlyVsEgressExternalAction(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	s := newServer()
	s.startPump(ctx)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	gs := grpc.NewServer()
	secflowv1.RegisterWorkerServiceServer(gs, s)
	secflowv1.RegisterPluginRegistryServiceServer(gs, s)
	secflowv1.RegisterSecretServiceServer(gs, s)
	go func() {
		_ = gs.Serve(lis)
	}()
	defer func() {
		gs.Stop()
		_ = lis.Close()
	}()

	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	// Create two secrets: one bound to declared required_secret_keys ("apiToken"),
	// and one bound to an undeclared key ("extraSecret") to verify strict key scoping.
	allowedSec, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Actor: owner, Name: "ext-action-token", Kind: secflowv1.SecretKind_SECRET_KIND_GENERIC, PlaintextValue: "top-secret-action-val",
	})
	if err != nil {
		t.Fatalf("CreateSecret allowed: %v", err)
	}
	undeclaredSec, err := s.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
		Actor: owner, Name: "undeclared-token", Kind: secflowv1.SecretKind_SECRET_KIND_GENERIC, PlaintextValue: "must-not-resolve",
	})
	if err != nil {
		t.Fatalf("CreateSecret undeclared: %v", err)
	}

	// 1. Install INTERNAL_ONLY LOGIC external plugin.
	internalInst, err := s.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "ext-logic-internal", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
	})
	if err != nil {
		t.Fatalf("InstallPlugin internal: %v", err)
	}
	internalManifest := &secflowv1.PluginManifest{
		PluginId:       "logic.ext-internal-test",
		Version:        "1.0.0",
		DisplayName:    "External Internal Logic",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "In"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "Out"}},
	}
	internalDone := make(chan struct{})
	internalLeaseCh := make(chan string, 1)
	internalResolveErrCh := make(chan error, 1)
	go func() {
		defer close(internalDone)
		_ = workerclient.RunWithConfig(ctx, workerclient.Config{
			Addr:             lis.Addr().String(),
			WorkerID:         "w-internal-1",
			Namespace:        "secflow-sandbox",
			PluginToken:      internalInst.GetPlaintextPluginToken(),
			Manifests:        []*secflowv1.PluginManifest{internalManifest},
			InitialBackoff:   10 * time.Millisecond,
			MaxBackoff:       50 * time.Millisecond,
			DefaultHeartbeat: 50 * time.Millisecond,
			Handle: func(hCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
				internalLeaseCh <- task.GetTaskLeaseToken()
				_, resolveErr := s.ResolveScopedSecret(hCtx, &secflowv1.ResolveScopedSecretRequest{
					SecretRef: allowedSec.GetSecret().GetSecretRef(),
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
				internalResolveErrCh <- resolveErr
				return &secflowv1.NodeResult{
					NodeRunId:         task.GetNodeRunId(),
					RunId:             task.GetRunId(),
					NodeId:            task.GetNodeId(),
					PluginId:          task.GetPluginId(),
					Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
					ActiveOutputPorts: []string{"default"},
				}
			},
		})
	}()

	// 2. Install EGRESS_EXTERNAL ACTION external plugin.
	actionInst, err := s.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:           owner,
		Name:            "ext-action-egress",
		SourceMode:      secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile:  secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		EgressAllowlist: []string{"hooks.example.com"},
	})
	if err != nil {
		t.Fatalf("InstallPlugin action: %v", err)
	}
	actionManifest := &secflowv1.PluginManifest{
		PluginId:           "action.ext-webhook-test",
		Version:            "1.0.0",
		DisplayName:        "External Webhook Action",
		Category:           secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		SandboxProfile:     secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		IsExternal:         true,
		RequiredSecretKeys: []string{"apiToken"},
		InputPorts:         []*secflowv1.PortDefinition{{Id: "default", Label: "In"}},
		OutputPorts:        []*secflowv1.PortDefinition{{Id: "default", Label: "Out"}},
	}
	actionDone := make(chan struct{})
	type actionResult struct {
		lease         string
		allowedPlain  string
		allowedErr    error
		undeclaredErr error
	}
	actionResCh := make(chan actionResult, 1)
	go func() {
		defer close(actionDone)
		_ = workerclient.RunWithConfig(ctx, workerclient.Config{
			Addr:             lis.Addr().String(),
			WorkerID:         "w-action-1",
			Namespace:        "secflow-sandbox",
			PluginToken:      actionInst.GetPlaintextPluginToken(),
			Manifests:        []*secflowv1.PluginManifest{actionManifest},
			InitialBackoff:   10 * time.Millisecond,
			MaxBackoff:       50 * time.Millisecond,
			DefaultHeartbeat: 50 * time.Millisecond,
			Handle: func(hCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
				res := actionResult{lease: task.GetTaskLeaseToken()}
				resp, rErr := s.ResolveScopedSecret(hCtx, &secflowv1.ResolveScopedSecretRequest{
					SecretRef: allowedSec.GetSecret().GetSecretRef(),
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
				res.allowedErr = rErr
				if resp != nil {
					res.allowedPlain = resp.GetPlaintextValue()
				}
				_, uErr := s.ResolveScopedSecret(hCtx, &secflowv1.ResolveScopedSecretRequest{
					SecretRef: undeclaredSec.GetSecret().GetSecretRef(),
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
				res.undeclaredErr = uErr
				actionResCh <- res
				return &secflowv1.NodeResult{
					NodeRunId:         task.GetNodeRunId(),
					RunId:             task.GetRunId(),
					NodeId:            task.GetNodeId(),
					PluginId:          task.GetPluginId(),
					Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
					ActiveOutputPorts: []string{"default"},
				}
			},
		})
	}()

	// Wait until both workers connect and submit pending manifests, then approve both as OWNER.
	waitPendingManifest := func(instID string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			got, err := s.GetPluginInstallation(ctx, &secflowv1.GetPluginInstallationRequest{Actor: owner, InstallationId: instID})
			if err == nil &&
				got.GetInstallation().GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL &&
				len(got.GetInstallation().GetPendingManifests()) > 0 {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("installation %s did not receive pending manifest", instID)
	}
	waitPendingManifest(internalInst.GetInstallation().GetId())
	waitPendingManifest(actionInst.GetInstallation().GetId())

	if _, err := s.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor: owner, InstallationId: internalInst.GetInstallation().GetId(),
	}); err != nil {
		t.Fatalf("Approve internal: %v", err)
	}
	if _, err := s.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor: owner, InstallationId: actionInst.GetInstallation().GetId(),
	}); err != nil {
		t.Fatalf("Approve action: %v", err)
	}

	// Wait until both external workers reconnect after approval and are ONLINE with >= 1 active worker.
	waitPluginOnline := func(pid string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			p, err := s.GetPlugin(ctx, &secflowv1.GetPluginRequest{Actor: owner, PluginId: pid})
			if err == nil && p.GetPlugin().GetActiveWorkers() > 0 && p.GetPlugin().GetEnabled() {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("plugin %s did not come online after approval", pid)
	}
	waitPluginOnline("logic.ext-internal-test")
	waitPluginOnline("action.ext-webhook-test")

	// Create workflow: trigger.manual -> logic.ext-internal-test -> action.ext-webhook-test
	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Actor: owner,
		Name:  "two-tier-secrets-wf",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", Label: "Trigger"},
				{
					Id: "l1", PluginId: "logic.ext-internal-test", Label: "Internal Logic",
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "apiToken", SecretRef: allowedSec.GetSecret().GetSecretRef()},
					},
				},
				{
					Id: "a1", PluginId: "action.ext-webhook-test", Label: "External Action",
					SecretBindings: []*secflowv1.SecretBinding{
						{ParamKey: "apiToken", SecretRef: allowedSec.GetSecret().GetSecretRef()},
						{ParamKey: "extraSecret", SecretRef: undeclaredSec.GetSecret().GetSecretRef()},
					},
				},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "l1", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "l1", SourceHandle: "default", TargetNodeId: "a1", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	if _, err := s.StartRun(ctx, &secflowv1.StartRunRequest{
		Actor: owner, WorkflowId: wfResp.GetWorkflow().GetId(),
	}); err != nil {
		t.Fatalf("StartRun: %v", err)
	}

	select {
	case gotLease := <-internalLeaseCh:
		if gotLease != "" {
			t.Fatalf("INTERNAL_ONLY external plugin must NOT receive task_lease_token, got %q", gotLease)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for internal logic task")
	}
	select {
	case rErr := <-internalResolveErrCh:
		if status.Code(rErr) != codes.PermissionDenied || !strings.Contains(rErr.Error(), "SECRET_SCOPE_DENIED") {
			t.Fatalf("INTERNAL_ONLY ResolveScopedSecret err=%v, want SECRET_SCOPE_DENIED", rErr)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for internal secret resolve check")
	}

	select {
	case ar := <-actionResCh:
		if ar.lease == "" {
			t.Fatal("OWNER-approved EGRESS_EXTERNAL ACTION must receive task_lease_token")
		}
		if ar.allowedErr != nil || ar.allowedPlain != "top-secret-action-val" {
			t.Fatalf("declared secret resolve: plain=%q err=%v", ar.allowedPlain, ar.allowedErr)
		}
		if status.Code(ar.undeclaredErr) != codes.PermissionDenied || !strings.Contains(ar.undeclaredErr.Error(), "SECRET_SCOPE_DENIED") {
			t.Fatalf("undeclared key secret resolve err=%v, want SECRET_SCOPE_DENIED", ar.undeclaredErr)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for action task")
	}

	cancel()
	<-internalDone
	<-actionDone
}

func TestDemoRiskRouter_EndToEndBranchingAndSubmissionImmutability(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	s := newServer()
	s.startPump(ctx)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	gs := grpc.NewServer()
	secflowv1.RegisterWorkerServiceServer(gs, s)
	secflowv1.RegisterPluginRegistryServiceServer(gs, s)
	go func() {
		_ = gs.Serve(lis)
	}()
	defer func() {
		gs.Stop()
		_ = lis.Close()
	}()

	owner := &secflowv1.ActorContext{Subject: "owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER}

	// 1. Verify risk-router is registered in built-in presets with BLOCK/REVIEW/OK ports.
	presetsResp, err := s.ListPluginPresets(ctx, &secflowv1.ListPluginPresetsRequest{Actor: owner})
	if err != nil {
		t.Fatalf("ListPluginPresets: %v", err)
	}
	var riskPreset *secflowv1.PluginPreset
	for _, p := range presetsResp.GetPresets() {
		if p.GetId() == "risk-router" {
			riskPreset = p
			break
		}
	}
	if riskPreset == nil || len(riskPreset.GetOutputPorts()) != 3 {
		t.Fatalf("risk-router preset missing or invalid: %+v", riskPreset)
	}

	// 2. Install demo-risk-router via EXTERNAL_PULL (with token) + connect real worker + approve.
	instResp, err := s.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor:          owner,
		Name:           "demo-risk-router-e2e",
		SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	instID := instResp.GetInstallation().GetId()
	tok := instResp.GetPlaintextPluginToken()

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		_ = workerclient.RunWithConfig(ctx, workerclient.Config{
			Addr:             lis.Addr().String(),
			WorkerID:         "demo-risk-router-e2e-1",
			Namespace:        "secflow-sandbox",
			PluginToken:      tok,
			Manifests:        []*secflowv1.PluginManifest{riskrouter.Manifest()},
			InitialBackoff:   10 * time.Millisecond,
			MaxBackoff:       50 * time.Millisecond,
			DefaultHeartbeat: 50 * time.Millisecond,
			Handle: func(_ context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
				return riskrouter.Evaluate(task)
			},
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := s.GetPluginInstallation(ctx, &secflowv1.GetPluginInstallationRequest{Actor: owner, InstallationId: instID})
		if err == nil && len(got.GetInstallation().GetPendingManifests()) > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := s.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{
		Actor: owner, InstallationId: instID,
	}); err != nil {
		t.Fatalf("ApprovePluginInstallation: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p, err := s.GetPlugin(ctx, &secflowv1.GetPluginRequest{Actor: owner, PluginId: riskrouter.PluginID})
		if err == nil && p.GetPlugin().GetActiveWorkers() > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Also connect a real external analyzer emitting 2 CRITICAL findings -> score = 20 >= blockThreshold 15.
	scanInst, err := s.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
		Actor: owner, Name: "risk-e2e-scanner", SourceMode: secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY, AutoApprove: true,
	})
	if err != nil {
		t.Fatalf("InstallPlugin scanner: %v", err)
	}
	scanManifest := &secflowv1.PluginManifest{
		PluginId:       "scan.risk-e2e-fixture",
		Version:        "1.0.0",
		DisplayName:    "Fixture Analyzer",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "In"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "Out"}},
	}
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		_ = workerclient.RunWithConfig(ctx, workerclient.Config{
			Addr:             lis.Addr().String(),
			WorkerID:         "risk-e2e-scan-1",
			Namespace:        "secflow-sandbox",
			PluginToken:      scanInst.GetPlaintextPluginToken(),
			Manifests:        []*secflowv1.PluginManifest{scanManifest},
			InitialBackoff:   10 * time.Millisecond,
			MaxBackoff:       50 * time.Millisecond,
			DefaultHeartbeat: 50 * time.Millisecond,
			Handle: func(_ context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
				l1, l2 := int32(10), int32(20)
				return &secflowv1.NodeResult{
					NodeRunId:         task.GetNodeRunId(),
					RunId:             task.GetRunId(),
					NodeId:            task.GetNodeId(),
					PluginId:          task.GetPluginId(),
					Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
					ActiveOutputPorts: []string{"default"},
					Findings: []*secflowv1.Finding{
						{
							FindingId: "f_crit_1", SourceNodeId: task.GetNodeId(), PluginId: task.GetPluginId(),
							Category: secflowv1.FindingCategory_FINDING_CATEGORY_SAST, Severity: secflowv1.Severity_SEVERITY_CRITICAL,
							Path: "src/App.kt", FindingClass: "sql-injection", Line: &l1, Description: "SQLi 1",
						},
						{
							FindingId: "f_crit_2", SourceNodeId: task.GetNodeId(), PluginId: task.GetPluginId(),
							Category: secflowv1.FindingCategory_FINDING_CATEGORY_SECRET, Severity: secflowv1.Severity_SEVERITY_CRITICAL,
							Path: "src/Config.kt", FindingClass: "hardcoded-secret", Line: &l2, Description: "Hardcoded secret",
						},
					},
				}
			},
		})
	}()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := s.GetPluginInstallation(ctx, &secflowv1.GetPluginInstallationRequest{Actor: owner, InstallationId: scanInst.GetInstallation().GetId()})
		if err == nil && len(got.GetInstallation().GetPendingManifests()) > 0 {
			_, _ = s.ApprovePluginInstallation(ctx, &secflowv1.ApprovePluginInstallationRequest{Actor: owner, InstallationId: scanInst.GetInstallation().GetId()})
		}
		p, err := s.GetPlugin(ctx, &secflowv1.GetPluginRequest{Actor: owner, PluginId: "scan.risk-e2e-fixture"})
		if err == nil && p.GetPlugin().GetActiveWorkers() > 0 && p.GetPlugin().GetEnabled() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// 3. Validate & create workflow with dynamic ports BLOCK / REVIEW / OK.
	graph := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{Id: "t1", PluginId: "trigger.manual", Label: "Trigger"},
			{Id: "src1", PluginId: "source.upload", Label: "Source", ParamsJson: []byte(`{"sourceId":"src_risk_test"}`)},
			{Id: "scan1", PluginId: "scan.risk-e2e-fixture", Label: "Fixture Scan"},
			{Id: "router1", PluginId: riskrouter.PluginID, Label: "Risk Router", ParamsJson: []byte(`{"criticalWeight":10,"blockThreshold":15,"reviewThreshold":5}`)},
			{Id: "n_block", PluginId: "logic.filter", Label: "Block Branch"},
			{Id: "n_review", PluginId: "logic.filter", Label: "Review Branch"},
			{Id: "n_ok", PluginId: "logic.filter", Label: "OK Branch"},
		},
		Edges: []*secflowv1.WorkflowEdge{
			{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "src1", TargetHandle: "default"},
			{Id: "e2", SourceNodeId: "src1", SourceHandle: "default", TargetNodeId: "scan1", TargetHandle: "default"},
			{Id: "e3", SourceNodeId: "scan1", SourceHandle: "default", TargetNodeId: "router1", TargetHandle: "default"},
			{Id: "e_blk", SourceNodeId: "router1", SourceHandle: "BLOCK", TargetNodeId: "n_block", TargetHandle: "default"},
			{Id: "e_rev", SourceNodeId: "router1", SourceHandle: "REVIEW", TargetNodeId: "n_review", TargetHandle: "default"},
			{Id: "e_ok", SourceNodeId: "router1", SourceHandle: "OK", TargetNodeId: "n_ok", TargetHandle: "default"},
		},
	}
	valResp, err := s.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{Actor: owner, Graph: graph})
	if err != nil {
		t.Fatalf("ValidateWorkflow: %v", err)
	}
	for _, iss := range valResp.GetIssues() {
		if iss.GetSeverity() == secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR {
			t.Fatalf("unexpected validation error on BLOCK/REVIEW/OK graph: %+v", iss)
		}
	}

	wfResp, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{Actor: owner, Name: "risk-router-e2e-wf", Graph: graph})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	runResp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{Actor: owner, WorkflowId: wfResp.GetWorkflow().GetId()})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := runResp.GetRun().GetId()

	// Wait for run completion.
	var finalRun *secflowv1.Run
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		got, err := s.GetRun(ctx, &secflowv1.GetRunRequest{Actor: owner, RunId: runID})
		if err == nil && (got.GetRun().GetStatus() == secflowv1.RunStatus_RUN_STATUS_SUCCEEDED || got.GetRun().GetStatus() == secflowv1.RunStatus_RUN_STATUS_FAILED) {
			finalRun = got.GetRun()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if finalRun == nil || finalRun.GetStatus() != secflowv1.RunStatus_RUN_STATUS_SUCCEEDED {
		t.Fatalf("run did not succeed: %+v", finalRun)
	}

	// Verify active branch n_block SUCCEEDED, inactive n_review & n_ok SKIPPED.
	nodeStatus := map[string]secflowv1.NodeRunStatus{}
	for _, nr := range finalRun.GetNodeRuns() {
		nodeStatus[nr.GetNodeId()] = nr.GetStatus()
	}
	if nodeStatus["n_block"] != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED ||
		nodeStatus["n_review"] != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SKIPPED ||
		nodeStatus["n_ok"] != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SKIPPED {
		t.Fatalf("unexpected branch statuses: %+v", nodeStatus)
	}

	// Verify Envelope patch on router1 (gate=FAIL, vars["plugins.logic.risk-router.route"]=="BLOCK", score=="20").
	payload, err := s.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{Actor: owner, RunId: runID, NodeId: "router1"})
	if err != nil {
		t.Fatalf("GetNodePayload(router1): %v", err)
	}
	outEnv := string(payload.GetOutputEnvelopeJson())
	for _, want := range []string{`"plugins.logic.risk-router.route":"BLOCK"`, `"plugins.logic.risk-router.score":"20"`, `"status":"FAIL"`} {
		if !strings.Contains(outEnv, want) {
			t.Fatalf("router1 output envelope missing %s: %s", want, outEnv)
		}
	}

	// Verify Submission Report immutability: exact 2 findings from analyzer, zero mutations from risk-router.
	sub, err := s.GetSubmissionReport(ctx, &secflowv1.GetSubmissionReportRequest{Actor: owner, RunId: runID})
	if err != nil {
		t.Fatalf("GetSubmissionReport: %v", err)
	}
	if sub.GetFindingCount() != 2 {
		t.Fatalf("Submission findingCount=%d, want 2 (immutable Run Findings)", sub.GetFindingCount())
	}

	cancel()
	<-workerDone
	<-scanDone
}
