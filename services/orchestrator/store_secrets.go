package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/lease"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/secretbox"
)

func cloneSecretMetadata(m *secflowv1.SecretMetadata) *secflowv1.SecretMetadata {
	if m == nil {
		return nil
	}
	cp, _ := proto.Clone(m).(*secflowv1.SecretMetadata)
	return cp
}

func cloneScopedTokenMetadata(m *secflowv1.ScopedTokenMetadata) *secflowv1.ScopedTokenMetadata {
	if m == nil {
		return nil
	}
	cp, _ := proto.Clone(m).(*secflowv1.ScopedTokenMetadata)
	return cp
}

var (
	secretStoresMu sync.Mutex
	secretStores   = map[*Server]secretbox.SecretStore{}
)

var globalForbiddenSecretParams = map[string]struct{}{
	"webhookSecret":  {},
	"gitStatusToken": {},
	"gitToken":       {},
	"apiKey":         {},
	"llmApiKey":      {},
	"botToken":       {},
	"hmacSecret":     {},
	"smtpPassword":   {},
}

func (s *Server) secretStore() (secretbox.SecretStore, error) {
	secretStoresMu.Lock()
	defer secretStoresMu.Unlock()
	if st, ok := secretStores[s]; ok {
		return st, nil
	}
	st, err := secretbox.NewStoreFromEnv(s.boxKey)
	if err != nil {
		return nil, err
	}
	secretStores[s] = st
	return st, nil
}

func (s *Server) setSecretStore(st secretbox.SecretStore) {
	secretStoresMu.Lock()
	secretStores[s] = st
	secretStoresMu.Unlock()
}

func secretBackendProto(name string) secflowv1.SecretStoreBackend {
	if name == secretbox.BackendVault {
		return secflowv1.SecretStoreBackend_SECRET_STORE_BACKEND_VAULT
	}
	return secflowv1.SecretStoreBackend_SECRET_STORE_BACKEND_PG_AES
}

func rejectInlineSecrets(g *secflowv1.WorkflowGraph) error {
	if g == nil {
		return nil
	}
	for _, n := range g.GetNodes() {
		if len(n.GetParamsJson()) == 0 {
			continue
		}
		params := map[string]any{}
		if err := json.Unmarshal(n.GetParamsJson(), &params); err != nil {
			continue
		}
		pluginKeys := inlineSecretKeys(n.GetPluginId())
		for key := range params {
			_, inGlobal := globalForbiddenSecretParams[key]
			_, inPlugin := pluginKeys[key]
			if inGlobal || inPlugin {
				return status.Errorf(codes.InvalidArgument, "plaintext secrets are forbidden in node params; use secretBindings (node %s, param %s)", n.GetId(), key)
			}
		}
	}
	return nil
}

func (s *Server) CreateSecret(ctx context.Context, req *secflowv1.CreateSecretRequest) (*secflowv1.CreateSecretResponse, error) {
	st, err := s.secretStore()
	if err != nil {
		slog.Error("init secret store", "err", err)
		return nil, status.Error(codes.Internal, "secret store unavailable")
	}
	ref := id("sec")
	if err := st.Put(ctx, ref, []byte(req.GetPlaintextValue())); err != nil {
		slog.Error("put secret", "secret_ref", ref, "backend", st.Backend(), "err", err)
		return nil, status.Error(codes.Internal, "store secret")
	}
	var sealed []byte
	if pg, ok := st.(*secretbox.PGAESStore); ok {
		sealed, _ = pg.Sealed(ref)
	}
	meta := &secflowv1.SecretMetadata{
		SecretRef:     ref,
		Name:          req.GetName(),
		Kind:          req.GetKind(),
		MaskedPreview: mask(req.GetPlaintextValue()),
		Backend:       secretBackendProto(st.Backend()),
		CreatedBy:     subject(req.GetActor()),
		CreatedAt:     timestamppb.Now(),
		UpdatedAt:     timestamppb.Now(),
	}
	s.secMu.Lock()
	s.secrets[ref] = &secretRec{meta: meta, sealed: slices.Clone(sealed)}
	snap := cloneSecretMetadata(meta)
	s.secMu.Unlock()
	s.persistSecret(ctx, snap, sealed)
	return &secflowv1.CreateSecretResponse{Secret: cloneSecretMetadata(snap)}, nil
}

func (s *Server) DeleteSecret(ctx context.Context, req *secflowv1.DeleteSecretRequest) (*secflowv1.DeleteSecretResponse, error) {
	s.secMu.Lock()
	delete(s.secrets, req.GetSecretRef())
	s.secMu.Unlock()
	if st, err := s.secretStore(); err == nil {
		if err := st.Delete(ctx, req.GetSecretRef()); err != nil {
			slog.Warn("delete secret from store", "secret_ref", req.GetSecretRef(), "backend", st.Backend(), "err", err)
		}
	}
	if s.pool != nil {
		dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(dbCtx, `DELETE FROM secrets WHERE secret_ref = $1`, req.GetSecretRef()); err != nil {
			slog.Warn("delete secret from db", "secret_ref", req.GetSecretRef(), "err", err)
		}
	}
	return &secflowv1.DeleteSecretResponse{Deleted: true}, nil
}

func (s *Server) ListMaskedSecrets(_ context.Context, _ *secflowv1.ListMaskedSecretsRequest) (*secflowv1.ListMaskedSecretsResponse, error) {
	s.secMu.Lock()
	defer s.secMu.Unlock()
	items := make([]*secflowv1.SecretMetadata, 0, len(s.secrets))
	for _, sec := range s.secrets {
		items = append(items, cloneSecretMetadata(sec.meta))
	}
	return &secflowv1.ListMaskedSecretsResponse{Secrets: items}, nil
}

func (s *Server) ResolveScopedSecret(ctx context.Context, req *secflowv1.ResolveScopedSecretRequest) (*secflowv1.ResolveScopedSecretResponse, error) {
	if err := s.authorizeSecret(req); err != nil {
		return nil, err
	}
	s.secMu.Lock()
	sec, ok := s.secrets[req.GetSecretRef()]
	var secretRef string
	var sealed []byte
	if ok {
		secretRef = sec.meta.GetSecretRef()
		sealed = slices.Clone(sec.sealed)
	}
	s.secMu.Unlock()
	if !ok {
		slog.Warn("resolve scoped secret: not found in registry", "secret_ref", req.GetSecretRef())
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	st, err := s.secretStore()
	if err != nil {
		slog.Warn("resolve scoped secret: store unavailable", "secret_ref", req.GetSecretRef(), "err", err)
		return nil, status.Error(codes.Internal, "secret store unavailable")
	}
	plain, err := st.Get(ctx, req.GetSecretRef())
	if errors.Is(err, secretbox.ErrNotFound) && len(sealed) > 0 {
		plain, err = secretbox.Open(s.boxKey, sealed)
	}
	if err != nil {
		slog.Warn("resolve scoped secret: decrypt/get failed", "secret_ref", req.GetSecretRef(), "err", err)
		if errors.Is(err, secretbox.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Error(codes.Internal, "open secret")
	}
	return &secflowv1.ResolveScopedSecretResponse{SecretRef: secretRef, PlaintextValue: string(plain)}, nil
}

func (s *Server) IssueScopedToken(ctx context.Context, req *secflowv1.IssueScopedTokenRequest) (*secflowv1.IssueScopedTokenResponse, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, status.Error(codes.Internal, "generate token")
	}
	prefix := "sf_ci_"
	if len(req.GetScopes()) > 0 {
		allMCP := true
		for _, sc := range req.GetScopes() {
			if !strings.HasPrefix(sc, "mcp:") {
				allMCP = false
				break
			}
		}
		if allMCP {
			prefix = "sf_mcp_"
		}
	}
	meta := &secflowv1.ScopedTokenMetadata{
		TokenId:     id("tok"),
		Name:        req.GetName(),
		TokenPrefix: prefix,
		Scopes:      slices.Clone(req.GetScopes()),
		WorkflowId:  req.GetWorkflowId(),
		CreatedBy:   subject(req.GetActor()),
		CreatedAt:   timestamppb.Now(),
		ExpiresAt:   req.GetExpiresAt(),
	}
	plain := meta.GetTokenPrefix() + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain))
	s.secMu.Lock()
	s.tokens[meta.GetTokenId()] = &tokenRec{meta: meta, hash: sum}
	snap := cloneScopedTokenMetadata(meta)
	s.secMu.Unlock()
	s.persistToken(ctx, snap, sum[:])
	return &secflowv1.IssueScopedTokenResponse{Metadata: cloneScopedTokenMetadata(snap), PlaintextToken: plain}, nil
}

func (s *Server) ListScopedTokens(_ context.Context, _ *secflowv1.ListScopedTokensRequest) (*secflowv1.ListScopedTokensResponse, error) {
	s.secMu.Lock()
	defer s.secMu.Unlock()
	items := make([]*secflowv1.ScopedTokenMetadata, 0, len(s.tokens))
	for _, tok := range s.tokens {
		items = append(items, cloneScopedTokenMetadata(tok.meta))
	}
	return &secflowv1.ListScopedTokensResponse{Tokens: items}, nil
}

func (s *Server) RevokeScopedToken(ctx context.Context, req *secflowv1.RevokeScopedTokenRequest) (*secflowv1.RevokeScopedTokenResponse, error) {
	s.secMu.Lock()
	tok, ok := s.tokens[req.GetTokenId()]
	if !ok {
		s.secMu.Unlock()
		return nil, status.Error(codes.NotFound, "token not found")
	}
	tok.meta.RevokedAt = timestamppb.Now()
	s.secMu.Unlock()
	if s.pool != nil {
		dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(dbCtx, `UPDATE scoped_tokens SET revoked_at = now() WHERE token_id = $1`, req.GetTokenId()); err != nil {
			slog.Warn("revoke scoped token in db", "token_id", req.GetTokenId(), "err", err)
		}
	}
	return &secflowv1.RevokeScopedTokenResponse{Revoked: true}, nil
}

func (s *Server) VerifyScopedToken(_ context.Context, req *secflowv1.VerifyScopedTokenRequest) (*secflowv1.VerifyScopedTokenResponse, error) {
	if req.GetPlaintextToken() == "" {
		return &secflowv1.VerifyScopedTokenResponse{Valid: false}, nil
	}
	sum := sha256.Sum256([]byte(req.GetPlaintextToken()))
	now := time.Now()
	s.secMu.Lock()
	defer s.secMu.Unlock()
	for _, tok := range s.tokens {
		if tok.meta.GetRevokedAt() != nil {
			continue
		}
		if tok.meta.GetExpiresAt() != nil && !tok.meta.GetExpiresAt().AsTime().After(now) {
			continue
		}
		if hmac.Equal(tok.hash[:], sum[:]) {
			tok.meta.LastUsedAt = timestamppb.Now()
			return &secflowv1.VerifyScopedTokenResponse{
				Valid:   true,
				TokenId: tok.meta.GetTokenId(),
				Actor: &secflowv1.ActorContext{
					Subject:          tok.meta.GetTokenId(),
					Scopes:           slices.Clone(tok.meta.GetScopes()),
					ScopedWorkflowId: tok.meta.GetWorkflowId(),
					AuthMode:         secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN,
				},
			}, nil
		}
	}
	return &secflowv1.VerifyScopedTokenResponse{Valid: false}, nil
}

func (s *Server) validServiceToken(got string) bool {
	if s.serviceTK == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.serviceTK)) == 1
}

func (s *Server) mayIssueTaskLease(pluginID string, m *secflowv1.PluginManifest) bool {
	if s.isAnalyzerPlugin(pluginID) || pluginID == "sbom.generate" {
		return false
	}
	if m == nil {
		// Fail closed unless pluginID is a known built-in non-analyzer plugin.
		builtin, ok := manifest.LookupBuiltin(pluginID)
		if !ok {
			return false
		}
		return builtin.Category != secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER &&
			builtin.SandboxProfile != secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
	}
	if m.GetCategory() == secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER ||
		m.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY {
		return false
	}
	if !m.GetIsExternal() {
		return true
	}
	return s.externalActionSecretEligible(pluginID, m)
}

func (s *Server) externalActionSecretEligible(pluginID string, m *secflowv1.PluginManifest) bool {
	if m == nil || !m.GetIsExternal() {
		return false
	}
	if m.GetCategory() != secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION ||
		m.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
		return false
	}
	if len(m.GetRequiredSecretKeys()) == 0 {
		return false
	}
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	instID := s.pluginInstallation[pluginOwnerKey(pluginID)]
	if instID == "" {
		// Standalone non-installation external worker registered with SERVICE_TOKEN in tests.
		return !s.pluginDisabled[pluginID] && s.pluginApprovalState[pluginID] != approvalStatePending
	}
	rec := s.installations[instID]
	if rec == nil || rec.proto == nil {
		return false
	}
	return rec.proto.GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE &&
		rec.proto.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL &&
		!s.pluginDisabled[pluginID]
}

func (s *Server) authorizeSecret(req *secflowv1.ResolveScopedSecretRequest) error {
	switch scope := req.GetScope().(type) {
	case *secflowv1.ResolveScopedSecretRequest_NodeTask:
		n := scope.NodeTask
		if n == nil || strings.HasPrefix(n.GetPluginId(), "scan.") || strings.HasPrefix(n.GetPluginId(), "sbom.") {
			slog.Warn("secret scope denied: forbidden plugin", "plugin_id", n.GetPluginId(), "secret_ref", req.GetSecretRef())
			return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
		}
		plugManifest := s.pluginManifestSnapshot(n.GetPluginId())
		if plugManifest == nil {
			builtin, ok := manifest.LookupBuiltin(n.GetPluginId())
			if !ok ||
				builtin.Category == secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER ||
				builtin.SandboxProfile == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY {
				return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
			}
		} else {
			if plugManifest.GetCategory() == secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER ||
				plugManifest.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY {
				return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
			}
			if plugManifest.GetIsExternal() && !s.externalActionSecretEligible(n.GetPluginId(), plugManifest) {
				return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
			}
		}
		if err := lease.Verify(s.leaseKey, n.GetTaskLeaseToken(), n.GetRunId(), n.GetNodeRunId(), n.GetNodeId(), n.GetPluginId()); err != nil {
			slog.Warn("secret scope denied: lease verify failed", "run_id", n.GetRunId(), "node_id", n.GetNodeId(), "plugin_id", n.GetPluginId(), "err", err)
			return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
		}
		if plugManifest != nil && plugManifest.GetIsExternal() {
			if !s.nodeHasDeclaredSecret(n.GetRunId(), n.GetNodeId(), req.GetSecretRef(), plugManifest.GetRequiredSecretKeys()) {
				return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
			}
		} else if !s.nodeHasSecret(n.GetRunId(), n.GetNodeId(), req.GetSecretRef()) {
			if n.GetPluginId() != "mcp.tool" || !s.nodeHasMcpSecret(n.GetRunId(), n.GetNodeId(), req.GetSecretRef()) {
				slog.Warn("secret scope denied: node does not bind secret", "run_id", n.GetRunId(), "node_id", n.GetNodeId(), "plugin_id", n.GetPluginId(), "secret_ref", req.GetSecretRef())
				return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
			}
		}
	case *secflowv1.ResolveScopedSecretRequest_WorkflowWebhook:
		w := scope.WorkflowWebhook
		if w == nil || !s.validServiceToken(req.GetServiceToken()) ||
			!s.bindingForNode(w.GetWorkflowId(), w.GetTriggerNodeId(), "trigger.webhook", "webhookSecret", req.GetSecretRef()) {
			return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
		}
	case *secflowv1.ResolveScopedSecretRequest_CommitStatus:
		c := scope.CommitStatus
		if c == nil || !s.validServiceToken(req.GetServiceToken()) ||
			c.GetRunId() == "" || c.GetWorkflowId() == "" ||
			s.workflowIDForRun(c.GetRunId()) != c.GetWorkflowId() ||
			!s.bindingForNode(c.GetWorkflowId(), c.GetTriggerNodeId(), "trigger.webhook", "gitStatusToken", req.GetSecretRef()) {
			return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
		}
	case *secflowv1.ResolveScopedSecretRequest_McpDiscovery:
		m := scope.McpDiscovery
		if m == nil || !s.validServiceToken(req.GetServiceToken()) || m.GetMcpConnectionId() == "" {
			return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
		}
		if m.GetMcpConnectionId() == "__ai_provider__" {
			if !s.aiProviderSecret(req.GetSecretRef()) {
				slog.Warn("secret scope denied: secret kind not allowed for ai provider", "secret_ref", req.GetSecretRef())
				return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
			}
			return nil
		}
		if !s.mcpSecret(m.GetMcpConnectionId(), req.GetSecretRef()) {
			return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
		}
	default:
		return status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
	}
	return nil
}

func (s *Server) workflowIDForRun(runID string) string {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	st := s.runs[runID]
	if st == nil || st.run == nil {
		return ""
	}
	return st.run.GetWorkflowId()
}

func (s *Server) nodeHasSecret(runID, nodeID, secretRef string) bool {
	if secretRef == "" {
		return false
	}
	s.runMu.Lock()
	var runGraphNodes []engine.Node
	wfID := ""
	if st := s.runs[runID]; st != nil {
		if st.run != nil {
			wfID = st.run.GetWorkflowId()
		}
		if len(st.graph.Nodes) > 0 {
			runGraphNodes = slices.Clone(st.graph.Nodes)
		}
	}
	s.runMu.Unlock()
	for _, n := range runGraphNodes {
		if n.ID != nodeID {
			continue
		}
		for _, ref := range n.Secrets {
			if ref == secretRef {
				return true
			}
		}
	}
	if wfID == "" {
		return false
	}
	wf := s.mustWorkflow(wfID)
	if wf == nil || wf.GetGraph() == nil {
		return false
	}
	for _, n := range wf.GetGraph().GetNodes() {
		if n.GetId() != nodeID {
			continue
		}
		for _, b := range n.GetSecretBindings() {
			if b.GetSecretRef() == secretRef {
				return true
			}
		}
	}
	return false
}

func (s *Server) nodeHasDeclaredSecret(runID, nodeID, secretRef string, declaredKeys []string) bool {
	if secretRef == "" || len(declaredKeys) == 0 {
		return false
	}
	wfID := s.workflowIDForRun(runID)
	if wfID == "" {
		return false
	}
	wf := s.mustWorkflow(wfID)
	if wf == nil || wf.GetGraph() == nil {
		return false
	}
	allowed := make(map[string]bool, len(declaredKeys))
	for _, k := range declaredKeys {
		if trimmed := strings.TrimSpace(k); trimmed != "" {
			allowed[trimmed] = true
		}
	}
	for _, n := range wf.GetGraph().GetNodes() {
		if n.GetId() != nodeID {
			continue
		}
		for _, b := range n.GetSecretBindings() {
			if b.GetSecretRef() == secretRef && allowed[b.GetParamKey()] {
				return true
			}
		}
	}
	return false
}

func (s *Server) nodeHasMcpSecret(runID, nodeID, secretRef string) bool {
	if secretRef == "" {
		return false
	}
	wfID := s.workflowIDForRun(runID)
	if wfID == "" {
		return false
	}
	wf := s.mustWorkflow(wfID)
	if wf == nil || wf.GetGraph() == nil {
		return false
	}
	var connIDs []string
	for _, n := range wf.GetGraph().GetNodes() {
		if n.GetId() != nodeID || n.GetPluginId() != "mcp.tool" {
			continue
		}
		params := map[string]any{}
		if err := json.Unmarshal(n.GetParamsJson(), &params); err != nil {
			continue
		}
		if connID, _ := params["connectionId"].(string); connID != "" {
			connIDs = append(connIDs, connID)
		}
	}
	for _, connID := range connIDs {
		if s.mcpSecret(connID, secretRef) {
			return true
		}
	}
	return false
}

func (s *Server) mcpSecret(connectionID, secretRef string) bool {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	conn := s.mcps[connectionID]
	return conn != nil && conn.GetConfig().GetAuthSecretRef() != "" && conn.GetConfig().GetAuthSecretRef() == secretRef
}

func (s *Server) aiProviderSecret(secretRef string) bool {
	if secretRef == "" {
		return false
	}
	s.secMu.Lock()
	sec := s.secrets[secretRef]
	s.secMu.Unlock()
	if sec == nil || sec.meta == nil {
		return false
	}
	k := sec.meta.GetKind()
	return k == secflowv1.SecretKind_SECRET_KIND_LLM_API_KEY || k == secflowv1.SecretKind_SECRET_KIND_GENERIC
}

func (s *Server) bindingForNode(workflowID, nodeID, plugin, param, secretRef string) bool {
	if workflowID == "" || nodeID == "" || secretRef == "" {
		return false
	}
	wf := s.mustWorkflow(workflowID)
	if wf == nil || wf.GetGraph() == nil {
		return false
	}
	for _, n := range wf.GetGraph().GetNodes() {
		if n.GetId() != nodeID || n.GetPluginId() != plugin {
			continue
		}
		for _, b := range n.GetSecretBindings() {
			if b.GetParamKey() == param && b.GetSecretRef() == secretRef {
				return true
			}
		}
	}
	return false
}

func (s *Server) persistSecret(ctx context.Context, meta *secflowv1.SecretMetadata, sealed []byte) {
	if s.pool == nil || meta == nil {
		return
	}
	if sealed == nil {
		sealed = []byte{}
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(dbCtx, `INSERT INTO secrets (secret_ref, name, kind, ciphertext, nonce, created_by) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (secret_ref) DO NOTHING`, meta.GetSecretRef(), meta.GetName(), meta.GetKind().String(), sealed, []byte{}, meta.GetCreatedBy()); err != nil {
		slog.Warn("persist secret", "secret_ref", meta.GetSecretRef(), "err", err)
	}
}

func (s *Server) persistToken(ctx context.Context, meta *secflowv1.ScopedTokenMetadata, hash []byte) {
	if s.pool == nil || meta == nil {
		return
	}
	scopes := meta.GetScopes()
	if scopes == nil {
		scopes = []string{}
	}
	var expiresAt *time.Time
	if meta.GetExpiresAt() != nil {
		t := meta.GetExpiresAt().AsTime()
		expiresAt = &t
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(dbCtx, `INSERT INTO scoped_tokens (token_id, name, token_prefix, scopes, workflow_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (token_id) DO NOTHING`,
		meta.GetTokenId(), meta.GetName(), meta.GetTokenPrefix(), scopes, meta.GetWorkflowId(), hash, expiresAt); err != nil {
		if strings.Contains(err.Error(), "expires_at") {
			if _, fbErr := s.pool.Exec(dbCtx, `INSERT INTO scoped_tokens (token_id, name, token_prefix, scopes, workflow_id, token_hash) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (token_id) DO NOTHING`,
				meta.GetTokenId(), meta.GetName(), meta.GetTokenPrefix(), scopes, meta.GetWorkflowId(), hash); fbErr != nil {
				slog.Warn("persist scoped token", "token_id", meta.GetTokenId(), "err", fbErr)
			}
			return
		}
		slog.Warn("persist scoped token", "token_id", meta.GetTokenId(), "err", err)
	}
}

func (s *Server) loadSecrets(ctx context.Context) {
	if s.pool == nil {
		return
	}
	st, err := s.secretStore()
	if err != nil {
		slog.Warn("init secret store during load", "err", err)
	}
	backend := secflowv1.SecretStoreBackend_SECRET_STORE_BACKEND_PG_AES
	if st != nil {
		backend = secretBackendProto(st.Backend())
	}
	rows, err := s.pool.Query(ctx, `SELECT secret_ref, name, kind, ciphertext, created_by FROM secrets`)
	if err != nil {
		slog.Warn("load secrets", "err", err)
		return
	}
	defer rows.Close()
	loaded := map[string]*secretRec{}
	for rows.Next() {
		var ref, name, kind, createdBy string
		var sealed []byte
		if err := rows.Scan(&ref, &name, &kind, &sealed, &createdBy); err != nil {
			slog.Warn("scan secret", "err", err)
			continue
		}
		if pg, ok := st.(*secretbox.PGAESStore); ok && len(sealed) > 0 {
			pg.LoadSealed(ref, sealed)
		}
		loaded[ref] = &secretRec{
			meta: &secflowv1.SecretMetadata{
				SecretRef: ref, Name: name, Kind: secflowv1.SecretKind(secflowv1.SecretKind_value[kind]),
				CreatedBy: createdBy, Backend: backend,
			},
			sealed: sealed,
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate secrets", "err", err)
	}
	s.secMu.Lock()
	for ref, rec := range loaded {
		s.secrets[ref] = rec
	}
	s.secMu.Unlock()
}

func (s *Server) loadTokens(ctx context.Context) {
	if s.pool == nil {
		return
	}
	hasExpiresAt := true
	rows, err := s.pool.Query(ctx, `SELECT token_id, name, token_prefix, scopes, COALESCE(workflow_id, ''), token_hash, revoked_at, expires_at FROM scoped_tokens`)
	if err != nil && strings.Contains(err.Error(), "expires_at") {
		hasExpiresAt = false
		rows, err = s.pool.Query(ctx, `SELECT token_id, name, token_prefix, scopes, COALESCE(workflow_id, ''), token_hash, revoked_at FROM scoped_tokens`)
	}
	if err != nil {
		slog.Warn("load tokens", "err", err)
		return
	}
	defer rows.Close()
	loaded := map[string]*tokenRec{}
	for rows.Next() {
		var tokID, name, prefix, workflowID string
		var scopes []string
		var hash []byte
		var revoked, expires *time.Time
		var scanErr error
		if hasExpiresAt {
			scanErr = rows.Scan(&tokID, &name, &prefix, &scopes, &workflowID, &hash, &revoked, &expires)
		} else {
			scanErr = rows.Scan(&tokID, &name, &prefix, &scopes, &workflowID, &hash, &revoked)
		}
		if scanErr != nil || len(hash) != 32 {
			if scanErr != nil {
				slog.Warn("scan token", "err", scanErr)
			}
			continue
		}
		var sum [32]byte
		copy(sum[:], hash)
		meta := &secflowv1.ScopedTokenMetadata{TokenId: tokID, Name: name, TokenPrefix: prefix, Scopes: scopes, WorkflowId: workflowID}
		if revoked != nil {
			meta.RevokedAt = timestamppb.New(*revoked)
		}
		if expires != nil {
			meta.ExpiresAt = timestamppb.New(*expires)
		}
		loaded[tokID] = &tokenRec{meta: meta, hash: sum}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate tokens", "err", err)
	}
	s.secMu.Lock()
	for tokID, rec := range loaded {
		s.tokens[tokID] = rec
	}
	s.secMu.Unlock()
}
