package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/declarativeplugin"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/urlguard"
)

const (
	approvalStateApproved = "APPROVED"
	approvalStatePending  = "PENDING_APPROVAL"
	approvalStateRejected = "REJECTED"

	pluginTokenPrefix    = "sf_plg_"
	defaultDrainGraceSec = int64(15)

	errInstallationIDRequired = "installation_id is required"
	errInstallationNotFound   = "plugin installation not found"
	errInstallationDeleting   = "INVALID_STATE_TRANSITION: installation is deleting"
)

type installationRec struct {
	proto             *secflowv1.PluginInstallation
	tokenHash         [32]byte
	hasToken          bool
	tokenPrefix       string
	approvedManifests []*secflowv1.PluginManifest
	lastError         string
}

func pluginOwnerKey(pid string) string {
	return strings.ToLower(strings.TrimSpace(pid))
}

func cloneInstallation(in *secflowv1.PluginInstallation) *secflowv1.PluginInstallation {
	if in == nil {
		return nil
	}
	cp, _ := proto.Clone(in).(*secflowv1.PluginInstallation)
	return cp
}

func requireOwnerActor(actor *secflowv1.ActorContext) error {
	if actor == nil {
		return status.Error(codes.PermissionDenied, "FORBIDDEN: owner role required")
	}
	if actor.GetAuthMode() == secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN {
		return status.Error(codes.PermissionDenied, "FORBIDDEN: scoped tokens cannot manage plugin installations")
	}
	if actor.GetRole() != secflowv1.Role_ROLE_OWNER {
		return status.Error(codes.PermissionDenied, "FORBIDDEN: owner role required")
	}
	return nil
}

func validateInstallationSpec(name, presetID, imageRef string, profile secflowv1.SandboxProfile, allowlist []string) error {
	for _, field := range []string{name, presetID, imageRef} {
		if urlguard.Denied(field) {
			return status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner name")
		}
	}
	if urlguard.Denied(name + " " + presetID + " " + imageRef) {
		return status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner name")
	}
	if profile == secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN {
		return status.Error(codes.InvalidArgument, "orchestrator builtin sandbox profile is not valid for installations")
	}
	if profile == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY && len(allowlist) > 0 {
		return status.Error(codes.InvalidArgument, "egress_allowlist must be empty for INTERNAL_ONLY")
	}
	for _, entry := range allowlist {
		if err := validateEgressEntry(entry); err != nil {
			return err
		}
	}
	return nil
}

var blockedSandboxPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func validateEgressEntry(raw string) error {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return status.Error(codes.InvalidArgument, "egress_allowlist contains an empty entry")
	}
	if urlguard.Denied(entry) {
		return status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner in egress_allowlist")
	}
	allowDevLocal := os.Getenv("SECFLOW_ENV") != "production" && os.Getenv("ALLOW_DEV_EGRESS_LOCAL") == "1"
	if strings.Contains(entry, "://") {
		u, err := url.Parse(entry)
		if err != nil || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
			return status.Errorf(codes.PermissionDenied, "ALLOWLIST_DENIED: unsupported scheme in target %q", entry)
		}
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host == "" || (!allowDevLocal && isBlockedSandboxHost(host)) {
			return status.Errorf(codes.PermissionDenied, "ALLOWLIST_DENIED: target %q is disallowed", entry)
		}
		return nil
	}
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid egress CIDR %q", entry)
		}
		if !allowDevLocal && isBlockedSandboxPrefix(prefix) {
			return status.Errorf(codes.PermissionDenied, "ALLOWLIST_DENIED: private or loopback CIDR %q is disallowed", entry)
		}
		return nil
	}
	host := extractEgressHost(entry)
	if host == "" || (!allowDevLocal && isBlockedSandboxHost(host)) {
		return status.Errorf(codes.PermissionDenied, "ALLOWLIST_DENIED: target %q is disallowed", entry)
	}
	return nil
}

func extractEgressHost(entry string) string {
	lower := strings.ToLower(strings.TrimSpace(entry))
	if h, _, err := net.SplitHostPort(lower); err == nil {
		lower = h
	} else if strings.HasPrefix(lower, "[") && strings.HasSuffix(lower, "]") {
		lower = lower[1 : len(lower)-1]
	}
	return strings.TrimPrefix(lower, "*.")
}

func isBlockedSandboxHost(rawHost string) bool {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if host == "" || strings.Contains(host, "%") {
		return true
	}
	for _, exact := range []string{"localhost", "local", "internal", "svc", "cluster.local", "home.arpa", "metadata.google.internal"} {
		if host == exact || strings.HasSuffix(host, "."+exact) {
			return true
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return isBlockedSandboxAddr(addr.Unmap())
	}
	if !strings.Contains(host, ".") {
		return true
	}
	lastDot := strings.LastIndexByte(host, '.')
	return isNumericOrHexLabel(host[lastDot+1:])
}

func isNumericOrHexLabel(label string) bool {
	if label == "" {
		return true
	}
	if strings.HasPrefix(label, "0x") && len(label) > 2 {
		for i := 2; i < len(label); i++ {
			c := label[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

func isBlockedSandboxPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return true
	}
	for _, blocked := range blockedSandboxPrefixes {
		if prefix.Overlaps(blocked) {
			return true
		}
	}
	return false
}

func isBlockedSandboxAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	for _, blocked := range blockedSandboxPrefixes {
		if blocked.Contains(addr) {
			return true
		}
	}
	return false
}

func appendAndCheckFields(b *strings.Builder, fields ...string) bool {
	for _, f := range fields {
		if urlguard.Denied(f) {
			return true
		}
		if f != "" {
			b.WriteByte(' ')
			b.WriteString(f)
		}
	}
	return false
}

func portsDenied(b *strings.Builder, ports []*secflowv1.PortDefinition) bool {
	for _, p := range ports {
		if appendAndCheckFields(b, p.GetId(), p.GetLabel(), p.GetDescription()) {
			return true
		}
	}
	return false
}

func collectJSONStrings(v any, b *strings.Builder) bool {
	switch tv := v.(type) {
	case string:
		return appendAndCheckFields(b, tv)
	case []any:
		for _, item := range tv {
			if collectJSONStrings(item, b) {
				return true
			}
		}
	case map[string]any:
		for k, val := range tv {
			if appendAndCheckFields(b, k) || collectJSONStrings(val, b) {
				return true
			}
		}
	}
	return false
}

func manifestDenied(m *secflowv1.PluginManifest) bool {
	if m == nil {
		return false
	}
	var b strings.Builder
	if appendAndCheckFields(
		&b,
		m.GetPluginId(),
		m.GetVersion(),
		m.GetDisplayName(),
		m.GetDescription(),
		m.GetRuntimeLanguage(),
	) {
		return true
	}
	if appendAndCheckFields(&b, m.GetCapabilities()...) || appendAndCheckFields(&b, m.GetRequiredSecretKeys()...) {
		return true
	}
	if portsDenied(&b, m.GetInputPorts()) || portsDenied(&b, m.GetOutputPorts()) {
		return true
	}
	if raw := m.GetParamsJsonSchema(); len(raw) > 0 {
		if appendAndCheckFields(&b, string(raw)) {
			return true
		}
		var doc any
		if json.Unmarshal(raw, &doc) == nil && collectJSONStrings(doc, &b) {
			return true
		}
	}
	return urlguard.Denied(b.String())
}

func validateExternalManifests(manifests []*secflowv1.PluginManifest, instProfile secflowv1.SandboxProfile) (secflowv1.ManifestRejectionCode, error) {
	if len(manifests) == 0 {
		return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_INVALID_SCHEMA,
			status.Error(codes.InvalidArgument, "at least one manifest is required")
	}
	seen := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		if m == nil {
			return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_INVALID_SCHEMA,
				status.Error(codes.InvalidArgument, "plugin_id must not be empty")
		}
		rawPID := m.GetPluginId()
		pid := strings.TrimSpace(rawPID)
		if pid == "" || rawPID != pid {
			return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_INVALID_SCHEMA,
				status.Error(codes.InvalidArgument, "plugin_id must not be empty or have leading/trailing whitespace")
		}
		lowPID := strings.ToLower(pid)
		if seen[lowPID] {
			return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DUPLICATE_PLUGIN_ID,
				status.Errorf(codes.AlreadyExists, "duplicate plugin_id %q in register manifest", pid)
		}
		seen[lowPID] = true
		if code, err := validateSingleExternalManifest(m, instProfile); err != nil {
			return code, err
		}
	}
	return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNSPECIFIED, nil
}

func validateSingleExternalManifest(m *secflowv1.PluginManifest, instProfile secflowv1.SandboxProfile) (secflowv1.ManifestRejectionCode, error) {
	if manifestDenied(m) {
		return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_DENYLIST_BLOCKED,
			status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED: prohibited scanner reference")
	}
	pid := strings.TrimSpace(m.GetPluginId())
	if _, isBuiltin := manifest.LookupBuiltin(strings.ToLower(pid)); isBuiltin {
		return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_BUILTIN_OVERRIDE_FORBIDDEN,
			status.Errorf(codes.PermissionDenied, "FORBIDDEN: cannot override built-in plugin_id %q", pid)
	}
	cat := m.GetCategory()
	if cat == secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED ||
		cat == secflowv1.PluginCategory_PLUGIN_CATEGORY_TRIGGER ||
		cat == secflowv1.PluginCategory_PLUGIN_CATEGORY_SOURCE {
		return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNSUPPORTED_CATEGORY,
			status.Errorf(codes.InvalidArgument, "external plugins cannot register category %s", cat.String())
	}
	if code, err := validateExternalSandboxProfile(m, instProfile); err != nil {
		return code, err
	}
	if raw := m.GetParamsJsonSchema(); len(raw) > 0 {
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_INVALID_SCHEMA,
				status.Errorf(codes.InvalidArgument, "invalid params_json_schema for %s", pid)
		}
	}
	return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNSPECIFIED, nil
}

func validateExternalSandboxProfile(m *secflowv1.PluginManifest, instProfile secflowv1.SandboxProfile) (secflowv1.ManifestRejectionCode, error) {
	sp := m.GetSandboxProfile()
	cat := m.GetCategory()
	if sp == secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN ||
		sp == secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED {
		return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH,
			status.Errorf(codes.FailedPrecondition, "SANDBOX_PROFILE_MISMATCH: invalid sandbox profile %s", sp.String())
	}
	if cat != secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION {
		if sp != secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY {
			return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH,
				status.Errorf(codes.FailedPrecondition, "SANDBOX_PROFILE_MISMATCH: category %s requires INTERNAL_ONLY", cat.String())
		}
		if len(m.GetRequiredSecretKeys()) > 0 {
			return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH,
				status.Errorf(codes.FailedPrecondition, "SANDBOX_PROFILE_MISMATCH: category %s cannot require secrets", cat.String())
		}
		if instProfile == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
			return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH,
				status.Errorf(codes.FailedPrecondition, "SANDBOX_PROFILE_MISMATCH: EGRESS_EXTERNAL installation only permits ACTION plugins, not %s", cat.String())
		}
	}
	if instProfile == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY &&
		sp == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
		return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH,
			status.Error(codes.FailedPrecondition, "SANDBOX_PROFILE_MISMATCH: installation is INTERNAL_ONLY")
	}
	return secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNSPECIFIED, nil
}

func generatePluginToken() (string, string, [32]byte, error) {
	var zero [32]byte
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", zero, fmt.Errorf("generate plugin token: %w", err)
	}
	plaintext := pluginTokenPrefix + hex.EncodeToString(buf)
	prefix := plaintext[:14]
	return plaintext, prefix, sha256.Sum256([]byte(plaintext)), nil
}

func hashPluginToken(plaintext string) [32]byte {
	return sha256.Sum256([]byte(plaintext))
}

func computeManifestDigest(manifests []*secflowv1.PluginManifest) string {
	if len(manifests) == 0 {
		return ""
	}
	cloned := clonePluginManifests(manifests)
	sort.Slice(cloned, func(i, j int) bool {
		return cloned[i].GetPluginId() < cloned[j].GetPluginId()
	})
	h := sha256.New()
	opts := proto.MarshalOptions{Deterministic: true}
	for _, m := range cloned {
		raw, _ := opts.Marshal(m)
		_, _ = h.Write(raw)
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func detectManifestEscalation(approved, incoming []*secflowv1.PluginManifest) bool {
	if len(approved) == 0 {
		return false
	}
	byID := make(map[string]*secflowv1.PluginManifest, len(approved))
	for _, m := range approved {
		byID[m.GetPluginId()] = m
	}
	for _, inc := range incoming {
		prev, ok := byID[inc.GetPluginId()]
		if !ok {
			return true
		}
		if inc.GetCategory() != prev.GetCategory() {
			return true
		}
		if prev.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY &&
			inc.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
			return true
		}
		for _, k := range inc.GetRequiredSecretKeys() {
			if !slices.Contains(prev.GetRequiredSecretKeys(), k) {
				return true
			}
		}
	}
	return false
}

func detectUpdateEscalation(prev *secflowv1.PluginInstallation, req *secflowv1.UpdatePluginInstallationRequest) bool {
	if prev == nil || req == nil {
		return false
	}
	if req.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL &&
		prev.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
		return true
	}
	if req.GetEgressAllowlist() != nil {
		for _, entry := range req.GetEgressAllowlist() {
			if !slices.Contains(prev.GetEgressAllowlist(), entry) {
				return true
			}
		}
	}
	if img := strings.TrimSpace(req.GetImageRef()); img != "" && img != prev.GetImageRef() &&
		(prev.GetSourceMode() == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_OCI_IMAGE ||
			prev.GetSourceMode() == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET) {
		return true
	}
	return false
}

func (s *Server) ListPluginPresets(_ context.Context, _ *secflowv1.ListPluginPresetsRequest) (*secflowv1.ListPluginPresetsResponse, error) {
	specs := builtinPluginPresets()
	out := make([]*secflowv1.PluginPreset, 0, len(specs))
	for _, spec := range specs {
		cloned := clonePresetSpec(spec)
		if cloned.preset != nil {
			out = append(out, cloned.preset)
		}
	}
	return &secflowv1.ListPluginPresetsResponse{Presets: out}, nil
}

func (s *Server) ListPluginInstallations(_ context.Context, _ *secflowv1.ListPluginInstallationsRequest) (*secflowv1.ListPluginInstallationsResponse, error) {
	s.plugMu.Lock()
	items := make([]*secflowv1.PluginInstallation, 0, len(s.installations))
	for _, rec := range s.installations {
		if rec != nil && rec.proto != nil {
			items = append(items, cloneInstallation(rec.proto))
		}
	}
	s.plugMu.Unlock()
	sort.Slice(items, func(i, j int) bool {
		return items[i].GetName() < items[j].GetName()
	})
	return &secflowv1.ListPluginInstallationsResponse{Installations: items}, nil
}

func (s *Server) GetPluginInstallation(_ context.Context, req *secflowv1.GetPluginInstallationRequest) (*secflowv1.GetPluginInstallationResponse, error) {
	instID := strings.TrimSpace(req.GetInstallationId())
	if instID == "" {
		return nil, status.Error(codes.InvalidArgument, errInstallationIDRequired)
	}
	s.plugMu.Lock()
	rec := s.installations[instID]
	var out *secflowv1.PluginInstallation
	if rec != nil && rec.proto != nil {
		out = cloneInstallation(rec.proto)
	}
	s.plugMu.Unlock()
	if out == nil {
		return nil, status.Error(codes.NotFound, errInstallationNotFound)
	}
	return &secflowv1.GetPluginInstallationResponse{Installation: out}, nil
}

func (s *Server) InstallPlugin(ctx context.Context, req *secflowv1.InstallPluginRequest) (*secflowv1.InstallPluginResponse, error) {
	sourceMode := req.GetSourceMode()
	if sourceMode == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE {
		if err := requireEditorOrOwnerActor(req.GetActor()); err != nil {
			return nil, err
		}
	} else {
		if err := requireOwnerActor(req.GetActor()); err != nil {
			return nil, err
		}
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "installation name is required")
	}
	if sourceMode == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "source_mode is required")
	}
	profile := req.GetSandboxProfile()
	if profile == secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED {
		profile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
	}
	if sourceMode != secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE {
		if err := validateInstallationSpec(name, req.GetPresetId(), req.GetImageRef(), profile, req.GetEgressAllowlist()); err != nil {
			return nil, err
		}
	}

	plaintext, prefix, tokHash, err := generatePluginToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "issue plugin token: %v", err)
	}
	now := timestamppb.Now()
	inst, approvedManifests, returnToken, err := s.buildNewInstallation(req, name, sourceMode, profile, now)
	if err != nil {
		return nil, err
	}

	rec := &installationRec{
		proto:             inst,
		tokenHash:         tokHash,
		hasToken:          true,
		tokenPrefix:       prefix,
		approvedManifests: approvedManifests,
	}

	s.plugMu.Lock()
	for _, existing := range s.installations {
		if existing == nil || existing.proto == nil {
			continue
		}
		if strings.EqualFold(existing.proto.GetName(), name) {
			s.plugMu.Unlock()
			return nil, status.Errorf(codes.AlreadyExists, "plugin installation %q already exists", name)
		}
		for _, pid := range inst.GetPluginIds() {
			if slices.ContainsFunc(existing.proto.GetPluginIds(), func(other string) bool {
				return strings.EqualFold(other, pid)
			}) {
				s.plugMu.Unlock()
				return nil, status.Errorf(codes.AlreadyExists, "DUPLICATE_PLUGIN_ID: plugin_id %q is already owned by installation %s", pid, existing.proto.GetId())
			}
		}
	}
	for _, m := range approvedManifests {
		pid := m.GetPluginId()
		ownerKey := pluginOwnerKey(pid)
		if _, isBuiltin := manifest.LookupBuiltin(ownerKey); isBuiltin {
			s.plugMu.Unlock()
			return nil, status.Errorf(codes.PermissionDenied, "FORBIDDEN: cannot override built-in plugin_id %q", pid)
		}
		if owner := s.pluginInstallation[ownerKey]; owner != "" {
			s.plugMu.Unlock()
			return nil, status.Errorf(codes.AlreadyExists, "DUPLICATE_PLUGIN_ID: plugin_id %q is already owned by installation %s", pid, owner)
		}
	}
	s.installations[inst.GetId()] = rec
	var pluginEvents []*secflowv1.PluginRegistryEvent
	if inst.GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE && len(approvedManifests) > 0 {
		pluginEvents = s.upsertInstallationPluginsLocked(inst.GetId(), approvedManifests, true, approvalStateApproved, now)
	}
	instOut := cloneInstallation(inst)
	s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED, instOut)
	for _, pev := range pluginEvents {
		s.fanoutPlugin(pev)
	}
	s.plugMu.Unlock()

	s.persistInstallationAndPlugins(ctx, rec, "CREATED", inst.GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE)

	resp := &secflowv1.InstallPluginResponse{Installation: instOut}
	if returnToken {
		resp.PlaintextPluginToken = plaintext
	}
	return resp, nil
}

func (s *Server) buildNewInstallation(
	req *secflowv1.InstallPluginRequest,
	name string,
	sourceMode secflowv1.PluginSourceMode,
	profile secflowv1.SandboxProfile,
	now *timestamppb.Timestamp,
) (*secflowv1.PluginInstallation, []*secflowv1.PluginManifest, bool, error) {
	desiredReplicas := req.GetDesiredReplicas()
	if desiredReplicas <= 0 {
		desiredReplicas = 1
	}
	inst := &secflowv1.PluginInstallation{
		Id:              id("inst"),
		Name:            name,
		SourceMode:      sourceMode,
		PresetId:        strings.TrimSpace(req.GetPresetId()),
		ImageRef:        strings.TrimSpace(req.GetImageRef()),
		SandboxProfile:  profile,
		EgressAllowlist: slices.Clone(req.GetEgressAllowlist()),
		ResourceLimits:  cloneLimits(req.GetResourceLimits()),
		DesiredReplicas: desiredReplicas,
		AutoApprove:     req.GetAutoApprove(),
		CreatedBy:       subject(req.GetActor()),
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	switch sourceMode {
	case secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET:
		return s.populatePresetInstallation(inst, req, now)
	case secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_OCI_IMAGE:
		if inst.GetImageRef() == "" {
			return nil, nil, false, status.Error(codes.InvalidArgument, "image_ref is required for OCI_IMAGE")
		}
		inst.AutoApprove = false
		if os.Getenv("PLUGIN_PROVISIONER_ENABLED") == "1" {
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING
		} else {
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
		}
		return inst, nil, false, nil
	case secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL:
		if req.GetAutoApprove() {
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
			inst.ApprovedBy = subject(req.GetActor())
			inst.ApprovedAt = now
		} else {
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
		}
		return inst, nil, true, nil
	case secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE:
		return s.populateDeclarativeInstallation(inst, req, now)
	default:
		return nil, nil, false, status.Error(codes.InvalidArgument, "unsupported source_mode")
	}
}

func (s *Server) populatePresetInstallation(
	inst *secflowv1.PluginInstallation,
	req *secflowv1.InstallPluginRequest,
	now *timestamppb.Timestamp,
) (*secflowv1.PluginInstallation, []*secflowv1.PluginManifest, bool, error) {
	spec, ok := lookupPluginPreset(inst.GetPresetId())
	if !ok {
		return nil, nil, false, status.Errorf(codes.NotFound, "preset %q not found", inst.GetPresetId())
	}
	if req.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED &&
		req.GetSandboxProfile() != spec.preset.GetSandboxProfile() {
		return nil, nil, false, status.Errorf(codes.FailedPrecondition, "SANDBOX_PROFILE_MISMATCH: preset %q requires %s", spec.preset.GetId(), spec.preset.GetSandboxProfile().String())
	}
	inst.SandboxProfile = spec.preset.GetSandboxProfile()
	if inst.GetImageRef() == "" {
		inst.ImageRef = spec.preset.GetImageRef()
	}
	if len(inst.GetEgressAllowlist()) == 0 && len(spec.preset.GetDefaultEgressAllowlist()) > 0 {
		inst.EgressAllowlist = slices.Clone(spec.preset.GetDefaultEgressAllowlist())
	}
	if inst.GetResourceLimits() == nil && spec.preset.GetDefaultResourceLimits() != nil {
		inst.ResourceLimits = cloneLimits(spec.preset.GetDefaultResourceLimits())
	}
	manifests := clonePluginManifests(spec.manifests)
	inst.PluginIds = manifestPluginIDs(manifests)
	if req.GetAutoApprove() && spec.preset.GetAutoApproveSupported() {
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
		inst.Manifests = manifests
		inst.ApprovedManifestDigest = computeManifestDigest(manifests)
		inst.ApprovedBy = subject(req.GetActor())
		inst.ApprovedAt = now
		return inst, clonePluginManifests(manifests), false, nil
	}
	inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
	inst.PendingManifests = manifests
	return inst, nil, false, nil
}

func (s *Server) ApprovePluginInstallation(ctx context.Context, req *secflowv1.ApprovePluginInstallationRequest) (*secflowv1.ApprovePluginInstallationResponse, error) {
	if err := requireOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	instID := strings.TrimSpace(req.GetInstallationId())
	if instID == "" {
		return nil, status.Error(codes.InvalidArgument, errInstallationIDRequired)
	}

	now := timestamppb.Now()
	s.plugMu.Lock()
	rec := s.installations[instID]
	if rec == nil || rec.proto == nil {
		s.plugMu.Unlock()
		return nil, status.Error(codes.NotFound, errInstallationNotFound)
	}
	inst := rec.proto
	hasPendingRevision := len(inst.GetPendingManifests()) > 0 || len(inst.GetPendingDeclarativeSpecJson()) > 0
	if inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL &&
		inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING &&
		inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DRAFT &&
		!(inst.GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE && hasPendingRevision) {
		s.plugMu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition, "INVALID_STATE_TRANSITION: cannot approve from %s", inst.GetStatus().String())
	}
	if inst.GetSourceMode() == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE && len(inst.GetPendingDeclarativeSpecJson()) > 0 {
		spec, err := declarativeplugin.ValidateSpec(inst.GetPendingDeclarativeSpecJson())
		if err != nil {
			s.plugMu.Unlock()
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		inst.SandboxProfile = spec.SandboxProfile()
		inst.EgressAllowlist = slices.Clone(spec.EgressAllowlist)
		inst.DeclarativeSpecJson = slices.Clone(inst.GetPendingDeclarativeSpecJson())
		inst.PendingDeclarativeSpecJson = nil
		inst.PluginVersion = spec.Version
	}
	if err := validateInstallationSpec(inst.GetName(), inst.GetPresetId(), inst.GetImageRef(), inst.GetSandboxProfile(), inst.GetEgressAllowlist()); err != nil {
		s.plugMu.Unlock()
		return nil, err
	}

	candidates := clonePluginManifests(inst.GetPendingManifests())
	if len(candidates) == 0 {
		candidates = clonePluginManifests(inst.GetManifests())
	}
	if len(candidates) > 0 {
		if _, err := validateExternalManifests(candidates, inst.GetSandboxProfile()); err != nil {
			s.plugMu.Unlock()
			return nil, err
		}
		for _, m := range candidates {
			if owner := s.pluginInstallation[pluginOwnerKey(m.GetPluginId())]; owner != "" && owner != instID {
				s.plugMu.Unlock()
				return nil, status.Errorf(codes.AlreadyExists, "plugin_id %q is owned by installation %s", m.GetPluginId(), owner)
			}
		}
		digest := computeManifestDigest(candidates)
		if exp := strings.TrimSpace(req.GetExpectedManifestDigest()); exp != "" && exp != digest {
			s.plugMu.Unlock()
			return nil, status.Errorf(codes.Aborted, "manifest digest mismatch: got %s want %s", digest, exp)
		}
		inst.Manifests = candidates
		inst.PluginIds = manifestPluginIDs(candidates)
		inst.ApprovedManifestDigest = digest
		rec.approvedManifests = clonePluginManifests(candidates)
	}
	inst.PendingManifests = nil
	inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
	inst.StatusReason = ""
	inst.ApprovedBy = subject(req.GetActor())
	inst.ApprovedAt = now
	inst.UpdatedAt = now

	var pluginEvents []*secflowv1.PluginRegistryEvent
	if len(inst.GetManifests()) > 0 {
		pluginEvents = s.upsertInstallationPluginsLocked(instID, inst.GetManifests(), true, approvalStateApproved, now)
	}
	instOut := cloneInstallation(inst)
	s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_APPROVED, instOut)
	for _, pev := range pluginEvents {
		s.fanoutPlugin(pev)
	}
	s.plugMu.Unlock()

	s.persistInstallationAndPlugins(ctx, rec, "APPROVED", len(instOut.GetManifests()) > 0)
	return &secflowv1.ApprovePluginInstallationResponse{Installation: instOut}, nil
}

func validateUpdateRequestedStatus(reqStatus secflowv1.PluginInstallationStatus) error {
	switch reqStatus {
	case secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_UNSPECIFIED,
		secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING,
		secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL,
		secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ERROR:
		return nil
	default:
		return status.Errorf(codes.FailedPrecondition, "INVALID_STATE_TRANSITION: cannot set status %s via UpdatePluginInstallation", reqStatus.String())
	}
}

func (s *Server) resetInstallationApprovalLocked(instID string, rec *installationRec) []*secflowv1.PluginRegistryEvent {
	inst := rec.proto
	inst.ApprovedManifestDigest = ""
	inst.ApprovedBy = ""
	inst.ApprovedAt = nil
	rec.approvedManifests = nil
	if len(inst.GetManifests()) > 0 {
		if len(inst.GetPendingManifests()) == 0 {
			inst.PendingManifests = clonePluginManifests(inst.GetManifests())
		}
		return s.setInstallationPluginsEnabledLocked(instID, false, approvalStatePending)
	}
	return nil
}

func (s *Server) applyEscalationLocked(instID string, rec *installationRec, prevStatus secflowv1.PluginInstallationStatus) ([]*secflowv1.PluginRegistryEvent, []*workerLink) {
	inst := rec.proto
	if prevStatus != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING {
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
		inst.StatusReason = "privilege escalation requires re-approval"
	}
	pluginEvents := s.resetInstallationApprovalLocked(instID, rec)
	return pluginEvents, s.markInstallationLinksDrainingLocked(instID)
}

func (s *Server) applyNonEscalatedUpdateStatusLocked(
	instID string,
	rec *installationRec,
	prevStatus secflowv1.PluginInstallationStatus,
	reqStatus secflowv1.PluginInstallationStatus,
	statusReason string,
) ([]*secflowv1.PluginRegistryEvent, []*workerLink, bool) {
	inst := rec.proto
	inst.Status = reqStatus
	if reqStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ERROR && statusReason != "" {
		rec.lastError = statusReason
	}
	if reqStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL {
		pluginEvents := s.resetInstallationApprovalLocked(instID, rec)
		var linksToDrain []*workerLink
		if prevStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE {
			linksToDrain = s.markInstallationLinksDrainingLocked(instID)
		}
		return pluginEvents, linksToDrain, true
	}
	if prevStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE &&
		(reqStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ERROR ||
			reqStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PROVISIONING) {
		pluginEvents := s.setInstallationPluginsEnabledLocked(instID, false, "")
		return pluginEvents, s.markInstallationLinksDrainingLocked(instID), true
	}
	return nil, nil, false
}

func (s *Server) UpdatePluginInstallation(ctx context.Context, req *secflowv1.UpdatePluginInstallationRequest) (*secflowv1.UpdatePluginInstallationResponse, error) {
	instID := strings.TrimSpace(req.GetInstallationId())
	if instID == "" {
		return nil, status.Error(codes.InvalidArgument, errInstallationIDRequired)
	}
	s.plugMu.Lock()
	existingRec := s.installations[instID]
	isDeclarative := existingRec != nil && existingRec.proto != nil && existingRec.proto.GetSourceMode() == secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_DECLARATIVE
	s.plugMu.Unlock()
	if isDeclarative {
		return s.updateDeclarativeInstallation(ctx, req)
	}
	if err := requireOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	if len(req.GetDeclarativeSpecJson()) > 0 {
		return nil, status.Error(codes.InvalidArgument, "VALIDATION_FAILED: declarative_spec_json is only supported for DECLARATIVE installations")
	}
	if err := validateUpdateRequestedStatus(req.GetStatus()); err != nil {
		return nil, err
	}

	s.plugMu.Lock()
	rec := s.installations[instID]
	if rec == nil || rec.proto == nil {
		s.plugMu.Unlock()
		return nil, status.Error(codes.NotFound, errInstallationNotFound)
	}
	inst := rec.proto
	prevStatus := inst.GetStatus()
	prevProfile := inst.GetSandboxProfile()
	if prevStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DELETING {
		s.plugMu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, errInstallationDeleting)
	}

	nextImage := inst.GetImageRef()
	if v := strings.TrimSpace(req.GetImageRef()); v != "" {
		nextImage = v
	}
	nextProfile := prevProfile
	if req.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_UNSPECIFIED {
		nextProfile = req.GetSandboxProfile()
	}
	downgradedProfile := prevProfile == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL &&
		nextProfile == secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
	nextAllowlist := inst.GetEgressAllowlist()
	if req.GetEgressAllowlist() != nil {
		nextAllowlist = slices.Clone(req.GetEgressAllowlist())
	} else if downgradedProfile {
		nextAllowlist = nil
	}
	if err := validateInstallationSpec(inst.GetName(), inst.GetPresetId(), nextImage, nextProfile, nextAllowlist); err != nil {
		s.plugMu.Unlock()
		return nil, err
	}

	escalated := detectUpdateEscalation(inst, req)
	now := timestamppb.Now()
	var plaintext string
	if req.GetRotateToken() {
		tok, prefix, tokHash, err := generatePluginToken()
		if err != nil {
			s.plugMu.Unlock()
			return nil, status.Errorf(codes.Internal, "rotate plugin token: %v", err)
		}
		plaintext = tok
		rec.tokenHash = tokHash
		rec.hasToken = true
		rec.tokenPrefix = prefix
	}

	inst.ImageRef = nextImage
	inst.SandboxProfile = nextProfile
	inst.EgressAllowlist = nextAllowlist
	if req.GetResourceLimits() != nil {
		inst.ResourceLimits = cloneLimits(req.GetResourceLimits())
	}
	if req.GetDesiredReplicas() > 0 {
		inst.DesiredReplicas = req.GetDesiredReplicas()
	}
	if req.GetRuntimeDiagnostics() != nil {
		diag, _ := proto.Clone(req.GetRuntimeDiagnostics()).(*secflowv1.PluginRuntimeDiagnostics)
		inst.RuntimeDiagnostics = diag
	}
	if req.GetStatusReason() != "" {
		inst.StatusReason = req.GetStatusReason()
	}

	var linksToDrain []*workerLink
	var pluginEvents []*secflowv1.PluginRegistryEvent
	syncPlugins := false

	if escalated {
		pluginEvents, linksToDrain = s.applyEscalationLocked(instID, rec, prevStatus)
		syncPlugins = true
	} else if reqStatus := req.GetStatus(); reqStatus != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_UNSPECIFIED {
		pluginEvents, linksToDrain, syncPlugins = s.applyNonEscalatedUpdateStatusLocked(instID, rec, prevStatus, reqStatus, req.GetStatusReason())
	}
	if len(linksToDrain) == 0 && (req.GetRotateToken() ||
		(downgradedProfile && prevStatus == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE)) {
		linksToDrain = s.markInstallationLinksDrainingLocked(instID)
	}
	inst.UpdatedAt = now
	instOut := cloneInstallation(inst)
	s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_UPDATED, instOut)
	for _, pev := range pluginEvents {
		s.fanoutPlugin(pev)
	}
	s.plugMu.Unlock()

	if len(linksToDrain) > 0 {
		drainReason := "installation configuration updated"
		switch {
		case escalated:
			drainReason = "privilege escalation requires re-approval"
		case downgradedProfile:
			drainReason = "sandbox profile downgraded to INTERNAL_ONLY"
		case req.GetRotateToken():
			drainReason = "plugin token rotated"
		}
		s.drainWorkerLinks(linksToDrain, drainReason, defaultDrainGraceSec)
	}
	s.persistInstallationAndPlugins(ctx, rec, "UPDATED", syncPlugins)

	return &secflowv1.UpdatePluginInstallationResponse{
		Installation:         instOut,
		PlaintextPluginToken: plaintext,
	}, nil
}

func (s *Server) SetPluginInstallationEnabled(ctx context.Context, req *secflowv1.SetPluginInstallationEnabledRequest) (*secflowv1.SetPluginInstallationEnabledResponse, error) {
	if err := requireOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	instID := strings.TrimSpace(req.GetInstallationId())
	if instID == "" {
		return nil, status.Error(codes.InvalidArgument, errInstallationIDRequired)
	}

	now := timestamppb.Now()
	s.plugMu.Lock()
	rec := s.installations[instID]
	if rec == nil || rec.proto == nil {
		s.plugMu.Unlock()
		return nil, status.Error(codes.NotFound, errInstallationNotFound)
	}
	inst := rec.proto
	if inst.GetStatus() == secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DELETING {
		s.plugMu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, errInstallationDeleting)
	}

	var linksToDrain []*workerLink
	var pluginEvents []*secflowv1.PluginRegistryEvent
	if !req.GetEnabled() {
		if inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE &&
			inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL &&
			inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ERROR &&
			inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DISABLED {
			s.plugMu.Unlock()
			return nil, status.Errorf(codes.FailedPrecondition, "INVALID_STATE_TRANSITION: cannot disable from %s", inst.GetStatus().String())
		}
		inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DISABLED
		inst.StatusReason = strings.TrimSpace(req.GetReason())
		pluginEvents = s.setInstallationPluginsEnabledLocked(instID, false, "")
		linksToDrain = s.markInstallationLinksDrainingLocked(instID)
	} else {
		if inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DISABLED &&
			inst.GetStatus() != secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE {
			s.plugMu.Unlock()
			return nil, status.Errorf(codes.FailedPrecondition, "INVALID_STATE_TRANSITION: cannot enable from %s", inst.GetStatus().String())
		}
		if len(inst.GetPendingManifests()) > 0 ||
			inst.GetApprovedAt() == nil ||
			(inst.GetApprovedManifestDigest() == "" && inst.GetSourceMode() != secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL) {
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL
			pluginEvents = s.setInstallationPluginsEnabledLocked(instID, false, approvalStatePending)
		} else {
			inst.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE
			inst.StatusReason = ""
			pluginEvents = s.setInstallationPluginsEnabledLocked(instID, true, approvalStateApproved)
		}
	}
	inst.UpdatedAt = now
	instOut := cloneInstallation(inst)
	s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_STATUS_CHANGED, instOut)
	for _, pev := range pluginEvents {
		s.fanoutPlugin(pev)
	}
	s.plugMu.Unlock()

	if len(linksToDrain) > 0 {
		reason := strings.TrimSpace(req.GetReason())
		if reason == "" {
			reason = "plugin installation disabled"
		}
		s.drainWorkerLinks(linksToDrain, reason, defaultDrainGraceSec)
	}
	s.persistInstallationAndPlugins(ctx, rec, "STATUS_CHANGED", true)
	return &secflowv1.SetPluginInstallationEnabledResponse{Installation: instOut}, nil
}

func (s *Server) DeletePluginInstallation(ctx context.Context, req *secflowv1.DeletePluginInstallationRequest) (*secflowv1.DeletePluginInstallationResponse, error) {
	if err := requireOwnerActor(req.GetActor()); err != nil {
		return nil, err
	}
	instID := strings.TrimSpace(req.GetInstallationId())
	if instID == "" {
		return nil, status.Error(codes.InvalidArgument, errInstallationIDRequired)
	}

	now := timestamppb.Now()
	s.plugMu.Lock()
	rec := s.installations[instID]
	if rec == nil || rec.proto == nil {
		s.plugMu.Unlock()
		return nil, status.Error(codes.NotFound, errInstallationNotFound)
	}
	rec.proto.Status = secflowv1.PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_DELETING
	statusReason := strings.TrimSpace(req.GetReason())
	rec.proto.StatusReason = statusReason
	rec.proto.UpdatedAt = now
	linksToDrain := s.markInstallationLinksDrainingLocked(instID)
	pluginEvents := s.removeInstallationPluginsLocked(instID)
	instOut := cloneInstallation(rec.proto)
	if os.Getenv("PLUGIN_PROVISIONER_ENABLED") != "1" {
		delete(s.installations, instID)
	}
	s.fanoutInstallationLocked(secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_DELETED, instOut)
	for _, pev := range pluginEvents {
		s.fanoutPlugin(pev)
	}
	s.plugMu.Unlock()

	if len(linksToDrain) > 0 {
		reason := statusReason
		if reason == "" {
			reason = "plugin installation deleted"
		}
		s.drainWorkerLinks(linksToDrain, reason, 10)
	}
	s.deleteInstallationInPG(ctx, instID, statusReason)
	return &secflowv1.DeletePluginInstallationResponse{Deleted: true}, nil
}

func (s *Server) WatchPluginInstallations(req *secflowv1.WatchPluginInstallationsRequest, stream secflowv1.PluginRegistryService_WatchPluginInstallationsServer) error {
	filterID := strings.TrimSpace(req.GetInstallationId())
	now := timestamppb.Now()

	s.plugMu.Lock()
	ch := make(chan *secflowv1.PluginInstallationEvent, 32)
	s.installWatch = append(s.installWatch, ch)
	initial := make([]*secflowv1.PluginInstallationEvent, 0, len(s.installations))
	for _, rec := range s.installations {
		if rec == nil || rec.proto == nil {
			continue
		}
		if filterID != "" && rec.proto.GetId() != filterID {
			continue
		}
		initial = append(initial, &secflowv1.PluginInstallationEvent{
			EventType:    secflowv1.PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED,
			Installation: cloneInstallation(rec.proto),
			OccurredAt:   now,
		})
	}
	s.plugMu.Unlock()

	defer func() {
		s.plugMu.Lock()
		kept := s.installWatch[:0]
		for _, w := range s.installWatch {
			if w != ch {
				kept = append(kept, w)
			}
		}
		s.installWatch = kept
		s.plugMu.Unlock()
	}()

	for _, ev := range initial {
		if err := stream.Send(&secflowv1.WatchPluginInstallationsResponse{Event: ev}); err != nil {
			return err
		}
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-ch:
			if filterID != "" && ev.GetInstallation().GetId() != filterID {
				continue
			}
			if err := stream.Send(&secflowv1.WatchPluginInstallationsResponse{Event: ev}); err != nil {
				return err
			}
		}
	}
}

func (s *Server) fanoutInstallationLocked(evType secflowv1.PluginInstallationEventType, inst *secflowv1.PluginInstallation) {
	ev := &secflowv1.PluginInstallationEvent{
		EventType:    evType,
		Installation: cloneInstallation(inst),
		OccurredAt:   timestamppb.Now(),
	}
	for _, ch := range s.installWatch {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Server) upsertInstallationPluginsLocked(
	instID string,
	manifests []*secflowv1.PluginManifest,
	enabled bool,
	approvalState string,
	now *timestamppb.Timestamp,
) []*secflowv1.PluginRegistryEvent {
	keep := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		if pid := m.GetPluginId(); pid != "" {
			keep[pid] = true
		}
	}
	events := s.pruneStaleInstallationPluginsLocked(instID, keep)
	for _, m := range manifests {
		pid := m.GetPluginId()
		if pid == "" {
			continue
		}
		_, existed := s.plugins[pid]
		s.plugins[pid] = clonePluginManifest(m)
		s.pluginInstallation[pluginOwnerKey(pid)] = instID
		s.pluginApprovalState[pid] = approvalState
		if enabled {
			delete(s.pluginDisabled, pid)
		} else {
			s.pluginDisabled[pid] = true
		}
		if s.pluginRegisteredAt[pid] == nil {
			s.pluginRegisteredAt[pid] = now
		}
		if s.pluginLastSeen[pid] == nil {
			s.pluginLastSeen[pid] = now
		}
		evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_REGISTERED
		if existed {
			evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
		}
		events = append(events, pluginEvent(evType, s.registeredPluginLocked(m, 0)))
	}
	return events
}

func (s *Server) pruneStaleInstallationPluginsLocked(instID string, keep map[string]bool) []*secflowv1.PluginRegistryEvent {
	keepOwners := make(map[string]bool, len(keep))
	for pid := range keep {
		keepOwners[pluginOwnerKey(pid)] = true
	}
	var events []*secflowv1.PluginRegistryEvent
	for pid, m := range s.plugins {
		ownerKey := pluginOwnerKey(pid)
		if s.pluginInstallation[ownerKey] != instID || keep[pid] {
			continue
		}
		if m != nil {
			rp := s.registeredPluginLocked(m, 0)
			rp.Status = secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE
			rp.Enabled = false
			rp.ActiveWorkers = 0
			events = append(events, pluginEvent(secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE, rp))
		}
		delete(s.plugins, pid)
		delete(s.pluginDisabled, pid)
		delete(s.pluginApprovalState, pid)
		delete(s.pluginRegisteredAt, pid)
		delete(s.pluginLastSeen, pid)
		delete(s.pluginDBWorkers, pid)
		delete(s.workers, pid)
		s.setActiveWorkers(pid, 0)
	}
	for ownerKey, owner := range s.pluginInstallation {
		if owner == instID && !keepOwners[ownerKey] {
			delete(s.pluginInstallation, ownerKey)
		}
	}
	return events
}

func (s *Server) setInstallationPluginsEnabledLocked(instID string, enabled bool, approvalState string) []*secflowv1.PluginRegistryEvent {
	var events []*secflowv1.PluginRegistryEvent
	for pid, m := range s.plugins {
		if s.pluginInstallation[pluginOwnerKey(pid)] != instID {
			continue
		}
		if approvalState != "" {
			s.pluginApprovalState[pid] = approvalState
		}
		if enabled {
			delete(s.pluginDisabled, pid)
		} else {
			s.pluginDisabled[pid] = true
		}
		if m != nil {
			evType := secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_UPDATED
			if !enabled {
				evType = secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE
			}
			events = append(events, pluginEvent(evType, s.registeredPluginLocked(m, 0)))
		}
	}
	return events
}

func (s *Server) removeInstallationPluginsLocked(instID string) []*secflowv1.PluginRegistryEvent {
	var events []*secflowv1.PluginRegistryEvent
	for pid, m := range s.plugins {
		if s.pluginInstallation[pluginOwnerKey(pid)] != instID {
			continue
		}
		if m != nil {
			rp := s.registeredPluginLocked(m, 0)
			rp.Status = secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE
			rp.Enabled = false
			rp.ActiveWorkers = 0
			events = append(events, pluginEvent(secflowv1.PluginRegistryEventType_PLUGIN_REGISTRY_EVENT_TYPE_OFFLINE, rp))
		}
		delete(s.plugins, pid)
		delete(s.pluginDisabled, pid)
		delete(s.pluginApprovalState, pid)
		delete(s.pluginRegisteredAt, pid)
		delete(s.pluginLastSeen, pid)
		delete(s.pluginDBWorkers, pid)
		delete(s.workers, pid)
		s.setActiveWorkers(pid, 0)
	}
	for ownerKey, owner := range s.pluginInstallation {
		if owner == instID {
			delete(s.pluginInstallation, ownerKey)
		}
	}
	return events
}

func (s *Server) markInstallationLinksDrainingLocked(instID string) []*workerLink {
	seen := map[*workerLink]bool{}
	var out []*workerLink
	for pid, list := range s.workers {
		owned := s.pluginInstallation[pluginOwnerKey(pid)] == instID
		for _, w := range list {
			if w != nil && w.installationID == instID && !seen[w] {
				seen[w] = true
				w.draining.Store(true)
				out = append(out, w)
				owned = true
			}
		}
		if owned {
			s.setActiveWorkers(pid, s.activeWorkerCountLocked(pid))
		}
	}
	return out
}

func (s *Server) drainWorkerLinks(links []*workerLink, reason string, graceSec int64) {
	if len(links) == 0 {
		return
	}
	req := &secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_DrainRequest{
			DrainRequest: &secflowv1.DrainRequest{
				Reason:             reason,
				GracePeriodSeconds: graceSec,
			},
		},
	}
	for _, w := range links {
		if w != nil {
			_ = w.Send(req)
		}
	}
}

func (s *Server) findInstallationByTokenLocked(tokenHash [32]byte) *installationRec {
	for _, rec := range s.installations {
		if rec == nil || !rec.hasToken {
			continue
		}
		if hmac.Equal(rec.tokenHash[:], tokenHash[:]) {
			return rec
		}
	}
	return nil
}

func cloneLimits(in *secflowv1.PluginResourceLimits) *secflowv1.PluginResourceLimits {
	if in == nil {
		return nil
	}
	cp, _ := proto.Clone(in).(*secflowv1.PluginResourceLimits)
	return cp
}
