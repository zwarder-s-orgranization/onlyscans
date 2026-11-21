package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/gradleparser"
	"github.com/secflow/secflow/services/internal/kotlinscan"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/report"
	"github.com/secflow/secflow/services/internal/secretbox"
	"github.com/secflow/secflow/services/internal/urlguard"
)

type secretRec struct {
	meta   *secflowv1.SecretMetadata
	sealed []byte
}

type tokenRec struct {
	meta *secflowv1.ScopedTokenMetadata
	hash [32]byte
}

type findingMeta struct {
	sourceNodeID    string
	pluginID        string
	maskedSnippet   string
	isNewVsBaseline bool
}

type runState struct {
	run            *secflowv1.Run
	idempotencyKey string
	findings       []report.Finding
	findingMeta    []findingMeta
	events         []*secflowv1.RunEvent
	payloads       map[string][]byte
	watchers       []chan *secflowv1.RunEvent
	graph          engine.Graph
	sourceID       string
	repoURL        string
	trace          string
	done           map[string]engine.NodeTrace
	skipped        map[string]bool
	queued         map[string]bool
	finished       bool
}

type memTask struct {
	runID, nodeID, plugin, nodeRun string
}

type activeTask struct {
	runID    string
	nodeID   string
	pluginID string
	worker   *workerLink
}

type workerLink struct {
	mu         sync.Mutex
	send       func(*secflowv1.ConnectResponse) error
	instanceID string
	plugins    []string
	draining   atomic.Bool
}

func (w *workerLink) Send(msg *secflowv1.ConnectResponse) error {
	if w == nil || w.send == nil {
		return fmt.Errorf("worker unavailable")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.send(msg)
}

// Server is the SecFlow control plane with per-domain locks to prevent lock contention and I/O under mutexes.
type Server struct {
	secflowv1.UnimplementedWorkflowServiceServer
	secflowv1.UnimplementedRunServiceServer
	secflowv1.UnimplementedPluginRegistryServiceServer
	secflowv1.UnimplementedSecretServiceServer
	secflowv1.UnimplementedCatalogServiceServer
	secflowv1.UnimplementedMCPRegistryServiceServer
	secflowv1.UnimplementedWorkerServiceServer

	wfMu      sync.RWMutex
	workflows map[string]*secflowv1.Workflow
	templates map[string]*secflowv1.WorkflowTemplate

	runMu        sync.Mutex
	runs         map[string]*runState
	idem         map[string]string
	results      map[string]chan *secflowv1.NodeResult
	activeTasks  map[string]activeTask
	memq         []memTask
	trackedQueue map[string]string

	secMu   sync.Mutex
	secrets map[string]*secretRec
	tokens  map[string]*tokenRec

	plugMu             sync.Mutex
	plugins            map[string]*secflowv1.PluginManifest
	workers            map[string][]*workerLink
	workerRR           map[string]uint64
	pluginRegisteredAt map[string]*timestamppb.Timestamp
	pluginLastSeen     map[string]*timestamppb.Timestamp
	pluginWatch        []chan *secflowv1.PluginRegistryEvent

	catMu    sync.Mutex
	catalogs map[string]*secflowv1.VulnerabilityCatalog

	mcpMu sync.Mutex
	mcps  map[string]*secflowv1.MCPConnection

	serviceTK string
	boxKey    []byte
	leaseKey  []byte
	pool      *pgxpool.Pool
	ingest    secflowv1.SourceIngesterServiceClient
	wake      chan struct{}
}

func newServer() *Server {
	now := timestamppb.Now()
	s := &Server{
		workflows:          map[string]*secflowv1.Workflow{},
		templates:          map[string]*secflowv1.WorkflowTemplate{},
		runs:               map[string]*runState{},
		secrets:            map[string]*secretRec{},
		tokens:             map[string]*tokenRec{},
		catalogs:           map[string]*secflowv1.VulnerabilityCatalog{},
		mcps:               map[string]*secflowv1.MCPConnection{},
		plugins:            map[string]*secflowv1.PluginManifest{},
		workers:            map[string][]*workerLink{},
		workerRR:           map[string]uint64{},
		pluginRegisteredAt: map[string]*timestamppb.Timestamp{},
		pluginLastSeen:     map[string]*timestamppb.Timestamp{},
		results:            map[string]chan *secflowv1.NodeResult{},
		activeTasks:        map[string]activeTask{},
		trackedQueue:       map[string]string{},
		idem:               map[string]string{},
		serviceTK:          envutil.Get("SERVICE_TOKEN", "dev-service-token"),
		boxKey:             secretbox.Key(envutil.Get("SECRET_KEY", envutil.Get("SERVICE_TOKEN", "dev-service-token"))),
		leaseKey:           []byte(envutil.Get("LEASE_SECRET", envutil.Get("SERVICE_TOKEN", "dev-service-token"))),
		wake:               make(chan struct{}, 1),
	}
	for _, m := range builtinManifests() {
		pid := m.GetPluginId()
		s.plugins[pid] = m
		s.pluginRegisteredAt[pid] = now
		if m.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN || isOrchestratorManagedSourcePlugin(pid) {
			s.pluginLastSeen[pid] = now
		}
	}
	s.seedTemplates()
	return s
}

func (s *Server) handlers(sourceID string) map[string]engine.Handler {
	return s.handlersCtx(context.Background(), sourceID, "")
}

func (s *Server) handlersCtx(ctx context.Context, sourceID, repoURL string) map[string]engine.Handler {
	if ctx == nil {
		ctx = context.Background()
	}
	root := sourceID
	if root == "" {
		root = os.Getenv("SOURCE_ROOT")
	}
	allowInProcess := os.Getenv("ALLOW_INPROCESS_ANALYZERS") == "1"
	workerRequired := func(plugin string) engine.Handler {
		return func(n engine.Node, in engine.Envelope) engine.Result {
			if res, ok := s.callWorker(ctx, plugin, n, in); ok {
				return res
			}
			return engine.Result{
				Status: "FAILED",
				Err:    fmt.Sprintf("WORKER_UNAVAILABLE: no active worker connected for plugin %s", plugin),
			}
		}
	}
	analyzerHandler := func(plugin, category string) engine.Handler {
		return func(n engine.Node, in engine.Envelope) engine.Result {
			if res, ok := s.callWorker(ctx, plugin, n, in); ok {
				return res
			}
			if !allowInProcess {
				return engine.Result{
					Status: "FAILED",
					Err:    fmt.Sprintf("WORKER_UNAVAILABLE: no active worker connected for plugin %s", plugin),
				}
			}
			dir, done := treeOf(ctx, root, in)
			defer done()
			return scanResult(dir, in, category)
		}
	}
	out := map[string]engine.Handler{
		"source.git": func(n engine.Node, in engine.Envelope) engine.Result {
			return s.ingestSourceCtx(ctx, n, in, true, sourceID, repoURL)
		},
		"source.upload": func(n engine.Node, in engine.Envelope) engine.Result {
			return s.ingestSourceCtx(ctx, n, in, false, sourceID, repoURL)
		},
		"scan.secrets":     analyzerHandler("scan.secrets", "SECRET"),
		"scan.sast.kotlin": analyzerHandler("scan.sast.kotlin", "SAST"),
		"scan.sca":         analyzerHandler("scan.sca", "SCA"),
		"sbom.generate": func(n engine.Node, in engine.Envelope) engine.Result {
			if res, ok := s.callWorker(ctx, "sbom.generate", n, in); ok {
				return res
			}
			if !allowInProcess {
				return engine.Result{
					Status: "FAILED",
					Err:    "WORKER_UNAVAILABLE: no active worker connected for plugin sbom.generate",
				}
			}
			dir, done := treeOf(ctx, root, in)
			defer done()
			return sbomResult(dir, in)
		},
		"ai.explain":      workerRequired("ai.explain"),
		"notify.telegram": workerRequired("notify.telegram"),
		"notify.webhook":  workerRequired("notify.webhook"),
		"notify.smtp":     workerRequired("notify.smtp"),
		"mcp.tool":        workerRequired("mcp.tool"),
	}
	s.plugMu.Lock()
	for pid, m := range s.plugins {
		if _, exists := out[pid]; exists {
			continue
		}
		if m.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN {
			continue
		}
		out[pid] = workerRequired(pid)
	}
	s.plugMu.Unlock()
	return out
}

func (s *Server) seedTemplates() {
	now := timestamppb.Now()
	for _, n := range builtinTemplateGraphs() {
		s.templates[n.slug] = &secflowv1.WorkflowTemplate{
			Id: n.slug, Slug: n.slug, Name: n.name, Description: n.description, ProblemSolved: n.problem, IsBuiltin: true,
			SanitizedGraph: n.graph, CreatedAt: now, UpdatedAt: now,
		}
	}
}

func builtinManifests() []*secflowv1.PluginManifest {
	specs := manifest.BuiltinSpecs()
	out := make([]*secflowv1.PluginManifest, 0, len(specs))
	for _, spec := range specs {
		raw, _ := paramschema.RawDef(spec.PluginID)
		out = append(out, spec.ToProto(string(raw)))
	}
	return out
}

func toEngine(g *secflowv1.WorkflowGraph) engine.Graph {
	var out engine.Graph
	if g == nil {
		return out
	}
	for _, n := range g.GetNodes() {
		params := map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			_ = json.Unmarshal(n.GetParamsJson(), &params)
		}
		secrets := map[string]string{}
		for _, b := range n.GetSecretBindings() {
			secrets[b.GetParamKey()] = b.GetSecretRef()
		}
		out.Nodes = append(out.Nodes, engine.Node{ID: n.GetId(), PluginID: n.GetPluginId(), Params: params, Secrets: secrets})
	}
	for _, e := range g.GetEdges() {
		out.Edges = append(out.Edges, engine.Edge{ID: e.GetId(), Source: e.GetSourceNodeId(), SourceHandle: e.GetSourceHandle(), Target: e.GetTargetNodeId(), TargetHandle: e.GetTargetHandle()})
	}
	return out
}

func issuesToProto(issues []engine.Issue) []*secflowv1.ValidationIssue {
	var out []*secflowv1.ValidationIssue
	for _, issue := range issues {
		sev := secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR
		if issue.Severity == "WARNING" {
			sev = secflowv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING
		}
		out = append(out, &secflowv1.ValidationIssue{Code: issue.Code, Severity: sev, Message: issue.Message, NodeId: issue.NodeID, EdgeId: issue.EdgeID})
	}
	return out
}

func hasError(issues []engine.Issue) bool {
	for _, issue := range issues {
		if issue.Severity == "ERROR" {
			return true
		}
	}
	return false
}

func inlineSecretKeys(plugin string) map[string]secflowv1.SecretKind {
	switch plugin {
	case "ai.explain":
		return map[string]secflowv1.SecretKind{
			"apiKey":    secflowv1.SecretKind_SECRET_KIND_LLM_API_KEY,
			"llmApiKey": secflowv1.SecretKind_SECRET_KIND_LLM_API_KEY,
		}
	case "notify.telegram":
		return map[string]secflowv1.SecretKind{
			"botToken": secflowv1.SecretKind_SECRET_KIND_TELEGRAM_BOT_TOKEN,
		}
	case "notify.smtp":
		return map[string]secflowv1.SecretKind{
			"smtpPassword": secflowv1.SecretKind_SECRET_KIND_SMTP_PASSWORD,
		}
	case "notify.webhook":
		return map[string]secflowv1.SecretKind{
			"hmacSecret": secflowv1.SecretKind_SECRET_KIND_WEBHOOK_HMAC_SECRET,
		}
	case "source.git":
		return map[string]secflowv1.SecretKind{
			"gitToken": secflowv1.SecretKind_SECRET_KIND_GIT_TOKEN,
		}
	case "trigger.webhook":
		return map[string]secflowv1.SecretKind{
			"webhookSecret":  secflowv1.SecretKind_SECRET_KIND_GIT_WEBHOOK_SECRET,
			"gitStatusToken": secflowv1.SecretKind_SECRET_KIND_GIT_TOKEN,
		}
	default:
		return nil
	}
}

func upsertSecretBinding(n *secflowv1.WorkflowNode, paramKey, secretRef string) {
	if n == nil || paramKey == "" {
		return
	}
	for _, b := range n.GetSecretBindings() {
		if b.GetParamKey() == paramKey {
			b.SecretRef = secretRef
			return
		}
	}
	n.SecretBindings = append(n.SecretBindings, &secflowv1.SecretBinding{ParamKey: paramKey, SecretRef: secretRef})
}

func preserveExistingSecretBindings(prev, next *secflowv1.WorkflowGraph, validSecrets map[string]bool) {
	if prev == nil || next == nil {
		return
	}
	prevByNode := map[string]map[string]string{}
	for _, n := range prev.GetNodes() {
		key := n.GetId() + ":" + n.GetPluginId()
		for _, b := range n.GetSecretBindings() {
			if b.GetParamKey() == "" || b.GetSecretRef() == "" {
				continue
			}
			if len(validSecrets) > 0 && !validSecrets[b.GetSecretRef()] {
				continue
			}
			if prevByNode[key] == nil {
				prevByNode[key] = map[string]string{}
			}
			prevByNode[key][b.GetParamKey()] = b.GetSecretRef()
		}
	}
	for _, n := range next.GetNodes() {
		oldBindings := prevByNode[n.GetId()+":"+n.GetPluginId()]
		if len(oldBindings) == 0 {
			continue
		}
		for paramKey, oldRef := range oldBindings {
			matched := false
			for _, b := range n.GetSecretBindings() {
				if b.GetParamKey() == paramKey {
					matched = true
					if b.GetSecretRef() == "" {
						b.SecretRef = oldRef
					}
					break
				}
			}
			if !matched {
				n.SecretBindings = append(n.SecretBindings, &secflowv1.SecretBinding{ParamKey: paramKey, SecretRef: oldRef})
			}
		}
	}
}

func stripInlineSecretParams(plugin string, raw []byte) []byte {
	keys := inlineSecretKeys(plugin)
	if len(keys) == 0 || len(raw) == 0 {
		return raw
	}
	params := map[string]any{}
	if err := json.Unmarshal(raw, &params); err != nil {
		return raw
	}
	changed := false
	for paramKey := range keys {
		if _, ok := params[paramKey]; ok {
			delete(params, paramKey)
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(params)
	if err != nil {
		return raw
	}
	return out
}

func sanitizeGraph(g *secflowv1.WorkflowGraph) *secflowv1.WorkflowGraph {
	if g == nil {
		return nil
	}
	clone := &secflowv1.WorkflowGraph{SchemaVersion: g.GetSchemaVersion(), Edges: g.GetEdges()}
	for _, n := range g.GetNodes() {
		clone.Nodes = append(clone.Nodes, &secflowv1.WorkflowNode{
			Id:             n.GetId(),
			PluginId:       n.GetPluginId(),
			Label:          n.GetLabel(),
			Position:       n.GetPosition(),
			ParamsJson:     sanitizeTemplateParams(n.GetPluginId(), n.GetParamsJson()),
			SecretBindings: nil, // Omit unbound slots; workflow-graph.schema.json requires secretRef minLength: 1.
		})
	}
	return clone
}

func sanitizeTemplateParams(plugin string, raw []byte) []byte {
	cleaned := stripInlineSecretParams(plugin, raw)
	if len(cleaned) == 0 {
		return cleaned
	}
	params := map[string]any{}
	if err := json.Unmarshal(cleaned, &params); err != nil {
		return cleaned
	}
	changed := false
	for k, v := range params {
		s, ok := v.(string)
		if !ok || strings.Contains(s, "{{") {
			continue
		}
		if isLocalOrInternalURLParam(k, s) {
			delete(params, k)
			changed = true
		}
	}
	if !changed {
		return cleaned
	}
	out, err := json.Marshal(params)
	if err != nil {
		return cleaned
	}
	return out
}

func isLocalOrInternalURLParam(key, raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	var host string
	switch {
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		u, err := url.Parse(trimmed)
		if err != nil {
			return false
		}
		host = strings.ToLower(u.Hostname())
	case strings.EqualFold(key, "smtpAddr"):
		h, _, err := net.SplitHostPort(trimmed)
		if err != nil {
			host = lower
		} else {
			host = strings.ToLower(h)
		}
	default:
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".cluster.local") ||
		strings.HasSuffix(host, ".home.arpa") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
	}
	// Single-label hostnames without a dot (e.g. ollama, mailpit, orchestrator, edge-gateway) are cluster-local.
	return !strings.Contains(host, ".")
}

func toReport(in []engine.Finding) []report.Finding {
	var out []report.Finding
	for _, f := range in {
		out = append(out, report.Finding{
			Category: f.Category, Path: f.Path, Class: f.Class, Severity: f.Severity,
			Line: f.Line, EndLine: f.EndLine, Group: f.Group, Artifact: f.Artifact,
			Version: f.Version, AdvisoryID: f.AdvisoryID, Description: f.Description, Remediation: f.Remediation,
		})
	}
	return out
}

func scanResult(root string, in engine.Envelope, category string) engine.Result {
	found, err := collect(root, category)
	if err != nil {
		return engine.Result{Status: "FAILED", Err: err.Error()}
	}
	out := in
	out.Findings = append(append([]engine.Finding{}, in.Findings...), found...)
	out.MaxSev = ""
	return engine.Result{Findings: found, Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
}

func collect(root, category string) ([]engine.Finding, error) {
	if root == "" {
		return nil, nil
	}
	if category == "SCA" {
		return collectSCA(root)
	}
	got, err := kotlinscan.Scan(root)
	if err != nil {
		return nil, err
	}
	var out []engine.Finding
	for _, f := range got {
		if f.Category != category {
			continue
		}
		out = append(out, engine.Finding{
			ID: f.Path + ":" + f.Class, Class: f.Class, Category: f.Category, Severity: f.Severity,
			Path: f.Path, Line: f.Line, EndLine: f.EndLine, Description: f.Description, Remediation: f.Remediation,
			PluginID: pluginFor(category),
		})
	}
	return out, nil
}

func collectSCA(root string) ([]engine.Finding, error) {
	catalog := os.Getenv("CATALOG_PATH")
	if catalog == "" {
		return nil, nil
	}
	deps, err := gradleparser.ParseProject(root)
	if err != nil {
		return nil, err
	}
	advisories, err := gradleparser.LoadCatalog(catalog)
	if err != nil {
		return nil, err
	}
	var out []engine.Finding
	for _, f := range gradleparser.Match(deps, advisories) {
		out = append(out, engine.Finding{
			ID: f.Group + ":" + f.Artifact + ":" + f.AdvisoryID, Category: "SCA", Severity: f.Severity,
			Path: f.Path, Line: f.Line, Group: f.Group, Artifact: f.Artifact, Version: f.Version,
			AdvisoryID: f.AdvisoryID, PluginID: "scan.sca",
		})
	}
	return out, nil
}

func pluginFor(category string) string {
	if category == "SECRET" {
		return "scan.secrets"
	}
	return "scan.sast.kotlin"
}

func denied(reg *secflowv1.WorkerRegisterManifest) bool {
	if reg == nil {
		return false
	}
	for _, m := range reg.GetManifests() {
		if urlguard.Denied(m.GetPluginId() + " " + m.GetDisplayName() + " " + m.GetDescription()) {
			return true
		}
	}
	return false
}

func blockedEndpoint(raw string) bool {
	return urlguard.Denied(raw)
}

func mask(v string) string {
	if len(v) < 4 {
		return "****"
	}
	return v[:2] + "****"
}

func subject(actor *secflowv1.ActorContext) string {
	if actor == nil {
		return ""
	}
	return actor.GetSubject()
}

func slug(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

func id(prefix string) string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return prefix + "_" + hex.EncodeToString(buf)
}

func traceID(traceparent string) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func containsPort(ports []string, handle string) bool {
	for _, port := range ports {
		if port == handle {
			return true
		}
	}
	return false
}
