// Package engine executes a SecFlow DAG inside the orchestrator.
// Analyzer plugins are injected; logic, gate, and report nodes run here.
package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	CodeCycle              = "DAG_CYCLE"
	CodeMissingSource      = "MISSING_SOURCE_NODE"
	CodeBadPort            = "INVALID_PORT_HANDLE"
	CodeMissingSecret      = "MISSING_SECRET_BINDING"
	CodeTriggerCount       = "TRIGGER_COUNT"
	CodePluginDisabled     = "PLUGIN_DISABLED"
	CodePluginUnregistered = "PLUGIN_UNREGISTERED"
)

// PluginMeta carries registry-supplied metadata used to validate Workflow graphs
// without hardcoding built-in plugin_ids.
type PluginMeta struct {
	PluginID           string
	Category           string // "TRIGGER" | "SOURCE" | "ANALYZER" | "LOGIC" | "AI_REPORT" | "ACTION"
	OutputPorts        []string
	RequiredSecretKeys []string
	Enabled            bool
	Registered         bool
}

// PluginLookup resolves metadata for a plugin_id from the active plugin registry.
type PluginLookup func(pluginID string) (PluginMeta, bool)

// Issue is one pre-run validation problem.
type Issue struct {
	Code     string
	Severity string
	Message  string
	NodeID   string
	EdgeID   string
}

// Node is one workflow vertex.
type Node struct {
	ID       string
	PluginID string
	Params   map[string]any
	Secrets  map[string]string
}

// Edge connects an output port to an input port.
type Edge struct {
	ID           string
	Source       string
	SourceHandle string
	Target       string
	TargetHandle string
}

// Graph is a workflow DAG.
type Graph struct {
	Nodes []Node
	Edges []Edge
}

// TriggerInfo captures why a Run started (aligned with envelope.schema.json).
type TriggerInfo struct {
	Type            string `json:"type"`
	RepoURL         string `json:"repoUrl,omitempty"`
	Branch          string `json:"branch,omitempty"`
	CommitSHA       string `json:"commitSha,omitempty"`
	PRNumber        *int   `json:"prNumber,omitempty"`
	GitProvider     string `json:"gitProvider,omitempty"`
	DeliveryID      string `json:"deliveryId,omitempty"`
	TriggeredBy     string `json:"triggeredBy,omitempty"`
	CommitStatusURL string `json:"commitStatusUrl,omitempty"`
	TriggeredAt     string `json:"triggeredAt,omitempty"`
	EventType       string `json:"-"`
}

// SourceRefInfo describes the ingested source archive in Garage (aligned with envelope.schema.json).
type SourceRefInfo struct {
	SourceID  string `json:"sourceId"`
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	SHA256    string `json:"sha256"`
	RepoName  string `json:"repoName"`
	RepoURL   string `json:"repoUrl,omitempty"`
	GitRef    string `json:"gitRef,omitempty"`
	CommitSHA string `json:"commitSha,omitempty"`
	SizeBytes int64  `json:"sizeBytes,omitempty"`
	FileCount int    `json:"fileCount,omitempty"`
}

// SbomRefInfo describes a CycloneDX 1.6 SBOM artifact in Garage (aligned with envelope.schema.json).
type SbomRefInfo struct {
	Bucket             string `json:"bucket"`
	Key                string `json:"key"`
	Digest             string `json:"digest"`
	SpecVersion        string `json:"specVersion"`
	ComponentCount     int    `json:"componentCount,omitempty"`
	VulnerabilityCount int    `json:"vulnerabilityCount,omitempty"`
	GeneratedAt        string `json:"generatedAt,omitempty"`
}

// GroundedFindingSummaryInfo carries deterministic finding coordinates inside an AI report item.
type GroundedFindingSummaryInfo struct {
	Category     string `json:"category"`
	Path         string `json:"path"`
	Line         *int   `json:"line,omitempty"`
	EndLine      *int   `json:"endLine,omitempty"`
	FindingClass string `json:"findingClass,omitempty"`
	Group        string `json:"group,omitempty"`
	Artifact     string `json:"artifact,omitempty"`
	Version      string `json:"version,omitempty"`
	AdvisoryID   string `json:"advisoryId,omitempty"`
	Severity     string `json:"severity,omitempty"`
}

// AIReportGroupInfo is a logical finding group produced by ai.explain.
type AIReportGroupInfo struct {
	Title       string   `json:"title"`
	MaxSeverity string   `json:"maxSeverity"`
	FindingIDs  []string `json:"findingIds"`
	Summary     string   `json:"summary"`
}

// AIReportItemInfo is one grounded explanation item produced by ai.explain.
type AIReportItemInfo struct {
	FindingID            string                     `json:"findingId"`
	PriorityRank         int                        `json:"priorityRank"`
	PlainLanguageRisk    string                     `json:"plainLanguageRisk"`
	BusinessImpact       string                     `json:"businessImpact"`
	RemediationSteps     []string                   `json:"remediationSteps"`
	ReferencedAdvisories []string                   `json:"referencedAdvisories"`
	Finding              GroundedFindingSummaryInfo `json:"finding"`
}

// AIReportInfo is the grounded LLM explanation embedded on an Envelope.
type AIReportInfo struct {
	Quality                        string              `json:"quality"`
	ReleaseDecision                string              `json:"releaseDecision"`
	ExecutiveSummary               string              `json:"executiveSummary"`
	Groups                         []AIReportGroupInfo `json:"groups"`
	Items                          []AIReportItemInfo  `json:"items"`
	ModelID                        string              `json:"modelId"`
	ProviderMode                   string              `json:"providerMode"`
	PrivacyMode                    string              `json:"privacyMode"`
	StrippedHallucinatedAdvisories int                 `json:"strippedHallucinatedAdvisories"`
	Cached                         bool                `json:"cached"`
	PromptHash                     string              `json:"promptHash"`
	TokensIn                       int                 `json:"tokensIn"`
	TokensOut                      int                 `json:"tokensOut"`
	LatencyMs                      int64               `json:"latencyMs"`
	CreatedAt                      string              `json:"createdAt"`
	AttemptedModelID               string              `json:"attemptedModelId,omitempty"`
	FallbackErrorStatus            int                 `json:"fallbackErrorStatus,omitempty"`
	FallbackErrorCode              string              `json:"fallbackErrorCode,omitempty"`
	FallbackErrorMessage           string              `json:"fallbackErrorMessage,omitempty"`
}

// GateInfo records the latest Policy Gate evaluation on an Envelope.
type GateInfo struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	NodeID      string `json:"nodeId"`
	EvaluatedAt string `json:"-"`
}

// EnvelopeStats is the flat aggregate summary aligned 1:1 with envelope.schema.json.
type EnvelopeStats struct {
	Total              int    `json:"total"`
	NewCount           int    `json:"newCount"`
	Critical           int    `json:"critical"`
	High               int    `json:"high"`
	Medium             int    `json:"medium"`
	Low                int    `json:"low"`
	SecretCount        int    `json:"secretCount"`
	SastCount          int    `json:"sastCount"`
	ScaCount           int    `json:"scaCount"`
	MaxSeverity        string `json:"maxSeverity,omitempty"`
	NewVsBaselineCount int    `json:"-"`
}

// Finding is an authoritative or branch-local finding aligned with envelope.schema.json.
type Finding struct {
	ID              string `json:"findingId"`
	Fingerprint     string `json:"fingerprint"`
	SourceNodeID    string `json:"sourceNodeId"`
	PluginID        string `json:"pluginId"`
	Category        string `json:"category"`
	Path            string `json:"path"`
	Class           string `json:"class,omitempty"`
	Line            int    `json:"line,omitempty"`
	EndLine         int    `json:"endLine,omitempty"`
	Group           string `json:"group,omitempty"`
	Artifact        string `json:"artifact,omitempty"`
	Version         string `json:"version,omitempty"`
	AdvisoryID      string `json:"advisoryId,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Description     string `json:"description,omitempty"`
	Remediation     string `json:"remediation,omitempty"`
	MaskedSnippet   string `json:"maskedSnippet,omitempty"`
	IsNewVsBaseline bool   `json:"isNewVsBaseline,omitempty"`
}

// FindingFingerprint returns the deterministic identity key used for deduplication and Baseline Diff.
func FindingFingerprint(f Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return strings.Join([]string{f.Category, f.Path, f.Class, f.Group, f.Artifact, f.AdvisoryID}, "|")
}

// Envelope is the branch-local payload (ADR-0004). Filters may narrow Findings here
// without modifying the Run's authoritative Findings ledger.
type Envelope struct {
	Trigger              TriggerInfo       `json:"trigger"`
	SourceRef            *SourceRefInfo    `json:"sourceRef,omitempty"`
	Findings             []Finding         `json:"findings"`
	SbomRef              *SbomRefInfo      `json:"sbomRef,omitempty"`
	AIReport             *AIReportInfo     `json:"aiReport,omitempty"`
	Gate                 *GateInfo         `json:"gate,omitempty"`
	Stats                EnvelopeStats     `json:"stats"`
	Vars                 map[string]string `json:"vars"`
	MaxSev               string            `json:"-"`
	RunID                string            `json:"-"`
	BaselineFingerprints map[string]bool   `json:"-"`
}

// ComputeStats calculates EnvelopeStats deterministically from a slice of findings.
func ComputeStats(fs []Finding) EnvelopeStats {
	st := EnvelopeStats{Total: len(fs)}
	for _, f := range fs {
		if f.IsNewVsBaseline {
			st.NewCount++
		}
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			st.Critical++
		case "HIGH":
			st.High++
		case "MEDIUM":
			st.Medium++
		case "LOW":
			st.Low++
		}
		switch strings.ToUpper(f.Category) {
		case "SECRET":
			st.SecretCount++
		case "SAST":
			st.SastCount++
		case "SCA":
			st.ScaCount++
		}
		if rank(f.Severity) > rank(st.MaxSeverity) {
			st.MaxSeverity = strings.ToUpper(f.Severity)
		}
	}
	st.NewVsBaselineCount = st.NewCount
	return st
}

// RefreshStats recomputes Stats and keeps MaxSev / NewVsBaselineCount synchronized.
func (e *Envelope) RefreshStats() {
	e.Stats = ComputeStats(e.Findings)
	if e.Stats.MaxSeverity != "" {
		e.MaxSev = e.Stats.MaxSeverity
	} else if len(e.Findings) == 0 && rank(e.MaxSev) > 0 {
		e.Stats.MaxSeverity = strings.ToUpper(e.MaxSev)
		e.MaxSev = e.Stats.MaxSeverity
	} else {
		e.MaxSev = ""
	}
}

// Normalize returns a defensive copy whose required fields and stats strictly satisfy envelope.schema.json.
func (e Envelope) Normalize() Envelope {
	out := e
	if out.Trigger.Type == "" {
		out.Trigger.Type = "MANUAL"
	}
	if out.Trigger.PRNumber != nil {
		pr := *out.Trigger.PRNumber
		out.Trigger.PRNumber = &pr
	}
	if out.SourceRef != nil {
		cp := *out.SourceRef
		out.SourceRef = &cp
	}
	if out.SbomRef != nil {
		cp := *out.SbomRef
		out.SbomRef = &cp
	}
	if out.AIReport != nil {
		cp := *out.AIReport
		out.AIReport = &cp
	}
	if out.Gate != nil {
		cp := *out.Gate
		out.Gate = &cp
	}
	out.Vars = cloneMap(e.Vars)
	if e.BaselineFingerprints != nil {
		out.BaselineFingerprints = make(map[string]bool, len(e.BaselineFingerprints))
		for k, v := range e.BaselineFingerprints {
			out.BaselineFingerprints[k] = v
		}
	}
	findings := make([]Finding, len(e.Findings))
	for i, f := range e.Findings {
		if f.Fingerprint == "" {
			f.Fingerprint = FindingFingerprint(f)
		}
		if f.ID == "" {
			f.ID = f.Fingerprint
		}
		findings[i] = f
	}
	out.Findings = findings
	out.RefreshStats()
	return out
}

// MarshalJSON normalizes the Envelope so serialized JSON always satisfies envelope.schema.json.
func (e Envelope) MarshalJSON() ([]byte, error) {
	type envelopeAlias Envelope
	return json.Marshal(envelopeAlias(e.Normalize()))
}

// UnmarshalJSON parses both canonical camelCase envelopes and legacy payloads.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	type envelopeAlias Envelope
	var aux envelopeAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*e = Envelope(aux)
	if e.Findings == nil {
		e.Findings = []Finding{}
	}
	if e.Vars == nil {
		e.Vars = map[string]string{}
	}
	if e.Trigger.Type == "" {
		e.Trigger.Type = "MANUAL"
	}
	if e.RunID == "" && e.Vars["runId"] != "" {
		e.RunID = e.Vars["runId"]
	}
	// Preserve legacy MaxSev if present in older persisted payloads.
	var legacy struct {
		MaxSev string `json:"MaxSev"`
	}
	if json.Unmarshal(data, &legacy) == nil && legacy.MaxSev != "" && e.Stats.MaxSeverity == "" {
		e.MaxSev = legacy.MaxSev
	} else if e.Stats.MaxSeverity != "" {
		e.MaxSev = e.Stats.MaxSeverity
	}
	e.RefreshStats()
	return nil
}

// Result is one node execution.
type Result struct {
	Findings        []Finding
	Envelope        Envelope
	PortEnvelopes   map[string]Envelope
	ActivePorts     []string
	ArtifactKey     string
	ArtifactContent []byte
	Status          string
	Err             string
	RedactedPreview []byte
}

// Handler executes one plugin. Logic plugins may be nil and use the built-ins.
type Handler func(node Node, in Envelope) Result

// Validate checks trigger cardinality, cycles, source-before-analyzer, and ports
// using built-in plugin heuristics. Prefer ValidateWithPlugins when a live plugin
// registry is available.
func Validate(g Graph) []Issue {
	return ValidateWithPlugins(g, nil)
}

// ValidateWithPlugins validates a Workflow DAG using metadata resolved from lookup
// (dynamic category, output ports, required secret keys, and enabled/registered status).
func ValidateWithPlugins(g Graph, lookup PluginLookup) []Issue {
	var issues []Issue
	triggers := 0
	nodes := map[string]Node{}
	metaByNode := map[string]PluginMeta{}

	for _, n := range g.Nodes {
		nodes[n.ID] = n
		if lookup != nil {
			meta, ok := lookup(n.PluginID)
			if !ok || !meta.Registered {
				issues = append(issues, Issue{
					Code:     CodePluginUnregistered,
					Severity: "ERROR",
					NodeID:   n.ID,
					Message:  fmt.Sprintf("плагин %q не зарегистрирован в реестре", n.PluginID),
				})
			} else {
				metaByNode[n.ID] = meta
				if !meta.Enabled {
					issues = append(issues, Issue{
						Code:     CodePluginDisabled,
						Severity: "ERROR",
						NodeID:   n.ID,
						Message:  fmt.Sprintf("плагин %q отключён", n.PluginID),
					})
				}
			}
		}
		if isTriggerNode(n, metaByNode[n.ID]) {
			triggers++
		}
	}
	if triggers != 1 {
		issues = append(issues, Issue{Code: CodeTriggerCount, Severity: "ERROR", Message: "граф должен содержать ровно один trigger"})
	}
	if cycle(g) {
		issues = append(issues, Issue{Code: CodeCycle, Severity: "ERROR", Message: "в графе есть цикл"})
	}
	for _, n := range g.Nodes {
		if !isAnalyzerNode(n, metaByNode[n.ID]) {
			continue
		}
		if !sourceOnPathWithMeta(g, n.ID, metaByNode) {
			issues = append(issues, Issue{
				Code: CodeMissingSource, Severity: "ERROR", NodeID: n.ID,
				Message: "перед анализатором нет source-ноды",
			})
		}
	}
	for _, e := range g.Edges {
		src, ok := nodes[e.Source]
		if !ok {
			continue
		}
		if !portAllowedWithMeta(src, e.SourceHandle, metaByNode[src.ID]) {
			issues = append(issues, Issue{
				Code: CodeBadPort, Severity: "ERROR", EdgeID: e.ID, NodeID: src.ID,
				Message: "sourceHandle " + e.SourceHandle + " не существует у " + src.PluginID,
			})
		}
	}
	for _, n := range g.Nodes {
		for _, key := range requiredSecretsWithMeta(n, metaByNode[n.ID]) {
			if hasNodeSecret(n, key) {
				continue
			}
			issues = append(issues, Issue{
				Code: CodeMissingSecret, Severity: "ERROR", NodeID: n.ID,
				Message: "нет секрета " + key + " (привяжите secretRef в secretBindings)",
			})
		}
	}
	return issues
}

func isTriggerNode(n Node, meta PluginMeta) bool {
	if meta.Registered && meta.Category != "" {
		return strings.EqualFold(meta.Category, "TRIGGER")
	}
	return strings.HasPrefix(n.PluginID, "trigger.")
}

func isAnalyzerNode(n Node, meta PluginMeta) bool {
	if meta.Registered && meta.Category != "" {
		return strings.EqualFold(meta.Category, "ANALYZER")
	}
	return isAnalyzer(n.PluginID)
}

func isSourceNode(pluginID string, meta PluginMeta) bool {
	if meta.Registered && meta.Category != "" {
		return strings.EqualFold(meta.Category, "SOURCE")
	}
	return strings.HasPrefix(pluginID, "source.")
}

func requiredSecretsWithMeta(n Node, meta PluginMeta) []string {
	if meta.Registered {
		return meta.RequiredSecretKeys
	}
	return requiredSecrets(n.PluginID)
}

func portAllowedWithMeta(n Node, handle string, meta PluginMeta) bool {
	if handle == "" {
		handle = "default"
	}
	for _, p := range outputPortsWithMeta(n, meta) {
		if p == handle {
			return true
		}
	}
	return false
}

func outputPortsWithMeta(n Node, meta PluginMeta) []string {
	if n.PluginID == "logic.switch" {
		return outputPorts(n)
	}
	if meta.Registered && len(meta.OutputPorts) > 0 {
		return meta.OutputPorts
	}
	return outputPorts(n)
}

// Step runs a single node. The queue uses it so any replica can execute one claimed task.
func Step(n Node, in Envelope, handlers map[string]Handler) Result {
	return dispatch(n, in, handlers)
}

// IsAnalyzer reports plugins whose findings are authoritative for the run.
func IsAnalyzer(plugin string) bool {
	return isAnalyzer(plugin)
}

func isAnalyzer(plugin string) bool {
	return strings.HasPrefix(plugin, "scan.") || plugin == "sbom.generate"
}

func hasNodeSecret(n Node, key string) bool {
	return strings.TrimSpace(n.Secrets[key]) != ""
}

func requiredSecrets(plugin string) []string {
	switch plugin {
	case "notify.telegram":
		return []string{"botToken"}
	case "notify.smtp":
		return []string{"smtpPassword"}
	case "trigger.webhook":
		return []string{"webhookSecret"}
	default:
		return nil
	}
}

func portAllowed(n Node, handle string) bool {
	if handle == "" {
		handle = "default"
	}
	for _, p := range outputPorts(n) {
		if p == handle {
			return true
		}
	}
	return false
}

func outputPorts(n Node) []string {
	switch n.PluginID {
	case "logic.if", "logic.compare":
		return []string{"true", "false"}
	case "logic.regex":
		return []string{"match", "nomatch"}
	case "gate.policy":
		return []string{"PASS", "WARN", "FAIL"}
	case "logic.switch":
		mode, _ := n.Params["mode"].(string)
		if mode == "category" {
			return []string{"SECRET", "SAST", "SCA", "CLEAN"}
		}
		return []string{"CRITICAL", "HIGH", "MEDIUM_LOW", "CLEAN"}
	default:
		return []string{"default"}
	}
}

func cycle(g Graph) bool {
	adj := map[string][]string{}
	indeg := map[string]int{}
	for _, n := range g.Nodes {
		indeg[n.ID] = 0
	}
	for _, e := range g.Edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
		indeg[e.Target]++
	}
	var q []string
	for id, d := range indeg {
		if d == 0 {
			q = append(q, id)
		}
	}
	seen := 0
	for len(q) > 0 {
		id := q[0]
		q = q[1:]
		seen++
		for _, nxt := range adj[id] {
			indeg[nxt]--
			if indeg[nxt] == 0 {
				q = append(q, nxt)
			}
		}
	}
	return seen != len(g.Nodes)
}

func sourceOnPathWithMeta(g Graph, nodeID string, metaByNode map[string]PluginMeta) bool {
	incoming := map[string][]string{}
	kind := map[string]string{}
	for _, n := range g.Nodes {
		kind[n.ID] = n.PluginID
	}
	for _, e := range g.Edges {
		incoming[e.Target] = append(incoming[e.Target], e.Source)
	}
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		if isSourceNode(kind[id], metaByNode[id]) {
			return true
		}
		for _, prev := range incoming[id] {
			if walk(prev) {
				return true
			}
		}
		return false
	}
	return walk(nodeID)
}

// NodeTrace is one node's input, output, active ports, and optional per-port envelopes.
type NodeTrace struct {
	Input           Envelope            `json:"input"`
	Output          Envelope            `json:"output"`
	Ports           []string            `json:"ports"`
	PortOutputs     map[string]Envelope `json:"portOutputs,omitempty"`
	ArtifactKey     string              `json:"artifactKey,omitempty"`
	ArtifactContent []byte              `json:"-"`
	RedactedPreview []byte              `json:"redactedPreview,omitempty"`
}

// Run executes the graph from the trigger. Authoritative findings are the
// analyzer outputs before any logic.filter or logic.regex narrowing.
func Run(g Graph, handlers map[string]Handler, seed Envelope) (authoritative []Finding, traces map[string]NodeTrace, skipped map[string]bool, err error) {
	if issues := Validate(g); len(issues) > 0 {
		return nil, nil, nil, fmt.Errorf("%s: %s", issues[0].Code, issues[0].Message)
	}
	traces = map[string]NodeTrace{}
	skipped = map[string]bool{}
	order := topo(g)
	incoming := map[string][]Edge{}
	outgoing := map[string][]Edge{}
	for _, e := range g.Edges {
		incoming[e.Target] = append(incoming[e.Target], e)
		outgoing[e.Source] = append(outgoing[e.Source], e)
	}
	nodes := map[string]Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	active := map[string]bool{}
	for _, n := range g.Nodes {
		if strings.HasPrefix(n.PluginID, "trigger.") {
			active[n.ID] = true
		}
	}
	normSeed := seed.Normalize()
	for _, id := range order {
		n := nodes[id]
		if !active[id] && !strings.HasPrefix(n.PluginID, "trigger.") {
			skipped[id] = true
			continue
		}
		var in Envelope
		if strings.HasPrefix(n.PluginID, "trigger.") && len(incoming[id]) == 0 {
			in = normSeed.Normalize()
		} else {
			dedupe := shouldDeduplicate(n)
			in = mergeIncoming(id, incoming, traces, dedupe)
		}
		result := dispatch(n, in, handlers)
		if result.Status == "FAILED" {
			return authoritative, traces, skipped, fmt.Errorf("node %s: %s", id, result.Err)
		}
		ports := slices.Clone(result.ActivePorts)
		traces[id] = NodeTrace{
			Input:           in,
			Output:          result.Envelope,
			Ports:           ports,
			PortOutputs:     clonePortEnvelopes(result.PortEnvelopes),
			ArtifactKey:     result.ArtifactKey,
			ArtifactContent: slices.Clone(result.ArtifactContent),
			RedactedPreview: slices.Clone(result.RedactedPreview),
		}
		if isAnalyzer(n.PluginID) {
			authoritative = append(authoritative, result.Findings...)
		}
		chosen := map[string]bool{}
		for _, p := range result.ActivePorts {
			chosen[p] = true
		}
		for _, e := range outgoing[id] {
			handle := e.SourceHandle
			if handle == "" {
				handle = "default"
			}
			if chosen[handle] {
				active[e.Target] = true
			}
		}
	}
	return authoritative, traces, skipped, nil
}

func shouldDeduplicate(n Node) bool {
	if n.PluginID == "logic.merge" && n.Params != nil {
		if b, ok := n.Params["deduplicateByFingerprint"].(bool); ok {
			return b
		}
	}
	return true
}

func mergeIncoming(id string, incoming map[string][]Edge, traces map[string]NodeTrace, dedupe bool) Envelope {
	merged := Envelope{
		Vars:     map[string]string{},
		Findings: []Finding{},
	}
	seen := map[string]bool{}
	for _, e := range incoming[id] {
		tr, ok := traces[e.Source]
		if !ok {
			continue
		}
		handle := e.SourceHandle
		if handle == "" {
			handle = "default"
		}
		if !slices.Contains(tr.Ports, handle) {
			continue
		}
		env := tr.Output
		if tr.PortOutputs != nil {
			if portEnv, exists := tr.PortOutputs[handle]; exists {
				env = portEnv
			}
		}
		mergeEnvelopeInto(&merged, env, seen, dedupe)
	}
	return merged.Normalize()
}

func mergeEnvelopeInto(dst *Envelope, src Envelope, seen map[string]bool, dedupe bool) {
	if dst.Vars == nil {
		dst.Vars = map[string]string{}
	}
	for k, v := range src.Vars {
		dst.Vars[k] = v
	}
	if dst.RunID == "" && src.RunID != "" {
		dst.RunID = src.RunID
	}
	if dst.Trigger.Type == "" && src.Trigger.Type != "" {
		dst.Trigger = src.Trigger
	} else {
		if dst.Trigger.RepoURL == "" {
			dst.Trigger.RepoURL = src.Trigger.RepoURL
		}
		if dst.Trigger.Branch == "" {
			dst.Trigger.Branch = src.Trigger.Branch
		}
		if dst.Trigger.CommitSHA == "" {
			dst.Trigger.CommitSHA = src.Trigger.CommitSHA
		}
		if dst.Trigger.PRNumber == nil && src.Trigger.PRNumber != nil {
			pr := *src.Trigger.PRNumber
			dst.Trigger.PRNumber = &pr
		}
		if dst.Trigger.GitProvider == "" {
			dst.Trigger.GitProvider = src.Trigger.GitProvider
		}
		if dst.Trigger.DeliveryID == "" {
			dst.Trigger.DeliveryID = src.Trigger.DeliveryID
		}
		if dst.Trigger.TriggeredBy == "" {
			dst.Trigger.TriggeredBy = src.Trigger.TriggeredBy
		}
		if dst.Trigger.CommitStatusURL == "" {
			dst.Trigger.CommitStatusURL = src.Trigger.CommitStatusURL
		}
		if dst.Trigger.TriggeredAt == "" {
			dst.Trigger.TriggeredAt = src.Trigger.TriggeredAt
		}
		if dst.Trigger.EventType == "" {
			dst.Trigger.EventType = src.Trigger.EventType
		}
	}
	if src.SourceRef != nil {
		cp := *src.SourceRef
		dst.SourceRef = &cp
	}
	if src.SbomRef != nil {
		cp := *src.SbomRef
		dst.SbomRef = &cp
	}
	if src.AIReport != nil {
		cp := *src.AIReport
		dst.AIReport = &cp
	}
	if src.Gate != nil {
		cp := *src.Gate
		dst.Gate = &cp
	}
	if len(src.BaselineFingerprints) > 0 {
		if dst.BaselineFingerprints == nil {
			dst.BaselineFingerprints = make(map[string]bool, len(src.BaselineFingerprints))
		}
		for k, v := range src.BaselineFingerprints {
			if v {
				dst.BaselineFingerprints[k] = true
			}
		}
	}
	for _, f := range src.Findings {
		key := FindingFingerprint(f)
		if key == "|||||" && f.ID != "" {
			key = f.ID
		}
		if dedupe && key != "" && seen[key] {
			continue
		}
		if key != "" {
			seen[key] = true
		}
		dst.Findings = append(dst.Findings, f)
	}
	if rank(src.MaxSev) > rank(dst.MaxSev) {
		dst.MaxSev = src.MaxSev
	}
}

func dispatch(n Node, in Envelope, handlers map[string]Handler) Result {
	normIn := in.Normalize()
	if h, ok := handlers[n.PluginID]; ok && h != nil {
		res := h(n, normIn)
		if res.Status == "FAILED" {
			return res
		}
		res.Findings = stampFindings(res.Findings, n)
		res.Envelope.Findings = stampFindings(res.Envelope.Findings, n)
		res.Envelope = res.Envelope.Normalize()
		if len(res.PortEnvelopes) > 0 {
			normPorts := make(map[string]Envelope, len(res.PortEnvelopes))
			for k, v := range res.PortEnvelopes {
				v.Findings = stampFindings(v.Findings, n)
				normPorts[k] = v.Normalize()
			}
			res.PortEnvelopes = normPorts
		}
		if len(res.ActivePorts) == 0 {
			res.ActivePorts = []string{"default"}
		}
		return res
	}
	switch n.PluginID {
	case "logic.filter":
		return filterNode(n, normIn)
	case "logic.regex":
		return regexNode(n, normIn)
	case "logic.if":
		return ifNode(n, normIn)
	case "logic.compare":
		return compareNode(n, normIn)
	case "logic.switch":
		return switchNode(n, normIn)
	case "report.export":
		out := normIn.Normalize()
		if title, ok := n.Params["title"].(string); ok && title != "" {
			out.Vars["reportTitle"] = title
		}
		if notes, ok := n.Params["notes"].(string); ok && notes != "" {
			out.Vars["reportNotes"] = notes
		}
		return Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED", Findings: out.Findings}
	case "logic.merge", "trigger.manual", "trigger.schedule", "trigger.webhook", "source.upload", "source.git":
		out := normIn.Normalize()
		return Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED", Findings: out.Findings}
	case "gate.policy":
		return gateNode(n, normIn)
	default:
		out := normIn.Normalize()
		return Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
	}
}

func stampFindings(fs []Finding, n Node) []Finding {
	if len(fs) == 0 {
		return fs
	}
	out := make([]Finding, len(fs))
	for i, f := range fs {
		if f.SourceNodeID == "" {
			f.SourceNodeID = n.ID
		}
		if f.PluginID == "" {
			f.PluginID = n.PluginID
		}
		if f.Fingerprint == "" {
			f.Fingerprint = FindingFingerprint(f)
		}
		if f.ID == "" {
			f.ID = f.Fingerprint
		}
		out[i] = f
	}
	return out
}

func filterNode(n Node, in Envelope) Result {
	minSev := strings.ToUpper(stringParam(n.Params, "minSeverity"))
	maxSev := strings.ToUpper(stringParam(n.Params, "maxSeverity"))
	categories := upperSet(stringSliceParam(n.Params, "categories"))
	if singleCat := strings.ToUpper(stringParam(n.Params, "category")); singleCat != "" {
		if categories == nil {
			categories = map[string]bool{}
		}
		categories[singleCat] = true
	}
	classes := lowerSet(stringSliceParam(n.Params, "findingClasses"))
	prefixes := stringSliceParam(n.Params, "pathPrefixes")
	onlyNew := boolParam(n.Params, "onlyNewVsBaseline", false)

	kept := make([]Finding, 0, len(in.Findings))
	for _, f := range in.Findings {
		if minSev != "" && rank(f.Severity) < rank(minSev) {
			continue
		}
		if maxSev != "" && rank(f.Severity) > rank(maxSev) {
			continue
		}
		if len(categories) > 0 && !categories[strings.ToUpper(f.Category)] {
			continue
		}
		if len(classes) > 0 && !classes[strings.ToLower(f.Class)] {
			continue
		}
		if len(prefixes) > 0 && !hasAnyPrefix(f.Path, prefixes) {
			continue
		}
		if onlyNew && !f.IsNewVsBaseline {
			continue
		}
		kept = append(kept, f)
	}
	out := in.Normalize()
	out.Findings = kept
	out.MaxSev = ""
	out.RefreshStats()
	return Result{Envelope: out, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
}

func regexNode(n Node, in Envelope) Result {
	pattern := stringParam(n.Params, "pattern")
	if pattern == "" {
		return Result{Status: "FAILED", Err: "invalid regex: pattern is required"}
	}
	if boolParam(n.Params, "caseInsensitive", false) && !strings.HasPrefix(pattern, "(?i)") {
		pattern = "(?i)" + pattern
	}
	field := stringParam(n.Params, "field")
	if field == "" {
		field = "path"
	}
	negate := boolParam(n.Params, "negate", false)
	splitEnvelope := boolParam(n.Params, "splitEnvelope", true)

	re, err := regexp.Compile(pattern)
	if err != nil {
		return Result{Status: "FAILED", Err: "invalid regex: " + err.Error()}
	}
	matched := make([]Finding, 0)
	unmatched := make([]Finding, 0)
	for _, f := range in.Findings {
		hit := findingMatchesRegex(f, field, re)
		if negate {
			hit = !hit
		}
		if hit {
			matched = append(matched, f)
		} else {
			unmatched = append(unmatched, f)
		}
	}

	matchEnv := in.Normalize()
	matchEnv.Findings = matched
	matchEnv.MaxSev = ""
	matchEnv.RefreshStats()

	nomatchEnv := in.Normalize()
	nomatchEnv.Findings = unmatched
	nomatchEnv.MaxSev = ""
	nomatchEnv.RefreshStats()

	if splitEnvelope {
		var ports []string
		portEnvs := map[string]Envelope{}
		if len(matched) > 0 {
			ports = append(ports, "match")
			portEnvs["match"] = matchEnv
		}
		if len(unmatched) > 0 {
			ports = append(ports, "nomatch")
			portEnvs["nomatch"] = nomatchEnv
		}
		if len(ports) == 0 {
			ports = []string{"nomatch"}
			portEnvs["nomatch"] = nomatchEnv
		}
		primary := nomatchEnv
		if len(matched) > 0 {
			primary = matchEnv
		}
		return Result{
			Envelope:      primary,
			PortEnvelopes: portEnvs,
			ActivePorts:   ports,
			Status:        "SUCCEEDED",
		}
	}

	if len(matched) > 0 {
		return Result{
			Envelope:      matchEnv,
			PortEnvelopes: map[string]Envelope{"match": matchEnv},
			ActivePorts:   []string{"match"},
			Status:        "SUCCEEDED",
		}
	}
	return Result{
		Envelope:      nomatchEnv,
		PortEnvelopes: map[string]Envelope{"nomatch": nomatchEnv},
		ActivePorts:   []string{"nomatch"},
		Status:        "SUCCEEDED",
	}
}

func findingMatchesRegex(f Finding, field string, re *regexp.Regexp) bool {
	switch field {
	case "path":
		return re.MatchString(f.Path)
	case "class":
		return re.MatchString(f.Class)
	case "advisoryId":
		return re.MatchString(f.AdvisoryID)
	case "description":
		return re.MatchString(f.Description)
	case "group":
		return re.MatchString(f.Group)
	case "artifact":
		return re.MatchString(f.Artifact)
	case "any":
		for _, v := range []string{f.Path, f.Class, f.AdvisoryID, f.Description, f.Group, f.Artifact} {
			if v != "" && re.MatchString(v) {
				return true
			}
		}
		return false
	default:
		return re.MatchString(f.Path)
	}
}

func ifNode(n Node, in Envelope) Result {
	out := in.Normalize()
	conds := extractConditions(n.Params)
	if len(conds) == 0 {
		// Legacy fallback: minCount threshold.
		threshold := intParam(n.Params, "minCount", 0)
		port := "false"
		if len(out.Findings) > threshold {
			port = "true"
		}
		return Result{Envelope: out, ActivePorts: []string{port}, Status: "SUCCEEDED"}
	}

	combinator := strings.ToUpper(strings.TrimSpace(stringParam(n.Params, "combinator")))
	if combinator != "OR" {
		combinator = "AND"
	}

	matched := combinator == "AND"
	for _, c := range conds {
		ok := evalCondition(out, c)
		if combinator == "AND" && !ok {
			matched = false
			break
		}
		if combinator == "OR" && ok {
			matched = true
			break
		}
	}

	port := "false"
	if matched {
		port = "true"
	}
	return Result{Envelope: out, ActivePorts: []string{port}, Status: "SUCCEEDED"}
}

type ruleCondition struct {
	field    string
	operator string
	value    any
}

func extractConditions(params map[string]any) []ruleCondition {
	if params == nil {
		return nil
	}
	raw, ok := params["conditions"]
	if !ok || raw == nil {
		return nil
	}
	var out []ruleCondition
	switch list := raw.(type) {
	case []any:
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, ruleCondition{
					field:    stringParam(m, "field"),
					operator: stringParam(m, "operator"),
					value:    m["value"],
				})
			}
		}
	case []map[string]any:
		for _, m := range list {
			out = append(out, ruleCondition{
				field:    stringParam(m, "field"),
				operator: stringParam(m, "operator"),
				value:    m["value"],
			})
		}
	}
	return out
}

func evalCondition(env Envelope, c ruleCondition) bool {
	op := strings.ToLower(strings.TrimSpace(c.operator))
	field := strings.TrimSpace(c.field)

	// Numeric fields
	if num, isNum := lookupNumericField(env, field); isNum {
		if op == "in" {
			for _, elem := range toAnySlice(c.value) {
				if target, ok := asFloat64(elem); ok && math.Abs(num-target) < 1e-9 {
					return true
				}
			}
			return false
		}
		target, ok := asFloat64(c.value)
		if !ok {
			return false
		}
		switch op {
		case "eq":
			return math.Abs(num-target) < 1e-9
		case "neq":
			return math.Abs(num-target) >= 1e-9
		case "gt":
			return num > target
		case "gte":
			return num >= target
		case "lt":
			return num < target
		case "lte":
			return num <= target
		default:
			return false
		}
	}

	// Severity field (supports rank ordering as well as equality/in)
	if field == "maxSeverity" || field == "stats.maxSeverity" {
		actual := strings.ToUpper(env.Stats.MaxSeverity)
		switch op {
		case "eq":
			return actual == strings.ToUpper(asScalarString(c.value))
		case "neq":
			return actual != strings.ToUpper(asScalarString(c.value))
		case "gt":
			return rank(actual) > rank(strings.ToUpper(asScalarString(c.value)))
		case "gte":
			return rank(actual) >= rank(strings.ToUpper(asScalarString(c.value)))
		case "lt":
			return rank(actual) < rank(strings.ToUpper(asScalarString(c.value)))
		case "lte":
			return rank(actual) <= rank(strings.ToUpper(asScalarString(c.value)))
		case "in":
			for _, elem := range toAnySlice(c.value) {
				if actual == strings.ToUpper(asScalarString(elem)) {
					return true
				}
			}
			return false
		case "contains":
			return strings.Contains(actual, strings.ToUpper(asScalarString(c.value)))
		default:
			return false
		}
	}

	// String fields
	actual := lookupStringField(env, field)
	expected := asScalarString(c.value)
	switch op {
	case "eq":
		return strings.EqualFold(actual, expected)
	case "neq":
		return !strings.EqualFold(actual, expected)
	case "contains":
		return strings.Contains(strings.ToLower(actual), strings.ToLower(expected))
	case "in":
		for _, elem := range toAnySlice(c.value) {
			if strings.EqualFold(actual, asScalarString(elem)) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func lookupNumericField(env Envelope, field string) (float64, bool) {
	switch field {
	case "total", "stats.total":
		return float64(env.Stats.Total), true
	case "critical", "stats.critical":
		return float64(env.Stats.Critical), true
	case "high", "stats.high":
		return float64(env.Stats.High), true
	case "medium", "stats.medium":
		return float64(env.Stats.Medium), true
	case "low", "stats.low":
		return float64(env.Stats.Low), true
	case "secretCount", "stats.secretCount":
		return float64(env.Stats.SecretCount), true
	case "scaCount", "stats.scaCount":
		return float64(env.Stats.ScaCount), true
	case "sastCount", "stats.sastCount":
		return float64(env.Stats.SastCount), true
	case "newCount", "stats.newCount", "newVsBaselineCount", "stats.newVsBaselineCount":
		return float64(env.Stats.NewCount), true
	default:
		return 0, false
	}
}

func lookupStringField(env Envelope, field string) string {
	switch field {
	case "branch", "trigger.branch":
		if env.Trigger.Branch != "" {
			return env.Trigger.Branch
		}
		return env.Vars["triggerBranch"]
	case "eventType", "trigger.eventType", "trigger.type":
		if env.Trigger.EventType != "" {
			return env.Trigger.EventType
		}
		if v := env.Vars["triggerEvent"]; v != "" {
			return v
		}
		return env.Trigger.Type
	case "gate.status", "gateStatus":
		if env.Gate != nil && env.Gate.Status != "" {
			return env.Gate.Status
		}
		return env.Vars["gate"]
	default:
		if strings.HasPrefix(field, "vars.") {
			return env.Vars[strings.TrimPrefix(field, "vars.")]
		}
		return env.Vars[field]
	}
}

func compareNode(n Node, in Envelope) Result {
	out := in.Normalize()
	mode := strings.TrimSpace(stringParam(n.Params, "mode"))
	if mode == "" {
		mode = "baselineDiff"
	}
	minSev := strings.ToUpper(stringParam(n.Params, "minSeverity"))
	minNew := intParam(n.Params, "minNewFindingsForTrue", 1)
	if minNew < 1 {
		minNew = 1
	}

	if mode == "threshold" {
		threshold := minNew
		if _, ok := n.Params["minNewFindingsForTrue"]; !ok {
			if _, hasT := n.Params["threshold"]; hasT {
				threshold = intParam(n.Params, "threshold", 1)
			} else if _, hasMC := n.Params["minCount"]; hasMC {
				threshold = intParam(n.Params, "minCount", 1)
			}
		}
		count := 0
		for _, f := range out.Findings {
			if minSev != "" && rank(f.Severity) < rank(minSev) {
				continue
			}
			count++
		}
		port := "false"
		if count >= threshold {
			port = "true"
		}
		return Result{Envelope: out, ActivePorts: []string{port}, Status: "SUCCEEDED"}
	}

	// baselineDiff mode: compare branch findings against baseline finding fingerprints.
	baseline := extractBaselineFingerprints(out)
	matchingNew := 0
	updated := make([]Finding, len(out.Findings))
	for i, f := range out.Findings {
		fp := FindingFingerprint(f)
		f.Fingerprint = fp
		f.IsNewVsBaseline = !baseline[fp]
		if f.IsNewVsBaseline && (minSev == "" || rank(f.Severity) >= rank(minSev)) {
			matchingNew++
		}
		updated[i] = f
	}
	out.Findings = updated
	out.RefreshStats()

	port := "false"
	if matchingNew >= minNew {
		port = "true"
	}
	return Result{Envelope: out, ActivePorts: []string{port}, Status: "SUCCEEDED"}
}

func extractBaselineFingerprints(env Envelope) map[string]bool {
	out := map[string]bool{}
	for fp, ok := range env.BaselineFingerprints {
		if ok && fp != "" {
			out[fp] = true
		}
	}
	if raw := strings.TrimSpace(env.Vars["_baselineFingerprints"]); raw != "" {
		var list []string
		if json.Unmarshal([]byte(raw), &list) == nil {
			for _, fp := range list {
				if fp != "" {
					out[fp] = true
				}
			}
		} else {
			for _, line := range strings.Split(raw, "\n") {
				if fp := strings.TrimSpace(line); fp != "" {
					out[fp] = true
				}
			}
		}
	}
	return out
}

func switchNode(n Node, in Envelope) Result {
	out := in.Normalize()
	mode := stringParam(n.Params, "mode")
	if mode == "category" {
		counts := map[string]int{}
		for _, f := range out.Findings {
			counts[strings.ToUpper(f.Category)]++
		}
		best := "CLEAN"
		bestN := 0
		for _, cat := range []string{"SECRET", "SAST", "SCA"} {
			if counts[cat] > bestN {
				best, bestN = cat, counts[cat]
			}
		}
		return Result{Envelope: out, ActivePorts: []string{best}, Status: "SUCCEEDED"}
	}
	sev := out.Stats.MaxSeverity
	if sev == "" {
		sev = maxSeverity(out.Findings)
	}
	port := "CLEAN"
	switch sev {
	case "CRITICAL":
		port = "CRITICAL"
	case "HIGH":
		port = "HIGH"
	case "MEDIUM", "LOW":
		port = "MEDIUM_LOW"
	}
	return Result{Envelope: out, ActivePorts: []string{port}, Status: "SUCCEEDED"}
}

func gateNode(n Node, in Envelope) Result {
	out := in.Normalize()
	failOn := strings.ToUpper(stringParam(n.Params, "failOnSeverity"))
	if _, specified := n.Params["failOnSeverity"]; !specified {
		failOn = "HIGH"
	}
	warnOn := strings.ToUpper(stringParam(n.Params, "warnOnSeverity"))
	if _, specified := n.Params["warnOnSeverity"]; !specified {
		warnOn = "MEDIUM"
	}
	failOnAnySecret := boolParam(n.Params, "failOnAnySecret", true)
	onlyNew := boolParam(n.Params, "onlyNewVsBaseline", false)
	maxAllowed, hasMaxAllowed := optionalIntParam(n.Params, "maxAllowedFindings")

	candidates := out.Findings
	if onlyNew {
		filtered := make([]Finding, 0, len(out.Findings))
		for _, f := range out.Findings {
			if f.IsNewVsBaseline {
				filtered = append(filtered, f)
			}
		}
		candidates = filtered
	}

	secretCount := 0
	for _, f := range candidates {
		if strings.EqualFold(f.Category, "SECRET") {
			secretCount++
		}
	}
	topSev := maxSeverity(candidates)

	var failReasons []string
	if failOnAnySecret && secretCount > 0 {
		failReasons = append(failReasons, fmt.Sprintf("%d secret finding(s) detected", secretCount))
	}
	if failOn != "" && len(candidates) > 0 && rank(topSev) >= rank(failOn) {
		failReasons = append(failReasons, fmt.Sprintf("max severity %s >= failOnSeverity %s", topSev, failOn))
	}
	if hasMaxAllowed && len(candidates) > maxAllowed {
		failReasons = append(failReasons, fmt.Sprintf("%d findings exceed maxAllowedFindings %d", len(candidates), maxAllowed))
	}

	status := "PASS"
	reason := "all policy checks passed"
	switch {
	case len(failReasons) > 0:
		status = "FAIL"
		reason = strings.Join(failReasons, "; ")
	case warnOn != "" && len(candidates) > 0 && rank(topSev) >= rank(warnOn):
		status = "WARN"
		reason = fmt.Sprintf("max severity %s >= warnOnSeverity %s", topSev, warnOn)
	}

	out.Gate = &GateInfo{
		Status:      status,
		Reason:      reason,
		NodeID:      n.ID,
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	out.Vars["gate"] = status
	out.Vars["gateReason"] = reason
	out.RefreshStats()
	return Result{Envelope: out, ActivePorts: []string{status}, Status: "SUCCEEDED"}
}

func topo(g Graph) []string {
	adj := map[string][]string{}
	indeg := map[string]int{}
	for _, n := range g.Nodes {
		indeg[n.ID] = 0
	}
	for _, e := range g.Edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
		indeg[e.Target]++
	}
	var q []string
	for id, d := range indeg {
		if d == 0 {
			q = append(q, id)
		}
	}
	sort.Strings(q)
	var order []string
	for len(q) > 0 {
		id := q[0]
		q = q[1:]
		order = append(order, id)
		next := append([]string{}, adj[id]...)
		sort.Strings(next)
		for _, nxt := range next {
			indeg[nxt]--
			if indeg[nxt] == 0 {
				q = append(q, nxt)
			}
		}
	}
	return order
}

func rank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func maxSeverity(fs []Finding) string {
	best := ""
	for _, f := range fs {
		if rank(f.Severity) > rank(best) {
			best = strings.ToUpper(f.Severity)
		}
	}
	return best
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func clonePortEnvelopes(in map[string]Envelope) map[string]Envelope {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]Envelope, len(in))
	for k, v := range in {
		out[k] = v.Normalize()
	}
	return out
}

func stringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	s, _ := params[key].(string)
	return s
}

func boolParam(params map[string]any, key string, def bool) bool {
	if params == nil {
		return def
	}
	if b, ok := params[key].(bool); ok {
		return b
	}
	return def
}

func intParam(params map[string]any, key string, def int) int {
	if v, ok := optionalIntParam(params, key); ok {
		return v
	}
	return def
}

func optionalIntParam(params map[string]any, key string) (int, bool) {
	if params == nil {
		return 0, false
	}
	raw, exists := params[key]
	if !exists || raw == nil {
		return 0, false
	}
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case json.Number:
		i, err := v.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

func stringSliceParam(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	switch v := params[key].(type) {
	case []string:
		return slices.Clone(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func upperSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]bool, len(items))
	for _, s := range items {
		out[strings.ToUpper(s)] = true
	}
	return out
}

func lowerSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]bool, len(items))
	for _, s := range items {
		out[strings.ToLower(s)] = true
	}
	return out
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func asFloat64(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case int32:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func asScalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}

func toAnySlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	case string:
		parts := strings.Split(t, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Rerun replays nodeID and all reachable downstream descendants in topological order
// using the cached input envelope for nodeID without recomputing upstream predecessors.
func Rerun(g Graph, nodeID string, cached Envelope, handlers map[string]Handler) (traces map[string]NodeTrace, skipped map[string]bool, err error) {
	if cycle(g) {
		return nil, nil, fmt.Errorf("%s: graph contains cycle", CodeCycle)
	}
	nodes := make(map[string]Node, len(g.Nodes))
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	if _, ok := nodes[nodeID]; !ok {
		return nil, nil, fmt.Errorf("node %s not found", nodeID)
	}

	incoming := map[string][]Edge{}
	outgoing := map[string][]Edge{}
	for _, e := range g.Edges {
		incoming[e.Target] = append(incoming[e.Target], e)
		outgoing[e.Source] = append(outgoing[e.Source], e)
	}

	// Collect nodeID and all downstream descendants reachable via directed edges.
	descendants := map[string]bool{nodeID: true}
	queue := []string{nodeID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range outgoing[cur] {
			if !descendants[e.Target] {
				descendants[e.Target] = true
				queue = append(queue, e.Target)
			}
		}
	}

	order := topo(g)
	traces = map[string]NodeTrace{}
	skipped = map[string]bool{}
	active := map[string]bool{nodeID: true}

	for _, id := range order {
		if !descendants[id] {
			continue
		}
		n := nodes[id]
		if !active[id] {
			skipped[id] = true
			continue
		}
		var in Envelope
		if id == nodeID {
			in = cached.Normalize()
		} else {
			in = mergeIncoming(id, incoming, traces, shouldDeduplicate(n))
		}
		result := dispatch(n, in, handlers)
		if result.Status == "FAILED" {
			return traces, skipped, fmt.Errorf("node %s: %s", id, result.Err)
		}
		ports := slices.Clone(result.ActivePorts)
		traces[id] = NodeTrace{
			Input:           in,
			Output:          result.Envelope,
			Ports:           ports,
			PortOutputs:     clonePortEnvelopes(result.PortEnvelopes),
			ArtifactKey:     result.ArtifactKey,
			ArtifactContent: slices.Clone(result.ArtifactContent),
			RedactedPreview: slices.Clone(result.RedactedPreview),
		}
		chosen := map[string]bool{}
		for _, p := range result.ActivePorts {
			chosen[p] = true
		}
		for _, e := range outgoing[id] {
			handle := e.SourceHandle
			if handle == "" {
				handle = "default"
			}
			if chosen[handle] {
				active[e.Target] = true
			}
		}
	}
	return traces, skipped, nil
}
