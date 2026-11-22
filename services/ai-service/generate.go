package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/paramschema"
)

type pluginCatalog struct {
	manifests map[string]*secflowv1.PluginManifest
	order     []string
}

func (c *pluginCatalog) has(pluginID string) bool {
	if c == nil {
		return false
	}
	_, ok := c.manifests[pluginID]
	return ok
}

func (c *pluginCatalog) get(pluginID string) *secflowv1.PluginManifest {
	if c == nil {
		return nil
	}
	return c.manifests[pluginID]
}

func (c *pluginCatalog) promptSummary() string {
	if c == nil || len(c.order) == 0 {
		return ""
	}
	var lines []string
	for _, pid := range c.order {
		m := c.manifests[pid]
		if m == nil {
			continue
		}
		var outPorts []string
		for _, p := range m.GetOutputPorts() {
			if p.GetId() != "" {
				outPorts = append(outPorts, p.GetId())
			}
		}
		if len(outPorts) == 0 {
			outPorts = []string{"default"}
		}
		line := fmt.Sprintf("- %s (category=%s, outputs=[%s])", pid, strings.TrimPrefix(m.GetCategory().String(), "PLUGIN_CATEGORY_"), strings.Join(outPorts, ","))
		if len(m.GetRequiredSecretKeys()) > 0 {
			line += fmt.Sprintf(" [requiredSecrets=%s]", strings.Join(m.GetRequiredSecretKeys(), ","))
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func defaultPluginCatalog() *pluginCatalog {
	specs := manifest.BuiltinSpecs()
	cat := &pluginCatalog{
		manifests: make(map[string]*secflowv1.PluginManifest, len(specs)),
		order:     make([]string, 0, len(specs)),
	}
	for _, spec := range specs {
		rawSchema, _ := paramschema.RawDef(spec.PluginID)
		m := spec.ToProto(string(rawSchema))
		cat.manifests[spec.PluginID] = m
		cat.order = append(cat.order, spec.PluginID)
	}
	return cat
}

func catalogFromRegisteredPlugins(plugins []*secflowv1.RegisteredPlugin) *pluginCatalog {
	if len(plugins) == 0 {
		return defaultPluginCatalog()
	}
	cat := &pluginCatalog{
		manifests: make(map[string]*secflowv1.PluginManifest, len(plugins)),
		order:     make([]string, 0, len(plugins)),
	}
	for _, rp := range plugins {
		m := rp.GetManifest()
		if m == nil || m.GetPluginId() == "" {
			continue
		}
		if _, exists := cat.manifests[m.GetPluginId()]; exists {
			continue
		}
		cat.manifests[m.GetPluginId()] = m
		cat.order = append(cat.order, m.GetPluginId())
	}
	if len(cat.order) == 0 {
		return defaultPluginCatalog()
	}
	return cat
}

func fetchLivePluginCatalog(ctx context.Context, orchAddr string) *pluginCatalog {
	orchAddr = strings.TrimSpace(orchAddr)
	if orchAddr == "" {
		return defaultPluginCatalog()
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(orchAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
	if err != nil {
		slog.WarnContext(ctx, "dial orchestrator plugin registry failed; using built-in catalog", "addr", orchAddr, "err", err)
		return defaultPluginCatalog()
	}
	defer func() { _ = conn.Close() }()

	resp, err := secflowv1.NewPluginRegistryServiceClient(conn).ListPlugins(rpcCtx, &secflowv1.ListPluginsRequest{})
	if err != nil {
		slog.WarnContext(ctx, "list live plugins failed; using built-in catalog", "addr", orchAddr, "err", err)
		return defaultPluginCatalog()
	}
	return catalogFromRegisteredPlugins(resp.GetPlugins())
}

type llmWorkflowDraft struct {
	SuggestedName        string `json:"suggestedName"`
	SuggestedDescription string `json:"suggestedDescription"`
	Rationale            string `json:"rationale"`
	Nodes                []struct {
		ID       string         `json:"id"`
		PluginID string         `json:"pluginId"`
		Label    string         `json:"label"`
		Params   map[string]any `json:"params"`
	} `json:"nodes"`
	Edges []struct {
		Source       string `json:"source"`
		Target       string `json:"target"`
		SourceHandle string `json:"sourceHandle"`
	} `json:"edges"`
}

type generateAuditInfo struct {
	UsedLLM    bool
	ModelID    string
	Mode       secflowv1.AIProviderMode
	PromptHash string
	TokensIn   int32
	TokensOut  int32
	LatencyMs  int64
}

func generateWorkflowFromPrompt(ctx context.Context, cfg llmConfig, prompt string) (*secflowv1.GenerateWorkflowResponse, bool, string, secflowv1.AIProviderMode) {
	resp, meta := generateWorkflowWithCatalog(ctx, cfg, prompt, "ru", defaultPluginCatalog())
	return resp, meta.UsedLLM, meta.ModelID, meta.Mode
}

func generateWorkflowWithCatalog(ctx context.Context, cfg llmConfig, prompt, locale string, catalog *pluginCatalog) (*secflowv1.GenerateWorkflowResponse, generateAuditInfo) {
	if catalog == nil || len(catalog.order) == 0 {
		catalog = defaultPluginCatalog()
	}
	loc := strings.ToLower(strings.TrimSpace(locale))
	if loc != "en" {
		loc = "ru"
	}

	systemPrompt := buildWorkflowSystemPrompt(catalog)
	userPrompt := buildWorkflowUserPrompt(prompt, loc)
	promptHash := hashPrompt(systemPrompt, userPrompt)

	var totalIn, totalOut int32
	var totalLatency int64

	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	llmResp, err := askModelMessages(ctx, cfg, messages)
	totalIn += llmResp.TokensIn
	totalOut += llmResp.TokensOut
	totalLatency += llmResp.LatencyMs

	if err == nil {
		resp, parseErr := parseWorkflowDraft(llmResp.Content, llmResp.Model, llmResp.Mode, loc, catalog)
		if parseErr != nil {
			// Perform 1 repair-retry when the LLM draft fails structural or plugin validation.
			repairMessages := []chatMessage{
				{Role: "system", Content: systemPrompt},
				{Role: "user", Content: userPrompt},
				{Role: "assistant", Content: truncateRunes(llmResp.Content, 3000)},
				{Role: "user", Content: "The Workflow draft failed validation: " + parseErr.Error() + ". Return ONLY a valid strict JSON Workflow DAG using allowed pluginIds, valid output handles, exactly 1 trigger, a source node before every analyzer, and no cycles."},
			}
			retryResp, retryErr := askModelMessages(ctx, cfg, repairMessages)
			totalIn += retryResp.TokensIn
			totalOut += retryResp.TokensOut
			totalLatency += retryResp.LatencyMs
			if retryErr == nil {
				llmResp = retryResp
				resp, parseErr = parseWorkflowDraft(retryResp.Content, retryResp.Model, retryResp.Mode, loc, catalog)
			}
		}
		if parseErr == nil {
			return resp, generateAuditInfo{
				UsedLLM:    true,
				ModelID:    llmResp.Model,
				Mode:       llmResp.Mode,
				PromptHash: promptHash,
				TokensIn:   totalIn,
				TokensOut:  totalOut,
				LatencyMs:  totalLatency,
			}
		}
	}

	resp := fallbackWorkflowFromPromptWithCatalog(prompt, loc, catalog)
	return resp, generateAuditInfo{
		UsedLLM:    false,
		ModelID:    "template-fallback",
		Mode:       secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK,
		PromptHash: promptHash,
		TokensIn:   totalIn,
		TokensOut:  totalOut,
		LatencyMs:  totalLatency,
	}
}

func buildWorkflowSystemPrompt(catalog *pluginCatalog) string {
	return "You are SecFlow's Text-to-Workflow generator (workflow-from-text@v1). " +
		"Convert the user's request into a valid SecFlow Workflow DAG JSON object for preview only. " +
		"Use ONLY registered pluginId values from the live PluginRegistry below:\n" + catalog.promptSummary() + "\n" +
		"HARD RULES: " +
		"(1) Exactly 1 Trigger Node (trigger.*). " +
		"(2) Every Analyzer or SBOM node (scan.*, sbom.generate) MUST have a Source Node (source.upload or source.git) on the path from the trigger. " +
		"(3) Every edge sourceHandle MUST match a declared output port of its source node (for logic.switch maxSeverity use CRITICAL|HIGH|MEDIUM_LOW|CLEAN; for gate.policy use PASS|WARN|FAIL; for logic.if/logic.compare use true|false; for logic.regex use match|nomatch). " +
		"(4) NEVER include real secrets or secretBindings in the output; leave credentials unbound. " +
		"(5) No cycles. Always use the term Workflow (never scenario or pipeline). " +
		"WRITING STYLE: Write suggestedName (short and clear, 3-6 words), suggestedDescription (1-2 simple sentences), rationale (1-3 plain sentences explaining why these steps were chosen), and concise human-readable node labels in the requested language using simple words and clean plain text (no raw Markdown or unexplained jargon). " +
		"Return STRICT JSON only (no markdown): " +
		`{"suggestedName":"...","suggestedDescription":"...","rationale":"...","nodes":[{"id":"n1","pluginId":"...","label":"...","params":{}}],"edges":[{"source":"n1","target":"n2","sourceHandle":"default"}]}`
}

func buildWorkflowUserPrompt(prompt, locale string) string {
	lang := "Russian"
	if locale == "en" {
		lang = "English"
	}
	return "Language for suggestedName, suggestedDescription, rationale, and labels: " + lang + "\nUser request:\n" + prompt
}

func parseWorkflowDraft(raw, model string, mode secflowv1.AIProviderMode, locale string, catalog *pluginCatalog) (*secflowv1.GenerateWorkflowResponse, error) {
	var draft llmWorkflowDraft
	if err := json.Unmarshal([]byte(extractJSONObject(raw)), &draft); err != nil {
		return nil, fmt.Errorf("invalid workflow json: %w", err)
	}
	if len(draft.Nodes) < 2 {
		return nil, errors.New("workflow must have at least 2 nodes")
	}

	seenID := map[string]bool{}
	var nodes []*secflowv1.WorkflowNode
	for i, n := range draft.Nodes {
		if !catalog.has(n.PluginID) {
			return nil, fmt.Errorf("unknown pluginId %q", n.PluginID)
		}
		nodeID := strings.TrimSpace(n.ID)
		if nodeID == "" || seenID[nodeID] {
			nodeID = fmt.Sprintf("n%d", i+1)
		}
		seenID[nodeID] = true

		params := sanitizeDraftParams(n.PluginID, n.Params, "")
		rawParams, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params for node %s: %w", nodeID, err)
		}
		label := strings.TrimSpace(n.Label)
		if label == "" {
			if m := catalog.get(n.PluginID); m != nil && m.GetDisplayName() != "" {
				label = m.GetDisplayName()
			} else {
				label = n.PluginID
			}
		}
		nodes = append(nodes, &secflowv1.WorkflowNode{
			Id:             nodeID,
			PluginId:       n.PluginID,
			Label:          label,
			ParamsJson:     rawParams,
			SecretBindings: nil, // Never emit SecretBinding{SecretRef: ""}; PluginManifest advertises required secret slots.
		})
	}

	var edges []*secflowv1.WorkflowEdge
	for i, e := range draft.Edges {
		if !seenID[e.Source] || !seenID[e.Target] || e.Source == e.Target {
			continue
		}
		handle := strings.TrimSpace(e.SourceHandle)
		if handle == "" {
			handle = "default"
		}
		edges = append(edges, &secflowv1.WorkflowEdge{
			Id:           fmt.Sprintf("e%d", i+1),
			SourceNodeId: e.Source,
			SourceHandle: handle,
			TargetNodeId: e.Target,
			TargetHandle: "default",
		})
	}
	if len(edges) == 0 {
		for i := 1; i < len(nodes); i++ {
			edges = append(edges, &secflowv1.WorkflowEdge{
				Id:           fmt.Sprintf("e%d", i),
				SourceNodeId: nodes[i-1].Id,
				SourceHandle: "default",
				TargetNodeId: nodes[i].Id,
				TargetHandle: "default",
			})
		}
	}

	graph := &secflowv1.WorkflowGraph{SchemaVersion: 1, Nodes: nodes, Edges: edges}
	if structuralErr := validateGeneratedGraphStructure(graph, catalog); structuralErr != nil {
		return nil, structuralErr
	}

	autoLayout(graph)
	name := strings.TrimSpace(draft.SuggestedName)
	if name == "" {
		if locale == "en" {
			name = "Generated SecFlow Workflow"
		} else {
			name = "Сгенерированный Workflow SecFlow"
		}
	}
	desc := strings.TrimSpace(draft.SuggestedDescription)
	if desc == "" {
		if locale == "en" {
			desc = "Workflow preview. Fill in required parameters and secret bindings before starting a Run."
		} else {
			desc = "Черновик Workflow. Проверьте параметры и привязки секретов перед запуском Run."
		}
	}
	rationale := strings.TrimSpace(draft.Rationale)
	if rationale == "" {
		if locale == "en" {
			rationale = "Generated as a preview Workflow against the live PluginRegistry; secrets are never pre-populated."
		} else {
			rationale = "Workflow собран в режиме предпросмотра по актуальному PluginRegistry без подстановки секретов."
		}
	}

	return &secflowv1.GenerateWorkflowResponse{
		SuggestedName:        name,
		SuggestedDescription: desc,
		Rationale:            rationale,
		Graph:                graph,
		MissingFields:        collectMissingFields(graph, catalog, locale),
		ModelId:              model,
		ProviderMode:         mode,
	}, nil
}

func validateGeneratedGraphStructure(g *secflowv1.WorkflowGraph, catalog *pluginCatalog) error {
	eng := toEngineGraph(g)
	for _, issue := range engine.Validate(eng) {
		if issue.Code == engine.CodeMissingSecret {
			// Preview graphs intentionally omit secrets; these are surfaced in MissingFields.
			continue
		}
		if issue.Severity == "ERROR" {
			return fmt.Errorf("%s: %s", issue.Code, issue.Message)
		}
	}
	// Also validate output handles against live plugin manifests for any external plugins.
	if catalog != nil {
		nodePlugin := make(map[string]string, len(g.GetNodes()))
		for _, n := range g.GetNodes() {
			nodePlugin[n.GetId()] = n.GetPluginId()
		}
		for _, e := range g.GetEdges() {
			m := catalog.get(nodePlugin[e.GetSourceNodeId()])
			if m == nil || len(m.GetOutputPorts()) == 0 {
				continue
			}
			handle := e.GetSourceHandle()
			if handle == "" {
				handle = "default"
			}
			allowed := false
			for _, p := range m.GetOutputPorts() {
				if p.GetId() == handle {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("INVALID_PORT_HANDLE: handle %q not declared on %s", handle, m.GetPluginId())
			}
		}
	}
	return nil
}

func toEngineGraph(g *secflowv1.WorkflowGraph) engine.Graph {
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
		out.Nodes = append(out.Nodes, engine.Node{
			ID:       n.GetId(),
			PluginID: n.GetPluginId(),
			Params:   params,
			Secrets:  secrets,
		})
	}
	for _, e := range g.GetEdges() {
		out.Edges = append(out.Edges, engine.Edge{
			ID:           e.GetId(),
			Source:       e.GetSourceNodeId(),
			SourceHandle: e.GetSourceHandle(),
			Target:       e.GetTargetNodeId(),
			TargetHandle: e.GetTargetHandle(),
		})
	}
	return out
}

func fallbackWorkflowFromPrompt(prompt string) *secflowv1.GenerateWorkflowResponse {
	return fallbackWorkflowFromPromptWithCatalog(prompt, "ru", defaultPluginCatalog())
}

func fallbackWorkflowFromPromptWithCatalog(prompt, locale string, catalog *pluginCatalog) *secflowv1.GenerateWorkflowResponse {
	if catalog == nil {
		catalog = defaultPluginCatalog()
	}
	low := strings.ToLower(prompt)

	trigger := "trigger.manual"
	if containsAny(low, "каждый", "ежеднев", "ноч", "распис", "cron", "schedule", "nightly", "daily", "weekly", "раз в") {
		trigger = "trigger.schedule"
	} else if containsAny(low, "webhook", "вебхук", "pr", "pull request", "push", "коммит", "commit", "ci") {
		trigger = "trigger.webhook"
	}

	source := "source.git"
	if containsAny(low, "zip", "архив", "upload", "загруз") && !containsAny(low, "git", "github", "gitlab", "репо") {
		source = "source.upload"
	}

	var scanners []string
	if containsAny(low, "секрет", "secret", "ключ", "токен", "token", "парол") {
		scanners = append(scanners, "scan.secrets")
	}
	if containsAny(low, "sca", "зависим", "cve", "gradle", "библиотек", "dep") {
		scanners = append(scanners, "scan.sca")
	}
	if containsAny(low, "sast", "код", "kotlin", "spring", "sql", "idor", "уязвим") {
		scanners = append(scanners, "scan.sast.kotlin")
	}
	if containsAny(low, "sbom", "cyclonedx") {
		scanners = append(scanners, "sbom.generate")
	}
	if len(scanners) == 0 {
		scanners = []string{"scan.secrets", "scan.sca", "scan.sast.kotlin"}
	}

	useGate := containsAny(low, "gate", "гейт", "critical", "критич", "high", "блокир", "fail", "порог")
	useAI := containsAny(low, "ai", "llm", "ии", "объясн", "рекоменд", "отчёт", "отчет", "explain")
	var notifies []string
	if containsAny(low, "telegram", "телеграм", "тг", "tg") {
		notifies = append(notifies, "notify.telegram")
	}
	if containsAny(low, "mail", "smtp", "почт", "email", "письм") {
		notifies = append(notifies, "notify.smtp")
	}
	if containsAny(low, "webhook", "вебхук", "http", "slack") && trigger != "trigger.webhook" {
		notifies = append(notifies, "notify.webhook")
	}
	if len(notifies) == 0 && !containsAny(low, "без уведом", "no notify") {
		notifies = append(notifies, "notify.telegram")
	}

	var nodes []*secflowv1.WorkflowNode
	var edges []*secflowv1.WorkflowEdge
	addNode := func(id, plugin string) {
		rawParams, _ := json.Marshal(sanitizeDraftParams(plugin, nil, trigger))
		label := plugin
		if m := catalog.get(plugin); m != nil && m.GetDisplayName() != "" {
			label = m.GetDisplayName()
		}
		nodes = append(nodes, &secflowv1.WorkflowNode{
			Id:             id,
			PluginId:       plugin,
			Label:          label,
			ParamsJson:     rawParams,
			SecretBindings: nil,
		})
	}
	addEdge := func(src, dst, handle string) {
		if handle == "" {
			handle = "default"
		}
		edges = append(edges, &secflowv1.WorkflowEdge{
			Id:           fmt.Sprintf("e%d", len(edges)+1),
			SourceNodeId: src,
			SourceHandle: handle,
			TargetNodeId: dst,
			TargetHandle: "default",
		})
	}

	addNode("t1", trigger)
	addNode("s1", source)
	addEdge("t1", "s1", "default")

	var scanIDs []string
	for i, sc := range scanners {
		sid := fmt.Sprintf("scan%d", i+1)
		addNode(sid, sc)
		addEdge("s1", sid, "default")
		scanIDs = append(scanIDs, sid)
	}

	tail := scanIDs[0]
	if len(scanIDs) > 1 {
		addNode("m1", "logic.merge")
		for _, sid := range scanIDs {
			addEdge(sid, "m1", "default")
		}
		tail = "m1"
	}

	if useGate {
		addNode("g1", "gate.policy")
		addEdge(tail, "g1", "default")
		tail = "g1"
	}

	if useAI {
		addNode("ai1", "ai.explain")
		handle := "default"
		if useGate {
			handle = "FAIL"
		}
		addEdge(tail, "ai1", handle)
		tail = "ai1"
		useGate = false
	}

	for i, nf := range notifies {
		nid := fmt.Sprintf("n%d", i+1)
		addNode(nid, nf)
		handle := "default"
		if useGate {
			handle = "FAIL"
		}
		addEdge(tail, nid, handle)
	}

	graph := &secflowv1.WorkflowGraph{SchemaVersion: 1, Nodes: nodes, Edges: edges}
	autoLayout(graph)

	name := "Workflow проверки безопасности"
	desc := "Черновик Workflow (preview only). Секреты не подставлены; заполните параметры перед запуском Run."
	rationale := "Детерминированный черновик Workflow: Trigger -> Source -> Analyzers -> Logic/AI/Notifications."
	if locale == "en" {
		name = "Security Verification Workflow"
		desc = "Workflow preview only. Secrets are not populated; fill in required fields before starting a Run."
		rationale = "Deterministic Workflow preview: Trigger -> Source -> Analyzers -> Logic/AI/Notifications."
	}
	if len(scanners) == 1 && scanners[0] == "scan.secrets" {
		if locale == "en" {
			name = "Secret Watch Workflow"
		} else {
			name = "Workflow контроля секретов"
		}
	} else if trigger == "trigger.webhook" {
		name = "PR / CI Security Gate Workflow"
	}

	return &secflowv1.GenerateWorkflowResponse{
		SuggestedName:        name,
		SuggestedDescription: desc,
		Rationale:            rationale,
		Graph:                graph,
		MissingFields:        collectMissingFields(graph, catalog, locale),
		ModelId:              "template-fallback",
		ProviderMode:         secflowv1.AIProviderMode_AI_PROVIDER_MODE_TEMPLATE_FALLBACK,
	}
}

func sanitizeDraftParams(plugin string, in map[string]any, triggerPlugin string) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		switch k {
		case "apiKey", "llmApiKey", "botToken", "smtpPassword", "hmacSecret", "gitToken", "webhookSecret", "gitStatusToken":
			continue
		default:
			out[k] = v
		}
	}
	switch plugin {
	case "trigger.schedule":
		if _, ok := out["cron"]; !ok {
			out["cron"] = "0 14 * * *"
		}
	case "trigger.webhook":
		if _, ok := out["gitProvider"]; !ok {
			out["gitProvider"] = "GITHUB"
		}
		if _, ok := out["events"]; !ok {
			out["events"] = []string{"push", "pull_request"}
		}
	case "source.upload":
		if _, ok := out["sourceId"]; !ok {
			out["sourceId"] = "pending-upload"
		}
	case "source.git":
		if _, ok := out["repoUrl"]; !ok {
			if triggerPlugin == "trigger.webhook" {
				out["repoUrl"] = "{{ $trigger.repoUrl }}"
			} else {
				out["repoUrl"] = "https://github.com/TBagirov/training"
			}
		}
		if _, ok := out["gitRef"]; !ok {
			if triggerPlugin == "trigger.webhook" {
				out["gitRef"] = "{{ $trigger.commitSha }}"
			} else {
				out["gitRef"] = "main"
			}
		}
	case "gate.policy":
		if _, ok := out["failOnSeverity"]; !ok {
			out["failOnSeverity"] = "HIGH"
		}
	case "logic.switch":
		if _, ok := out["mode"]; !ok {
			out["mode"] = "maxSeverity"
		}
	case "logic.compare":
		if _, ok := out["mode"]; !ok {
			out["mode"] = "baselineDiff"
		}
	case "logic.if":
		if _, ok := out["combinator"]; !ok {
			out["combinator"] = "AND"
		}
		if _, ok := out["conditions"]; !ok {
			out["conditions"] = []map[string]any{{"field": "stats.total", "operator": "gt", "value": 0}}
		}
	case "ai.explain":
		if _, ok := out["privacyMode"]; !ok {
			out["privacyMode"] = "REDACTED_SNIPPET"
		}
		if _, ok := out["locale"]; !ok {
			out["locale"] = "ru"
		}
	case "notify.telegram":
		if _, ok := out["chatId"]; !ok {
			out["chatId"] = ""
		}
	case "notify.smtp":
		if _, ok := out["to"]; !ok {
			out["to"] = []string{}
		}
		if _, ok := out["subject"]; !ok {
			out["subject"] = "SecFlow Security Report"
		}
	case "notify.webhook":
		if _, ok := out["url"]; !ok {
			out["url"] = ""
		}
	}
	return out
}

func collectMissingFields(g *secflowv1.WorkflowGraph, catalog *pluginCatalog, locale string) []*secflowv1.ValidationIssue {
	var out []*secflowv1.ValidationIssue
	seen := map[string]bool{}
	addIssue := func(nodeID, code, fieldPath, msg string) {
		key := nodeID + "|" + code + "|" + fieldPath
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, &secflowv1.ValidationIssue{
			Code:      code,
			Severity:  secflowv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING,
			Message:   msg,
			NodeId:    nodeID,
			FieldPath: fieldPath,
		})
	}

	// 1. Collect engine validation issues (e.g. missing required secret bindings).
	for _, issue := range engine.Validate(toEngineGraph(g)) {
		fieldPath := ""
		if issue.Code == engine.CodeMissingSecret {
			if rest, ok := strings.CutPrefix(issue.Message, "нет секрета "); ok {
				key, _, _ := strings.Cut(rest, " ")
				if key != "" {
					fieldPath = "secretBindings." + key
				}
			}
		}
		addIssue(issue.NodeID, issue.Code, fieldPath, issue.Message)
	}

	// 2. Collect plugin manifest required secrets and node-params.schema.json issues.
	for _, n := range g.GetNodes() {
		pid := n.GetPluginId()
		if catalog != nil {
			if m := catalog.get(pid); m != nil {
				bound := map[string]bool{}
				for _, b := range n.GetSecretBindings() {
					if strings.TrimSpace(b.GetSecretRef()) != "" {
						bound[b.GetParamKey()] = true
					}
				}
				for _, key := range m.GetRequiredSecretKeys() {
					if bound[key] {
						continue
					}
					msg := "Привяжите секрет " + key + " через secretBindings"
					if locale == "en" {
						msg = "Bind required secret " + key + " via secretBindings"
					}
					addIssue(n.GetId(), engine.CodeMissingSecret, "secretBindings."+key, msg)
				}
			}
		}

		params := map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			_ = json.Unmarshal(n.GetParamsJson(), &params)
		}
		if err := paramschema.Check(pid, params); err != nil {
			code := "INVALID_PARAM_SCHEMA"
			if strings.Contains(err.Error(), ": нет поля ") || strings.Contains(err.Error(), "короче") {
				code = "MISSING_REQUIRED_PARAM"
			}
			addIssue(n.GetId(), code, "params", err.Error())
		}

		switch pid {
		case "source.git":
			msg := "Проверьте URL репозитория (и привяжите gitToken для приватного репо)"
			if locale == "en" {
				msg = "Verify repository URL (and bind gitToken for private repositories)"
			}
			addIssue(n.GetId(), "MISSING_REQUIRED_PARAM", "params.repoUrl", msg)
		case "source.upload":
			if asString(params["sourceId"]) == "" || asString(params["sourceId"]) == "pending-upload" {
				msg := "Загрузите ZIP-архив исходников перед запуском Run"
				if locale == "en" {
					msg = "Upload a source ZIP archive before starting a Run"
				}
				addIssue(n.GetId(), "MISSING_REQUIRED_PARAM", "params.sourceId", msg)
			}
		case "ai.explain":
			msg := "При необходимости укажите baseUrl, model и привязку llmApiKey (или используйте локальную Ollama)"
			if locale == "en" {
				msg = "Optionally configure baseUrl, model, and llmApiKey secret binding (or use local Ollama)"
			}
			addIssue(n.GetId(), "MISSING_REQUIRED_PARAM", "params.model", msg)
		}
	}
	return out
}

func autoLayout(g *secflowv1.WorkflowGraph) {
	depth := map[string]int{}
	for _, n := range g.GetNodes() {
		depth[n.GetId()] = 0
	}
	for pass := 0; pass < len(g.GetNodes()); pass++ {
		changed := false
		for _, e := range g.GetEdges() {
			if depth[e.GetSourceNodeId()]+1 > depth[e.GetTargetNodeId()] {
				depth[e.GetTargetNodeId()] = depth[e.GetSourceNodeId()] + 1
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	rowCount := map[int]int{}
	for _, n := range g.GetNodes() {
		col := depth[n.GetId()]
		row := rowCount[col]
		rowCount[col] = row + 1
		n.Position = &secflowv1.Position{
			X: float64(col * 240),
			Y: float64(40 + row*140),
		}
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
