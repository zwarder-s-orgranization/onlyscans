package manifest

import (
	"slices"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

// BuiltinSpec describes one canonical built-in SecFlow Plugin from the 6 orthogonal families.
type BuiltinSpec struct {
	PluginID           string
	DisplayName        string
	Description        string
	Category           secflowv1.PluginCategory
	Capabilities       []string
	RuntimeLanguage    string
	SandboxProfile     secflowv1.SandboxProfile
	InputPorts         []string
	OutputPorts        []string
	RequiredSecretKeys []string
	OptionalSecretKeys []string
}

var builtins = []BuiltinSpec{
	{
		PluginID: "trigger.manual", DisplayName: "Manual Trigger", Description: "Starts a Workflow Run manually from the UI, API, or MCP.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_TRIGGER, Capabilities: []string{"trigger"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		OutputPorts: []string{"default"},
	},
	{
		PluginID: "trigger.schedule", DisplayName: "Schedule Trigger", Description: "Starts a Workflow Run on a cron schedule.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_TRIGGER, Capabilities: []string{"trigger"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		OutputPorts: []string{"default"},
	},
	{
		PluginID: "trigger.webhook", DisplayName: "Git Webhook Trigger", Description: "Starts a Workflow Run from signed GitHub or GitLab webhooks.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_TRIGGER, Capabilities: []string{"trigger"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		OutputPorts: []string{"default"}, RequiredSecretKeys: []string{"webhookSecret"}, OptionalSecretKeys: []string{"gitStatusToken"},
	},
	{
		PluginID: "source.upload", DisplayName: "Uploaded Archive Source", Description: "Attaches an uploaded ZIP archive snapshot to the Run.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_SOURCE, Capabilities: []string{"source"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "source.git", DisplayName: "Git Repository Source", Description: "Clones an allowlisted Git repository into the Run.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_SOURCE, Capabilities: []string{"source"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"}, OptionalSecretKeys: []string{"gitToken"},
	},
	{
		PluginID: "scan.secrets", DisplayName: "Secret Scanner (PSI)", Description: "Detects hardcoded secrets and credentials using Kotlin PSI and YAML analysis.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, Capabilities: []string{"analyzer"},
		RuntimeLanguage: "kotlin-jvm", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "scan.sca", DisplayName: "Gradle SCA Scanner", Description: "Matches project dependencies against versioned Maven vulnerability catalogs.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, Capabilities: []string{"analyzer"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "scan.sast.kotlin", DisplayName: "Kotlin/Spring SAST (PSI)", Description: "Detects Kotlin and Spring security flaws using deterministic PSI analysis.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, Capabilities: []string{"analyzer"},
		RuntimeLanguage: "kotlin-jvm", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "sbom.generate", DisplayName: "CycloneDX 1.6 SBOM", Description: "Generates CycloneDX 1.6 JSON software bill of materials.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, Capabilities: []string{"sbom"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "logic.if", DisplayName: "If Condition", Description: "Routes execution to true or false based on visual rules.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC, Capabilities: []string{"logic"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"true", "false"},
	},
	{
		PluginID: "logic.switch", DisplayName: "Severity/Category Switch", Description: "Branches execution by highest severity or finding category.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC, Capabilities: []string{"logic"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"CRITICAL", "HIGH", "MEDIUM_LOW", "SECRET", "SAST", "SCA", "CLEAN"},
	},
	{
		PluginID: "logic.compare", DisplayName: "Compare / Baseline Diff", Description: "Compares branch findings against thresholds or previous baseline Run.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC, Capabilities: []string{"logic"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"true", "false"},
	},
	{
		PluginID: "logic.filter", DisplayName: "Filter Findings", Description: "Filters branch-local Envelope findings without mutating Run Findings.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC, Capabilities: []string{"logic"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "logic.regex", DisplayName: "Regex Match", Description: "Matches or splits branch-local findings by regular expression.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC, Capabilities: []string{"logic"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"match", "nomatch"},
	},
	{
		PluginID: "logic.merge", DisplayName: "Merge Branches", Description: "Merges multiple incoming branch Envelopes with finding deduplication.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC, Capabilities: []string{"logic"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "gate.policy", DisplayName: "Policy Gate", Description: "Evaluates findings against threshold rules to emit PASS, WARN, or FAIL.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC, Capabilities: []string{"logic", "gate"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"PASS", "WARN", "FAIL"},
	},
	{
		PluginID: "ai.explain", DisplayName: "AI Explain (Grounded)", Description: "Explains deterministic Findings with strict grounding and zero fake CVEs.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_AI_REPORT, Capabilities: []string{"ai"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"}, OptionalSecretKeys: []string{"llmApiKey"},
	},
	{
		PluginID: "report.export", DisplayName: "Report Export", Description: "Builds Submission Report JSON and human-readable Markdown/HTML report.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_AI_REPORT, Capabilities: []string{"report"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_ORCHESTRATOR_BUILTIN,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
	{
		PluginID: "notify.telegram", DisplayName: "Telegram Notification", Description: "Sends MarkdownV2 security report notifications to Telegram.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, Capabilities: []string{"notify"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"}, RequiredSecretKeys: []string{"botToken"},
	},
	{
		PluginID: "notify.webhook", DisplayName: "Signed Webhook", Description: "Delivers HMAC-signed JSON notifications to an allowlisted webhook URL.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, Capabilities: []string{"notify"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"}, OptionalSecretKeys: []string{"hmacSecret"},
	},
	{
		PluginID: "notify.smtp", DisplayName: "Email (SMTP)", Description: "Sends email notifications over SMTP.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, Capabilities: []string{"notify"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"}, RequiredSecretKeys: []string{"smtpPassword"},
	},
	{
		PluginID: "mcp.tool", DisplayName: "MCP Tool Node", Description: "Invokes one explicitly selected tool on an allowlisted MCP Connection.",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, Capabilities: []string{"mcp"},
		RuntimeLanguage: "go", SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		InputPorts: []string{"default"}, OutputPorts: []string{"default"},
	},
}

var builtinIndex = func() map[string]BuiltinSpec {
	m := make(map[string]BuiltinSpec, len(builtins))
	for _, spec := range builtins {
		m[spec.PluginID] = spec
	}
	return m
}()

// BuiltinSpecs returns a copy of all 22 canonical built-in plugin specifications.
func BuiltinSpecs() []BuiltinSpec {
	return slices.Clone(builtins)
}

// LookupBuiltin finds a canonical built-in plugin specification by plugin_id.
func LookupBuiltin(pluginID string) (BuiltinSpec, bool) {
	spec, ok := builtinIndex[pluginID]
	return spec, ok
}

// OutputPorts returns the valid output port IDs for a built-in plugin (or ["default"] for unknown/external plugins).
func OutputPorts(pluginID string) []string {
	spec, ok := builtinIndex[pluginID]
	if !ok || len(spec.OutputPorts) == 0 {
		return []string{"default"}
	}
	return slices.Clone(spec.OutputPorts)
}

// ToProto converts a BuiltinSpec into a protobuf PluginManifest.
func (s BuiltinSpec) ToProto(paramsSchema string) *secflowv1.PluginManifest {
	inPorts := make([]*secflowv1.PortDefinition, 0, len(s.InputPorts))
	for _, id := range s.InputPorts {
		inPorts = append(inPorts, &secflowv1.PortDefinition{Id: id, Label: id})
	}
	outPorts := make([]*secflowv1.PortDefinition, 0, len(s.OutputPorts))
	for _, id := range s.OutputPorts {
		outPorts = append(outPorts, &secflowv1.PortDefinition{Id: id, Label: id})
	}
	return &secflowv1.PluginManifest{
		PluginId:           s.PluginID,
		Version:            "1.0.0",
		DisplayName:        s.DisplayName,
		Description:        s.Description,
		Category:           s.Category,
		Capabilities:       slices.Clone(s.Capabilities),
		InputPorts:         inPorts,
		OutputPorts:        outPorts,
		ParamsJsonSchema:   []byte(paramsSchema),
		RequiredSecretKeys: slices.Clone(s.RequiredSecretKeys),
		RuntimeLanguage:    s.RuntimeLanguage,
		SandboxProfile:     s.SandboxProfile,
		IsExternal:         false,
	}
}
