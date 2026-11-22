// Package declarativeplugin validates and deterministically evaluates no-code
// Declarative Plugins (ANALYZER, LOGIC, ACTION) and Saved Node parameter hashes
// across the orchestrator Test Bench and secflow-sandbox runtime pools (ADR-0011).
package declarativeplugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/urlguard"
)

// Category is the allowed Declarative Plugin category.
type Category string

const (
	CategoryAnalyzer Category = "ANALYZER"
	CategoryLogic    Category = "LOGIC"
	CategoryAction   Category = "ACTION"
)

// Hard pool safety caps (ADR-0011 / Spec #33).
const (
	MaxSpecBytes            = 128 * 1024
	MaxAnalyzerRules        = 50
	MaxRegexLength          = 512
	MaxMatchesPerRule       = 200
	MaxScannedFileBytes     = 1024 * 1024
	MaxAnalyzerTimeoutSec   = 30
	MaxLogicOutputPorts     = 8
	MaxLogicComputedVars    = 10
	MaxLogicRoutes          = 30
	DefaultActionTimeoutSec = 10
	MaxActionTimeoutSec     = 30
	MaxActionResponseBytes  = 256 * 1024
	MaxTestBenchFiles       = 5
	MaxTestBenchBytes       = 256 * 1024
)

// Matcher types for ANALYZER rules.
const (
	MatcherRegex        = "regex"
	MatcherConfigKey    = "config_key"
	MatcherFilePresence = "file_presence"

	PresenceExists = "exists"
	PresenceAbsent = "absent"
)

// ComputedVar kinds for LOGIC plugins.
const (
	ComputedWeightedScore = "weighted_score"
	ComputedFindingCount  = "finding_count"
	ComputedTemplate      = "template"
)

var (
	pluginSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,47}$`)
	paramKeyRe   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,47}$`)
	portIDRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
	semverRe     = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
)

// Spec is the secret-free declarative plugin definition persisted in PluginInstallation.
type Spec struct {
	PluginID           string        `json:"pluginId"`
	Version            string        `json:"version,omitempty"`
	DisplayName        string        `json:"displayName"`
	Description        string        `json:"description,omitempty"`
	Category           Category      `json:"category"`
	Params             []ParamField  `json:"params,omitempty"`
	OutputPorts        []PortSpec    `json:"outputPorts,omitempty"`
	RequiredSecretKeys []string      `json:"requiredSecretKeys,omitempty"`
	EgressAllowlist    []string      `json:"egressAllowlist,omitempty"`
	Analyzer           *AnalyzerSpec `json:"analyzer,omitempty"`
	Logic              *LogicSpec    `json:"logic,omitempty"`
	Action             *ActionSpec   `json:"action,omitempty"`
}

// ParamField describes one flat JSON Schema parameter supported by SchemaParamsInspector.
type ParamField struct {
	Key         string   `json:"key"`
	Type        string   `json:"type"` // string | enum | integer | number | boolean | array
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Default     any      `json:"default,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Minimum     *float64 `json:"minimum,omitempty"`
	Maximum     *float64 `json:"maximum,omitempty"`
}

// PortSpec defines a named output port on a Node.
type PortSpec struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// AnalyzerSpec configures deterministic source-code / config analysis rules.
type AnalyzerSpec struct {
	Rules []AnalyzerRule `json:"rules"`
}

// AnalyzerRule defines a single deterministic check emitting Findings.
type AnalyzerRule struct {
	RuleID             string   `json:"ruleId"`
	Category           string   `json:"category"` // SECRET | SCA | SAST
	Severity           string   `json:"severity"` // LOW|MEDIUM|HIGH|CRITICAL or {{ params.<key> }}
	Title              string   `json:"title"`
	Description        string   `json:"description,omitempty"`
	Remediation        string   `json:"remediation,omitempty"`
	IncludeGlobs       []string `json:"includeGlobs,omitempty"`
	ExcludeGlobs       []string `json:"excludeGlobs,omitempty"`
	MatcherType        string   `json:"matcherType"` // regex | config_key | file_presence
	Pattern            string   `json:"pattern,omitempty"`
	Multiline          bool     `json:"multiline,omitempty"`
	ExcludePatterns    []string `json:"excludePatterns,omitempty"`
	ConfigKey          string   `json:"configKey,omitempty"`
	ConfigValuePattern string   `json:"configValuePattern,omitempty"`
	PresenceMode       string   `json:"presenceMode,omitempty"` // exists | absent
	EnabledParam       string   `json:"enabledParam,omitempty"`
}

// LogicSpec configures deterministic Envelope computation and multi-port routing.
type LogicSpec struct {
	ComputedVars []ComputedVar     `json:"computedVars,omitempty"`
	Routes       []LogicRoute      `json:"routes"`
	FallbackPort string            `json:"fallbackPort"`
	FallbackGate string            `json:"fallbackGate,omitempty"`
	FallbackVars map[string]string `json:"fallbackVars,omitempty"`
}

// ComputedVar computes a branch-local variable from Envelope findings or templates.
type ComputedVar struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"` // weighted_score | finding_count | template
	CriticalWeight int    `json:"criticalWeight,omitempty"`
	HighWeight     int    `json:"highWeight,omitempty"`
	MediumWeight   int    `json:"mediumWeight,omitempty"`
	LowWeight      int    `json:"lowWeight,omitempty"`
	FilterCategory string `json:"filterCategory,omitempty"`
	FilterSeverity string `json:"filterSeverity,omitempty"`
	FilterRuleID   string `json:"filterRuleId,omitempty"`
	Template       string `json:"template,omitempty"`
}

// LogicCondition compares an Envelope/var/param field against an expected value.
type LogicCondition struct {
	Field    string `json:"field"`    // stats.total | stats.critical | stats.high | stats.medium | stats.low | gate | vars.<k> | params.<k>
	Operator string `json:"operator"` // eq | neq | gt | gte | lt | lte | contains | matches
	Value    string `json:"value"`
}

// FindingFilter restricts branch-local Envelope.findings without mutating Run Findings.
type FindingFilter struct {
	MinSeverity string   `json:"minSeverity,omitempty"`
	Categories  []string `json:"categories,omitempty"`
}

// LogicRoute maps an ordered condition group to an output port and Envelope mutations.
type LogicRoute struct {
	Name           string            `json:"name,omitempty"`
	MatchMode      string            `json:"matchMode,omitempty"` // ALL | ANY (default ALL)
	Conditions     []LogicCondition  `json:"conditions"`
	OutputPort     string            `json:"outputPort"`
	Gate           string            `json:"gate,omitempty"` // "" | PASS | WARN | FAIL
	SetVars        map[string]string `json:"setVars,omitempty"`
	FilterFindings *FindingFilter    `json:"filterFindings,omitempty"`
}

// ActionSpec configures a templated outbound HTTP action.
type ActionSpec struct {
	Method           string            `json:"method"` // POST | PUT | PATCH | GET
	URL              string            `json:"url"`
	Headers          map[string]string `json:"headers,omitempty"`
	BodyTemplate     string            `json:"bodyTemplate,omitempty"`
	ExpectedStatuses []int             `json:"expectedStatuses,omitempty"`
	TimeoutSeconds   int               `json:"timeoutSeconds,omitempty"`
	ExtractVars      map[string]string `json:"extractVars,omitempty"`
}

// VirtualFile represents an in-memory file passed to EvaluateAnalyzer or Test Bench.
type VirtualFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// StarterBlueprint packages a ready-to-use example spec for the modal builder.
type StarterBlueprint struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Spec        Spec   `json:"spec"`
}

// ValidateSpec parses, normalizes, and strictly validates a Declarative Plugin Spec JSON.
func ValidateSpec(raw []byte) (Spec, error) {
	if len(raw) == 0 {
		return Spec{}, fmt.Errorf("VALIDATION_FAILED: declarative spec is empty")
	}
	if len(raw) > MaxSpecBytes {
		return Spec{}, fmt.Errorf("VALIDATION_FAILED: declarative spec exceeds %d bytes limit", MaxSpecBytes)
	}
	var spec Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return Spec{}, fmt.Errorf("VALIDATION_FAILED: invalid declarative spec JSON: %w", err)
	}
	if err := normalizeAndValidate(&spec); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

func normalizeAndValidate(s *Spec) error {
	s.PluginID = strings.ToLower(strings.TrimSpace(s.PluginID))
	s.DisplayName = strings.TrimSpace(s.DisplayName)
	s.Description = strings.TrimSpace(s.Description)
	s.Version = strings.TrimSpace(s.Version)
	if s.Version == "" {
		s.Version = "1.0.0"
	}
	if !semverRe.MatchString(s.Version) {
		return fmt.Errorf("VALIDATION_FAILED: version %q must be semver (e.g. 1.0.0)", s.Version)
	}
	if s.DisplayName == "" {
		return fmt.Errorf("VALIDATION_FAILED: displayName is required")
	}

	var requiredPrefix string
	switch s.Category {
	case CategoryAnalyzer:
		requiredPrefix = "custom.scan."
	case CategoryLogic:
		requiredPrefix = "custom.logic."
	case CategoryAction:
		requiredPrefix = "custom.action."
	default:
		return fmt.Errorf("VALIDATION_FAILED: unsupported category %q (allowed: ANALYZER, LOGIC, ACTION)", s.Category)
	}

	if !strings.HasPrefix(s.PluginID, requiredPrefix) {
		return fmt.Errorf("VALIDATION_FAILED: pluginId %q must start with %q", s.PluginID, requiredPrefix)
	}
	slug := strings.TrimPrefix(s.PluginID, requiredPrefix)
	if !pluginSlugRe.MatchString(slug) {
		return fmt.Errorf("VALIDATION_FAILED: pluginId slug %q must match [a-z0-9][a-z0-9-]{1,47}", slug)
	}

	if err := checkDenylist(s.PluginID, s.DisplayName, s.Description); err != nil {
		return err
	}
	if err := validateParams(s.Params); err != nil {
		return err
	}

	if s.Category != CategoryAction {
		if len(s.EgressAllowlist) > 0 {
			return fmt.Errorf("VALIDATION_FAILED: egressAllowlist must be empty for INTERNAL_ONLY category %s", s.Category)
		}
		if len(s.RequiredSecretKeys) > 0 {
			return fmt.Errorf("VALIDATION_FAILED: requiredSecretKeys are allowed only for ACTION plugins")
		}
	}

	switch s.Category {
	case CategoryAnalyzer:
		s.OutputPorts = []PortSpec{{ID: "default", Label: "default"}}
		return validateAnalyzerSpec(s.Analyzer)
	case CategoryLogic:
		return validateLogicSpec(s)
	case CategoryAction:
		s.OutputPorts = []PortSpec{{ID: "default", Label: "default"}}
		return validateActionSpec(s)
	default:
		return fmt.Errorf("VALIDATION_FAILED: unsupported category %q", s.Category)
	}
}

func checkDenylist(fields ...string) error {
	for _, f := range fields {
		if f != "" && urlguard.Denied(f) {
			return fmt.Errorf("DENYLIST_BLOCKED: prohibited scanner reference in %q", f)
		}
	}
	joined := strings.Join(fields, " ")
	if joined != "" && urlguard.Denied(joined) {
		return fmt.Errorf("DENYLIST_BLOCKED: prohibited scanner reference")
	}
	return nil
}

func validateParams(params []ParamField) error {
	seen := make(map[string]bool, len(params))
	for i := range params {
		p := &params[i]
		p.Key = strings.TrimSpace(p.Key)
		if !paramKeyRe.MatchString(p.Key) {
			return fmt.Errorf("VALIDATION_FAILED: invalid parameter key %q", p.Key)
		}
		if seen[p.Key] {
			return fmt.Errorf("VALIDATION_FAILED: duplicate parameter key %q", p.Key)
		}
		seen[p.Key] = true
		if err := checkDenylist(p.Key, p.Description); err != nil {
			return err
		}
		switch p.Type {
		case "string", "integer", "number", "boolean", "array":
		case "enum":
			if len(p.Enum) == 0 {
				return fmt.Errorf("VALIDATION_FAILED: enum parameter %q requires at least one option", p.Key)
			}
		default:
			return fmt.Errorf("VALIDATION_FAILED: unsupported parameter type %q for %q (allowed: string, enum, integer, number, boolean, array)", p.Type, p.Key)
		}
		if p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum {
			return fmt.Errorf("VALIDATION_FAILED: parameter %q minimum exceeds maximum", p.Key)
		}
	}
	return nil
}

func validateAnalyzerSpec(a *AnalyzerSpec) error {
	if a == nil || len(a.Rules) == 0 {
		return fmt.Errorf("VALIDATION_FAILED: ANALYZER requires at least 1 rule")
	}
	if len(a.Rules) > MaxAnalyzerRules {
		return fmt.Errorf("VALIDATION_FAILED: ANALYZER allows at most %d rules", MaxAnalyzerRules)
	}
	for i := range a.Rules {
		r := &a.Rules[i]
		r.RuleID = strings.TrimSpace(r.RuleID)
		r.Title = strings.TrimSpace(r.Title)
		if r.RuleID == "" || r.Title == "" {
			return fmt.Errorf("VALIDATION_FAILED: analyzer rule[%d] requires ruleId and title", i)
		}
		if err := checkDenylist(r.RuleID, r.Title, r.Description, r.Remediation, r.Pattern, r.ConfigKey, r.ConfigValuePattern); err != nil {
			return err
		}
		switch strings.ToUpper(strings.TrimSpace(r.Category)) {
		case "SECRET", "SAST", "SCA":
			r.Category = strings.ToUpper(strings.TrimSpace(r.Category))
		default:
			return fmt.Errorf("VALIDATION_FAILED: rule %q has invalid finding category %q", r.RuleID, r.Category)
		}
		if err := validateSeverityExpr(r.Severity); err != nil {
			return fmt.Errorf("VALIDATION_FAILED: rule %q: %w", r.RuleID, err)
		}
		for _, ep := range r.ExcludePatterns {
			if len(ep) > MaxRegexLength {
				return fmt.Errorf("VALIDATION_FAILED: rule %q excludePattern exceeds %d chars", r.RuleID, MaxRegexLength)
			}
			if _, err := regexp.Compile(ep); err != nil {
				return fmt.Errorf("VALIDATION_FAILED: rule %q invalid excludePattern RE2: %w", r.RuleID, err)
			}
		}
		switch r.MatcherType {
		case MatcherRegex:
			if strings.TrimSpace(r.Pattern) == "" {
				return fmt.Errorf("VALIDATION_FAILED: regex rule %q requires pattern", r.RuleID)
			}
			if len(r.Pattern) > MaxRegexLength {
				return fmt.Errorf("VALIDATION_FAILED: regex rule %q pattern exceeds %d chars", r.RuleID, MaxRegexLength)
			}
			if _, err := regexp.Compile(r.Pattern); err != nil {
				return fmt.Errorf("VALIDATION_FAILED: regex rule %q invalid RE2 pattern: %w", r.RuleID, err)
			}
		case MatcherConfigKey:
			if strings.TrimSpace(r.ConfigKey) == "" {
				return fmt.Errorf("VALIDATION_FAILED: config_key rule %q requires configKey", r.RuleID)
			}
			if r.ConfigValuePattern != "" {
				if len(r.ConfigValuePattern) > MaxRegexLength {
					return fmt.Errorf("VALIDATION_FAILED: config_key rule %q value pattern exceeds %d chars", r.RuleID, MaxRegexLength)
				}
				if _, err := regexp.Compile(r.ConfigValuePattern); err != nil {
					return fmt.Errorf("VALIDATION_FAILED: config_key rule %q invalid value RE2: %w", r.RuleID, err)
				}
			}
		case MatcherFilePresence:
			if len(r.IncludeGlobs) == 0 {
				return fmt.Errorf("VALIDATION_FAILED: file_presence rule %q requires includeGlobs", r.RuleID)
			}
			if r.PresenceMode != PresenceExists && r.PresenceMode != PresenceAbsent {
				return fmt.Errorf("VALIDATION_FAILED: file_presence rule %q presenceMode must be exists or absent", r.RuleID)
			}
		default:
			return fmt.Errorf("VALIDATION_FAILED: rule %q unsupported matcherType %q", r.RuleID, r.MatcherType)
		}
	}
	return nil
}

func validateSeverityExpr(raw string) error {
	v := strings.TrimSpace(raw)
	if strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}") {
		return nil
	}
	switch strings.ToUpper(v) {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return nil
	default:
		return fmt.Errorf("invalid severity %q", raw)
	}
}

func validateLogicSpec(s *Spec) error {
	if s.Logic == nil {
		return fmt.Errorf("VALIDATION_FAILED: LOGIC spec is required")
	}
	if len(s.OutputPorts) == 0 {
		s.OutputPorts = []PortSpec{{ID: "default", Label: "default"}}
	}
	if len(s.OutputPorts) > MaxLogicOutputPorts {
		return fmt.Errorf("VALIDATION_FAILED: LOGIC allows at most %d output ports", MaxLogicOutputPorts)
	}
	portSet := make(map[string]bool, len(s.OutputPorts))
	for i := range s.OutputPorts {
		p := &s.OutputPorts[i]
		p.ID = strings.TrimSpace(p.ID)
		p.Label = strings.TrimSpace(p.Label)
		if !portIDRe.MatchString(p.ID) {
			return fmt.Errorf("VALIDATION_FAILED: invalid output port id %q", p.ID)
		}
		if p.Label == "" {
			p.Label = p.ID
		}
		if portSet[p.ID] {
			return fmt.Errorf("VALIDATION_FAILED: duplicate output port id %q", p.ID)
		}
		portSet[p.ID] = true
		if err := checkDenylist(p.ID, p.Label, p.Description); err != nil {
			return err
		}
	}
	if len(s.Logic.ComputedVars) > MaxLogicComputedVars {
		return fmt.Errorf("VALIDATION_FAILED: LOGIC allows at most %d computedVars", MaxLogicComputedVars)
	}
	for _, cv := range s.Logic.ComputedVars {
		if !paramKeyRe.MatchString(strings.TrimSpace(cv.Name)) {
			return fmt.Errorf("VALIDATION_FAILED: invalid computedVar name %q", cv.Name)
		}
		switch cv.Kind {
		case ComputedWeightedScore, ComputedFindingCount, ComputedTemplate:
		default:
			return fmt.Errorf("VALIDATION_FAILED: unsupported computedVar kind %q", cv.Kind)
		}
	}
	if len(s.Logic.Routes) > MaxLogicRoutes {
		return fmt.Errorf("VALIDATION_FAILED: LOGIC allows at most %d routes", MaxLogicRoutes)
	}
	for i, r := range s.Logic.Routes {
		if !portSet[r.OutputPort] {
			return fmt.Errorf("VALIDATION_FAILED: route[%d] references unknown outputPort %q", i, r.OutputPort)
		}
		if err := validateGateValue(r.Gate); err != nil {
			return err
		}
		for _, c := range r.Conditions {
			if c.Operator == "matches" {
				if len(c.Value) > MaxRegexLength {
					return fmt.Errorf("VALIDATION_FAILED: route[%d] regex condition exceeds %d chars", i, MaxRegexLength)
				}
				if _, err := regexp.Compile(c.Value); err != nil {
					return fmt.Errorf("VALIDATION_FAILED: route[%d] invalid RE2 condition: %w", i, err)
				}
			}
		}
	}
	if strings.TrimSpace(s.Logic.FallbackPort) == "" || !portSet[s.Logic.FallbackPort] {
		return fmt.Errorf("VALIDATION_FAILED: LOGIC requires a valid fallbackPort from outputPorts")
	}
	if err := validateGateValue(s.Logic.FallbackGate); err != nil {
		return err
	}
	return nil
}

func validateGateValue(g string) error {
	switch strings.ToUpper(strings.TrimSpace(g)) {
	case "", "PASS", "WARN", "FAIL":
		return nil
	default:
		return fmt.Errorf("VALIDATION_FAILED: invalid gate value %q", g)
	}
}

func validateActionSpec(s *Spec) error {
	if s.Action == nil {
		return fmt.Errorf("VALIDATION_FAILED: ACTION spec is required")
	}
	if len(s.EgressAllowlist) == 0 {
		return fmt.Errorf("VALIDATION_FAILED: ACTION requires at least one egressAllowlist host")
	}
	for _, h := range s.EgressAllowlist {
		if err := checkDenylist(h); err != nil {
			return err
		}
	}
	for _, sk := range s.RequiredSecretKeys {
		if !paramKeyRe.MatchString(strings.TrimSpace(sk)) {
			return fmt.Errorf("VALIDATION_FAILED: invalid requiredSecretKey %q", sk)
		}
	}
	method := strings.ToUpper(strings.TrimSpace(s.Action.Method))
	switch method {
	case "POST", "PUT", "PATCH", "GET":
		s.Action.Method = method
	default:
		return fmt.Errorf("VALIDATION_FAILED: unsupported ACTION HTTP method %q", s.Action.Method)
	}
	if strings.TrimSpace(s.Action.URL) == "" {
		return fmt.Errorf("VALIDATION_FAILED: ACTION url is required")
	}
	if err := checkDenylist(s.Action.URL, s.Action.BodyTemplate); err != nil {
		return err
	}
	// Reject templated URL scheme so scheme enforcement cannot be bypassed.
	trimmedURL := strings.TrimSpace(s.Action.URL)
	if !strings.HasPrefix(strings.ToLower(trimmedURL), "https://") && !strings.HasPrefix(strings.ToLower(trimmedURL), "http://") {
		return fmt.Errorf("VALIDATION_FAILED: ACTION url must start with literal https:// or http:// scheme")
	}
	if parsed, err := url.Parse(trimmedURL); err == nil {
		if strings.Contains(parsed.Scheme, "{") {
			return fmt.Errorf("VALIDATION_FAILED: ACTION url scheme must not contain template expressions")
		}
	}
	if s.Action.TimeoutSeconds <= 0 {
		s.Action.TimeoutSeconds = DefaultActionTimeoutSec
	}
	if s.Action.TimeoutSeconds > MaxActionTimeoutSec {
		return fmt.Errorf("VALIDATION_FAILED: ACTION timeoutSeconds cannot exceed %d", MaxActionTimeoutSec)
	}
	if len(s.Action.ExpectedStatuses) == 0 {
		s.Action.ExpectedStatuses = []int{200, 201, 202, 204}
	}
	return nil
}

// SandboxProfile returns the mandatory two-tier isolation profile for this spec.
func (s Spec) SandboxProfile() secflowv1.SandboxProfile {
	if s.Category == CategoryAction {
		return secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL
	}
	return secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
}

// ParamsSchemaJSON builds the Draft 2020-12 JSON Schema consumed by SchemaParamsInspector.
func (s Spec) ParamsSchemaJSON() ([]byte, error) {
	props := make(map[string]any, len(s.Params))
	var required []string
	for _, p := range s.Params {
		prop := map[string]any{}
		if p.Description != "" {
			prop["description"] = p.Description
		}
		if p.Default != nil {
			prop["default"] = p.Default
		}
		switch p.Type {
		case "enum":
			prop["type"] = "string"
			prop["enum"] = p.Enum
		case "array":
			prop["type"] = "array"
			prop["items"] = map[string]any{"type": "string", "minLength": 1}
		default:
			prop["type"] = p.Type
			if p.Minimum != nil {
				prop["minimum"] = *p.Minimum
			}
			if p.Maximum != nil {
				prop["maximum"] = *p.Maximum
			}
		}
		props[p.Key] = prop
		if p.Required {
			required = append(required, p.Key)
		}
	}
	schema := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"additionalProperties": false,
		"properties":           props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return json.Marshal(schema)
}

// ToPluginManifest converts a validated Declarative Plugin Spec into a Pull SPI PluginManifest.
func (s Spec) ToPluginManifest() (*secflowv1.PluginManifest, error) {
	schemaBytes, err := s.ParamsSchemaJSON()
	if err != nil {
		return nil, fmt.Errorf("build params schema: %w", err)
	}
	var cat secflowv1.PluginCategory
	var caps []string
	switch s.Category {
	case CategoryAnalyzer:
		cat = secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER
		caps = []string{"analyzer", "declarative"}
	case CategoryLogic:
		cat = secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC
		caps = []string{"logic", "declarative"}
	case CategoryAction:
		cat = secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION
		caps = []string{"action", "declarative"}
	default:
		return nil, fmt.Errorf("unsupported category %q", s.Category)
	}
	outPorts := make([]*secflowv1.PortDefinition, 0, len(s.OutputPorts))
	for _, p := range s.OutputPorts {
		outPorts = append(outPorts, &secflowv1.PortDefinition{
			Id:          p.ID,
			Label:       p.Label,
			Description: p.Description,
		})
	}
	if len(outPorts) == 0 {
		outPorts = []*secflowv1.PortDefinition{{Id: "default", Label: "default"}}
	}
	return &secflowv1.PluginManifest{
		PluginId:           s.PluginID,
		Version:            s.Version,
		DisplayName:        s.DisplayName,
		Description:        s.Description,
		Category:           cat,
		Capabilities:       caps,
		ParamsJsonSchema:   schemaBytes,
		InputPorts:         []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:        outPorts,
		RuntimeLanguage:    "declarative",
		SandboxProfile:     s.SandboxProfile(),
		IsExternal:         true,
		RequiredSecretKeys: append([]string(nil), s.RequiredSecretKeys...),
		MaxConcurrency:     4,
	}, nil
}

// BumpPatchVersion increments the patch component of a semver string.
func BumpPatchVersion(ver string) string {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(ver))
	if len(m) != 4 {
		return "1.0.1"
	}
	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return "1.0.1"
	}
	return fmt.Sprintf("%s.%s.%d", m[1], m[2], patch+1)
}

// SanitizeSpecForExport normalizes a spec into secret-free indented JSON for export.
func SanitizeSpecForExport(spec Spec) ([]byte, error) {
	return json.MarshalIndent(spec, "", "  ")
}

// StarterBlueprints returns the 3 built-in starter blueprints (one per category).
func StarterBlueprints() []StarterBlueprint {
	return []StarterBlueprint{
		{
			ID:          "spring-yaml-config-check",
			Name:        "Spring / YAML Config Check",
			Description: "Проверяет открытые Actuator endpoints, хардкодные пароли в YAML/properties и наличие SECURITY.md.",
			Spec: Spec{
				PluginID:    "custom.scan.spring-config-guard",
				Version:     "1.0.0",
				DisplayName: "Spring Config Guard",
				Description: "Декларативная проверка конфигурации Spring Boot и политики репозитория.",
				Category:    CategoryAnalyzer,
				Params: []ParamField{
					{
						Key:         "severity",
						Type:        "enum",
						Enum:        []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"},
						Default:     "HIGH",
						Description: "Уровень критичности находок конфигурации.",
					},
					{
						Key:         "checkSecurityPolicy",
						Type:        "boolean",
						Default:     true,
						Description: "Проверять наличие SECURITY.md в корне репозитория.",
					},
				},
				Analyzer: &AnalyzerSpec{
					Rules: []AnalyzerRule{
						{
							RuleID:             "SPRING-ACTUATOR-WILDCARD",
							Category:           "SAST",
							Severity:           "{{ params.severity }}",
							Title:              "Spring Actuator exposed with wildcard (*)",
							Description:        "Wildcard exposure opens sensitive Actuator endpoints (/env, /heapdump, /beans).",
							Remediation:        "Restrict management.endpoints.web.exposure.include to health,info.",
							IncludeGlobs:       []string{"**/application*.yml", "**/application*.yaml", "**/application*.properties"},
							MatcherType:        MatcherConfigKey,
							ConfigKey:          "management.endpoints.web.exposure.include",
							ConfigValuePattern: `^\*$`,
							ExcludePatterns:    []string{`\$\{.*\}`},
						},
						{
							RuleID:       "REPO-SECURITY-MD",
							Category:     "SAST",
							Severity:     "LOW",
							Title:        "Missing SECURITY.md policy file",
							Description:  "Repository does not declare a vulnerability reporting policy.",
							Remediation:  "Add SECURITY.md at the repository root.",
							IncludeGlobs: []string{"SECURITY.md"},
							MatcherType:  MatcherFilePresence,
							PresenceMode: PresenceAbsent,
							EnabledParam: "checkSecurityPolicy",
						},
					},
				},
			},
		},
		{
			ID:          "weighted-risk-router",
			Name:        "Weighted Risk Router",
			Description: "Считает взвешенный риск-скор по Finding и маршрутизирует поток на порты BLOCK / REVIEW / OK.",
			Spec: Spec{
				PluginID:    "custom.logic.weighted-risk-router",
				Version:     "1.0.0",
				DisplayName: "Weighted Risk Router",
				Description: "Маршрутизация релиза по взвешенному риск-скору находок.",
				Category:    CategoryLogic,
				OutputPorts: []PortSpec{
					{ID: "BLOCK", Label: "BLOCK", Description: "Критический риск — блокировка релиза"},
					{ID: "REVIEW", Label: "REVIEW", Description: "Требуется ручное ревью AppSec"},
					{ID: "OK", Label: "OK", Description: "Допустимый уровень риска"},
				},
				Params: []ParamField{
					{Key: "blockThreshold", Type: "integer", Default: 15, Description: "Порог скора для порта BLOCK"},
					{Key: "reviewThreshold", Type: "integer", Default: 5, Description: "Порог скора для порта REVIEW"},
				},
				Logic: &LogicSpec{
					ComputedVars: []ComputedVar{
						{
							Name:           "riskScore",
							Kind:           ComputedWeightedScore,
							CriticalWeight: 10,
							HighWeight:     5,
							MediumWeight:   2,
							LowWeight:      1,
						},
					},
					Routes: []LogicRoute{
						{
							Name:       "Block release",
							MatchMode:  "ALL",
							OutputPort: "BLOCK",
							Gate:       "FAIL",
							SetVars:    map[string]string{"riskDecision": "BLOCK"},
							Conditions: []LogicCondition{
								{Field: "vars.riskScore", Operator: "gte", Value: "{{ params.blockThreshold }}"},
							},
						},
						{
							Name:       "Require AppSec review",
							MatchMode:  "ALL",
							OutputPort: "REVIEW",
							Gate:       "WARN",
							SetVars:    map[string]string{"riskDecision": "REVIEW"},
							Conditions: []LogicCondition{
								{Field: "vars.riskScore", Operator: "gte", Value: "{{ params.reviewThreshold }}"},
							},
						},
					},
					FallbackPort: "OK",
					FallbackGate: "PASS",
					FallbackVars: map[string]string{"riskDecision": "OK"},
				},
			},
		},
		{
			ID:          "webhook-issue-ticket",
			Name:        "Webhook / Issue Ticket",
			Description: "Отправляет структурированный JSON-запрос во внешний трекер с Secret Reference и сохраняет ключ тикета в Envelope.vars.",
			Spec: Spec{
				PluginID:           "custom.action.issue-ticket",
				Version:            "1.0.0",
				DisplayName:        "Create Issue Ticket",
				Description:        "Создание задачи во внешнем трекере по итогам сканирования.",
				Category:           CategoryAction,
				RequiredSecretKeys: []string{"apiToken"},
				EgressAllowlist:    []string{"tracker.example.com"},
				Params: []ParamField{
					{Key: "projectKey", Type: "string", Default: "APPSEC", Required: true, Description: "Ключ проекта в трекере"},
				},
				Action: &ActionSpec{
					Method: "POST",
					URL:    "https://tracker.example.com/api/v1/issues",
					Headers: map[string]string{
						"Authorization": "Bearer {{ secrets.apiToken }}",
						"Content-Type":  "application/json",
					},
					BodyTemplate:     `{"project":"{{ params.projectKey }}","summary":"SecFlow scan: {{ envelope.stats.total }} findings (CRITICAL: {{ envelope.stats.critical }})"}`,
					ExpectedStatuses: []int{200, 201, 202},
					TimeoutSeconds:   10,
					ExtractVars: map[string]string{
						"ticketKey": "key",
						"ticketUrl": "url",
					},
				},
			},
		},
	}
}

var secretKeySubstrings = []string{
	"secret",
	"token",
	"password",
	"passwd",
	"apikey",
	"api_key",
	"authorization",
	"credential",
	"privatekey",
	"private_key",
	"hmac",
}

func isSecretParamKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	if lk == "" {
		return false
	}
	for _, sub := range secretKeySubstrings {
		if strings.Contains(lk, sub) {
			return true
		}
	}
	return false
}

func stripSecretsRecursive(v any) any {
	switch m := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			if isSecretParamKey(k) {
				continue
			}
			out[k] = stripSecretsRecursive(val)
		}
		return out
	case []any:
		out := make([]any, len(m))
		for i, elem := range m {
			out[i] = stripSecretsRecursive(elem)
		}
		return out
	default:
		return v
	}
}

// SanitizeAndHashParams strips secret fields from Node params JSON and returns
// canonical JSON bytes plus a deterministic SHA-256 hex digest for Saved Node deduplication.
func SanitizeAndHashParams(raw []byte) ([]byte, string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		trimmed = "{}"
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: params JSON invalid: %w", err)
	}
	if _, ok := parsed.(map[string]any); !ok {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: params JSON must be an object")
	}
	cleaned := stripSecretsRecursive(parsed)
	canonical, err := canonicalJSON(cleaned)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize params: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(v any) ([]byte, error) {
	switch m := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			vb, err := canonicalJSON(m[k])
			if err != nil {
				return nil, err
			}
			b.Write(kb)
			b.WriteByte(':')
			b.Write(vb)
		}
		b.WriteByte('}')
		return []byte(b.String()), nil
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, elem := range m {
			if i > 0 {
				b.WriteByte(',')
			}
			vb, err := canonicalJSON(elem)
			if err != nil {
				return nil, err
			}
			b.Write(vb)
		}
		b.WriteByte(']')
		return []byte(b.String()), nil
	default:
		return json.Marshal(v)
	}
}
