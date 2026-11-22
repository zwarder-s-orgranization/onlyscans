package declarativeplugin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/declarativeplugin"
	"github.com/secflow/secflow/services/internal/engine"
)

func TestValidateSpec_RulesAndLimits(t *testing.T) {
	t.Parallel()

	validAnalyzer := declarativeplugin.Spec{
		PluginID:    "custom.scan.corp-headers",
		Version:     "1.0.0",
		DisplayName: "Corp Headers Check",
		Description: "Detects insecure header policies",
		Category:    declarativeplugin.CategoryAnalyzer,
		Params: []declarativeplugin.ParamField{
			{
				Key:         "severity",
				Type:        "enum",
				Enum:        []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"},
				Default:     "HIGH",
				Description: "Finding severity",
			},
		},
		Analyzer: &declarativeplugin.AnalyzerSpec{
			Rules: []declarativeplugin.AnalyzerRule{
				{
					RuleID:       "CORP-001",
					Category:     "SAST",
					Severity:     "{{ params.severity }}",
					Title:        "Wildcard CORS origin",
					Description:  "CORS wildcard allows any origin",
					Remediation:  "Specify explicit origins",
					IncludeGlobs: []string{"**/*.kt", "**/*.yml"},
					MatcherType:  declarativeplugin.MatcherRegex,
					Pattern:      `allowedOrigins\s*=\s*"\*"`,
				},
			},
		},
	}

	rawValid, err := json.Marshal(validAnalyzer)
	if err != nil {
		t.Fatalf("marshal valid spec: %v", err)
	}
	parsed, err := declarativeplugin.ValidateSpec(rawValid)
	if err != nil {
		t.Fatalf("ValidateSpec valid analyzer: %v", err)
	}
	manifest, err := parsed.ToPluginManifest()
	if err != nil {
		t.Fatalf("ToPluginManifest: %v", err)
	}
	if manifest.GetPluginId() != "custom.scan.corp-headers" {
		t.Fatalf("manifest plugin_id = %q", manifest.GetPluginId())
	}
	if manifest.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY {
		t.Fatalf("analyzer sandbox_profile = %v, want INTERNAL_ONLY", manifest.GetSandboxProfile())
	}
	if !manifest.GetIsExternal() {
		t.Fatal("expected IsExternal = true")
	}

	tests := []struct {
		name   string
		mutate func(s *declarativeplugin.Spec)
		want   string
	}{
		{
			name: "rejects builtin prefix collision",
			mutate: func(s *declarativeplugin.Spec) {
				s.PluginID = "scan.secrets"
			},
			want: "custom.scan.",
		},
		{
			name: "rejects prohibited scanner denylist in title",
			mutate: func(s *declarativeplugin.Spec) {
				s.Analyzer.Rules[0].Title = "Semgrep custom check"
			},
			want: "DENYLIST_BLOCKED",
		},
		{
			name: "rejects egress allowlist on analyzer",
			mutate: func(s *declarativeplugin.Spec) {
				s.EgressAllowlist = []string{"hooks.example.com"}
			},
			want: "INTERNAL_ONLY",
		},
		{
			name: "rejects secrets on analyzer",
			mutate: func(s *declarativeplugin.Spec) {
				s.RequiredSecretKeys = []string{"apiToken"}
			},
			want: "ACTION",
		},
		{
			name: "rejects nested object param type",
			mutate: func(s *declarativeplugin.Spec) {
				s.Params = append(s.Params, declarativeplugin.ParamField{Key: "nested", Type: "object"})
			},
			want: "unsupported parameter type",
		},
		{
			name: "rejects regex longer than 512 chars",
			mutate: func(s *declarativeplugin.Spec) {
				s.Analyzer.Rules[0].Pattern = strings.Repeat("a", 513)
			},
			want: "512",
		},
		{
			name: "rejects more than 50 analyzer rules",
			mutate: func(s *declarativeplugin.Spec) {
				s.Analyzer.Rules = make([]declarativeplugin.AnalyzerRule, 51)
				for i := range s.Analyzer.Rules {
					s.Analyzer.Rules[i] = declarativeplugin.AnalyzerRule{
						RuleID:      "R",
						Category:    "SAST",
						Severity:    "HIGH",
						Title:       "Rule",
						MatcherType: declarativeplugin.MatcherRegex,
						Pattern:     "foo",
					}
				}
			},
			want: "50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cp := validAnalyzer
			rulesCopy := append([]declarativeplugin.AnalyzerRule(nil), validAnalyzer.Analyzer.Rules...)
			cp.Analyzer = &declarativeplugin.AnalyzerSpec{Rules: rulesCopy}
			cp.Params = append([]declarativeplugin.ParamField(nil), validAnalyzer.Params...)
			tt.mutate(&cp)
			b, _ := json.Marshal(cp)
			_, vErr := declarativeplugin.ValidateSpec(b)
			if vErr == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(vErr.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", vErr.Error(), tt.want)
			}
		})
	}
}

func TestStarterBlueprints_AllValid(t *testing.T) {
	t.Parallel()
	bps := declarativeplugin.StarterBlueprints()
	if len(bps) != 3 {
		t.Fatalf("len(StarterBlueprints) = %d, want 3", len(bps))
	}
	seenCats := map[declarativeplugin.Category]bool{}
	for _, bp := range bps {
		raw, err := json.Marshal(bp.Spec)
		if err != nil {
			t.Fatalf("marshal blueprint %s: %v", bp.ID, err)
		}
		if _, err := declarativeplugin.ValidateSpec(raw); err != nil {
			t.Fatalf("blueprint %s invalid: %v", bp.ID, err)
		}
		seenCats[bp.Spec.Category] = true
	}
	for _, want := range []declarativeplugin.Category{
		declarativeplugin.CategoryAnalyzer,
		declarativeplugin.CategoryLogic,
		declarativeplugin.CategoryAction,
	} {
		if !seenCats[want] {
			t.Fatalf("missing starter blueprint for category %s", want)
		}
	}
}

func TestEvaluateAnalyzer_RegexConfigKeyAndFilePresence(t *testing.T) {
	t.Parallel()

	spec := declarativeplugin.Spec{
		PluginID:    "custom.scan.spring-suite",
		Version:     "1.0.0",
		DisplayName: "Spring Suite",
		Category:    declarativeplugin.CategoryAnalyzer,
		Params: []declarativeplugin.ParamField{
			{Key: "severity", Type: "enum", Enum: []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}, Default: "HIGH"},
		},
		Analyzer: &declarativeplugin.AnalyzerSpec{
			Rules: []declarativeplugin.AnalyzerRule{
				{
					RuleID:          "SEC-TOK-1",
					Category:        "SECRET",
					Severity:        "CRITICAL",
					Title:           "Hardcoded internal API token",
					Description:     "Plaintext corp token found",
					Remediation:     "Move token to SecretStore / env",
					IncludeGlobs:    []string{"**/*.kt"},
					MatcherType:     declarativeplugin.MatcherRegex,
					Pattern:         `corp_live_[A-Za-z0-9]{12,}`,
					ExcludePatterns: []string{`System\.getenv`, `example_placeholder`},
				},
				{
					RuleID:             "CFG-ACTUATOR",
					Category:           "SAST",
					Severity:           "{{ params.severity }}",
					Title:              "Exposed Actuator wildcard",
					Description:        "Actuator exposes all endpoints",
					Remediation:        "Limit to health,info",
					IncludeGlobs:       []string{"**/application*.yml", "**/application*.properties", "**/config.json"},
					MatcherType:        declarativeplugin.MatcherConfigKey,
					ConfigKey:          "management.endpoints.web.exposure.include",
					ConfigValuePattern: `^\*$`,
					ExcludePatterns:    []string{`\$\{.*\}`},
				},
				{
					RuleID:       "POLICY-SECURITY-MD",
					Category:     "SAST",
					Severity:     "LOW",
					Title:        "Missing SECURITY.md",
					Description:  "Repository must contain SECURITY.md",
					Remediation:  "Add SECURITY.md at repo root",
					IncludeGlobs: []string{"SECURITY.md"},
					MatcherType:  declarativeplugin.MatcherFilePresence,
					PresenceMode: declarativeplugin.PresenceAbsent,
				},
			},
		},
	}

	files := []declarativeplugin.VirtualFile{
		{
			Path: "src/main/kotlin/Client.kt",
			Content: strings.Join([]string{
				`val safe = System.getenv("CORP_TOKEN") // corp_live_1234567890abcd`,
				`val bad = "corp_live_ABCDEF1234567890"`,
			}, "\n"),
		},
		{
			Path: "src/main/resources/application.yml",
			Content: strings.Join([]string{
				"management:",
				"  endpoints:",
				"    web:",
				"      exposure:",
				"        include: \"*\"",
			}, "\n"),
		},
		{
			Path:    "src/main/resources/application-safe.properties",
			Content: "management.endpoints.web.exposure.include=${ACTUATOR_INCLUDE}\n",
		},
		{
			Path:    "src/main/resources/config.json",
			Content: `{"management":{"endpoints":{"web":{"exposure":{"include":"*"}}}}}`,
		},
	}

	findings, err := declarativeplugin.EvaluateAnalyzer(
		context.Background(),
		spec,
		map[string]any{"severity": "HIGH"},
		files,
		"node_scan_1",
	)
	if err != nil {
		t.Fatalf("EvaluateAnalyzer: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4: %+v", len(findings), findings)
	}

	var foundSecret, foundYAML, foundJSON, foundAbsent bool
	for _, f := range findings {
		switch {
		case f.GetFindingClass() == "SEC-TOK-1" && f.GetPath() == "src/main/kotlin/Client.kt":
			foundSecret = true
			if f.GetLine() != 2 {
				t.Fatalf("secret line = %d, want 2 (line 1 is Control)", f.GetLine())
			}
			if strings.Contains(f.GetMaskedSnippet(), "corp_live_ABCDEF1234567890") {
				t.Fatalf("secret snippet was not masked: %q", f.GetMaskedSnippet())
			}
		case f.GetFindingClass() == "CFG-ACTUATOR" && f.GetPath() == "src/main/resources/application.yml":
			foundYAML = true
			if f.GetSeverity() != secflowv1.Severity_SEVERITY_HIGH {
				t.Fatalf("yaml severity = %v, want HIGH", f.GetSeverity())
			}
		case f.GetFindingClass() == "CFG-ACTUATOR" && f.GetPath() == "src/main/resources/config.json":
			foundJSON = true
		case f.GetFindingClass() == "POLICY-SECURITY-MD":
			foundAbsent = true
		}
	}
	if !foundSecret || !foundYAML || !foundJSON || !foundAbsent {
		t.Fatalf("missing expected findings: secret=%v yaml=%v json=%v absent=%v", foundSecret, foundYAML, foundJSON, foundAbsent)
	}
}

func TestEvaluateLogic_ComputedVarsAndRouting(t *testing.T) {
	t.Parallel()

	spec := declarativeplugin.Spec{
		PluginID:    "custom.logic.risk-router",
		Version:     "1.0.0",
		DisplayName: "Custom Risk Router",
		Category:    declarativeplugin.CategoryLogic,
		OutputPorts: []declarativeplugin.PortSpec{
			{ID: "BLOCK", Label: "BLOCK"},
			{ID: "REVIEW", Label: "REVIEW"},
			{ID: "OK", Label: "OK"},
		},
		Params: []declarativeplugin.ParamField{
			{Key: "blockThreshold", Type: "integer", Default: 15},
			{Key: "reviewThreshold", Type: "integer", Default: 5},
		},
		Logic: &declarativeplugin.LogicSpec{
			ComputedVars: []declarativeplugin.ComputedVar{
				{
					Name:           "riskScore",
					Kind:           declarativeplugin.ComputedWeightedScore,
					CriticalWeight: 10,
					HighWeight:     5,
					MediumWeight:   2,
					LowWeight:      1,
				},
			},
			Routes: []declarativeplugin.LogicRoute{
				{
					Name:       "Block high risk",
					MatchMode:  "ALL",
					OutputPort: "BLOCK",
					Gate:       "FAIL",
					SetVars:    map[string]string{"decision": "block"},
					Conditions: []declarativeplugin.LogicCondition{
						{Field: "vars.riskScore", Operator: "gte", Value: "{{ params.blockThreshold }}"},
					},
				},
				{
					Name:       "Review medium risk",
					MatchMode:  "ALL",
					OutputPort: "REVIEW",
					Gate:       "WARN",
					SetVars:    map[string]string{"decision": "review"},
					Conditions: []declarativeplugin.LogicCondition{
						{Field: "vars.riskScore", Operator: "gte", Value: "{{ params.reviewThreshold }}"},
					},
				},
			},
			FallbackPort: "OK",
			FallbackGate: "PASS",
			FallbackVars: map[string]string{"decision": "ok"},
		},
	}

	env := engine.Envelope{
		Findings: []engine.Finding{
			{ID: "f1", Category: "SECRET", Severity: "CRITICAL"},
			{ID: "f2", Category: "SAST", Severity: "HIGH"},
			{ID: "f3", Category: "SCA", Severity: "LOW"},
		},
	}.Normalize()

	res, err := declarativeplugin.EvaluateLogic(spec, map[string]any{"blockThreshold": 15, "reviewThreshold": 5}, env)
	if err != nil {
		t.Fatalf("EvaluateLogic: %v", err)
	}
	if len(res.ActivePorts) != 1 || res.ActivePorts[0] != "BLOCK" {
		t.Fatalf("active ports = %v, want [BLOCK]", res.ActivePorts)
	}
	if res.Gate != "FAIL" {
		t.Fatalf("gate = %q, want FAIL", res.Gate)
	}
	if res.Vars["riskScore"] != "16" || res.Vars["decision"] != "block" {
		t.Fatalf("vars = %+v", res.Vars)
	}
}

func TestAction_DryRunAndExecuteWithRedirectBlock(t *testing.T) {
	t.Parallel()

	var hitCount int
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount++
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"issue":{"key":"SEC-42","url":"https://tracker.example/SEC-42"}}`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	spec := declarativeplugin.Spec{
		PluginID:           "custom.action.ticket-create",
		Version:            "1.0.0",
		DisplayName:        "Create Security Ticket",
		Category:           declarativeplugin.CategoryAction,
		RequiredSecretKeys: []string{"apiToken"},
		EgressAllowlist:    []string{host},
		Action: &declarativeplugin.ActionSpec{
			Method:           "POST",
			URL:              srv.URL + "/issues",
			Headers:          map[string]string{"Authorization": "Bearer {{ secrets.apiToken }}", "Content-Type": "application/json"},
			BodyTemplate:     `{"summary":"Findings: {{ envelope.stats.total }}"}`,
			ExpectedStatuses: []int{200, 201},
			TimeoutSeconds:   10,
			ExtractVars:      map[string]string{"ticketKey": "issue.key", "ticketUrl": "issue.url"},
		},
	}

	env := engine.Envelope{
		Findings: []engine.Finding{{ID: "f1", Severity: "HIGH", Category: "SAST"}},
	}.Normalize()

	// 1. Offline DryRun must NEVER hit the server and must mask secrets.
	dry, err := declarativeplugin.DryRunAction(context.Background(), spec, map[string]any{}, env, true)
	if err != nil {
		t.Fatalf("DryRunAction: %v", err)
	}
	if hitCount != 0 {
		t.Fatalf("DryRunAction hit network %d times, want 0", hitCount)
	}
	if !dry.Allowed {
		t.Fatalf("expected DryRun Allowed=true, got reason=%q", dry.PolicyReason)
	}
	if !strings.Contains(dry.Headers["Authorization"], "***") {
		t.Fatalf("expected masked Authorization header, got %q", dry.Headers["Authorization"])
	}

	// 2. Live execution injects secret and extracts response vars.
	execRes, err := declarativeplugin.ExecuteAction(
		context.Background(),
		spec,
		map[string]any{},
		env,
		map[string]string{"apiToken": "super-secret-token"},
		true,
	)
	if err != nil {
		t.Fatalf("ExecuteAction: %v", err)
	}
	if gotAuth != "Bearer super-secret-token" {
		t.Fatalf("server got Authorization=%q", gotAuth)
	}
	if execRes.ExtractedVars["ticketKey"] != "SEC-42" || execRes.ExtractedVars["ticketUrl"] != "https://tracker.example/SEC-42" {
		t.Fatalf("extracted vars = %+v", execRes.ExtractedVars)
	}

	// 3. Redirects MUST be rejected.
	redirSpec := spec
	redirAction := *spec.Action
	redirAction.URL = srv.URL + "/redirect"
	redirSpec.Action = &redirAction
	if _, err := declarativeplugin.ExecuteAction(
		context.Background(),
		redirSpec,
		map[string]any{},
		env,
		map[string]string{"apiToken": "super-secret-token"},
		true,
	); err == nil {
		t.Fatal("expected ExecuteAction to reject HTTP redirect")
	}
}

func TestSavedNodeSanitizationAndCanonicalHash(t *testing.T) {
	t.Parallel()

	p1 := []byte(`{"severity":"HIGH","apiToken":"secret-1","nested":{"b":2,"a":1},"secretRef":"sec-123"}`)
	p2 := []byte(`{  "nested": {"a": 1, "b": 2}, "severity": "HIGH" }`)

	clean1, hash1, err := declarativeplugin.SanitizeAndHashParams(p1)
	if err != nil {
		t.Fatalf("SanitizeAndHashParams(p1): %v", err)
	}
	_, hash2, err := declarativeplugin.SanitizeAndHashParams(p2)
	if err != nil {
		t.Fatalf("SanitizeAndHashParams(p2): %v", err)
	}
	if strings.Contains(string(clean1), "secret-1") || strings.Contains(string(clean1), "sec-123") {
		t.Fatalf("secrets leaked in sanitized params: %s", string(clean1))
	}
	if hash1 != hash2 {
		t.Fatalf("canonical hashes differ: %q vs %q", hash1, hash2)
	}
}
