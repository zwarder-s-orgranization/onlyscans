package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectsCycleAndMissingSource(t *testing.T) {
	t.Parallel()
	g := Graph{
		Nodes: []Node{
			{ID: "t", PluginID: "trigger.manual"},
			{ID: "a", PluginID: "scan.secrets"},
			{ID: "b", PluginID: "logic.filter"},
		},
		Edges: []Edge{
			{ID: "e1", Source: "t", SourceHandle: "default", Target: "a", TargetHandle: "default"},
			{ID: "e2", Source: "a", SourceHandle: "default", Target: "b", TargetHandle: "default"},
			{ID: "e3", Source: "b", SourceHandle: "default", Target: "a", TargetHandle: "default"},
		},
	}
	issues := Validate(g)
	codes := map[string]bool{}
	for _, issue := range issues {
		codes[issue.Code] = true
	}
	if !codes[CodeCycle] {
		t.Fatal("expected cycle")
	}
	if !codes[CodeMissingSource] {
		t.Fatal("expected missing source")
	}
}

func TestSwitchPortsAndFilterDoesNotChangeAuthoritative(t *testing.T) {
	t.Parallel()
	g := Graph{
		Nodes: []Node{
			{ID: "t", PluginID: "trigger.manual"},
			{ID: "s", PluginID: "source.upload"},
			{ID: "scan", PluginID: "scan.secrets"},
			{ID: "sw", PluginID: "logic.switch", Params: map[string]any{"mode": "maxSeverity"}},
			{ID: "filt", PluginID: "logic.filter", Params: map[string]any{"minSeverity": "CRITICAL"}},
		},
		Edges: []Edge{
			{ID: "1", Source: "t", SourceHandle: "default", Target: "s", TargetHandle: "default"},
			{ID: "2", Source: "s", SourceHandle: "default", Target: "scan", TargetHandle: "default"},
			{ID: "3", Source: "scan", SourceHandle: "default", Target: "sw", TargetHandle: "default"},
			{ID: "4", Source: "sw", SourceHandle: "HIGH", Target: "filt", TargetHandle: "default"},
		},
	}
	if issues := Validate(g); len(issues) != 0 {
		t.Fatalf("validate: %+v", issues)
	}
	handlers := map[string]Handler{
		"scan.secrets": func(n Node, in Envelope) Result {
			findings := []Finding{
				{ID: "F-1", Category: "SECRET", Class: "password", Severity: "HIGH", Path: "a.kt"},
				{ID: "F-2", Category: "SECRET", Class: "api-key", Severity: "LOW", Path: "b.kt"},
			}
			env := in
			env.Findings = findings
			env.MaxSev = "HIGH"
			return Result{Findings: findings, Envelope: env, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
		},
	}
	auth, outs, skipped, err := Run(g, handlers, Envelope{})
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != 2 {
		t.Fatalf("authoritative findings = %d", len(auth))
	}
	if len(outs["filt"].Output.Findings) != 0 {
		t.Fatalf("filter should drop LOW and keep only CRITICAL, got %+v", outs["filt"].Output.Findings)
	}
	if !skipped["filt"] && outs["sw"].Output.MaxSev != "HIGH" {
		t.Fatal("switch should have routed HIGH")
	}
	if skipped["filt"] {
		t.Fatal("HIGH branch should not be skipped")
	}
}

func TestCategorySwitchRejectsMediumLowHandle(t *testing.T) {
	t.Parallel()
	g := Graph{
		Nodes: []Node{
			{ID: "t", PluginID: "trigger.manual"},
			{ID: "sw", PluginID: "logic.switch", Params: map[string]any{"mode": "category"}},
		},
		Edges: []Edge{{ID: "e", Source: "sw", SourceHandle: "MEDIUM_LOW", Target: "t", TargetHandle: "default"}},
	}
	issues := Validate(g)
	found := false
	for _, issue := range issues {
		if issue.Code == CodeBadPort {
			found = true
		}
	}
	if !found {
		t.Fatal("expected invalid port")
	}
}

func TestRerunUsesCachedInputAndRunsDownstream(t *testing.T) {
	t.Parallel()
	g := Graph{
		Nodes: []Node{
			{ID: "t", PluginID: "trigger.manual"},
			{ID: "s", PluginID: "source.upload"},
			{ID: "scan", PluginID: "scan.secrets"},
			{ID: "rx", PluginID: "logic.regex", Params: map[string]any{"field": "path", "pattern": `^src/`, "splitEnvelope": true}},
			{ID: "mail", PluginID: "notify.smtp", Secrets: map[string]string{"smtpPassword": "sec-1"}, Params: map[string]any{}},
			{ID: "hook", PluginID: "notify.webhook", Params: map[string]any{"url": "https://example.com"}},
		},
		Edges: []Edge{
			{ID: "e1", Source: "t", SourceHandle: "default", Target: "s", TargetHandle: "default"},
			{ID: "e2", Source: "s", SourceHandle: "default", Target: "scan", TargetHandle: "default"},
			{ID: "e3", Source: "scan", SourceHandle: "default", Target: "rx", TargetHandle: "default"},
			{ID: "e4", Source: "rx", SourceHandle: "match", Target: "mail", TargetHandle: "default"},
			{ID: "e5", Source: "rx", SourceHandle: "nomatch", Target: "hook", TargetHandle: "default"},
		},
	}
	cached := Envelope{
		Findings: []Finding{
			{ID: "F-1", Category: "SAST", Class: "sql-injection", Severity: "HIGH", Path: "src/Main.kt"},
			{ID: "F-2", Category: "SECRET", Class: "password", Severity: "LOW", Path: "docs/README.md"},
		},
	}
	scanCalls := 0
	var mailFindings, hookFindings []Finding
	handlers := map[string]Handler{
		"scan.secrets": func(n Node, in Envelope) Result {
			scanCalls++
			return Result{Envelope: in, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
		},
		"notify.smtp": func(n Node, in Envelope) Result {
			mailFindings = append([]Finding{}, in.Findings...)
			return Result{Envelope: in, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
		},
		"notify.webhook": func(n Node, in Envelope) Result {
			hookFindings = append([]Finding{}, in.Findings...)
			return Result{Envelope: in, ActivePorts: []string{"default"}, Status: "SUCCEEDED"}
		},
	}
	traces, skipped, err := Rerun(g, "rx", cached, handlers)
	if err != nil {
		t.Fatal(err)
	}
	if scanCalls != 0 {
		t.Fatalf("upstream scan node must not be re-executed, got %d calls", scanCalls)
	}
	if len(traces) != 3 {
		t.Fatalf("expected 3 re-executed nodes (rx, mail, hook), got %d (%v)", len(traces), traces)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped downstream nodes, got %v", skipped)
	}
	if len(mailFindings) != 1 || mailFindings[0].Path != "src/Main.kt" {
		t.Fatalf("match branch findings = %+v, want src/Main.kt only", mailFindings)
	}
	if len(hookFindings) != 1 || hookFindings[0].Path != "docs/README.md" {
		t.Fatalf("nomatch branch findings = %+v, want docs/README.md only", hookFindings)
	}
}

func TestValidateRequiresSecretBindings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		graph     Graph
		wantIssue bool
	}{
		{
			name: "telegram bound botToken passes",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "tg", PluginID: "notify.telegram", Params: map[string]any{"chatId": "123"}, Secrets: map[string]string{"botToken": "sec_tg_1"}},
				},
				Edges: []Edge{{ID: "e1", Source: "t", SourceHandle: "default", Target: "tg", TargetHandle: "default"}},
			},
			wantIssue: false,
		},
		{
			name: "telegram inline botToken in params is rejected as missing secret binding",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "tg", PluginID: "notify.telegram", Params: map[string]any{"chatId": "123", "botToken": "123:abc"}},
				},
				Edges: []Edge{{ID: "e1", Source: "t", SourceHandle: "default", Target: "tg", TargetHandle: "default"}},
			},
			wantIssue: true,
		},
		{
			name: "webhook bound webhookSecret passes",
			graph: Graph{
				Nodes: []Node{
					{ID: "w", PluginID: "trigger.webhook", Params: map[string]any{"gitProvider": "GITHUB"}, Secrets: map[string]string{"webhookSecret": "sec_wh_1"}},
				},
			},
			wantIssue: false,
		},
		{
			name: "webhook inline webhookSecret without binding fails",
			graph: Graph{
				Nodes: []Node{
					{ID: "w", PluginID: "trigger.webhook", Params: map[string]any{"gitProvider": "GITHUB", "webhookSecret": "whsec_123"}},
				},
			},
			wantIssue: true,
		},
		{
			name: "smtp missing binding fails",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "mail", PluginID: "notify.smtp", Params: map[string]any{"to": []string{"ops@example.com"}, "subject": "Alert"}},
				},
				Edges: []Edge{{ID: "e1", Source: "t", SourceHandle: "default", Target: "mail", TargetHandle: "default"}},
			},
			wantIssue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			issues := Validate(tt.graph)
			hasMissing := false
			for _, issue := range issues {
				if issue.Code == CodeMissingSecret {
					hasMissing = true
				}
			}
			if hasMissing != tt.wantIssue {
				t.Fatalf("Validate() missing secret = %v, want %v (issues: %+v)", hasMissing, tt.wantIssue, issues)
			}
		})
	}
}

func TestEnvelopeCamelCaseSchemaCompliance(t *testing.T) {
	t.Parallel()
	pr := 42
	env := Envelope{
		Trigger: TriggerInfo{
			Type:        "WEBHOOK",
			RepoURL:     "https://github.com/org/repair-desk",
			Branch:      "main",
			CommitSHA:   "abc123",
			PRNumber:    &pr,
			GitProvider: "GITHUB",
		},
		SourceRef: &SourceRefInfo{
			SourceID: "src_1",
			Bucket:   "secflow-sources",
			Key:      "deadbeef.tar.gz",
			SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			RepoName: "repair-desk",
		},
		Findings: []Finding{
			{
				ID:              "F-001",
				SourceNodeID:    "scan1",
				PluginID:        "scan.secrets",
				Category:        "SECRET",
				Path:            "src/App.kt",
				Class:           "password",
				Line:            10,
				EndLine:         12,
				Severity:        "CRITICAL",
				Description:     "Hardcoded password",
				Remediation:     "Use secret store",
				IsNewVsBaseline: true,
			},
			{
				ID:           "F-002",
				SourceNodeID: "scan2",
				PluginID:     "scan.sca",
				Category:     "SCA",
				Path:         "build.gradle.kts",
				Group:        "org.apache.commons",
				Artifact:     "commons-text",
				Version:      "1.9",
				AdvisoryID:   "CVE-2022-42889",
				Severity:     "HIGH",
			},
		},
		Gate: &GateInfo{
			Status:      "FAIL",
			Reason:      "secret finding detected",
			NodeID:      "gate1",
			EvaluatedAt: "2026-11-21T00:00:00Z",
		},
		Vars:                 map[string]string{"runId": "run_1"},
		BaselineFingerprints: map[string]bool{"old": true},
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal envelope map: %v", err)
	}

	// Verify top-level keys match envelope.schema.json (additionalProperties: false).
	schemaRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "contracts", "schemas", "envelope.schema.json"))
	if err != nil {
		t.Fatalf("read envelope.schema.json: %v", err)
	}
	var schema struct {
		Required   []string               `json:"required"`
		Properties map[string]interface{} `json:"properties"`
	}
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		t.Fatalf("parse envelope.schema.json: %v", err)
	}
	for _, reqKey := range schema.Required {
		if _, ok := doc[reqKey]; !ok {
			t.Errorf("missing required top-level key %q in %s", reqKey, string(raw))
		}
	}
	for k := range doc {
		if _, allowed := schema.Properties[k]; !allowed {
			t.Errorf("unexpected top-level key %q violates envelope.schema.json additionalProperties:false", k)
		}
	}

	stats, ok := doc["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stats missing or wrong type: %T", doc["stats"])
	}
	if stats["total"] != float64(2) || stats["critical"] != float64(1) || stats["high"] != float64(1) ||
		stats["secretCount"] != float64(1) || stats["scaCount"] != float64(1) || stats["newCount"] != float64(1) ||
		stats["maxSeverity"] != "CRITICAL" {
		t.Fatalf("unexpected stats: %#v", stats)
	}

	// Round-trip unmarshal restores Stats.NewVsBaselineCount and MaxSev.
	var decoded Envelope
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if decoded.Stats.NewVsBaselineCount != 1 || decoded.MaxSev != "CRITICAL" || len(decoded.Findings) != 2 {
		t.Fatalf("decoded envelope mismatch: stats=%+v maxSev=%q findings=%d", decoded.Stats, decoded.MaxSev, len(decoded.Findings))
	}
}

func TestLogicIfVisualRules(t *testing.T) {
	t.Parallel()
	baseEnv := Envelope{
		Trigger: TriggerInfo{Type: "WEBHOOK", Branch: "release/1.0", EventType: "pull_request"},
		Findings: []Finding{
			{ID: "F-1", Category: "SECRET", Severity: "CRITICAL", Path: "a.kt", IsNewVsBaseline: true},
			{ID: "F-2", Category: "SAST", Severity: "HIGH", Path: "b.kt", IsNewVsBaseline: true},
			{ID: "F-3", Category: "SCA", Severity: "MEDIUM", Path: "build.gradle.kts"},
		},
		Gate: &GateInfo{Status: "FAIL", Reason: "secrets", NodeID: "g1"},
	}

	tests := []struct {
		name     string
		params   map[string]any
		wantPort string
	}{
		{
			name: "AND all true with canonical stats.* and short names",
			params: map[string]any{
				"combinator": "AND",
				"conditions": []map[string]any{
					{"field": "stats.total", "operator": "gte", "value": 3},
					{"field": "critical", "operator": "eq", "value": 1},
					{"field": "newVsBaselineCount", "operator": "gt", "value": 1},
					{"field": "maxSeverity", "operator": "gte", "value": "HIGH"},
					{"field": "branch", "operator": "contains", "value": "release/"},
					{"field": "eventType", "operator": "in", "value": []any{"push", "pull_request"}},
				},
			},
			wantPort: "true",
		},
		{
			name: "AND fails when one condition is false",
			params: map[string]any{
				"combinator": "AND",
				"conditions": []map[string]any{
					{"field": "secretCount", "operator": "eq", "value": 1},
					{"field": "scaCount", "operator": "gt", "value": 2},
				},
			},
			wantPort: "false",
		},
		{
			name: "OR succeeds when second condition matches",
			params: map[string]any{
				"combinator": "OR",
				"conditions": []map[string]any{
					{"field": "low", "operator": "gt", "value": 5},
					{"field": "gate.status", "operator": "eq", "value": "FAIL"},
				},
			},
			wantPort: "true",
		},
		{
			name: "OR false when all fail",
			params: map[string]any{
				"combinator": "OR",
				"conditions": []map[string]any{
					{"field": "sastCount", "operator": "lt", "value": 1},
					{"field": "trigger.branch", "operator": "eq", "value": "main"},
				},
			},
			wantPort: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := Step(Node{ID: "if1", PluginID: "logic.if", Params: tt.params}, baseEnv, nil)
			if res.Status != "SUCCEEDED" || len(res.ActivePorts) != 1 || res.ActivePorts[0] != tt.wantPort {
				t.Fatalf("Step(logic.if) = status:%s ports:%v, want %q", res.Status, res.ActivePorts, tt.wantPort)
			}
		})
	}
}

func TestLogicCompareBaselineDiff(t *testing.T) {
	t.Parallel()
	existing := Finding{Category: "SAST", Path: "src/Old.kt", Class: "sql-injection", Severity: "HIGH"}
	newLow := Finding{Category: "SAST", Path: "src/NewLow.kt", Class: "tls-verification", Severity: "LOW"}
	newCrit := Finding{Category: "SECRET", Path: "src/NewSecret.kt", Class: "password", Severity: "CRITICAL"}

	tests := []struct {
		name      string
		params    map[string]any
		findings  []Finding
		baseline  map[string]bool
		wantPort  string
		wantNewCt int
	}{
		{
			name:      "new finding detected routes true and tags findings",
			params:    map[string]any{"mode": "baselineDiff", "minNewFindingsForTrue": 1},
			findings:  []Finding{existing, newCrit},
			baseline:  map[string]bool{FindingFingerprint(existing): true},
			wantPort:  "true",
			wantNewCt: 1,
		},
		{
			name:      "all findings in baseline routes false",
			params:    map[string]any{"mode": "baselineDiff", "minNewFindingsForTrue": 1},
			findings:  []Finding{existing},
			baseline:  map[string]bool{FindingFingerprint(existing): true},
			wantPort:  "false",
			wantNewCt: 0,
		},
		{
			name:      "minSeverity filters which new findings trigger true",
			params:    map[string]any{"mode": "baselineDiff", "minNewFindingsForTrue": 1, "minSeverity": "HIGH"},
			findings:  []Finding{existing, newLow},
			baseline:  map[string]bool{FindingFingerprint(existing): true},
			wantPort:  "false",
			wantNewCt: 1,
		},
		{
			name:      "threshold mode counts matching findings",
			params:    map[string]any{"mode": "threshold", "minNewFindingsForTrue": 2, "minSeverity": "HIGH"},
			findings:  []Finding{existing, newCrit, newLow},
			baseline:  nil,
			wantPort:  "true",
			wantNewCt: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := Envelope{Findings: tt.findings, BaselineFingerprints: tt.baseline}
			res := Step(Node{ID: "cmp", PluginID: "logic.compare", Params: tt.params}, env, nil)
			if res.Status != "SUCCEEDED" || len(res.ActivePorts) != 1 || res.ActivePorts[0] != tt.wantPort {
				t.Fatalf("ports = %v, want %q", res.ActivePorts, tt.wantPort)
			}
			if res.Envelope.Stats.NewCount != tt.wantNewCt || res.Envelope.Stats.NewVsBaselineCount != tt.wantNewCt {
				t.Fatalf("newCount = %d/%d, want %d", res.Envelope.Stats.NewCount, res.Envelope.Stats.NewVsBaselineCount, tt.wantNewCt)
			}
		})
	}
}

func TestLogicFilterMultiCriteria(t *testing.T) {
	t.Parallel()
	input := []Finding{
		{ID: "F-1", Category: "SECRET", Class: "password", Severity: "CRITICAL", Path: "src/auth/Login.kt", IsNewVsBaseline: true},
		{ID: "F-2", Category: "SAST", Class: "sql-injection", Severity: "HIGH", Path: "src/repo/Ticket.kt", IsNewVsBaseline: true},
		{ID: "F-3", Category: "SAST", Class: "tls-verification", Severity: "MEDIUM", Path: "src/net/Client.kt", IsNewVsBaseline: false},
		{ID: "F-4", Category: "SCA", Class: "", Severity: "LOW", Path: "build.gradle.kts", IsNewVsBaseline: true},
	}
	res := Step(Node{
		ID:       "flt",
		PluginID: "logic.filter",
		Params: map[string]any{
			"categories":        []any{"SECRET", "SAST"},
			"minSeverity":       "HIGH",
			"maxSeverity":       "HIGH",
			"findingClasses":    []any{"sql-injection"},
			"pathPrefixes":      []any{"src/repo/"},
			"onlyNewVsBaseline": true,
		},
	}, Envelope{Findings: input}, nil)

	if res.Status != "SUCCEEDED" {
		t.Fatalf("status = %s", res.Status)
	}
	if len(res.Envelope.Findings) != 1 || res.Envelope.Findings[0].ID != "F-2" {
		t.Fatalf("filtered findings = %+v, want only F-2", res.Envelope.Findings)
	}
	if res.Envelope.Stats.Total != 1 || res.Envelope.Stats.MaxSeverity != "HIGH" {
		t.Fatalf("stats = %+v", res.Envelope.Stats)
	}
	// Input slice must remain untouched.
	if len(input) != 4 {
		t.Fatalf("input mutated")
	}
}

func TestLogicRegexFieldsAndSplitEnvelope(t *testing.T) {
	t.Parallel()
	findings := []Finding{
		{ID: "F-1", Category: "SCA", Path: "build.gradle.kts", Group: "org.apache.logging", Artifact: "log4j-core", AdvisoryID: "CVE-2021-44228", Description: "Log4Shell JNDI", Severity: "CRITICAL"},
		{ID: "F-2", Category: "SAST", Path: "src/Main.kt", Class: "sql-injection", Description: "Raw SQL query", Severity: "HIGH"},
	}

	tests := []struct {
		name        string
		params      map[string]any
		wantMatch   int
		wantNoMatch int
		wantPorts   []string
	}{
		{
			name:        "splitEnvelope routes matched to match and unmatched to nomatch",
			params:      map[string]any{"field": "advisoryId", "pattern": `^CVE-2021-`, "splitEnvelope": true},
			wantMatch:   1,
			wantNoMatch: 1,
			wantPorts:   []string{"match", "nomatch"},
		},
		{
			name:        "caseInsensitive any field",
			params:      map[string]any{"field": "any", "pattern": "log4shell", "caseInsensitive": true, "splitEnvelope": true},
			wantMatch:   1,
			wantNoMatch: 1,
			wantPorts:   []string{"match", "nomatch"},
		},
		{
			name:        "negate inverts match set",
			params:      map[string]any{"field": "group", "pattern": `apache`, "negate": true, "splitEnvelope": true},
			wantMatch:   1,
			wantNoMatch: 1,
			wantPorts:   []string{"match", "nomatch"},
		},
		{
			name:        "artifact match all findings",
			params:      map[string]any{"field": "description", "pattern": `(?i)jndi|sql`, "splitEnvelope": true},
			wantMatch:   2,
			wantNoMatch: 0,
			wantPorts:   []string{"match"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := Step(Node{ID: "rx", PluginID: "logic.regex", Params: tt.params}, Envelope{Findings: findings}, nil)
			if res.Status != "SUCCEEDED" {
				t.Fatalf("status=%s err=%s", res.Status, res.Err)
			}
			if len(res.ActivePorts) != len(tt.wantPorts) {
				t.Fatalf("activePorts = %v, want %v", res.ActivePorts, tt.wantPorts)
			}
			if tt.wantMatch > 0 && len(res.PortEnvelopes["match"].Findings) != tt.wantMatch {
				t.Fatalf("match findings = %d, want %d", len(res.PortEnvelopes["match"].Findings), tt.wantMatch)
			}
			if tt.wantNoMatch > 0 && len(res.PortEnvelopes["nomatch"].Findings) != tt.wantNoMatch {
				t.Fatalf("nomatch findings = %d, want %d", len(res.PortEnvelopes["nomatch"].Findings), tt.wantNoMatch)
			}
		})
	}
}

func TestPolicyGatePassWarnFail(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		params     map[string]any
		findings   []Finding
		wantStatus string
	}{
		{
			name:       "PASS when no findings",
			params:     map[string]any{"failOnSeverity": "HIGH", "warnOnSeverity": "MEDIUM", "failOnAnySecret": true},
			findings:   nil,
			wantStatus: "PASS",
		},
		{
			name:   "WARN when only MEDIUM SAST and failOnSeverity HIGH",
			params: map[string]any{"failOnSeverity": "HIGH", "warnOnSeverity": "MEDIUM", "failOnAnySecret": true},
			findings: []Finding{
				{ID: "F-1", Category: "SAST", Severity: "MEDIUM", Path: "a.kt"},
			},
			wantStatus: "WARN",
		},
		{
			name:   "FAIL on any SECRET even if LOW",
			params: map[string]any{"failOnSeverity": "CRITICAL", "warnOnSeverity": "HIGH", "failOnAnySecret": true},
			findings: []Finding{
				{ID: "F-1", Category: "SECRET", Severity: "LOW", Path: "application.yml"},
			},
			wantStatus: "FAIL",
		},
		{
			name:   "FAIL on maxAllowedFindings exceeded",
			params: map[string]any{"failOnSeverity": "CRITICAL", "warnOnSeverity": "CRITICAL", "failOnAnySecret": false, "maxAllowedFindings": 1},
			findings: []Finding{
				{ID: "F-1", Category: "SAST", Severity: "LOW", Path: "a.kt"},
				{ID: "F-2", Category: "SAST", Severity: "LOW", Path: "b.kt"},
			},
			wantStatus: "FAIL",
		},
		{
			name:   "PASS when onlyNewVsBaseline ignores old CRITICAL",
			params: map[string]any{"failOnSeverity": "HIGH", "warnOnSeverity": "MEDIUM", "failOnAnySecret": true, "onlyNewVsBaseline": true},
			findings: []Finding{
				{ID: "F-1", Category: "SECRET", Severity: "CRITICAL", Path: "old.kt", IsNewVsBaseline: false},
			},
			wantStatus: "PASS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := Step(Node{ID: "gate1", PluginID: "gate.policy", Params: tt.params}, Envelope{Findings: tt.findings}, nil)
			if res.Status != "SUCCEEDED" {
				t.Fatalf("status=%s err=%s", res.Status, res.Err)
			}
			if len(res.ActivePorts) != 1 || res.ActivePorts[0] != tt.wantStatus {
				t.Fatalf("activePorts = %v, want [%s]", res.ActivePorts, tt.wantStatus)
			}
			if res.Envelope.Gate == nil || res.Envelope.Gate.Status != tt.wantStatus || res.Envelope.Gate.NodeID != "gate1" || res.Envelope.Gate.EvaluatedAt == "" || res.Envelope.Gate.Reason == "" {
				t.Fatalf("gate info = %+v", res.Envelope.Gate)
			}
		})
	}
}

func TestValidateWithPluginsDynamicMetadata(t *testing.T) {
	t.Parallel()

	registry := map[string]PluginMeta{
		"trigger.manual": {
			PluginID:    "trigger.manual",
			Category:    "TRIGGER",
			OutputPorts: []string{"default"},
			Enabled:     true,
			Registered:  true,
		},
		"source.upload": {
			PluginID:    "source.upload",
			Category:    "SOURCE",
			OutputPorts: []string{"default"},
			Enabled:     true,
			Registered:  true,
		},
		"custom.iac-checker": {
			PluginID:    "custom.iac-checker",
			Category:    "ANALYZER",
			OutputPorts: []string{"default"},
			Enabled:     true,
			Registered:  true,
		},
		"logic.risk-router": {
			PluginID:    "logic.risk-router",
			Category:    "LOGIC",
			OutputPorts: []string{"BLOCK", "REVIEW", "OK"},
			Enabled:     true,
			Registered:  true,
		},
		"action.mattermost": {
			PluginID:           "action.mattermost",
			Category:           "ACTION",
			OutputPorts:        []string{"default"},
			RequiredSecretKeys: []string{"webhookToken"},
			Enabled:            true,
			Registered:         true,
		},
		"custom.disabled-analyzer": {
			PluginID:    "custom.disabled-analyzer",
			Category:    "ANALYZER",
			OutputPorts: []string{"default"},
			Enabled:     false,
			Registered:  true,
		},
	}
	lookup := func(pluginID string) (PluginMeta, bool) {
		m, ok := registry[pluginID]
		return m, ok
	}

	tests := []struct {
		name      string
		graph     Graph
		wantCodes []string
	}{
		{
			name: "valid graph with custom analyzer, custom logic ports, and bound action secret",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "s", PluginID: "source.upload"},
					{ID: "a", PluginID: "custom.iac-checker"},
					{ID: "r", PluginID: "logic.risk-router"},
					{ID: "act", PluginID: "action.mattermost", Secrets: map[string]string{"webhookToken": "sec_mm_1"}},
				},
				Edges: []Edge{
					{ID: "e1", Source: "t", SourceHandle: "default", Target: "s", TargetHandle: "default"},
					{ID: "e2", Source: "s", SourceHandle: "default", Target: "a", TargetHandle: "default"},
					{ID: "e3", Source: "a", SourceHandle: "default", Target: "r", TargetHandle: "default"},
					{ID: "e4", Source: "r", SourceHandle: "BLOCK", Target: "act", TargetHandle: "default"},
				},
			},
			wantCodes: nil,
		},
		{
			name: "custom analyzer without scan prefix requires upstream source node",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "a", PluginID: "custom.iac-checker"},
				},
				Edges: []Edge{
					{ID: "e1", Source: "t", SourceHandle: "default", Target: "a", TargetHandle: "default"},
				},
			},
			wantCodes: []string{CodeMissingSource},
		},
		{
			name: "custom logic node rejects undeclared output port",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "r", PluginID: "logic.risk-router"},
					{ID: "act", PluginID: "action.mattermost", Secrets: map[string]string{"webhookToken": "sec_mm_1"}},
				},
				Edges: []Edge{
					{ID: "e1", Source: "t", SourceHandle: "default", Target: "r", TargetHandle: "default"},
					{ID: "e2", Source: "r", SourceHandle: "UNKNOWN_PORT", Target: "act", TargetHandle: "default"},
				},
			},
			wantCodes: []string{CodeBadPort},
		},
		{
			name: "external action node enforces manifest required_secret_keys",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "act", PluginID: "action.mattermost"},
				},
				Edges: []Edge{
					{ID: "e1", Source: "t", SourceHandle: "default", Target: "act", TargetHandle: "default"},
				},
			},
			wantCodes: []string{CodeMissingSecret},
		},
		{
			name: "disabled plugin yields PLUGIN_DISABLED without mutating graph",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "s", PluginID: "source.upload"},
					{ID: "d", PluginID: "custom.disabled-analyzer"},
				},
				Edges: []Edge{
					{ID: "e1", Source: "t", SourceHandle: "default", Target: "s", TargetHandle: "default"},
					{ID: "e2", Source: "s", SourceHandle: "default", Target: "d", TargetHandle: "default"},
				},
			},
			wantCodes: []string{CodePluginDisabled},
		},
		{
			name: "unregistered plugin yields PLUGIN_UNREGISTERED without mutating graph",
			graph: Graph{
				Nodes: []Node{
					{ID: "t", PluginID: "trigger.manual"},
					{ID: "u", PluginID: "custom.removed"},
				},
				Edges: []Edge{
					{ID: "e1", Source: "t", SourceHandle: "default", Target: "u", TargetHandle: "default"},
				},
			},
			wantCodes: []string{CodePluginUnregistered},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			issues := ValidateWithPlugins(tt.graph, lookup)
			got := map[string]bool{}
			for _, iss := range issues {
				got[iss.Code] = true
			}
			if len(tt.wantCodes) == 0 && len(issues) != 0 {
				t.Fatalf("ValidateWithPlugins() = %+v, want no issues", issues)
			}
			for _, want := range tt.wantCodes {
				if !got[want] {
					t.Fatalf("ValidateWithPlugins() missing code %q; got %+v", want, issues)
				}
			}
		})
	}
}
