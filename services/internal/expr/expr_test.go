package expr

import (
	"reflect"
	"testing"
)

func TestEval(t *testing.T) {
	t.Parallel()
	vars := map[string]string{
		"trigger.repoUrl":             "https://github.com/org/repair-desk",
		"trigger.branch":              "main",
		"trigger.commitSha":           "deadbeef123",
		"envelope.stats.total":        "15",
		"envelope.stats.critical":     "1",
		"envelope.stats.newCount":     "3",
		"envelope.stats.maxSeverity":  "CRITICAL",
		"envelope.sourceRef.repoName": "repair-desk",
		"ai.executiveSummary":         "1 critical secret found",
		"ai.releaseDecision":          "BLOCK",
		"run.id":                      "run_123",
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "canonical trigger fields",
			input: "{{ $trigger.repoUrl }}@{{ $trigger.commitSha }} ({{ $trigger.branch }})",
			want:  "https://github.com/org/repair-desk@deadbeef123 (main)",
		},
		{
			name:  "canonical envelope stats and sourceRef",
			input: "{{ $envelope.sourceRef.repoName }}: total={{ $envelope.stats.total }} crit={{ $envelope.stats.critical }} new={{ $envelope.stats.newVsBaselineCount }} max={{ $envelope.stats.maxSeverity }}",
			want:  "repair-desk: total=15 crit=1 new=3 max=CRITICAL",
		},
		{
			name:  "legacy envelope and ai aliases",
			input: "run={{ run.id }} total={{ envelope.total }} crit={{ envelope.critical }} decision={{ ai.decision }} summary={{ ai.summary }}",
			want:  "run=run_123 total=15 crit=1 decision=BLOCK summary=1 critical secret found",
		},
		{
			name:  "unknown variable evaluates to empty string",
			input: "prefix-{{ $trigger.missing }}-suffix",
			want:  "prefix--suffix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Eval(tt.input, vars); got != tt.want {
				t.Fatalf("Eval(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEvalPreserveUnknown(t *testing.T) {
	t.Parallel()
	vars := map[string]string{
		"trigger.repoUrl": "https://github.com/org/repo",
	}
	got := EvalPreserveUnknown("{{ $trigger.repoUrl }} / {{ $trigger.unknown }}", vars)
	want := "https://github.com/org/repo / {{ $trigger.unknown }}"
	if got != want {
		t.Fatalf("EvalPreserveUnknown() = %q, want %q", got, want)
	}
	if bad, ok := HasUnresolved(got); !ok || bad != "{{ $trigger.unknown }}" {
		t.Fatalf("HasUnresolved(%q) = (%q, %v), want ({{ $trigger.unknown }}, true)", got, bad, ok)
	}
}

func TestEvalMapRecursive(t *testing.T) {
	t.Parallel()
	vars := map[string]string{
		"trigger.branch":             "feature/auth",
		"envelope.stats.critical":    "2",
		"envelope.stats.maxSeverity": "CRITICAL",
		"ai.executiveSummary":        "Fix SQLi",
	}
	in := map[string]any{
		"title": "Scan {{ $trigger.branch }}",
		"arguments": map[string]any{
			"body":   "Max={{ $envelope.stats.maxSeverity }} ({{ $envelope.stats.critical }})",
			"labels": []any{"secflow", "branch:{{ $trigger.branch }}", 42},
			"tags":   []string{"{{ $ai.summary }}"},
		},
		"count": 7,
	}
	got := EvalMap(in, vars)
	want := map[string]any{
		"title": "Scan feature/auth",
		"arguments": map[string]any{
			"body":   "Max=CRITICAL (2)",
			"labels": []any{"secflow", "branch:feature/auth", 42},
			"tags":   []string{"Fix SQLi"},
		},
		"count": 7,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EvalMap() = %#v, want %#v", got, want)
	}
	// Ensure original map was not mutated.
	if in["title"] != "Scan {{ $trigger.branch }}" {
		t.Fatalf("input map was mutated: %#v", in)
	}
}

func TestVarsFromEnvelopeJSON(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
		"trigger": {"type": "WEBHOOK", "repoUrl": "https://github.com/org/app", "branch": "main", "commitSha": "abc123", "prNumber": 42, "gitProvider": "GITHUB"},
		"sourceRef": {"sourceId": "src_1", "bucket": "secflow-sources", "key": "abc.tar.gz", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "repoName": "app"},
		"findings": [],
		"gate": {"status": "FAIL", "reason": "secret found", "nodeId": "g1"},
		"stats": {"total": 4, "newCount": 2, "critical": 1, "high": 1, "medium": 1, "low": 1, "secretCount": 1, "sastCount": 2, "scaCount": 1, "maxSeverity": "CRITICAL"},
		"vars": {"runId": "run_9", "explain": "{\"releaseDecision\":\"BLOCK\",\"executiveSummary\":\"Critical secret exposed\"}", "_internal": "hidden"}
	}`)
	vars := VarsFromEnvelopeJSON(raw, "")
	checks := map[string]string{
		"run.id":                      "run_9",
		"trigger.type":                "WEBHOOK",
		"trigger.repoUrl":             "https://github.com/org/app",
		"trigger.branch":              "main",
		"trigger.commitSha":           "abc123",
		"trigger.prNumber":            "42",
		"envelope.sourceRef.repoName": "app",
		"envelope.stats.total":        "4",
		"envelope.stats.newCount":     "2",
		"envelope.stats.critical":     "1",
		"envelope.stats.maxSeverity":  "CRITICAL",
		"envelope.gate.status":        "FAIL",
		"ai.releaseDecision":          "BLOCK",
		"ai.executiveSummary":         "Critical secret exposed",
	}
	for k, want := range checks {
		if got := vars[k]; got != want {
			t.Errorf("vars[%q] = %q, want %q", k, got, want)
		}
	}
	if _, leaked := vars["envelope.vars._internal"]; leaked {
		t.Fatalf("internal var leaked into template vars")
	}
}
