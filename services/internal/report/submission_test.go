package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSubmissionJSON_SchemaCompliance(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{
			Category:    "SECRET",
			Path:        "src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt",
			Class:       "recoverable-token",
			Line:        7,
			EndLine:     10,
			Severity:    "MEDIUM",
			Description: "Token assembled from fragments",
			Remediation: "Read full token from env",
			// Extra SCA fields should never leak into SECRET JSON.
			Group:      "ignored.group",
			Artifact:   "ignored-artifact",
			Version:    "1.0.0",
			AdvisoryID: "CVE-2022-42889",
		},
		{
			Category:    "SAST",
			Path:        "src/main/kotlin/lab/repairdesk/config/RepairCors.kt",
			Class:       "credentialed-cors",
			Line:        13,
			EndLine:     50, // exceeds line + 14 -> must clamp to 27
			Severity:    "MEDIUM",
			Description: "Wildcard CORS with credentials",
			Remediation: "Restrict allowed origins",
		},
		{
			Category: "SCA",
			Path:     "build.gradle.kts",
			// Forbidden fields for scaFinding in submission-report.schema.json:
			Class:       "known-vulnerable-dependency",
			Line:        31,
			EndLine:     31,
			Group:       "org.apache.commons",
			Artifact:    "commons-text",
			Version:     "1.9",
			AdvisoryID:  "CVE-2022-42889",
			Severity:    "CRITICAL",
			Description: "StringSubstitutor lookup RCE",
			Remediation: "Upgrade to 1.10.0",
		},
	}

	raw, err := SubmissionJSON(findings)
	if err != nil {
		t.Fatalf("SubmissionJSON() error = %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal submission json: %v", err)
	}
	if len(doc) != 1 {
		t.Fatalf("top-level keys = %v, want only findings", doc)
	}
	arr, ok := doc["findings"].([]any)
	if !ok || len(arr) != 3 {
		t.Fatalf("findings len = %d, want 3", len(arr))
	}

	// Verify SECRET finding has only codeOrSecretFinding properties.
	sec := arr[0].(map[string]any)
	assertAllowedKeys(t, "SECRET", sec, map[string]bool{
		"category": true, "path": true, "class": true, "line": true, "endLine": true,
		"severity": true, "description": true, "remediation": true,
	})
	if sec["class"] != "recoverable-token" {
		t.Errorf("SECRET class = %v, want recoverable-token", sec["class"])
	}
	if _, hasFindingClass := sec["findingClass"]; hasFindingClass {
		t.Error("SECRET must not serialize findingClass")
	}

	// Verify SAST endLine clamping (line=13, raw endLine=50 -> clamped 27).
	sast := arr[1].(map[string]any)
	if got := int(sast["endLine"].(float64)); got != 27 {
		t.Errorf("SAST clamped endLine = %d, want 27", got)
	}

	// Verify SCA finding NEVER serializes line, endLine, or class.
	sca := arr[2].(map[string]any)
	assertAllowedKeys(t, "SCA", sca, map[string]bool{
		"category": true, "path": true, "group": true, "artifact": true, "version": true,
		"advisoryId": true, "severity": true, "description": true, "remediation": true,
	})
	for _, forbidden := range []string{"line", "endLine", "class"} {
		if _, exists := sca[forbidden]; exists {
			t.Errorf("SCA finding serialized forbidden property %q", forbidden)
		}
	}
	if sca["advisoryId"] != "CVE-2022-42889" {
		t.Errorf("SCA advisoryId = %v, want CVE-2022-42889", sca["advisoryId"])
	}
}

func TestSubmissionJSON_EmptySlice(t *testing.T) {
	t.Parallel()

	raw, err := SubmissionJSON(nil)
	if err != nil {
		t.Fatalf("SubmissionJSON(nil) error = %v", err)
	}
	if string(raw) != `{"findings":[]}` {
		t.Fatalf("got %s, want {\"findings\":[]}", string(raw))
	}
}

func TestSubmissionJSON_ValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		finding Finding
		wantErr string
	}{
		{
			name:    "absolute leading slash path",
			finding: Finding{Category: "SAST", Path: "/etc/passwd", Class: "sql-injection", Line: 1},
			wantErr: "relative POSIX path",
		},
		{
			name:    "windows drive letter path",
			finding: Finding{Category: "SAST", Path: `C:\repo\App.kt`, Class: "sql-injection", Line: 1},
			wantErr: "relative POSIX path",
		},
		{
			name:    "parent traversal segment",
			finding: Finding{Category: "SECRET", Path: "src/../secret.yml", Class: "configuration-token", Line: 5},
			wantErr: "'..'",
		},
		{
			name:    "line less than 1",
			finding: Finding{Category: "SAST", Path: "src/App.kt", Class: "sql-injection", Line: 0},
			wantErr: "line must be >= 1",
		},
		{
			name:    "endLine less than line",
			finding: Finding{Category: "SAST", Path: "src/App.kt", Class: "sql-injection", Line: 10, EndLine: 9},
			wantErr: "endLine (9) < line (10)",
		},
		{
			name:    "missing class on secret",
			finding: Finding{Category: "SECRET", Path: "src/App.kt", Line: 4},
			wantErr: "non-empty class",
		},
		{
			name: "invalid SCA advisoryId",
			finding: Finding{
				Category: "SCA", Path: "build.gradle.kts",
				Group: "org.json", Artifact: "json", Version: "20230227",
				AdvisoryID: "NOT-A-CVE",
			},
			wantErr: "advisoryId",
		},
		{
			name:    "invalid severity",
			finding: Finding{Category: "SAST", Path: "src/App.kt", Class: "sql-injection", Line: 4, Severity: "SEVERE"},
			wantErr: "invalid severity",
		},
		{
			name:    "unsupported category",
			finding: Finding{Category: "SBOM", Path: "build.gradle.kts"},
			wantErr: "unsupported finding category",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := SubmissionJSON([]Finding{tc.finding})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func assertAllowedKeys(t *testing.T, label string, m map[string]any, allowed map[string]bool) {
	t.Helper()
	for k := range m {
		if !allowed[k] {
			t.Errorf("%s contains unexpected key %q", label, k)
		}
	}
}
