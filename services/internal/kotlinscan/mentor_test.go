package kotlinscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	gradleparser "github.com/secflow/secflow/services/internal/gradleparser"
)

func TestMentorFifteenTruePositivesZeroFalsePositives(t *testing.T) {
	root := repoRoot(t)
	project := filepath.Join(root, "tests", "data", "repos", "mentor-training", "training-project")
	raw, err := os.ReadFile(filepath.Join(root, "tests", "data", "repos", "mentor-training", "ground-truth", "training-findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var truth struct {
		Findings []struct {
			ID          string   `json:"id"`
			Category    string   `json:"category"`
			Class       string   `json:"class"`
			Path        string   `json:"path"`
			Line        int      `json:"line"`
			EndLine     int      `json:"endLine"`
			Group       string   `json:"group"`
			Artifact    string   `json:"artifact"`
			Version     string   `json:"version"`
			AdvisoryIDs []string `json:"advisoryIds"`
		} `json:"findings"`
		Controls []struct {
			Category string `json:"category"`
			Class    string `json:"class"`
			Path     string `json:"path"`
			Line     int    `json:"line"`
			Group    string `json:"group"`
			Artifact string `json:"artifact"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(raw, &truth); err != nil {
		t.Fatal(err)
	}

	code, err := Scan(project)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := gradleparser.ParseProject(project)
	if err != nil {
		t.Fatal(err)
	}
	advisories, err := gradleparser.LoadCatalog(filepath.Join(root, "tests", "data", "repos", "mentor-training", "vulnerability-database", "vulnerabilities.json"))
	if err != nil {
		t.Fatal(err)
	}
	sca := gradleparser.Match(deps, advisories)

	for _, want := range truth.Findings {
		switch want.Category {
		case "SCA":
			if !scaHit(sca, want.Group, want.Artifact, want.Version, want.AdvisoryIDs) {
				t.Errorf("missing SCA %s %s:%s:%s", want.ID, want.Group, want.Artifact, want.Version)
			}
		default:
			if !codeHit(code, want.Category, want.Class, want.Path, want.Line, want.EndLine) {
				t.Errorf("missing %s %s %s:%d-%d (got %+v)", want.ID, want.Class, want.Path, want.Line, want.EndLine, code)
			}
		}
	}
	for _, ctrl := range truth.Controls {
		switch ctrl.Category {
		case "SCA":
			for _, f := range sca {
				if f.Group == ctrl.Group && f.Artifact == ctrl.Artifact {
					t.Errorf("false positive SCA %s:%s", f.Group, f.Artifact)
				}
			}
		default:
			for _, f := range code {
				if f.Category == ctrl.Category && f.Class == ctrl.Class && f.Path == ctrl.Path && f.Line == ctrl.Line {
					t.Errorf("false positive %s %s:%d", f.Class, f.Path, f.Line)
				}
			}
		}
	}
}

func TestFilterFindings(t *testing.T) {
	t.Parallel()

	sample := []Finding{
		{Category: "SECRET", Class: "password", Path: "src/main/kotlin/a/Secret.kt", Line: 4},
		{Category: "SECRET", Class: "configuration-token", Path: "src/main/resources/application.yml", Line: 13},
		{Category: "SAST", Class: "sql-injection", Path: "src/main/kotlin/b/Lookup.kt", Line: 13},
		{Category: "SAST", Class: "credentialed-cors", Path: "src/main/kotlin/config/Cors.kt", Line: 13, EndLine: 14},
	}

	got := FilterFindings(sample, FilterOptions{
		IncludePaths: []string{"src/main/kotlin/**"},
		ExcludePaths: []string{"**/config/**"},
	})
	if len(got) != 2 {
		t.Fatalf("path filter got %d (%+v), want 2", len(got), got)
	}

	rulesOnly := FilterFindings(sample, FilterOptions{
		EnabledRules: []string{"credentialed-cors"},
	})
	if len(rulesOnly) != 1 || rulesOnly[0].Class != "credentialed-cors" {
		t.Fatalf("rule filter got %+v, want only credentialed-cors", rulesOnly)
	}
}

func codeHit(fs []Finding, category, class, path string, line, endLine int) bool {
	for _, f := range fs {
		if f.Category == category && f.Class == class && f.Path == path && f.Line == line {
			if endLine > 0 && f.EndLine != endLine {
				continue
			}
			return true
		}
	}
	return false
}

func scaHit(fs []gradleparser.Finding, group, artifact, version string, ids []string) bool {
	for _, f := range fs {
		if f.Group != group || f.Artifact != artifact || f.Version != version {
			continue
		}
		for _, id := range ids {
			if f.AdvisoryID == id {
				return true
			}
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "tests", "data", "repos", "mentor-training")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found")
		}
		dir = parent
	}
}
