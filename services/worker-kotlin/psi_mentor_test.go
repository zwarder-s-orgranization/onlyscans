package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

func mentorProjectRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "tests", "data", "repos", "mentor-training", "training-project")
	if _, err := os.Stat(root); err != nil {
		root = filepath.Join("..", "tests", "data", "repos", "mentor-training", "training-project")
	}
	if _, err := os.Stat(root); err != nil {
		t.Skipf("optional mentor-training fixture not present: %v", err)
	}
	return root
}

func writeSyntheticKotlinProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"src/main/kotlin/demo/Cors.kt": `package demo

import org.springframework.web.cors.CorsConfiguration

class Cors {
    fun build(): CorsConfiguration {
        val cfg = CorsConfiguration()
        cfg.allowedOriginPatterns = listOf("*")
        cfg.allowCredentials = true
        return cfg
    }
}
`,
		"src/main/kotlin/demo/Lookup.kt": `package demo

import org.springframework.jdbc.core.JdbcTemplate

class Lookup(private val jdbc: JdbcTemplate) {
    fun find(q: String) = jdbc.queryForList("SELECT id FROM items WHERE name = '$q'")
}
`,
		"src/main/kotlin/demo/Secrets.kt": `package demo

class Secrets {
    val dbPassword = "ProdDbPassword123!"
    val stripeApiKey = "sk_live_9876543210"
}
`,
		"src/main/resources/application.yml": `integration:
  token: "cfg_secret_token_998877"
`,
	}
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestWorkerManifestsRuntimeAndSandbox(t *testing.T) {
	t.Parallel()

	manifests := workerManifests()
	if len(manifests) != 2 {
		t.Fatalf("manifests len = %d, want 2", len(manifests))
	}
	for _, m := range manifests {
		if m.GetRuntimeLanguage() != "kotlin-jvm" {
			t.Errorf("%s RuntimeLanguage = %q, want kotlin-jvm", m.GetPluginId(), m.GetRuntimeLanguage())
		}
		if m.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY {
			t.Errorf("%s SandboxProfile = %v, want INTERNAL_ONLY", m.GetPluginId(), m.GetSandboxProfile())
		}
	}
}

func TestScanTree_ParamsAndEndLinePreserved(t *testing.T) {
	t.Parallel()

	root := writeSyntheticKotlinProject(t)

	sastAll, err := scanTree(t.Context(), "scan.sast.kotlin", root, nil)
	if err != nil {
		t.Fatalf("scanTree sast error = %v", err)
	}
	if len(sastAll) != 2 {
		t.Fatalf("sast findings = %d (%+v), want 2", len(sastAll), sastAll)
	}

	protoFindings := toProtoFindings("scan.sast.kotlin", sastAll)
	foundCors := false
	for _, f := range protoFindings {
		if f.GetFindingClass() == "credentialed-cors" {
			foundCors = true
			if f.Line == nil || *f.Line != 8 {
				t.Errorf("credentialed-cors line = %v, want 8", f.Line)
			}
			if f.EndLine == nil || *f.EndLine != 9 {
				t.Errorf("credentialed-cors endLine = %v, want 9", f.EndLine)
			}
		}
	}
	if !foundCors {
		t.Fatal("missing credentialed-cors finding")
	}

	filteredSAST, err := scanTree(t.Context(), "scan.sast.kotlin", root, []byte(`{"enabledRules":["credentialed-cors"]}`))
	if err != nil {
		t.Fatalf("scanTree filtered sast error = %v", err)
	}
	if len(filteredSAST) != 1 || filteredSAST[0].Class != "credentialed-cors" {
		t.Fatalf("filtered sast findings = %+v, want only credentialed-cors", filteredSAST)
	}

	secretsOnlyYml, err := scanTree(t.Context(), "scan.secrets", root, []byte(`{"includePaths":["src/main/resources/**"]}`))
	if err != nil {
		t.Fatalf("scanTree filtered secrets error = %v", err)
	}
	if len(secretsOnlyYml) != 1 || secretsOnlyYml[0].Class != "configuration-token" {
		t.Fatalf("filtered secrets = %+v, want only configuration-token", secretsOnlyYml)
	}

	secretsExcludedYml, err := scanTree(t.Context(), "scan.secrets", root, []byte(`{"excludePaths":["**/*.yml"]}`))
	if err != nil {
		t.Fatalf("scanTree excluded secrets error = %v", err)
	}
	if len(secretsExcludedYml) != 2 {
		t.Fatalf("excluded yml secrets = %d (%+v), want 2", len(secretsExcludedYml), secretsExcludedYml)
	}
}

func TestMentorPSIWhenJarPresent(t *testing.T) {
	jar := os.Getenv("KOTLIN_PSI_JAR")
	if jar == "" {
		t.Skip("KOTLIN_PSI_JAR is not set")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java is not installed")
	}
	root := mentorProjectRoot(t)

	type psiHit struct {
		Category string `json:"category"`
		Class    string `json:"class"`
		Path     string `json:"path"`
		Line     int    `json:"line"`
		EndLine  int    `json:"endLine"`
	}

	runMode := func(mode string) []psiHit {
		out, err := exec.Command("java", "-jar", jar, "--mode", mode, root).Output()
		if err != nil {
			t.Fatalf("psi --mode %s: %v", mode, err)
		}
		var hits []psiHit
		if err := json.Unmarshal(out, &hits); err != nil {
			t.Fatalf("unmarshal psi --mode %s: %v", mode, err)
		}
		return hits
	}

	sastHits := runMode("sast")
	wantSast := map[string]string{
		"sql-injection":        "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt",
		"tls-verification":     "src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt",
		"credentialed-cors":    "src/main/kotlin/lab/repairdesk/config/RepairCors.kt",
		"route-authorization":  "src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt",
		"object-authorization": "src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt",
	}
	gotSast := map[string]string{}
	for _, hit := range sastHits {
		if hit.Category != "SAST" {
			t.Fatalf("unexpected non-SAST hit in --mode sast: %+v", hit)
		}
		gotSast[hit.Class] = hit.Path
		if hit.Class == "credentialed-cors" && (hit.Line != 13 || hit.EndLine != 14) {
			t.Fatalf("credentialed-cors span = %d..%d, want 13..14", hit.Line, hit.EndLine)
		}
	}
	if len(gotSast) != len(wantSast) {
		t.Fatalf("sast set %+v", gotSast)
	}
	for class, path := range wantSast {
		if gotSast[class] != path {
			t.Fatalf("%s -> %s, want %s", class, gotSast[class], path)
		}
	}

	secretHits := runMode("secrets")
	wantSecrets := map[string]string{
		"password":            "src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt",
		"api-key":             "src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
		"configuration-token": "src/main/resources/application.yml",
		"secret-fallback":     "src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt",
		"recoverable-token":   "src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt",
	}
	gotSecrets := map[string]string{}
	for _, hit := range secretHits {
		if hit.Category != "SECRET" {
			t.Fatalf("unexpected non-SECRET hit in --mode secrets: %+v", hit)
		}
		gotSecrets[hit.Class] = hit.Path
	}
	if len(gotSecrets) != len(wantSecrets) {
		t.Fatalf("secrets set %+v", gotSecrets)
	}
	for class, path := range wantSecrets {
		if gotSecrets[class] != path {
			t.Fatalf("%s -> %s, want %s", class, gotSecrets[class], path)
		}
	}
}
