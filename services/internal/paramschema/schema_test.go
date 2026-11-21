package paramschema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secflow/secflow/services/internal/manifest"
)

func TestRejectsMissingCronAndAcceptsSwitch(t *testing.T) {
	if err := LoadDefault(); err != nil {
		t.Fatal(err)
	}
	if err := Check("trigger.schedule", map[string]any{}); err == nil {
		t.Fatal("expected missing cron")
	}
	if err := Check("logic.switch", map[string]any{"mode": "category"}); err != nil {
		t.Fatal(err)
	}
	if err := Check("logic.switch", map[string]any{"mode": "nope"}); err == nil {
		t.Fatal("expected enum failure")
	}
	if err := Check("source.git", map[string]any{"repoUrl": "https://github.com/example/app"}); err != nil {
		t.Fatal(err)
	}
	if err := Check("source.git", map[string]any{"repoUrl": "https://github.com/example/app", "gitToken": "ghp_test"}); err == nil {
		t.Fatal("expected inline gitToken to be rejected by param schema")
	}
	if err := Check("ai.explain", map[string]any{"baseUrl": "https://api.openai.com/v1", "model": "gpt-4o-mini"}); err != nil {
		t.Fatal(err)
	}
	if err := Check("ai.explain", map[string]any{"baseUrl": "https://api.openai.com/v1", "model": "gpt-4o-mini", "apiKey": "sk-test"}); err == nil {
		t.Fatal("expected inline apiKey to be rejected by param schema")
	}
	if err := Check("notify.telegram", map[string]any{"chatId": "100"}); err != nil {
		t.Fatal(err)
	}
	if err := Check("notify.telegram", map[string]any{"chatId": "100", "botToken": "123:abc"}); err == nil {
		t.Fatal("expected inline botToken to be rejected by param schema")
	}
	if err := Check("notify.smtp", map[string]any{"to": []any{"ops@example.com"}, "subject": "SecFlow", "smtpAddr": "smtp.example.com:587"}); err != nil {
		t.Fatal(err)
	}
	if err := Check("trigger.webhook", map[string]any{"gitProvider": "GITHUB"}); err != nil {
		t.Fatal(err)
	}
}

func TestRawDefCoversAllBuiltinPlugins(t *testing.T) {
	specs := manifest.BuiltinSpecs()
	if len(specs) != 22 {
		t.Fatalf("expected 22 built-in plugins, got %d", len(specs))
	}
	for _, spec := range specs {
		t.Run(spec.PluginID, func(t *testing.T) {
			raw, ok := RawDef(spec.PluginID)
			if !ok || len(raw) == 0 {
				t.Fatalf("RawDef(%q) missing", spec.PluginID)
			}
			var obj map[string]any
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatalf("RawDef(%q) invalid JSON: %v", spec.PluginID, err)
			}
			if obj["type"] != "object" {
				t.Fatalf("RawDef(%q) type = %v, want object", spec.PluginID, obj["type"])
			}
		})
	}
	if _, ok := RawDef("unknown.plugin"); ok {
		t.Fatal("expected unknown plugin to return ok=false")
	}
}

func TestCheckFailsClosedWhenSchemaUnavailable(t *testing.T) {
	t.Cleanup(func() {
		reset()
		_ = LoadDefault()
	})

	t.Run("missing schema file", func(t *testing.T) {
		reset()
		t.Setenv("PARAMS_SCHEMA", filepath.Join(t.TempDir(), "does-not-exist.json"))
		err := Check("trigger.manual", map[string]any{})
		if err == nil {
			t.Fatal("expected Check to fail closed when schema file is missing")
		}
		if !strings.Contains(err.Error(), "param schema unavailable") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty defs schema file", func(t *testing.T) {
		reset()
		badPath := filepath.Join(t.TempDir(), "empty.json")
		if err := os.WriteFile(badPath, []byte(`{"$defs":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PARAMS_SCHEMA", badPath)
		if err := Check("trigger.manual", map[string]any{}); err == nil {
			t.Fatal("expected Check to fail closed when schema has empty $defs")
		}
	})
}
