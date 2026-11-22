package springscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindsExposureAndPassword(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := "spring:\n  datasource:\n    password: hunter2\nmanagement:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n"
	if err := os.WriteFile(filepath.Join(dir, "application.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Scan(dir)
	if len(got) < 2 {
		t.Fatalf("got %#v", got)
	}
}

func TestScanWithOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		files     map[string]string
		opts      Options
		wantCount int
		wantClass string
	}{
		{
			name: "actuator check disabled leaves only password finding",
			files: map[string]string{
				"application.yml": "spring:\n  datasource:\n    password: secret\nmanagement:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n",
			},
			opts:      Options{CheckActuatorExposure: false, CheckPlaintextPasswords: true},
			wantCount: 1,
			wantClass: "plaintext-password",
		},
		{
			name: "password check disabled leaves only actuator finding",
			files: map[string]string{
				"application.properties": "management.endpoints.web.exposure.include=*\nspring.datasource.password=secret\n",
			},
			opts:      Options{CheckActuatorExposure: true, CheckPlaintextPasswords: false},
			wantCount: 1,
			wantClass: "actuator-exposure",
		},
		{
			name: "include and exclude path filters",
			files: map[string]string{
				"src/main/resources/application.properties": "spring.datasource.password=secret\n",
				"src/test/resources/application.properties": "spring.datasource.password=testpass\n",
			},
			opts: Options{
				CheckActuatorExposure:   true,
				CheckPlaintextPasswords: true,
				IncludePaths:            []string{"src/"},
				ExcludePaths:            []string{"src/test/"},
			},
			wantCount: 1,
			wantClass: "plaintext-password",
		},
		{
			name: "env var placeholder does not false positive",
			files: map[string]string{
				"application.yml": "spring:\n  datasource:\n    password: ${DB_PASSWORD}\n",
			},
			opts:      DefaultOptions(),
			wantCount: 0,
		},
		{
			name: "all checks disabled returns empty",
			files: map[string]string{
				"application.yml": "spring:\n  datasource:\n    password: secret\n",
			},
			opts:      Options{},
			wantCount: 0,
		},
		{
			name: "include and exclude do not collide on sibling directory prefixes",
			files: map[string]string{
				"src/main/resources/application.yml":             "spring:\n  datasource:\n    password: secret\n",
				"src/main2/resources/application.yml":            "spring:\n  datasource:\n    password: secret\n",
				"src/test/resources/application.yml":             "spring:\n  datasource:\n    password: secret\n",
				"src/test-integration/resources/application.yml": "spring:\n  datasource:\n    password: secret\n",
			},
			opts: Options{
				CheckActuatorExposure:   true,
				CheckPlaintextPasswords: true,
				IncludePaths:            []string{"./src/../src/main", "src/test-integration"},
				ExcludePaths:            []string{"src/test"},
			},
			wantCount: 2,
			wantClass: "plaintext-password",
		},
		{
			name: "quoted env var and comments in properties do not false positive",
			files: map[string]string{
				"application.properties": "spring.datasource.password=\"${DB_PASS}\"\nspring.mail.password='${MAIL_PASS}'\nspring.redis.password=\"\"\nspring.ldap.password=#comment\n",
			},
			opts:      DefaultOptions(),
			wantCount: 0,
		},
		{
			name: "unicode uppercase expanding under ToLower before password= does not panic",
			files: map[string]string{
				"application.properties": "ȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺpassword=secret\n",
			},
			opts:      DefaultOptions(),
			wantCount: 1,
			wantClass: "plaintext-password",
		},
		{
			name: "comment-only lines starting with hash do not false positive",
			files: map[string]string{
				"application.properties": "# spring.datasource.password=commented_out\n  # management.endpoints.web.exposure.include=*\n",
			},
			opts:      DefaultOptions(),
			wantCount: 0,
		},
		{
			name: "include path with double leading slash matches cleanly",
			files: map[string]string{
				"src/main/resources/application.yml": "spring:\n  datasource:\n    password: secret\n",
				"src/other/application.yml":          "spring:\n  datasource:\n    password: secret\n",
			},
			opts: Options{
				CheckActuatorExposure:   true,
				CheckPlaintextPasswords: true,
				IncludePaths:            []string{"//src/main"},
			},
			wantCount: 1,
			wantClass: "plaintext-password",
		},
		{
			name: "empty default placeholder and jdbc url password placeholder do not false positive",
			files: map[string]string{
				"a/application.properties": "spring.datasource.password=${DB_PASS:}\n",
				"b/application.properties": "spring.datasource.password=\"${DB_PASS:}\"\n",
				"c/application.properties": "spring.datasource.url=jdbc:postgresql://localhost:5432/db?password=${DB_PASS}\n",
				"d/application.properties": "spring.datasource.url=jdbc:postgresql://localhost:5432/db?password=${DB_PASS:}&ssl=true\n",
				"e/application.properties": "spring.datasource.password = ${DB_PASS:}\n",
			},
			opts:      DefaultOptions(),
			wantCount: 0,
		},
		{
			name: "jdbc url with plaintext password is flagged",
			files: map[string]string{
				"application.properties": "spring.datasource.url=jdbc:postgresql://localhost:5432/db?password=realpass\n",
			},
			opts:      DefaultOptions(),
			wantCount: 1,
			wantClass: "plaintext-password",
		},
		{
			name: "commented exposure wildcard after exposure key does not false positive",
			files: map[string]string{
				"application.yml": "management:\n  endpoints:\n    web:\n      exposure:\n        # include: '*'\n        include: health\n",
			},
			opts:      DefaultOptions(),
			wantCount: 0,
		},
		{
			name: "exposure wildcard after comment line is still flagged",
			files: map[string]string{
				"application.yml": "management:\n  endpoints:\n    web:\n      exposure:\n        # expose all for debugging\n        include: '*'\n",
			},
			opts:      DefaultOptions(),
			wantCount: 1,
			wantClass: "actuator-exposure",
		},
		{
			name: "yaml sequence wildcard exposure and multi-document profile are detected",
			files: map[string]string{
				"application.yml": "management:\n  endpoints:\n    web:\n      exposure:\n        include:\n          - health\n          - '*'\n---\nspring:\n  datasource:\n    password: ProdDbPassword99\n",
			},
			opts:      DefaultOptions(),
			wantCount: 2,
		},
		{
			name: "non-secret password metadata keys and placeholders do not false positive",
			files: map[string]string{
				"application.yml": "security:\n  password-policy: strict\n  password-encoder: bcrypt\n  max-password-length: 64\nspring:\n  datasource:\n    password: CHANGE_ME\n",
			},
			opts:      DefaultOptions(),
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for rel, content := range tt.files {
				full := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := ScanWithOptions(dir, tt.opts)
			if len(got) != tt.wantCount {
				t.Fatalf("ScanWithOptions len = %d (%#v), want %d", len(got), got, tt.wantCount)
			}
			if tt.wantClass != "" && len(got) > 0 && got[0].Class != tt.wantClass {
				t.Fatalf("finding class = %q, want %q", got[0].Class, tt.wantClass)
			}
		})
	}
}
