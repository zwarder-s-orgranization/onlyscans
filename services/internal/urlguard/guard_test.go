package urlguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckBlocksPrivateAndDenylist(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "")
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{name: "loopback ip", raw: "http://127.0.0.1:8080/hook", want: ErrAllowlistDenied},
		{name: "metadata ip", raw: "http://169.254.169.254/latest/meta-data", want: ErrAllowlistDenied},
		{name: "private rfc1918", raw: "http://10.0.0.5/internal", want: ErrAllowlistDenied},
		{name: "localhost name", raw: "http://localhost:9000", want: ErrAllowlistDenied},
		{name: "denylist scanner", raw: "https://api.example.com/semgrep", want: ErrDenylistBlocked},
		{name: "bad scheme", raw: "file:///etc/passwd", want: ErrAllowlistDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckCtx(t.Context(), tc.raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("CheckCtx(%q) = %v, want %v", tc.raw, err, tc.want)
			}
		})
	}
}

func TestSafeClientBlocksPrivateDial(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewSafeClient(2 * time.Second)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("expected private loopback dial to be blocked")
	}
	if !errors.Is(err, ErrAllowlistDenied) {
		t.Fatalf("expected ErrAllowlistDenied, got %v", err)
	}
}

func TestDeniedBlocksAllThirteenProhibitedScanners(t *testing.T) {
	t.Parallel()
	blocked := []struct {
		name string
		raw  string
	}{
		{name: "semgrep lowercase", raw: "https://mcp.example.com/semgrep"},
		{name: "gitleaks mixed case", raw: "GitLeaks-Scanner"},
		{name: "trivy tool", raw: "run_trivy_fs"},
		{name: "detekt analyzer", raw: "kotlin-DETEKT-mcp"},
		{name: "osv-scanner hyphen", raw: "osv-scanner"},
		{name: "osv_scanner underscore", raw: "run_osv_scanner_check"},
		{name: "osv scanner space", raw: "OSV Scanner MCP"},
		{name: "osvscanner compact", raw: "https://osvscanner.example.com/mcp"},
		{name: "grype", raw: "grype_sbom_scan"},
		{name: "syft", raw: "SyftGenerator"},
		{name: "snyk", raw: "https://api.snyk.io/mcp"},
		{name: "bandit", raw: "python_bandit_tool"},
		{name: "sonarqube", raw: "SonarQube Issues"},
		{name: "checkmarx", raw: "checkmarx-one"},
		{name: "codeql", raw: "github_codeql_query"},
		{name: "trufflehog", raw: "TruffleHog-v3"},
	}
	for _, tc := range blocked {
		t.Run("blocked/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if !Denied(tc.raw) {
				t.Fatalf("Denied(%q) = false, want true", tc.raw)
			}
		})
	}

	allowed := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "github issues mcp", raw: "https://mcp.github.example.com/v1 create_issue"},
		{name: "jira mcp", raw: "https://jira.example.com/mcp create_ticket"},
		{name: "slack notify", raw: "post_slack_message"},
		{name: "secflow custom", raw: "secflow_custom_workflow"},
	}
	for _, tc := range allowed {
		t.Run("allowed/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if Denied(tc.raw) {
				t.Fatalf("Denied(%q) = true, want false", tc.raw)
			}
		})
	}
}

func TestCheckBlocksDenylistEvenWhenPrivateAllowed(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "1")
	for _, scanner := range []string{
		"semgrep", "gitleaks", "trivy", "detekt", "osv-scanner", "osv_scanner",
		"grype", "syft", "snyk", "bandit", "sonarqube", "checkmarx", "codeql", "trufflehog",
	} {
		t.Run(scanner, func(t *testing.T) {
			err := CheckCtx(t.Context(), "http://127.0.0.1:9000/"+scanner)
			if !errors.Is(err, ErrDenylistBlocked) {
				t.Fatalf("CheckCtx(%q) = %v, want ErrDenylistBlocked", scanner, err)
			}
		})
	}
}
