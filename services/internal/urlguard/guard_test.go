package urlguard

import (
	"errors"
	"net"
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

func TestCheckCtx_IPv4CompatibleAndPublicIPv6(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "")
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{name: "ipv4-compatible loopback", raw: "http://[::127.0.0.1]/hook", want: ErrAllowlistDenied},
		{name: "ipv4-compatible metadata", raw: "http://[::169.254.169.254]/latest/meta-data", want: ErrAllowlistDenied},
		{name: "ipv4-compatible unspecified", raw: "http://[::0.0.0.0]/", want: ErrAllowlistDenied},
		{name: "ipv4-mapped loopback", raw: "http://[::ffff:127.0.0.1]/hook", want: ErrAllowlistDenied},
		{name: "nat64 loopback", raw: "http://[64:ff9b::127.0.0.1]/hook", want: ErrAllowlistDenied},
		{name: "zoned link-local ipv6", raw: "http://[fe80::1%25eth0]/hook", want: ErrAllowlistDenied},
		{name: "public ipv6 allowed", raw: "https://[2606:4700:4700::1111]/hook", want: nil},
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

func TestIsPrivateIP_IPv6Cases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "ipv4-compatible loopback", ip: "::127.0.0.1", want: true},
		{name: "ipv4-compatible metadata", ip: "::169.254.169.254", want: true},
		{name: "ipv4-compatible unspecified", ip: "::0.0.0.0", want: true},
		{name: "ipv4-mapped loopback", ip: "::ffff:127.0.0.1", want: true},
		{name: "nat64 loopback", ip: "64:ff9b::127.0.0.1", want: true},
		{name: "public ipv6", ip: "2606:4700:4700::1111", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) = nil", tc.ip)
			}
			if got := isPrivateIP(ip); got != tc.want {
				t.Fatalf("isPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestSafeClient_BlocksIPv4CompatibleIPv6Dial(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "")
	client := NewSafeClient(2 * time.Second)
	for _, raw := range []string{
		"http://[::127.0.0.1]:80/hook",
		"http://[::169.254.169.254]:80/latest/meta-data",
		"http://[::0.0.0.0]:80/",
	} {
		t.Run(raw, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, raw, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("expected dial to %q to be blocked", raw)
			}
			if !errors.Is(err, ErrAllowlistDenied) {
				t.Fatalf("client.Do(%q) err = %v, want ErrAllowlistDenied", raw, err)
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
		{name: "sem_grep underscore", raw: "sem_grep"},
		{name: "git-leaks hyphen", raw: "git-leaks"},
		{name: "osv.scanner dot", raw: "osv.scanner"},
		{name: "truffle_hog underscore", raw: "truffle_hog"},
		{name: "sonar_qube underscore", raw: "sonar_qube"},
		{name: "check-marx hyphen", raw: "check-marx"},
		{name: "code_ql underscore", raw: "code_ql"},
		{name: "url encoded semgrep", raw: "ghcr.io/foo/%73emgrep:1.0"},
		{name: "query encoded trivy", raw: "https://example.com/?tool=%74rivy+fs"},
		{name: "stray percent before url encoded semgrep", raw: "100% pure %73emgrep"},
		{name: "stray percent deterministic before url encoded semgrep", raw: "100% deterministic %73emgrep"},
		{name: "double url encoded semgrep", raw: "%2573emgrep"},
		{name: "triple url encoded semgrep", raw: "%252573emgrep"},
		{name: "oci path with stray percent and url encoded semgrep", raw: "ghcr.io/100%/%73emgrep:1.0"},
		{name: "query with stray percent and url encoded trivy", raw: "https://example.com/?x=100%&t=%74rivy"},
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
		{name: "percent text without scanner", raw: "100% pure custom workflow"},
		{name: "spring config plugin", raw: "scan.spring-config spring-config-hardening"},
		{name: "risk router plugin", raw: "logic.risk-router"},
		{name: "url with encoded percent", raw: "https://example.com/my%20plugin?pct=100%25"},
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
