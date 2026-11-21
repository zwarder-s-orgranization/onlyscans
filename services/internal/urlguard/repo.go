package urlguard

import (
	"net"
	"net/url"
	"os"
	"strings"
)

// DefaultRepoAllowlist restricts scanning to the organizer's training repository
// unless additional educational repositories are explicitly configured via REPO_ALLOWLIST.
const DefaultRepoAllowlist = "github.com/TBagirov/training"

// RepoAllowed validates a Git repository URL against HTTPS, SSRF, and REPO_ALLOWLIST rules.
// Rules support exact repo paths ("github.com/TBagirov/training"), owner wildcards
// ("github.com/my-org/*"), or explicit host entries when configured in REPO_ALLOWLIST.
func RepoAllowed(raw, allowlistCSV string) (bool, string, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return false, "SCHEME_NOT_HTTPS", "only https repository URLs are allowed"
	}
	if u.User != nil {
		return false, "EMBEDDED_CREDENTIALS", "repository URL must not contain embedded credentials"
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || host == "metadata.google.internal" || host == "169.254.169.254" {
		return false, "SSRF_PRIVATE_IP", "private or metadata host is blocked"
	}
	if ip := net.ParseIP(host); ip != nil && private(ip) {
		return false, "SSRF_PRIVATE_IP", "private address is blocked"
	}
	if strings.Contains(u.Path, "..") {
		return false, "HOST_NOT_ALLOWLISTED", "invalid repository path"
	}
	repoPath := normalizeRepoPath(u.Path)
	if allowlistCSV == "" {
		allowlistCSV = os.Getenv("REPO_ALLOWLIST")
	}
	if strings.TrimSpace(allowlistCSV) == "" {
		allowlistCSV = DefaultRepoAllowlist
	}
	for _, rawRule := range strings.Split(allowlistCSV, ",") {
		rule := strings.TrimSpace(strings.ToLower(rawRule))
		if rule == "" {
			continue
		}
		rule = strings.TrimPrefix(rule, "https://")
		rule = strings.TrimPrefix(rule, "http://")
		if idx := strings.IndexByte(rule, '/'); idx >= 0 {
			ruleHost := rule[:idx]
			rulePath := normalizeRepoPath(rule[idx+1:])
			if host != ruleHost {
				continue
			}
			if strings.HasSuffix(rulePath, "/*") {
				prefix := strings.TrimSuffix(rulePath, "/*")
				if prefix != "" && strings.HasPrefix(repoPath, prefix+"/") {
					return true, "", ""
				}
				continue
			}
			if rulePath != "" && (repoPath == rulePath || strings.HasPrefix(repoPath, rulePath+"/")) {
				return true, "", ""
			}
			continue
		}
		if host == rule || strings.HasSuffix(host, "."+rule) {
			return true, "", ""
		}
	}
	return false, "HOST_NOT_ALLOWLISTED", "repository is outside REPO_ALLOWLIST (only organizer or configured educational repositories are allowed)"
}

func normalizeRepoPath(p string) string {
	p = strings.Trim(strings.ToLower(strings.TrimSpace(p)), "/")
	p = strings.TrimSuffix(p, ".git")
	return p
}
