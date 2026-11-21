// Package urlguard blocks private and denylisted outbound URLs and provides an SSRF-safe HTTP client.
package urlguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	// ErrAllowlistDenied indicates an outbound target failed SSRF or scheme validation.
	ErrAllowlistDenied = errors.New("ALLOWLIST_DENIED")
	// ErrDenylistBlocked indicates an outbound target references a forbidden third-party scanner.
	ErrDenylistBlocked = errors.New("DENYLIST_BLOCKED")
)

// Check rejects SSRF targets and scanner denylist words using a bounded lookup context.
// MCP_ALLOW_PRIVATE=1 skips the private-address check for local development.
func Check(raw string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return CheckCtx(ctx, raw)
}

// CheckCtx rejects SSRF targets and scanner denylist words while honoring ctx cancellation.
func CheckCtx(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return ErrAllowlistDenied
	}
	host := strings.ToLower(u.Hostname())
	if Denied(host + " " + raw) {
		return ErrDenylistBlocked
	}
	if allowPrivate() {
		return nil
	}
	return checkHost(ctx, host)
}

func checkHost(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" || host == "169.254.169.254" {
		return ErrAllowlistDenied
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return ErrAllowlistDenied
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ErrAllowlistDenied
	}
	for _, ip := range ips {
		if isPrivateIP(ip.IP) {
			return ErrAllowlistDenied
		}
	}
	return nil
}

// NewSafeClient returns an *http.Client that validates every dial target IP (preventing DNS rebinding),
// validates every redirect hop, caps redirects, and enforces an explicit request timeout.
func NewSafeClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          64,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("split host port: %w", err)
			}
			if Denied(host) {
				return nil, ErrDenylistBlocked
			}
			if allowPrivate() {
				return dialer.DialContext(ctx, network, addr)
			}
			if host == "" || strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") || strings.EqualFold(host, "metadata.google.internal") {
				return nil, ErrAllowlistDenied
			}
			if ip := net.ParseIP(host); ip != nil {
				if isPrivateIP(ip) {
					return nil, ErrAllowlistDenied
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, ErrAllowlistDenied
			}
			for _, ip := range ips {
				if isPrivateIP(ip.IP) {
					return nil, ErrAllowlistDenied
				}
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("dial validated ip: %w", lastErr)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return CheckCtx(req.Context(), req.URL.String())
		},
	}
}

var deniedScanners = []string{
	"semgrep",
	"gitleaks",
	"trivy",
	"detekt",
	"osv-scanner",
	"osvscanner",
	"grype",
	"syft",
	"snyk",
	"bandit",
	"sonarqube",
	"checkmarx",
	"codeql",
	"trufflehog",
}

var scannerNormReplacer = strings.NewReplacer("_", "-", " ", "-")

// Denied reports prohibited third-party security scanner product names that must not be invoked (ADR-0003).
func Denied(raw string) bool {
	if raw == "" {
		return false
	}
	low := strings.ToLower(raw)
	norm := scannerNormReplacer.Replace(low)
	for _, word := range deniedScanners {
		if strings.Contains(low, word) || strings.Contains(norm, word) {
			return true
		}
	}
	return false
}

func allowPrivate() bool {
	return os.Getenv("MCP_ALLOW_PRIVATE") == "1"
}

func private(ip net.IP) bool {
	return isPrivateIP(ip)
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}
