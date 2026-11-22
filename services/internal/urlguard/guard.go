// Package urlguard blocks private and denylisted outbound URLs and provides an SSRF-safe HTTP client.
package urlguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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
	host = strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" || host == "169.254.169.254" {
		return ErrAllowlistDenied
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if isBlockedAddr(addr) {
			return ErrAllowlistDenied
		}
		return nil
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
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
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
			trimmedHost := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
			if trimmedHost == "" || trimmedHost == "localhost" || strings.HasSuffix(trimmedHost, ".localhost") || trimmedHost == "metadata.google.internal" || trimmedHost == "169.254.169.254" {
				return nil, ErrAllowlistDenied
			}
			if addr, err := netip.ParseAddr(trimmedHost); err == nil {
				if isBlockedAddr(addr) {
					return nil, ErrAllowlistDenied
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			}
			if ip := net.ParseIP(trimmedHost); ip != nil {
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

var deniedScannerStems = []string{
	"semgrep",
	"gitleaks",
	"trivy",
	"detekt",
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

func stripToAlnum(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func matchesDeniedScanner(candidate string) bool {
	if candidate == "" {
		return false
	}
	low := strings.ToLower(candidate)
	norm := scannerNormReplacer.Replace(low)
	for _, word := range deniedScanners {
		if strings.Contains(low, word) || strings.Contains(norm, word) {
			return true
		}
	}
	compact := stripToAlnum(low)
	for _, stem := range deniedScannerStems {
		if strings.Contains(compact, stem) {
			return true
		}
	}
	return false
}

func hexByteValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func decodePercentTolerant(s string) (string, bool) {
	if !strings.ContainsRune(s, '%') {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok1 := hexByteValue(s[i+1]); ok1 {
				if lo, ok2 := hexByteValue(s[i+2]); ok2 {
					b.WriteByte(hi<<4 | lo)
					changed = true
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func matchesDeniedWithPlus(candidate string) bool {
	if matchesDeniedScanner(candidate) {
		return true
	}
	if strings.ContainsRune(candidate, '+') {
		return matchesDeniedScanner(strings.ReplaceAll(candidate, "+", " "))
	}
	return false
}

// Denied reports prohibited third-party security scanner product names that must not be invoked (ADR-0003).
func Denied(raw string) bool {
	if raw == "" {
		return false
	}
	cur := raw
	for pass := range 4 {
		if matchesDeniedWithPlus(cur) {
			return true
		}
		if pass == 3 {
			break
		}
		next, changed := decodePercentTolerant(cur)
		if !changed || next == cur {
			break
		}
		cur = next
	}
	return false
}

func allowPrivate() bool {
	return os.Getenv("MCP_ALLOW_PRIVATE") == "1"
}

func private(ip net.IP) bool {
	return isPrivateIP(ip)
}

var blockedURLPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func isZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return true
	}
	for _, check := range []netip.Addr{addr, addr.Unmap()} {
		if check.IsLoopback() || check.IsPrivate() || check.IsLinkLocalUnicast() || check.IsLinkLocalMulticast() || check.IsMulticast() || check.IsUnspecified() || check.IsInterfaceLocalMulticast() {
			return true
		}
		for _, prefix := range blockedURLPrefixes {
			if prefix.Contains(check) {
				return true
			}
		}
		if check.Is6() {
			b := check.As16()
			if isZeroBytes(b[:10]) && ((b[10] == 0 && b[11] == 0) || (b[10] == 0xff && b[11] == 0xff)) {
				return true
			}
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return isBlockedAddr(addr)
}
