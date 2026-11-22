package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/secflow/secflow/services/internal/urlguard"
)

var (
	ErrImageDenied    = errors.New("image policy violation")
	ErrEgressDenied   = errors.New("egress SSRF policy violation")
	ErrProfileInvalid = errors.New("invalid sandbox profile")
)

var blockedSandboxPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// ValidateImageRef enforces registry allowlisting, prohibited scanner denylist,
// and production :latest / untagged rejection.
func ValidateImageRef(raw string, registryAllowlist []string, production bool) error {
	ref := strings.TrimSpace(raw)
	if ref == "" {
		return fmt.Errorf("%w: image_ref is required", ErrImageDenied)
	}
	if strings.ContainsAny(ref, " \t\r\n") {
		return fmt.Errorf("%w: image_ref must not contain whitespace", ErrImageDenied)
	}
	if urlguard.Denied(ref) {
		return fmt.Errorf("%w: image_ref matches prohibited scanner denylist", ErrImageDenied)
	}

	// Split optional @digest first.
	withoutDigest, digest, hasDigest := strings.Cut(ref, "@")
	if hasDigest {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) < len("sha256:")+16 {
			return fmt.Errorf("%w: malformed image digest", ErrImageDenied)
		}
	}

	// Extract registry host (first slash-delimited segment containing '.' or ':' or 'localhost').
	slashIdx := strings.IndexByte(withoutDigest, '/')
	if slashIdx <= 0 {
		return fmt.Errorf("%w: image_ref must specify an explicit registry host", ErrImageDenied)
	}
	registry := strings.ToLower(withoutDigest[:slashIdx])
	repoAndTag := withoutDigest[slashIdx+1:]
	if repoAndTag == "" || (!strings.ContainsAny(registry, ".:") && registry != "localhost") {
		return fmt.Errorf("%w: image_ref must specify an explicit registry host", ErrImageDenied)
	}

	// Check registry allowlist (fail-closed if configured).
	if len(registryAllowlist) == 0 {
		return fmt.Errorf("%w: PLUGIN_IMAGE_REGISTRY_ALLOWLIST is empty", ErrImageDenied)
	}
	matched := false
	for _, entry := range registryAllowlist {
		e := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(entry, "/")))
		if e == "" {
			continue
		}
		if e == registry || strings.HasPrefix(strings.ToLower(withoutDigest), e+"/") {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("%w: registry %q is not in PLUGIN_IMAGE_REGISTRY_ALLOWLIST", ErrImageDenied, registry)
	}

	// Check tag vs digest in production.
	lastSlash := strings.LastIndexByte(repoAndTag, '/')
	nameSegment := repoAndTag
	if lastSlash >= 0 {
		nameSegment = repoAndTag[lastSlash+1:]
	}
	_, tag, hasTag := strings.Cut(nameSegment, ":")
	if production {
		if hasTag && strings.EqualFold(strings.TrimSpace(tag), "latest") {
			return fmt.Errorf("%w: tag :latest is forbidden in production", ErrImageDenied)
		}
		if !hasTag && !hasDigest {
			return fmt.Errorf("%w: untagged image (implicit :latest) is forbidden in production", ErrImageDenied)
		}
	}
	if hasTag && strings.TrimSpace(tag) == "" {
		return fmt.Errorf("%w: empty image tag", ErrImageDenied)
	}
	return nil
}

// EgressTarget represents one validated egress NetworkPolicy target (CIDR + optional port).
type EgressTarget struct {
	Raw  string
	CIDR string // Validated public IP/CIDR when entry is an IP/CIDR; empty for hostnames.
	Host string // Validated public hostname when entry is a hostname/URL.
	Port int32  // Optional explicit TCP port (defaults to 443 when 0).
}

// ValidateEgressAllowlist enforces ADR-0010 two-tier egress rules and SSRF guards.
func ValidateEgressAllowlist(profile string, entries []string) ([]EgressTarget, error) {
	switch profile {
	case ProfileInternalOnly:
		if len(entries) > 0 {
			return nil, fmt.Errorf("%w: egress_allowlist must be empty for INTERNAL_ONLY", ErrEgressDenied)
		}
		return nil, nil
	case ProfileEgressExternal:
		// Validate each entry below.
	default:
		return nil, fmt.Errorf("%w: unsupported sandbox profile %q", ErrProfileInvalid, profile)
	}

	out := make([]EgressTarget, 0, len(entries))
	for _, rawEntry := range entries {
		entry := strings.TrimSpace(rawEntry)
		if entry == "" {
			continue
		}
		target, err := parseAndValidateEgressEntry(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, nil
}

func parseAndValidateEgressEntry(entry string) (EgressTarget, error) {
	if urlguard.Denied(entry) {
		return EgressTarget{}, fmt.Errorf("%w: prohibited scanner host %q", ErrEgressDenied, entry)
	}
	if strings.Contains(entry, "://") {
		u, err := url.Parse(entry)
		if err != nil || u.Hostname() == "" {
			return EgressTarget{}, fmt.Errorf("%w: invalid egress URL %q", ErrEgressDenied, entry)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return EgressTarget{}, fmt.Errorf("%w: unsupported egress scheme %q", ErrEgressDenied, u.Scheme)
		}
		port := int32(443)
		if u.Scheme == "http" {
			port = 80
		}
		if p := u.Port(); p != "" {
			n, pErr := strconv.Atoi(p)
			if pErr != nil || n < 1 || n > 65535 {
				return EgressTarget{}, fmt.Errorf("%w: invalid egress port in %q", ErrEgressDenied, entry)
			}
			port = int32(n)
		}
		host := strings.ToLower(strings.TrimRight(u.Hostname(), "."))
		if addr, err := netip.ParseAddr(host); err == nil {
			addr = addr.Unmap()
			if isBlockedAddr(addr) {
				return EgressTarget{}, fmt.Errorf("%w: private/loopback/metadata IP %q is forbidden", ErrEgressDenied, host)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			return EgressTarget{Raw: entry, CIDR: netip.PrefixFrom(addr, bits).String(), Port: port}, nil
		}
		if isBlockedHost(host) {
			return EgressTarget{}, fmt.Errorf("%w: internal/metadata host %q is forbidden", ErrEgressDenied, host)
		}
		return EgressTarget{Raw: entry, Host: host, Port: port}, nil
	}

	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return EgressTarget{}, fmt.Errorf("%w: invalid CIDR %q", ErrEgressDenied, entry)
		}
		if isBlockedPrefix(prefix) {
			return EgressTarget{}, fmt.Errorf("%w: private/loopback/metadata CIDR %q is forbidden", ErrEgressDenied, entry)
		}
		return EgressTarget{Raw: entry, CIDR: prefix.Masked().String(), Port: 443}, nil
	}

	// Host or host:port or bare IP.
	host := entry
	port := int32(443)
	if h, p, splitErr := net.SplitHostPort(entry); splitErr == nil {
		host = h
		n, pErr := strconv.Atoi(p)
		if pErr != nil || n < 1 || n > 65535 {
			return EgressTarget{}, fmt.Errorf("%w: invalid port in %q", ErrEgressDenied, entry)
		}
		port = int32(n)
	}
	host = strings.ToLower(strings.TrimRight(strings.TrimPrefix(host, "*."), "."))
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if isBlockedAddr(addr) {
			return EgressTarget{}, fmt.Errorf("%w: private/loopback/metadata IP %q is forbidden", ErrEgressDenied, host)
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		return EgressTarget{Raw: entry, CIDR: netip.PrefixFrom(addr, bits).String(), Port: port}, nil
	}
	if isBlockedHost(host) {
		return EgressTarget{}, fmt.Errorf("%w: internal/metadata host %q is forbidden", ErrEgressDenied, host)
	}
	return EgressTarget{Raw: entry, Host: host, Port: port}, nil
}

func isBlockedPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return true
	}
	for _, blocked := range blockedSandboxPrefixes {
		if prefix.Overlaps(blocked) {
			return true
		}
	}
	return false
}

func isBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	for _, blocked := range blockedSandboxPrefixes {
		if blocked.Contains(addr) {
			return true
		}
	}
	return false
}

func isBlockedHost(host string) bool {
	if host == "" || strings.Contains(host, "%") || !strings.Contains(host, ".") {
		return true
	}
	for _, exact := range []string{"localhost", "local", "internal", "svc", "cluster.local", "home.arpa", "metadata.google.internal"} {
		if host == exact || strings.HasSuffix(host, "."+exact) {
			return true
		}
	}
	lastDot := strings.LastIndexByte(host, '.')
	return isNumericOrHexLabel(host[lastDot+1:])
}

func isNumericOrHexLabel(label string) bool {
	if label == "" {
		return true
	}
	if strings.HasPrefix(label, "0x") && len(label) > 2 {
		for i := 2; i < len(label); i++ {
			c := label[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

// ResourceCeiling defines maximum allowed container resources for sandbox pods.
type ResourceCeiling struct {
	MaxCPU      resource.Quantity
	MaxMemory   resource.Quantity
	MaxReplicas int32
}

// DefaultResourceCeiling returns safe default upper bounds for secflow-sandbox pods.
func DefaultResourceCeiling() ResourceCeiling {
	return ResourceCeiling{
		MaxCPU:      resource.MustParse("2"),
		MaxMemory:   resource.MustParse("2Gi"),
		MaxReplicas: 5,
	}
}

// ClampResourceLimits normalizes and caps requested CPU, RAM, and replicas within ceiling.
func ClampResourceLimits(in ResourceLimits, desired int32, ceiling ResourceCeiling) (cpuReq, cpuLim, memReq, memLim resource.Quantity, minRep, maxRep, replicas int32) {
	cpuReq = parseQtyOrDefault(in.CPURequest, "100m")
	cpuLim = parseQtyOrDefault(in.CPULimit, "500m")
	memReq = parseQtyOrDefault(in.MemoryRequest, "128Mi")
	memLim = parseQtyOrDefault(in.MemoryLimit, "512Mi")

	if cpuLim.Cmp(ceiling.MaxCPU) > 0 {
		cpuLim = ceiling.MaxCPU.DeepCopy()
	}
	if cpuReq.Cmp(cpuLim) > 0 {
		cpuReq = cpuLim.DeepCopy()
	}
	if memLim.Cmp(ceiling.MaxMemory) > 0 {
		memLim = ceiling.MaxMemory.DeepCopy()
	}
	if memReq.Cmp(memLim) > 0 {
		memReq = memLim.DeepCopy()
	}

	maxRep = in.MaxReplicas
	if maxRep <= 0 {
		maxRep = 2
	}
	if ceiling.MaxReplicas > 0 && maxRep > ceiling.MaxReplicas {
		maxRep = ceiling.MaxReplicas
	}
	minRep = in.MinReplicas
	if minRep < 0 {
		minRep = 0
	}
	if minRep > maxRep {
		minRep = maxRep
	}
	replicas = desired
	if replicas <= 0 {
		replicas = max(minRep, 1)
	}
	if replicas > maxRep {
		replicas = maxRep
	}
	return cpuReq, cpuLim, memReq, memLim, minRep, maxRep, replicas
}

func parseQtyOrDefault(raw, fallback string) resource.Quantity {
	if s := strings.TrimSpace(raw); s != "" {
		if q, err := resource.ParseQuantity(s); err == nil && q.Sign() > 0 {
			return q
		}
	}
	return resource.MustParse(fallback)
}
