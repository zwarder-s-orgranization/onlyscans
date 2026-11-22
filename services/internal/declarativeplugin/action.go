package declarativeplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/urlguard"
)

// ErrRedirectBlocked is returned whenever an ACTION HTTP response attempts any redirect.
var ErrRedirectBlocked = errors.New("ALLOWLIST_DENIED: HTTP redirects are disabled for declarative ACTION plugins")

// DryRunHTTPPreview represents the offline-rendered HTTP request for Test Bench.
type DryRunHTTPPreview struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	Allowed         bool              `json:"allowed"`
	PolicyReason    string            `json:"policyReason,omitempty"`
	MatchedHostRule string            `json:"matchedHostRule,omitempty"`
}

// ActionExecResult holds the redacted outcome and extracted variables from ExecuteAction.
type ActionExecResult struct {
	StatusCode    int               `json:"statusCode"`
	ExtractedVars map[string]string `json:"extractedVars,omitempty"`
	PreviewBody   string            `json:"previewBody,omitempty"`
}

var templateTokenRe = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

// DryRunAction renders an ACTION HTTP request offline (never dialing the network),
// masks every secret expression as ***, and validates the target URL against scheme,
// egressAllowlist, and urlguard SSRF/denylist rules.
func DryRunAction(
	ctx context.Context,
	spec Spec,
	params map[string]any,
	env engine.Envelope,
	allowDevHTTP bool,
) (DryRunHTTPPreview, error) {
	if spec.Category != CategoryAction || spec.Action == nil {
		return DryRunHTTPPreview{}, fmt.Errorf("spec %q is not an ACTION plugin", spec.PluginID)
	}
	normEnv := env.Normalize()
	mergedParams := mergeParamDefaults(spec.Params, params)
	maskedSecrets := make(map[string]string, len(spec.RequiredSecretKeys))
	for _, k := range spec.RequiredSecretKeys {
		maskedSecrets[k] = "***"
	}

	renderedURL := interpolateSimple(spec.Action.URL, mergedParams, &normEnv, normEnv.Vars, maskedSecrets)
	headers := make(map[string]string, len(spec.Action.Headers))
	for k, v := range spec.Action.Headers {
		headers[k] = interpolateSimple(v, mergedParams, &normEnv, normEnv.Vars, maskedSecrets)
	}
	body := interpolateSimple(spec.Action.BodyTemplate, mergedParams, &normEnv, normEnv.Vars, maskedSecrets)

	matchedRule, policyErr := validateActionTargetURL(ctx, renderedURL, spec.EgressAllowlist, allowDevHTTP, true)
	preview := DryRunHTTPPreview{
		Method:          spec.Action.Method,
		URL:             renderedURL,
		Headers:         headers,
		Body:            body,
		Allowed:         policyErr == nil,
		MatchedHostRule: matchedRule,
	}
	if policyErr != nil {
		preview.PolicyReason = policyErr.Error()
	}
	return preview, nil
}

// ExecuteAction performs a live outbound HTTP request for an approved ACTION Declarative Plugin.
// It enforces scheme rules, egressAllowlist, urlguard DNS-pinned SSRF protection,
// zero redirects, bounded response reads (<= 256 KB), and JSON dot-path var extraction.
func ExecuteAction(
	ctx context.Context,
	spec Spec,
	params map[string]any,
	env engine.Envelope,
	resolvedSecrets map[string]string,
	allowDevHTTP bool,
) (ActionExecResult, error) {
	if spec.Category != CategoryAction || spec.Action == nil {
		return ActionExecResult{}, fmt.Errorf("spec %q is not an ACTION plugin", spec.PluginID)
	}
	normEnv := env.Normalize()
	mergedParams := mergeParamDefaults(spec.Params, params)

	renderedURL := interpolateSimple(spec.Action.URL, mergedParams, &normEnv, normEnv.Vars, resolvedSecrets)
	if _, err := validateActionTargetURL(ctx, renderedURL, spec.EgressAllowlist, allowDevHTTP, false); err != nil {
		return ActionExecResult{}, err
	}

	bodyStr := interpolateSimple(spec.Action.BodyTemplate, mergedParams, &normEnv, normEnv.Vars, resolvedSecrets)
	timeout := time.Duration(spec.Action.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = DefaultActionTimeoutSec * time.Second
	}
	if timeout > MaxActionTimeoutSec*time.Second {
		timeout = MaxActionTimeoutSec * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var bodyReader io.Reader
	if spec.Action.Method != http.MethodGet && bodyStr != "" {
		bodyReader = bytes.NewBufferString(bodyStr)
	}
	req, err := http.NewRequestWithContext(reqCtx, spec.Action.Method, renderedURL, bodyReader)
	if err != nil {
		return ActionExecResult{}, fmt.Errorf("build action request: %w", err)
	}
	for k, v := range spec.Action.Headers {
		req.Header.Set(k, interpolateSimple(v, mergedParams, &normEnv, normEnv.Vars, resolvedSecrets))
	}

	var client *http.Client
	if allowDevHTTP {
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrRedirectBlocked
			},
		}
	} else {
		client = urlguard.NewSafeClient(timeout)
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return ErrRedirectBlocked
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ActionExecResult{}, fmt.Errorf("action HTTP request failed: %s", redactSecretValues(err.Error(), resolvedSecrets))
	}
	defer resp.Body.Close()

	limited, err := io.ReadAll(io.LimitReader(resp.Body, MaxActionResponseBytes+1))
	if err != nil {
		return ActionExecResult{}, fmt.Errorf("read action response: %w", err)
	}
	if len(limited) > MaxActionResponseBytes {
		return ActionExecResult{}, fmt.Errorf("action response exceeded %d bytes limit", MaxActionResponseBytes)
	}

	expected := spec.Action.ExpectedStatuses
	if len(expected) == 0 {
		expected = []int{200, 201, 202, 204}
	}
	if !slices.Contains(expected, resp.StatusCode) {
		return ActionExecResult{}, fmt.Errorf("unexpected HTTP status %d (expected %v): %s", resp.StatusCode, expected, redactSecretValues(truncateStr(string(limited), 240), resolvedSecrets))
	}

	extracted := make(map[string]string, len(spec.Action.ExtractVars))
	if len(spec.Action.ExtractVars) > 0 && len(bytes.TrimSpace(limited)) > 0 {
		var parsed any
		if err := json.Unmarshal(limited, &parsed); err == nil {
			for varKey, dotPath := range spec.Action.ExtractVars {
				if v, ok := lookupDotPath(parsed, dotPath); ok {
					extracted[varKey] = redactSecretValues(v, resolvedSecrets)
				}
			}
		}
	}

	return ActionExecResult{
		StatusCode:    resp.StatusCode,
		ExtractedVars: extracted,
		PreviewBody:   redactSecretValues(truncateStr(string(limited), 512), resolvedSecrets),
	}, nil
}

func validateActionTargetURL(ctx context.Context, rawURL string, allowlist []string, allowDevHTTP, offlineDryRun bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("ALLOWLIST_DENIED: invalid target URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(allowDevHTTP && scheme == "http") {
		return "", fmt.Errorf("ALLOWLIST_DENIED: only https:// URLs are permitted for ACTION plugins")
	}
	if urlguard.Denied(u.Hostname() + " " + rawURL) {
		return "", fmt.Errorf("DENYLIST_BLOCKED: prohibited scanner host or URL")
	}
	matched := matchEgressAllowlist(u.Host, u.Hostname(), allowlist)
	if matched == "" {
		return "", fmt.Errorf("ALLOWLIST_DENIED: host %q is not in egressAllowlist %v", u.Host, allowlist)
	}
	if !allowDevHTTP {
		// In offline dry-run, still block literal private IPs/localhost without requiring DNS lookup
		// so drafts targeting external hostnames can be previewed cleanly even in air-gapped CI.
		if offlineDryRun {
			h := strings.ToLower(strings.TrimSpace(u.Hostname()))
			if h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "metadata.google.internal" || h == "169.254.169.254" {
				return "", urlguard.ErrAllowlistDenied
			}
			if ip := net.ParseIP(h); ip != nil {
				if err := urlguard.CheckCtx(ctx, rawURL); err != nil {
					return "", err
				}
			}
		} else {
			if err := urlguard.CheckCtx(ctx, rawURL); err != nil {
				return "", err
			}
		}
	}
	return matched, nil
}

func matchEgressAllowlist(hostWithPort, hostOnly string, allowlist []string) string {
	hp := strings.ToLower(strings.TrimSpace(hostWithPort))
	ho := strings.ToLower(strings.TrimSpace(hostOnly))
	for _, entry := range allowlist {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		if e == hp || e == ho {
			return entry
		}
		if strings.HasPrefix(e, "*.") {
			suffix := strings.TrimPrefix(e, "*")
			if strings.HasSuffix(ho, suffix) && len(ho) > len(suffix) {
				return entry
			}
		}
	}
	return ""
}

func lookupDotPath(root any, dotPath string) (string, bool) {
	cur := root
	for _, seg := range strings.Split(strings.TrimSpace(dotPath), ".") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return "", false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return "", false
			}
			cur = node[idx]
		default:
			return "", false
		}
	}
	if cur == nil {
		return "", false
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

func interpolateSimple(
	tmpl string,
	params map[string]any,
	env *engine.Envelope,
	vars map[string]string,
	secrets map[string]string,
) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	return templateTokenRe.ReplaceAllStringFunc(tmpl, func(raw string) string {
		m := templateTokenRe.FindStringSubmatch(raw)
		if len(m) != 2 {
			return raw
		}
		expr := strings.TrimSpace(m[1])
		expr = strings.TrimPrefix(expr, "$")
		if val, ok := resolveTemplateExpr(expr, params, env, vars, secrets); ok {
			return val
		}
		return ""
	})
}

func resolveTemplateExpr(
	expr string,
	params map[string]any,
	env *engine.Envelope,
	vars map[string]string,
	secrets map[string]string,
) (string, bool) {
	if key, ok := strings.CutPrefix(expr, "params."); ok {
		if v, exists := params[key]; exists && v != nil {
			return fmt.Sprint(v), true
		}
		return "", false
	}
	if key, ok := strings.CutPrefix(expr, "secrets."); ok {
		if secrets != nil {
			if v, exists := secrets[key]; exists {
				return v, true
			}
		}
		return "***", true
	}
	if key, ok := strings.CutPrefix(expr, "vars."); ok {
		if vars != nil {
			if v, exists := vars[key]; exists {
				return v, true
			}
		}
		return "", false
	}
	if env == nil {
		return "", false
	}
	switch expr {
	case "envelope.runId", "runId":
		return env.RunID, true
	case "envelope.stats.total", "stats.total":
		return strconv.Itoa(env.Stats.Total), true
	case "envelope.stats.critical", "stats.critical":
		return strconv.Itoa(env.Stats.Critical), true
	case "envelope.stats.high", "stats.high":
		return strconv.Itoa(env.Stats.High), true
	case "envelope.stats.medium", "stats.medium":
		return strconv.Itoa(env.Stats.Medium), true
	case "envelope.stats.low", "stats.low":
		return strconv.Itoa(env.Stats.Low), true
	case "envelope.gate.status", "gate.status":
		if env.Gate != nil {
			return env.Gate.Status, true
		}
		return "", true
	case "trigger.type":
		return env.Trigger.Type, true
	case "trigger.repoUrl":
		return env.Trigger.RepoURL, true
	case "trigger.branch":
		return env.Trigger.Branch, true
	case "trigger.commitSha":
		return env.Trigger.CommitSHA, true
	case "ai.executiveSummary":
		if env.AIReport != nil {
			return env.AIReport.ExecutiveSummary, true
		}
		return "", true
	case "ai.releaseDecision":
		if env.AIReport != nil {
			return env.AIReport.ReleaseDecision, true
		}
		return "", true
	}
	if key, ok := strings.CutPrefix(expr, "envelope.vars."); ok {
		if env.Vars != nil {
			if v, exists := env.Vars[key]; exists {
				return v, true
			}
		}
	}
	return "", false
}

func redactSecretValues(s string, secrets map[string]string) string {
	out := s
	for _, v := range secrets {
		if len(v) >= 4 {
			out = strings.ReplaceAll(out, v, "***")
		}
	}
	return out
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
