package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/expr"
	"github.com/secflow/secflow/services/internal/secretclient"
	"github.com/secflow/secflow/services/internal/urlguard"
)

const maxDiscardBodyBytes = 64 << 10

var (
	notifyHTTP       = urlguard.NewSafeClient(10 * time.Second)
	inspectorHTTP    = newInspectorClient(10 * time.Second)
	telegramAPIBase  = "https://api.telegram.org"
	smtpLookupIPAddr = net.DefaultResolver.LookupIPAddr
	smtpDialContext  = (&net.Dialer{Timeout: 8 * time.Second}).DialContext
)

func newInspectorClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          16,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           dialer.DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return urlguard.ErrAllowlistDenied
		},
	}
}

func deliver(ctx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
	base := &secflowv1.NodeResult{NodeRunId: task.GetNodeRunId(), RunId: task.GetRunId(), NodeId: task.GetNodeId(), PluginId: task.GetPluginId(), ActiveOutputPorts: []string{"default"}}
	params := map[string]any{}
	if len(task.GetParamsJson()) > 0 {
		_ = json.Unmarshal(task.GetParamsJson(), &params)
	}
	secrets := map[string]string{}
	orchAddr := envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051")
	for _, b := range task.GetSecretBindings() {
		plain, err := secretclient.ResolveNodeSecret(ctx, orchAddr, task, b.GetSecretRef())
		if err != nil {
			base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
			base.ErrorCode = "SECRET_SCOPE_DENIED"
			base.ErrorMessage = "secret unavailable"
			return base
		}
		secrets[b.GetParamKey()] = plain
	}
	summary := buildNotifySummary(task.GetRunId(), task.GetEnvelopeJson())
	var err error
	switch task.GetPluginId() {
	case "notify.telegram":
		text := summary.renderText(asString(params["messageTemplate"]))
		err = sendTelegram(ctx, asString(params["chatId"]), secrets["botToken"], task.GetRunId(), text)
	case "notify.webhook":
		body := summary.renderWebhookBody(asString(params["bodyTemplate"]))
		err = sendWebhook(ctx, asString(params["url"]), secrets["hmacSecret"], body)
	case "notify.smtp":
		text := summary.renderText(asString(params["bodyTemplate"]))
		err = sendSMTP(
			ctx,
			asStringList(params["to"]),
			asString(params["subject"]),
			secrets["smtpPassword"],
			text,
			asString(params["smtpAddr"]),
			asString(params["smtpUser"]),
			asString(params["smtpFrom"]),
		)
	default:
		err = errors.New("unknown notify plugin")
	}
	if err != nil {
		base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED
		switch {
		case errors.Is(err, urlguard.ErrAllowlistDenied):
			base.ErrorCode = "ALLOWLIST_DENIED"
		case errors.Is(err, urlguard.ErrDenylistBlocked):
			base.ErrorCode = "DENYLIST_BLOCKED"
		default:
			base.ErrorCode = "DELIVERY_FAILED"
		}
		base.ErrorMessage = "delivery failed"
		return base
	}
	base.Status = secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED
	return base
}

func runPublicURL(runID string) string {
	base := strings.TrimRight(strings.TrimSpace(envutil.Get("SECFLOW_PUBLIC_URL", "http://localhost:8080")), "/")
	if runID == "" {
		return base
	}
	return base + "/runs/" + url.PathEscape(runID)
}

func escapeMarkdownV2(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '\\', '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func escapeMarkdownV2URL(rawURL string) string {
	var b strings.Builder
	b.Grow(len(rawURL) + 8)
	for _, r := range rawURL {
		if r == '\\' || r == ')' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func formatTelegramMarkdownV2(runID, text string) string {
	escapedBody := escapeMarkdownV2(text)
	linkSuffix := ""
	if strings.TrimSpace(runID) != "" {
		runURL := runPublicURL(runID)
		linkSuffix = fmt.Sprintf("\n\n[Open Run %s](%s)", escapeMarkdownV2(runID), escapeMarkdownV2URL(runURL))
	}
	const maxRunes = 4000
	bodyRunes := []rune(escapedBody)
	suffixRunes := []rune(linkSuffix)
	if len(bodyRunes)+len(suffixRunes) > maxRunes {
		limit := maxRunes - len(suffixRunes) - 6 // reserve room for `\.\.\.`
		if limit < 0 {
			limit = 0
		}
		if limit > len(bodyRunes) {
			limit = len(bodyRunes)
		}
		// Never slice right between an escape backslash and the escaped character.
		bs := 0
		for i := limit - 1; i >= 0 && bodyRunes[i] == '\\'; i-- {
			bs++
		}
		if bs%2 == 1 && limit > 0 {
			limit--
		}
		escapedBody = string(bodyRunes[:limit]) + `\.\.\.`
	}
	return escapedBody + linkSuffix
}

func sendTelegram(ctx context.Context, chatID, token, runID, text string) error {
	if token == "" || chatID == "" {
		return errors.New("DELIVERY_FAILED")
	}
	formatted := formatTelegramMarkdownV2(runID, text)
	body, err := json.Marshal(map[string]string{
		"chat_id":    chatID,
		"text":       formatted,
		"parse_mode": "MarkdownV2",
	})
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(telegramAPIBase, "/") + "/bot" + token + "/sendMessage"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := notifyHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscardBodyBytes))
	if resp.StatusCode >= 300 {
		return errors.New("DELIVERY_FAILED")
	}
	return nil
}

func isWebhookInspectorAllowed(target string) bool {
	prefix := strings.TrimSpace(os.Getenv("WEBHOOK_INSPECTOR_URL_PREFIX"))
	if prefix == "" {
		return false
	}
	pu, err := url.Parse(prefix)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return false
	}
	tu, err := url.Parse(strings.TrimSpace(target))
	if err != nil || tu.User != nil {
		return false
	}
	if !strings.EqualFold(pu.Scheme, tu.Scheme) || !strings.EqualFold(pu.Host, tu.Host) {
		return false
	}
	if strings.Contains(tu.Path, "..") || strings.Contains(tu.RawPath, "..") {
		return false
	}
	cleanPrefix := pu.Path
	if !strings.HasSuffix(cleanPrefix, "/") {
		cleanPrefix += "/"
	}
	cleanTarget := path.Clean(tu.Path)
	if strings.HasSuffix(tu.Path, "/") && !strings.HasSuffix(cleanTarget, "/") {
		cleanTarget += "/"
	}
	if !strings.HasPrefix(cleanTarget, cleanPrefix) {
		return false
	}
	return !urlguard.Denied(target)
}

func sendWebhook(ctx context.Context, target, secret string, body []byte) error {
	if urlguard.Denied(target) {
		return urlguard.ErrDenylistBlocked
	}
	client := notifyHTTP
	if isWebhookInspectorAllowed(target) {
		client = inspectorHTTP
	} else if err := urlguard.CheckCtx(ctx, target); err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		req.Header.Set("X-SecFlow-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscardBodyBytes))
	if resp.StatusCode >= 300 {
		return errors.New("DELIVERY_FAILED")
	}
	return nil
}

func hasCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func isPrivateOrNonGlobalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	return false
}

// dialSafeSMTP resolves host once, validates every resolved IP against private/loopback/metadata
// ranges (unless allowPrivate is true), and dials the validated IP literal directly to prevent
// DNS-rebinding TOCTOU SSRF.
func dialSafeSMTP(ctx context.Context, host, port string, allowPrivate bool) (net.Conn, error) {
	if allowPrivate {
		return smtpDialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	lowerHost := strings.ToLower(strings.TrimSpace(host))
	if lowerHost == "" || lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") || lowerHost == "metadata.google.internal" || lowerHost == "169.254.169.254" {
		return nil, urlguard.ErrAllowlistDenied
	}
	if ip := net.ParseIP(lowerHost); ip != nil {
		if isPrivateOrNonGlobalIP(ip) {
			return nil, urlguard.ErrAllowlistDenied
		}
		return smtpDialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	}
	ips, err := smtpLookupIPAddr(ctx, lowerHost)
	if err != nil || len(ips) == 0 {
		return nil, urlguard.ErrAllowlistDenied
	}
	for _, ipAddr := range ips {
		if isPrivateOrNonGlobalIP(ipAddr.IP) {
			return nil, urlguard.ErrAllowlistDenied
		}
	}
	var lastErr error
	for _, ipAddr := range ips {
		conn, dialErr := smtpDialContext(ctx, "tcp", net.JoinHostPort(ipAddr.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("dial validated smtp ip: %w", lastErr)
}

func sendSMTP(ctx context.Context, to []string, subject, password, bodyText, addrOverride, userOverride, fromOverride string) error {
	if len(to) == 0 || strings.TrimSpace(subject) == "" {
		return errors.New("DELIVERY_FAILED")
	}
	if hasCRLF(subject) {
		return errors.New("invalid smtp subject: contains crlf")
	}
	cleanTo := make([]string, 0, len(to))
	for _, rcpt := range to {
		if hasCRLF(rcpt) {
			return errors.New("invalid smtp recipient: contains crlf")
		}
		trimmed := strings.TrimSpace(rcpt)
		if trimmed == "" {
			return errors.New("invalid smtp recipient: empty")
		}
		cleanTo = append(cleanTo, trimmed)
	}
	from := fromOverride
	if strings.TrimSpace(from) == "" {
		from = envutil.Get("SMTP_FROM", "secflow@localhost")
	}
	if hasCRLF(from) {
		return errors.New("invalid smtp from: contains crlf")
	}
	from = strings.TrimSpace(from)
	if from == "" {
		return errors.New("DELIVERY_FAILED")
	}

	envAddr := strings.TrimSpace(os.Getenv("SMTP_ADDR"))
	addr := strings.TrimSpace(addrOverride)
	serverConfigured := false
	if addr == "" {
		addr = envAddr
		serverConfigured = addr != ""
	} else if envAddr != "" && strings.EqualFold(addr, envAddr) {
		serverConfigured = true
	}
	if addr == "" {
		return errors.New("DELIVERY_FAILED")
	}
	host, port, err := splitHost(addr)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("DELIVERY_FAILED")
	}
	if port == "" {
		port = "25"
	}
	if urlguard.Denied(host) {
		return urlguard.ErrDenylistBlocked
	}
	allowPrivate := serverConfigured ||
		os.Getenv("SMTP_ALLOW_PRIVATE") == "1" ||
		os.Getenv("NOTIFY_ALLOW_PRIVATE") == "1" ||
		os.Getenv("MCP_ALLOW_PRIVATE") == "1"

	msg := []byte("From: " + from + "\r\nTo: " + strings.Join(cleanTo, ", ") + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + bodyText + "\r\n")
	var auth smtp.Auth
	if password != "" {
		user := strings.TrimSpace(userOverride)
		if user == "" {
			user = os.Getenv("SMTP_USER")
		}
		auth = smtp.PlainAuth("", user, password, host)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := dialSafeSMTP(dialCtx, host, port, allowPrivate)
	if err != nil {
		if errors.Is(err, urlguard.ErrAllowlistDenied) || errors.Is(err, urlguard.ErrDenylistBlocked) {
			return err
		}
		return fmt.Errorf("dial smtp: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() {
		_ = c.Close()
	}()
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range cleanTo {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt: %w", err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write data: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}
	return nil
}

type notifyFinding struct {
	Category    string `json:"Category"`
	Class       string `json:"Class"`
	Severity    string `json:"Severity"`
	Path        string `json:"Path"`
	Line        int    `json:"Line"`
	Artifact    string `json:"Artifact"`
	Version     string `json:"Version"`
	AdvisoryID  string `json:"AdvisoryID"`
	Remediation string `json:"Remediation"`
}

type notifySummary struct {
	RunID              string
	Findings           []notifyFinding
	Critical           int
	High               int
	Medium             int
	Low                int
	MaxSeverity        string
	ReleaseDecision    string
	ExecutiveSummary   string
	TopRecommendations []string
}

func buildNotifySummary(runID string, envelopeRaw []byte) notifySummary {
	sum := notifySummary{RunID: runID, MaxSeverity: "NONE"}
	var envDoc struct {
		Findings []notifyFinding   `json:"Findings"`
		Vars     map[string]string `json:"Vars"`
		MaxSev   string            `json:"MaxSev"`
	}
	if len(envelopeRaw) > 0 {
		_ = json.Unmarshal(envelopeRaw, &envDoc)
	}
	sum.Findings = envDoc.Findings
	for _, f := range envDoc.Findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			sum.Critical++
		case "HIGH":
			sum.High++
		case "MEDIUM":
			sum.Medium++
		case "LOW":
			sum.Low++
		}
	}
	switch {
	case sum.Critical > 0:
		sum.MaxSeverity = "CRITICAL"
	case sum.High > 0:
		sum.MaxSeverity = "HIGH"
	case sum.Medium > 0:
		sum.MaxSeverity = "MEDIUM"
	case sum.Low > 0:
		sum.MaxSeverity = "LOW"
	case envDoc.MaxSev != "":
		sum.MaxSeverity = envDoc.MaxSev
	}

	if explainRaw := strings.TrimSpace(envDoc.Vars["explain"]); explainRaw != "" {
		var aiDoc struct {
			ReleaseDecision  string `json:"releaseDecision"`
			ExecutiveSummary string `json:"executiveSummary"`
			Explain          string `json:"explain"`
			Items            []struct {
				RemediationSteps []string `json:"remediationSteps"`
			} `json:"items"`
		}
		if json.Unmarshal([]byte(explainRaw), &aiDoc) == nil && (aiDoc.ExecutiveSummary != "" || aiDoc.Explain != "") {
			sum.ReleaseDecision = aiDoc.ReleaseDecision
			if aiDoc.ExecutiveSummary != "" {
				sum.ExecutiveSummary = aiDoc.ExecutiveSummary
			} else {
				sum.ExecutiveSummary = aiDoc.Explain
			}
			for _, it := range aiDoc.Items {
				if len(it.RemediationSteps) > 0 && len(sum.TopRecommendations) < 5 {
					sum.TopRecommendations = append(sum.TopRecommendations, it.RemediationSteps[0])
				}
			}
		} else {
			sum.ExecutiveSummary = explainRaw
		}
	}
	return sum
}

func (s notifySummary) defaultText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SecFlow отчёт по прогону %s\n", s.RunID)
	fmt.Fprintf(&b, "Находок: %d (CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d)\n", len(s.Findings), s.Critical, s.High, s.Medium, s.Low)
	if s.ReleaseDecision != "" {
		fmt.Fprintf(&b, "Вердикт: %s\n", s.ReleaseDecision)
	}
	if s.ExecutiveSummary != "" {
		fmt.Fprintf(&b, "\nAI-разбор:\n%s\n", s.ExecutiveSummary)
	}
	if len(s.Findings) > 0 {
		b.WriteString("\nОсновные находки:\n")
		limit := len(s.Findings)
		if limit > 8 {
			limit = 8
		}
		for i := 0; i < limit; i++ {
			f := s.Findings[i]
			loc := f.Path
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
			} else if f.Artifact != "" {
				loc = fmt.Sprintf("%s:%s (%s)", f.Artifact, f.Version, f.AdvisoryID)
			}
			fmt.Fprintf(&b, "- [%s/%s] %s — %s\n", f.Severity, f.Category, f.Class, loc)
		}
	}
	if len(s.TopRecommendations) > 0 {
		b.WriteString("\nРекомендации:\n")
		for _, rec := range s.TopRecommendations {
			fmt.Fprintf(&b, "- %s\n", rec)
		}
	}
	return strings.TrimSpace(b.String())
}

func (s notifySummary) templateVars() map[string]string {
	return map[string]string{
		"run.id":               s.RunID,
		"envelope.total":       strconv.Itoa(len(s.Findings)),
		"envelope.critical":    strconv.Itoa(s.Critical),
		"envelope.high":        strconv.Itoa(s.High),
		"envelope.medium":      strconv.Itoa(s.Medium),
		"envelope.low":         strconv.Itoa(s.Low),
		"envelope.maxSeverity": s.MaxSeverity,
		"ai.summary":           s.ExecutiveSummary,
		"ai.decision":          s.ReleaseDecision,
		"report.text":          s.defaultText(),
	}
}

func (s notifySummary) renderText(tpl string) string {
	if strings.TrimSpace(tpl) != "" {
		return expr.Eval(tpl, s.templateVars())
	}
	return s.defaultText()
}

func (s notifySummary) renderWebhookBody(tpl string) []byte {
	if strings.TrimSpace(tpl) != "" {
		return []byte(expr.Eval(tpl, s.templateVars()))
	}
	raw, _ := json.Marshal(map[string]any{
		"runId":            s.RunID,
		"findingCount":     len(s.Findings),
		"critical":         s.Critical,
		"high":             s.High,
		"medium":           s.Medium,
		"low":              s.Low,
		"maxSeverity":      s.MaxSeverity,
		"releaseDecision":  s.ReleaseDecision,
		"executiveSummary": s.ExecutiveSummary,
		"recommendations":  s.TopRecommendations,
	})
	return raw
}

func splitHost(addr string) (string, string, error) {
	if !strings.Contains(addr, "://") {
		addr = "smtp://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return "", "", err
	}
	return u.Hostname(), u.Port(), nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asStringList(v any) []string {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}
