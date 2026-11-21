package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/urlguard"
)

func TestNotifySummary_RendersFindingsAndAIExplanation(t *testing.T) {
	explainJSON, _ := json.Marshal(map[string]any{
		"releaseDecision":  "BLOCK",
		"executiveSummary": "Обнаружена критическая уязвимость Text4Shell.",
		"items": []map[string]any{
			{"remediationSteps": []string{"Обновите commons-text до 1.10.0"}},
		},
	})
	envRaw, _ := json.Marshal(map[string]any{
		"Findings": []notifyFinding{
			{Category: "SCA", Class: "vulnerable-dependency", Severity: "CRITICAL", Artifact: "commons-text", Version: "1.9", AdvisoryID: "CVE-2022-42889"},
			{Category: "SECRET", Class: "password", Severity: "HIGH", Path: "src/App.kt", Line: 12},
		},
		"Vars": map[string]string{"explain": string(explainJSON)},
	})

	sum := buildNotifySummary("run_42", envRaw)
	text := sum.renderText("")
	for _, want := range []string{"run_42", "CRITICAL: 1", "HIGH: 1", "BLOCK", "Text4Shell", "Обновите commons-text до 1.10.0"} {
		if !strings.Contains(text, want) {
			t.Fatalf("defaultText missing %q:\n%s", want, text)
		}
	}

	custom := sum.renderText("Run {{ $run.id }}: total={{ $envelope.total }}, decision={{ $ai.decision }}")
	if custom != "Run run_42: total=2, decision=BLOCK" {
		t.Fatalf("custom template = %q", custom)
	}

	wh := sum.renderWebhookBody("")
	var doc map[string]any
	if err := json.Unmarshal(wh, &doc); err != nil {
		t.Fatalf("webhook json invalid: %v", err)
	}
	if doc["releaseDecision"] != "BLOCK" || doc["maxSeverity"] != "CRITICAL" {
		t.Fatalf("webhook doc = %+v", doc)
	}
}

func TestDeliver_IgnoresInlinePlaintextSecretParams(t *testing.T) {
	res := deliver(t.Context(), &secflowv1.NodeTask{
		NodeRunId:  "nr_1",
		RunId:      "run_1",
		NodeId:     "tg_1",
		PluginId:   "notify.telegram",
		ParamsJson: []byte(`{"chatId":"100","botToken":"123:plaintext-must-be-ignored"}`),
	})
	if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED {
		t.Fatalf("expected FAILED when botToken is only in params, got %v", res.GetStatus())
	}
}

func TestSendWebhook_SecFlowSignatureAndInspectorAllowlist(t *testing.T) {
	var gotSig, gotLegacySig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-SecFlow-Signature-256")
		gotLegacySig = r.Header.Get("X-Hub-Signature-256")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	t.Setenv("MCP_ALLOW_PRIVATE", "")
	t.Setenv("WEBHOOK_INSPECTOR_URL_PREFIX", "")

	// Without WEBHOOK_INSPECTOR_URL_PREFIX or MCP_ALLOW_PRIVATE, local private URL MUST be blocked.
	if err := sendWebhook(t.Context(), srv.URL+"/webhooks/inspector/demo", "wh-secret", []byte(`{"ok":true}`)); !errors.Is(err, urlguard.ErrAllowlistDenied) {
		t.Fatalf("expected ErrAllowlistDenied without inspector prefix, got %v", err)
	}

	// Enable narrow opt-in WEBHOOK_INSPECTOR_URL_PREFIX (still with MCP_ALLOW_PRIVATE unset!).
	t.Setenv("WEBHOOK_INSPECTOR_URL_PREFIX", srv.URL+"/webhooks/inspector/")

	// Non-matching path and traversal attempt MUST still be rejected.
	for _, badTarget := range []string{
		srv.URL + "/admin/internal",
		srv.URL + "/webhooks/inspector/../../admin",
	} {
		if err := sendWebhook(t.Context(), badTarget, "wh-secret", []byte(`{"ok":true}`)); !errors.Is(err, urlguard.ErrAllowlistDenied) {
			t.Fatalf("expected ErrAllowlistDenied for %q, got %v", badTarget, err)
		}
	}

	// Matching inspector URL succeeds and signs with X-SecFlow-Signature-256 (not X-Hub-Signature-256).
	payload := []byte(`{"runId":"run_77","critical":1}`)
	if err := sendWebhook(t.Context(), srv.URL+"/webhooks/inspector/demo-chan", "wh-secret", payload); err != nil {
		t.Fatalf("sendWebhook to allowlisted inspector failed: %v", err)
	}
	mac := hmac.New(sha256.New, []byte("wh-secret"))
	_, _ = mac.Write(payload)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != wantSig {
		t.Fatalf("X-SecFlow-Signature-256 = %q, want %q", gotSig, wantSig)
	}
	if gotLegacySig != "" {
		t.Fatalf("expected empty X-Hub-Signature-256, got %q", gotLegacySig)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body = %q, want %q", string(gotBody), string(payload))
	}
}

func TestSendTelegram_MarkdownV2EscapingAndRunLink(t *testing.T) {
	var captured map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	origBase := telegramAPIBase
	origHTTP := notifyHTTP
	telegramAPIBase = srv.URL
	notifyHTTP = srv.Client()
	t.Cleanup(func() {
		telegramAPIBase = origBase
		notifyHTTP = origHTTP
	})

	t.Setenv("SECFLOW_PUBLIC_URL", "https://secflow.example.org/")

	rawMsg := "Found [CRITICAL] issue_1 in app.kt (line 42)! score=9.8+1-0 *bold* ~strike~ `code` > # | { }"
	if err := sendTelegram(t.Context(), "-100123", "bot-token", "run_abc_1", rawMsg); err != nil {
		t.Fatalf("sendTelegram failed: %v", err)
	}
	if captured["parse_mode"] != "MarkdownV2" {
		t.Fatalf("parse_mode = %q, want MarkdownV2", captured["parse_mode"])
	}
	if captured["chat_id"] != "-100123" {
		t.Fatalf("chat_id = %q", captured["chat_id"])
	}
	wantEscaped := escapeMarkdownV2(rawMsg)
	if !strings.Contains(captured["text"], wantEscaped) {
		t.Fatalf("text missing escaped message:\ngot:  %q\nwant: %q", captured["text"], wantEscaped)
	}
	wantLink := `[Open Run run\_abc\_1](https://secflow.example.org/runs/run_abc_1)`
	if !strings.Contains(captured["text"], wantLink) {
		t.Fatalf("text missing MarkdownV2 run link %q:\n%s", wantLink, captured["text"])
	}

	// Verify truncation of very long text keeps the link and never ends with a dangling backslash.
	longText := formatTelegramMarkdownV2("run_long", strings.Repeat("a.b_c!", 1500))
	if !strings.Contains(longText, "https://secflow.example.org/runs/run_long") {
		t.Fatalf("truncated message lost run link")
	}
	if len([]rune(longText)) > 4096 {
		t.Fatalf("truncated message exceeds Telegram limit: %d runes", len([]rune(longText)))
	}
}

func TestSendCommitStatus_ValidationTargetURLAndGitLabFailedState(t *testing.T) {
	srv := notify{}

	t.Run("rejects empty url without fake 201", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		resp, err := srv.SendCommitStatus(t.Context(), &secflowv1.SendCommitStatusRequest{
			RunId: "run_1",
			State: secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS,
		})
		if err != nil {
			t.Fatalf("unexpected rpc error: %v", err)
		}
		if resp.GetDelivered() || resp.GetErrorMessage() == "" || resp.GetHttpStatus() == 201 {
			t.Fatalf("expected Delivered=false with error for empty URL, got %+v", resp)
		}
	})

	t.Run("rejects localhost and 127.0.0.1 via SSRF urlguard", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		for _, target := range []string{
			"http://127.0.0.1:9999/repos/org/app/statuses/abc",
			"http://localhost:9999/repos/org/app/statuses/abc",
		} {
			resp, err := srv.SendCommitStatus(t.Context(), &secflowv1.SendCommitStatusRequest{
				RunId:           "run_1",
				CommitStatusUrl: target,
				State:           secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS,
			})
			if err != nil {
				t.Fatalf("unexpected rpc error: %v", err)
			}
			if resp.GetDelivered() || resp.GetErrorMessage() != "ALLOWLIST_DENIED" {
				t.Fatalf("target=%q expected Delivered=false ALLOWLIST_DENIED, got %+v", target, resp)
			}
		}
	})

	t.Run("delivers target_url and maps GitLab failure to failed", func(t *testing.T) {
		var mu sync.Mutex
		received := map[string]map[string]string{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			var doc map[string]string
			_ = json.Unmarshal(raw, &doc)
			mu.Lock()
			received[r.URL.Path] = doc
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		}))
		defer ts.Close()

		t.Setenv("MCP_ALLOW_PRIVATE", "1")

		ghResp, err := srv.SendCommitStatus(t.Context(), &secflowv1.SendCommitStatusRequest{
			RunId:           "run_gh",
			GitProvider:     secflowv1.GitProvider_GIT_PROVIDER_GITHUB,
			CommitStatusUrl: ts.URL + "/repos/org/app/statuses/abc123",
			State:           secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE,
			Context:         "secflow/security-gate",
			Description:     "Gate failed",
			TargetUrl:       "https://secflow.local/runs/run_gh",
		})
		if err != nil || !ghResp.GetDelivered() || ghResp.GetHttpStatus() != http.StatusCreated {
			t.Fatalf("GitHub SendCommitStatus = (%+v, %v)", ghResp, err)
		}

		glResp, err := srv.SendCommitStatus(t.Context(), &secflowv1.SendCommitStatusRequest{
			RunId:           "run_gl",
			GitProvider:     secflowv1.GitProvider_GIT_PROVIDER_GITLAB,
			CommitStatusUrl: ts.URL + "/api/v4/projects/77/statuses/def456",
			State:           secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE,
			Context:         "secflow/security-gate",
			Description:     "Gate failed",
			TargetUrl:       "https://secflow.local/runs/run_gl",
		})
		if err != nil || !glResp.GetDelivered() || glResp.GetHttpStatus() != http.StatusCreated {
			t.Fatalf("GitLab SendCommitStatus = (%+v, %v)", glResp, err)
		}

		mu.Lock()
		defer mu.Unlock()
		ghDoc := received["/repos/org/app/statuses/abc123"]
		if ghDoc["state"] != "failure" || ghDoc["target_url"] != "https://secflow.local/runs/run_gh" {
			t.Fatalf("unexpected GitHub payload: %+v", ghDoc)
		}
		glDoc := received["/api/v4/projects/77/statuses/def456"]
		if glDoc["state"] != "failed" || glDoc["target_url"] != "https://secflow.local/runs/run_gl" {
			t.Fatalf("unexpected GitLab payload (want state=failed): %+v", glDoc)
		}
	})
}

func startMockSMTPServer(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock smtp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := bufio.NewWriter(c)
				writeLine := func(s string) {
					_, _ = w.WriteString(s + "\r\n")
					_ = w.Flush()
				}
				writeLine("220 mock-smtp ready")
				var dataBuf strings.Builder
				inData := false
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if line == ".\r\n" || line == ".\n" {
							inData = false
							got <- dataBuf.String()
							writeLine("250 OK")
							continue
						}
						dataBuf.WriteString(line)
						continue
					}
					upper := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
						writeLine("250-mock-smtp")
						writeLine("250 OK")
					case strings.HasPrefix(upper, "MAIL FROM:"):
						writeLine("250 OK")
					case strings.HasPrefix(upper, "RCPT TO:"):
						writeLine("250 OK")
					case upper == "DATA":
						inData = true
						writeLine("354 Start mail input")
					case upper == "QUIT":
						writeLine("221 Bye")
						return
					default:
						writeLine("250 OK")
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), got
}

func TestSendSMTP_CRLFInjectionSSRFAndBoundedClient(t *testing.T) {
	smtpAddr, received := startMockSMTPServer(t)

	t.Run("rejects CRLF header injection in from, to, and subject", func(t *testing.T) {
		t.Setenv("SMTP_ALLOW_PRIVATE", "1")
		cases := []struct {
			name    string
			to      []string
			subject string
			from    string
		}{
			{"crlf in subject", []string{"sec@example.com"}, "Alert\r\nBcc: evil@attacker.tld", "bot@example.com"},
			{"lf in subject", []string{"sec@example.com"}, "Alert\nX-Injected: 1", "bot@example.com"},
			{"crlf in to", []string{"sec@example.com\r\nBcc: evil@attacker.tld"}, "Alert", "bot@example.com"},
			{"crlf in from", []string{"sec@example.com"}, "Alert", "bot@example.com\r\nBcc: evil@attacker.tld"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := sendSMTP(t.Context(), tc.to, tc.subject, "", "body", smtpAddr, "", tc.from)
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
			})
		}
	})

	t.Run("blocks private addrOverride unless SMTP_ALLOW_PRIVATE=1 or server SMTP_ADDR", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		t.Setenv("SMTP_ALLOW_PRIVATE", "")
		t.Setenv("SMTP_ADDR", "")

		err := sendSMTP(t.Context(), []string{"sec@example.com"}, "Scan alert", "", "hello", smtpAddr, "", "secflow@example.com")
		if !errors.Is(err, urlguard.ErrAllowlistDenied) {
			t.Fatalf("expected ErrAllowlistDenied for private addrOverride, got %v", err)
		}
	})

	t.Run("allows server-configured SMTP_ADDR and delivers via bounded smtp.NewClient", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		t.Setenv("SMTP_ALLOW_PRIVATE", "")
		t.Setenv("SMTP_ADDR", smtpAddr)

		if err := sendSMTP(t.Context(), []string{"sec@example.com"}, "SecFlow Gate Alert", "", "CRITICAL found", "", "", "secflow@example.com"); err != nil {
			t.Fatalf("sendSMTP via server SMTP_ADDR failed: %v", err)
		}
		msg := <-received
		for _, want := range []string{"From: secflow@example.com", "To: sec@example.com", "Subject: SecFlow Gate Alert", "CRITICAL found"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("SMTP message missing %q:\n%s", want, msg)
			}
		}
	})

	t.Run("resolves DNS once and dials validated IP literal to prevent DNS rebinding", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		t.Setenv("SMTP_ALLOW_PRIVATE", "")
		t.Setenv("NOTIFY_ALLOW_PRIVATE", "")
		t.Setenv("SMTP_ADDR", "")

		origLookup := smtpLookupIPAddr
		origDial := smtpDialContext
		t.Cleanup(func() {
			smtpLookupIPAddr = origLookup
			smtpDialContext = origDial
		})

		// Mixed public + private DNS answer must fail closed without dialing.
		var dialCalls atomic.Int32
		smtpLookupIPAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("93.184.216.34")},
				{IP: net.ParseIP("127.0.0.1")},
			}, nil
		}
		smtpDialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("should not dial")
		}
		err := sendSMTP(t.Context(), []string{"sec@example.com"}, "Alert", "", "body", "rebind.example.com:2525", "", "bot@example.com")
		if !errors.Is(err, urlguard.ErrAllowlistDenied) {
			t.Fatalf("expected ErrAllowlistDenied for mixed private DNS answer, got %v", err)
		}
		if dialCalls.Load() != 0 {
			t.Fatalf("expected 0 dial calls on rejected DNS answer, got %d", dialCalls.Load())
		}

		// Public-only DNS answer: lookup called once, dialer receives validated IP literal (not hostname).
		var lookupCalls atomic.Int32
		var dialedAddr string
		smtpLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			lookupCalls.Add(1)
			if host != "mail.example.com" {
				t.Errorf("unexpected lookup host %q", host)
			}
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}
		smtpDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialedAddr = addr
			// Redirect to mock SMTP server so the SMTP protocol flow completes cleanly.
			return (&net.Dialer{}).DialContext(ctx, network, smtpAddr)
		}
		if err := sendSMTP(t.Context(), []string{"sec@example.com"}, "Pinned IP Alert", "", "body", "mail.example.com:2525", "", "bot@example.com"); err != nil {
			t.Fatalf("sendSMTP with pinned public IP failed: %v", err)
		}
		if lookupCalls.Load() != 1 {
			t.Fatalf("expected exactly 1 DNS lookup, got %d", lookupCalls.Load())
		}
		if dialedAddr != "93.184.216.34:2525" {
			t.Fatalf("dialed %q, want validated IP literal 93.184.216.34:2525", dialedAddr)
		}
		<-received
	})
}

func TestSendCommitStatus_SchemeHostAllowlistAndFailClosedSecret(t *testing.T) {
	srv := notify{}

	t.Run("rejects insecure http scheme and non-allowlisted hosts", func(t *testing.T) {
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		t.Setenv("NOTIFY_ALLOW_INSECURE_COMMIT_STATUS", "")
		t.Setenv("REPO_ALLOWLIST", "github.com/TBagirov/training")
		t.Setenv("COMMIT_STATUS_ALLOWLIST", "")

		rejected := []string{
			"http://api.github.com/repos/TBagirov/training/statuses/abc",
			"https://evil.attacker.example/repos/org/app/statuses/abc",
			"ftp://api.github.com/repos/org/app/statuses/abc",
		}
		for _, target := range rejected {
			resp, err := srv.SendCommitStatus(t.Context(), &secflowv1.SendCommitStatusRequest{
				RunId:           "run_reject",
				CommitStatusUrl: target,
				State:           secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS,
			})
			if err != nil {
				t.Fatalf("target=%q unexpected rpc err: %v", target, err)
			}
			if resp.GetDelivered() || resp.GetErrorMessage() != "ALLOWLIST_DENIED" {
				t.Fatalf("target=%q got %+v, want Delivered=false ALLOWLIST_DENIED", target, resp)
			}
		}

		// Even with MCP_ALLOW_PRIVATE=1, arbitrary external non-allowlisted host is still rejected.
		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		resp, err := srv.SendCommitStatus(t.Context(), &secflowv1.SendCommitStatusRequest{
			RunId:           "run_reject_ext",
			CommitStatusUrl: "https://evil.attacker.example/repos/org/app/statuses/abc",
			State:           secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS,
		})
		if err != nil || resp.GetDelivered() || resp.GetErrorMessage() != "ALLOWLIST_DENIED" {
			t.Fatalf("arbitrary external host with MCP_ALLOW_PRIVATE=1: got (%+v, %v), want ALLOWLIST_DENIED", resp, err)
		}

		// Allowlisted hosts via REPO_ALLOWLIST and COMMIT_STATUS_ALLOWLIST pass host check.
		t.Setenv("MCP_ALLOW_PRIVATE", "")
		t.Setenv("REPO_ALLOWLIST", "git.edu.example/team/*")
		t.Setenv("COMMIT_STATUS_ALLOWLIST", "status-api.corp.example")
		for _, host := range []string{"api.github.com", "gitlab.com", "git.edu.example", "api.git.edu.example", "status-api.corp.example"} {
			if !commitStatusHostAllowed(host) {
				t.Fatalf("expected host %q to be allowlisted", host)
			}
		}
		if commitStatusHostAllowed("evil.example") {
			t.Fatal("expected evil.example to be rejected")
		}
	})

	t.Run("fails closed without sending HTTP request when secret resolution fails or returns empty", func(t *testing.T) {
		var hits atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusCreated)
		}))
		defer ts.Close()

		t.Setenv("MCP_ALLOW_PRIVATE", "1")
		origResolve := resolveCommitSecretFn
		t.Cleanup(func() { resolveCommitSecretFn = origResolve })

		for _, tc := range []struct {
			name string
			tok  string
			err  error
		}{
			{"resolver returns error", "", errors.New("permission denied")},
			{"resolver returns empty token", "   ", nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				hits.Store(0)
				resolveCommitSecretFn = func(_ context.Context, _, _ string, _ *secflowv1.SendCommitStatusRequest, _ string) (string, error) {
					return tc.tok, tc.err
				}
				resp, err := srv.SendCommitStatus(t.Context(), &secflowv1.SendCommitStatusRequest{
					RunId:              "run_sec_fail",
					GitProvider:        secflowv1.GitProvider_GIT_PROVIDER_GITHUB,
					CommitStatusUrl:    ts.URL + "/repos/org/app/statuses/abc",
					GitStatusSecretRef: "sec_git_token",
					State:              secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS,
				})
				if err != nil {
					t.Fatalf("unexpected rpc err: %v", err)
				}
				if resp.GetDelivered() || resp.GetErrorMessage() == "" {
					t.Fatalf("expected Delivered=false with explicit error, got %+v", resp)
				}
				if hits.Load() != 0 {
					t.Fatalf("expected 0 HTTP requests on secret failure, got %d", hits.Load())
				}
			})
		}
	})
}

func TestNotifyManifests_RichMetadataAndSecretKeys(t *testing.T) {
	manifests := notifyManifests()
	if len(manifests) != 3 {
		t.Fatalf("manifest count = %d, want 3", len(manifests))
	}
	byID := make(map[string]*secflowv1.PluginManifest, len(manifests))
	for _, m := range manifests {
		byID[m.GetPluginId()] = m
		if strings.TrimSpace(m.GetDescription()) == "" {
			t.Errorf("manifest %s missing Description", m.GetPluginId())
		}
		if m.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
			t.Errorf("manifest %s SandboxProfile = %v, want EGRESS_EXTERNAL", m.GetPluginId(), m.GetSandboxProfile())
		}
		if m.GetCategory() != secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION {
			t.Errorf("manifest %s Category = %v, want ACTION", m.GetPluginId(), m.GetCategory())
		}
		if !slices.Contains(m.GetCapabilities(), "notify") {
			t.Errorf("manifest %s missing notify capability: %v", m.GetPluginId(), m.GetCapabilities())
		}
	}
	if !slices.Equal(byID["notify.telegram"].GetRequiredSecretKeys(), []string{"botToken"}) {
		t.Errorf("notify.telegram RequiredSecretKeys = %v, want [botToken]", byID["notify.telegram"].GetRequiredSecretKeys())
	}
	if !slices.Equal(byID["notify.smtp"].GetRequiredSecretKeys(), []string{"smtpPassword"}) {
		t.Errorf("notify.smtp RequiredSecretKeys = %v, want [smtpPassword]", byID["notify.smtp"].GetRequiredSecretKeys())
	}
	if len(byID["notify.webhook"].GetRequiredSecretKeys()) != 0 {
		t.Errorf("notify.webhook RequiredSecretKeys = %v, want empty (optional)", byID["notify.webhook"].GetRequiredSecretKeys())
	}
}
