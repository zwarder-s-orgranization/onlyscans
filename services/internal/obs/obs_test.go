package obs

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TestInitGeneratesValidTraceAndSpanIDsWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	shutdown, err := Init(t.Context(), "obs-test-svc")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Shutdown(shutdown)

	ctx, span := StartTaskSpan(t.Context(), "", "test.root")
	defer span.End()

	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Fatalf("expected valid span context without OTLP endpoint")
	}
	tp := InjectTraceparent(ctx)
	if !strings.HasPrefix(tp, "00-"+sc.TraceID().String()+"-"+sc.SpanID().String()+"-") {
		t.Fatalf("InjectTraceparent() = %q, want trace %s span %s", tp, sc.TraceID(), sc.SpanID())
	}
}

func TestHTTPMiddlewareExtractsAndInjectsTraceparentAndLogs(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Init(t.Context(), "edge-gateway")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Shutdown(shutdown)

	var logBuf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(NewHandler(&logBuf, "edge-gateway")))
	defer slog.SetDefault(prevLogger)

	const incomingTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const incomingParentSpanID = "00f067aa0ba902b7"
	incomingTP := "00-" + incomingTraceID + "-" + incomingParentSpanID + "-01"

	var handlerTraceID, handlerSpanID string
	h := HTTPMiddleware("edge-gateway", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc := trace.SpanContextFromContext(r.Context())
		handlerTraceID = sc.TraceID().String()
		handlerSpanID = sc.SpanID().String()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodPost, "/runs/run_123/submission.json", nil)
	req.Header.Set("traceparent", incomingTP)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if handlerTraceID != incomingTraceID {
		t.Fatalf("handler trace_id = %q, want %q", handlerTraceID, incomingTraceID)
	}
	if handlerSpanID == "" || handlerSpanID == incomingParentSpanID {
		t.Fatalf("expected new child span_id, got %q", handlerSpanID)
	}
	respTP := rec.Header().Get("Traceparent")
	if !strings.Contains(respTP, incomingTraceID) {
		t.Fatalf("response Traceparent = %q, want trace_id %s", respTP, incomingTraceID)
	}

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &entry); err != nil {
		t.Fatalf("unmarshal log JSON (%q): %v", logBuf.String(), err)
	}
	if entry["service"] != "edge-gateway" {
		t.Fatalf("log service = %v, want edge-gateway", entry["service"])
	}
	if entry["trace_id"] != incomingTraceID {
		t.Fatalf("log trace_id = %v, want %s", entry["trace_id"], incomingTraceID)
	}
	if entry["span_id"] != handlerSpanID {
		t.Fatalf("log span_id = %v, want %s", entry["span_id"], handlerSpanID)
	}
	if entry["method"] != http.MethodPost || entry["path"] != "/runs/:id/submission.json" {
		t.Fatalf("unexpected log method/path: %v %v", entry["method"], entry["path"])
	}
	if statusVal, ok := entry["status"].(float64); !ok || int(statusVal) != http.StatusCreated {
		t.Fatalf("log status = %v, want %d", entry["status"], http.StatusCreated)
	}
	if _, ok := entry["duration_ms"]; !ok {
		t.Fatalf("expected duration_ms in log entry: %v", entry)
	}
}

func TestSlogHandlerCorrelatesTraceAndRedactsSecrets(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Init(t.Context(), "orchestrator")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Shutdown(shutdown)

	tests := []struct {
		name      string
		key       string
		value     any
		wantValue string
	}{
		{name: "key token", key: "token", value: "plain-value", wantValue: redactedValue},
		{name: "key secret", key: "jwt_secret", value: "plain-value", wantValue: redactedValue},
		{name: "key password", key: "smtp_password", value: "hunter2", wantValue: redactedValue},
		{name: "key authorization", key: "Authorization", value: "Basic abc", wantValue: redactedValue},
		{name: "key apikey", key: "apikey", value: "abc123", wantValue: redactedValue},
		{name: "key api_key", key: "api_key", value: "abc123", wantValue: redactedValue},
		{name: "key private_token", key: "private_token", value: "abc123", wantValue: redactedValue},
		{name: "key cookie", key: "cookie", value: "sid=xyz", wantValue: redactedValue},
		{name: "key credential", key: "credential", value: "abc", wantValue: redactedValue},
		{name: "value Bearer", key: "header", value: "Bearer topsecretjwt", wantValue: redactedValue},
		{name: "value sf_ci", key: "note", value: "using sf_ci_1234567890abcdef", wantValue: redactedValue},
		{name: "value sf_mcp", key: "note", value: "sf_mcp_abcdef123456", wantValue: redactedValue},
		{name: "value sk-", key: "note", value: "sk-proj-secretkey123", wantValue: redactedValue},
		{name: "value ghp_", key: "note", value: "ghp_1234567890abcdef", wantValue: redactedValue},
		{name: "value glpat-", key: "note", value: "glpat-abcdef123456", wantValue: redactedValue},
		{name: "value private key", key: "pem", value: "-----BEGIN PRIVATE KEY-----\nMIIE...", wantValue: redactedValue},
		{name: "error containing secret", key: "err", value: errors.New("upstream failed with Bearer supersecret"), wantValue: redactedValue},
		{name: "safe value with sk- inside word", key: "task_name", value: "repair-desk-1", wantValue: "repair-desk-1"},
		{name: "safe run_id", key: "run_id", value: "run_abc123", wantValue: "run_abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(NewHandler(&buf, "orchestrator"))

			ctx, span := StartTaskSpan(t.Context(), "", "test.log")
			defer span.End()

			logger.InfoContext(ctx, "audit check", tt.key, tt.value, "tokens_in", 42)

			var entry map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
				t.Fatalf("unmarshal log JSON: %v", err)
			}
			if entry["service"] != "orchestrator" {
				t.Fatalf("service = %v, want orchestrator", entry["service"])
			}
			if entry["trace_id"] != trace.SpanContextFromContext(ctx).TraceID().String() {
				t.Fatalf("trace_id mismatch: got %v", entry["trace_id"])
			}
			if entry["span_id"] != trace.SpanContextFromContext(ctx).SpanID().String() {
				t.Fatalf("span_id mismatch: got %v", entry["span_id"])
			}
			if got, ok := entry[tt.key].(string); !ok || got != tt.wantValue {
				t.Fatalf("entry[%q] = %#v, want %q", tt.key, entry[tt.key], tt.wantValue)
			}
			if tokensIn, ok := entry["tokens_in"].(float64); !ok || int(tokensIn) != 42 {
				t.Fatalf("tokens_in = %v, want 42", entry["tokens_in"])
			}
		})
	}
}

func TestSlogHandlerRedactsWithAttrsAndGroups(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewHandler(&buf, "worker-sca")).
		With("api_key", "super-secret").
		WithGroup("meta")

	logger.InfoContext(t.Context(), "checking group", slog.String("raw", "ghp_secret123456"), slog.String("ok", "visible"))

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("unmarshal log JSON: %v", err)
	}
	if entry["api_key"] != redactedValue {
		t.Fatalf("WithAttrs api_key = %v, want %q", entry["api_key"], redactedValue)
	}
	meta, ok := entry["meta"].(map[string]any)
	if !ok {
		t.Fatalf("expected meta group object, got %#v", entry["meta"])
	}
	if meta["raw"] != redactedValue {
		t.Fatalf("group raw = %v, want %q", meta["raw"], redactedValue)
	}
	if meta["ok"] != "visible" {
		t.Fatalf("group ok = %v, want visible", meta["ok"])
	}
}

func TestStartTaskSpanLinksParentAndChildTrace(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Init(t.Context(), "worker-kotlin")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Shutdown(shutdown)

	parentCtx, parentSpan := StartTaskSpan(t.Context(), "", "orchestrator.dispatch", attribute.String("secflow.run_id", "run_1"))
	parentSC := trace.SpanContextFromContext(parentCtx)
	tp := InjectTraceparent(parentCtx)
	parentSpan.End()

	if tp == "" {
		t.Fatal("expected non-empty traceparent from parent span")
	}

	childCtx, childSpan := StartTaskSpan(t.Context(), tp, "plugin.scan.sast.kotlin", attribute.String("secflow.node_id", "n1"))
	childSC := trace.SpanContextFromContext(childCtx)
	childSpan.End()

	if !childSC.IsValid() {
		t.Fatal("expected valid child span context")
	}
	if childSC.TraceID() != parentSC.TraceID() {
		t.Fatalf("child trace_id = %s, want parent trace_id %s", childSC.TraceID(), parentSC.TraceID())
	}
	if childSC.SpanID() == parentSC.SpanID() {
		t.Fatalf("child span_id %s must differ from parent span_id", childSC.SpanID())
	}
}

func TestNormalizeHTTPPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/healthz", "/healthz"},
		{"/readyz", "/readyz"},
		{"/metrics", "/metrics"},
		{"/graphql", "/graphql"},
		{"/mcp", "/mcp"},
		{"/upload", "/upload"},
		{"/sources/upload", "/sources/upload"},
		{"/catalogs/upload", "/catalogs/upload"},
		{"/webhooks/git/wf_12345", "/webhooks/git/:id"},
		{"/webhooks/inspector/demo-chan-1", "/webhooks/inspector/:key"},
		{"/runs/run_42", "/runs/:id"},
		{"/runs/run_42/submission.json", "/runs/:id/submission.json"},
		{"/runs/run_42/sbom.cdx.json", "/runs/:id/sbom.cdx.json"},
		{"/runs/run_42/report.md", "/runs/:id/report.md"},
		{"/runs/run_42/report.html", "/runs/:id/report.html"},
		{"/runs/run_42/custom-artifact.txt", "/runs/:id/:artifact"},
		{"/runs/run_42/nested/unknown/path", "/runs/:id/:artifact"},
		{"/wp-login.php", "/unknown"},
		{"/random/unbounded/123456789", "/unknown"},
		{"", "/unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeHTTPPath(tt.in); got != tt.want {
				t.Fatalf("normalizeHTTPPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
