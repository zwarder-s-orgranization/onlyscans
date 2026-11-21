// Package obs provides OpenTelemetry tracing, correlated structured logging with secret redaction,
// HTTP/gRPC instrumentation, and Prometheus metrics for SecFlow Go services.
package obs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

const redactedValue = "[REDACTED]"

var (
	w3cPropagator = propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	secretKeyFragments = []string{
		"token",
		"secret",
		"password",
		"authorization",
		"apikey",
		"api_key",
		"private_token",
		"cookie",
		"credential",
	}

	secretValueRe = regexp.MustCompile(
		`(?i)(bearer\s+\S+|sf_ci_[a-z0-9_\-]+|sf_mcp_[a-z0-9_\-]+|(?:^|[\s"'=:,;({\[]+)sk-[a-z0-9_\-]{3,}|ghp_[a-z0-9_]+|glpat-[a-z0-9_\-]+|BEGIN [A-Z ]*PRIVATE KEY)`,
	)

	// PromQL: sum by (service, method, path, status) (rate(secflow_http_requests_total[5m])).
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secflow_http_requests_total",
			Help: "Total number of HTTP requests handled by SecFlow services.",
		},
		[]string{"service", "method", "path", "status"},
	)

	// PromQL: histogram_quantile(0.95, sum by (le, service, path) (rate(secflow_http_request_duration_seconds_bucket[5m]))).
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "secflow_http_request_duration_seconds",
			Help:    "HTTP request latency distribution in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"service", "method", "path"},
	)

	// PromQL: sum by (service, method, code) (rate(rpc_server_requests_total[5m])).
	rpcServerRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rpc_server_requests_total",
			Help: "Total number of gRPC server RPCs handled by SecFlow services.",
		},
		[]string{"service", "method", "code"},
	)

	// PromQL: histogram_quantile(0.95, sum by (le, service, method) (rate(rpc_server_duration_seconds_bucket[5m]))).
	rpcServerDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rpc_server_duration_seconds",
			Help:    "gRPC server RPC latency distribution in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"service", "method"},
	)
)

func init() {
	otel.SetTextMapPropagator(w3cPropagator)
	prometheus.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		rpcServerRequestsTotal,
		rpcServerDuration,
	)
}

// Init configures the global OpenTelemetry TracerProvider and W3C propagators.
// When OTEL_EXPORTER_OTLP_ENDPOINT is unset, an SDK TracerProvider without an exporter is installed
// so valid trace_id/span_id values and traceparent headers are always generated.
func Init(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(w3cPropagator)

	res := resource.NewSchemaless(attribute.String("service.name", serviceName))
	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	}

	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	if endpoint != "" {
		expOpts := buildOTLPHTTPOptions(endpoint)
		exp, err := otlptracehttp.New(ctx, expOpts...)
		if err != nil {
			return nil, fmt.Errorf("create otlp http trace exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exp))
	}

	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

func buildOTLPHTTPOptions(endpoint string) []otlptracehttp.Option {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return []otlptracehttp.Option{otlptracehttp.WithEndpointURL(endpoint)}
	}
	return []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	}
}

// Shutdown invokes a TracerProvider shutdown callback with a bounded timeout.
func Shutdown(fn func(context.Context) error) {
	if fn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fn(ctx); err != nil {
		slog.Warn("telemetry shutdown", "err", err)
	}
}

// SetupLogger installs the default JSON slog logger with automatic service, trace_id, span_id
// correlation and secret redaction.
func SetupLogger(serviceName string) {
	slog.SetDefault(slog.New(NewHandler(os.Stdout, serviceName)))
}

// NewHandler constructs a JSON slog.Handler writing to w with automatic service, trace_id, span_id
// attributes and recursive secret redaction.
func NewHandler(w io.Writer, serviceName string) slog.Handler {
	var base slog.Handler = slog.NewJSONHandler(w, nil)
	if serviceName != "" {
		base = base.WithAttrs([]slog.Attr{slog.String("service", serviceName)})
	}
	return &redactingTraceHandler{next: base}
}

type redactingTraceHandler struct {
	next slog.Handler
}

func (h *redactingTraceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *redactingTraceHandler) Handle(ctx context.Context, r slog.Record) error {
	rec := slog.NewRecord(r.Time, r.Level, redactStringIfSecret(r.Message), r.PC)
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		rec.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, rec)
}

func (h *redactingTraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &redactingTraceHandler{next: h.next.WithAttrs(redacted)}
}

func (h *redactingTraceHandler) WithGroup(name string) slog.Handler {
	return &redactingTraceHandler{next: h.next.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		items := a.Value.Group()
		out := make([]slog.Attr, len(items))
		for i, item := range items {
			out[i] = redactAttr(item)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	}
	if isSecretKey(a.Key) {
		return slog.String(a.Key, redactedValue)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		if containsSecretValue(a.Value.String()) {
			return slog.String(a.Key, redactedValue)
		}
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok && err != nil {
			if containsSecretValue(err.Error()) {
				return slog.String(a.Key, redactedValue)
			}
		} else if a.Value.Any() != nil && containsSecretValue(fmt.Sprint(a.Value.Any())) {
			return slog.String(a.Key, redactedValue)
		}
	default:
	}
	return a
}

func isSecretKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" || k == "tokens_in" || k == "tokens_out" {
		return false
	}
	for _, frag := range secretKeyFragments {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return false
}

func containsSecretValue(val string) bool {
	if val == "" {
		return false
	}
	return secretValueRe.MatchString(val)
}

func redactStringIfSecret(msg string) string {
	if containsSecretValue(msg) {
		return redactedValue
	}
	return msg
}

// ExtractTraceparent parses a W3C traceparent header string into ctx.
func ExtractTraceparent(ctx context.Context, traceparent string) context.Context {
	tp := strings.TrimSpace(traceparent)
	if tp == "" {
		return ctx
	}
	return otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier{"traceparent": tp})
}

// InjectTraceparent serializes the active span context in ctx as a W3C traceparent string.
func InjectTraceparent(ctx context.Context) string {
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	return carrier["traceparent"]
}

// TraceIDFromContext returns the active hex trace_id from ctx, or empty when none is valid.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// StartTaskSpan extracts a W3C traceparent (if present) and starts a child span for a workflow or worker task.
// Callers must always defer span.End().
func StartTaskSpan(ctx context.Context, traceparent, spanName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if tp := strings.TrimSpace(traceparent); tp != "" {
		ctx = ExtractTraceparent(ctx, tp)
	}
	return otel.Tracer("secflow.task").Start(
		ctx,
		spanName,
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(attrs...),
	)
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if sr.wroteHeader {
		return
	}
	sr.status = code
	sr.wroteHeader = true
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(p []byte) (int, error) {
	if !sr.wroteHeader {
		sr.WriteHeader(http.StatusOK)
	}
	return sr.ResponseWriter.Write(p)
}

func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := sr.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return h.Hijack()
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

// HTTPMiddleware extracts W3C traceparent, starts a server span, echoes traceparent on the response,
// records Prometheus HTTP metrics, and logs structured request completion with trace correlation.
func HTTPMiddleware(serviceName string, next http.Handler) http.Handler {
	tracer := otel.Tracer(serviceName)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		normPath := normalizeHTTPPath(r.URL.Path)

		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.Start(
			ctx,
			r.Method+" "+normPath,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", normPath),
			),
		)
		defer span.End()

		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(w.Header()))

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))

		dur := time.Since(start)
		code := rec.status
		span.SetAttributes(attribute.Int("http.response.status_code", code))
		if code >= http.StatusInternalServerError {
			span.SetStatus(otelcodes.Error, http.StatusText(code))
		}

		httpRequestsTotal.WithLabelValues(serviceName, r.Method, normPath, strconv.Itoa(code)).Inc()
		observeWithExemplar(httpRequestDuration.WithLabelValues(serviceName, r.Method, normPath), dur.Seconds(), ctx)

		slog.InfoContext(ctx, "http request",
			"method", r.Method,
			"path", normPath,
			"status", code,
			"duration_ms", dur.Milliseconds(),
		)
	})
}

func normalizeHTTPPath(p string) string {
	switch p {
	case "/healthz", "/readyz", "/metrics", "/graphql", "/mcp", "/upload", "/sources/upload", "/catalogs/upload":
		return p
	}
	switch {
	case strings.HasPrefix(p, "/webhooks/git/"):
		return "/webhooks/git/:id"
	case strings.HasPrefix(p, "/webhooks/inspector/"):
		return "/webhooks/inspector/:key"
	case strings.HasPrefix(p, "/runs/"):
		rest := strings.TrimPrefix(p, "/runs/")
		idx := strings.IndexByte(rest, '/')
		if idx < 0 {
			return "/runs/:id"
		}
		switch rest[idx+1:] {
		case "submission.json":
			return "/runs/:id/submission.json"
		case "sbom.cdx.json":
			return "/runs/:id/sbom.cdx.json"
		case "report.md":
			return "/runs/:id/report.md"
		case "report.html":
			return "/runs/:id/report.html"
		default:
			return "/runs/:id/:artifact"
		}
	default:
		return "/unknown"
	}
}

func observeWithExemplar(obs prometheus.Observer, value float64, ctx context.Context) {
	if tid := TraceIDFromContext(ctx); tid != "" {
		if eo, ok := obs.(prometheus.ExemplarObserver); ok {
			eo.ObserveWithExemplar(value, prometheus.Labels{"trace_id": tid})
			return
		}
	}
	obs.Observe(value)
}

// GRPCServerOptions returns gRPC ServerOptions that enable W3C trace propagation on unary and
// streaming RPCs via otelgrpc plus Prometheus RED metrics interceptors.
func GRPCServerOptions(serviceName string) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(UnaryServerInterceptor(serviceName)),
		grpc.ChainStreamInterceptor(StreamServerInterceptor(serviceName)),
	}
}

// GRPCDialOption returns a gRPC DialOption that propagates W3C traceparent on unary and streaming RPCs.
func GRPCDialOption() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}

// UnaryServerInterceptor records Prometheus RED metrics for unary gRPC server calls.
func UnaryServerInterceptor(serviceName string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		dur := time.Since(start).Seconds()
		code := status.Code(err).String()
		rpcServerRequestsTotal.WithLabelValues(serviceName, info.FullMethod, code).Inc()
		observeWithExemplar(rpcServerDuration.WithLabelValues(serviceName, info.FullMethod), dur, ctx)
		return resp, err
	}
}

// StreamServerInterceptor records Prometheus RED metrics for streaming gRPC server calls.
func StreamServerInterceptor(serviceName string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		dur := time.Since(start).Seconds()
		code := status.Code(err).String()
		rpcServerRequestsTotal.WithLabelValues(serviceName, info.FullMethod, code).Inc()
		observeWithExemplar(rpcServerDuration.WithLabelValues(serviceName, info.FullMethod), dur, ss.Context())
		return err
	}
}
