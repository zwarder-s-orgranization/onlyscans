package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/vektah/gqlparser/v2/ast"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/oidc"
)

func effectiveGatewayEnv() string {
	if v := strings.TrimSpace(os.Getenv("SECFLOW_ENV")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("ENV"))
}

func validateGatewayConfig(secflowEnv, authMode, jwtSecret, serviceToken string, corsAllowOrigins ...string) error {
	if !strings.EqualFold(strings.TrimSpace(secflowEnv), "production") {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(authMode), "oidc") && strings.TrimSpace(jwtSecret) == "" {
		return errors.New("JWT_SECRET is required when SECFLOW_ENV=production and AUTH_MODE!=oidc")
	}
	if strings.TrimSpace(serviceToken) == "" {
		return errors.New("SERVICE_TOKEN is required when SECFLOW_ENV=production")
	}
	if len(corsAllowOrigins) > 0 {
		if err := validateCORSAllowOrigins(corsAllowOrigins[0]); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	obs.SetupLogger("edge-gateway")
	if err := validateGatewayConfig(
		effectiveGatewayEnv(),
		os.Getenv("AUTH_MODE"),
		os.Getenv("JWT_SECRET"),
		os.Getenv("SERVICE_TOKEN"),
		os.Getenv("CORS_ALLOW_ORIGINS"),
	); err != nil {
		slog.Error("invalid gateway configuration", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "edge-gateway")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}
	if err := blobstore.Ensure(ctx); err != nil {
		slog.Warn("garage", "err", err)
	}
	schema, err := loadSchema()
	if err != nil {
		slog.Error("schema", "err", err)
		os.Exit(1)
	}
	var pool *pgxpool.Pool
	if dsn := strings.TrimSpace(os.Getenv("DATABASE_URL")); dsn != "" {
		p, err := pgxpool.New(ctx, dsn)
		if err != nil {
			slog.Error("open users database", "err", err)
			if strings.EqualFold(effectiveGatewayEnv(), "production") {
				os.Exit(1)
			}
		} else {
			pool = p
			defer pool.Close()
			if isLocalAuthMode() {
				if seedErr := ensureLocalUsersTable(ctx, pool); seedErr != nil {
					slog.Warn("ensure local users table", "err", seedErr)
				}
			}
		}
	}
	rdb := newRedisClient(os.Getenv("REDIS_ADDR"))
	if rdb != nil {
		defer rdb.Close()
	}
	orch := dial(envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"))
	defer orch.Close()
	ingest := dial(envutil.Get("INGESTER_ADDR", "source-ingester:50052"))
	defer ingest.Close()
	aiConn := dial(envutil.Get("AI_ADDR", "ai-service:50053"))
	defer aiConn.Close()
	notifyConn := dial(envutil.Get("NOTIFY_ADDR", "notify-service:50054"))
	defer notifyConn.Close()
	gw := &gateway{
		schema:       schema,
		secret:       []byte(envutil.Get("JWT_SECRET", "dev-jwt-secret-change-me")),
		serviceToken: envutil.Get("SERVICE_TOKEN", "dev-service-token"),
		pool:         pool,
		rdb:          rdb,
		insp:         map[string][]inspectorEntry{},
		inspUpdated:  map[string]time.Time{},
		subs:         map[string][]chan map[string]any{},
		wf:           secflowv1.NewWorkflowServiceClient(orch),
		runs:         secflowv1.NewRunServiceClient(orch),
		plugs:        secflowv1.NewPluginRegistryServiceClient(orch),
		secs:         secflowv1.NewSecretServiceClient(orch),
		cats:         secflowv1.NewCatalogServiceClient(orch),
		mcp:          secflowv1.NewMCPRegistryServiceClient(orch),
		ingest:       secflowv1.NewSourceIngesterServiceClient(ingest),
		ai:           secflowv1.NewAIServiceClient(aiConn),
		notify:       secflowv1.NewNotifyServiceClient(notifyConn),
	}
	if metricsAddr := strings.TrimSpace(os.Getenv("METRICS_ADDR")); metricsAddr != "" {
		httpserver.Start(ctx, metricsAddr)
	}
	addr := envutil.Get("HTTP_ADDR", ":8080")
	slog.Info("edge-gateway", "addr", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           gw.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			slog.Warn("http shutdown", "err", err)
		}
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("http", "err", err)
		os.Exit(1)
	}
}

type gateway struct {
	schema         *ast.Schema
	secret         []byte
	serviceToken   string
	pool           *pgxpool.Pool
	rdb            *redis.Client
	pgPing         func(ctx context.Context) error
	garageCheck    func(ctx context.Context) error
	userLookup     func(ctx context.Context, email string) (passwordHash, role string, found bool, err error)
	rateLimitCheck func(ctx context.Context, subject string) bool
	gqlOnce        sync.Once
	gqlSrv         *handler.Server
	mu             sync.Mutex
	insp           map[string][]inspectorEntry
	inspUpdated    map[string]time.Time
	inspTTL        time.Duration
	subs           map[string][]chan map[string]any
	aiCfg          *aiProviderConfigDTO
	wf             secflowv1.WorkflowServiceClient
	runs           secflowv1.RunServiceClient
	plugs          secflowv1.PluginRegistryServiceClient
	secs           secflowv1.SecretServiceClient
	cats           secflowv1.CatalogServiceClient
	mcp            secflowv1.MCPRegistryServiceClient
	ingest         secflowv1.SourceIngesterServiceClient
	ai             secflowv1.AIServiceClient
	notify         secflowv1.NotifyServiceClient
	jwks           []oidc.Key
	jwksAt         time.Time
}

func (g *gateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.healthz)
	mux.HandleFunc("/readyz", g.readyz)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/graphql", g.graphql)
	mux.HandleFunc("/upload", g.upload)
	mux.HandleFunc("/catalogs/upload", g.catalogUpload)
	mux.HandleFunc("/mcp", g.mcpServerHTTP)
	mux.HandleFunc("/webhooks/git/", g.webhook)
	mux.HandleFunc("/webhooks/inspector/", g.inspector)
	mux.HandleFunc("/runs/", g.runFile)
	mux.HandleFunc("/api/ai/provider", g.aiProviderConfig)
	mux.HandleFunc("/api/ai/provider/test", g.aiProviderTest)
	mux.HandleFunc("/api/ai/models", g.aiProviderModels)
	return obs.HTTPMiddleware("edge-gateway", withCORS(mux))
}

func traceparentUnaryInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if obs.TraceIDFromContext(ctx) == "" {
			if tp, ok := ctx.Value(traceKey{}).(string); ok && tp != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, "traceparent", tp)
			}
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func dial(addr string) *grpc.ClientConn {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		obs.GRPCDialOption(),
		grpc.WithUnaryInterceptor(traceparentUnaryInterceptor()),
	)
	if err != nil {
		slog.Error("dial", "addr", addr, "err", err)
		os.Exit(1)
	}
	return conn
}

type traceKey struct{}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
