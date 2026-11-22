package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/obs"
)

func main() {
	obs.SetupLogger("orchestrator")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "orchestrator")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}
	if err := blobstore.Ensure(ctx); err != nil {
		slog.Warn("blobstore ensure", "err", err)
	}
	var pool *pgxpool.Pool
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		if err := migrate(ctx, dsn); err != nil {
			slog.Error("migrate", "err", err)
			os.Exit(1)
		}
		var err error
		pool, err = pgxpool.New(ctx, dsn)
		if err != nil {
			slog.Error("postgres", "err", err)
			os.Exit(1)
		}
		defer pool.Close()
	}
	addr := envutil.Get("GRPC_ADDR", ":50051")
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
	srv := newServer()
	srv.pool = pool
	scaler, scalerInterval, err := buildWorkerScaler()
	if err != nil {
		slog.Error("worker scaler init", "err", err)
		os.Exit(1)
	}
	srv.workerScaler = scaler
	slog.Info("worker scaler configured", "driver", scaler.Driver())
	if ingAddr := os.Getenv("INGESTER_ADDR"); ingAddr != "" {
		conn, err := grpc.NewClient(ingAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
		if err != nil {
			slog.Error("ingester", "err", err)
			os.Exit(1)
		}
		defer conn.Close()
		srv.ingest = secflowv1.NewSourceIngesterServiceClient(conn)
	}
	srv.loadState(ctx)
	srv.startPluginListener(ctx)
	srv.startWorkerScaler(ctx, scalerInterval)
	srv.startPump(ctx)
	srv.startScheduler(ctx)
	gs := grpc.NewServer(obs.GRPCServerOptions("orchestrator")...)
	secflowv1.RegisterWorkflowServiceServer(gs, srv)
	secflowv1.RegisterRunServiceServer(gs, srv)
	secflowv1.RegisterPluginRegistryServiceServer(gs, srv)
	secflowv1.RegisterSecretServiceServer(gs, srv)
	secflowv1.RegisterCatalogServiceServer(gs, srv)
	secflowv1.RegisterMCPRegistryServiceServer(gs, srv)
	secflowv1.RegisterWorkerServiceServer(gs, srv)
	httpserver.Start(ctx, envutil.Get("HTTP_ADDR", ":8081"))
	go func() {
		slog.Info("orchestrator listening", "grpc", addr)
		if err := gs.Serve(lis); err != nil {
			slog.Error("grpc", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	gs.GracefulStop()
}

func migrate(ctx context.Context, dsn string) error {
	var last error
	for range 30 {
		last = migrateOnce(ctx, dsn)
		if last == nil {
			return nil
		}
		slog.Warn("migrate retry", "err", last)
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

type migrationFile struct {
	version string
	sql     string
}

func loadMigrationFiles() ([]migrationFile, error) {
	dirs := []string{"migrations", "/migrations"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
				names = append(names, e.Name())
			}
		}
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		out := make([]migrationFile, 0, len(names))
		for _, name := range names {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return nil, fmt.Errorf("read migration %s: %w", name, err)
			}
			version := strings.TrimSuffix(name, ".sql")
			out = append(out, migrationFile{version: version, sql: stripGoose(string(raw))})
		}
		return out, nil
	}
	return nil, fmt.Errorf("migrations directory not found")
}

func migrateOnce(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect postgres for migration: %w", err)
	}
	defer pool.Close()

	files, err := loadMigrationFiles()
	if err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	for _, mf := range files {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration tx %s: %w", mf.version, err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7326017)`); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("lock migration %s: %w", mf.version, err)
		}
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, mf.version).Scan(&applied); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("check migration %s: %w", mf.version, err)
		}
		if applied {
			_ = tx.Rollback(ctx)
			continue
		}
		if _, err := tx.Exec(ctx, mf.sql); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", mf.version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, mf.version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", mf.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", mf.version, err)
		}
	}
	return nil
}

func stripGoose(sql string) string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "-- +goose Down" {
			break
		}
		if strings.HasPrefix(trimmed, "-- +goose") {
			continue
		}
		b.WriteString(strings.TrimRight(line, "\r"))
		b.WriteByte('\n')
	}
	return b.String()
}
