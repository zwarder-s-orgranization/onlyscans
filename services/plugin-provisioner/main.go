package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/obs"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownObs, err := obs.Init(ctx, "plugin-provisioner")
	if err != nil {
		slog.Warn("obs init failed", "err", err)
	} else {
		defer func() {
			sCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdownObs(sCtx)
		}()
	}

	httpAddr := envutil.Get("HTTP_ADDR", ":8089")
	httpserver.Start(ctx, httpAddr)

	driver := strings.ToLower(envutil.Get("PROVISIONER_DRIVER", "noop"))
	prov, err := buildProvisioner(driver)
	if err != nil {
		slog.Error("init provisioner", "driver", driver, "err", err)
		os.Exit(1)
	}

	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		slog.Info("plugin-provisioner running in standby (DATABASE_URL not set)", "driver", prov.Driver())
		<-ctx.Done()
		return
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		slog.Error("connect postgres", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	resyncSec := envInt("PROVISIONER_RESYNC_SECONDS", 15)
	rec := NewReconciler(NewPGStore(pool), prov, time.Duration(resyncSec)*time.Second)
	slog.Info("plugin-provisioner started", "driver", prov.Driver(), "http_addr", httpAddr, "resync_seconds", resyncSec)
	rec.Run(ctx, pool)
}

func buildProvisioner(driver string) (RuntimeProvisioner, error) {
	switch driver {
	case "", "noop", "external":
		return NewNoopProvisioner(driver), nil
	case "k8s", "kubernetes":
		rcfg, err := loadKubeConfig()
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
		kube, err := kubernetes.NewForConfig(rcfg)
		if err != nil {
			return nil, fmt.Errorf("create kubernetes client: %w", err)
		}
		var dyn dynamic.Interface
		enableKEDA := envBool("ENABLE_KEDA", false)
		if enableKEDA {
			dyn, err = dynamic.NewForConfig(rcfg)
			if err != nil {
				return nil, fmt.Errorf("create kubernetes dynamic client: %w", err)
			}
		}
		allowlist := splitCSV(envutil.Get("PLUGIN_IMAGE_REGISTRY_ALLOWLIST", "ghcr.io/secflow"))
		cfg := K8sConfig{
			Namespace:               envutil.Get("SANDBOX_NAMESPACE", "secflow-sandbox"),
			OrchestratorAddr:        envutil.Get("ORCHESTRATOR_ADDR", "orchestrator.secflow-core.svc.cluster.local:50051"),
			OrchestratorNamespace:   envutil.Get("ORCHESTRATOR_NAMESPACE", "secflow-core"),
			GarageEndpoint:          envutil.Get("GARAGE_ENDPOINT", "http://garage.secflow-core.svc.cluster.local:3900"),
			GarageNamespace:         envutil.Get("GARAGE_NAMESPACE", "secflow-core"),
			GarageReadOnlyAccessKey: os.Getenv("GARAGE_RO_ACCESS_KEY_ID"),
			GarageReadOnlySecretKey: os.Getenv("GARAGE_RO_SECRET_ACCESS_KEY"),
			ImageRegistryAllowlist:  allowlist,
			Production:              strings.EqualFold(envutil.Get("SECFLOW_ENV", "production"), "production"),
			EnableKEDA:              enableKEDA,
			PrometheusAddress:       envutil.Get("PROMETHEUS_ADDRESS", "http://prometheus.secflow-observability.svc.cluster.local:9090"),
		}
		return NewK8sProvisioner(kube, dyn, cfg), nil
	default:
		return NewNoopProvisioner(driver), nil
	}
}

func envInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func loadKubeConfig() (*rest.Config, error) {
	if kubeconfig := strings.TrimSpace(os.Getenv("KUBECONFIG")); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}
