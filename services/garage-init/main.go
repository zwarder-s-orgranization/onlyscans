// Package main implements the one-shot idempotent Garage bootstrapper for SecFlow.
// It waits for Garage Admin API readiness, assigns a single-node layout if needed,
// creates all four SecFlow buckets, writes S3 credentials to GARAGE_CRED_FILE,
// and seeds secflow-catalogs/default.json from the bundled vulnerability database.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/obs"
	"k8s.io/client-go/kubernetes"
)

func main() {
	obs.SetupLogger("garage-init")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	k8sCfg := loadK8sSecretSyncConfig()
	var kube kubernetes.Interface
	if k8sCfg.enabled() {
		client, err := newKubeClient()
		if err != nil {
			slog.Error("init kubernetes client for garage secret sync", "err", err)
			os.Exit(1)
		}
		kube = client
		if access, secret, found, err := loadExistingGarageSecret(ctx, kube, k8sCfg); err != nil {
			slog.Warn("check existing garage k8s secret", "err", err)
		} else if found {
			blobstore.SeedCredentials(access, secret)
			slog.Info("reusing existing garage credentials from kubernetes secret", "secret", k8sCfg.SecretName)
		}
	}

	var lastErr error
	for attempt := 1; attempt <= 30; attempt++ {
		err := blobstore.Ensure(ctx)
		if err == nil && k8sCfg.enabled() {
			_, access, secret := blobstore.Credentials()
			if syncErr := syncGarageCredentialsToK8s(ctx, kube, k8sCfg, access, secret); syncErr != nil {
				err = syncErr
			} else {
				slog.Info("synced garage credentials to kubernetes secrets", "secret", k8sCfg.SecretName, "namespaces", k8sCfg.Namespaces)
			}
		}
		if err == nil {
			slog.Info("garage bootstrap completed", "attempt", attempt)
			return
		}
		lastErr = err
		slog.Warn("garage bootstrap retry", "attempt", attempt, "err", err)
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			slog.Error("garage bootstrap cancelled", "err", ctx.Err())
			os.Exit(1)
		case <-timer.C:
		}
	}
	slog.Error("garage bootstrap failed", "err", lastErr)
	os.Exit(1)
}
