package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type k8sSecretSyncConfig struct {
	SecretName string
	Namespaces []string
}

func loadK8sSecretSyncConfig() k8sSecretSyncConfig {
	name := strings.TrimSpace(os.Getenv("GARAGE_K8S_SECRET_NAME"))
	rawNS := strings.TrimSpace(os.Getenv("GARAGE_K8S_SECRET_NAMESPACES"))
	if rawNS == "" {
		rawNS = strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	}
	var namespaces []string
	seen := map[string]bool{}
	for _, part := range strings.Split(rawNS, ",") {
		ns := strings.TrimSpace(part)
		if ns != "" && !seen[ns] {
			seen[ns] = true
			namespaces = append(namespaces, ns)
		}
	}
	return k8sSecretSyncConfig{
		SecretName: name,
		Namespaces: namespaces,
	}
}

func (c k8sSecretSyncConfig) enabled() bool {
	return c.SecretName != "" && len(c.Namespaces) > 0
}

func newKubeClient() (kubernetes.Interface, error) {
	var (
		rcfg *rest.Config
		err  error
	)
	if kubeconfig := strings.TrimSpace(os.Getenv("KUBECONFIG")); kubeconfig != "" {
		rcfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		rcfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("load kubernetes config: %w", err)
	}
	client, err := kubernetes.NewForConfig(rcfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	return client, nil
}

// loadExistingGarageSecret checks target namespaces for an existing Secret containing
// Garage S3 credentials so re-running garage-init is idempotent.
func loadExistingGarageSecret(ctx context.Context, kube kubernetes.Interface, cfg k8sSecretSyncConfig) (access, secret string, found bool, err error) {
	if kube == nil || !cfg.enabled() {
		return "", "", false, nil
	}
	for _, ns := range cfg.Namespaces {
		sec, getErr := kube.CoreV1().Secrets(ns).Get(ctx, cfg.SecretName, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			continue
		}
		if getErr != nil {
			return "", "", false, fmt.Errorf("get secret %s/%s: %w", ns, cfg.SecretName, getErr)
		}
		a := strings.TrimSpace(string(sec.Data["GARAGE_ACCESS_KEY"]))
		if a == "" {
			a = strings.TrimSpace(string(sec.Data["GARAGE_ACCESS_KEY_ID"]))
		}
		s := strings.TrimSpace(string(sec.Data["GARAGE_SECRET_KEY"]))
		if s == "" {
			s = strings.TrimSpace(string(sec.Data["GARAGE_SECRET_ACCESS_KEY"]))
		}
		if a != "" && s != "" {
			return a, s, true, nil
		}
	}
	return "", "", false, nil
}

// syncGarageCredentialsToK8s upserts the Garage S3 credentials Secret in every configured namespace.
func syncGarageCredentialsToK8s(ctx context.Context, kube kubernetes.Interface, cfg k8sSecretSyncConfig, access, secret string) error {
	if kube == nil || !cfg.enabled() {
		return nil
	}
	if strings.TrimSpace(access) == "" || strings.TrimSpace(secret) == "" {
		return fmt.Errorf("garage credentials are empty")
	}
	data := map[string][]byte{
		"GARAGE_ACCESS_KEY":        []byte(access),
		"GARAGE_SECRET_KEY":        []byte(secret),
		"GARAGE_ACCESS_KEY_ID":     []byte(access),
		"GARAGE_SECRET_ACCESS_KEY": []byte(secret),
		"ACCESS_KEY_ID":            []byte(access),
		"SECRET_ACCESS_KEY":        []byte(secret),
	}
	labels := map[string]string{
		"app.kubernetes.io/part-of":    "secflow",
		"app.kubernetes.io/managed-by": "garage-init",
	}
	for _, ns := range cfg.Namespaces {
		desired := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cfg.SecretName,
				Namespace: ns,
				Labels:    labels,
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}
		existing, err := kube.CoreV1().Secrets(ns).Get(ctx, cfg.SecretName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, createErr := kube.CoreV1().Secrets(ns).Create(ctx, desired, metav1.CreateOptions{}); createErr != nil {
				return fmt.Errorf("create secret %s/%s: %w", ns, cfg.SecretName, createErr)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("get secret %s/%s: %w", ns, cfg.SecretName, err)
		}
		desired.ResourceVersion = existing.ResourceVersion
		if _, updateErr := kube.CoreV1().Secrets(ns).Update(ctx, desired, metav1.UpdateOptions{}); updateErr != nil {
			return fmt.Errorf("update secret %s/%s: %w", ns, cfg.SecretName, updateErr)
		}
	}
	return nil
}
