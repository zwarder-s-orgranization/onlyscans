package main

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSyncGarageCredentialsToK8s_CreateAndIdempotentUpdate(t *testing.T) {
	t.Parallel()
	kube := fake.NewSimpleClientset()
	cfg := k8sSecretSyncConfig{
		SecretName: "secflow-garage-creds",
		Namespaces: []string{"secflow-app", "secflow-workers", "secflow-sandbox"},
	}

	if err := syncGarageCredentialsToK8s(t.Context(), kube, cfg, "GK123456", "sec-abc"); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	for _, ns := range cfg.Namespaces {
		sec, err := kube.CoreV1().Secrets(ns).Get(t.Context(), cfg.SecretName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get secret in %s: %v", ns, err)
		}
		if string(sec.Data["GARAGE_ACCESS_KEY"]) != "GK123456" {
			t.Fatalf("unexpected GARAGE_ACCESS_KEY in %s: %q", ns, string(sec.Data["GARAGE_ACCESS_KEY"]))
		}
		if string(sec.Data["GARAGE_SECRET_KEY"]) != "sec-abc" {
			t.Fatalf("unexpected GARAGE_SECRET_KEY in %s: %q", ns, string(sec.Data["GARAGE_SECRET_KEY"]))
		}
		if string(sec.Data["ACCESS_KEY_ID"]) != "GK123456" {
			t.Fatalf("unexpected ACCESS_KEY_ID in %s: %q", ns, string(sec.Data["ACCESS_KEY_ID"]))
		}
	}

	access, secret, found, err := loadExistingGarageSecret(t.Context(), kube, cfg)
	if err != nil {
		t.Fatalf("loadExistingGarageSecret: %v", err)
	}
	if !found || access != "GK123456" || secret != "sec-abc" {
		t.Fatalf("expected existing creds, got found=%v access=%q secret=%q", found, access, secret)
	}

	// Update idempotently with rotated values.
	if err := syncGarageCredentialsToK8s(t.Context(), kube, cfg, "GK999999", "sec-xyz"); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	sec, err := kube.CoreV1().Secrets("secflow-workers").Get(t.Context(), cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated secret: %v", err)
	}
	if string(sec.Data["GARAGE_ACCESS_KEY"]) != "GK999999" || string(sec.Data["GARAGE_SECRET_KEY"]) != "sec-xyz" {
		t.Fatalf("secret not updated: %+v", sec.Data)
	}
}
