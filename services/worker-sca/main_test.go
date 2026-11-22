package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/gradleparser"
)

const sampleCatalogJSON = `{
  "vulnerabilities": [
    {
      "id": "GHSA-599f-7c49-w659",
      "aliases": ["CVE-2022-42889"],
      "group": "org.apache.commons",
      "artifact": "commons-text",
      "severity": "CRITICAL",
      "ranges": [{"lower": "1.5", "lowerInclusive": true, "upper": "1.10.0", "upperInclusive": false}]
    }
  ]
}`

func writeSampleGradleProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	build := `
dependencies {
    implementation("org.apache.commons:commons-text:1.9")
}
`
	if err := os.WriteFile(filepath.Join(dir, "build.gradle.kts"), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMatchWithResolver_CatalogResolutionOrder(t *testing.T) {
	t.Parallel()

	projectDir := writeSampleGradleProject(t)

	t.Run("explicit catalogId via CatalogService and Garage omits Line and Class", func(t *testing.T) {
		t.Parallel()
		var gotBucket, gotKey string
		resolver := &catalogResolver{
			orchestratorAddr: "orchestrator:50051",
			fetchCatalogMeta: func(_ context.Context, _, catalogID string) (*secflowv1.VulnerabilityCatalog, error) {
				if catalogID != "cat_custom" {
					t.Fatalf("catalogID = %q, want cat_custom", catalogID)
				}
				return &secflowv1.VulnerabilityCatalog{
					Id:     "cat_custom",
					Bucket: "secflow-catalogs",
					S3Key:  "cat_custom.json",
				}, nil
			},
			blobConfigured: func() bool { return true },
			blobGet: func(_ context.Context, bucket, key string) ([]byte, error) {
				gotBucket, gotKey = bucket, key
				return []byte(sampleCatalogJSON), nil
			},
		}

		findings, err := matchWithResolver(t.Context(), projectDir, "cat_custom", resolver)
		if err != nil {
			t.Fatalf("matchWithResolver() error = %v", err)
		}
		if gotBucket != "secflow-catalogs" || gotKey != "cat_custom.json" {
			t.Fatalf("downloaded %s/%s, want secflow-catalogs/cat_custom.json", gotBucket, gotKey)
		}
		if len(findings) != 1 {
			t.Fatalf("findings len = %d, want 1", len(findings))
		}
		f := findings[0]
		if f.Line != nil {
			t.Errorf("SCA finding Line must be nil, got %d", *f.Line)
		}
		if f.EndLine != nil {
			t.Errorf("SCA finding EndLine must be nil, got %d", *f.EndLine)
		}
		if f.FindingClass != "" {
			t.Errorf("SCA finding FindingClass must be empty, got %q", f.FindingClass)
		}
		if f.AdvisoryId != "CVE-2022-42889" {
			t.Errorf("AdvisoryId = %q, want CVE-2022-42889", f.AdvisoryId)
		}
	})

	t.Run("default Garage secflow-catalogs/default.json when no catalogId", func(t *testing.T) {
		t.Parallel()
		var gotBucket, gotKey string
		resolver := &catalogResolver{
			blobConfigured: func() bool { return true },
			blobGet: func(_ context.Context, bucket, key string) ([]byte, error) {
				gotBucket, gotKey = bucket, key
				return []byte(sampleCatalogJSON), nil
			},
		}

		findings, err := matchWithResolver(t.Context(), projectDir, "", resolver)
		if err != nil {
			t.Fatalf("matchWithResolver() error = %v", err)
		}
		if gotBucket != "secflow-catalogs" || gotKey != "default.json" {
			t.Fatalf("downloaded %s/%s, want secflow-catalogs/default.json", gotBucket, gotKey)
		}
		if len(findings) != 1 {
			t.Fatalf("findings len = %d, want 1", len(findings))
		}
	})

	t.Run("fallback to CATALOG_PATH when Garage unconfigured", func(t *testing.T) {
		t.Parallel()
		catPath := filepath.Join(t.TempDir(), "catalog.json")
		if err := os.WriteFile(catPath, []byte(sampleCatalogJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		resolver := &catalogResolver{
			catalogPath:    catPath,
			blobConfigured: func() bool { return false },
		}

		findings, err := matchWithResolver(t.Context(), projectDir, "", resolver)
		if err != nil {
			t.Fatalf("matchWithResolver() error = %v", err)
		}
		if len(findings) != 1 || findings[0].AdvisoryId != "CVE-2022-42889" {
			t.Fatalf("unexpected findings: %+v", findings)
		}
	})

	t.Run("falls back to live OSV API when stored catalog is unavailable", func(t *testing.T) {
		t.Parallel()
		calledLive := false
		resolver := &catalogResolver{
			blobConfigured: func() bool { return true },
			blobGet: func(_ context.Context, _, _ string) ([]byte, error) {
				return nil, errors.New("garage unavailable")
			},
			osvAPIBaseURL: "https://api.osv.dev",
			liveQueryOSV: func(_ context.Context, deps []gradleparser.Dependency, _ string) ([]gradleparser.Finding, error) {
				calledLive = true
				if len(deps) != 1 || deps[0].Artifact != "commons-text" {
					t.Fatalf("unexpected deps passed to live OSV: %+v", deps)
				}
				return []gradleparser.Finding{{
					Group: "org.apache.commons", Artifact: "commons-text", Version: "1.9",
					Path: "build.gradle.kts", AdvisoryID: "CVE-2022-42889", Severity: "CRITICAL",
				}}, nil
			},
		}

		findings, err := matchWithResolver(t.Context(), projectDir, "", resolver)
		if err != nil {
			t.Fatalf("matchWithResolver() error = %v", err)
		}
		if !calledLive || len(findings) != 1 || findings[0].AdvisoryId != "CVE-2022-42889" {
			t.Fatalf("expected live OSV fallback finding, calledLive=%v findings=%+v", calledLive, findings)
		}
	})

	t.Run("fails cleanly when no catalog source succeeds", func(t *testing.T) {
		t.Parallel()
		resolver := &catalogResolver{
			blobConfigured: func() bool { return true },
			blobGet: func(_ context.Context, _, _ string) ([]byte, error) {
				return nil, errors.New("garage unavailable")
			},
			fallbackFiles: []string{filepath.Join(t.TempDir(), "missing.json")},
		}

		if _, err := matchWithResolver(t.Context(), projectDir, "", resolver); err == nil {
			t.Fatal("expected error when no catalog can be loaded, got nil")
		}
	})
}

func TestParseSCAParams(t *testing.T) {
	t.Parallel()

	p := parseSCAParams([]byte(`{"catalogId":"  cat_v2  "}`))
	if p.CatalogID != "cat_v2" {
		t.Fatalf("CatalogID = %q, want cat_v2", p.CatalogID)
	}
	empty := parseSCAParams(nil)
	if empty.CatalogID != "" {
		t.Fatalf("empty CatalogID = %q, want empty", empty.CatalogID)
	}
}
