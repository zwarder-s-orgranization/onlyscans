package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/gradleparser"
)

func writeSBOMTestProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	build := `
dependencies {
    implementation("org.apache.commons:commons-text:1.9")
    runtimeOnly("org.jsoup:jsoup:1.14.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}
`
	if err := os.WriteFile(filepath.Join(dir, "build.gradle.kts"), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExecuteSBOMTask_CycloneDX16AndDevFilteringAndGarageUpload(t *testing.T) {
	t.Parallel()

	projectDir := writeSBOMTestProject(t)
	resolveStub := func(_ context.Context, _ []byte) (string, func()) {
		return projectDir, func() {}
	}
	envelope := []byte(`{
		"findings": [
			{
				"category": "SCA",
				"path": "build.gradle.kts",
				"group": "org.apache.commons",
				"artifact": "commons-text",
				"version": "1.9",
				"advisoryId": "CVE-2022-42889",
				"severity": "CRITICAL",
				"description": "StringSubstitutor lookup RCE"
			},
			{
				"category": "SAST",
				"path": "src/App.kt",
				"class": "sql-injection",
				"line": 10,
				"severity": "HIGH"
			}
		]
	}`)

	t.Run("default includeDevDependencies=false filters test deps, populates vulnerabilities, and uploads to Garage", func(t *testing.T) {
		t.Parallel()
		var uploadedBucket, uploadedKey string
		var uploadedBody []byte

		task := &secflowv1.NodeTask{
			RunId:        "run-123",
			NodeRunId:    "nr-1",
			NodeId:       "sbom",
			PluginId:     "sbom.generate",
			ParamsJson:   []byte(`{}`),
			EnvelopeJson: envelope,
		}
		res := executeSBOMTask(
			t.Context(),
			task,
			resolveStub,
			func() bool { return true },
			func(_ context.Context, bucket, key string, body []byte) error {
				uploadedBucket, uploadedKey, uploadedBody = bucket, key, body
				return nil
			},
		)

		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			t.Fatalf("status = %v (err=%s: %s), want SUCCEEDED", res.GetStatus(), res.GetErrorCode(), res.GetErrorMessage())
		}
		if uploadedBucket != "secflow-sbom" || uploadedKey != "runs/run-123/sbom.cdx.json" {
			t.Fatalf("uploaded to %s/%s, want secflow-sbom/runs/run-123/sbom.cdx.json", uploadedBucket, uploadedKey)
		}
		if res.GetPayloadS3Key() != "runs/run-123/sbom.cdx.json" {
			t.Errorf("PayloadS3Key = %q, want runs/run-123/sbom.cdx.json", res.GetPayloadS3Key())
		}

		var doc cdxDocument
		if err := json.Unmarshal(uploadedBody, &doc); err != nil {
			t.Fatalf("unmarshal uploaded sbom: %v", err)
		}
		if doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
			t.Errorf("unexpected bom metadata: %+v", doc)
		}
		if len(doc.Components) != 2 {
			t.Fatalf("components count = %d (%+v), want 2 (dev filtered out by default)", len(doc.Components), doc.Components)
		}
		for _, c := range doc.Components {
			if c.Name == "junit-jupiter" {
				t.Errorf("dev dependency %q should be excluded by default", c.Name)
			}
		}
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("vulnerabilities count = %d, want 1", len(doc.Vulnerabilities))
		}
		v := doc.Vulnerabilities[0]
		if v.ID != "CVE-2022-42889" {
			t.Errorf("vuln id = %q, want CVE-2022-42889", v.ID)
		}
		if len(v.Ratings) != 1 || v.Ratings[0].Severity != "critical" {
			t.Errorf("vuln ratings = %+v, want [{Severity:critical}]", v.Ratings)
		}
		if len(v.Affects) != 1 || v.Affects[0].Ref != "pkg:maven/org.apache.commons/commons-text@1.9" {
			t.Errorf("vuln affects = %+v", v.Affects)
		}
		if v.Description != "StringSubstitutor lookup RCE" {
			t.Errorf("vuln description = %q", v.Description)
		}
	})

	t.Run("includeDevDependencies=true includes test dependencies", func(t *testing.T) {
		t.Parallel()
		task := &secflowv1.NodeTask{
			RunId:        "run-456",
			NodeRunId:    "nr-2",
			NodeId:       "sbom",
			PluginId:     "sbom.generate",
			ParamsJson:   []byte(`{"includeDevDependencies":true}`),
			EnvelopeJson: envelope,
		}
		res := executeSBOMTask(t.Context(), task, resolveStub, func() bool { return false }, nil)
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			t.Fatalf("status = %v, want SUCCEEDED", res.GetStatus())
		}
		var doc cdxDocument
		if err := json.Unmarshal(res.GetEnvelopePatchJson(), &doc); err != nil {
			t.Fatalf("unmarshal sbom: %v", err)
		}
		if len(doc.Components) != 3 {
			t.Fatalf("components count = %d (%+v), want 3 (including testImplementation)", len(doc.Components), doc.Components)
		}
		foundDev := false
		for _, c := range doc.Components {
			if c.Name == "junit-jupiter" && c.Scope == "optional" {
				foundDev = true
			}
		}
		if !foundDev {
			t.Errorf("expected optional junit-jupiter component when includeDevDependencies=true, got %+v", doc.Components)
		}
	})

	t.Run("fails task when Garage upload returns error", func(t *testing.T) {
		t.Parallel()
		task := &secflowv1.NodeTask{
			RunId:        "run-789",
			NodeRunId:    "nr-3",
			NodeId:       "sbom",
			PluginId:     "sbom.generate",
			ParamsJson:   []byte(`{}`),
			EnvelopeJson: envelope,
		}
		res := executeSBOMTask(
			t.Context(),
			task,
			resolveStub,
			func() bool { return true },
			func(_ context.Context, _, _ string, _ []byte) error {
				return errors.New("garage write timeout")
			},
		)
		if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED {
			t.Fatalf("status = %v, want FAILED", res.GetStatus())
		}
		if res.GetErrorCode() != "UPLOAD_ERROR" {
			t.Errorf("ErrorCode = %q, want UPLOAD_ERROR", res.GetErrorCode())
		}
	})
}

func TestBuildCycloneDX_DeduplicatesByPURLAndUpgradesScope(t *testing.T) {
	t.Parallel()

	deps := []gradleparser.Dependency{
		{Group: "org.jsoup", Artifact: "jsoup", Version: "1.14.1", Path: "core/build.gradle.kts", Scope: "testImplementation", IsDev: true},
		{Group: "org.jsoup", Artifact: "jsoup", Version: "1.14.1", Path: "app/build.gradle.kts", Scope: "implementation", IsDev: false},
		{Group: "org.apache.commons", Artifact: "commons-text", Version: "1.9", Path: "core/build.gradle.kts", Scope: "implementation", IsDev: false},
		{Group: "org.apache.commons", Artifact: "commons-text", Version: "1.9", Path: "app/build.gradle.kts", Scope: "testImplementation", IsDev: true},
		{Group: "org.junit.jupiter", Artifact: "junit-jupiter", Version: "5.10.2", Path: "core/build.gradle.kts", Scope: "testImplementation", IsDev: true},
		{Group: "org.junit.jupiter", Artifact: "junit-jupiter", Version: "5.10.2", Path: "app/build.gradle.kts", Scope: "testImplementation", IsDev: true},
	}

	doc := buildCycloneDX(deps, true, nil)
	if len(doc.Components) != 3 {
		t.Fatalf("components count = %d (%+v), want 3 deduplicated components", len(doc.Components), doc.Components)
	}

	byPURL := map[string]cdxComponent{}
	for _, c := range doc.Components {
		if _, dup := byPURL[c.Purl]; dup {
			t.Fatalf("duplicate purl %q in components", c.Purl)
		}
		if c.BomRef != c.Purl {
			t.Errorf("BomRef = %q, want %q", c.BomRef, c.Purl)
		}
		byPURL[c.Purl] = c
	}

	if got := byPURL["pkg:maven/org.jsoup/jsoup@1.14.1"].Scope; got != "required" {
		t.Errorf("jsoup scope = %q, want required (upgraded from optional)", got)
	}
	if got := byPURL["pkg:maven/org.apache.commons/commons-text@1.9"].Scope; got != "required" {
		t.Errorf("commons-text scope = %q, want required", got)
	}
	if got := byPURL["pkg:maven/org.junit.jupiter/junit-jupiter@5.10.2"].Scope; got != "optional" {
		t.Errorf("junit-jupiter scope = %q, want optional", got)
	}
}
