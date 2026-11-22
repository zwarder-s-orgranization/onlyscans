package gradleparser

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func buildTestOSVZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetchOSVMavenCatalog_ConvertsZipDumpAndMatches(t *testing.T) {
	t.Parallel()

	zipPayload := buildTestOSVZip(t, map[string]string{
		"GHSA-599f-7c49-w659.json": `{
			"id": "GHSA-599f-7c49-w659",
			"aliases": ["CVE-2022-42889"],
			"database_specific": {"severity": "CRITICAL"},
			"affected": [{
				"package": {"ecosystem": "Maven", "name": "org.apache.commons:commons-text"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.5"}, {"fixed": "1.10.0"}]}]
			}]
		}`,
		"GHSA-unpatched.json": `{
			"id": "GHSA-unpatched",
			"aliases": ["CVE-2025-99999"],
			"database_specific": {"severity": "MODERATE"},
			"affected": [{
				"package": {"ecosystem": "Maven", "name": "org.example:widget"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.1.0"}]}]
			}]
		}`,
		"GHSA-withdrawn.json": `{
			"id": "GHSA-withdrawn",
			"withdrawn": "2024-01-01T00:00:00Z",
			"affected": [{
				"package": {"ecosystem": "Maven", "name": "org.apache.commons:commons-text"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
			}]
		}`,
		"GHSA-npm.json": `{
			"id": "GHSA-npm",
			"affected": [{
				"package": {"ecosystem": "npm", "name": "lodash"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
			}]
		}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipPayload)
	}))
	defer srv.Close()

	raw, count, err := fetchOSVMavenCatalogWithClient(t.Context(), srv.Client(), srv.URL+"/Maven/all.zip")
	if err != nil {
		t.Fatalf("FetchOSVMavenCatalog() error = %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2 (ignoring withdrawn and npm)", count)
	}

	advs, err := LoadCatalogBytes(raw)
	if err != nil {
		t.Fatalf("LoadCatalogBytes() error = %v", err)
	}
	deps := []Dependency{
		{Group: "org.apache.commons", Artifact: "commons-text", Version: "1.9", Path: "build.gradle.kts"},
		{Group: "org.apache.commons", Artifact: "commons-text", Version: "1.10.0", Path: "build.gradle.kts"},
		{Group: "org.example", Artifact: "widget", Version: "2.1.0", Path: "pom.xml"},
	}
	findings := Match(deps, advs)
	if len(findings) != 2 {
		t.Fatalf("findings len = %d (%+v), want 2", len(findings), findings)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.AdvisoryID] = f
	}
	if f, ok := byID["CVE-2022-42889"]; !ok || f.Severity != "CRITICAL" {
		t.Errorf("missing/bad CVE-2022-42889: %+v", findings)
	}
	if f, ok := byID["CVE-2025-99999"]; !ok || f.Severity != "MEDIUM" {
		t.Errorf("missing/bad CVE-2025-99999 (last_affected inclusive + MODERATE->MEDIUM): %+v", findings)
	}
}

func TestQueryOSVLive_BatchAndDetailResolution(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Version string `json:"version"`
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				if q.Package.Name == "org.apache.commons:commons-text" && q.Version == "1.9" {
					results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-599f-7c49-w659"}}}
				} else {
					results[i] = map[string]any{}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			if id == "GHSA-599f-7c49-w659" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":                "GHSA-599f-7c49-w659",
					"aliases":           []string{"CVE-2022-42889"},
					"database_specific": map[string]string{"severity": "CRITICAL"},
				})
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	deps := []Dependency{
		{Group: "org.apache.commons", Artifact: "commons-text", Version: "1.9", Path: "build.gradle.kts"},
		{Group: "org.jsoup", Artifact: "jsoup", Version: "1.18.1", Path: "build.gradle.kts"},
	}
	findings, err := queryOSVLiveWithClient(t.Context(), srv.Client(), deps, srv.URL)
	if err != nil {
		t.Fatalf("QueryOSVLive() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings len = %d (%+v), want 1", len(findings), findings)
	}
	if findings[0].AdvisoryID != "CVE-2022-42889" || findings[0].Severity != "CRITICAL" {
		t.Fatalf("unexpected live finding: %+v", findings[0])
	}
}
