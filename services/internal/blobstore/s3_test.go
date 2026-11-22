package blobstore

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPutWithoutConfigDoesNothing(t *testing.T) {
	t.Setenv("GARAGE_ENDPOINT", "")
	t.Setenv("GARAGE_ACCESS_KEY", "")
	t.Setenv("GARAGE_SECRET_KEY", "")
	t.Setenv("GARAGE_CRED_FILE", filepath.Join(t.TempDir(), "missing.json"))
	remember("", "")
	if Configured() {
		t.Fatal("expected Configured() to be false without credentials")
	}
	if err := Put(context.Background(), "secflow-sources", "a.bin", []byte("x")); err != nil {
		t.Fatal(err)
	}
}

func TestSaveCredsAtomicAndConfigured(t *testing.T) {
	credFile := filepath.Join(t.TempDir(), "nested", "garage.json")
	t.Setenv("GARAGE_CRED_FILE", credFile)
	t.Setenv("GARAGE_ENDPOINT", "http://127.0.0.1:3900")
	t.Setenv("GARAGE_ACCESS_KEY", "")
	t.Setenv("GARAGE_SECRET_KEY", "")
	remember("", "")

	if err := saveCreds("AKIA123", "SECRET456"); err != nil {
		t.Fatalf("saveCreds: %v", err)
	}
	access, secret, ok := loadStored()
	if !ok || access != "AKIA123" || secret != "SECRET456" {
		t.Fatalf("loadStored = (%q, %q, %v)", access, secret, ok)
	}
	if !Configured() {
		t.Fatal("expected Configured() to be true after loading stored creds")
	}
	// Ensure no stray temp files remain in the directory.
	entries, err := os.ReadDir(filepath.Dir(credFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "garage.json" {
		t.Fatalf("unexpected files in cred dir: %+v", entries)
	}
}

func TestEnsureCreatesFourBucketsAndSeedsCatalog(t *testing.T) {
	var mu sync.Mutex
	createdBuckets := map[string]string{}
	allowedBuckets := map[string]bool{}
	storedObjects := map[string][]byte{}

	adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/GetClusterStatus":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"nodes": []map[string]any{{"id": "n1", "role": map[string]any{"zone": "dc1"}}},
			})
		case "/v2/CreateBucket":
			var req struct {
				GlobalAlias string `json:"globalAlias"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			id := "bkt-" + req.GlobalAlias
			createdBuckets[req.GlobalAlias] = id
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
		case "/v2/CreateKey":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"accessKeyId":     "GK-test",
				"secretAccessKey": "GS-test",
			})
		case "/v2/AllowBucketKey":
			var req struct {
				BucketID string `json:"bucketId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			allowedBuckets[req.BucketID] = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unknown admin path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer adminSrv.Close()

	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			data, ok := storedObjects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			storedObjects[r.URL.Path] = body
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer s3Srv.Close()

	catalogFile := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogFile, []byte(`{"advisories":[{"id":"CVE-2022-42889"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GARAGE_ADMIN_URL", adminSrv.URL)
	t.Setenv("GARAGE_ADMIN_TOKEN", "admin-token")
	t.Setenv("GARAGE_ENDPOINT", s3Srv.URL)
	t.Setenv("GARAGE_ACCESS_KEY", "")
	t.Setenv("GARAGE_SECRET_KEY", "")
	t.Setenv("GARAGE_CRED_FILE", filepath.Join(t.TempDir(), "garage.json"))
	t.Setenv("DEFAULT_CATALOG_PATH", catalogFile)
	remember("", "")

	if err := Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	for _, name := range []string{"secflow-sources", "secflow-catalogs", "secflow-artifacts", "secflow-sbom"} {
		id, ok := createdBuckets[name]
		if !ok {
			t.Fatalf("bucket %q was not created", name)
		}
		if !allowedBuckets[id] {
			t.Fatalf("key was not allowed on bucket %q (%s)", name, id)
		}
	}
	seeded := storedObjects["/secflow-catalogs/default.json"]
	if string(seeded) != `{"advisories":[{"id":"CVE-2022-42889"}]}` {
		t.Fatalf("seeded catalog = %q", string(seeded))
	}
}

func TestEnsureSeedsDefaultCatalogFromLiveOSVFeed(t *testing.T) {
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create("GHSA-599f-7c49-w659.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`{
		"id": "GHSA-599f-7c49-w659",
		"aliases": ["CVE-2022-42889"],
		"database_specific": {"severity": "CRITICAL"},
		"affected": [{
			"package": {"ecosystem": "Maven", "name": "org.apache.commons:commons-text"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.5"}, {"fixed": "1.10.0"}]}]
		}]
	}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBuf.Bytes())
	}))
	defer osvSrv.Close()

	var mu sync.Mutex
	storedObjects := map[string][]byte{}
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			data, ok := storedObjects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			storedObjects[r.URL.Path] = body
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer s3Srv.Close()

	t.Setenv("GARAGE_ENDPOINT", s3Srv.URL)
	t.Setenv("GARAGE_ACCESS_KEY", "GK-test")
	t.Setenv("GARAGE_SECRET_KEY", "GS-test")
	t.Setenv("DEFAULT_CATALOG_PATH", "")
	t.Setenv("CATALOG_PATH", "")
	t.Setenv("CATALOG_FEED_URL", "")
	t.Setenv("OSV_MAVEN_ZIP_URL", osvSrv.URL+"/Maven/all.zip")
	remember("", "")

	if err := Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure(live OSV feed): %v", err)
	}
	seeded := string(storedObjects["/secflow-catalogs/default.json"])
	if !strings.Contains(seeded, "CVE-2022-42889") || !strings.Contains(seeded, "commons-text") {
		t.Fatalf("expected OSV catalog seeded into Garage, got %q", seeded)
	}
}

func TestHTTPClientsHaveExplicitTimeouts(t *testing.T) {
	if s3HTTPClient == nil || s3HTTPClient.Timeout <= 0 {
		t.Fatalf("s3HTTPClient must have an explicit positive timeout, got %+v", s3HTTPClient)
	}
	if garageHTTPClient == nil || garageHTTPClient.Timeout <= 0 {
		t.Fatalf("garageHTTPClient must have an explicit positive timeout, got %+v", garageHTTPClient)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGetRetriesTransientTransportError(t *testing.T) {
	t.Setenv("GARAGE_ENDPOINT", "http://garage.local:3900")
	t.Setenv("GARAGE_ACCESS_KEY", "GK-test")
	t.Setenv("GARAGE_SECRET_KEY", "GS-test")
	remember("", "")

	origClient := s3HTTPClient
	origBackoffs := s3RetryBackoffs
	t.Cleanup(func() {
		s3HTTPClient = origClient
		s3RetryBackoffs = origBackoffs
	})

	var attempts atomic.Int32
	s3RetryBackoffs = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	s3HTTPClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			if attempts.Add(1) < 3 {
				return nil, errors.New("dial tcp 10.43.0.10:3900: connect: connection refused")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("archive-bytes")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	got, err := Get(t.Context(), "secflow-sources", "sample.tar.gz")
	if err != nil {
		t.Fatalf("Get() after transient errors returned err = %v", err)
	}
	if string(got) != "archive-bytes" {
		t.Fatalf("Get() = %q, want %q", string(got), "archive-bytes")
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
}

func TestWaitReachable(t *testing.T) {
	t.Run("unset endpoint returns immediately", func(t *testing.T) {
		t.Setenv("GARAGE_ENDPOINT", "")
		if err := WaitReachable(t.Context(), 100*time.Millisecond); err != nil {
			t.Fatalf("WaitReachable with empty endpoint: %v", err)
		}
	})

	t.Run("reachable TCP listener succeeds", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		go func() {
			if c, aErr := ln.Accept(); aErr == nil {
				_ = c.Close()
			}
		}()

		t.Setenv("GARAGE_ENDPOINT", "http://"+ln.Addr().String())
		if err := WaitReachable(t.Context(), 2*time.Second); err != nil {
			t.Fatalf("WaitReachable against live listener: %v", err)
		}
	})
}
