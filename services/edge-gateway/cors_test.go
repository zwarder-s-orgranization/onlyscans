package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestCORSAllowsLocalWeb(t *testing.T) {
	t.Setenv("CORS_ALLOW_ORIGINS", "")
	h := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("Allow-Origin = %q, want http://localhost:3000", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != corsAllowMethods {
		t.Fatalf("Allow-Methods = %q, want %q", got, corsAllowMethods)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != corsAllowHeaders {
		t.Fatalf("Allow-Headers = %q, want %q", got, corsAllowHeaders)
	}
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != corsExposeHeaders {
		t.Fatalf("Expose-Headers = %q, want %q", got, corsExposeHeaders)
	}
	vary := rec.Header().Values("Vary")
	for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !slices.Contains(vary, want) {
			t.Fatalf("Vary = %v, missing %q", vary, want)
		}
	}
}

func TestCORSOriginNormalizationAndExposeHeadersAndVary(t *testing.T) {
	t.Setenv("CORS_ALLOW_ORIGINS", "HTTPS://App.SecFlow.Local:8443/")
	h := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/runs/r1/submission.json", nil)
	req.Header.Set("Origin", "https://app.secflow.local:8443/")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.secflow.local:8443" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != corsExposeHeaders {
		t.Fatalf("Expose-Headers = %q, want %q", got, corsExposeHeaders)
	}
	vary := rec.Header().Values("Vary")
	if !slices.Contains(vary, "Origin") || !slices.Contains(vary, "Accept-Encoding") {
		t.Fatalf("Vary headers overwritten: %v", vary)
	}
}

func TestCORSRejectsUnknownOriginAndDisallowedPreflight(t *testing.T) {
	t.Setenv("CORS_ALLOW_ORIGINS", "http://localhost:3000")
	nextCalled := false
	h := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	// Regular GET with unknown origin passes through without ACAO but still sets Vary: Origin.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unknown origin was allowed")
	}
	if !slices.Contains(rec.Header().Values("Vary"), "Origin") {
		t.Fatalf("expected Vary: Origin even on rejected origin, got %v", rec.Header().Values("Vary"))
	}
	if rec.Code != http.StatusOK || !nextCalled {
		t.Fatalf("status=%d nextCalled=%v", rec.Code, nextCalled)
	}

	// Disallowed CORS preflight returns 403 Forbidden and does not call next.
	nextCalled = false
	pre := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	pre.Header.Set("Origin", "http://evil.example")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	preRec := httptest.NewRecorder()
	h.ServeHTTP(preRec, pre)
	if preRec.Code != http.StatusForbidden {
		t.Fatalf("disallowed preflight status = %d, want 403", preRec.Code)
	}
	if nextCalled {
		t.Fatal("disallowed preflight invoked next handler")
	}
	if preRec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed preflight set Allow-Origin = %q", preRec.Header().Get("Access-Control-Allow-Origin"))
	}
	for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !slices.Contains(preRec.Header().Values("Vary"), want) {
			t.Fatalf("disallowed preflight Vary = %v, missing %q", preRec.Header().Values("Vary"), want)
		}
	}
}

func TestCORSWildcardEmitsLiteralStarNeverEchoesNull(t *testing.T) {
	t.Setenv("CORS_ALLOW_ORIGINS", "*")
	h := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, origin := range []string{"null", "https://any.example"} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("wildcard for origin %q emitted %q, want literal '*'", origin, got)
		}
	}
}

func TestCORSNonPreflightOptionsPassesThrough(t *testing.T) {
	t.Setenv("CORS_ALLOW_ORIGINS", "http://localhost:3000")
	called := false
	h := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	// OPTIONS without Access-Control-Request-Method is not a CORS preflight.
	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusTeapot {
		t.Fatalf("non-CORS OPTIONS called=%v status=%d, want true/418", called, rec.Code)
	}
	if !slices.Contains(rec.Header().Values("Vary"), "Origin") {
		t.Fatalf("expected Vary: Origin on non-CORS request, got %v", rec.Header().Values("Vary"))
	}
}

func TestWSOriginParityWithCORS(t *testing.T) {
	t.Setenv("CORS_ALLOW_ORIGINS", "")

	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "empty origin allowed for non-browser CLI/tests", origin: "", want: true},
		{name: "default localhost allowed", origin: "http://localhost:3000", want: true},
		{name: "case-insensitive trailing slash allowed", origin: "HTTP://127.0.0.1:3000/", want: true},
		{name: "unknown browser origin rejected by default", origin: "https://evil.example", want: false},
		{name: "null origin rejected by default", origin: "null", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if got := checkWSOrigin(req); got != tc.want {
				t.Fatalf("checkWSOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

func TestValidateGatewayConfigProductionCORS(t *testing.T) {
	if err := validateGatewayConfig("production", "local", "jwt", "svc", ""); err == nil {
		t.Fatal("expected error when CORS_ALLOW_ORIGINS is empty in production")
	}
	if err := validateGatewayConfig("production", "local", "jwt", "svc", "*"); err == nil {
		t.Fatal("expected error when CORS_ALLOW_ORIGINS is '*' in production")
	}
	if err := validateGatewayConfig("production", "local", "jwt", "svc", "https://app.secflow.local, *"); err == nil {
		t.Fatal("expected error when CORS_ALLOW_ORIGINS contains '*' in production")
	}
	if err := validateGatewayConfig("production", "local", "jwt", "svc", "https://app.secflow.local"); err != nil {
		t.Fatalf("valid production CORS failed: %v", err)
	}
	if err := validateGatewayConfig("development", "local", "", "", "*"); err != nil {
		t.Fatalf("development should allow wildcard: %v", err)
	}

	t.Setenv("SECFLOW_ENV", "")
	t.Setenv("ENV", "production")
	if got := effectiveGatewayEnv(); got != "production" {
		t.Fatalf("effectiveGatewayEnv() = %q, want production", got)
	}
}
