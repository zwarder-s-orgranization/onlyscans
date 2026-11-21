package main

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	defaultCORSAllowOrigins = "http://localhost:3000,http://127.0.0.1:3000"
	corsExposeHeaders       = "Content-Disposition, X-SecFlow-Sha256, Mcp-Session-Id"
	corsAllowMethods        = "GET, POST, DELETE, HEAD, OPTIONS"
	corsAllowHeaders        = "Authorization, Content-Type, Mcp-Session-Id, traceparent, X-SecFlow-Signature-256, X-SecFlow-Test-Secret"
)

func configuredCORSAllowOrigins() string {
	raw := strings.TrimSpace(os.Getenv("CORS_ALLOW_ORIGINS"))
	if raw == "" {
		return defaultCORSAllowOrigins
	}
	return raw
}

// normalizeOrigin canonicalizes an HTTP origin as lowercased "scheme://host"
// with trailing slashes trimmed. Returns "" for invalid or non-origin values
// (such as "null" or URLs containing paths, queries, fragments, or userinfo).
func normalizeOrigin(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func validateCORSAllowOrigins(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("CORS_ALLOW_ORIGINS is required in production")
	}
	hasOrigin := false
	for _, item := range strings.Split(trimmed, ",") {
		entry := strings.TrimSpace(item)
		if entry == "" {
			continue
		}
		if entry == "*" {
			return errors.New("CORS_ALLOW_ORIGINS must not contain wildcard '*' in production")
		}
		if normalizeOrigin(entry) == "" {
			return errors.New("CORS_ALLOW_ORIGINS contains an invalid origin")
		}
		hasOrigin = true
	}
	if !hasOrigin {
		return errors.New("CORS_ALLOW_ORIGINS is required in production")
	}
	return nil
}

// matchAllowedOrigin checks origin against CORS_ALLOW_ORIGINS (defaulting to
// localhost:3000 / 127.0.0.1:3000 when unset) and returns the exact
// Access-Control-Allow-Origin header value to emit.
func matchAllowedOrigin(origin string) (string, bool) {
	trimmed := strings.TrimSpace(origin)
	if trimmed == "" {
		return "", false
	}
	raw := configuredCORSAllowOrigins()
	for _, item := range strings.Split(raw, ",") {
		if strings.TrimSpace(item) == "*" {
			return "*", true
		}
	}
	normOrigin := normalizeOrigin(trimmed)
	if normOrigin == "" {
		return "", false
	}
	for _, item := range strings.Split(raw, ",") {
		if cand := normalizeOrigin(item); cand != "" && cand == normOrigin {
			return normOrigin, true
		}
	}
	return "", false
}

// allowedWSOrigin enforces the same origin policy for WebSocket upgrades while
// allowing empty Origin headers from non-browser CLI/gRPC/test clients.
func allowedWSOrigin(origin string) bool {
	if strings.TrimSpace(origin) == "" {
		return true
	}
	_, ok := matchAllowedOrigin(origin)
	return ok
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")

		origin := r.Header.Get("Origin")
		isPreflight := r.Method == http.MethodOptions &&
			strings.TrimSpace(origin) != "" &&
			strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")) != ""

		allowOrigin, ok := matchAllowedOrigin(origin)
		if isPreflight {
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
			w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if ok {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
		}
		next.ServeHTTP(w, r)
	})
}
