// Package blobstore writes objects to Garage when credentials exist.
// Without GARAGE_ENDPOINT and a key pair the call is a no-op.
package blobstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	credMu          sync.Mutex
	runtimeAccess   string
	runtimeSecret   string
	s3HTTPClient    = &http.Client{Timeout: 30 * time.Second}
	s3RetryBackoffs = []time.Duration{
		250 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		1500 * time.Millisecond,
		2 * time.Second,
		2 * time.Second,
		3 * time.Second,
	}
)

func remember(access, secret string) {
	credMu.Lock()
	runtimeAccess, runtimeSecret = access, secret
	credMu.Unlock()
}

// SeedCredentials preloads an existing S3 access/secret key pair into memory so
// Ensure reuses it idempotently (for example when loaded from a Kubernetes Secret).
func SeedCredentials(access, secret string) {
	access = strings.TrimSpace(access)
	secret = strings.TrimSpace(secret)
	if access == "" || secret == "" {
		return
	}
	remember(access, secret)
}

// Credentials returns the active Garage endpoint and S3 key pair from env, memory, or cred file.
func Credentials() (endpoint, access, secret string) {
	return credentials()
}

func credPath() string {
	if p := os.Getenv("GARAGE_CRED_FILE"); p != "" {
		return p
	}
	return "/var/lib/secflow/garage.json"
}

func loadStored() (string, string, bool) {
	raw, err := os.ReadFile(credPath())
	if err != nil {
		return "", "", false
	}
	var doc struct {
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.AccessKey == "" || doc.SecretKey == "" {
		return "", "", false
	}
	return doc.AccessKey, doc.SecretKey, true
}

func saveCreds(access, secret string) error {
	target := credPath()
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create cred dir %s: %w", dir, err)
	}
	raw, err := json.Marshal(map[string]string{"accessKey": access, "secretKey": secret})
	if err != nil {
		return fmt.Errorf("marshal garage creds: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".garage-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cred file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp cred file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp cred file: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("rename temp cred file: %w", err)
	}
	cleanup = false
	return nil
}

// Configured reports whether Garage endpoint and credentials are available.
func Configured() bool {
	endpoint, access, secret := credentials()
	return endpoint != "" && access != "" && secret != ""
}

// WaitReachable waits until the configured GARAGE_ENDPOINT accepts TCP connections
// (or until timeout / ctx cancellation). This avoids cold-start races on k3s/kube-router
// where a freshly spawned worker pod connects to orchestrator milliseconds before the
// NetworkPolicy ipset allows egress/ingress to Garage.
// When GARAGE_ENDPOINT is unset it returns nil immediately.
func WaitReachable(ctx context.Context, timeout time.Duration) error {
	endpoint := strings.TrimSpace(os.Getenv("GARAGE_ENDPOINT"))
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil
	}
	addr := u.Host
	if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
		if strings.EqualFold(u.Scheme, "https") {
			addr = net.JoinHostPort(addr, "443")
		} else {
			addr = net.JoinHostPort(addr, "80")
		}
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{Timeout: 1 * time.Second}
	var lastErr error
	for {
		dialCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		conn, dialErr := dialer.DialContext(dialCtx, "tcp", addr)
		cancel()
		if dialErr == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("garage %s not reachable within %s: %w", addr, timeout, lastErr)
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func credentials() (endpoint, access, secret string) {
	endpoint = strings.TrimRight(os.Getenv("GARAGE_ENDPOINT"), "/")
	access = strings.TrimSpace(os.Getenv("GARAGE_ACCESS_KEY"))
	if access == "" {
		access = strings.TrimSpace(os.Getenv("GARAGE_ACCESS_KEY_ID"))
	}
	secret = strings.TrimSpace(os.Getenv("GARAGE_SECRET_KEY"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("GARAGE_SECRET_ACCESS_KEY"))
	}
	if access == "" || secret == "" {
		credMu.Lock()
		if access == "" {
			access = runtimeAccess
		}
		if secret == "" {
			secret = runtimeSecret
		}
		credMu.Unlock()
	}
	if access == "" || secret == "" {
		if a, s, ok := loadStored(); ok {
			remember(a, s)
			if access == "" {
				access = a
			}
			if secret == "" {
				secret = s
			}
		}
	}
	return endpoint, access, secret
}

// Put stores body at bucket/key. Missing configuration is not an error.
func Put(ctx context.Context, bucket, key string, body []byte) error {
	resp, err := signed(ctx, http.MethodPut, bucket, key, body)
	if err != nil || resp == nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("garage put %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

// Get reads an object. Missing configuration returns a nil body and a nil error.
func Get(ctx context.Context, bucket, key string) ([]byte, error) {
	resp, err := signed(ctx, http.MethodGet, bucket, key, nil)
	if err != nil || resp == nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 80<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("garage get %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func signed(ctx context.Context, method, bucket, key string, body []byte) (*http.Response, error) {
	endpoint, access, secret := credentials()
	if endpoint == "" || access == "" || secret == "" || bucket == "" || key == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, err
	}
	region := os.Getenv("GARAGE_REGION")
	if region == "" {
		region = "garage"
	}
	path := "/" + escape(bucket) + "/" + escapeKey(key)
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])

	maxAttempts := len(s3RetryBackoffs) + 1
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		now := time.Now().UTC()
		amzDate := now.Format("20060102T150405Z")
		day := now.Format("20060102")
		canonHeaders := "host:" + u.Host + "\n" + "x-amz-content-sha256:" + payload + "\n" + "x-amz-date:" + amzDate + "\n"
		signedHeaders := "host;x-amz-content-sha256;x-amz-date"
		canonical := method + "\n" + path + "\n\n" + canonHeaders + "\n" + signedHeaders + "\n" + payload
		scope := day + "/" + region + "/s3/aws4_request"
		canonSum := sha256.Sum256([]byte(canonical))
		stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonSum[:])
		sig := hex.EncodeToString(sign(secret, day, region, stringToSign))
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, endpoint+path, reader)
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("Host", u.Host)
		req.Header.Set("x-amz-date", amzDate)
		req.Header.Set("x-amz-content-sha256", payload)
		req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", access, scope, signedHeaders, sig))

		resp, doErr := s3HTTPClient.Do(req)
		if doErr == nil {
			return resp, nil
		}
		lastErr = doErr
		if ctx.Err() != nil || attempt >= len(s3RetryBackoffs) {
			break
		}
		timer := time.NewTimer(s3RetryBackoffs[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func sign(secret, day, region, stringToSign string) []byte {
	kDate := hmacSum([]byte("AWS4"+secret), day)
	kRegion := hmacSum(kDate, region)
	kService := hmacSum(kRegion, "s3")
	kSigning := hmacSum(kService, "aws4_request")
	return hmacSum(kSigning, stringToSign)
}

func hmacSum(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func escape(part string) string {
	return strings.ReplaceAll(url.PathEscape(part), "+", "%20")
}

func escapeKey(key string) string {
	parts := strings.Split(strings.TrimPrefix(key, "/"), "/")
	for i, part := range parts {
		parts[i] = escape(part)
	}
	return strings.Join(parts, "/")
}
