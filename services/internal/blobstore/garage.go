package blobstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	garageHTTPClient = &http.Client{Timeout: 30 * time.Second}
	requiredBuckets  = []string{
		"secflow-sources",
		"secflow-catalogs",
		"secflow-artifacts",
		"secflow-sbom",
	}
)

// Ensure assigns a Garage layout, creates all 4 SecFlow buckets with key permissions,
// keeps an access key in memory when static credentials are absent, and pre-seeds
// secflow-catalogs/default.json when missing.
func Ensure(ctx context.Context) error {
	if os.Getenv("GARAGE_ACCESS_KEY") != "" && os.Getenv("GARAGE_SECRET_KEY") != "" {
		return seedDefaultCatalog(ctx)
	}
	base := strings.TrimRight(os.Getenv("GARAGE_ADMIN_URL"), "/")
	token := os.Getenv("GARAGE_ADMIN_TOKEN")
	if base == "" || token == "" || os.Getenv("GARAGE_ENDPOINT") == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if err := ensureLayout(ctx, base, token); err != nil {
		return err
	}
	ids := make([]string, 0, len(requiredBuckets))
	for _, name := range requiredBuckets {
		id, err := ensureBucket(ctx, base, token, name)
		if err != nil {
			return err
		}
		ids = append(ids, id)
	}
	access, secret, ok := loadStored()
	if !ok {
		var err error
		access, secret, err = createKey(ctx, base, token)
		if err != nil {
			return err
		}
		if err := saveCreds(access, secret); err != nil {
			return err
		}
	}
	remember(access, secret)
	for _, id := range ids {
		if err := allowKey(ctx, base, token, id, access); err != nil {
			return err
		}
	}
	return seedDefaultCatalog(ctx)
}

func seedDefaultCatalog(ctx context.Context) error {
	if !Configured() {
		return nil
	}
	if existing, err := Get(ctx, "secflow-catalogs", "default.json"); err == nil && len(existing) > 0 {
		return nil
	}
	raw, ok := readDefaultCatalogFile()
	if !ok || len(raw) == 0 {
		return nil
	}
	if err := Put(ctx, "secflow-catalogs", "default.json", raw); err != nil {
		return fmt.Errorf("seed default catalog: %w", err)
	}
	return nil
}

func readDefaultCatalogFile() ([]byte, bool) {
	var candidates []string
	if p := os.Getenv("DEFAULT_CATALOG_PATH"); p != "" {
		candidates = append(candidates, p)
	}
	if p := os.Getenv("CATALOG_PATH"); p != "" {
		candidates = append(candidates, p)
	}
	if dir, err := os.Getwd(); err == nil {
		for {
			candidates = append(candidates,
				filepath.Join(dir, "tests", "data", "repos", "mentor-training", "vulnerability-database", "maven-vulnerabilities.json"),
				filepath.Join(dir, "tests", "data", "repos", "mentor-training", "vulnerability-database", "vulnerabilities.json"),
				filepath.Join(dir, "mentor-training", "vulnerability-database", "maven-vulnerabilities.json"),
				filepath.Join(dir, "mentor-training", "vulnerability-database", "vulnerabilities.json"),
			)
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	candidates = append(candidates,
		"/mentor-training/vulnerability-database/maven-vulnerabilities.json",
		"/mentor-training/vulnerability-database/vulnerabilities.json",
	)
	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err == nil && len(raw) > 0 {
			return raw, true
		}
	}
	return nil, false
}

func ensureLayout(ctx context.Context, base, token string) error {
	raw, _, err := admin(ctx, base, token, http.MethodGet, "/v2/GetClusterStatus", nil)
	if err != nil {
		return err
	}
	var status struct {
		Nodes []struct {
			ID   string          `json:"id"`
			Role json.RawMessage `json:"role"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return err
	}
	var roles []map[string]any
	for _, node := range status.Nodes {
		if len(node.Role) == 0 || string(node.Role) == "null" {
			roles = append(roles, map[string]any{"id": node.ID, "zone": "dc1", "capacity": 1073741824, "tags": []string{"dev"}})
		}
	}
	if len(roles) == 0 {
		return nil
	}
	if _, _, err := admin(ctx, base, token, http.MethodPost, "/v2/UpdateClusterLayout", map[string]any{"roles": roles}); err != nil {
		return err
	}
	raw, _, err = admin(ctx, base, token, http.MethodGet, "/v1/layout", nil)
	if err != nil {
		return err
	}
	var layout struct {
		Version           int               `json:"version"`
		StagedRoleChanges []json.RawMessage `json:"stagedRoleChanges"`
	}
	if err := json.Unmarshal(raw, &layout); err != nil {
		return err
	}
	if len(layout.StagedRoleChanges) == 0 {
		return nil
	}
	_, code, err := admin(ctx, base, token, http.MethodPost, "/v2/ApplyClusterLayout", map[string]any{"version": layout.Version + 1})
	if code == http.StatusConflict {
		return nil
	}
	return err
}

func ensureBucket(ctx context.Context, base, token, name string) (string, error) {
	raw, code, err := admin(ctx, base, token, http.MethodPost, "/v2/CreateBucket", map[string]any{"globalAlias": name})
	if code == http.StatusConflict || (err != nil && strings.Contains(err.Error(), "BucketAlreadyExists")) {
		return bucketID(ctx, base, token, name)
	}
	if err != nil {
		return "", err
	}
	var doc struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	if doc.ID == "" {
		return "", fmt.Errorf("garage bucket %s has no id", name)
	}
	return doc.ID, nil
}

func bucketID(ctx context.Context, base, token, name string) (string, error) {
	raw, _, err := admin(ctx, base, token, http.MethodGet, "/v2/ListBuckets", nil)
	if err != nil {
		return "", err
	}
	var items []struct {
		ID            string   `json:"id"`
		GlobalAliases []string `json:"globalAliases"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return "", err
	}
	for _, item := range items {
		for _, alias := range item.GlobalAliases {
			if alias == name {
				return item.ID, nil
			}
		}
	}
	return "", fmt.Errorf("garage bucket %s missing after conflict", name)
}

func createKey(ctx context.Context, base, token string) (string, string, error) {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	raw, _, err := admin(ctx, base, token, http.MethodPost, "/v2/CreateKey", map[string]any{"name": "secflow-" + hex.EncodeToString(buf)})
	if err != nil {
		return "", "", err
	}
	var doc struct {
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", "", err
	}
	if doc.AccessKeyID == "" || doc.SecretAccessKey == "" {
		return "", "", fmt.Errorf("garage key response is incomplete")
	}
	return doc.AccessKeyID, doc.SecretAccessKey, nil
}

func allowKey(ctx context.Context, base, token, bucketID, access string) error {
	_, _, err := admin(ctx, base, token, http.MethodPost, "/v2/AllowBucketKey", map[string]any{
		"bucketId": bucketID, "accessKeyId": access,
		"permissions": map[string]bool{"read": true, "write": true, "owner": true},
	})
	return err
}

func admin(ctx context.Context, base, token, method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := garageHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return raw, resp.StatusCode, fmt.Errorf("garage %s %d: %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, resp.StatusCode, nil
}
