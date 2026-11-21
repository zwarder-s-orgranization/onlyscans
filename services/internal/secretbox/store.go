package secretbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	BackendPGAES = "PG_AES"
	BackendVault = "VAULT"
)

// ErrNotFound reports that no secret exists for the given secretRef.
var ErrNotFound = errors.New("secret not found")

// SecretStore persists secret values behind a pluggable backend (PG_AES or VAULT).
type SecretStore interface {
	Put(ctx context.Context, secretRef string, plaintext []byte) error
	Get(ctx context.Context, secretRef string) ([]byte, error)
	Delete(ctx context.Context, secretRef string) error
	Backend() string
}

// NewStoreFromEnv constructs the configured SecretStore from environment variables:
//   - SECRET_STORE=pg-aes (default) -> PGAESStore using kek
//   - SECRET_STORE=vault -> VaultStore using VAULT_ADDR, VAULT_TOKEN, VAULT_MOUNT (default "secret")
func NewStoreFromEnv(kek []byte) (SecretStore, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("SECRET_STORE")))
	switch mode {
	case "", "pg-aes", "pg_aes":
		return NewPGAESStore(kek), nil
	case "vault", "openbao":
		mount := strings.TrimSpace(os.Getenv("VAULT_MOUNT"))
		if mount == "" {
			mount = "secret"
		}
		return NewVaultStore(VaultConfig{
			Addr:  strings.TrimSpace(os.Getenv("VAULT_ADDR")),
			Token: strings.TrimSpace(os.Getenv("VAULT_TOKEN")),
			Mount: mount,
		})
	default:
		return nil, fmt.Errorf("unsupported SECRET_STORE %q", mode)
	}
}

// PGAESStore seals secrets with AES-256-GCM envelope encryption in memory and
// exposes sealed blobs for PostgreSQL persistence.
type PGAESStore struct {
	mu    sync.RWMutex
	kek   []byte
	blobs map[string][]byte
}

// NewPGAESStore creates a PGAESStore backed by the provided KEK.
func NewPGAESStore(kek []byte) *PGAESStore {
	cp := append([]byte(nil), kek...)
	return &PGAESStore{
		kek:   cp,
		blobs: map[string][]byte{},
	}
}

func (s *PGAESStore) Put(_ context.Context, secretRef string, plaintext []byte) error {
	if err := validateRef(secretRef); err != nil {
		return err
	}
	sealed, err := Seal(s.kek, plaintext)
	if err != nil {
		return fmt.Errorf("seal secret: %w", err)
	}
	s.mu.Lock()
	s.blobs[secretRef] = sealed
	s.mu.Unlock()
	return nil
}

func (s *PGAESStore) Get(_ context.Context, secretRef string) ([]byte, error) {
	s.mu.RLock()
	sealed, ok := s.blobs[secretRef]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	plain, err := Open(s.kek, sealed)
	if err != nil {
		return nil, fmt.Errorf("open secret: %w", err)
	}
	return plain, nil
}

func (s *PGAESStore) Delete(_ context.Context, secretRef string) error {
	s.mu.Lock()
	delete(s.blobs, secretRef)
	s.mu.Unlock()
	return nil
}

func (s *PGAESStore) Backend() string {
	return BackendPGAES
}

// Sealed returns a copy of the envelope-encrypted blob for PostgreSQL storage.
func (s *PGAESStore) Sealed(secretRef string) ([]byte, bool) {
	s.mu.RLock()
	sealed, ok := s.blobs[secretRef]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return append([]byte(nil), sealed...), true
}

// LoadSealed hydrates a previously persisted sealed blob from PostgreSQL.
func (s *PGAESStore) LoadSealed(secretRef string, sealed []byte) {
	if secretRef == "" || len(sealed) == 0 {
		return
	}
	s.mu.Lock()
	s.blobs[secretRef] = append([]byte(nil), sealed...)
	s.mu.Unlock()
}

// VaultConfig configures the Vault / OpenBao KV v2 HTTP client.
type VaultConfig struct {
	Addr       string
	Token      string
	Mount      string
	HTTPClient *http.Client
}

// VaultStore stores secrets in HashiCorp Vault or OpenBao KV v2 over HTTP.
type VaultStore struct {
	addr   string
	token  string
	mount  string
	client *http.Client
}

// NewVaultStore validates config and returns a KV v2 SecretStore.
func NewVaultStore(cfg VaultConfig) (*VaultStore, error) {
	addr := strings.TrimRight(strings.TrimSpace(cfg.Addr), "/")
	if addr == "" {
		return nil, errors.New("VAULT_ADDR is required")
	}
	u, err := url.Parse(addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("invalid VAULT_ADDR")
	}
	token := strings.TrimSpace(cfg.Token)
	if token == "" {
		return nil, errors.New("VAULT_TOKEN is required")
	}
	mount := strings.Trim(strings.TrimSpace(cfg.Mount), "/")
	if mount == "" {
		mount = "secret"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	return &VaultStore{
		addr:   addr,
		token:  token,
		mount:  mount,
		client: client,
	}, nil
}

func (v *VaultStore) Put(ctx context.Context, secretRef string, plaintext []byte) error {
	if err := validateRef(secretRef); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"data": map[string]string{"value": string(plaintext)},
	})
	if err != nil {
		return fmt.Errorf("marshal vault secret: %w", err)
	}
	endpoint := fmt.Sprintf("%s/v1/%s/data/secflow/%s", v.addr, v.mount, url.PathEscape(secretRef))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build vault put request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault put request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vault put status %d", resp.StatusCode)
	}
	return nil
}

func (v *VaultStore) Get(ctx context.Context, secretRef string) ([]byte, error) {
	if err := validateRef(secretRef); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/v1/%s/data/secflow/%s", v.addr, v.mount, url.PathEscape(secretRef))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build vault get request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault get request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read vault response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault get status %d", resp.StatusCode)
	}
	var doc struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Destroyed    bool   `json:"destroyed"`
				DeletionTime string `json:"deletion_time"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode vault response: %w", err)
	}
	if doc.Data.Metadata.Destroyed || doc.Data.Metadata.DeletionTime != "" {
		return nil, ErrNotFound
	}
	val, ok := doc.Data.Data["value"]
	if !ok {
		return nil, ErrNotFound
	}
	return []byte(val), nil
}

func (v *VaultStore) Delete(ctx context.Context, secretRef string) error {
	if err := validateRef(secretRef); err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1/%s/metadata/secflow/%s", v.addr, v.mount, url.PathEscape(secretRef))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build vault delete request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault delete request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return nil
	}
	return fmt.Errorf("vault delete status %d", resp.StatusCode)
}

func (v *VaultStore) Backend() string {
	return BackendVault
}

func validateRef(secretRef string) error {
	if secretRef == "" || strings.Contains(secretRef, "/") || strings.Contains(secretRef, "\\") || strings.Contains(secretRef, "..") {
		return errors.New("invalid secret ref")
	}
	return nil
}
