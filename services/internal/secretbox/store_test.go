package secretbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPGAESStoreCRUD(t *testing.T) {
	ctx := t.Context()
	st := NewPGAESStore(Key("test-pg-aes"))
	if st.Backend() != BackendPGAES {
		t.Fatalf("Backend() = %q, want %q", st.Backend(), BackendPGAES)
	}

	if err := st.Put(ctx, "sec_1", []byte("top-secret")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	sealed, ok := st.Sealed("sec_1")
	if !ok || len(sealed) == 0 || bytes.Contains(sealed, []byte("top-secret")) {
		t.Fatalf("expected encrypted envelope blob, ok=%v len=%d", ok, len(sealed))
	}

	got, err := st.Get(ctx, "sec_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "top-secret" {
		t.Fatalf("Get = %q, want top-secret", got)
	}

	// Reload into a fresh store from persisted sealed bytes.
	reloaded := NewPGAESStore(Key("test-pg-aes"))
	reloaded.LoadSealed("sec_1", sealed)
	got2, err := reloaded.Get(ctx, "sec_1")
	if err != nil || string(got2) != "top-secret" {
		t.Fatalf("reloaded Get = %q, err=%v", got2, err)
	}

	if err := st.Delete(ctx, "sec_1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(ctx, "sec_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestVaultStoreKVv2(t *testing.T) {
	var (
		mu      sync.Mutex
		storage = map[string]string{}
	)
	const wantToken = "hvs.test-token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != wantToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/kv/data/secflow/"):
			ref := strings.TrimPrefix(r.URL.Path, "/v1/kv/data/secflow/")
			var req struct {
				Data map[string]string `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			storage[ref] = req.Data["value"]
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"version":1}}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/kv/data/secflow/"):
			ref := strings.TrimPrefix(r.URL.Path, "/v1/kv/data/secflow/")
			mu.Lock()
			val, ok := storage[ref]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data":     map[string]string{"value": val},
					"metadata": map[string]any{"destroyed": false, "deletion_time": ""},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/kv/metadata/secflow/"):
			ref := strings.TrimPrefix(r.URL.Path, "/v1/kv/metadata/secflow/")
			mu.Lock()
			delete(storage, ref)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("SECRET_STORE", "vault")
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", wantToken)
	t.Setenv("VAULT_MOUNT", "kv")

	st, err := NewStoreFromEnv(Key("unused"))
	if err != nil {
		t.Fatalf("NewStoreFromEnv: %v", err)
	}
	if st.Backend() != BackendVault {
		t.Fatalf("Backend() = %q, want %q", st.Backend(), BackendVault)
	}

	ctx := t.Context()
	if err := st.Put(ctx, "sec_vault_1", []byte("vault-secret-value")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := st.Get(ctx, "sec_vault_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "vault-secret-value" {
		t.Fatalf("Get = %q, want vault-secret-value", got)
	}

	// Path traversal in ref must be rejected client-side.
	if err := st.Put(ctx, "../escape", []byte("x")); err == nil {
		t.Fatal("expected traversal ref error")
	}

	if err := st.Delete(ctx, "sec_vault_1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(ctx, "sec_vault_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}
