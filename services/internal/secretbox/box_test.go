package secretbox

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestKeyUsesHKDFNotRawSHA256(t *testing.T) {
	pass := "master-passphrase"
	kek1 := Key(pass)
	kek2 := Key(pass)
	if len(kek1) != 32 {
		t.Fatalf("len(Key) = %d, want 32", len(kek1))
	}
	if !bytes.Equal(kek1, kek2) {
		t.Fatal("Key must be deterministic for same passphrase")
	}
	rawSHA := sha256.Sum256([]byte(pass))
	if bytes.Equal(kek1, rawSHA[:]) {
		t.Fatal("Key must use HKDF-SHA256 rather than plain SHA-256")
	}
	if bytes.Equal(kek1, Key("different-passphrase")) {
		t.Fatal("distinct passphrases must derive distinct KEKs")
	}
}

func TestEnvelopeSealOpenRoundTripAndTamperDetection(t *testing.T) {
	kek := Key("prod-kek-secret")
	otherKEK := Key("other-kek-secret")
	plaintext := []byte("tg-bot-token-super-secret-value")

	blob1, err := Seal(kek, plaintext)
	if err != nil {
		t.Fatalf("Seal #1: %v", err)
	}
	blob2, err := Seal(kek, plaintext)
	if err != nil {
		t.Fatalf("Seal #2: %v", err)
	}
	if blob1[0] != envelopeVersionV1 {
		t.Fatalf("version byte = %d, want %d", blob1[0], envelopeVersionV1)
	}
	if bytes.Equal(blob1, blob2) {
		t.Fatal("sealing identical plaintext twice must produce unique DEK & nonces")
	}

	got, err := Open(kek, blob1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open = %q, want %q", got, plaintext)
	}

	tests := []struct {
		name string
		key  []byte
		blob []byte
	}{
		{
			name: "wrong kek rejected",
			key:  otherKEK,
			blob: blob1,
		},
		{
			name: "tampered version rejected",
			key:  kek,
			blob: func() []byte { b := append([]byte(nil), blob1...); b[0] = 2; return b }(),
		},
		{
			name: "tampered wrapped dek rejected",
			key:  kek,
			blob: func() []byte { b := append([]byte(nil), blob1...); b[10] ^= 0xff; return b }(),
		},
		{
			name: "tampered payload rejected",
			key:  kek,
			blob: func() []byte { b := append([]byte(nil), blob1...); b[len(b)-1] ^= 0xff; return b }(),
		},
		{
			name: "truncated blob rejected",
			key:  kek,
			blob: blob1[:10],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Open(tt.key, tt.blob); err == nil {
				t.Fatal("expected Open to fail")
			}
		})
	}
}
