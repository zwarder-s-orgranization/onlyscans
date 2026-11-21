// Package secretbox seals secret values with AES-256-GCM envelope encryption
// (HKDF-SHA256 KEK + per-secret random 32-byte DEK) and provides pluggable
// SecretStore backends (PG_AES and OpenBao/Vault KV v2).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	envelopeVersionV1 byte = 1
	dekLength              = 32
	hkdfSalt               = "secflow-secretbox-salt-v1"
	hkdfInfo               = "secflow-secretbox-kek-v1"
)

// Key derives a 32-byte KEK from a passphrase using HKDF-SHA256.
func Key(passphrase string) []byte {
	derived, err := hkdf.Key(sha256.New, []byte(passphrase), []byte(hkdfSalt), hkdfInfo, dekLength)
	if err != nil {
		sum := sha256.Sum256([]byte(passphrase))
		return sum[:]
	}
	return derived
}

// Seal encrypts plaintext using envelope encryption:
// a fresh 32-byte random DEK encrypts plaintext with AES-256-GCM, and the KEK
// wraps the DEK with AES-256-GCM.
//
// Binary v1 layout:
//
//	[0]                version (0x01)
//	[1:3]              uint16 big-endian wrappedDEK length
//	[3:3+wrapLen]      wrappedDEK (wrapNonce || AES-GCM(kek, dek, aad=[0x01]))
//	[3+wrapLen:]       payload    (dataNonce || AES-GCM(dek, plaintext, aad=[0x01]))
func Seal(kek, plaintext []byte) ([]byte, error) {
	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, fmt.Errorf("init kek cipher: %w", err)
	}

	dek := make([]byte, dekLength)
	defer clear(dek)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate dek: %w", err)
	}

	wrapNonce := make([]byte, kekGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, wrapNonce); err != nil {
		return nil, fmt.Errorf("generate wrap nonce: %w", err)
	}
	aad := []byte{envelopeVersionV1}
	wrappedDEK := kekGCM.Seal(wrapNonce, wrapNonce, dek, aad)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("init dek cipher: %w", err)
	}
	dataNonce := make([]byte, dekGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return nil, fmt.Errorf("generate data nonce: %w", err)
	}
	encPayload := dekGCM.Seal(dataNonce, dataNonce, plaintext, aad)

	out := make([]byte, 0, 1+2+len(wrappedDEK)+len(encPayload))
	out = append(out, envelopeVersionV1)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wrappedDEK)))
	out = append(out, lenBuf[:]...)
	out = append(out, wrappedDEK...)
	out = append(out, encPayload...)
	return out, nil
}

// Open reverses Seal for v1 envelope blobs.
func Open(kek, blob []byte) ([]byte, error) {
	if len(blob) < 3 {
		return nil, errors.New("ciphertext too short")
	}
	if blob[0] != envelopeVersionV1 {
		return nil, errors.New("unsupported envelope version")
	}

	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, fmt.Errorf("init kek cipher: %w", err)
	}
	wrapLen := int(binary.BigEndian.Uint16(blob[1:3]))
	minWrap := kekGCM.NonceSize() + kekGCM.Overhead()
	if wrapLen < minWrap || 3+wrapLen >= len(blob) {
		return nil, errors.New("invalid envelope framing")
	}

	aad := []byte{envelopeVersionV1}
	wrappedDEK := blob[3 : 3+wrapLen]
	wrapNonce := wrappedDEK[:kekGCM.NonceSize()]
	wrapCT := wrappedDEK[kekGCM.NonceSize():]
	dek, err := kekGCM.Open(nil, wrapNonce, wrapCT, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	defer clear(dek)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("init dek cipher: %w", err)
	}
	payload := blob[3+wrapLen:]
	if len(payload) < dekGCM.NonceSize()+dekGCM.Overhead() {
		return nil, errors.New("ciphertext payload too short")
	}
	dataNonce := payload[:dekGCM.NonceSize()]
	dataCT := payload[dekGCM.NonceSize():]
	plain, err := dekGCM.Open(nil, dataNonce, dataCT, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
