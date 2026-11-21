// Package oidc verifies RS256 access tokens against a JWKS document.
package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"time"
)

// Key is one RSA public key from a JWKS.
type Key struct {
	KID string
	Pub *rsa.PublicKey
}

// ParseJWKS reads a {"keys":[...]} document.
func ParseJWKS(raw []byte) ([]Key, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []Key
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		out = append(out, Key{KID: k.Kid, Pub: &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}})
	}
	if len(out) == 0 {
		return nil, errors.New("no rsa keys")
	}
	return out, nil
}

// Identity is the subset of claims the gateway needs.
type Identity struct {
	Subject string
	Email   string
	Role    string
}

// Verify checks an RS256 compact JWT against the provided keys.
func Verify(token string, keys []Key) (Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Identity{}, errors.New("malformed jwt")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Identity{}, err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return Identity{}, err
	}
	if header.Alg != "RS256" {
		return Identity{}, errors.New("unsupported alg")
	}
	var pub *rsa.PublicKey
	for _, key := range keys {
		if header.Kid == "" || key.KID == header.Kid {
			pub = key.Pub
			break
		}
	}
	if pub == nil {
		return Identity{}, errors.New("unknown kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return Identity{}, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, err
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Role  string `json:"role"`
		Exp   int64  `json:"exp"`
		Iss   string `json:"iss"`
		Aud   any    `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Identity{}, err
	}
	if claims.Sub == "" {
		return Identity{}, errors.New("missing sub")
	}
	if claims.Exp == 0 || claims.Exp < time.Now().Unix() {
		return Identity{}, errors.New("expired")
	}
	if want := os.Getenv("OIDC_ISSUER"); want != "" && claims.Iss != want {
		return Identity{}, errors.New("issuer")
	}
	if want := os.Getenv("OIDC_AUDIENCE"); want != "" && !audience(claims.Aud, want) {
		return Identity{}, errors.New("audience")
	}
	return Identity{Subject: claims.Sub, Email: claims.Email, Role: claims.Role}, nil
}

func audience(raw any, want string) bool {
	switch v := raw.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// PublicJWK renders one public key as a JWKS key object. Tests use it.
func PublicJWK(kid string, pub *rsa.PublicKey) ([]byte, error) {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": kid, "alg": "RS256", "n": n, "e": e}}})
}

// SignForTest builds an RS256 JWT. Not used in production.
func SignForTest(kid string, key *rsa.PrivateKey, payload []byte) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	body := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(body))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return body + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
