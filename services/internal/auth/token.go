package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Claims is the local JWT-shaped token payload. Role is empty for scoped tokens.
type Claims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email,omitempty"`
	Role    string   `json:"role,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
	Wf      string   `json:"wf,omitempty"`
	Exp     int64    `json:"exp"`
}

// Sign builds an HS256 JWT. It is not a third-party JWT library.
func Sign(secret []byte, claims Claims) (string, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(raw)
	unsigned := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig, nil
}

// Verify checks the HS256 signature and expiry.
func Verify(secret []byte, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("malformed token")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, err
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil || header.Alg != "HS256" {
		return Claims{}, errors.New("unsupported alg")
	}
	unsigned := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return Claims{}, errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Claims{}, err
	}
	if claims.Exp <= 0 || time.Now().Unix() >= claims.Exp {
		return Claims{}, errors.New("expired")
	}
	return claims, nil
}
