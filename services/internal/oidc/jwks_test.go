package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestVerifyRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := PublicJWK("k1", &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(raw)
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignForTest("k1", key, []byte(`{"sub":"user-1","email":"a@b.c","role":"editor","exp":4102444800,"iss":"https://issuer.example","aud":"secflow"}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := Verify(token, keys)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "user-1" || id.Role != "editor" {
		t.Fatalf("%+v", id)
	}
	if _, err := Verify(token+"x", keys); err == nil {
		t.Fatal("expected bad signature")
	}
	t.Setenv("OIDC_ISSUER", "https://issuer.example")
	t.Setenv("OIDC_AUDIENCE", "secflow")
	if _, err := Verify(token, keys); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIDC_AUDIENCE", "other")
	if _, err := Verify(token, keys); err == nil {
		t.Fatal("expected audience mismatch")
	}
}
