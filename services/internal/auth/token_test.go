package auth

import (
	"testing"
	"time"
)

func TestHS256JWTRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	futureExp := time.Now().Add(time.Hour).Unix()

	token, err := Sign(secret, Claims{Subject: "owner@secflow.local", Email: "owner@secflow.local", Role: "owner", Exp: futureExp})
	if err != nil {
		t.Fatal(err)
	}
	parts := 0
	for _, c := range token {
		if c == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Fatalf("token %s is not a three-part jwt", token)
	}
	got, err := Verify(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "owner" {
		t.Fatalf("%+v", got)
	}
	if _, err := Verify(secret, token+"x"); err == nil {
		t.Fatal("expected bad signature")
	}
}

func TestVerify_ExpValidation(t *testing.T) {
	secret := []byte("test-secret")
	now := time.Now().Unix()

	tests := []struct {
		name    string
		exp     int64
		wantErr bool
	}{
		{
			name:    "future expiry accepted",
			exp:     now + 300,
			wantErr: false,
		},
		{
			name:    "zero expiry rejected",
			exp:     0,
			wantErr: true,
		},
		{
			name:    "negative expiry rejected",
			exp:     -100,
			wantErr: true,
		},
		{
			name:    "current timestamp rejected",
			exp:     now,
			wantErr: true,
		},
		{
			name:    "past expiry rejected",
			exp:     now - 60,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := Sign(secret, Claims{Subject: "user@secflow.local", Role: "viewer", Exp: tt.exp})
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			_, err = Verify(secret, tok)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Verify() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
