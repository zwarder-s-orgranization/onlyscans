package main

import (
	"testing"

	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

func TestGitAuthUsesTokenAsPassword(t *testing.T) {
	t.Parallel()
	if gitAuth("") != nil {
		t.Fatal("empty token")
	}
	auth, ok := gitAuth("secret-token").(*githttp.BasicAuth)
	if !ok {
		t.Fatalf("expected *githttp.BasicAuth, got %T", gitAuth("secret-token"))
	}
	if auth.Username != "x-access-token" || auth.Password != "secret-token" {
		t.Fatalf("%+v", auth)
	}
}
