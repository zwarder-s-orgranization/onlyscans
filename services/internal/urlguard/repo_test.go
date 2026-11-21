package urlguard

import "testing"

func TestRepoAllowed(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		allowlist string
		wantOK    bool
	}{
		{
			name:   "default allowlist allows organizer training repo",
			url:    "https://github.com/TBagirov/training.git",
			wantOK: true,
		},
		{
			name:   "default allowlist blocks arbitrary github repo",
			url:    "https://github.com/some-random-org/production-bank",
			wantOK: false,
		},
		{
			name:      "owner wildcard allows team educational repos",
			url:       "https://github.com/my-edu-org/kotlin-demo",
			allowlist: "github.com/TBagirov/training,github.com/my-edu-org/*",
			wantOK:    true,
		},
		{
			name:      "blocks http scheme even when path matches",
			url:       "http://github.com/TBagirov/training",
			allowlist: "github.com/TBagirov/training",
			wantOK:    false,
		},
		{
			name:      "blocks metadata ip",
			url:       "https://169.254.169.254/latest/meta-data",
			allowlist: "169.254.169.254",
			wantOK:    false,
		},
		{
			name:      "blocks embedded user and password credentials",
			url:       "https://user:ghp_secret123@github.com/TBagirov/training.git",
			allowlist: "github.com/TBagirov/training",
			wantOK:    false,
		},
		{
			name:      "blocks embedded token username",
			url:       "https://oauth2@github.com/TBagirov/training",
			allowlist: "github.com/TBagirov/training",
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("REPO_ALLOWLIST", "")
			ok, _, _ := RepoAllowed(tt.url, tt.allowlist)
			if ok != tt.wantOK {
				t.Fatalf("RepoAllowed(%q, %q) = %v, want %v", tt.url, tt.allowlist, ok, tt.wantOK)
			}
		})
	}
}
