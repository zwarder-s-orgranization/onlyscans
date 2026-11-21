package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestStripsHallucinatedCVE(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		text        string
		allow       map[string]struct{}
		wantStrip   int
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "uppercase real kept and fake stripped",
			text:        "риск CVE-2022-42889 и выдуманный CVE-1999-0001",
			allow:       map[string]struct{}{"CVE-2022-42889": {}},
			wantStrip:   1,
			wantContain: []string{"CVE-2022-42889", "[removed-advisory]"},
			wantAbsent:  []string{"CVE-1999-0001"},
		},
		{
			name:        "case-insensitive cve and ghsa cannot bypass allowlist",
			text:        "подтверждённая cve-2022-42889, фейки cve-1999-9999 и GHSA-ABCD-1234-EFGH и ghsa-0000-1111-2222",
			allow:       map[string]struct{}{"CVE-2022-42889": {}, "GHSA-abcd-1234-efgh": {}},
			wantStrip:   2,
			wantContain: []string{"cve-2022-42889", "GHSA-ABCD-1234-EFGH"},
			wantAbsent:  []string{"cve-1999-9999", "ghsa-0000-1111-2222"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, n := StripUnknownAdvisories(tt.text, tt.allow)
			if n != tt.wantStrip {
				t.Fatalf("stripped = %d, want %d (out=%q)", n, tt.wantStrip, out)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(out, want) {
					t.Fatalf("expected %q in %q", want, out)
				}
			}
			for _, bad := range tt.wantAbsent {
				if strings.Contains(out, bad) {
					t.Fatalf("unexpected %q in %q", bad, out)
				}
			}
		})
	}
}

func TestTruncateRunesPreservesUTF8(t *testing.T) {
	t.Parallel()
	in := "Кириллица и эмодзи 🔒 текст"
	got := truncateRunes(in, 10)
	if !utf8.ValidString(got) {
		t.Fatalf("truncateRunes produced invalid UTF-8: %q", got)
	}
	if len([]rune(got)) != 10 {
		t.Fatalf("rune length = %d, want 10", len([]rune(got)))
	}
}
