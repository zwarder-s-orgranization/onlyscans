package springscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindsExposureAndPassword(t *testing.T) {
	dir := t.TempDir()
	body := "spring:\n  datasource:\n    password: hunter2\nmanagement:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n"
	if err := os.WriteFile(filepath.Join(dir, "application.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Scan(dir)
	if len(got) < 2 {
		t.Fatalf("got %#v", got)
	}
}
