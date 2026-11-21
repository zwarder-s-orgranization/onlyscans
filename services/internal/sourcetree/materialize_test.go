package sourcetree

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type tarSpec struct {
	name     string
	typeflag byte
	linkname string
	body     []byte
}

func buildTarGz(t *testing.T, specs []tarSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, s := range specs {
		tf := s.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     s.name,
			Typeflag: tf,
			Linkname: s.linkname,
			Mode:     0o644,
			Size:     int64(len(s.body)),
		}
		if tf == tar.TypeDir {
			hdr.Mode = 0o755
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %q: %v", s.name, err)
		}
		if tf == tar.TypeReg && len(s.body) > 0 {
			if _, err := tw.Write(s.body); err != nil {
				t.Fatalf("write tar body %q: %v", s.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

type zipSpec struct {
	name string
	mode os.FileMode
	body []byte
}

func buildZip(t *testing.T, specs []zipSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, s := range specs {
		hdr := &zip.FileHeader{
			Name:   s.name,
			Method: zip.Deflate,
		}
		if s.mode != 0 {
			hdr.SetMode(s.mode)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create zip header %q: %v", s.name, err)
		}
		if len(s.body) > 0 {
			if _, err := w.Write(s.body); err != nil {
				t.Fatalf("write zip body %q: %v", s.name, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func buildZeroTarGz(t *testing.T, files int, bytesPerFile int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	chunk := make([]byte, 64<<10)
	for i := range files {
		hdr := &tar.Header{
			Name:     "f" + strconv.Itoa(i) + ".bin",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     bytesPerFile,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		rem := bytesPerFile
		for rem > 0 {
			n := min(rem, int64(len(chunk)))
			if _, err := tw.Write(chunk[:n]); err != nil {
				t.Fatalf("write tar zeros: %v", err)
			}
			rem -= n
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func buildZeroZip(t *testing.T, files int, bytesPerFile int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	chunk := make([]byte, 64<<10)
	for i := range files {
		w, err := zw.Create("f" + strconv.Itoa(i) + ".bin")
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		rem := bytesPerFile
		for rem > 0 {
			n := min(rem, int64(len(chunk)))
			if _, err := w.Write(chunk[:n]); err != nil {
				t.Fatalf("write zip zeros: %v", err)
			}
			rem -= n
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func TestUntarRejectsZipSlipAndUnsafeEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		spec    tarSpec
		wantErr error
	}{
		{name: "parent traversal", spec: tarSpec{name: "../evil.txt", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "nested traversal", spec: tarSpec{name: "a/../../evil.txt", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "absolute unix path", spec: tarSpec{name: "/etc/passwd", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "double slash path", spec: tarSpec{name: "//etc/passwd", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "windows drive backslash", spec: tarSpec{name: `C:\Windows\win.ini`, body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "windows drive forward slash", spec: tarSpec{name: "C:/evil.txt", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "backslash separator", spec: tarSpec{name: `a\b\c.txt`, body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "symlink entry", spec: tarSpec{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}, wantErr: ErrUnsafeArchiveEntry},
		{name: "hardlink entry", spec: tarSpec{name: "hardlink", typeflag: tar.TypeLink, linkname: "/etc/passwd"}, wantErr: ErrUnsafeArchiveEntry},
		{name: "fifo entry", spec: tarSpec{name: "pipe", typeflag: tar.TypeFifo}, wantErr: ErrUnsafeArchiveEntry},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archive := buildTarGz(t, []tarSpec{tt.spec})
			err := untar(t.TempDir(), archive)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("untar(%s) err = %v, want %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestUnzipRejectsZipSlipAndUnsafeEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		spec    zipSpec
		wantErr error
	}{
		{name: "parent traversal", spec: zipSpec{name: "../evil.txt", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "nested traversal", spec: zipSpec{name: "a/../../evil.txt", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "absolute unix path", spec: zipSpec{name: "/etc/passwd", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "double slash path", spec: zipSpec{name: "//etc/passwd", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "windows drive backslash", spec: zipSpec{name: `C:\Windows\win.ini`, body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "windows drive forward slash", spec: zipSpec{name: "C:/evil.txt", body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "backslash separator", spec: zipSpec{name: `a\b\c.txt`, body: []byte("x")}, wantErr: ErrUnsafeArchivePath},
		{name: "symlink entry", spec: zipSpec{name: "link", mode: os.ModeSymlink | 0o777, body: []byte("/etc/passwd")}, wantErr: ErrUnsafeArchiveEntry},
		{name: "fifo entry", spec: zipSpec{name: "pipe", mode: os.ModeNamedPipe | 0o644}, wantErr: ErrUnsafeArchiveEntry},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archive := buildZip(t, []zipSpec{tt.spec})
			err := unzip(t.TempDir(), archive)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("unzip(%s) err = %v, want %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestArchiveLimitsEnforced(t *testing.T) {
	t.Parallel()

	t.Run("untar file count limit", func(t *testing.T) {
		t.Parallel()
		specs := make([]tarSpec, maxExtractFiles+1)
		for i := range specs {
			specs[i] = tarSpec{name: "dir/f" + strconv.Itoa(i) + ".txt", body: []byte("a")}
		}
		err := untar(t.TempDir(), buildTarGz(t, specs))
		if !errors.Is(err, ErrArchiveLimitExceeded) {
			t.Fatalf("untar file count err = %v, want %v", err, ErrArchiveLimitExceeded)
		}
	})

	t.Run("unzip file count limit", func(t *testing.T) {
		t.Parallel()
		specs := make([]zipSpec, maxExtractFiles+1)
		for i := range specs {
			specs[i] = zipSpec{name: "dir/f" + strconv.Itoa(i) + ".txt", body: []byte("a")}
		}
		err := unzip(t.TempDir(), buildZip(t, specs))
		if !errors.Is(err, ErrArchiveLimitExceeded) {
			t.Fatalf("unzip file count err = %v, want %v", err, ErrArchiveLimitExceeded)
		}
	})

	t.Run("untar per-file byte limit", func(t *testing.T) {
		t.Parallel()
		archive := buildZeroTarGz(t, 1, maxExtractFileBytes+1)
		err := untar(t.TempDir(), archive)
		if !errors.Is(err, ErrArchiveLimitExceeded) {
			t.Fatalf("untar per-file err = %v, want %v", err, ErrArchiveLimitExceeded)
		}
	})

	t.Run("unzip per-file byte limit", func(t *testing.T) {
		t.Parallel()
		archive := buildZeroZip(t, 1, maxExtractFileBytes+1)
		err := unzip(t.TempDir(), archive)
		if !errors.Is(err, ErrArchiveLimitExceeded) {
			t.Fatalf("unzip per-file err = %v, want %v", err, ErrArchiveLimitExceeded)
		}
	})

	t.Run("untar total byte limit", func(t *testing.T) {
		t.Parallel()
		archive := buildZeroTarGz(t, 6, 18<<20) // 108 MiB > 100 MiB
		err := untar(t.TempDir(), archive)
		if !errors.Is(err, ErrArchiveLimitExceeded) {
			t.Fatalf("untar total err = %v, want %v", err, ErrArchiveLimitExceeded)
		}
	})

	t.Run("unzip total byte limit", func(t *testing.T) {
		t.Parallel()
		archive := buildZeroZip(t, 6, 18<<20) // 108 MiB > 100 MiB
		err := unzip(t.TempDir(), archive)
		if !errors.Is(err, ErrArchiveLimitExceeded) {
			t.Fatalf("unzip total err = %v, want %v", err, ErrArchiveLimitExceeded)
		}
	})
}

func TestExtractValidArchives(t *testing.T) {
	t.Parallel()

	t.Run("valid tar.gz", func(t *testing.T) {
		t.Parallel()
		raw := buildTarGz(t, []tarSpec{
			{name: "src", typeflag: tar.TypeDir},
			{name: "src/Main.kt", body: []byte("fun main() {}")},
		})
		dir, err := extract(raw)
		if err != nil {
			t.Fatalf("extract tar.gz: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()

		got, err := os.ReadFile(filepath.Join(dir, "src", "Main.kt"))
		if err != nil {
			t.Fatalf("read extracted file: %v", err)
		}
		if string(got) != "fun main() {}" {
			t.Fatalf("got %q, want %q", string(got), "fun main() {}")
		}
	})

	t.Run("valid zip", func(t *testing.T) {
		t.Parallel()
		raw := buildZip(t, []zipSpec{
			{name: "src/", mode: os.ModeDir | 0o755},
			{name: "src/App.kt", body: []byte("val x = 1")},
		})
		dir, err := extract(raw)
		if err != nil {
			t.Fatalf("extract zip: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()

		got, err := os.ReadFile(filepath.Join(dir, "src", "App.kt"))
		if err != nil {
			t.Fatalf("read extracted file: %v", err)
		}
		if string(got) != "val x = 1" {
			t.Fatalf("got %q, want %q", string(got), "val x = 1")
		}
	})
}

func TestResolveDoesNotFallbackToSourceRootOnGarageFailure(t *testing.T) {
	fallbackDir := t.TempDir()
	t.Setenv("SOURCE_ROOT", fallbackDir)
	t.Setenv("GARAGE_CRED_FILE", filepath.Join(t.TempDir(), "missing-garage.json"))

	envelope := []byte(`{"vars":{"sourceBucket":"secflow-sources","sourceKey":"abc.tar.gz"}}`)

	t.Run("garage HTTP 500 error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "storage unavailable", http.StatusInternalServerError)
		}))
		defer srv.Close()

		t.Setenv("GARAGE_ENDPOINT", srv.URL)
		t.Setenv("GARAGE_ACCESS_KEY", "test-access")
		t.Setenv("GARAGE_SECRET_KEY", "test-secret")

		dir, cleanup, err := ResolveErr(context.Background(), envelope)
		cleanup()
		if err == nil {
			t.Fatal("expected error from ResolveErr on Garage 500")
		}
		if dir != "" {
			t.Fatalf("ResolveErr returned dir=%q, want empty (must not fall back to SOURCE_ROOT)", dir)
		}

		dir2, cleanup2 := Resolve(context.Background(), envelope)
		cleanup2()
		if dir2 != "" {
			t.Fatalf("Resolve returned dir=%q, want empty (must not fall back to SOURCE_ROOT)", dir2)
		}
	})

	t.Run("malicious archive from garage", func(t *testing.T) {
		badArchive := buildTarGz(t, []tarSpec{{name: "../escape.txt", body: []byte("pwn")}})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, bytes.NewReader(badArchive))
		}))
		defer srv.Close()

		t.Setenv("GARAGE_ENDPOINT", srv.URL)
		t.Setenv("GARAGE_ACCESS_KEY", "test-access")
		t.Setenv("GARAGE_SECRET_KEY", "test-secret")

		dir, cleanup, err := ResolveErr(context.Background(), envelope)
		cleanup()
		if !errors.Is(err, ErrUnsafeArchivePath) {
			t.Fatalf("ResolveErr err = %v, want %v", err, ErrUnsafeArchivePath)
		}
		if dir != "" {
			t.Fatalf("ResolveErr returned dir=%q, want empty", dir)
		}

		dir2, cleanup2 := Resolve(context.Background(), envelope)
		cleanup2()
		if dir2 != "" {
			t.Fatalf("Resolve returned dir=%q, want empty (must not fall back to SOURCE_ROOT)", dir2)
		}
	})

	t.Run("unconfigured garage with explicit source ref", func(t *testing.T) {
		t.Setenv("GARAGE_ENDPOINT", "")
		t.Setenv("GARAGE_ACCESS_KEY", "")
		t.Setenv("GARAGE_SECRET_KEY", "")

		dir, cleanup, err := ResolveErr(context.Background(), envelope)
		cleanup()
		if !errors.Is(err, ErrEmptySourceObject) {
			t.Fatalf("ResolveErr err = %v, want %v", err, ErrEmptySourceObject)
		}
		if dir != "" {
			t.Fatalf("ResolveErr returned dir=%q, want empty", dir)
		}

		dir2, cleanup2 := Resolve(context.Background(), envelope)
		cleanup2()
		if dir2 != "" {
			t.Fatalf("Resolve returned dir=%q, want empty", dir2)
		}
	})

	t.Run("valid archive from garage", func(t *testing.T) {
		goodArchive := buildTarGz(t, []tarSpec{{name: "README.md", body: []byte("hello")}})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(goodArchive)
		}))
		defer srv.Close()

		t.Setenv("GARAGE_ENDPOINT", srv.URL)
		t.Setenv("GARAGE_ACCESS_KEY", "test-access")
		t.Setenv("GARAGE_SECRET_KEY", "test-secret")

		dir, cleanup, err := ResolveErr(context.Background(), envelope)
		if err != nil {
			t.Fatalf("ResolveErr valid archive: %v", err)
		}
		defer cleanup()

		got, err := os.ReadFile(filepath.Join(dir, "README.md"))
		if err != nil {
			t.Fatalf("read README.md: %v", err)
		}
		if string(got) != "hello" {
			t.Fatalf("got %q, want hello", string(got))
		}
	})

	t.Run("no source ref falls back to SOURCE_ROOT", func(t *testing.T) {
		dir, cleanup, err := ResolveErr(context.Background(), []byte(`{"vars":{}}`))
		cleanup()
		if err != nil {
			t.Fatalf("ResolveErr without source ref: %v", err)
		}
		if dir != fallbackDir {
			t.Fatalf("ResolveErr dir = %q, want %q", dir, fallbackDir)
		}
	})
}
