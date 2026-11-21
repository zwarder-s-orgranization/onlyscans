package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/urlguard"
)

type testZipEntry struct {
	name string
	mode os.FileMode
	body []byte
}

func makeZipBytes(t *testing.T, entries []testZipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{
			Name:   e.name,
			Method: zip.Deflate,
		}
		if e.mode != 0 {
			hdr.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create zip header %q: %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := w.Write(e.body); err != nil {
				t.Fatalf("write zip entry %q: %v", e.name, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func makeZeroZip(t *testing.T, files int, bytesPerFile int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	chunk := make([]byte, 64<<10)
	for i := range files {
		w, err := zw.Create("blob-" + strconv.Itoa(i) + ".bin")
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		rem := bytesPerFile
		for rem > 0 {
			n := min(rem, int64(len(chunk)))
			if _, err := w.Write(chunk[:n]); err != nil {
				t.Fatalf("write zeros: %v", err)
			}
			rem -= n
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// forgeZipCentralDirUncompressedSize overwrites the 32-bit uncompressed size field
// in every ZIP central directory file header (PK\x01\x02, offset +24) to forgedSize.
func forgeZipCentralDirUncompressedSize(t *testing.T, raw []byte, forgedSize uint32) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	sig := []byte{0x50, 0x4b, 0x01, 0x02}
	patched := 0
	for i := 0; i <= len(out)-30; i++ {
		if bytes.Equal(out[i:i+4], sig) {
			binary.LittleEndian.PutUint32(out[i+24:i+28], forgedSize)
			patched++
		}
	}
	if patched == 0 {
		t.Fatal("failed to locate central directory header in zip")
	}
	return out
}

func readTarGzEntries(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			t.Fatalf("unexpected non-regular tar entry %q type %q", hdr.Name, hdr.Typeflag)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %q: %v", hdr.Name, err)
		}
		got[hdr.Name] = string(b)
	}
	return got
}

func newTestServer() *server {
	return &server{
		sources:        map[string]*secflowv1.SourceRef{},
		blobConfigured: func() bool { return false },
	}
}

func TestIngestUploadRejectsZipSlipAndUnsafeModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		entry testZipEntry
	}{
		{name: "parent traversal", entry: testZipEntry{name: "../evil.txt", body: []byte("bad")}},
		{name: "nested traversal", entry: testZipEntry{name: "a/../../evil.txt", body: []byte("bad")}},
		{name: "absolute path", entry: testZipEntry{name: "/etc/passwd", body: []byte("bad")}},
		{name: "double slash absolute", entry: testZipEntry{name: "//etc/passwd", body: []byte("bad")}},
		{name: "windows backslash", entry: testZipEntry{name: `dir\sub\file.txt`, body: []byte("bad")}},
		{name: "windows drive letter", entry: testZipEntry{name: `C:\Windows\win.ini`, body: []byte("bad")}},
		{name: "windows drive forward slash", entry: testZipEntry{name: "C:/evil.txt", body: []byte("bad")}},
		{name: "symlink entry", entry: testZipEntry{name: "leak", mode: os.ModeSymlink | 0o777, body: []byte("/etc/passwd")}},
		{name: "fifo entry", entry: testZipEntry{name: "pipe", mode: os.ModeNamedPipe | 0o644}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newTestServer()
			raw := makeZipBytes(t, []testZipEntry{tt.entry})
			_, err := srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
				Filename:   "test.zip",
				ArchiveZip: raw,
			})
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %v", err)
			}
			if st.Code() != codes.InvalidArgument || st.Message() != codeZipSlipDetected {
				t.Fatalf("got (%v, %q), want (%v, %q)", st.Code(), st.Message(), codes.InvalidArgument, codeZipSlipDetected)
			}
		})
	}
}

func TestIngestUploadZipBombProtection(t *testing.T) {
	t.Parallel()

	t.Run("forged zero uncompressed header rejected without OOM", func(t *testing.T) {
		t.Parallel()
		raw := makeZeroZip(t, 1, maxZipFileBytes+1)
		forged := forgeZipCentralDirUncompressedSize(t, raw, 0)

		zr, err := zip.NewReader(bytes.NewReader(forged), int64(len(forged)))
		if err != nil {
			t.Fatalf("verify forged zip readable: %v", err)
		}
		if zr.File[0].UncompressedSize64 != 0 {
			t.Fatalf("expected forged UncompressedSize64 == 0, got %d", zr.File[0].UncompressedSize64)
		}

		srv := newTestServer()
		_, err = srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
			Filename:   "bomb-zero.zip",
			ArchiveZip: forged,
		})
		if err == nil {
			t.Fatal("expected forged zero-size zip bomb to be rejected")
		}
		if len(srv.sources) != 0 {
			t.Fatalf("rejected bomb must not be recorded in sources, got %d", len(srv.sources))
		}
	})

	t.Run("forged multi-gigabyte header aborts streaming at per-file limit without OOM", func(t *testing.T) {
		t.Parallel()
		raw := makeZeroZip(t, 1, maxZipFileBytes+(64<<10))
		forged := forgeZipCentralDirUncompressedSize(t, raw, 0xFFFFFFF0)

		zr, err := zip.NewReader(bytes.NewReader(forged), int64(len(forged)))
		if err != nil {
			t.Fatalf("verify forged zip readable: %v", err)
		}
		if zr.File[0].UncompressedSize64 != 0xFFFFFFF0 {
			t.Fatalf("expected forged UncompressedSize64 == 0xFFFFFFF0, got %d", zr.File[0].UncompressedSize64)
		}

		srv := newTestServer()
		_, err = srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
			Filename:   "bomb-forged-huge.zip",
			ArchiveZip: forged,
		})
		st := status.Convert(err)
		if st.Code() != codes.ResourceExhausted || st.Message() != codeZipBombDetected {
			t.Fatalf("got (%v, %q), want (%v, %q)", st.Code(), st.Message(), codes.ResourceExhausted, codeZipBombDetected)
		}
	})

	t.Run("single file exceeding 20 MiB per-file limit", func(t *testing.T) {
		t.Parallel()
		raw := makeZeroZip(t, 1, maxZipFileBytes+1)
		srv := newTestServer()
		_, err := srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
			Filename:   "single-bomb.zip",
			ArchiveZip: raw,
		})
		st := status.Convert(err)
		if st.Code() != codes.ResourceExhausted || st.Message() != codeZipBombDetected {
			t.Fatalf("got (%v, %q), want (%v, %q)", st.Code(), st.Message(), codes.ResourceExhausted, codeZipBombDetected)
		}
	})

	t.Run("cumulative decompressed size exceeds total limit", func(t *testing.T) {
		t.Parallel()
		raw := makeZeroZip(t, 6, 18<<20) // 108 MiB > 100 MiB
		srv := newTestServer()
		_, err := srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
			Filename:   "multi-bomb.zip",
			ArchiveZip: raw,
		})
		st := status.Convert(err)
		if st.Code() != codes.ResourceExhausted || st.Message() != codeZipBombDetected {
			t.Fatalf("got (%v, %q), want (%v, %q)", st.Code(), st.Message(), codes.ResourceExhausted, codeZipBombDetected)
		}
	})

	t.Run("too many files", func(t *testing.T) {
		t.Parallel()
		entries := make([]testZipEntry, maxZipFiles+1)
		for i := range entries {
			entries[i] = testZipEntry{name: "f" + strconv.Itoa(i) + ".txt", body: []byte("x")}
		}
		srv := newTestServer()
		_, err := srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
			Filename:   "many.zip",
			ArchiveZip: makeZipBytes(t, entries),
		})
		st := status.Convert(err)
		if st.Code() != codes.ResourceExhausted || st.Message() != codeZipBombDetected {
			t.Fatalf("got (%v, %q), want (%v, %q)", st.Code(), st.Message(), codes.ResourceExhausted, codeZipBombDetected)
		}
	})
}

func TestIngestUploadValidCountsFilesAndDeduplicates(t *testing.T) {
	t.Parallel()
	srv := newTestServer()
	raw := makeZipBytes(t, []testZipEntry{
		{name: "src/", mode: os.ModeDir | 0o755},
		{name: "src/Main.kt", body: []byte("fun main() {}")},
		{name: "build.gradle.kts", body: []byte("plugins {}")},
	})

	resp1, err := srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
		Filename:   "demo.zip",
		RepoName:   "repair-desk",
		ArchiveZip: raw,
	})
	if err != nil {
		t.Fatalf("first IngestUpload failed: %v", err)
	}
	ref := resp1.GetSourceRef()
	if ref.GetFileCount() != 2 {
		t.Fatalf("FileCount = %d, want 2", ref.GetFileCount())
	}
	if ref.GetSizeBytes() <= 0 || len(ref.GetSha256()) != 64 {
		t.Fatalf("unexpected ref metadata: %+v", ref)
	}
	if resp1.GetDeduplicatedHit() {
		t.Fatal("expected DeduplicatedHit=false on first upload")
	}

	resp2, err := srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
		Filename:   "demo.zip",
		RepoName:   "repair-desk",
		ArchiveZip: raw,
	})
	if err != nil {
		t.Fatalf("second IngestUpload failed: %v", err)
	}
	if !resp2.GetDeduplicatedHit() {
		t.Fatal("expected DeduplicatedHit=true on identical second upload")
	}
}

func TestIngestUploadPropagatesGarageError(t *testing.T) {
	t.Parallel()
	srv := &server{
		sources:        map[string]*secflowv1.SourceRef{},
		blobConfigured: func() bool { return true },
		putBlob: func(_ context.Context, _, _ string, _ []byte) error {
			return errors.New("garage internal secret connection string failure")
		},
	}
	raw := makeZipBytes(t, []testZipEntry{
		{name: "README.md", body: []byte("hi")},
	})
	_, err := srv.IngestUpload(context.Background(), &secflowv1.IngestUploadRequest{
		Filename:   "demo.zip",
		ArchiveZip: raw,
	})
	st := status.Convert(err)
	if st.Code() != codes.Internal {
		t.Fatalf("got code %v, want %v", st.Code(), codes.Internal)
	}
	if strings.Contains(st.Message(), "connection string") {
		t.Fatalf("error message leaked internal details: %q", st.Message())
	}
	if len(srv.sources) != 0 {
		t.Fatalf("failed upload must not populate sources cache, got %d entries", len(srv.sources))
	}
}

func TestCloneTreeChecksOutCommitSHAAndPopulatesMetadata(t *testing.T) {
	t.Parallel()
	repoDir := t.TempDir()
	repo, err := git.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("git init: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}

	writeFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(repoDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir %q: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %q: %v", rel, err)
		}
		if _, err := wt.Add(rel); err != nil {
			t.Fatalf("git add %q: %v", rel, err)
		}
	}

	sig := &object.Signature{Name: "SecFlow Test", Email: "test@secflow.local", When: time.Unix(1700000000, 0)}

	writeFile("src/App.kt", "val version = 1")
	writeFile("README.md", "commit 1")
	commit1, err := wt.Commit("first commit", &git.CommitOptions{Author: sig})
	if err != nil {
		t.Fatalf("commit 1: %v", err)
	}

	writeFile("src/App.kt", "val version = 2")
	writeFile("extra.kt", "val extra = true")
	commit2, err := wt.Commit("second commit", &git.CommitOptions{Author: sig})
	if err != nil {
		t.Fatalf("commit 2: %v", err)
	}

	tests := []struct {
		name      string
		gitRef    string
		wantSHA   string
		wantCount int32
		wantApp   string
		wantExtra bool
	}{
		{
			name:      "default HEAD",
			gitRef:    "",
			wantSHA:   commit2.String(),
			wantCount: 3,
			wantApp:   "val version = 2",
			wantExtra: true,
		},
		{
			name:      "full commit 1 SHA",
			gitRef:    commit1.String(),
			wantSHA:   commit1.String(),
			wantCount: 2,
			wantApp:   "val version = 1",
			wantExtra: false,
		},
		{
			name:      "abbreviated commit 1 SHA",
			gitRef:    commit1.String()[:8],
			wantSHA:   commit1.String(),
			wantCount: 2,
			wantApp:   "val version = 1",
			wantExtra: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := cloneTree(context.Background(), repoDir, tt.gitRef, "")
			if err != nil {
				t.Fatalf("cloneTree(%q) failed: %v", tt.gitRef, err)
			}
			if res.commitSHA != tt.wantSHA {
				t.Fatalf("commitSHA = %q, want %q", res.commitSHA, tt.wantSHA)
			}
			if res.fileCount != tt.wantCount {
				t.Fatalf("fileCount = %d, want %d", res.fileCount, tt.wantCount)
			}
			entries := readTarGzEntries(t, res.archive)
			if entries["src/App.kt"] != tt.wantApp {
				t.Fatalf("src/App.kt = %q, want %q", entries["src/App.kt"], tt.wantApp)
			}
			_, hasExtra := entries["extra.kt"]
			if hasExtra != tt.wantExtra {
				t.Fatalf("hasExtra = %v, want %v", hasExtra, tt.wantExtra)
			}
		})
	}
}

func TestClassifyGitEntrySkipsSymlinksAndSpecialFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rel  string
		mode os.FileMode
		want gitEntryAction
	}{
		{name: "root dot", rel: ".", mode: os.ModeDir | 0o755, want: gitEntrySkip},
		{name: "git dir", rel: ".git", mode: os.ModeDir | 0o755, want: gitEntrySkipDir},
		{name: "git nested file", rel: filepath.Join(".git", "config"), mode: 0o644, want: gitEntrySkip},
		{name: "symlink skipped", rel: "exfil.txt", mode: os.ModeSymlink | 0o777, want: gitEntrySkip},
		{name: "fifo skipped", rel: "pipe", mode: os.ModeNamedPipe | 0o644, want: gitEntrySkip},
		{name: "device skipped", rel: "dev", mode: os.ModeDevice | 0o644, want: gitEntrySkip},
		{name: "socket skipped", rel: "sock", mode: os.ModeSocket | 0o644, want: gitEntrySkip},
		{name: "regular dir included", rel: "src", mode: os.ModeDir | 0o755, want: gitEntryDir},
		{name: "regular file included", rel: "src/Main.kt", mode: 0o644, want: gitEntryFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyGitEntry(tt.rel, tt.mode); got != tt.want {
				t.Fatalf("classifyGitEntry(%q, %v) = %v, want %v", tt.rel, tt.mode, got, tt.want)
			}
		})
	}
}

func TestTarGzSkipsSymlinks(t *testing.T) {
	t.Parallel()
	outsideDir := t.TempDir()
	outsideSecret := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideSecret, []byte("TOP_SECRET"), 0o600); err != nil {
		t.Fatalf("write outside secret: %v", err)
	}

	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "main.kt"), []byte("fun main() {}"), 0o600); err != nil {
		t.Fatalf("write main.kt: %v", err)
	}
	linkPath := filepath.Join(repoDir, "exfil.txt")
	if err := os.Symlink(outsideSecret, linkPath); err != nil {
		t.Skipf("os.Symlink not permitted in this environment: %v", err)
	}

	archive, fileCount, err := tarGz(repoDir)
	if err != nil {
		t.Fatalf("tarGz failed: %v", err)
	}
	if fileCount != 1 {
		t.Fatalf("fileCount = %d, want 1 (symlink must be skipped)", fileCount)
	}
	entries := readTarGzEntries(t, archive)
	if _, leaked := entries["exfil.txt"]; leaked {
		t.Fatal("symlink target was exfiltrated into tar.gz archive")
	}
	if entries["main.kt"] != "fun main() {}" {
		t.Fatalf("main.kt = %q, want %q", entries["main.kt"], "fun main() {}")
	}
}

func TestCloneTreeBlocksLoopbackSSRFViaSafeGitHTTPTransport(t *testing.T) {
	t.Setenv("MCP_ALLOW_PRIVATE", "")
	hit := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		http.Error(w, "should not be reached", http.StatusOK)
	}))
	defer ts.Close()

	_, err := cloneTree(context.Background(), ts.URL+"/repo.git", "", "")
	if err == nil {
		t.Fatal("expected safe git HTTP transport to block loopback SSRF target")
	}
	if !errors.Is(err, urlguard.ErrAllowlistDenied) {
		t.Fatalf("expected ErrAllowlistDenied in error chain, got %v", err)
	}
	if hit {
		t.Fatal("loopback server was contacted despite safe git HTTP transport")
	}
}

func TestMapCloneErrorSanitizesInternalErrors(t *testing.T) {
	t.Parallel()
	raw := errors.New("authentication failed for https://x-access-token:ghp_SUPERSECRET@github.com/org/repo.git")
	st := status.Convert(mapCloneError(raw))
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	if strings.Contains(st.Message(), "ghp_SUPERSECRET") {
		t.Fatalf("sanitized error leaked token: %q", st.Message())
	}
}
