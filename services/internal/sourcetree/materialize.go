// Package sourcetree turns a stored source object into a local directory.
package sourcetree

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/secflow/secflow/services/internal/blobstore"
)

const (
	maxExtractFiles      = 5000
	maxExtractEntries    = 10000
	maxExtractFileBytes  = 20 << 20  // 20 MiB per file.
	maxExtractTotalBytes = 100 << 20 // 100 MiB cumulative extracted bytes.
)

var (
	// ErrUnsafeArchivePath indicates an archive entry attempted path traversal or used a disallowed path format.
	ErrUnsafeArchivePath = errors.New("unsafe archive path")
	// ErrUnsafeArchiveEntry indicates an archive contained a symlink, hardlink, or non-regular file entry.
	ErrUnsafeArchiveEntry = errors.New("unsafe archive entry type")
	// ErrArchiveLimitExceeded indicates an archive exceeded file count or decompressed byte limits.
	ErrArchiveLimitExceeded = errors.New("archive extraction limit exceeded")
	// ErrEmptySourceObject indicates Garage returned an empty payload for an explicit source reference.
	ErrEmptySourceObject = errors.New("empty source object")
	// ErrIncompleteSourceRef indicates only one of sourceBucket or sourceKey was provided in the envelope.
	ErrIncompleteSourceRef = errors.New("incomplete source reference")
)

// Resolve downloads sourceBucket/sourceKey from the envelope, or returns SOURCE_ROOT when no explicit
// source reference is present. On Garage fetch or archive extraction errors, Resolve logs the error
// and returns ("", noop) without falling back to SOURCE_ROOT.
func Resolve(ctx context.Context, envelopeJSON []byte) (string, func()) {
	dir, cleanup, err := ResolveErr(ctx, envelopeJSON)
	if err != nil {
		slog.ErrorContext(ctx, "materialize source failed", "err", err)
		return "", func() {}
	}
	return dir, cleanup
}

// ResolveErr downloads and safely extracts sourceBucket/sourceKey from the envelope.
// When sourceBucket/sourceKey is present and fetching or extraction fails, it returns an explicit error
// instead of falling back to SOURCE_ROOT.
func ResolveErr(ctx context.Context, envelopeJSON []byte) (string, func(), error) {
	noop := func() {}
	bucket, key := parseEnvelopeSource(envelopeJSON)
	if bucket != "" || key != "" {
		if bucket == "" || key == "" {
			return "", noop, ErrIncompleteSourceRef
		}
		raw, err := blobstore.Get(ctx, bucket, key)
		if err != nil {
			return "", noop, fmt.Errorf("fetch source %s/%s: %w", bucket, key, err)
		}
		if len(raw) == 0 {
			return "", noop, fmt.Errorf("fetch source %s/%s: %w", bucket, key, ErrEmptySourceObject)
		}
		dir, err := extract(raw)
		if err != nil {
			return "", noop, fmt.Errorf("extract source %s/%s: %w", bucket, key, err)
		}
		return dir, func() { _ = os.RemoveAll(dir) }, nil
	}
	if root := os.Getenv("SOURCE_ROOT"); root != "" {
		return root, noop, nil
	}
	return "", noop, nil
}

func parseEnvelopeSource(envelopeJSON []byte) (bucket, key string) {
	var env struct {
		Vars map[string]string `json:"Vars"`
	}
	_ = json.Unmarshal(envelopeJSON, &env)
	if env.Vars == nil {
		var alt struct {
			Vars map[string]string `json:"vars"`
		}
		_ = json.Unmarshal(envelopeJSON, &alt)
		env.Vars = alt.Vars
	}
	return strings.TrimSpace(env.Vars["sourceBucket"]), strings.TrimSpace(env.Vars["sourceKey"])
}

func extract(raw []byte) (string, error) {
	dir, err := os.MkdirTemp("", "secflow-src-")
	if err != nil {
		return "", fmt.Errorf("create temp source dir: %w", err)
	}
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		err = untar(dir, raw)
	} else {
		err = unzip(dir, raw)
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func untar(dir string, raw []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open extract root: %w", err)
	}
	defer func() { _ = root.Close() }()

	tr := tar.NewReader(gz)
	var total int64
	var fileCount int
	var entryCount int
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		entryCount++
		if entryCount > maxExtractEntries {
			return ErrArchiveLimitExceeded
		}
		if err := validateTarEntryType(hdr); err != nil {
			return err
		}
		local, err := validateArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		if err := checkContained(dir, local); err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeDir {
			if local != "." {
				if err := root.MkdirAll(local, 0o750); err != nil {
					return fmt.Errorf("create dir %q: %w", local, err)
				}
			}
			continue
		}
		if local == "." {
			return ErrUnsafeArchivePath
		}
		fileCount++
		if fileCount > maxExtractFiles {
			return ErrArchiveLimitExceeded
		}
		n, err := writeRootFile(root, local, tr, maxExtractFileBytes, maxExtractTotalBytes-total)
		if err != nil {
			return err
		}
		total += n
	}
}

func unzip(dir string, raw []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return fmt.Errorf("open zip archive: %w", err)
	}
	if len(zr.File) > maxExtractEntries {
		return ErrArchiveLimitExceeded
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open extract root: %w", err)
	}
	defer func() { _ = root.Close() }()

	var total int64
	var fileCount int
	for _, f := range zr.File {
		if err := validateZipEntryMode(f.Mode()); err != nil {
			return err
		}
		local, err := validateArchivePath(f.Name)
		if err != nil {
			return err
		}
		if err := checkContained(dir, local); err != nil {
			return err
		}
		if f.Mode().IsDir() {
			if local != "." {
				if err := root.MkdirAll(local, 0o750); err != nil {
					return fmt.Errorf("create dir %q: %w", local, err)
				}
			}
			continue
		}
		if local == "." {
			return ErrUnsafeArchivePath
		}
		fileCount++
		if fileCount > maxExtractFiles {
			return ErrArchiveLimitExceeded
		}
		n, err := extractZipFile(root, local, f, maxExtractFileBytes, maxExtractTotalBytes-total)
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

func extractZipFile(root *os.Root, local string, f *zip.File, maxFile, remaining int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("open zip entry %q: %w", local, err)
	}
	defer func() { _ = rc.Close() }()
	return writeRootFile(root, local, rc, maxFile, remaining)
}

func writeRootFile(root *os.Root, local string, src io.Reader, maxFile, remaining int64) (int64, error) {
	if parent := filepath.Dir(local); parent != "." {
		if err := root.MkdirAll(parent, 0o750); err != nil {
			return 0, fmt.Errorf("create parent dir %q: %w", parent, err)
		}
	}
	out, err := root.OpenFile(local, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create file %q: %w", local, err)
	}
	n, copyErr := copyBounded(out, src, maxFile, remaining)
	closeErr := out.Close()
	if copyErr != nil {
		return n, copyErr
	}
	if closeErr != nil {
		return n, fmt.Errorf("close file %q: %w", local, closeErr)
	}
	return n, nil
}

func copyBounded(dst io.Writer, src io.Reader, maxFile, remaining int64) (int64, error) {
	if remaining < 0 {
		remaining = 0
	}
	limit := min(maxFile, remaining)
	n, err := io.Copy(dst, io.LimitReader(src, limit))
	if err != nil {
		return n, fmt.Errorf("copy entry bytes: %w", err)
	}
	extra, probeErr := io.Copy(io.Discard, io.LimitReader(src, 1))
	if extra > 0 {
		return n, ErrArchiveLimitExceeded
	}
	if probeErr != nil {
		return n, fmt.Errorf("probe entry overflow: %w", probeErr)
	}
	return n, nil
}

func validateTarEntryType(hdr *tar.Header) error {
	switch hdr.Typeflag {
	case tar.TypeDir, tar.TypeReg:
	default:
		return fmt.Errorf("%w: tar type %q", ErrUnsafeArchiveEntry, hdr.Typeflag)
	}
	mode := hdr.FileInfo().Mode()
	const forbidden = os.ModeSymlink | os.ModeDevice | os.ModeCharDevice | os.ModeNamedPipe | os.ModeSocket
	if mode&forbidden != 0 {
		return fmt.Errorf("%w: mode %v", ErrUnsafeArchiveEntry, mode)
	}
	return nil
}

func validateZipEntryMode(mode os.FileMode) error {
	const forbidden = os.ModeSymlink | os.ModeDevice | os.ModeCharDevice | os.ModeNamedPipe | os.ModeSocket | os.ModeIrregular
	if mode&forbidden != 0 {
		return fmt.Errorf("%w: mode %v", ErrUnsafeArchiveEntry, mode)
	}
	if !mode.IsDir() && !mode.IsRegular() {
		return fmt.Errorf("%w: non-regular mode %v", ErrUnsafeArchiveEntry, mode)
	}
	return nil
}

func validateArchivePath(raw string) (string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) || strings.ContainsRune(raw, '\\') || strings.HasPrefix(raw, "/") || strings.ContainsRune(raw, ':') {
		return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, raw)
	}
	trimmed := strings.TrimRight(raw, "/")
	if trimmed == "" {
		return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, raw)
	}
	if trimmed == "." {
		return ".", nil
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, raw)
		}
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "" || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, raw)
	}
	local := filepath.FromSlash(cleaned)
	if filepath.IsAbs(local) || !filepath.IsLocal(local) {
		return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, raw)
	}
	return local, nil
}

func checkContained(dir, local string) error {
	target := filepath.Join(dir, local)
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeArchivePath, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%w: %q escapes root", ErrUnsafeArchivePath, local)
	}
	return nil
}
