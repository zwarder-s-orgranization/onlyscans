package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/urlguard"
)

const (
	sourceBucket             = "secflow-sources"
	maxCompressedUploadBytes = 50 << 20  // 50 MiB compressed upload and packed .tar.gz output.
	maxZipFiles              = 5000      // Max entries / regular files in an archive.
	maxZipFileBytes          = 20 << 20  // 20 MiB per file decompressed.
	maxZipTotalBytes         = 100 << 20 // 100 MiB cumulative decompressed bytes.
	gitCloneTotalTimeout     = 90 * time.Second
	gitCloneAttemptTimeout   = 35 * time.Second

	codeZipSlipDetected = "ZIP_SLIP_DETECTED"
	codeZipBombDetected = "ZIP_BOMB_DETECTED"
	codeAllowlistDenied = "ALLOWLIST_DENIED"
	errMsgInvalidZip    = "invalid zip"
	errMsgStoreFailed   = "failed to store source archive"
)

var (
	errPrivate        = errors.New("private address")
	errZipSlip        = errors.New("zip slip detected")
	errZipBomb        = errors.New("zip bomb detected")
	errCommitNotFound = errors.New("git ref not found")

	safeGitTransportOnce sync.Once
)

func main() {
	obs.SetupLogger("source-ingester")
	installSafeGitTransport()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "source-ingester")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}
	lis, err := net.Listen("tcp", envutil.Get("GRPC_ADDR", ":50052"))
	if err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
	if err := blobstore.Ensure(ctx); err != nil {
		slog.Warn("garage", "err", err)
	}
	gs := grpc.NewServer(obs.GRPCServerOptions("source-ingester")...)
	src := &server{sources: map[string]*secflowv1.SourceRef{}}
	if addr := os.Getenv("ORCHESTRATOR_ADDR"); addr != "" {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
		if err != nil {
			slog.Error("orchestrator", "err", err)
			os.Exit(1)
		}
		defer func() { _ = conn.Close() }()
		src.secrets = secflowv1.NewSecretServiceClient(conn)
	}
	secflowv1.RegisterSourceIngesterServiceServer(gs, src)
	httpserver.Start(ctx, envutil.Get("HTTP_ADDR", ":8082"))
	go func() {
		if err := gs.Serve(lis); err != nil {
			slog.Error("grpc", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	gs.GracefulStop()
}

type server struct {
	secflowv1.UnimplementedSourceIngesterServiceServer
	mu             sync.Mutex
	sources        map[string]*secflowv1.SourceRef
	secrets        secflowv1.SecretServiceClient
	blobConfigured func() bool
	putBlob        func(ctx context.Context, bucket, key string, body []byte) error
}

func (s *server) storeBlob(ctx context.Context, bucket, key string, body []byte) error {
	configured := blobstore.Configured
	if s.blobConfigured != nil {
		configured = s.blobConfigured
	}
	if !configured() {
		return nil
	}
	put := blobstore.Put
	if s.putBlob != nil {
		put = s.putBlob
	}
	return put(ctx, bucket, key, body)
}

func (s *server) IngestUpload(ctx context.Context, req *secflowv1.IngestUploadRequest) (*secflowv1.IngestUploadResponse, error) {
	packed, fileCount, err := packZipToTarGz(req.GetArchiveZip())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(packed)
	shaHex := hex.EncodeToString(sum[:])
	ref := &secflowv1.SourceRef{
		SourceId:  hex.EncodeToString(sum[:8]),
		Bucket:    sourceBucket,
		Key:       shaHex + ".tar.gz",
		Sha256:    shaHex,
		RepoName:  req.GetRepoName(),
		SizeBytes: int64(len(packed)),
		FileCount: fileCount,
	}
	if err := s.storeBlob(ctx, ref.GetBucket(), ref.GetKey(), packed); err != nil {
		slog.ErrorContext(ctx, "garage put failed", "bucket", ref.GetBucket(), "key", ref.GetKey(), "err", err)
		return nil, status.Error(codes.Internal, errMsgStoreFailed)
	}
	dup := s.recordSource(ref)
	return &secflowv1.IngestUploadResponse{SourceRef: ref, DeduplicatedHit: dup, IngestedAt: timestamppb.Now()}, nil
}

func (s *server) IngestGit(ctx context.Context, req *secflowv1.IngestGitRequest) (*secflowv1.IngestGitResponse, error) {
	allowed, code, reason := checkURL(req.GetRepoUrl())
	if !allowed {
		return nil, status.Errorf(codes.PermissionDenied, "%s: %s", code.String(), reason)
	}
	if err := rejectPrivateHost(ctx, req.GetRepoUrl()); err != nil {
		slog.WarnContext(ctx, "git repo host rejected", "repo_url", sanitizeURLForLog(req.GetRepoUrl()), "err", err)
		return nil, status.Error(codes.PermissionDenied, codeAllowlistDenied)
	}
	token, err := s.gitToken(ctx, req)
	if err != nil {
		slog.WarnContext(ctx, "resolve git token failed", "run_id", req.GetRunId(), "node_id", req.GetNodeId(), "err", err)
		return nil, status.Error(codes.PermissionDenied, "SECRET_SCOPE_DENIED")
	}
	res, err := cloneTree(ctx, req.GetRepoUrl(), req.GetGitRef(), token)
	if err != nil {
		slog.ErrorContext(ctx, "git clone failed", "repo_url", sanitizeURLForLog(req.GetRepoUrl()), "git_ref", req.GetGitRef(), "err", err)
		return nil, mapCloneError(err)
	}
	sum := sha256.Sum256(res.archive)
	shaHex := hex.EncodeToString(sum[:])
	ref := &secflowv1.SourceRef{
		SourceId:  hex.EncodeToString(sum[:8]),
		Bucket:    sourceBucket,
		Key:       shaHex + ".tar.gz",
		Sha256:    shaHex,
		RepoUrl:   req.GetRepoUrl(),
		GitRef:    req.GetGitRef(),
		CommitSha: res.commitSHA,
		SizeBytes: int64(len(res.archive)),
		FileCount: res.fileCount,
	}
	if err := s.storeBlob(ctx, ref.GetBucket(), ref.GetKey(), res.archive); err != nil {
		slog.ErrorContext(ctx, "garage put failed", "bucket", ref.GetBucket(), "key", ref.GetKey(), "err", err)
		return nil, status.Error(codes.Internal, errMsgStoreFailed)
	}
	dup := s.recordSource(ref)
	return &secflowv1.IngestGitResponse{SourceRef: ref, DeduplicatedHit: dup, IngestedAt: timestamppb.Now()}, nil
}

func (s *server) recordSource(ref *secflowv1.SourceRef) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sources == nil {
		s.sources = map[string]*secflowv1.SourceRef{}
	}
	_, dup := s.sources[ref.GetSha256()]
	s.sources[ref.GetSha256()] = ref
	return dup
}

func (s *server) GetSource(_ context.Context, req *secflowv1.GetSourceRequest) (*secflowv1.GetSourceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ref := range s.sources {
		if ref.GetSourceId() == req.GetSourceId() || ref.GetSha256() == req.GetSourceId() {
			return &secflowv1.GetSourceResponse{SourceRef: ref, IngestedAt: timestamppb.Now()}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "source not found")
}

func (s *server) CheckRepoAllowlist(_ context.Context, req *secflowv1.CheckRepoAllowlistRequest) (*secflowv1.CheckRepoAllowlistResponse, error) {
	ok, code, reason := checkURL(req.GetRepoUrl())
	return &secflowv1.CheckRepoAllowlistResponse{Allowed: ok, RejectionCode: code, Reason: reason}, nil
}

type limitedWriter struct {
	w       io.Writer
	written int64
	limit   int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.written+int64(len(p)) > lw.limit {
		return 0, errZipBomb
	}
	n, err := lw.w.Write(p)
	lw.written += int64(n)
	return n, err
}

func copyBounded(dst io.Writer, src io.Reader, maxFile, remaining int64) (int64, error) {
	if remaining < 0 {
		remaining = 0
	}
	limit := min(maxFile, remaining)
	n, err := io.Copy(dst, io.LimitReader(src, limit))
	if err != nil {
		return n, err
	}
	extra, probeErr := io.Copy(io.Discard, io.LimitReader(src, 1))
	if extra > 0 {
		return n, errZipBomb
	}
	if probeErr != nil {
		return n, probeErr
	}
	return n, nil
}

func packZipToTarGz(raw []byte) ([]byte, int32, error) {
	if len(raw) == 0 {
		return nil, 0, status.Error(codes.InvalidArgument, "empty archive")
	}
	if len(raw) > maxCompressedUploadBytes {
		return nil, 0, status.Error(codes.ResourceExhausted, codeZipBombDetected)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, 0, status.Error(codes.InvalidArgument, errMsgInvalidZip)
	}
	if len(zr.File) > maxZipFiles {
		return nil, 0, status.Error(codes.ResourceExhausted, codeZipBombDetected)
	}

	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, limit: maxCompressedUploadBytes}
	gz := gzip.NewWriter(lw)
	tw := tar.NewWriter(gz)

	var fileBuf bytes.Buffer
	var totalBytes int64
	var fileCount int32

	for _, f := range zr.File {
		cleanName, err := validateZipEntryPath(f.Name)
		if err != nil {
			return nil, 0, status.Error(codes.InvalidArgument, codeZipSlipDetected)
		}
		if err := validateZipEntryMode(f.Mode()); err != nil {
			return nil, 0, status.Error(codes.InvalidArgument, codeZipSlipDetected)
		}
		if f.Mode().IsDir() {
			if cleanName == "." {
				continue
			}
			hdr := &tar.Header{
				Typeflag: tar.TypeDir,
				Name:     cleanName,
				Mode:     0o750,
				ModTime:  f.Modified,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, 0, mapZipError(err)
			}
			continue
		}
		if cleanName == "." {
			return nil, 0, status.Error(codes.InvalidArgument, codeZipSlipDetected)
		}
		fileCount++
		if int(fileCount) > maxZipFiles {
			return nil, 0, status.Error(codes.ResourceExhausted, codeZipBombDetected)
		}
		n, err := writeZipEntryToTar(tw, f, cleanName, &fileBuf, maxZipFileBytes, maxZipTotalBytes-totalBytes)
		if err != nil {
			return nil, 0, mapZipError(err)
		}
		totalBytes += n
	}

	if err := tw.Close(); err != nil {
		return nil, 0, mapZipError(err)
	}
	if err := gz.Close(); err != nil {
		return nil, 0, mapZipError(err)
	}
	return buf.Bytes(), fileCount, nil
}

func writeZipEntryToTar(tw *tar.Writer, f *zip.File, cleanName string, fileBuf *bytes.Buffer, maxFile, remaining int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("open zip entry: %w", err)
	}
	defer func() { _ = rc.Close() }()

	fileBuf.Reset()
	n, err := copyBounded(fileBuf, rc, maxFile, remaining)
	if err != nil {
		return n, err
	}
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     cleanName,
		Size:     int64(fileBuf.Len()),
		Mode:     fileModeOrDefault(f.Mode()),
		ModTime:  f.Modified,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return n, err
	}
	if _, err := tw.Write(fileBuf.Bytes()); err != nil {
		return n, err
	}
	return n, nil
}

func validateZipEntryMode(mode os.FileMode) error {
	const forbidden = os.ModeSymlink | os.ModeDevice | os.ModeCharDevice | os.ModeNamedPipe | os.ModeSocket | os.ModeIrregular
	if mode&forbidden != 0 {
		return errZipSlip
	}
	if !mode.IsDir() && !mode.IsRegular() {
		return errZipSlip
	}
	return nil
}

func validateZipEntryPath(raw string) (string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) || strings.ContainsRune(raw, '\\') || strings.HasPrefix(raw, "/") || strings.ContainsRune(raw, ':') {
		return "", errZipSlip
	}
	trimmed := strings.TrimRight(raw, "/")
	if trimmed == "" {
		return "", errZipSlip
	}
	if trimmed == "." {
		return ".", nil
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return "", errZipSlip
		}
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "" || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", errZipSlip
	}
	local := filepath.FromSlash(cleaned)
	if filepath.IsAbs(local) || !filepath.IsLocal(local) {
		return "", errZipSlip
	}
	return cleaned, nil
}

func fileModeOrDefault(mode os.FileMode) int64 {
	perm := mode.Perm()
	if perm == 0 {
		return 0o644
	}
	return int64(perm)
}

func mapZipError(err error) error {
	if errors.Is(err, errZipBomb) {
		return status.Error(codes.ResourceExhausted, codeZipBombDetected)
	}
	if errors.Is(err, errZipSlip) {
		return status.Error(codes.InvalidArgument, codeZipSlipDetected)
	}
	return status.Error(codes.InvalidArgument, errMsgInvalidZip)
}

func mapCloneError(err error) error {
	if errors.Is(err, urlguard.ErrAllowlistDenied) || errors.Is(err, urlguard.ErrDenylistBlocked) || errors.Is(err, errPrivate) {
		return status.Error(codes.PermissionDenied, codeAllowlistDenied)
	}
	if errors.Is(err, errZipBomb) {
		return status.Error(codes.ResourceExhausted, codeZipBombDetected)
	}
	if errors.Is(err, errCommitNotFound) {
		return status.Error(codes.FailedPrecondition, "git ref not found")
	}
	return status.Errorf(codes.FailedPrecondition, "failed to clone git repository: %s", briefCloneCause(err))
}

func briefCloneCause(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "tls handshake timeout"):
		return "TLS handshake timeout"
	case strings.Contains(msg, "timeout"):
		return "timeout"
	case strings.Contains(msg, "connection reset"):
		return "connection reset"
	case strings.Contains(msg, "authentication"):
		return "authentication failed"
	default:
		return "network error"
	}
}

func checkURL(raw string) (bool, secflowv1.AllowlistRejectionCode, string) {
	ok, code, reason := urlguard.RepoAllowed(raw, os.Getenv("REPO_ALLOWLIST"))
	if ok {
		return true, secflowv1.AllowlistRejectionCode_ALLOWLIST_REJECTION_CODE_UNSPECIFIED, ""
	}
	switch code {
	case "SCHEME_NOT_HTTPS":
		return false, secflowv1.AllowlistRejectionCode_ALLOWLIST_REJECTION_CODE_SCHEME_NOT_HTTPS, reason
	case "SSRF_PRIVATE_IP":
		return false, secflowv1.AllowlistRejectionCode_ALLOWLIST_REJECTION_CODE_SSRF_PRIVATE_IP, reason
	default:
		return false, secflowv1.AllowlistRejectionCode_ALLOWLIST_REJECTION_CODE_HOST_NOT_ALLOWLISTED, reason
	}
}

func rejectPrivateHost(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errPrivate
	}
	for _, ip := range ips {
		if ip.IP.IsLoopback() || ip.IP.IsPrivate() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() || ip.IP.IsMulticast() || ip.IP.IsUnspecified() {
			return errPrivate
		}
	}
	return nil
}

func installSafeGitTransport() {
	safeGitTransportOnce.Do(func() {
		httpTransport := githttp.NewClient(newSafeGitHTTPClient(gitCloneAttemptTimeout))
		gitclient.InstallProtocol("http", httpTransport)
		gitclient.InstallProtocol("https", httpTransport)
	})
}

func newSafeGitHTTPClient(timeout time.Duration) *http.Client {
	safeClient := urlguard.NewSafeClient(timeout)
	if tr, ok := safeClient.Transport.(*http.Transport); ok {
		tr.TLSHandshakeTimeout = 15 * time.Second
		tr.ResponseHeaderTimeout = 25 * time.Second
	}
	baseRedirect := safeClient.CheckRedirect
	safeClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if baseRedirect != nil {
			if err := baseRedirect(req, via); err != nil {
				return err
			}
		}
		if req.URL.Scheme != "https" {
			return urlguard.ErrAllowlistDenied
		}
		if ok, _, _ := checkURL(stripGitSmartHTTPPath(req.URL)); !ok {
			return urlguard.ErrAllowlistDenied
		}
		return nil
	}
	return safeClient
}

func stripGitSmartHTTPPath(u *url.URL) string {
	clone := *u
	clone.RawQuery = ""
	clone.Fragment = ""
	for _, suffix := range []string{"/info/refs", "/git-upload-pack", "/git-receive-pack"} {
		if strings.HasSuffix(clone.Path, suffix) {
			clone.Path = strings.TrimSuffix(clone.Path, suffix)
			break
		}
	}
	return clone.String()
}

func sanitizeURLForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid-url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (s *server) gitToken(ctx context.Context, req *secflowv1.IngestGitRequest) (string, error) {
	if req.GetAuthSecretRef() == "" {
		return "", nil
	}
	if s.secrets == nil {
		return "", errors.New("no secret client")
	}
	resp, err := s.secrets.ResolveScopedSecret(ctx, &secflowv1.ResolveScopedSecretRequest{
		SecretRef: req.GetAuthSecretRef(),
		Scope: &secflowv1.ResolveScopedSecretRequest_NodeTask{NodeTask: &secflowv1.NodeTaskSecretScope{
			RunId:          req.GetRunId(),
			NodeRunId:      req.GetRunId() + ":" + req.GetNodeId(),
			NodeId:         req.GetNodeId(),
			PluginId:       "source.git",
			TaskLeaseToken: req.GetTaskLeaseToken(),
		}},
	})
	if err != nil {
		return "", err
	}
	return resp.GetPlaintextValue(), nil
}

func gitAuth(token string) transport.AuthMethod {
	if token == "" {
		return nil
	}
	return &githttp.BasicAuth{Username: "x-access-token", Password: token}
}

type cloneResult struct {
	archive   []byte
	commitSHA string
	fileCount int32
}

func cloneTree(ctx context.Context, repoURL, gitRef, token string) (cloneResult, error) {
	installSafeGitTransport()
	totalCtx, cancelTotal := context.WithTimeout(ctx, gitCloneTotalTimeout)
	defer cancelTotal()
	return cloneWithRetry(
		totalCtx,
		3,
		func(attempt int) time.Duration { return time.Duration(attempt) * time.Second },
		func(attemptCtx context.Context) (cloneResult, error) {
			return cloneTreeOnce(attemptCtx, repoURL, gitRef, token)
		},
		repoURL,
	)
}

func cloneWithRetry(
	ctx context.Context,
	maxAttempts int,
	backoff func(attempt int) time.Duration,
	attemptFn func(context.Context) (cloneResult, error),
	repoURL string,
) (cloneResult, error) {
	var last error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return cloneResult{}, err
		}
		res, err := attemptFn(ctx)
		if err == nil {
			return res, nil
		}
		last = err
		if ctx.Err() != nil {
			return cloneResult{}, err
		}
		if attempt == maxAttempts || !transientCloneError(ctx, err) {
			return cloneResult{}, err
		}
		slog.WarnContext(ctx, "git clone retry", "attempt", attempt, "repo_url", sanitizeURLForLog(repoURL), "err", err)
		delay := time.Duration(0)
		if backoff != nil {
			delay = backoff(attempt)
		}
		if delay <= 0 {
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return cloneResult{}, ctx.Err()
		case <-timer.C:
		}
	}
	return cloneResult{}, last
}

func transientCloneError(parentCtx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if parentCtx != nil && parentCtx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, transport.ErrAuthenticationRequired) ||
		errors.Is(err, transport.ErrAuthorizationFailed) ||
		errors.Is(err, transport.ErrRepositoryNotFound) ||
		errors.Is(err, urlguard.ErrAllowlistDenied) ||
		errors.Is(err, urlguard.ErrDenylistBlocked) ||
		errors.Is(err, errPrivate) ||
		errors.Is(err, errCommitNotFound) ||
		errors.Is(err, errZipBomb) ||
		errors.Is(err, errZipSlip) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls handshake timeout") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe")
}

func cloneTreeOnce(ctx context.Context, repoURL, gitRef, token string) (cloneResult, error) {
	dir, err := os.MkdirTemp("", "secflow-git-")
	if err != nil {
		return cloneResult{}, fmt.Errorf("create temp git dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	attemptCtx, cancel := context.WithTimeout(ctx, gitCloneAttemptTimeout)
	defer cancel()

	repo, err := cloneAndCheckout(attemptCtx, dir, repoURL, strings.TrimSpace(gitRef), gitAuth(token))
	if err != nil {
		return cloneResult{}, err
	}
	head, err := repo.Head()
	if err != nil {
		return cloneResult{}, fmt.Errorf("resolve HEAD: %w", err)
	}
	archive, fileCount, err := tarGz(dir)
	if err != nil {
		return cloneResult{}, err
	}
	return cloneResult{
		archive:   archive,
		commitSHA: head.Hash().String(),
		fileCount: fileCount,
	}, nil
}

func cloneAndCheckout(ctx context.Context, dir, repoURL, gitRef string, auth transport.AuthMethod) (*git.Repository, error) {
	if gitRef == "" {
		return git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
			URL:          repoURL,
			Depth:        1,
			SingleBranch: true,
			Auth:         auth,
		})
	}
	if looksSHA(gitRef) {
		return cloneAndCheckoutSHA(ctx, dir, repoURL, gitRef, auth)
	}
	if strings.HasPrefix(gitRef, "refs/") {
		return git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
			URL:           repoURL,
			Depth:         1,
			SingleBranch:  true,
			ReferenceName: plumbing.ReferenceName(gitRef),
			Auth:          auth,
		})
	}
	opts := &git.CloneOptions{
		URL:           repoURL,
		Depth:         1,
		SingleBranch:  true,
		ReferenceName: plumbing.NewBranchReferenceName(gitRef),
		Auth:          auth,
	}
	repo, err := git.PlainCloneContext(ctx, dir, false, opts)
	if err == nil {
		return repo, nil
	}
	if err := resetDir(dir); err != nil {
		return nil, err
	}
	opts.ReferenceName = plumbing.NewTagReferenceName(gitRef)
	repo, tagErr := git.PlainCloneContext(ctx, dir, false, opts)
	if tagErr != nil {
		return nil, err
	}
	return repo, nil
}

func cloneAndCheckoutSHA(ctx context.Context, dir, repoURL, shaRef string, auth transport.AuthMethod) (*git.Repository, error) {
	repo, err := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:  repoURL,
		Auth: auth,
	})
	if err != nil {
		return nil, fmt.Errorf("full clone for sha checkout: %w", err)
	}
	hash, err := repo.ResolveRevision(plumbing.Revision(shaRef))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCommitNotFound, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("open worktree: %w", err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{Hash: *hash, Force: true}); err != nil {
		return nil, fmt.Errorf("checkout commit %s: %w", hash.String(), err)
	}
	return repo, nil
}

func resetDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("reset temp git dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("recreate temp git dir: %w", err)
	}
	return nil
}

func looksSHA(ref string) bool {
	if len(ref) < 7 || len(ref) > 40 {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

type gitEntryAction uint8

const (
	gitEntrySkip gitEntryAction = iota
	gitEntrySkipDir
	gitEntryDir
	gitEntryFile
)

func classifyGitEntry(rel string, mode fs.FileMode) gitEntryAction {
	if rel == "." {
		return gitEntrySkip
	}
	if rel == ".git" || strings.HasPrefix(rel, ".git"+string(os.PathSeparator)) {
		if mode.IsDir() {
			return gitEntrySkipDir
		}
		return gitEntrySkip
	}
	if mode&os.ModeSymlink != 0 {
		return gitEntrySkip
	}
	if mode.IsDir() {
		return gitEntryDir
	}
	if !mode.IsRegular() {
		return gitEntrySkip
	}
	return gitEntryFile
}

func tarGz(root string) ([]byte, int32, error) {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, 0, fmt.Errorf("open git root: %w", err)
	}
	defer func() { _ = rootFS.Close() }()

	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, limit: maxCompressedUploadBytes}
	gz := gzip.NewWriter(lw)
	tw := tar.NewWriter(gz)

	var totalBytes int64
	var fileCount int32

	err = filepath.WalkDir(root, func(entryPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, entryPath)
		if err != nil {
			return err
		}
		switch classifyGitEntry(rel, d.Type()) {
		case gitEntrySkipDir:
			return filepath.SkipDir
		case gitEntrySkip:
			if d.Type()&os.ModeSymlink != 0 {
				slog.Warn("skipping symlink in git repository", "path", filepath.ToSlash(rel))
			} else if rel != "." && rel != ".git" && !strings.HasPrefix(rel, ".git"+string(os.PathSeparator)) {
				slog.Warn("skipping non-regular file in git repository", "path", filepath.ToSlash(rel))
			}
			return nil
		case gitEntryDir:
			return tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     filepath.ToSlash(rel),
				Mode:     0o750,
			})
		case gitEntryFile:
			fileCount++
			if int(fileCount) > maxZipFiles {
				return errZipBomb
			}
			n, err := writeLocalFileToTar(tw, rootFS, rel, maxZipFileBytes, maxZipTotalBytes-totalBytes)
			if err != nil {
				return err
			}
			totalBytes += n
			return nil
		default:
			return nil
		}
	})
	if err != nil {
		return nil, 0, err
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if err := gz.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), fileCount, nil
}

func writeLocalFileToTar(tw *tar.Writer, rootFS *os.Root, rel string, maxFile, remaining int64) (int64, error) {
	f, err := rootFS.Open(rel)
	if err != nil {
		return 0, fmt.Errorf("open repo file %q: %w", rel, err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat repo file %q: %w", rel, err)
	}
	if !fi.Mode().IsRegular() {
		slog.Warn("skipping non-regular file after open", "path", filepath.ToSlash(rel))
		return 0, nil
	}
	size := fi.Size()
	if size < 0 || size > maxFile || size > remaining {
		return 0, errZipBomb
	}
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     filepath.ToSlash(rel),
		Size:     size,
		Mode:     fileModeOrDefault(fi.Mode()),
		ModTime:  fi.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return 0, err
	}
	n, err := copyBounded(tw, f, size, remaining)
	if err != nil {
		return n, err
	}
	if n != size {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
