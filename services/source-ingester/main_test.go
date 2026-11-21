package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/secflow/secflow/services/internal/urlguard"
)

type stubNetError struct {
	msg     string
	timeout bool
}

func (e stubNetError) Error() string   { return e.msg }
func (e stubNetError) Timeout() bool   { return e.timeout }
func (e stubNetError) Temporary() bool { return e.timeout }

func TestTransientCloneError(t *testing.T) {
	t.Parallel()

	liveCtx := t.Context()
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	expiredCtx, expireCancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer expireCancel()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "nil error", ctx: liveCtx, err: nil, want: false},
		{name: "context canceled", ctx: liveCtx, err: context.Canceled, want: false},
		{name: "auth required", ctx: liveCtx, err: fmt.Errorf("clone: %w", transport.ErrAuthenticationRequired), want: false},
		{name: "auth failed", ctx: liveCtx, err: fmt.Errorf("clone: %w", transport.ErrAuthorizationFailed), want: false},
		{name: "repo not found", ctx: liveCtx, err: fmt.Errorf("clone: %w", transport.ErrRepositoryNotFound), want: false},
		{name: "allowlist denied", ctx: liveCtx, err: urlguard.ErrAllowlistDenied, want: false},
		{name: "denylist blocked", ctx: liveCtx, err: urlguard.ErrDenylistBlocked, want: false},
		{name: "private host", ctx: liveCtx, err: errPrivate, want: false},
		{name: "commit not found", ctx: liveCtx, err: errCommitNotFound, want: false},
		{name: "zip bomb", ctx: liveCtx, err: errZipBomb, want: false},
		{name: "zip slip", ctx: liveCtx, err: errZipSlip, want: false},
		{name: "generic tls handshake cert error is permanent", ctx: liveCtx, err: errors.New("tls handshake failed: x509: unknown authority"), want: false},
		{name: "tls handshake timeout is transient", ctx: liveCtx, err: errors.New("net/http: TLS handshake timeout"), want: true},
		{name: "net.Error timeout is transient", ctx: liveCtx, err: stubNetError{msg: "dial tcp: i/o timeout", timeout: true}, want: true},
		{name: "net.Error non-timeout is permanent", ctx: liveCtx, err: stubNetError{msg: "no such host", timeout: false}, want: false},
		{name: "connection reset string is transient", ctx: liveCtx, err: errors.New("read tcp: connection reset by peer"), want: true},
		{name: "broken pipe string is transient", ctx: liveCtx, err: errors.New("write tcp: broken pipe"), want: true},
		{name: "syscall ECONNRESET is transient", ctx: liveCtx, err: fmt.Errorf("read: %w", syscall.ECONNRESET), want: true},
		{name: "syscall EPIPE is transient", ctx: liveCtx, err: fmt.Errorf("write: %w", syscall.EPIPE), want: true},
		{name: "child deadline exceeded with live parent is transient", ctx: liveCtx, err: context.DeadlineExceeded, want: true},
		{name: "deadline exceeded with expired parent is not retried", ctx: expiredCtx, err: context.DeadlineExceeded, want: false},
		{name: "transient error with canceled parent is not retried", ctx: canceledCtx, err: errors.New("connection reset by peer"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := transientCloneError(tt.ctx, tt.err); got != tt.want {
				t.Fatalf("transientCloneError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestBriefCloneCause(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil error", err: nil, want: ""},
		{name: "tls handshake timeout", err: errors.New("net/http: TLS handshake timeout"), want: "TLS handshake timeout"},
		{name: "generic timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "connection reset", err: errors.New("connection reset by peer"), want: "connection reset"},
		{name: "authentication", err: errors.New("authentication required"), want: "authentication failed"},
		{name: "other", err: errors.New("unexpected transport error"), want: "network error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := briefCloneCause(tt.err); got != tt.want {
				t.Fatalf("briefCloneCause(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestSafeGitHTTPClientTimeouts(t *testing.T) {
	t.Parallel()

	if gitCloneTotalTimeout != 90*time.Second {
		t.Fatalf("gitCloneTotalTimeout = %v, want 90s", gitCloneTotalTimeout)
	}
	if gitCloneAttemptTimeout != 35*time.Second {
		t.Fatalf("gitCloneAttemptTimeout = %v, want 35s", gitCloneAttemptTimeout)
	}
	cli := newSafeGitHTTPClient(gitCloneAttemptTimeout)
	tr, ok := cli.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", cli.Transport)
	}
	if tr.TLSHandshakeTimeout != 15*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 15s", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 25*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 25s", tr.ResponseHeaderTimeout)
	}
}

func TestCloneWithRetryBehavior(t *testing.T) {
	t.Parallel()

	t.Run("retries transient error and succeeds", func(t *testing.T) {
		t.Parallel()
		attempts := 0
		res, err := cloneWithRetry(
			t.Context(),
			3,
			func(int) time.Duration { return time.Millisecond },
			func(context.Context) (cloneResult, error) {
				attempts++
				if attempts < 3 {
					return cloneResult{}, errors.New("net/http: TLS handshake timeout")
				}
				return cloneResult{commitSHA: "abc123", fileCount: 2}, nil
			},
			"https://github.com/org/repo",
		)
		if err != nil {
			t.Fatalf("cloneWithRetry() error = %v", err)
		}
		if attempts != 3 || res.commitSHA != "abc123" {
			t.Fatalf("attempts=%d res=%+v, want 3 / abc123", attempts, res)
		}
	})

	t.Run("does not retry permanent error", func(t *testing.T) {
		t.Parallel()
		attempts := 0
		_, err := cloneWithRetry(
			t.Context(),
			3,
			func(int) time.Duration { return time.Millisecond },
			func(context.Context) (cloneResult, error) {
				attempts++
				return cloneResult{}, transport.ErrRepositoryNotFound
			},
			"https://github.com/org/repo",
		)
		if !errors.Is(err, transport.ErrRepositoryNotFound) {
			t.Fatalf("err = %v, want ErrRepositoryNotFound", err)
		}
		if attempts != 1 {
			t.Fatalf("attempts = %d, want 1", attempts)
		}
	})

	t.Run("stops immediately when parent context is canceled without sleeping", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		attempts := 0
		backoffCalled := false
		_, err := cloneWithRetry(
			ctx,
			3,
			func(int) time.Duration {
				backoffCalled = true
				return 5 * time.Second
			},
			func(context.Context) (cloneResult, error) {
				attempts++
				cancel()
				return cloneResult{}, errors.New("net/http: TLS handshake timeout")
			},
			"https://github.com/org/repo",
		)
		if err == nil {
			t.Fatal("expected error when parent context canceled")
		}
		if attempts != 1 {
			t.Fatalf("attempts = %d, want 1", attempts)
		}
		if backoffCalled {
			t.Fatal("backoff was called after parent context was canceled")
		}
	})
}
