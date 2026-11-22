package workerclient

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

type fakeWorkerClient struct {
	connects atomic.Int32
	fn       func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error)
}

func (f *fakeWorkerClient) Connect(ctx context.Context, _ ...grpc.CallOption) (secflowv1.WorkerService_ConnectClient, error) {
	f.connects.Add(1)
	return f.fn(ctx)
}

type fakeStream struct {
	ctx  context.Context
	msgs []*secflowv1.ConnectResponse
	idx  int
}

func (s *fakeStream) Send(*secflowv1.ConnectRequest) error { return nil }
func (s *fakeStream) Recv() (*secflowv1.ConnectResponse, error) {
	if s.idx >= len(s.msgs) {
		return nil, io.EOF
	}
	m := s.msgs[s.idx]
	s.idx++
	return m, nil
}
func (s *fakeStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fakeStream) Trailer() metadata.MD         { return nil }
func (s *fakeStream) CloseSend() error             { return nil }
func (s *fakeStream) Context() context.Context     { return s.ctx }
func (s *fakeStream) SendMsg(any) error            { return nil }
func (s *fakeStream) RecvMsg(any) error            { return nil }

type chanStream struct {
	ctx        context.Context
	recvCh     chan *secflowv1.ConnectResponse
	mu         sync.Mutex
	sent       []*secflowv1.ConnectRequest
	sendCh     chan *secflowv1.ConnectRequest
	closedSend atomic.Bool
}

func newChanStream(ctx context.Context) *chanStream {
	return &chanStream{
		ctx:    ctx,
		recvCh: make(chan *secflowv1.ConnectResponse, 16),
		sendCh: make(chan *secflowv1.ConnectRequest, 32),
	}
}

func (s *chanStream) Send(req *secflowv1.ConnectRequest) error {
	s.mu.Lock()
	s.sent = append(s.sent, req)
	s.mu.Unlock()
	select {
	case s.sendCh <- req:
	default:
	}
	return nil
}

func (s *chanStream) Recv() (*secflowv1.ConnectResponse, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case m, ok := <-s.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	}
}

func (s *chanStream) Header() (metadata.MD, error) { return nil, nil }
func (s *chanStream) Trailer() metadata.MD         { return nil }
func (s *chanStream) CloseSend() error {
	s.closedSend.Store(true)
	return nil
}
func (s *chanStream) Context() context.Context { return s.ctx }
func (s *chanStream) SendMsg(any) error        { return nil }
func (s *chanStream) RecvMsg(any) error        { return nil }

func TestRunStopsOnRejectedManifest(t *testing.T) {
	t.Parallel()
	fc := &fakeWorkerClient{
		fn: func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error) {
			return &fakeStream{
				ctx: ctx,
				msgs: []*secflowv1.ConnectResponse{
					{Payload: &secflowv1.ConnectResponse_ManifestAck{ManifestAck: &secflowv1.ManifestAck{Accepted: false, RejectionReason: "forbidden scanner"}}},
				},
			}, nil
		},
	}
	err := runClient(t.Context(), fc, "w1", nil, func(context.Context, *secflowv1.NodeTask) *secflowv1.NodeResult { return nil }, 5*time.Millisecond, 20*time.Millisecond)
	if !errors.Is(err, ErrManifestRejected) {
		t.Fatalf("expected ErrManifestRejected, got %v", err)
	}
	if got := fc.connects.Load(); got != 1 {
		t.Fatalf("expected 1 connect attempt, got %d", got)
	}
}

func TestRunPassesContextAndAppliesBackoff(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Millisecond)
	defer cancel()
	fc := &fakeWorkerClient{
		fn: func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error) {
			return &fakeStream{ctx: ctx}, nil
		},
	}
	err := runClient(ctx, fc, "w2", nil, func(context.Context, *secflowv1.NodeTask) *secflowv1.NodeResult { return nil }, 15*time.Millisecond, 60*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if got := fc.connects.Load(); got > 4 {
		t.Fatalf("expected backoff to limit retries, got %d connects", got)
	}
}

func TestWorkerHeartbeatProgressCancelAndDrain(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	cs := newChanStream(ctx)
	fc := &fakeWorkerClient{
		fn: func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error) {
			return cs, nil
		},
	}

	taskStarted := make(chan string, 2)
	taskCancelled := make(chan string, 1)
	releaseDrainTask := make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- runClientWithHeartbeat(ctx, fc, "worker-1", nil, func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
			_ = ReportProgress(taskCtx, 42, "scanning")
			taskStarted <- task.GetNodeRunId()
			switch task.GetNodeRunId() {
			case "nr-cancel":
				<-taskCtx.Done()
				taskCancelled <- task.GetNodeRunId()
				return &secflowv1.NodeResult{
					NodeRunId: task.GetNodeRunId(),
					Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_CANCELLED,
				}
			case "nr-drain":
				<-releaseDrainTask
				return &secflowv1.NodeResult{
					NodeRunId: task.GetNodeRunId(),
					Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
				}
			}
			return nil
		}, 10*time.Millisecond, 50*time.Millisecond, 20*time.Millisecond)
	}()

	// Accept manifest (0s interval falls back to 20ms test default).
	cs.recvCh <- &secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_ManifestAck{
			ManifestAck: &secflowv1.ManifestAck{Accepted: true},
		},
	}

	// Dispatch task that will be cancelled.
	cs.recvCh <- &secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_DispatchTask{
			DispatchTask: &secflowv1.NodeTask{RunId: "r1", NodeRunId: "nr-cancel", NodeId: "n1", PluginId: "scan.sca"},
		},
	}
	if got := <-taskStarted; got != "nr-cancel" {
		t.Fatalf("started = %q, want nr-cancel", got)
	}

	// Wait for at least one heartbeat carrying nr-cancel and a progress frame.
	var sawHB, sawProgress bool
	deadline := time.After(time.Second)
	for !(sawHB && sawProgress) {
		select {
		case req := <-cs.sendCh:
			if hb := req.GetHeartbeat(); hb != nil {
				for _, id := range hb.GetActiveNodeRunIds() {
					if id == "nr-cancel" {
						sawHB = true
					}
				}
			}
			if pr := req.GetTaskProgress(); pr != nil && pr.GetNodeRunId() == "nr-cancel" && pr.GetPercent() == 42 {
				sawProgress = true
			}
		case <-deadline:
			t.Fatalf("timeout waiting for heartbeat=%v progress=%v", sawHB, sawProgress)
		}
	}

	// Send CancelTask and verify task context is cancelled.
	cs.recvCh <- &secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_CancelTask{
			CancelTask: &secflowv1.CancelTask{NodeRunId: "nr-cancel", Reason: "user cancelled"},
		},
	}
	select {
	case id := <-taskCancelled:
		if id != "nr-cancel" {
			t.Fatalf("cancelled = %q", id)
		}
	case <-time.After(time.Second):
		t.Fatal("task was not cancelled")
	}

	// Dispatch another task, then send DrainRequest; worker must wait for task to finish and exit cleanly.
	cs.recvCh <- &secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_DispatchTask{
			DispatchTask: &secflowv1.NodeTask{RunId: "r2", NodeRunId: "nr-drain", NodeId: "n2", PluginId: "scan.sca"},
		},
	}
	if got := <-taskStarted; got != "nr-drain" {
		t.Fatalf("started = %q, want nr-drain", got)
	}
	cs.recvCh <- &secflowv1.ConnectResponse{
		Payload: &secflowv1.ConnectResponse_DrainRequest{
			DrainRequest: &secflowv1.DrainRequest{Reason: "scale down", GracePeriodSeconds: 5},
		},
	}

	// Wait for WorkerDrainNotice before releasing the task.
	sawDrain := false
	drainDeadline := time.After(time.Second)
	for !sawDrain {
		select {
		case req := <-cs.sendCh:
			if d := req.GetDrain(); d != nil && d.GetWorkerInstanceId() == "worker-1" {
				sawDrain = true
			}
		case <-drainDeadline:
			t.Fatal("expected WorkerDrainNotice")
		}
	}
	close(releaseDrainTask)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected clean drain exit, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not exit after drain")
	}
	if !cs.closedSend.Load() {
		t.Fatal("expected stream CloseSend on drain")
	}
}

type errorRecvStream struct {
	fakeStream
	recvErr error
}

func (s *errorRecvStream) Recv() (*secflowv1.ConnectResponse, error) {
	return nil, s.recvErr
}

func TestRunWithConfig_AttachesPluginTokenMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		pluginToken  string
		serviceToken string
		wantKey      string
		wantVal      string
		wantAbsent   string
	}{
		{
			name:        "attaches x-plugin-token and preserves existing metadata",
			pluginToken: "tok_secret_123",
			wantKey:     "x-plugin-token",
			wantVal:     "tok_secret_123",
		},
		{
			name:         "attaches x-service-token when plugin token empty",
			serviceToken: "svc_secret_456",
			wantKey:      "x-service-token",
			wantVal:      "svc_secret_456",
			wantAbsent:   "x-plugin-token",
		},
		{
			name:       "attaches no auth headers when tokens empty",
			wantAbsent: "x-plugin-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var seenMD metadata.MD
			fc := &fakeWorkerClient{
				fn: func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error) {
					seenMD, _ = metadata.FromOutgoingContext(ctx)
					return &fakeStream{
						ctx: ctx,
						msgs: []*secflowv1.ConnectResponse{
							{Payload: &secflowv1.ConnectResponse_DrainRequest{DrainRequest: &secflowv1.DrainRequest{Reason: "done"}}},
						},
					}, nil
				},
			}

			baseCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("traceparent", "00-abc-def-01"))
			err := runClientWithConfig(baseCtx, fc, Config{
				WorkerID:         "w-meta",
				Namespace:        "secflow-sandbox",
				PluginToken:      tt.pluginToken,
				ServiceToken:     tt.serviceToken,
				InitialBackoff:   5 * time.Millisecond,
				MaxBackoff:       20 * time.Millisecond,
				DefaultHeartbeat: 50 * time.Millisecond,
				Handle:           func(context.Context, *secflowv1.NodeTask) *secflowv1.NodeResult { return nil },
			})
			if err != nil {
				t.Fatalf("runClientWithConfig: %v", err)
			}
			if got := seenMD.Get("traceparent"); len(got) != 1 || got[0] != "00-abc-def-01" {
				t.Fatalf("traceparent overwritten: %v", got)
			}
			if tt.wantKey != "" {
				if got := seenMD.Get(tt.wantKey); len(got) != 1 || got[0] != tt.wantVal {
					t.Fatalf("metadata %s = %v, want [%s]", tt.wantKey, got, tt.wantVal)
				}
			}
			if tt.wantAbsent != "" {
				if got := seenMD.Get(tt.wantAbsent); len(got) != 0 {
					t.Fatalf("metadata %s = %v, want absent", tt.wantAbsent, got)
				}
			}
		})
	}
}

func TestRunWithConfig_StopsOnUnauthenticatedAndPermissionDenied(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func() *fakeWorkerClient
		wantErr  error
		wantAuth bool
	}{
		{
			name: "Connect returns codes.Unauthenticated",
			setup: func() *fakeWorkerClient {
				return &fakeWorkerClient{
					fn: func(context.Context) (secflowv1.WorkerService_ConnectClient, error) {
						return nil, status.Error(codes.Unauthenticated, "invalid token")
					},
				}
			},
			wantErr: ErrUnauthenticated,
		},
		{
			name: "stream.Recv returns codes.Unauthenticated",
			setup: func() *fakeWorkerClient {
				return &fakeWorkerClient{
					fn: func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error) {
						return &errorRecvStream{
							fakeStream: fakeStream{ctx: ctx},
							recvErr:    status.Error(codes.Unauthenticated, "missing x-plugin-token"),
						}, nil
					},
				}
			},
			wantErr: ErrUnauthenticated,
		},
		{
			name: "stream.Recv returns codes.PermissionDenied",
			setup: func() *fakeWorkerClient {
				return &fakeWorkerClient{
					fn: func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error) {
						return &errorRecvStream{
							fakeStream: fakeStream{ctx: ctx},
							recvErr:    status.Error(codes.PermissionDenied, "builtin override forbidden"),
						}, nil
					},
				}
			},
			wantErr: ErrPermissionDenied,
		},
		{
			name: "ManifestAck UNAUTHENTICATED stops with ErrManifestRejected and ErrUnauthenticated",
			setup: func() *fakeWorkerClient {
				return &fakeWorkerClient{
					fn: func(ctx context.Context) (secflowv1.WorkerService_ConnectClient, error) {
						return &fakeStream{
							ctx: ctx,
							msgs: []*secflowv1.ConnectResponse{
								{
									Payload: &secflowv1.ConnectResponse_ManifestAck{
										ManifestAck: &secflowv1.ManifestAck{
											Accepted:        false,
											RejectionCode:   secflowv1.ManifestRejectionCode_MANIFEST_REJECTION_CODE_UNAUTHENTICATED,
											RejectionReason: "invalid x-plugin-token",
										},
									},
								},
							},
						}, nil
					},
				}
			},
			wantErr:  ErrManifestRejected,
			wantAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fc := tt.setup()
			err := runClientWithConfig(t.Context(), fc, Config{
				WorkerID:       "w-auth",
				InitialBackoff: 5 * time.Millisecond,
				MaxBackoff:     20 * time.Millisecond,
				Handle:         func(context.Context, *secflowv1.NodeTask) *secflowv1.NodeResult { return nil },
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want errors.Is(..., %v)", err, tt.wantErr)
			}
			if tt.wantAuth && !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("err = %v, want errors.Is(..., ErrUnauthenticated)", err)
			}
			if got := fc.connects.Load(); got != 1 {
				t.Fatalf("connect attempts = %d, want 1", got)
			}
		})
	}
}
