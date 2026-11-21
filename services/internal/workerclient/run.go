package workerclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/obs"
)

// ErrManifestRejected is returned when orchestrator permanently rejects a Plugin manifest.
var ErrManifestRejected = errors.New("manifest rejected")

// Handler turns a leased task into a result. Secret values must not be logged.
type Handler func(ctx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult

type progressKey struct{}

type progressFn func(percent int32, message string) error

// ReportProgress emits a WorkerTaskProgress frame on the active worker stream.
// Outside a worker task context it is a safe no-op.
func ReportProgress(ctx context.Context, percent int32, message string) error {
	if ctx == nil {
		return nil
	}
	fn, ok := ctx.Value(progressKey{}).(progressFn)
	if !ok || fn == nil {
		return nil
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return fn(percent, message)
}

type streamSender struct {
	mu     sync.Mutex
	stream secflowv1.WorkerService_ConnectClient
}

func (s *streamSender) Send(req *secflowv1.ConnectRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(req)
}

func (s *streamSender) CloseSend() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.CloseSend()
}

// Run dials the orchestrator and keeps the pull stream open with exponential backoff.
func Run(ctx context.Context, addr, workerID string, manifests []*secflowv1.PluginManifest, handle Handler) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
	if err != nil {
		return fmt.Errorf("dial orchestrator %s: %w", addr, err)
	}
	defer conn.Close()
	return runClient(ctx, secflowv1.NewWorkerServiceClient(conn), workerID, manifests, handle, 250*time.Millisecond, 30*time.Second)
}

func runClient(
	ctx context.Context,
	client secflowv1.WorkerServiceClient,
	workerID string,
	manifests []*secflowv1.PluginManifest,
	handle Handler,
	initialBackoff time.Duration,
	maxBackoff time.Duration,
) error {
	return runClientWithHeartbeat(ctx, client, workerID, manifests, handle, initialBackoff, maxBackoff, 10*time.Second)
}

func runClientWithHeartbeat(
	ctx context.Context,
	client secflowv1.WorkerServiceClient,
	workerID string,
	manifests []*secflowv1.PluginManifest,
	handle Handler,
	initialBackoff time.Duration,
	maxBackoff time.Duration,
	defaultHeartbeat time.Duration,
) error {
	var maxConcurrency int32
	for _, m := range manifests {
		if m != nil && m.GetMaxConcurrency() > 0 {
			maxConcurrency += m.GetMaxConcurrency()
		}
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}
	namespace := envutil.Get("POD_NAMESPACE", "secflow-workers")
	backoff := initialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		stream, err := client.Connect(ctx)
		if err != nil {
			slog.Warn("worker connect failed", "worker_id", workerID, "err", err)
			if err := sleepWithContext(ctx, backoff); err != nil {
				return err
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		sender := &streamSender{stream: stream}
		err = sender.Send(&secflowv1.ConnectRequest{Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: workerID,
				Namespace:        namespace,
				Manifests:        manifests,
			},
		}})
		if err != nil {
			slog.Warn("worker register manifest failed", "worker_id", workerID, "err", err)
			if err := sleepWithContext(ctx, backoff); err != nil {
				return err
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		accepted, drained, err := serve(ctx, stream, sender, workerID, maxConcurrency, defaultHeartbeat, handle)
		if drained {
			return nil
		}
		if errors.Is(err, ErrManifestRejected) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Info("worker stream closed", "worker_id", workerID, "err", err)
		if accepted {
			backoff = initialBackoff
		}
		if err := sleepWithContext(ctx, backoff); err != nil {
			return err
		}
		backoff = nextBackoff(backoff, maxBackoff)
	}
}

func serve(
	ctx context.Context,
	stream secflowv1.WorkerService_ConnectClient,
	sender *streamSender,
	workerID string,
	maxConcurrency int32,
	defaultHeartbeat time.Duration,
	handle Handler,
) (accepted bool, drained bool, err error) {
	streamCtx, streamCancel := context.WithCancel(ctx)
	var activeMu sync.Mutex
	activeTasks := map[string]context.CancelFunc{}
	var draining atomic.Bool
	var taskWg sync.WaitGroup
	var hbWg sync.WaitGroup
	var hbOnce sync.Once

	defer func() {
		streamCancel()
		hbWg.Wait()
		taskWg.Wait()
	}()

	startHeartbeat := func(interval time.Duration) {
		if interval <= 0 {
			interval = 10 * time.Second
		}
		hbOnce.Do(func() {
			hbWg.Add(1)
			go func() {
				defer hbWg.Done()
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-streamCtx.Done():
						return
					case <-ticker.C:
						activeMu.Lock()
						ids := make([]string, 0, len(activeTasks))
						for id := range activeTasks {
							ids = append(ids, id)
						}
						activeMu.Unlock()
						avail := maxConcurrency - int32(len(ids))
						if avail < 0 || draining.Load() {
							avail = 0
						}
						if sendErr := sender.Send(&secflowv1.ConnectRequest{
							Payload: &secflowv1.ConnectRequest_Heartbeat{
								Heartbeat: &secflowv1.WorkerHeartbeat{
									WorkerInstanceId: workerID,
									ActiveNodeRunIds: ids,
									AvailableSlots:   avail,
								},
							},
						}); sendErr != nil {
							return
						}
					}
				}
			}()
		})
	}

	cancelActive := func(nodeRunID string) {
		activeMu.Lock()
		cancel := activeTasks[nodeRunID]
		activeMu.Unlock()
		if cancel != nil {
			cancel()
		}
	}

	for {
		msg, recvErr := stream.Recv()
		if recvErr != nil {
			return accepted, false, fmt.Errorf("stream recv: %w", recvErr)
		}
		switch p := msg.GetPayload().(type) {
		case *secflowv1.ConnectResponse_ManifestAck:
			if !p.ManifestAck.GetAccepted() {
				slog.Error("manifest rejected", "reason", p.ManifestAck.GetRejectionReason())
				return false, false, fmt.Errorf("%w: %s", ErrManifestRejected, p.ManifestAck.GetRejectionReason())
			}
			accepted = true
			interval := defaultHeartbeat
			if sec := p.ManifestAck.GetHeartbeatIntervalSeconds(); sec > 0 {
				interval = time.Duration(sec) * time.Second
			}
			startHeartbeat(interval)

		case *secflowv1.ConnectResponse_DispatchTask:
			task := p.DispatchTask
			if task == nil {
				continue
			}
			if draining.Load() {
				_ = sender.Send(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_CompleteTask{
						CompleteTask: &secflowv1.NodeResult{
							NodeRunId:    task.GetNodeRunId(),
							RunId:        task.GetRunId(),
							NodeId:       task.GetNodeId(),
							PluginId:     task.GetPluginId(),
							Status:       secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
							ErrorCode:    "WORKER_DRAINING",
							ErrorMessage: "worker is draining and not accepting new tasks",
						},
					},
				})
				continue
			}
			nodeRunID := task.GetNodeRunId()
			var taskCtx context.Context
			var taskCancel context.CancelFunc
			if timeoutSec := task.GetHardTimeoutSeconds(); timeoutSec > 0 {
				taskCtx, taskCancel = context.WithTimeout(streamCtx, time.Duration(timeoutSec)*time.Second)
			} else {
				taskCtx, taskCancel = context.WithCancel(streamCtx)
			}
			taskCtx = context.WithValue(taskCtx, progressKey{}, progressFn(func(percent int32, message string) error {
				return sender.Send(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_TaskProgress{
						TaskProgress: &secflowv1.WorkerTaskProgress{
							NodeRunId:     nodeRunID,
							Percent:       percent,
							StatusMessage: message,
						},
					},
				})
			}))
			activeMu.Lock()
			activeTasks[nodeRunID] = taskCancel
			activeMu.Unlock()

			taskWg.Add(1)
			go func(t *secflowv1.NodeTask, tCtx context.Context, tCancel context.CancelFunc) {
				defer taskWg.Done()
				defer func() {
					tCancel()
					activeMu.Lock()
					delete(activeTasks, t.GetNodeRunId())
					activeMu.Unlock()
				}()
				spanCtx, span := obs.StartTaskSpan(
					tCtx,
					t.GetTraceparent(),
					"plugin."+t.GetPluginId(),
					attribute.String("secflow.run_id", t.GetRunId()),
					attribute.String("secflow.node_id", t.GetNodeId()),
					attribute.String("secflow.node_run_id", t.GetNodeRunId()),
					attribute.String("secflow.plugin_id", t.GetPluginId()),
				)
				defer span.End()

				slog.InfoContext(spanCtx, "worker task started",
					"run_id", t.GetRunId(),
					"node_id", t.GetNodeId(),
					"plugin_id", t.GetPluginId(),
				)
				result := handle(spanCtx, t)
				if result == nil {
					return
				}
				if result.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED {
					span.SetStatus(otelcodes.Error, result.GetErrorMessage())
				}
				if sendErr := sender.Send(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_CompleteTask{CompleteTask: result},
				}); sendErr != nil {
					slog.WarnContext(spanCtx, "stream send complete task failed", "node_run_id", t.GetNodeRunId(), "err", sendErr)
				}
			}(task, taskCtx, taskCancel)

		case *secflowv1.ConnectResponse_CancelTask:
			if p.CancelTask != nil {
				cancelActive(p.CancelTask.GetNodeRunId())
			}

		case *secflowv1.ConnectResponse_HeartbeatAck:
			if p.HeartbeatAck != nil {
				for _, expiredID := range p.HeartbeatAck.GetExpiredNodeRunIds() {
					cancelActive(expiredID)
				}
			}

		case *secflowv1.ConnectResponse_DrainRequest:
			draining.Store(true)
			reason := ""
			var grace time.Duration
			if p.DrainRequest != nil {
				reason = p.DrainRequest.GetReason()
				if p.DrainRequest.GetGracePeriodSeconds() > 0 {
					grace = time.Duration(p.DrainRequest.GetGracePeriodSeconds()) * time.Second
				}
			}
			_ = sender.Send(&secflowv1.ConnectRequest{
				Payload: &secflowv1.ConnectRequest_Drain{
					Drain: &secflowv1.WorkerDrainNotice{
						WorkerInstanceId: workerID,
						Reason:           reason,
					},
				},
			})
			done := make(chan struct{})
			go func() {
				taskWg.Wait()
				close(done)
			}()
			if grace > 0 {
				timer := time.NewTimer(grace)
				select {
				case <-done:
					timer.Stop()
				case <-ctx.Done():
					timer.Stop()
					streamCancel()
					<-done
				case <-timer.C:
					streamCancel()
					<-done
				}
			} else {
				select {
				case <-done:
				case <-ctx.Done():
					streamCancel()
					<-done
				}
			}
			streamCancel()
			hbWg.Wait()
			_ = sender.CloseSend()
			return accepted, true, nil
		default:
		}
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	if current <= 0 {
		return max
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
