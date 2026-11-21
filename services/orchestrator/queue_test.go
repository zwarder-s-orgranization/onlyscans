package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
)

type watchCollector struct {
	ctx    context.Context
	cancel context.CancelFunc
	events chan *secflowv1.RunEvent
}

func (w *watchCollector) Send(resp *secflowv1.WatchRunResponse) error {
	ev := resp.GetEvent()
	w.events <- ev
	if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_COMPLETED {
		w.cancel()
	}
	return nil
}
func (w *watchCollector) SetHeader(metadata.MD) error  { return nil }
func (w *watchCollector) SendHeader(metadata.MD) error { return nil }
func (w *watchCollector) SetTrailer(metadata.MD)       {}
func (w *watchCollector) Context() context.Context     { return w.ctx }
func (w *watchCollector) SendMsg(any) error            { return nil }
func (w *watchCollector) RecvMsg(any) error            { return nil }

func TestCloneKeepsSecretSlotWithoutValue(t *testing.T) {
	t.Parallel()
	s := newServer()
	resp, err := s.CloneTemplate(t.Context(), &secflowv1.CloneTemplateRequest{TemplateId: "nightly-secret-watch", NewWorkflowName: "nightly"})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range resp.GetWorkflow().GetGraph().GetNodes() {
		if n.GetPluginId() != "notify.telegram" {
			continue
		}
		found = true
		if len(n.GetSecretBindings()) != 0 {
			t.Fatalf("expected no unbound empty secret bindings, got %+v", n.GetSecretBindings())
		}
	}
	if !found {
		t.Fatal("telegram node missing")
	}
	if issues := engine.Validate(toEngine(resp.GetWorkflow().GetGraph())); !hasError(issues) {
		t.Fatal("empty secret ref must block a run")
	}
}

func TestQueuedRunCompletesWithoutDatabase(t *testing.T) {
	t.Parallel()
	s := newServer()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	s.startPump(ctx)
	s.wfMu.Lock()
	s.workflows["w"] = &secflowv1.Workflow{Id: "w", Name: "manual", Graph: &secflowv1.WorkflowGraph{SchemaVersion: 1, Nodes: []*secflowv1.WorkflowNode{{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)}}}}
	s.wfMu.Unlock()
	resp, err := s.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: "w"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetRun().GetStatus() != secflowv1.RunStatus_RUN_STATUS_QUEUED {
		t.Fatalf("status %s", resp.GetRun().GetStatus())
	}

	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	wc := &watchCollector{ctx: watchCtx, cancel: watchCancel, events: make(chan *secflowv1.RunEvent, 16)}
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.WatchRun(&secflowv1.WatchRunRequest{RunId: resp.GetRun().GetId()}, wc)
	}()

	for {
		select {
		case ev := <-wc.events:
			if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_COMPLETED {
				if ev.GetRunStatus() != secflowv1.RunStatus_RUN_STATUS_SUCCEEDED {
					t.Fatalf("expected SUCCEEDED, got %s (%s)", ev.GetRunStatus(), ev.GetMessage())
				}
				return
			}
		case err := <-errCh:
			if err != nil {
				t.Fatalf("watch run failed: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("run did not finish before timeout")
		}
	}
}
