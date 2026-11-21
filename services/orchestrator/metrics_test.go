package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/obs"
)

func TestOrchestratorQueueDepthEnqueueSettleCancelAndMetricsEndpoint(t *testing.T) {
	s := newServer()
	const pluginID = "trigger.manual"

	before := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(pluginID))

	s.wfMu.Lock()
	s.workflows["wf_metrics"] = &secflowv1.Workflow{
		Id:   "wf_metrics",
		Name: "metrics-test",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: pluginID, ParamsJson: []byte(`{}`)},
			},
		},
	}
	s.wfMu.Unlock()

	// 1. Enqueue via StartRun (without pump running) increments orchestrator_queue_depth.
	startResp, err := s.StartRun(t.Context(), &secflowv1.StartRunRequest{WorkflowId: "wf_metrics"})
	if err != nil {
		t.Fatalf("StartRun() error = %v", err)
	}
	runID1 := startResp.GetRun().GetId()

	afterEnqueue := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(pluginID))
	if afterEnqueue != before+1 {
		t.Fatalf("orchestrator_queue_depth after enqueue = %v, want %v", afterEnqueue, before+1)
	}

	// Verify /metrics HTTP endpoint exposes orchestrator_queue_depth{plugin_id="trigger.manual"}.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	httpserver.NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	wantLine := `orchestrator_queue_depth{plugin_id="trigger.manual"}`
	if !strings.Contains(body, wantLine) {
		t.Fatalf("/metrics output missing %q", wantLine)
	}

	// 2. Settling the task decrements orchestrator_queue_depth back to before.
	s.drain(t.Context())
	afterSettle := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(pluginID))
	if afterSettle != before {
		t.Fatalf("orchestrator_queue_depth after settle = %v, want %v", afterSettle, before)
	}
	// Idempotent double-settle must not decrement below baseline.
	s.settleTask(t.Context(), runID1, "t1", "SUCCEEDED", nil)
	if afterDouble := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(pluginID)); afterDouble != before {
		t.Fatalf("orchestrator_queue_depth after duplicate settle = %v, want %v", afterDouble, before)
	}

	// 3. Enqueue a second run and cancel it before draining -> decrements back to before.
	startResp2, err := s.StartRun(t.Context(), &secflowv1.StartRunRequest{WorkflowId: "wf_metrics"})
	if err != nil {
		t.Fatalf("StartRun() #2 error = %v", err)
	}
	runID2 := startResp2.GetRun().GetId()
	if got := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(pluginID)); got != before+1 {
		t.Fatalf("orchestrator_queue_depth after second enqueue = %v, want %v", got, before+1)
	}

	if _, err := s.CancelRun(t.Context(), &secflowv1.CancelRunRequest{RunId: runID2, Reason: "test cancel"}); err != nil {
		t.Fatalf("CancelRun() error = %v", err)
	}
	if afterCancel := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(pluginID)); afterCancel != before {
		t.Fatalf("orchestrator_queue_depth after cancel = %v, want %v", afterCancel, before)
	}

	// Verify /metrics also exposes orchestrator_runs_total and orchestrator_node_duration_seconds.
	rec2 := httptest.NewRecorder()
	httpserver.NewHandler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body2 := rec2.Body.String()
	for _, metric := range []string{"orchestrator_queue_depth", "orchestrator_runs_total", "orchestrator_node_duration_seconds"} {
		if !strings.Contains(body2, metric) {
			t.Fatalf("/metrics output missing %q", metric)
		}
	}
}

func TestStartRunAndWorkerDispatchPropagateTraceparent(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := obs.Init(t.Context(), "orchestrator")
	if err != nil {
		t.Fatalf("obs.Init() error = %v", err)
	}
	defer obs.Shutdown(shutdown)

	s := newServer()

	// Capture dispatched NodeTask traceparent from a mock connected worker.
	dispatched := make(chan *secflowv1.NodeTask, 1)
	link := &workerLink{
		instanceID: "worker-test",
		plugins:    []string{"scan.sca"},
		send: func(msg *secflowv1.ConnectResponse) error {
			if dt := msg.GetDispatchTask(); dt != nil {
				dispatched <- dt
				go s.deliver(&secflowv1.NodeResult{
					NodeRunId:         dt.GetNodeRunId(),
					RunId:             dt.GetRunId(),
					NodeId:            dt.GetNodeId(),
					PluginId:          dt.GetPluginId(),
					Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
					ActiveOutputPorts: []string{"default"},
				})
			}
			return nil
		},
	}
	s.plugMu.Lock()
	s.workers["scan.sca"] = []*workerLink{link}
	s.setActiveWorkers("scan.sca", s.activeWorkerCountLocked("scan.sca"))
	s.plugMu.Unlock()
	defer func() {
		s.plugMu.Lock()
		delete(s.workers, "scan.sca")
		s.setActiveWorkers("scan.sca", 0)
		s.plugMu.Unlock()
	}()

	s.wfMu.Lock()
	s.workflows["wf_trace"] = &secflowv1.Workflow{
		Id:   "wf_trace",
		Name: "trace-test",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "src1", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "sca1", PluginId: "scan.sca", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", TargetNodeId: "src1"},
				{Id: "e2", SourceNodeId: "src1", TargetNodeId: "sca1"},
			},
		},
	}
	s.wfMu.Unlock()

	rootCtx, rootSpan := obs.StartTaskSpan(t.Context(), "", "graphql.startRun")
	wantTraceID := obs.TraceIDFromContext(rootCtx)
	startResp, err := s.StartRun(rootCtx, &secflowv1.StartRunRequest{WorkflowId: "wf_trace"})
	rootSpan.End()
	if err != nil {
		t.Fatalf("StartRun() error = %v", err)
	}
	if startResp.GetRun().GetTraceId() != wantTraceID {
		t.Fatalf("Run.TraceId = %q, want %q", startResp.GetRun().GetTraceId(), wantTraceID)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s.drain(ctx)

	select {
	case task := <-dispatched:
		if !strings.Contains(task.GetTraceparent(), wantTraceID) {
			t.Fatalf("NodeTask.Traceparent = %q, want trace_id %q", task.GetTraceparent(), wantTraceID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for dispatched NodeTask")
	}

	// Ensure unused import guard isn't triggered; verify direct track/release helper with custom plugin.
	const customPlugin = "plugin.custom.metrics"
	s.runMu.Lock()
	s.trackQueuedTaskLocked("run_x:n1", customPlugin)
	if got := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(customPlugin)); got != 1 {
		s.runMu.Unlock()
		t.Fatalf("custom plugin queue depth = %v, want 1", got)
	}
	s.releaseQueuedTaskLocked("run_x:n1")
	s.runMu.Unlock()
	if got := testutil.ToFloat64(orchestratorQueueDepth.WithLabelValues(customPlugin)); got != 0 {
		t.Fatalf("custom plugin queue depth after release = %v, want 0", got)
	}
}
