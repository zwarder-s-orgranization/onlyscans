package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/workerclient"
)

func startTestGRPC(t *testing.T, s *Server) (*grpc.ClientConn, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	secflowv1.RegisterWorkerServiceServer(gs, s)
	secflowv1.RegisterPluginRegistryServiceServer(gs, s)
	secflowv1.RegisterRunServiceServer(gs, s)
	go func() {
		_ = gs.Serve(lis)
	}()
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		gs.Stop()
		_ = lis.Close()
		t.Fatalf("dial bufconn: %v", err)
	}
	return conn, func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	}
}

func TestBuiltinManifestsIncludeParamsSchemaAndLiveStatus(t *testing.T) {
	t.Parallel()
	s := newServer()

	// Seed a queued task in memq to verify QueueDepth reporting.
	s.runMu.Lock()
	s.memq = append(s.memq, memTask{runID: "r1", nodeID: "n1", plugin: "scan.sca", nodeRun: "r1:n1"})
	s.runMu.Unlock()

	resp, err := s.ListPlugins(t.Context(), &secflowv1.ListPluginsRequest{})
	if err != nil {
		t.Fatalf("ListPlugins: %v", err)
	}
	if len(resp.GetPlugins()) != 22 {
		t.Fatalf("plugin count = %d, want 22", len(resp.GetPlugins()))
	}

	byID := map[string]*secflowv1.RegisteredPlugin{}
	for _, rp := range resp.GetPlugins() {
		pid := rp.GetManifest().GetPluginId()
		byID[pid] = rp
		raw := rp.GetManifest().GetParamsJsonSchema()
		if len(raw) == 0 {
			t.Fatalf("plugin %s has empty ParamsJsonSchema", pid)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("plugin %s invalid ParamsJsonSchema JSON: %v", pid, err)
		}
	}

	if got := byID["trigger.manual"].GetStatus(); got != secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE {
		t.Fatalf("trigger.manual status = %v, want ONLINE", got)
	}
	if got := byID["gate.policy"].GetStatus(); got != secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE {
		t.Fatalf("gate.policy status = %v, want ONLINE", got)
	}
	sca := byID["scan.sca"]
	if sca.GetStatus() != secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE {
		t.Fatalf("scan.sca without workers status = %v, want OFFLINE", sca.GetStatus())
	}
	if sca.GetActiveWorkers() != 0 || sca.GetQueueDepth() != 1 {
		t.Fatalf("scan.sca active=%d depth=%d, want active=0 depth=1", sca.GetActiveWorkers(), sca.GetQueueDepth())
	}
}

func TestCompetingConsumersRoundRobinAndDrain(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	workerCli := secflowv1.NewWorkerServiceClient(conn)
	plugCli := secflowv1.NewPluginRegistryServiceClient(conn)

	m := manifest.One("scan.sca", "SCA", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"analyzer"}, false)
	m.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY

	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()

	s1, err := workerCli.Connect(ctx1)
	if err != nil {
		t.Fatalf("connect worker 1: %v", err)
	}
	s2, err := workerCli.Connect(ctx2)
	if err != nil {
		t.Fatalf("connect worker 2: %v", err)
	}

	for i, st := range []secflowv1.WorkerService_ConnectClient{s1, s2} {
		if err := st.Send(&secflowv1.ConnectRequest{
			Payload: &secflowv1.ConnectRequest_RegisterManifest{
				RegisterManifest: &secflowv1.WorkerRegisterManifest{
					WorkerInstanceId: "sca-" + string(rune('1'+i)),
					Manifests:        []*secflowv1.PluginManifest{m},
				},
			},
		}); err != nil {
			t.Fatalf("register worker %d: %v", i+1, err)
		}
		ack, err := st.Recv()
		if err != nil || !ack.GetManifestAck().GetAccepted() {
			t.Fatalf("manifest ack %d failed: %v %+v", i+1, err, ack)
		}
	}

	got, err := plugCli.GetPlugin(t.Context(), &secflowv1.GetPluginRequest{PluginId: "scan.sca"})
	if err != nil {
		t.Fatalf("GetPlugin: %v", err)
	}
	if got.GetPlugin().GetStatus() != secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE || got.GetPlugin().GetActiveWorkers() != 2 {
		t.Fatalf("plugin = %+v, want ONLINE with 2 active workers", got.GetPlugin())
	}

	var count1, count2 atomic.Int32
	serveLoop := func(st secflowv1.WorkerService_ConnectClient, counter *atomic.Int32) {
		for {
			msg, err := st.Recv()
			if err != nil {
				return
			}
			if task := msg.GetDispatchTask(); task != nil {
				counter.Add(1)
				_ = st.Send(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_CompleteTask{
						CompleteTask: &secflowv1.NodeResult{
							NodeRunId:         task.GetNodeRunId(),
							RunId:             task.GetRunId(),
							NodeId:            task.GetNodeId(),
							PluginId:          task.GetPluginId(),
							Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
							ActiveOutputPorts: []string{"default"},
						},
					},
				})
			}
		}
	}
	go serveLoop(s1, &count1)
	go serveLoop(s2, &count2)

	for range 4 {
		res, ok := s.callWorker(t.Context(), "scan.sca", engine.Node{ID: "n1", PluginID: "scan.sca"}, engine.Envelope{Vars: map[string]string{"runId": "r1"}})
		if !ok || res.Status != "SUCCEEDED" {
			t.Fatalf("callWorker failed: ok=%v res=%+v", ok, res)
		}
	}
	if count1.Load() != 2 || count2.Load() != 2 {
		t.Fatalf("round-robin counts = (%d, %d), want (2, 2)", count1.Load(), count2.Load())
	}

	// Mark worker 1 as draining; dispatches must route exclusively to worker 2.
	if err := s1.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_Drain{
			Drain: &secflowv1.WorkerDrainNotice{WorkerInstanceId: "sca-1", Reason: "rolling update"},
		},
	}); err != nil {
		t.Fatalf("send drain: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		resp, err := plugCli.GetPlugin(t.Context(), &secflowv1.GetPluginRequest{PluginId: "scan.sca"})
		if err == nil && resp.GetPlugin().GetActiveWorkers() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, err = plugCli.GetPlugin(t.Context(), &secflowv1.GetPluginRequest{PluginId: "scan.sca"})
	if err != nil || got.GetPlugin().GetActiveWorkers() != 1 || got.GetPlugin().GetStatus() != secflowv1.PluginStatus_PLUGIN_STATUS_ONLINE {
		t.Fatalf("after drain plugin = %+v, err=%v", got.GetPlugin(), err)
	}

	for range 2 {
		res, ok := s.callWorker(t.Context(), "scan.sca", engine.Node{ID: "n2", PluginID: "scan.sca"}, engine.Envelope{Vars: map[string]string{"runId": "r1"}})
		if !ok || res.Status != "SUCCEEDED" {
			t.Fatalf("callWorker after drain failed: ok=%v res=%+v", ok, res)
		}
	}
	if count1.Load() != 2 || count2.Load() != 4 {
		t.Fatalf("counts after drain = (%d, %d), want (2, 4)", count1.Load(), count2.Load())
	}

	// Disconnect both workers; plugin must become OFFLINE.
	cancel1()
	cancel2()
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		resp, err := plugCli.GetPlugin(t.Context(), &secflowv1.GetPluginRequest{PluginId: "scan.sca"})
		if err == nil && resp.GetPlugin().GetStatus() == secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("plugin did not transition to OFFLINE after all workers disconnected")
}

func TestWorkerHeartbeatProgressAndCancelRun(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s.startPump(ctx)

	workerCli := secflowv1.NewWorkerServiceClient(conn)
	runCli := secflowv1.NewRunServiceClient(conn)

	m := manifest.One("scan.sca", "SCA", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"analyzer"}, false)
	stream, err := workerCli.Connect(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := stream.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_RegisterManifest{
			RegisterManifest: &secflowv1.WorkerRegisterManifest{
				WorkerInstanceId: "sca-cancel-worker",
				Manifests:        []*secflowv1.PluginManifest{m},
			},
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("manifest ack: %v", err)
	}

	s.wfMu.Lock()
	s.workflows["wf_cancel"] = &secflowv1.Workflow{
		Id:      "wf_cancel",
		Name:    "Cancel Test",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "src", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "sca", PluginId: "scan.sca", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "src", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "sca", TargetHandle: "default"},
			},
		},
	}
	s.wfMu.Unlock()

	startResp, err := runCli.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: "wf_cancel"})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := startResp.GetRun().GetId()

	// Wait for worker to receive DispatchTask.
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("worker recv task: %v", err)
	}
	task := msg.GetDispatchTask()
	if task == nil || task.GetPluginId() != "scan.sca" {
		t.Fatalf("expected scan.sca dispatch, got %+v", msg)
	}

	// Send Heartbeat and verify HeartbeatAck.
	if err := stream.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_Heartbeat{
			Heartbeat: &secflowv1.WorkerHeartbeat{
				WorkerInstanceId: "sca-cancel-worker",
				ActiveNodeRunIds: []string{task.GetNodeRunId()},
				AvailableSlots:   3,
			},
		},
	}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	hbResp, err := stream.Recv()
	if err != nil || hbResp.GetHeartbeatAck() == nil {
		t.Fatalf("expected HeartbeatAck, got %+v err=%v", hbResp, err)
	}

	// Send TaskProgress and synchronize with a Heartbeat round-trip so the
	// server's Connect loop finishes recording the progress event before
	// CancelRun removes the task from activeTasks.
	if err := stream.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_TaskProgress{
			TaskProgress: &secflowv1.WorkerTaskProgress{
				NodeRunId:     task.GetNodeRunId(),
				Percent:       55,
				StatusMessage: "matching maven catalog",
			},
		},
	}); err != nil {
		t.Fatalf("send progress: %v", err)
	}
	if err := stream.Send(&secflowv1.ConnectRequest{
		Payload: &secflowv1.ConnectRequest_Heartbeat{
			Heartbeat: &secflowv1.WorkerHeartbeat{
				WorkerInstanceId: "sca-cancel-worker",
				ActiveNodeRunIds: []string{task.GetNodeRunId()},
				AvailableSlots:   3,
			},
		},
	}); err != nil {
		t.Fatalf("send barrier heartbeat: %v", err)
	}
	barrierResp, err := stream.Recv()
	if err != nil || barrierResp.GetHeartbeatAck() == nil {
		t.Fatalf("expected barrier HeartbeatAck, got %+v err=%v", barrierResp, err)
	}

	// Cancel the run and verify the worker receives CancelTask.
	cancelResp, err := runCli.CancelRun(ctx, &secflowv1.CancelRunRequest{RunId: runID, Reason: "stop now"})
	if err != nil {
		t.Fatalf("CancelRun: %v", err)
	}
	if cancelResp.GetRun().GetStatus() != secflowv1.RunStatus_RUN_STATUS_CANCELLED {
		t.Fatalf("cancel status = %v", cancelResp.GetRun().GetStatus())
	}

	cancelMsg, err := stream.Recv()
	if err != nil {
		t.Fatalf("worker recv cancel: %v", err)
	}
	if cancelMsg.GetCancelTask().GetNodeRunId() != task.GetNodeRunId() {
		t.Fatalf("expected CancelTask for %q, got %+v", task.GetNodeRunId(), cancelMsg)
	}

	// Verify WatchRun replays progress + cancelled events.
	watchStream, err := runCli.WatchRun(ctx, &secflowv1.WatchRunRequest{RunId: runID, AfterSeq: 0})
	if err != nil {
		t.Fatalf("WatchRun: %v", err)
	}
	var sawProgress, sawCancelled bool
	for !(sawProgress && sawCancelled) {
		evResp, err := watchStream.Recv()
		if err != nil {
			t.Fatalf("watch recv: %v", err)
		}
		ev := evResp.GetEvent()
		if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_NODE_STATUS_CHANGED && strings.Contains(ev.GetMessage(), "matching maven catalog") {
			sawProgress = true
		}
		if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_CANCELLED {
			sawCancelled = true
		}
	}
}

func TestWorkerUnavailableFailsWithoutSilentPassOrFallback(t *testing.T) {
	t.Setenv("ALLOW_INPROCESS_ANALYZERS", "")
	s := newServer()
	h := s.handlers("")

	remotePlugins := []string{
		"scan.secrets",
		"scan.sast.kotlin",
		"scan.sca",
		"sbom.generate",
		"ai.explain",
		"notify.telegram",
		"notify.webhook",
		"notify.smtp",
		"mcp.tool",
	}
	for _, pluginID := range remotePlugins {
		t.Run(pluginID, func(t *testing.T) {
			fn, ok := h[pluginID]
			if !ok {
				t.Fatalf("handler missing for %s", pluginID)
			}
			res := fn(engine.Node{ID: "n1", PluginID: pluginID}, engine.Envelope{})
			if res.Status != "FAILED" || !strings.Contains(res.Err, "WORKER_UNAVAILABLE") {
				t.Fatalf("%s returned status=%q err=%q, want FAILED with WORKER_UNAVAILABLE", pluginID, res.Status, res.Err)
			}
		})
	}
}

func TestRunLifecycleEventsAndGarageArtifactPersistence(t *testing.T) {
	var mu sync.Mutex
	stored := map[string][]byte{}
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			stored[r.URL.Path] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			data, ok := stored[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer s3Srv.Close()

	t.Setenv("GARAGE_ENDPOINT", s3Srv.URL)
	t.Setenv("GARAGE_ACCESS_KEY", "test-access")
	t.Setenv("GARAGE_SECRET_KEY", "test-secret")

	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s.startPump(ctx)

	// Connect an sbom.generate worker using the real workerclient loop.
	sbomManifest := manifest.One("sbom.generate", "SBOM", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"sbom"}, false)
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()
	workerReady := make(chan struct{})
	go func() {
		cli := secflowv1.NewWorkerServiceClient(conn)
		stream, err := cli.Connect(workerCtx)
		if err != nil {
			return
		}
		_ = stream.Send(&secflowv1.ConnectRequest{
			Payload: &secflowv1.ConnectRequest_RegisterManifest{
				RegisterManifest: &secflowv1.WorkerRegisterManifest{
					WorkerInstanceId: "sbom-test-1",
					Manifests:        []*secflowv1.PluginManifest{sbomManifest},
				},
			},
		})
		if _, err := stream.Recv(); err != nil {
			return
		}
		close(workerReady)
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if task := msg.GetDispatchTask(); task != nil {
				_ = workerclient.ReportProgress(workerCtx, 100, "done")
				_ = stream.Send(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_CompleteTask{
						CompleteTask: &secflowv1.NodeResult{
							NodeRunId:         task.GetNodeRunId(),
							RunId:             task.GetRunId(),
							NodeId:            task.GetNodeId(),
							PluginId:          "sbom.generate",
							Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
							EnvelopePatchJson: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`),
							ActiveOutputPorts: []string{"default"},
						},
					},
				})
			}
		}
	}()
	<-workerReady

	s.wfMu.Lock()
	s.workflows["wf_sbom"] = &secflowv1.Workflow{
		Id:      "wf_sbom",
		Name:    "SBOM Artifacts",
		Version: 1,
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "src", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "sbom", PluginId: "sbom.generate", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "src", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "sbom", TargetHandle: "default"},
			},
		},
	}
	s.wfMu.Unlock()

	runCli := secflowv1.NewRunServiceClient(conn)
	startResp, err := runCli.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: "wf_sbom"})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := startResp.GetRun().GetId()

	watchStream, err := runCli.WatchRun(ctx, &secflowv1.WatchRunRequest{RunId: runID})
	if err != nil {
		t.Fatalf("WatchRun: %v", err)
	}
	var events []*secflowv1.RunEvent
	for {
		resp, err := watchStream.Recv()
		if err != nil {
			t.Fatalf("watch recv: %v", err)
		}
		ev := resp.GetEvent()
		events = append(events, ev)
		if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_COMPLETED {
			break
		}
	}

	var sawNodeRunning, sawNodeSucceeded bool
	for _, ev := range events {
		if ev.GetEventType() == secflowv1.RunEventType_RUN_EVENT_TYPE_NODE_STATUS_CHANGED && ev.GetNodeId() == "sbom" {
			if ev.GetNodeStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_RUNNING {
				sawNodeRunning = true
			}
			if ev.GetNodeStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
				sawNodeSucceeded = true
			}
		}
	}
	if !sawNodeRunning || !sawNodeSucceeded {
		t.Fatalf("expected sbom node lifecycle events (running=%v succeeded=%v)", sawNodeRunning, sawNodeSucceeded)
	}

	// Verify afterSeq replay only returns events with seq_id > afterSeq.
	lastSeq := events[len(events)-1].GetSeqId()
	replayCtx, replayCancel := context.WithCancel(ctx)
	replayStream, err := runCli.WatchRun(replayCtx, &secflowv1.WatchRunRequest{RunId: runID, AfterSeq: lastSeq - 1})
	if err != nil {
		t.Fatalf("WatchRun afterSeq: %v", err)
	}
	replayed, err := replayStream.Recv()
	replayCancel()
	if err != nil {
		t.Fatalf("replay recv: %v", err)
	}
	if replayed.GetEvent().GetSeqId() != lastSeq {
		t.Fatalf("replayed seq = %d, want %d", replayed.GetEvent().GetSeqId(), lastSeq)
	}

	// Verify Garage artifact paths.
	mu.Lock()
	defer mu.Unlock()
	wantPaths := []string{
		"/secflow-artifacts/runs/" + runID + "/nodes/sbom/in.json",
		"/secflow-artifacts/runs/" + runID + "/nodes/sbom/out.json",
		"/secflow-artifacts/runs/" + runID + "/nodes/sbom/out.default.json",
		"/secflow-sbom/runs/" + runID + "/sbom.cdx.json",
	}
	for _, p := range wantPaths {
		if len(stored[p]) == 0 {
			t.Fatalf("missing Garage artifact %q; stored keys=%v", p, keysOf(stored))
		}
	}
}

func TestRunEventsChannelSanitization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		runID string
		want  string
	}{
		{name: "standard id", runID: "run_abc123", want: "run_events_run_abc123"},
		{name: "special chars", runID: "run-1; DROP TABLE runs;", want: "run_events_run_1__DROP_TABLE_runs_"},
		{name: "long id truncated to 63", runID: strings.Repeat("a", 80), want: "run_events_" + strings.Repeat("a", 52)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := runEventsChannel(tt.runID)
			if got != tt.want {
				t.Fatalf("runEventsChannel(%q) = %q, want %q", tt.runID, got, tt.want)
			}
			if len(got) > 63 {
				t.Fatalf("channel length %d exceeds 63", len(got))
			}
		})
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
