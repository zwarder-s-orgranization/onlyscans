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
	"google.golang.org/grpc/metadata"
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
	secflowv1.RegisterWorkflowServiceServer(gs, s)
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

	// Send TaskProgress and flush the bidirectional stream with a Heartbeat round-trip
	// so handleTaskProgress has persisted the event before CancelRun tears down activeTasks.
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
		t.Fatalf("send sync heartbeat: %v", err)
	}
	if syncResp, err := stream.Recv(); err != nil || syncResp.GetHeartbeatAck() == nil {
		t.Fatalf("expected sync HeartbeatAck, got %+v err=%v", syncResp, err)
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

func connectTestWorker(
	t *testing.T,
	ctx context.Context,
	conn *grpc.ClientConn,
	instanceID string,
	manifests []*secflowv1.PluginManifest,
	handler func(task *secflowv1.NodeTask) *secflowv1.NodeResult,
) {
	t.Helper()
	workerCtx := ctx
	isExternal := false
	sandboxProfile := secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY
	for _, m := range manifests {
		if m != nil && m.GetIsExternal() {
			isExternal = true
			if m.GetSandboxProfile() == secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL {
				sandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL
			}
		}
	}
	if isExternal {
		plugCli := secflowv1.NewPluginRegistryServiceClient(conn)
		instResp, err := plugCli.InstallPlugin(ctx, &secflowv1.InstallPluginRequest{
			Actor:          &secflowv1.ActorContext{Subject: "test-owner@secflow.local", Role: secflowv1.Role_ROLE_OWNER},
			Name:           "test-" + instanceID,
			SourceMode:     secflowv1.PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
			SandboxProfile: sandboxProfile,
			AutoApprove:    true,
		})
		if err != nil {
			t.Fatalf("InstallPlugin for test worker %s: %v", instanceID, err)
		}
		workerCtx = metadata.AppendToOutgoingContext(ctx, "x-plugin-token", instResp.GetPlaintextPluginToken())
	}
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		cli := secflowv1.NewWorkerServiceClient(conn)
		stream, err := cli.Connect(workerCtx)
		if err != nil {
			errCh <- err
			return
		}
		if err := stream.Send(&secflowv1.ConnectRequest{
			Payload: &secflowv1.ConnectRequest_RegisterManifest{
				RegisterManifest: &secflowv1.WorkerRegisterManifest{
					WorkerInstanceId: instanceID,
					Namespace:        "secflow-sandbox",
					Manifests:        manifests,
				},
			},
		}); err != nil {
			errCh <- err
			return
		}
		ack, err := stream.Recv()
		if err != nil {
			errCh <- err
			return
		}
		if !ack.GetManifestAck().GetAccepted() {
			errCh <- io.EOF
			return
		}
		close(ready)
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if task := msg.GetDispatchTask(); task != nil {
				res := handler(task)
				if sendErr := stream.Send(&secflowv1.ConnectRequest{
					Payload: &secflowv1.ConnectRequest_CompleteTask{CompleteTask: res},
				}); sendErr != nil {
					return
				}
			}
		}
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("connect test worker %s: %v", instanceID, err)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out connecting test worker %s", instanceID)
	}
}

func waitForRunCompletion(t *testing.T, ctx context.Context, runCli secflowv1.RunServiceClient, runID string) {
	t.Helper()
	watchStream, err := runCli.WatchRun(ctx, &secflowv1.WatchRunRequest{RunId: runID})
	if err != nil {
		t.Fatalf("WatchRun: %v", err)
	}
	for {
		evResp, err := watchStream.Recv()
		if err != nil {
			t.Fatalf("watch recv: %v", err)
		}
		et := evResp.GetEvent().GetEventType()
		if et == secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_COMPLETED {
			return
		}
		if et == secflowv1.RunEventType_RUN_EVENT_TYPE_RUN_FAILED {
			t.Fatalf("run failed unexpectedly: %s", evResp.GetEvent().GetMessage())
		}
	}
}

func TestExternalPluginsFourCategoriesEndToEnd(t *testing.T) {
	var s3Mu sync.Mutex
	stored := map[string][]byte{}
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s3Mu.Lock()
		defer s3Mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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

	line12 := int32(12)
	analyzerManifest := &secflowv1.PluginManifest{
		PluginId:       "custom.iac-checker",
		Version:        "1.0.0",
		DisplayName:    "Custom IaC Checker",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		Capabilities:   []string{"analyzer"},
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	logicManifest := &secflowv1.PluginManifest{
		PluginId:     "logic.risk-router",
		Version:      "1.0.0",
		DisplayName:  "Risk Router",
		Category:     secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC,
		Capabilities: []string{"logic"},
		ParamsJsonSchema: []byte(`{
			"type": "object",
			"additionalProperties": false,
			"required": ["blockThreshold"],
			"properties": {
				"blockThreshold": {"type": "integer", "minimum": 1}
			}
		}`),
		InputPorts: []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts: []*secflowv1.PortDefinition{
			{Id: "BLOCK", Label: "BLOCK"},
			{Id: "REVIEW", Label: "REVIEW"},
			{Id: "OK", Label: "OK"},
		},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	reportManifest := &secflowv1.PluginManifest{
		PluginId:       "report.sarif-exporter",
		Version:        "1.0.0",
		DisplayName:    "SARIF 2.1 Exporter",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_AI_REPORT,
		Capabilities:   []string{"report"},
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	actionManifest := &secflowv1.PluginManifest{
		PluginId:           "action.mattermost",
		Version:            "1.0.0",
		DisplayName:        "Mattermost Notifier",
		Category:           secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		Capabilities:       []string{"notify"},
		RequiredSecretKeys: []string{"webhookToken"},
		ParamsJsonSchema: []byte(`{
			"type": "object",
			"required": ["message"],
			"properties": {
				"message": {"type": "string", "minLength": 1},
				"webhookToken": {"type": "string"}
			}
		}`),
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		IsExternal:     true,
	}

	var analyzerLeaseToken string
	var analyzerMu sync.Mutex
	connectTestWorker(t, ctx, conn, "iac-1", []*secflowv1.PluginManifest{analyzerManifest}, func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		analyzerMu.Lock()
		analyzerLeaseToken = task.GetTaskLeaseToken()
		analyzerMu.Unlock()
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "custom.iac-checker",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			ActiveOutputPorts: []string{"default"},
			Findings: []*secflowv1.Finding{
				{
					FindingId:    "F-IAC-1",
					SourceNodeId: task.GetNodeId(),
					PluginId:     "custom.iac-checker",
					Category:     secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
					Severity:     secflowv1.Severity_SEVERITY_HIGH,
					Path:         "deploy/pod.yaml",
					FindingClass: "privileged-container",
					Line:         &line12,
					Description:  "Container runs privileged",
				},
				{
					FindingId:    "F-BAD-CAT",
					SourceNodeId: task.GetNodeId(),
					PluginId:     "custom.iac-checker",
					Category:     secflowv1.FindingCategory_FINDING_CATEGORY_UNSPECIFIED,
					Severity:     secflowv1.Severity_SEVERITY_LOW,
					Path:         "deploy/ignored.yaml",
					FindingClass: "invalid-cat",
				},
			},
		}
	})

	connectTestWorker(t, ctx, conn, "risk-1", []*secflowv1.PluginManifest{logicManifest}, func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		return &secflowv1.NodeResult{
			NodeRunId: task.GetNodeRunId(),
			RunId:     task.GetRunId(),
			NodeId:    task.GetNodeId(),
			PluginId:  "logic.risk-router",
			Status:    secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			// Include an undeclared port to verify it is filtered out.
			ActiveOutputPorts: []string{"BLOCK", "UNDECLARED_PORT"},
			// Attempt to inject an unauthorized finding from a LOGIC plugin; must be ignored in Run Findings.
			Findings: []*secflowv1.Finding{
				{
					FindingId: "F-SPOOF-LOGIC",
					Category:  secflowv1.FindingCategory_FINDING_CATEGORY_SAST,
					Severity:  secflowv1.Severity_SEVERITY_CRITICAL,
					Path:      "spoof.kt",
				},
			},
			// Attempt to fabricate a nonexistent finding in branch-local findings; must be stripped.
			EnvelopePatchJson: []byte(`{
				"findings": [{"findingId": "F-FABRICATED", "category": "SAST", "severity": "CRITICAL", "path": "fake.kt"}],
				"gate": {"status": "FAIL", "reason": "risk score 95 >= 50"},
				"vars": {"score": "95", "tier": "critical"}
			}`),
		}
	})

	connectTestWorker(t, ctx, conn, "sarif-1", []*secflowv1.PluginManifest{reportManifest}, func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "report.sarif-exporter",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			ActiveOutputPorts: []string{"default"},
			PayloadS3Key:      "runs/" + task.GetRunId() + "/nodes/" + task.GetNodeId() + "/report.sarif",
			Findings: []*secflowv1.Finding{
				{
					FindingId: "F-SPOOF-REPORT",
					Category:  secflowv1.FindingCategory_FINDING_CATEGORY_SECRET,
					Severity:  secflowv1.Severity_SEVERITY_CRITICAL,
					Path:      "spoof-report.yml",
				},
			},
			EnvelopePatchJson: []byte(`{"vars": {"format": "sarif-2.1.0"}, "artifactContent": "{\"version\":\"2.1.0\",\"runs\":[]}"}`),
		}
	})

	var actionReceivedParams map[string]any
	var actionMu sync.Mutex
	connectTestWorker(t, ctx, conn, "mm-1", []*secflowv1.PluginManifest{actionManifest}, func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		var p map[string]any
		if err := json.Unmarshal(task.GetParamsJson(), &p); err != nil {
			t.Errorf("unmarshal action params: %v", err)
		}
		actionMu.Lock()
		actionReceivedParams = p
		actionMu.Unlock()
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "action.mattermost",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			ActiveOutputPorts: []string{"default"},
			Findings: []*secflowv1.Finding{
				{
					FindingId: "F-SPOOF-ACTION",
					Category:  secflowv1.FindingCategory_FINDING_CATEGORY_SCA,
					Severity:  secflowv1.Severity_SEVERITY_CRITICAL,
					Path:      "build.gradle.kts",
				},
			},
			EnvelopePatchJson: []byte(`{"vars": {"deliveryId": "mm_42"}}`),
		}
	})

	wfCli := secflowv1.NewWorkflowServiceClient(conn)
	runCli := secflowv1.NewRunServiceClient(conn)

	graph := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
			{Id: "src", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
			{Id: "iac", PluginId: "custom.iac-checker", ParamsJson: []byte(`{}`)},
			{Id: "risk", PluginId: "logic.risk-router", ParamsJson: []byte(`{"blockThreshold":50}`)},
			{Id: "sarif", PluginId: "report.sarif-exporter", ParamsJson: []byte(`{}`)},
			{
				Id:             "mm",
				PluginId:       "action.mattermost",
				ParamsJson:     []byte(`{"message":"Risk={{ $envelope.vars.plugins.logic.risk-router.score }} Gate={{ $envelope.gate.status }} Format={{ $envelope.vars.plugins.report.sarif-exporter.format }}","webhookToken":"{{ $envelope.gate.status }}"}`),
				SecretBindings: []*secflowv1.SecretBinding{{ParamKey: "webhookToken", SecretRef: "sec_mm_1"}},
			},
			{Id: "ok_hook", PluginId: "notify.webhook", ParamsJson: []byte(`{"url":"https://example.com/ok"}`)},
		},
		Edges: []*secflowv1.WorkflowEdge{
			{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "src", TargetHandle: "default"},
			{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "iac", TargetHandle: "default"},
			{Id: "e3", SourceNodeId: "iac", SourceHandle: "default", TargetNodeId: "risk", TargetHandle: "default"},
			{Id: "e4", SourceNodeId: "risk", SourceHandle: "BLOCK", TargetNodeId: "sarif", TargetHandle: "default"},
			{Id: "e5", SourceNodeId: "sarif", SourceHandle: "default", TargetNodeId: "mm", TargetHandle: "default"},
			{Id: "e6", SourceNodeId: "risk", SourceHandle: "OK", TargetNodeId: "ok_hook", TargetHandle: "default"},
		},
	}

	valResp, err := wfCli.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{Graph: graph})
	if err != nil {
		t.Fatalf("ValidateWorkflow: %v", err)
	}
	if !valResp.GetValid() {
		t.Fatalf("expected valid workflow with 4 external plugin categories, got issues: %+v", valResp.GetIssues())
	}

	createResp, err := wfCli.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{Name: "External 4 Categories", Graph: graph})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	startResp, err := runCli.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: createResp.GetWorkflow().GetId()})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := startResp.GetRun().GetId()
	waitForRunCompletion(t, ctx, runCli, runID)

	analyzerMu.Lock()
	gotAnalyzerLease := analyzerLeaseToken
	analyzerMu.Unlock()
	if gotAnalyzerLease != "" {
		t.Fatalf("non-scan ANALYZER plugin must not receive TaskLeaseToken, got %q", gotAnalyzerLease)
	}

	runResp, err := runCli.GetRun(ctx, &secflowv1.GetRunRequest{RunId: runID})
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got := runResp.GetRun().GetGateResult(); got == nil || got.GetStatus() != secflowv1.GateStatus_GATE_STATUS_FAIL || got.GetReason() != "risk score 95 >= 50" {
		t.Fatalf("gate result = %+v, want FAIL from logic.risk-router", got)
	}

	riskPayload, err := runCli.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "risk"})
	if err != nil {
		t.Fatalf("GetNodePayload(risk): %v", err)
	}
	if len(riskPayload.GetActiveOutputPorts()) != 1 || riskPayload.GetActiveOutputPorts()[0] != "BLOCK" {
		t.Fatalf("risk activeOutputPorts = %v, want [BLOCK] (undeclared port must be filtered)", riskPayload.GetActiveOutputPorts())
	}

	findingsResp, err := runCli.ListFindings(ctx, &secflowv1.ListFindingsRequest{RunId: runID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findingsResp.GetFindings()) != 1 || findingsResp.GetFindings()[0].GetPath() != "deploy/pod.yaml" {
		t.Fatalf("Run Findings = %+v, want strictly 1 valid finding from ANALYZER (no spoofed findings, no invalid category)", findingsResp.GetFindings())
	}

	subResp, err := runCli.GetSubmissionReport(ctx, &secflowv1.GetSubmissionReportRequest{RunId: runID})
	if err != nil {
		t.Fatalf("GetSubmissionReport: %v", err)
	}
	var subDoc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(subResp.GetSubmissionJson(), &subDoc); err != nil {
		t.Fatalf("unmarshal submission.json: %v", err)
	}
	if len(subDoc.Findings) != 1 || subDoc.Findings[0]["path"] != "deploy/pod.yaml" {
		t.Fatalf("Submission Report = %s, want immutable single finding", string(subResp.GetSubmissionJson()))
	}

	s3Mu.Lock()
	sarifBlob := stored["/secflow-artifacts/runs/"+runID+"/nodes/sarif/report.sarif"]
	s3Mu.Unlock()
	if string(sarifBlob) != `{"version":"2.1.0","runs":[]}` {
		t.Fatalf("secflow-artifacts SARIF blob = %q, want persisted SARIF payload", string(sarifBlob))
	}

	actionMu.Lock()
	gotMsg, _ := actionReceivedParams["message"].(string)
	gotSecretParam, _ := actionReceivedParams["webhookToken"].(string)
	actionMu.Unlock()
	if gotMsg != "Risk=95 Gate=FAIL Format=sarif-2.1.0" {
		t.Fatalf("action.mattermost resolved message = %q, want %q", gotMsg, "Risk=95 Gate=FAIL Format=sarif-2.1.0")
	}
	if gotSecretParam != "{{ $envelope.gate.status }}" {
		t.Fatalf("secret key param webhookToken must not be template-interpolated, got %q", gotSecretParam)
	}

	mmPayload, err := runCli.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "mm"})
	if err != nil {
		t.Fatalf("GetNodePayload(mm): %v", err)
	}
	var mmOut engine.Envelope
	if err := json.Unmarshal(mmPayload.GetOutputEnvelopeJson(), &mmOut); err != nil {
		t.Fatalf("unmarshal mm output envelope: %v", err)
	}
	if mmOut.Vars["plugins.action.mattermost.deliveryId"] != "mm_42" {
		t.Fatalf("mm output vars = %+v, want plugins.action.mattermost.deliveryId=mm_42", mmOut.Vars)
	}
	if mmOut.Vars["plugins.report.sarif-exporter.artifactKey"] != "runs/"+runID+"/nodes/sarif/report.sarif" {
		t.Fatalf("mm output vars = %+v, want sarif artifactKey preserved", mmOut.Vars)
	}
	if len(mmOut.Findings) != 0 {
		t.Fatalf("branch-local findings after logic.risk-router filter = %+v, want empty (fabricated finding must be dropped)", mmOut.Findings)
	}

	okPayload, err := runCli.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{RunId: runID, NodeId: "ok_hook"})
	if err != nil {
		t.Fatalf("GetNodePayload(ok_hook): %v", err)
	}
	if okPayload.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SKIPPED {
		t.Fatalf("inactive OK branch status = %v, want SKIPPED", okPayload.GetStatus())
	}
}

func TestValidateWorkflowAndStartRunExternalPluginErrors(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	s.plugMu.Lock()
	s.plugins["custom.iac-checker"] = &secflowv1.PluginManifest{
		PluginId:       "custom.iac-checker",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	s.plugins["logic.risk-router"] = &secflowv1.PluginManifest{
		PluginId: "logic.risk-router",
		Category: secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC,
		ParamsJsonSchema: []byte(`{
			"type": "object",
			"required": ["blockThreshold"],
			"properties": {"blockThreshold": {"type": "integer", "minimum": 1}}
		}`),
		OutputPorts: []*secflowv1.PortDefinition{
			{Id: "BLOCK", Label: "BLOCK"},
			{Id: "OK", Label: "OK"},
		},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	s.plugMu.Unlock()

	wfCli := secflowv1.NewWorkflowServiceClient(conn)
	runCli := secflowv1.NewRunServiceClient(conn)

	t.Run("missing source before non-scan analyzer and bad external params", func(t *testing.T) {
		g := &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "iac", PluginId: "custom.iac-checker", ParamsJson: []byte(`{}`)},
				{Id: "risk", PluginId: "logic.risk-router", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "iac", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "iac", SourceHandle: "default", TargetNodeId: "risk", TargetHandle: "default"},
			},
		}
		resp, err := wfCli.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{Graph: g})
		if err != nil {
			t.Fatalf("ValidateWorkflow: %v", err)
		}
		codes := map[string]bool{}
		for _, iss := range resp.GetIssues() {
			codes[iss.GetCode()] = true
		}
		if !codes[engine.CodeMissingSource] {
			t.Fatalf("expected %s, got %+v", engine.CodeMissingSource, resp.GetIssues())
		}
		if !codes["MISSING_REQUIRED_PARAM"] {
			t.Fatalf("expected MISSING_REQUIRED_PARAM for external schema, got %+v", resp.GetIssues())
		}
	})

	t.Run("disabled and unregistered plugins fail validation and StartRun without mutating workflow", func(t *testing.T) {
		g := &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "src", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "iac", PluginId: "custom.iac-checker", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "src", TargetHandle: "default"},
				{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "iac", TargetHandle: "default"},
			},
		}
		created, err := wfCli.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{Name: "Disable Check", Graph: g})
		if err != nil {
			t.Fatalf("CreateWorkflow: %v", err)
		}
		wfID := created.GetWorkflow().GetId()

		s.setPluginEnabled("custom.iac-checker", false)

		valResp, err := wfCli.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{Graph: g})
		if err != nil {
			t.Fatalf("ValidateWorkflow: %v", err)
		}
		var sawDisabled bool
		for _, iss := range valResp.GetIssues() {
			if iss.GetCode() == engine.CodePluginDisabled && iss.GetNodeId() == "iac" {
				sawDisabled = true
			}
		}
		if !sawDisabled {
			t.Fatalf("expected PLUGIN_DISABLED on node iac, got %+v", valResp.GetIssues())
		}

		if _, err := runCli.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wfID}); err == nil || !strings.Contains(err.Error(), engine.CodePluginDisabled) || !strings.Contains(err.Error(), "iac") {
			t.Fatalf("StartRun with disabled plugin err = %v, want %s with nodeId iac", err, engine.CodePluginDisabled)
		}

		// Saved workflow nodes must remain untouched.
		gotWf, err := wfCli.GetWorkflow(ctx, &secflowv1.GetWorkflowRequest{WorkflowId: wfID})
		if err != nil || len(gotWf.GetWorkflow().GetGraph().GetNodes()) != 3 {
			t.Fatalf("saved workflow mutated after plugin disable: wf=%+v err=%v", gotWf, err)
		}

		// Remove plugin from registry -> PLUGIN_UNREGISTERED.
		s.plugMu.Lock()
		delete(s.plugins, "custom.iac-checker")
		s.plugMu.Unlock()

		valResp2, err := wfCli.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{Graph: g})
		if err != nil {
			t.Fatalf("ValidateWorkflow after removal: %v", err)
		}
		var sawUnreg bool
		for _, iss := range valResp2.GetIssues() {
			if iss.GetCode() == engine.CodePluginUnregistered && iss.GetNodeId() == "iac" {
				sawUnreg = true
			}
		}
		if !sawUnreg {
			t.Fatalf("expected PLUGIN_UNREGISTERED on node iac, got %+v", valResp2.GetIssues())
		}
		if _, err := runCli.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wfID}); err == nil || !strings.Contains(err.Error(), engine.CodePluginUnregistered) || !strings.Contains(err.Error(), "iac") {
			t.Fatalf("StartRun with unregistered plugin err = %v, want %s with nodeId iac", err, engine.CodePluginUnregistered)
		}
	})
}

func TestExternalLogicPerPortEnvelopes(t *testing.T) {
	t.Parallel()
	s := newServer()
	conn, cleanup := startTestGRPC(t, s)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s.startPump(ctx)

	splitterManifest := &secflowv1.PluginManifest{
		PluginId:       "logic.custom-split",
		Version:        "1.0.0",
		DisplayName:    "Custom Split",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC,
		Capabilities:   []string{"logic"},
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "HIGH_RISK", Label: "HIGH_RISK"}, {Id: "LOW_RISK", Label: "LOW_RISK"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:     true,
	}
	sinkManifest := &secflowv1.PluginManifest{
		PluginId:       "action.sink",
		Version:        "1.0.0",
		DisplayName:    "Test Sink",
		Category:       secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION,
		Capabilities:   []string{"notify"},
		InputPorts:     []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		OutputPorts:    []*secflowv1.PortDefinition{{Id: "default", Label: "default"}},
		SandboxProfile: secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL,
		IsExternal:     true,
	}

	connectTestWorker(t, ctx, conn, "split-1", []*secflowv1.PluginManifest{splitterManifest}, func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "logic.custom-split",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			ActiveOutputPorts: []string{"HIGH_RISK", "LOW_RISK"},
			EnvelopePatchJson: []byte(`{
				"portEnvelopes": {
					"HIGH_RISK": {"vars": {"bucket": "high"}},
					"LOW_RISK": {"vars": {"bucket": "low"}}
				}
			}`),
		}
	})

	var mu sync.Mutex
	seenVars := map[string]string{}
	connectTestWorker(t, ctx, conn, "sink-1", []*secflowv1.PluginManifest{sinkManifest}, func(task *secflowv1.NodeTask) *secflowv1.NodeResult {
		var env engine.Envelope
		if err := json.Unmarshal(task.GetEnvelopeJson(), &env); err != nil {
			t.Errorf("unmarshal sink envelope: %v", err)
		}
		mu.Lock()
		seenVars[task.GetNodeId()] = env.Vars["plugins.logic.custom-split.bucket"]
		mu.Unlock()
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          "action.sink",
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			ActiveOutputPorts: []string{"default"},
		}
	})

	wfCli := secflowv1.NewWorkflowServiceClient(conn)
	runCli := secflowv1.NewRunServiceClient(conn)

	g := &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes: []*secflowv1.WorkflowNode{
			{Id: "t", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
			{Id: "sp", PluginId: "logic.custom-split", ParamsJson: []byte(`{}`)},
			{Id: "hi", PluginId: "action.sink", ParamsJson: []byte(`{}`)},
			{Id: "lo", PluginId: "action.sink", ParamsJson: []byte(`{}`)},
		},
		Edges: []*secflowv1.WorkflowEdge{
			{Id: "e1", SourceNodeId: "t", SourceHandle: "default", TargetNodeId: "sp", TargetHandle: "default"},
			{Id: "e2", SourceNodeId: "sp", SourceHandle: "HIGH_RISK", TargetNodeId: "hi", TargetHandle: "default"},
			{Id: "e3", SourceNodeId: "sp", SourceHandle: "LOW_RISK", TargetNodeId: "lo", TargetHandle: "default"},
		},
	}

	created, err := wfCli.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{Name: "Per-Port Split", Graph: g})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	started, err := runCli.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: created.GetWorkflow().GetId()})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	waitForRunCompletion(t, ctx, runCli, started.GetRun().GetId())

	mu.Lock()
	defer mu.Unlock()
	if seenVars["hi"] != "high" || seenVars["lo"] != "low" {
		t.Fatalf("per-port envelope vars = %+v, want hi=high lo=low", seenVars)
	}
}
