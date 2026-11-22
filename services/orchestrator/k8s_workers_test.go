package main

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/workerclient"
)

func TestDesiredReplicas(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		pool   WorkerPoolSpec
		demand int32
		want   int32
	}{
		{
			name:   "scale to zero when idle and min 0",
			pool:   WorkerPoolSpec{MinReplicas: 0, MaxReplicas: 5, TasksPerWorker: 1},
			demand: 0,
			want:   0,
		},
		{
			name:   "respect min replicas when idle",
			pool:   WorkerPoolSpec{MinReplicas: 1, MaxReplicas: 5, TasksPerWorker: 2},
			demand: 0,
			want:   1,
		},
		{
			name:   "one task per worker splits 3 tasks to 3 replicas",
			pool:   WorkerPoolSpec{MinReplicas: 0, MaxReplicas: 5, TasksPerWorker: 1},
			demand: 3,
			want:   3,
		},
		{
			name:   "two tasks per worker rounds up 5 tasks to 3 replicas",
			pool:   WorkerPoolSpec{MinReplicas: 0, MaxReplicas: 5, TasksPerWorker: 2},
			demand: 5,
			want:   3,
		},
		{
			name:   "clamp at max replicas",
			pool:   WorkerPoolSpec{MinReplicas: 0, MaxReplicas: 4, TasksPerWorker: 1},
			demand: 12,
			want:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := DesiredReplicas(tt.pool, tt.demand); got != tt.want {
				t.Fatalf("DesiredReplicas(%+v, %d) = %d, want %d", tt.pool, tt.demand, got, tt.want)
			}
		})
	}
}

func TestK8sWorkerScaler_CreateOnDemandScaleUpAndCooldownDown(t *testing.T) {
	t.Parallel()
	kube := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	scaler := NewK8sWorkerScaler(kube, K8sWorkerScalerConfig{
		Namespace:          "secflow-workers",
		OrchestratorAddr:   "orchestrator.secflow-app.svc.cluster.local:50051",
		ImageRegistry:      "secflow",
		ImageTag:           "local",
		DefaultCooldown:    60 * time.Second,
		DefaultMaxReplicas: 4,
	})
	scaler.now = func() time.Time { return now }

	// 1. First task creates hardened Deployment on demand.
	desired, err := scaler.EnsureCapacity(t.Context(), "scan.sast.kotlin", 1)
	if err != nil {
		t.Fatalf("EnsureCapacity create: %v", err)
	}
	if desired != 1 {
		t.Fatalf("desired = %d, want 1", desired)
	}

	dep, err := kube.AppsV1().Deployments("secflow-workers").Get(t.Context(), "worker-kotlin", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get created worker-kotlin deployment: %v", err)
	}
	assertHardenedWorkerDeployment(t, dep, "secflow/worker-kotlin:local", egressTierInternalOnly, 1)

	// 2. Burst of 3 tasks across scan.sast.kotlin + scan.secrets scales up to 3.
	desired, err = scaler.EnsureCapacity(t.Context(), "scan.secrets", 3)
	if err != nil {
		t.Fatalf("EnsureCapacity scale up: %v", err)
	}
	if desired != 3 {
		t.Fatalf("desired = %d, want 3", desired)
	}
	dep, err = kube.AppsV1().Deployments("secflow-workers").Get(t.Context(), "worker-kotlin", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scaled deployment: %v", err)
	}
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 3 {
		t.Fatalf("replicas = %v, want 3", dep.Spec.Replicas)
	}

	// 3. Before cooldown elapses, ReconcileOnce with 0 demand keeps 3 replicas.
	now = now.Add(30 * time.Second)
	var drainCalls int
	if err := scaler.ReconcileOnce(t.Context(), map[string]int32{}, func(_ []string, _ int32) {
		drainCalls++
	}); err != nil {
		t.Fatalf("ReconcileOnce before cooldown: %v", err)
	}
	dep, _ = kube.AppsV1().Deployments("secflow-workers").Get(t.Context(), "worker-kotlin", metav1.GetOptions{})
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 3 {
		t.Fatalf("scaled down too early: replicas = %v", dep.Spec.Replicas)
	}
	if drainCalls != 0 {
		t.Fatalf("expected 0 drain calls before cooldown, got %d", drainCalls)
	}

	// 4. After cooldown elapses, ReconcileOnce drains and scales down to 0.
	now = now.Add(45 * time.Second)
	var drainedExcess int32
	if err := scaler.ReconcileOnce(t.Context(), map[string]int32{}, func(_ []string, excess int32) {
		drainCalls++
		drainedExcess = excess
	}); err != nil {
		t.Fatalf("ReconcileOnce after cooldown: %v", err)
	}
	dep, _ = kube.AppsV1().Deployments("secflow-workers").Get(t.Context(), "worker-kotlin", metav1.GetOptions{})
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 {
		t.Fatalf("expected scale to 0 after cooldown, got %v", dep.Spec.Replicas)
	}
	if drainCalls != 1 || drainedExcess != 3 {
		t.Fatalf("expected 1 drain call for excess 3, got calls=%d excess=%d", drainCalls, drainedExcess)
	}
}

func assertHardenedWorkerDeployment(t *testing.T, dep *appsv1.Deployment, wantImage, wantTier string, wantReplicas int32) {
	t.Helper()
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != wantReplicas {
		t.Fatalf("replicas = %v, want %d", dep.Spec.Replicas, wantReplicas)
	}
	if dep.Labels[workerPoolLabelEgressTier] != wantTier {
		t.Fatalf("egress tier label = %q, want %q", dep.Labels[workerPoolLabelEgressTier], wantTier)
	}
	podSpec := dep.Spec.Template.Spec
	if podSpec.AutomountServiceAccountToken == nil || *podSpec.AutomountServiceAccountToken {
		t.Fatal("expected automountServiceAccountToken=false on worker pod")
	}
	if len(podSpec.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(podSpec.Containers))
	}
	c := podSpec.Containers[0]
	if c.Image != wantImage {
		t.Fatalf("image = %q, want %q", c.Image, wantImage)
	}
	if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatal("expected readOnlyRootFilesystem=true")
	}
	if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Fatal("expected allowPrivilegeEscalation=false")
	}
	hasInstanceID := false
	for _, ev := range c.Env {
		if ev.Name == "WORKER_INSTANCE_ID" && ev.ValueFrom != nil && ev.ValueFrom.FieldRef != nil && ev.ValueFrom.FieldRef.FieldPath == "metadata.name" {
			hasInstanceID = true
		}
	}
	if !hasInstanceID {
		t.Fatal("expected WORKER_INSTANCE_ID sourced from Downward API metadata.name")
	}
}

func TestOrchestrator_DynamicWorkerCreationAndParallelTaskSplitting(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	kube := fake.NewSimpleClientset()
	scaler := NewK8sWorkerScaler(kube, K8sWorkerScalerConfig{
		Namespace:        "secflow-workers",
		ProvisionTimeout: 5 * time.Second,
		ScaleWaitTimeout: 2 * time.Second,
		Pools: []WorkerPoolSpec{
			{
				Name:           "worker-sca",
				PluginIDs:      []string{"scan.sca"},
				Image:          "secflow/worker-sca:local",
				MinReplicas:    0,
				MaxReplicas:    4,
				TasksPerWorker: 1,
				EgressTier:     egressTierInternalOnly,
				NeedsGarage:    true,
			},
		},
	})

	srv := newServer()
	srv.workerScaler = scaler
	srv.startPump(ctx)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	secflowv1.RegisterWorkerServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.GracefulStop()
		_ = lis.Close()
	})

	// Track which worker handled each task and peak concurrency.
	var (
		mu          sync.Mutex
		handledBy   = map[string]int{}
		activeNow   atomic.Int32
		maxParallel atomic.Int32
		bothStarted = make(chan struct{})
		startedCnt  atomic.Int32
	)

	spawnWorker := func(workerID string) {
		go func() {
			m := manifest.One("scan.sca", "SCA", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"analyzer"}, false)
			m.MaxConcurrency = 1
			_ = workerclient.RunWithConfig(ctx, workerclient.Config{
				Addr:      lis.Addr().String(),
				WorkerID:  workerID,
				Namespace: "secflow-workers",
				Manifests: []*secflowv1.PluginManifest{m},
				Handle: func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
					cur := activeNow.Add(1)
					for {
						prev := maxParallel.Load()
						if cur <= prev || maxParallel.CompareAndSwap(prev, cur) {
							break
						}
					}
					if startedCnt.Add(1) == 2 {
						close(bothStarted)
					}
					select {
					case <-bothStarted:
					case <-time.After(1500 * time.Millisecond):
					case <-taskCtx.Done():
					}
					activeNow.Add(-1)

					mu.Lock()
					handledBy[workerID]++
					mu.Unlock()
					return &secflowv1.NodeResult{
						NodeRunId:         task.GetNodeRunId(),
						RunId:             task.GetRunId(),
						NodeId:            task.GetNodeId(),
						PluginId:          "scan.sca",
						Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
						ActiveOutputPorts: []string{"default"},
					}
				},
			})
		}()
	}

	// Simulate Kubernetes Deployment controller watching secflow-workers and starting pods as replicas increase.
	go func() {
		spawned := 0
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				dep, err := kube.AppsV1().Deployments("secflow-workers").Get(ctx, "worker-sca", metav1.GetOptions{})
				if err != nil || dep.Spec.Replicas == nil {
					continue
				}
				target := int(*dep.Spec.Replicas)
				for spawned < target {
					spawned++
					spawnWorker("worker-sca-pod-" + string(rune('0'+spawned)))
				}
			}
		}
	}()

	// Workflow with two parallel scan.sca nodes after source.upload (zero workers connected initially!).
	wf := &secflowv1.Workflow{
		Id:   "wf-parallel-sca",
		Name: "Parallel SCA Split",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "trig", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
				{Id: "src", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
				{Id: "sca1", PluginId: "scan.sca", ParamsJson: []byte(`{}`)},
				{Id: "sca2", PluginId: "scan.sca", ParamsJson: []byte(`{}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "trig", SourceHandle: "default", TargetNodeId: "src"},
				{Id: "e2", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "sca1"},
				{Id: "e3", SourceNodeId: "src", SourceHandle: "default", TargetNodeId: "sca2"},
			},
		},
	}
	srv.wfMu.Lock()
	srv.workflows[wf.Id] = wf
	srv.wfMu.Unlock()

	startResp, err := srv.StartRun(ctx, &secflowv1.StartRunRequest{WorkflowId: wf.Id})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := startResp.GetRun().GetId()

	// Wait for run completion.
	deadline := time.After(8 * time.Second)
	for {
		getResp, gErr := srv.GetRun(ctx, &secflowv1.GetRunRequest{RunId: runID})
		if gErr != nil {
			t.Fatalf("GetRun: %v", gErr)
		}
		st := getResp.GetRun().GetStatus()
		if st == secflowv1.RunStatus_RUN_STATUS_SUCCEEDED {
			break
		}
		if st == secflowv1.RunStatus_RUN_STATUS_FAILED {
			t.Fatalf("run failed: %s", getResp.GetRun().GetErrorMessage())
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for run %s (last status %s)", runID, st)
		case <-time.After(30 * time.Millisecond):
		}
	}

	dep, err := kube.AppsV1().Deployments("secflow-workers").Get(ctx, "worker-sca", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected worker-sca Deployment to be created: %v", err)
	}
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas < 2 {
		t.Fatalf("expected worker-sca scaled to >=2 replicas for parallel tasks, got %v", dep.Spec.Replicas)
	}
	if maxParallel.Load() < 2 {
		t.Fatalf("expected 2 tasks executing in parallel, peak concurrency = %d", maxParallel.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(handledBy) < 2 {
		t.Fatalf("expected tasks split across 2 distinct worker pods, got distribution %+v", handledBy)
	}
}
