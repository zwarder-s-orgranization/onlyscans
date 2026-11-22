package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/secflow/secflow/services/internal/envutil"
)

const (
	workerPoolLabelManagedBy  = "secflow.io/managed-by"
	workerPoolLabelName       = "secflow.io/worker-pool"
	workerPoolLabelEgressTier = "secflow.io/egress-tier"
	workerPoolManagedByOrch   = "orchestrator"
	egressTierInternalOnly    = "internal-only"
	egressTierEgressExternal  = "egress-external"
)

// WorkerPoolSpec describes a Kubernetes worker Deployment managed and scaled by orchestrator.
type WorkerPoolSpec struct {
	Name              string            `json:"name"`
	PluginIDs         []string          `json:"pluginIds"`
	Image             string            `json:"image"`
	ImagePullPolicy   string            `json:"imagePullPolicy,omitempty"`
	MinReplicas       int32             `json:"minReplicas"`
	MaxReplicas       int32             `json:"maxReplicas"`
	TasksPerWorker    int32             `json:"tasksPerWorker"`
	CooldownSeconds   int               `json:"cooldownSeconds,omitempty"`
	CPURequest        string            `json:"cpuRequest,omitempty"`
	CPULimit          string            `json:"cpuLimit,omitempty"`
	MemoryRequest     string            `json:"memoryRequest,omitempty"`
	MemoryLimit       string            `json:"memoryLimit,omitempty"`
	EmptyDirSizeLimit string            `json:"emptyDirSizeLimit,omitempty"`
	EgressTier        string            `json:"egressTier,omitempty"`
	NeedsGarage       bool              `json:"needsGarage,omitempty"`
	NeedsDatabase     bool              `json:"needsDatabase,omitempty"`
	NeedsRedis        bool              `json:"needsRedis,omitempty"`
	ExtraEnv          map[string]string `json:"extraEnv,omitempty"`
}

func (p WorkerPoolSpec) cooldown(fallback time.Duration) time.Duration {
	if p.CooldownSeconds > 0 {
		return time.Duration(p.CooldownSeconds) * time.Second
	}
	if fallback > 0 {
		return fallback
	}
	return 120 * time.Second
}

func (p WorkerPoolSpec) tasksPerWorker() int32 {
	if p.TasksPerWorker > 0 {
		return p.TasksPerWorker
	}
	return 1
}

// WorkerScaler provisions and scales worker pools on demand.
type WorkerScaler interface {
	Driver() string
	Handles(pluginID string) bool
	PoolForPlugin(pluginID string) (WorkerPoolSpec, bool)
	ProvisionTimeout() time.Duration
	ScaleWaitTimeout() time.Duration
	EnsureCapacity(ctx context.Context, pluginID string, demand int32) (int32, error)
	ReconcileOnce(ctx context.Context, demandByPlugin map[string]int32, onDrain func(pluginIDs []string, excess int32)) error
}

type noopWorkerScaler struct{}

func (noopWorkerScaler) Driver() string                                               { return "noop" }
func (noopWorkerScaler) Handles(string) bool                                          { return false }
func (noopWorkerScaler) PoolForPlugin(string) (WorkerPoolSpec, bool)                  { return WorkerPoolSpec{}, false }
func (noopWorkerScaler) ProvisionTimeout() time.Duration                              { return 0 }
func (noopWorkerScaler) ScaleWaitTimeout() time.Duration                              { return 0 }
func (noopWorkerScaler) EnsureCapacity(context.Context, string, int32) (int32, error) { return 0, nil }
func (noopWorkerScaler) ReconcileOnce(context.Context, map[string]int32, func([]string, int32)) error {
	return nil
}

// K8sWorkerScalerConfig configures the orchestrator's Kubernetes API worker scaler.
type K8sWorkerScalerConfig struct {
	Namespace            string
	OrchestratorAddr     string
	GarageEndpoint       string
	GarageSecretName     string
	WorkerAuthSecretName string
	DBSecretName         string
	RedisAddr            string
	OTelEndpoint         string
	ImageRegistry        string
	ImageTag             string
	ImagePullPolicy      string
	ImagePullSecrets     []string
	ProvisionTimeout     time.Duration
	ScaleWaitTimeout     time.Duration
	ReconcileInterval    time.Duration
	DefaultCooldown      time.Duration
	DefaultMaxReplicas   int32
	Pools                []WorkerPoolSpec
}

func (c K8sWorkerScalerConfig) withDefaults() K8sWorkerScalerConfig {
	if strings.TrimSpace(c.Namespace) == "" {
		c.Namespace = "secflow-workers"
	}
	if strings.TrimSpace(c.OrchestratorAddr) == "" {
		c.OrchestratorAddr = "orchestrator.secflow-app.svc.cluster.local:50051"
	}
	if strings.TrimSpace(c.GarageEndpoint) == "" {
		c.GarageEndpoint = "http://garage.secflow-system.svc.cluster.local:3900"
	}
	if strings.TrimSpace(c.GarageSecretName) == "" {
		c.GarageSecretName = "secflow-garage-creds"
	}
	if strings.TrimSpace(c.WorkerAuthSecretName) == "" {
		c.WorkerAuthSecretName = "secflow-worker-auth"
	}
	if strings.TrimSpace(c.DBSecretName) == "" {
		c.DBSecretName = "secflow-db"
	}
	if strings.TrimSpace(c.RedisAddr) == "" {
		c.RedisAddr = "redis.secflow-system.svc.cluster.local:6379"
	}
	if strings.TrimSpace(c.ImageRegistry) == "" {
		c.ImageRegistry = "ghcr.io/secflow"
	}
	if strings.TrimSpace(c.ImageTag) == "" {
		c.ImageTag = "latest"
	}
	if strings.TrimSpace(c.ImagePullPolicy) == "" {
		c.ImagePullPolicy = string(corev1.PullIfNotPresent)
	}
	if c.ProvisionTimeout <= 0 {
		c.ProvisionTimeout = 90 * time.Second
	}
	if c.ScaleWaitTimeout <= 0 {
		c.ScaleWaitTimeout = 15 * time.Second
	}
	if c.ReconcileInterval <= 0 {
		c.ReconcileInterval = 10 * time.Second
	}
	if c.DefaultCooldown <= 0 {
		c.DefaultCooldown = 120 * time.Second
	}
	if c.DefaultMaxReplicas <= 0 {
		c.DefaultMaxReplicas = 5
	}
	if len(c.Pools) == 0 {
		c.Pools = defaultWorkerPools(c.ImageRegistry, c.ImageTag, c.ImagePullPolicy, c.DefaultMaxReplicas, int(c.DefaultCooldown/time.Second))
	}
	return c
}

func workerImageRef(registry, name, tag string) string {
	reg := strings.TrimRight(strings.TrimSpace(registry), "/")
	if reg == "" {
		return name + ":" + tag
	}
	return reg + "/" + name + ":" + tag
}

func defaultWorkerPools(registry, tag, pullPolicy string, maxReplicas int32, cooldownSec int) []WorkerPoolSpec {
	if maxReplicas <= 0 {
		maxReplicas = 5
	}
	return []WorkerPoolSpec{
		{
			Name:              "worker-kotlin",
			PluginIDs:         []string{"scan.sast.kotlin", "scan.secrets"},
			Image:             workerImageRef(registry, "worker-kotlin", tag),
			ImagePullPolicy:   pullPolicy,
			MinReplicas:       0,
			MaxReplicas:       maxReplicas,
			TasksPerWorker:    1,
			CooldownSeconds:   cooldownSec,
			CPURequest:        "250m",
			CPULimit:          "1500m",
			MemoryRequest:     "512Mi",
			MemoryLimit:       "1536Mi",
			EmptyDirSizeLimit: "512Mi",
			EgressTier:        egressTierInternalOnly,
			NeedsGarage:       true,
		},
		{
			Name:              "worker-sca",
			PluginIDs:         []string{"scan.sca"},
			Image:             workerImageRef(registry, "worker-sca", tag),
			ImagePullPolicy:   pullPolicy,
			MinReplicas:       0,
			MaxReplicas:       maxReplicas,
			TasksPerWorker:    2,
			CooldownSeconds:   cooldownSec,
			CPURequest:        "100m",
			CPULimit:          "500m",
			MemoryRequest:     "128Mi",
			MemoryLimit:       "512Mi",
			EmptyDirSizeLimit: "256Mi",
			EgressTier:        egressTierInternalOnly,
			NeedsGarage:       true,
		},
		{
			Name:              "sbom-service",
			PluginIDs:         []string{"sbom.generate"},
			Image:             workerImageRef(registry, "sbom-service", tag),
			ImagePullPolicy:   pullPolicy,
			MinReplicas:       0,
			MaxReplicas:       maxReplicas,
			TasksPerWorker:    2,
			CooldownSeconds:   cooldownSec,
			CPURequest:        "100m",
			CPULimit:          "500m",
			MemoryRequest:     "128Mi",
			MemoryLimit:       "512Mi",
			EmptyDirSizeLimit: "256Mi",
			EgressTier:        egressTierInternalOnly,
			NeedsGarage:       true,
		},
		{
			Name:              "ai-service",
			PluginIDs:         []string{"ai.explain"},
			Image:             workerImageRef(registry, "ai-service", tag),
			ImagePullPolicy:   pullPolicy,
			MinReplicas:       1,
			MaxReplicas:       maxReplicas,
			TasksPerWorker:    2,
			CooldownSeconds:   cooldownSec,
			CPURequest:        "100m",
			CPULimit:          "500m",
			MemoryRequest:     "128Mi",
			MemoryLimit:       "512Mi",
			EmptyDirSizeLimit: "128Mi",
			EgressTier:        egressTierEgressExternal,
			NeedsGarage:       true,
			NeedsDatabase:     true,
			NeedsRedis:        true,
		},
		{
			Name:              "notify-service",
			PluginIDs:         []string{"notify.telegram", "notify.webhook", "notify.smtp"},
			Image:             workerImageRef(registry, "notify-service", tag),
			ImagePullPolicy:   pullPolicy,
			MinReplicas:       1,
			MaxReplicas:       maxReplicas,
			TasksPerWorker:    4,
			CooldownSeconds:   cooldownSec,
			CPURequest:        "50m",
			CPULimit:          "250m",
			MemoryRequest:     "64Mi",
			MemoryLimit:       "256Mi",
			EmptyDirSizeLimit: "64Mi",
			EgressTier:        egressTierEgressExternal,
		},
		{
			Name:              "mcp-bridge",
			PluginIDs:         []string{"mcp.tool"},
			Image:             workerImageRef(registry, "mcp-bridge", tag),
			ImagePullPolicy:   pullPolicy,
			MinReplicas:       1,
			MaxReplicas:       maxReplicas,
			TasksPerWorker:    4,
			CooldownSeconds:   cooldownSec,
			CPURequest:        "50m",
			CPULimit:          "250m",
			MemoryRequest:     "64Mi",
			MemoryLimit:       "256Mi",
			EmptyDirSizeLimit: "64Mi",
			EgressTier:        egressTierEgressExternal,
		},
	}
}

// K8sWorkerScaler creates and scales hardened worker Deployments in secflow-workers
// via the Kubernetes API based on live per-plugin task demand.
type K8sWorkerScaler struct {
	kube      kubernetes.Interface
	cfg       K8sWorkerScalerConfig
	now       func() time.Time
	mu        sync.Mutex
	pools     map[string]WorkerPoolSpec
	pluginMap map[string]string
	lastBusy  map[string]time.Time
}

// NewK8sWorkerScaler constructs a Kubernetes API worker scaler.
func NewK8sWorkerScaler(kube kubernetes.Interface, cfg K8sWorkerScalerConfig) *K8sWorkerScaler {
	cfg = cfg.withDefaults()
	pools := make(map[string]WorkerPoolSpec, len(cfg.Pools))
	pluginMap := make(map[string]string, len(cfg.Pools)*2)
	for _, p := range cfg.Pools {
		if strings.TrimSpace(p.Name) == "" {
			continue
		}
		if p.MaxReplicas < p.MinReplicas {
			p.MaxReplicas = p.MinReplicas
		}
		if p.MaxReplicas <= 0 {
			p.MaxReplicas = cfg.DefaultMaxReplicas
		}
		if strings.TrimSpace(p.ImagePullPolicy) == "" {
			p.ImagePullPolicy = cfg.ImagePullPolicy
		}
		pools[p.Name] = p
		for _, pid := range p.PluginIDs {
			if trimmed := strings.TrimSpace(pid); trimmed != "" {
				pluginMap[trimmed] = p.Name
			}
		}
	}
	return &K8sWorkerScaler{
		kube:      kube,
		cfg:       cfg,
		now:       time.Now,
		pools:     pools,
		pluginMap: pluginMap,
		lastBusy:  make(map[string]time.Time, len(pools)),
	}
}

func (k *K8sWorkerScaler) Driver() string { return "k8s" }

func (k *K8sWorkerScaler) ProvisionTimeout() time.Duration { return k.cfg.ProvisionTimeout }

func (k *K8sWorkerScaler) ScaleWaitTimeout() time.Duration { return k.cfg.ScaleWaitTimeout }

func (k *K8sWorkerScaler) Handles(pluginID string) bool {
	_, ok := k.pluginMap[pluginID]
	return ok
}

func (k *K8sWorkerScaler) PoolForPlugin(pluginID string) (WorkerPoolSpec, bool) {
	name, ok := k.pluginMap[pluginID]
	if !ok {
		return WorkerPoolSpec{}, false
	}
	pool, ok := k.pools[name]
	return pool, ok
}

// DesiredReplicas computes the clamped target replica count for a pool given total queued/active tasks.
func DesiredReplicas(pool WorkerPoolSpec, demand int32) int32 {
	var desired int32
	if demand > 0 {
		perWorker := pool.tasksPerWorker()
		desired = (demand + perWorker - 1) / perWorker
	}
	if desired < pool.MinReplicas {
		desired = pool.MinReplicas
	}
	if pool.MaxReplicas > 0 && desired > pool.MaxReplicas {
		desired = pool.MaxReplicas
	}
	return desired
}

// EnsureCapacity creates the worker Deployment if missing or scales it up immediately
// to satisfy demand. Scale-down is handled solely by ReconcileOnce after idle cooldown.
func (k *K8sWorkerScaler) EnsureCapacity(ctx context.Context, pluginID string, demand int32) (int32, error) {
	pool, ok := k.PoolForPlugin(pluginID)
	if !ok {
		return 0, nil
	}
	if demand < 1 {
		demand = 1
	}
	desired := DesiredReplicas(pool, demand)
	if desired < 1 {
		desired = 1
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	k.lastBusy[pool.Name] = k.now()
	return k.ensurePoolLocked(ctx, pool, desired, true)
}

// ReconcileOnce evaluates every managed worker pool against current demand,
// scaling up immediately on bursts and scaling down gracefully after idle cooldown.
func (k *K8sWorkerScaler) ReconcileOnce(ctx context.Context, demandByPlugin map[string]int32, onDrain func(pluginIDs []string, excess int32)) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.now()
	names := make([]string, 0, len(k.pools))
	for name := range k.pools {
		names = append(names, name)
	}
	sort.Strings(names)

	var firstErr error
	for _, name := range names {
		pool := k.pools[name]
		var poolDemand int32
		for _, pid := range pool.PluginIDs {
			poolDemand += demandByPlugin[pid]
		}
		if poolDemand > 0 {
			k.lastBusy[name] = now
		}
		desired := DesiredReplicas(pool, poolDemand)

		dep, err := k.kube.AppsV1().Deployments(k.cfg.Namespace).Get(ctx, pool.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if desired > 0 {
				if _, cErr := k.ensurePoolLocked(ctx, pool, desired, false); cErr != nil && firstErr == nil {
					firstErr = cErr
				}
			}
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("get worker deployment %s/%s: %w", k.cfg.Namespace, pool.Name, err)
			}
			continue
		}

		current := int32(0)
		if dep.Spec.Replicas != nil {
			current = *dep.Spec.Replicas
		}

		if desired > current {
			if _, sErr := k.scaleDeploymentLocked(ctx, pool.Name, dep, desired, "up"); sErr != nil && firstErr == nil {
				firstErr = sErr
			}
			continue
		}

		if desired < current {
			lastActive, seen := k.lastBusy[name]
			if !seen {
				// First observation of a running pool with zero demand starts the idle timer.
				k.lastBusy[name] = now
				continue
			}
			if now.Sub(lastActive) < pool.cooldown(k.cfg.DefaultCooldown) {
				continue
			}
			excess := current - desired
			if onDrain != nil && excess > 0 {
				onDrain(pool.PluginIDs, excess)
			}
			if _, sErr := k.scaleDeploymentLocked(ctx, pool.Name, dep, desired, "down"); sErr != nil && firstErr == nil {
				firstErr = sErr
			}
		}
	}
	return firstErr
}

func (k *K8sWorkerScaler) ensurePoolLocked(ctx context.Context, pool WorkerPoolSpec, desired int32, scaleUpOnly bool) (int32, error) {
	ns := k.cfg.Namespace
	dep, err := k.kube.AppsV1().Deployments(ns).Get(ctx, pool.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		specDep := k.buildDeployment(pool, desired)
		created, cErr := k.kube.AppsV1().Deployments(ns).Create(ctx, specDep, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(cErr) {
			dep, err = k.kube.AppsV1().Deployments(ns).Get(ctx, pool.Name, metav1.GetOptions{})
			if err != nil {
				return 0, fmt.Errorf("get worker deployment %s/%s after race: %w", ns, pool.Name, err)
			}
		} else if cErr != nil {
			return 0, fmt.Errorf("create worker deployment %s/%s: %w", ns, pool.Name, cErr)
		} else {
			recordWorkerPoolScale(pool.Name, "create", desired)
			slog.InfoContext(ctx, "created worker deployment on demand",
				"namespace", ns,
				"pool", pool.Name,
				"image", pool.Image,
				"replicas", desired,
			)
			if created.Spec.Replicas != nil {
				return *created.Spec.Replicas, nil
			}
			return desired, nil
		}
	} else if err != nil {
		return 0, fmt.Errorf("get worker deployment %s/%s: %w", ns, pool.Name, err)
	}

	if dep.Labels[workerPoolLabelManagedBy] == workerPoolManagedByOrch {
		if synced, err := k.syncManagedDeploymentSpecLocked(ctx, pool, dep); err != nil {
			slog.WarnContext(ctx, "sync worker deployment template", "namespace", ns, "pool", pool.Name, "err", err)
		} else if synced != nil {
			dep = synced
		}
	}

	current := int32(0)
	if dep.Spec.Replicas != nil {
		current = *dep.Spec.Replicas
	}
	if scaleUpOnly && desired <= current {
		return current, nil
	}
	if desired == current {
		return current, nil
	}
	direction := "up"
	if desired < current {
		direction = "down"
	}
	return k.scaleDeploymentLocked(ctx, pool.Name, dep, desired, direction)
}

func (k *K8sWorkerScaler) syncManagedDeploymentSpecLocked(ctx context.Context, pool WorkerPoolSpec, dep *appsv1.Deployment) (*appsv1.Deployment, error) {
	if dep == nil || len(dep.Spec.Template.Spec.Containers) == 0 {
		return dep, nil
	}
	desiredDep := k.buildDeployment(pool, 0)
	wantC := desiredDep.Spec.Template.Spec.Containers[0]
	wantSecrets := desiredDep.Spec.Template.Spec.ImagePullSecrets

	curC := dep.Spec.Template.Spec.Containers[0]
	changed := curC.Image != wantC.Image ||
		curC.ImagePullPolicy != wantC.ImagePullPolicy ||
		!equalLocalObjectRefs(dep.Spec.Template.Spec.ImagePullSecrets, wantSecrets)
	if !changed {
		return dep, nil
	}
	cp := dep.DeepCopy()
	cp.Spec.Template.Spec.Containers[0].Image = wantC.Image
	cp.Spec.Template.Spec.Containers[0].ImagePullPolicy = wantC.ImagePullPolicy
	cp.Spec.Template.Spec.ImagePullSecrets = wantSecrets
	updated, err := k.kube.AppsV1().Deployments(k.cfg.Namespace).Update(ctx, cp, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func equalLocalObjectRefs(a, b []corev1.LocalObjectReference) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return false
		}
	}
	return true
}

func (k *K8sWorkerScaler) scaleDeploymentLocked(ctx context.Context, poolName string, dep *appsv1.Deployment, desired int32, direction string) (int32, error) {
	ns := k.cfg.Namespace
	patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, desired))
	if _, err := k.kube.AppsV1().Deployments(ns).Patch(ctx, poolName, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		cp := dep.DeepCopy()
		cp.Spec.Replicas = &desired
		if _, uErr := k.kube.AppsV1().Deployments(ns).Update(ctx, cp, metav1.UpdateOptions{}); uErr != nil {
			return 0, fmt.Errorf("scale worker deployment %s/%s to %d: %w", ns, poolName, desired, uErr)
		}
	}
	recordWorkerPoolScale(poolName, direction, desired)
	slog.InfoContext(ctx, "scaled worker deployment",
		"namespace", ns,
		"pool", poolName,
		"direction", direction,
		"replicas", desired,
	)
	return desired, nil
}

func (k *K8sWorkerScaler) buildDeployment(pool WorkerPoolSpec, replicas int32) *appsv1.Deployment {
	tier := strings.TrimSpace(pool.EgressTier)
	if tier == "" {
		tier = egressTierInternalOnly
	}
	labels := map[string]string{
		"app":                       pool.Name,
		"app.kubernetes.io/name":    pool.Name,
		"app.kubernetes.io/part-of": "secflow",
		workerPoolLabelManagedBy:    workerPoolManagedByOrch,
		workerPoolLabelName:         pool.Name,
		workerPoolLabelEgressTier:   tier,
	}

	runAsNonRoot := true
	readOnlyRoot := true
	allowPrivEsc := false
	automountSA := false
	nonRootUID := int64(65532)
	graceSec := int64(60)
	emptyDirLimit := parseQuantityOrDefault(pool.EmptyDirSizeLimit, "256Mi")

	envVars := []corev1.EnvVar{
		{Name: "ORCHESTRATOR_ADDR", Value: k.cfg.OrchestratorAddr},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{
			Name: "WORKER_INSTANCE_ID",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		},
		{
			Name: "SERVICE_TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: k.cfg.WorkerAuthSecretName},
					Key:                  "SERVICE_TOKEN",
					Optional:             boolPtr(true),
				},
			},
		},
	}
	if k.cfg.OTelEndpoint != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: k.cfg.OTelEndpoint})
	}
	if pool.NeedsGarage {
		envVars = append(envVars,
			corev1.EnvVar{Name: "GARAGE_ENDPOINT", Value: k.cfg.GarageEndpoint},
			corev1.EnvVar{
				Name: "GARAGE_ACCESS_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: k.cfg.GarageSecretName},
						Key:                  "GARAGE_ACCESS_KEY",
						Optional:             boolPtr(true),
					},
				},
			},
			corev1.EnvVar{
				Name: "GARAGE_SECRET_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: k.cfg.GarageSecretName},
						Key:                  "GARAGE_SECRET_KEY",
						Optional:             boolPtr(true),
					},
				},
			},
		)
	}
	if pool.NeedsDatabase {
		envVars = append(envVars, corev1.EnvVar{
			Name: "DATABASE_URL",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: k.cfg.DBSecretName},
					Key:                  "DATABASE_URL",
					Optional:             boolPtr(true),
				},
			},
		})
	}
	if pool.NeedsRedis && k.cfg.RedisAddr != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "REDIS_ADDR", Value: k.cfg.RedisAddr})
	}
	if len(pool.ExtraEnv) > 0 {
		keys := make([]string, 0, len(pool.ExtraEnv))
		for ek := range pool.ExtraEnv {
			keys = append(keys, ek)
		}
		sort.Strings(keys)
		for _, ek := range keys {
			envVars = append(envVars, corev1.EnvVar{Name: ek, Value: pool.ExtraEnv[ek]})
		}
	}

	pullPolicy := corev1.PullPolicy(pool.ImagePullPolicy)
	if pullPolicy == "" {
		pullPolicy = corev1.PullIfNotPresent
	}

	var imagePullSecrets []corev1.LocalObjectReference
	for _, secretName := range k.cfg.ImagePullSecrets {
		if trimmed := strings.TrimSpace(secretName); trimmed != "" {
			imagePullSecrets = append(imagePullSecrets, corev1.LocalObjectReference{Name: trimmed})
		}
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pool.Name,
			Namespace: k.cfg.Namespace,
			Labels:    maps.Clone(labels),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": pool.Name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: maps.Clone(labels),
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken:  &automountSA,
					TerminationGracePeriodSeconds: &graceSec,
					ImagePullSecrets:              imagePullSecrets,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
						RunAsUser:    &nonRootUID,
						RunAsGroup:   &nonRootUID,
						FSGroup:      &nonRootUID,
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{
						{
							Name:            pool.Name,
							Image:           pool.Image,
							ImagePullPolicy: pullPolicy,
							Env:             envVars,
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot:             &runAsNonRoot,
								ReadOnlyRootFilesystem:   &readOnlyRoot,
								AllowPrivilegeEscalation: &allowPrivEsc,
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    parseQuantityOrDefault(pool.CPURequest, "100m"),
									corev1.ResourceMemory: parseQuantityOrDefault(pool.MemoryRequest, "128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    parseQuantityOrDefault(pool.CPULimit, "500m"),
									corev1.ResourceMemory: parseQuantityOrDefault(pool.MemoryLimit, "512Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "tmp", MountPath: "/tmp"},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "tmp",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									SizeLimit: &emptyDirLimit,
								},
							},
						},
					},
				},
			},
		},
	}
}

func parseQuantityOrDefault(raw, fallback string) resource.Quantity {
	if q, err := resource.ParseQuantity(strings.TrimSpace(raw)); err == nil && !q.IsZero() {
		return q
	}
	return resource.MustParse(fallback)
}

func boolPtr(v bool) *bool { return &v }

// buildWorkerScaler initializes the configured WorkerScaler (noop by default, k8s when WORKER_SCALER_DRIVER=k8s).
func buildWorkerScaler() (WorkerScaler, time.Duration, error) {
	driver := strings.ToLower(strings.TrimSpace(envutil.Get("WORKER_SCALER_DRIVER", "noop")))
	switch driver {
	case "", "noop", "disabled":
		return noopWorkerScaler{}, 0, nil
	case "k8s", "kubernetes":
		var (
			rcfg *rest.Config
			err  error
		)
		if kubeconfig := strings.TrimSpace(os.Getenv("KUBECONFIG")); kubeconfig != "" {
			rcfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		} else {
			rcfg, err = rest.InClusterConfig()
		}
		if err != nil {
			return nil, 0, fmt.Errorf("load kubernetes config for worker scaler: %w", err)
		}
		kube, err := kubernetes.NewForConfig(rcfg)
		if err != nil {
			return nil, 0, fmt.Errorf("create kubernetes client for worker scaler: %w", err)
		}
		cfg := K8sWorkerScalerConfig{
			Namespace:            envutil.Get("WORKERS_NAMESPACE", "secflow-workers"),
			OrchestratorAddr:     envutil.Get("ORCHESTRATOR_INTERNAL_ADDR", "orchestrator.secflow-app.svc.cluster.local:50051"),
			GarageEndpoint:       envutil.Get("GARAGE_ENDPOINT", "http://garage.secflow-system.svc.cluster.local:3900"),
			GarageSecretName:     envutil.Get("WORKER_GARAGE_SECRET_NAME", "secflow-garage-creds"),
			WorkerAuthSecretName: envutil.Get("WORKER_AUTH_SECRET_NAME", "secflow-worker-auth"),
			DBSecretName:         envutil.Get("WORKER_DB_SECRET_NAME", "secflow-db"),
			RedisAddr:            envutil.Get("WORKER_REDIS_ADDR", "redis.secflow-system.svc.cluster.local:6379"),
			OTelEndpoint:         strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
			ImageRegistry:        envutil.Get("WORKER_IMAGE_REGISTRY", "ghcr.io/secflow"),
			ImageTag:             envutil.Get("WORKER_IMAGE_TAG", "latest"),
			ImagePullPolicy:      envutil.Get("WORKER_IMAGE_PULL_POLICY", string(corev1.PullIfNotPresent)),
			ImagePullSecrets:     parseCSVList(os.Getenv("WORKER_IMAGE_PULL_SECRETS")),
			ProvisionTimeout:     time.Duration(envPositiveInt("WORKER_PROVISION_TIMEOUT_SECONDS", 90)) * time.Second,
			ScaleWaitTimeout:     time.Duration(envPositiveInt("WORKER_SCALE_WAIT_TIMEOUT_SECONDS", 15)) * time.Second,
			ReconcileInterval:    time.Duration(envPositiveInt("WORKER_RECONCILE_INTERVAL_SECONDS", 10)) * time.Second,
			DefaultCooldown:      time.Duration(envPositiveInt("WORKER_IDLE_TTL_SECONDS", 120)) * time.Second,
			DefaultMaxReplicas:   int32(envPositiveInt("WORKER_MAX_REPLICAS", 5)),
		}
		if configPath := strings.TrimSpace(os.Getenv("WORKER_POOLS_CONFIG")); configPath != "" {
			raw, rErr := os.ReadFile(configPath)
			if rErr != nil {
				return nil, 0, fmt.Errorf("read WORKER_POOLS_CONFIG %q: %w", configPath, rErr)
			}
			var pools []WorkerPoolSpec
			if uErr := json.Unmarshal(raw, &pools); uErr != nil {
				return nil, 0, fmt.Errorf("parse WORKER_POOLS_CONFIG %q: %w", configPath, uErr)
			}
			cfg.Pools = pools
		}
		scaler := NewK8sWorkerScaler(kube, cfg)
		return scaler, scaler.cfg.ReconcileInterval, nil
	default:
		return nil, 0, fmt.Errorf("unsupported WORKER_SCALER_DRIVER %q", driver)
	}
}

func envPositiveInt(key string, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func parseCSVList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// startWorkerScaler runs the periodic worker autoscaler reconciliation loop.
// When PostgreSQL is configured, a transaction-scoped advisory lock ensures only one
// orchestrator replica performs scale-down reconciliation per tick.
func (s *Server) startWorkerScaler(ctx context.Context, interval time.Duration) {
	if s.workerScaler == nil || s.workerScaler.Driver() == "noop" {
		return
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reconcileWorkerPools(ctx)
			}
		}
	}()
}

func (s *Server) reconcileWorkerPools(ctx context.Context) {
	if s.workerScaler == nil || s.workerScaler.Driver() == "noop" {
		return
	}
	if s.pool != nil {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			slog.WarnContext(ctx, "begin worker scaler lock tx", "err", err)
			return
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		var acquired bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(7326099)`).Scan(&acquired); err != nil {
			slog.WarnContext(ctx, "acquire worker scaler advisory lock", "err", err)
			return
		}
		if !acquired {
			return
		}
	}
	demand := s.pluginDemandSnapshot(ctx)
	if err := s.workerScaler.ReconcileOnce(ctx, demand, s.drainIdleWorkersForPlugins); err != nil {
		slog.WarnContext(ctx, "reconcile worker pools", "err", err)
	}
}

func (s *Server) pluginDemandSnapshot(ctx context.Context) map[string]int32 {
	out := map[string]int32{}
	if s.pool != nil {
		dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		rows, err := s.pool.Query(dbCtx, `SELECT plugin_id, COUNT(*) FROM node_tasks WHERE status IN ('QUEUED', 'RUNNING') GROUP BY plugin_id`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var pid string
				var cnt int64
				if rows.Scan(&pid, &cnt) == nil && cnt > 0 {
					out[pid] = int32(cnt)
				}
			}
			if rows.Err() == nil {
				return out
			}
		}
	}
	s.runMu.Lock()
	for _, pid := range s.trackedQueue {
		if pid != "" {
			out[pid]++
		}
	}
	for _, at := range s.activeTasks {
		if at.pluginID != "" {
			if _, tracked := s.trackedQueue[at.runID+":"+at.nodeID]; !tracked {
				out[at.pluginID]++
			}
		}
	}
	s.runMu.Unlock()
	return out
}

func (s *Server) poolDemandForPlugin(ctx context.Context, pluginID string) int32 {
	demandMap := s.pluginDemandSnapshot(ctx)
	if s.workerScaler == nil {
		return max(demandMap[pluginID], 1)
	}
	pool, ok := s.workerScaler.PoolForPlugin(pluginID)
	if !ok {
		return max(demandMap[pluginID], 1)
	}
	var total int32
	for _, pid := range pool.PluginIDs {
		total += demandMap[pid]
	}
	if total < 1 {
		total = 1
	}
	return total
}

// drainIdleWorkersForPlugins sends graceful DrainRequest to up to excess non-draining
// worker streams serving pluginIDs, prioritizing workers with zero in-flight tasks.
func (s *Server) drainIdleWorkersForPlugins(pluginIDs []string, excess int32) {
	if excess <= 0 || len(pluginIDs) == 0 {
		return
	}
	s.plugMu.Lock()
	seen := map[*workerLink]bool{}
	var candidates []*workerLink
	for _, pid := range pluginIDs {
		for _, w := range s.workers[pid] {
			if w == nil || w.draining.Load() || seen[w] {
				continue
			}
			seen[w] = true
			candidates = append(candidates, w)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].inFlight.Load() < candidates[j].inFlight.Load()
	})
	var toDrain []*workerLink
	for _, w := range candidates {
		if int32(len(toDrain)) >= excess {
			break
		}
		// Only mark workers draining if they have no active tasks or we still have others.
		if w.inFlight.Load() == 0 {
			w.draining.Store(true)
			toDrain = append(toDrain, w)
		}
	}
	s.plugMu.Unlock()

	if len(toDrain) > 0 {
		s.drainWorkerLinks(toDrain, "scaled down after idle cooldown", 30)
	}
}
