package main

import (
	"context"
	"fmt"
	"maps"
	"net"
	"regexp"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var kedaScaledObjectGVR = schema.GroupVersionResource{
	Group:    "keda.sh",
	Version:  "v1alpha1",
	Resource: "scaledobjects",
}

var k8sNameSanitizer = regexp.MustCompile(`[^a-z0-9-]+`)

// K8sConfig configures the secflow-sandbox Kubernetes RuntimeProvisioner.
type K8sConfig struct {
	Namespace               string
	OrchestratorAddr        string
	OrchestratorNamespace   string
	OrchestratorPort        int32
	GarageEndpoint          string
	GarageNamespace         string
	GaragePort              int32
	GarageReadOnlyAccessKey string
	GarageReadOnlySecretKey string
	ImageRegistryAllowlist  []string
	Production              bool
	EnableKEDA              bool
	PrometheusAddress       string
	ResourceCeiling         ResourceCeiling
	EmptyDirSizeLimit       string
}

func (c K8sConfig) withDefaults() K8sConfig {
	if strings.TrimSpace(c.Namespace) == "" {
		c.Namespace = "secflow-sandbox"
	}
	if strings.TrimSpace(c.OrchestratorAddr) == "" {
		c.OrchestratorAddr = "orchestrator.secflow-core.svc.cluster.local:50051"
	}
	if strings.TrimSpace(c.OrchestratorNamespace) == "" {
		c.OrchestratorNamespace = "secflow-core"
	}
	if c.OrchestratorPort <= 0 {
		c.OrchestratorPort = 50051
	}
	if strings.TrimSpace(c.GarageEndpoint) == "" {
		c.GarageEndpoint = "http://garage.secflow-core.svc.cluster.local:3900"
	}
	if strings.TrimSpace(c.GarageNamespace) == "" {
		c.GarageNamespace = "secflow-core"
	}
	if c.GaragePort <= 0 {
		c.GaragePort = 3900
	}
	if strings.TrimSpace(c.PrometheusAddress) == "" {
		c.PrometheusAddress = "http://prometheus.secflow-observability.svc.cluster.local:9090"
	}
	if c.ResourceCeiling.MaxCPU.IsZero() {
		c.ResourceCeiling = DefaultResourceCeiling()
	}
	if strings.TrimSpace(c.EmptyDirSizeLimit) == "" {
		c.EmptyDirSizeLimit = "128Mi"
	}
	return c
}

// K8sProvisioner reconciles Deployment, Secret, NetworkPolicy, and optional KEDA ScaledObject
// strictly inside the configured secflow-sandbox namespace.
type K8sProvisioner struct {
	kube    kubernetes.Interface
	dyn     dynamic.Interface
	cfg     K8sConfig
	resolve func(ctx context.Context, host string) ([]string, error)
}

// NewK8sProvisioner creates a hardened Kubernetes sandbox provisioner.
func NewK8sProvisioner(kube kubernetes.Interface, dyn dynamic.Interface, cfg K8sConfig) *K8sProvisioner {
	return &K8sProvisioner{
		kube:    kube,
		dyn:     dyn,
		cfg:     cfg.withDefaults(),
		resolve: net.DefaultResolver.LookupHost,
	}
}

func (p *K8sProvisioner) Driver() string { return "k8s" }

func resourceBaseName(installationID string) string {
	clean := strings.ToLower(strings.TrimSpace(installationID))
	clean = k8sNameSanitizer.ReplaceAllString(clean, "-")
	clean = strings.Trim(clean, "-")
	if clean == "" {
		clean = "plugin"
	}
	name := "plg-" + clean
	if len(name) > 52 {
		name = strings.TrimRight(name[:52], "-")
	}
	return name
}

func installationLabels(spec InstallationSpec) map[string]string {
	profileLabel := "internal-only"
	if spec.SandboxProfile == ProfileEgressExternal {
		profileLabel = "egress-external"
	}
	return map[string]string{
		LabelInstallationID: spec.ID,
		LabelManagedBy:      ManagedByValue,
		LabelSandboxProfile: profileLabel,
	}
}

// Reconcile converges Kubernetes resources in secflow-sandbox to match spec and returns pod diagnostics.
func (p *K8sProvisioner) Reconcile(ctx context.Context, spec InstallationSpec) (Diagnostics, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(spec.ID) == "" {
		return Diagnostics{Phase: "Error", LastError: "installation id is required", UpdatedAt: now}, fmt.Errorf("installation id is required")
	}
	if spec.Status == StatusDeleting {
		if err := p.Delete(ctx, spec.ID); err != nil {
			return Diagnostics{Phase: "Deleting", LastError: err.Error(), UpdatedAt: now}, err
		}
		return Diagnostics{Phase: "Deleted", Message: "Sandbox resources removed", UpdatedAt: now}, nil
	}
	if spec.SourceMode == SourceModeExternalPull {
		return Diagnostics{
			Phase:           "ExternalPull",
			DesiredReplicas: spec.DesiredReplicas,
			Message:         "Managed externally via Pull gRPC connection",
			UpdatedAt:       now,
		}, nil
	}
	if spec.SourceMode == SourceModeDeclarative {
		return declarativeDiagnostics(spec, now), nil
	}

	if err := ValidateImageRef(spec.ImageRef, p.cfg.ImageRegistryAllowlist, p.cfg.Production); err != nil {
		return Diagnostics{Phase: "Error", LastError: err.Error(), Message: "Image policy rejected", UpdatedAt: now}, err
	}
	egressTargets, err := ValidateEgressAllowlist(spec.SandboxProfile, spec.EgressAllowlist)
	if err != nil {
		return Diagnostics{Phase: "Error", LastError: err.Error(), Message: "Egress policy rejected", UpdatedAt: now}, err
	}

	base := resourceBaseName(spec.ID)
	labels := installationLabels(spec)

	if err := p.reconcileSecret(ctx, base, labels, spec); err != nil {
		return Diagnostics{Phase: "Error", LastError: err.Error(), UpdatedAt: now}, err
	}
	if err := p.reconcileNetworkPolicy(ctx, base, labels, spec, egressTargets); err != nil {
		return Diagnostics{Phase: "Error", LastError: err.Error(), UpdatedAt: now}, err
	}
	dep, err := p.reconcileDeployment(ctx, base, labels, spec)
	if err != nil {
		return Diagnostics{Phase: "Error", LastError: err.Error(), UpdatedAt: now}, err
	}
	if err := p.reconcileScaledObject(ctx, base, labels, spec); err != nil {
		return Diagnostics{Phase: "Error", LastError: err.Error(), UpdatedAt: now}, err
	}

	return p.collectDiagnostics(ctx, spec, dep)
}

func (p *K8sProvisioner) reconcileSecret(ctx context.Context, base string, labels map[string]string, spec InstallationSpec) error {
	secretName := base + "-env"
	ns := p.cfg.Namespace
	existing, err := p.kube.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get secret %s: %w", secretName, err)
	}

	data := map[string][]byte{}
	if existing != nil && existing.Data != nil {
		if tok, ok := existing.Data["PLUGIN_TOKEN"]; ok && len(tok) > 0 {
			data["PLUGIN_TOKEN"] = tok
		}
	}
	if strings.TrimSpace(spec.PluginToken) != "" {
		data["PLUGIN_TOKEN"] = []byte(spec.PluginToken)
	}
	// ADR-0010 strict two-tier isolation:
	// INTERNAL_ONLY receives read-only Garage creds; EGRESS_EXTERNAL ACTION NEVER gets secflow-sources credentials.
	if spec.SandboxProfile == ProfileInternalOnly {
		if p.cfg.GarageReadOnlyAccessKey != "" {
			data["GARAGE_ACCESS_KEY_ID"] = []byte(p.cfg.GarageReadOnlyAccessKey)
		}
		if p.cfg.GarageReadOnlySecretKey != "" {
			data["GARAGE_SECRET_ACCESS_KEY"] = []byte(p.cfg.GarageReadOnlySecretKey)
		}
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels:    maps.Clone(labels),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	if apierrors.IsNotFound(err) {
		if _, err := p.kube.CoreV1().Secrets(ns).Create(ctx, desired, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create secret %s: %w", secretName, err)
		}
		return nil
	}
	if _, err := p.kube.CoreV1().Secrets(ns).Update(ctx, desired, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update secret %s: %w", secretName, err)
	}
	return nil
}

func (p *K8sProvisioner) reconcileNetworkPolicy(ctx context.Context, base string, labels map[string]string, spec InstallationSpec, targets []EgressTarget) error {
	npName := base + "-netpol"
	ns := p.cfg.Namespace
	udpProto := corev1.ProtocolUDP
	tcpProto := corev1.ProtocolTCP
	dnsPort := intstr.FromInt32(53)
	orchPort := intstr.FromInt32(p.cfg.OrchestratorPort)

	egress := []networkingv1.NetworkPolicyEgressRule{
		// CoreDNS resolution
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
					},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"k8s-app": "kube-dns"},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &udpProto, Port: &dnsPort},
				{Protocol: &tcpProto, Port: &dnsPort},
			},
		},
		// Orchestrator Pull gRPC
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": p.cfg.OrchestratorNamespace},
					},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "orchestrator"},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcpProto, Port: &orchPort},
			},
		},
	}

	if spec.SandboxProfile == ProfileInternalOnly {
		garagePort := intstr.FromInt32(p.cfg.GaragePort)
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": p.cfg.GarageNamespace},
					},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "garage"},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcpProto, Port: &garagePort},
			},
		})
	} else if spec.SandboxProfile == ProfileEgressExternal {
		// EGRESS_EXTERNAL (ACTION): NO Garage access; only explicitly approved public CIDRs/hosts.
		for _, t := range targets {
			portVal := intstr.FromInt32(t.Port)
			if t.CIDR != "" {
				egress = append(egress, networkingv1.NetworkPolicyEgressRule{
					To: []networkingv1.NetworkPolicyPeer{
						{IPBlock: &networkingv1.IPBlock{CIDR: t.CIDR}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &portVal},
					},
				})
				continue
			}
			// Hostname target: fail-closed resolution to explicitly pinned public IPs (never 0.0.0.0/0).
			resolver := p.resolve
			if resolver == nil {
				resolver = net.DefaultResolver.LookupHost
			}
			ips, rErr := resolver(ctx, t.Host)
			if rErr != nil {
				return fmt.Errorf("%w: resolve egress host %q: %w", ErrEgressDenied, t.Host, rErr)
			}
			var peers []networkingv1.NetworkPolicyPeer
			for _, ip := range ips {
				validated, vErr := parseAndValidateEgressEntry(ip)
				if vErr != nil || validated.CIDR == "" {
					return fmt.Errorf("%w: egress host %q resolved to blocked address %q", ErrEgressDenied, t.Host, ip)
				}
				peers = append(peers, networkingv1.NetworkPolicyPeer{
					IPBlock: &networkingv1.IPBlock{CIDR: validated.CIDR},
				})
			}
			if len(peers) == 0 {
				return fmt.Errorf("%w: egress host %q resolved to no public addresses", ErrEgressDenied, t.Host)
			}
			egress = append(egress, networkingv1.NetworkPolicyEgressRule{
				To:    peers,
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcpProto, Port: &portVal}},
			})
		}
	}

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      npName,
			Namespace: ns,
			Labels:    maps.Clone(labels),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{LabelInstallationID: spec.ID},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  egress,
		},
	}

	_, err := p.kube.NetworkingV1().NetworkPolicies(ns).Get(ctx, npName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := p.kube.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create networkpolicy %s: %w", npName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get networkpolicy %s: %w", npName, err)
	}
	if _, err := p.kube.NetworkingV1().NetworkPolicies(ns).Update(ctx, np, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update networkpolicy %s: %w", npName, err)
	}
	return nil
}

func (p *K8sProvisioner) reconcileDeployment(ctx context.Context, base string, labels map[string]string, spec InstallationSpec) (*appsv1.Deployment, error) {
	ns := p.cfg.Namespace
	cpuReq, cpuLim, memReq, memLim, _, _, replicas := ClampResourceLimits(spec.ResourceLimits, spec.DesiredReplicas, p.cfg.ResourceCeiling)
	if spec.Status == StatusDisabled {
		replicas = 0
	}

	runAsNonRoot := true
	readOnlyRoot := true
	allowPrivEsc := false
	automountSA := false
	nonRootUID := int64(65532)
	emptyDirLimit := resource.MustParse(p.cfg.EmptyDirSizeLimit)
	secretName := base + "-env"

	envVars := []corev1.EnvVar{
		{Name: "ORCHESTRATOR_ADDR", Value: p.cfg.OrchestratorAddr},
		{Name: "POD_NAMESPACE", Value: ns},
		{Name: "SANDBOX_PROFILE", Value: spec.SandboxProfile},
		{
			Name: "PLUGIN_TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  "PLUGIN_TOKEN",
					Optional:             ptrBool(true),
				},
			},
		},
	}
	if spec.SandboxProfile == ProfileInternalOnly {
		envVars = append(envVars,
			corev1.EnvVar{Name: "GARAGE_ENDPOINT", Value: p.cfg.GarageEndpoint},
			corev1.EnvVar{
				Name: "GARAGE_ACCESS_KEY_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
						Key:                  "GARAGE_ACCESS_KEY_ID",
						Optional:             ptrBool(true),
					},
				},
			},
			corev1.EnvVar{
				Name: "GARAGE_SECRET_ACCESS_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
						Key:                  "GARAGE_SECRET_ACCESS_KEY",
						Optional:             ptrBool(true),
					},
				},
			},
		)
	}

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      base,
			Namespace: ns,
			Labels:    maps.Clone(labels),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{LabelInstallationID: spec.ID},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: maps.Clone(labels),
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &automountSA,
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
							Name:            "plugin",
							Image:           spec.ImageRef,
							ImagePullPolicy: corev1.PullIfNotPresent,
							// Zero inbound container ports per ADR-0001.
							Ports: nil,
							Env:   envVars,
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot:             &runAsNonRoot,
								ReadOnlyRootFilesystem:   &readOnlyRoot,
								AllowPrivilegeEscalation: &allowPrivEsc,
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    cpuReq,
									corev1.ResourceMemory: memReq,
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    cpuLim,
									corev1.ResourceMemory: memLim,
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

	_, err := p.kube.AppsV1().Deployments(ns).Get(ctx, base, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		created, cErr := p.kube.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{})
		if cErr != nil {
			return nil, fmt.Errorf("create deployment %s: %w", base, cErr)
		}
		return created, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get deployment %s: %w", base, err)
	}
	updated, uErr := p.kube.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{})
	if uErr != nil {
		return nil, fmt.Errorf("update deployment %s: %w", base, uErr)
	}
	return updated, nil
}

func (p *K8sProvisioner) reconcileScaledObject(ctx context.Context, base string, labels map[string]string, spec InstallationSpec) error {
	if !p.cfg.EnableKEDA || p.dyn == nil {
		return nil
	}
	soName := base + "-keda"
	ns := p.cfg.Namespace
	if spec.Status == StatusDisabled || len(spec.PluginIDs) == 0 {
		err := p.dyn.Resource(kedaScaledObjectGVR).Namespace(ns).Delete(ctx, soName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete scaledobject %s: %w", soName, err)
		}
		return nil
	}

	_, _, _, _, minRep, maxRep, _ := ClampResourceLimits(spec.ResourceLimits, spec.DesiredReplicas, p.cfg.ResourceCeiling)
	escaped := make([]string, 0, len(spec.PluginIDs))
	for _, pid := range spec.PluginIDs {
		escaped = append(escaped, regexp.QuoteMeta(pid))
	}
	query := fmt.Sprintf(`sum(orchestrator_queue_depth{plugin_id=~"%s"})`, strings.Join(escaped, "|"))

	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "keda.sh/v1alpha1",
			"kind":       "ScaledObject",
			"metadata": map[string]any{
				"name":      soName,
				"namespace": ns,
				"labels":    toAnyMap(labels),
			},
			"spec": map[string]any{
				"scaleTargetRef": map[string]any{
					"name": base,
				},
				"minReplicaCount": int64(minRep),
				"maxReplicaCount": int64(maxRep),
				"triggers": []any{
					map[string]any{
						"type": "prometheus",
						"metadata": map[string]any{
							"serverAddress": p.cfg.PrometheusAddress,
							"metricName":    "orchestrator_queue_depth",
							"threshold":     "1",
							"query":         query,
						},
					},
				},
			},
		},
	}

	existing, err := p.dyn.Resource(kedaScaledObjectGVR).Namespace(ns).Get(ctx, soName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := p.dyn.Resource(kedaScaledObjectGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create scaledobject %s: %w", soName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get scaledobject %s: %w", soName, err)
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	if _, err := p.dyn.Resource(kedaScaledObjectGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update scaledobject %s: %w", soName, err)
	}
	return nil
}

func (p *K8sProvisioner) collectDiagnostics(ctx context.Context, spec InstallationSpec, dep *appsv1.Deployment) (Diagnostics, error) {
	now := time.Now().UTC()
	desired := int32(0)
	if dep != nil && dep.Spec.Replicas != nil {
		desired = *dep.Spec.Replicas
	}
	ready := int32(0)
	if dep != nil {
		ready = dep.Status.ReadyReplicas
	}

	selector := fmt.Sprintf("%s=%s", LabelInstallationID, spec.ID)
	pods, err := p.kube.CoreV1().Pods(p.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return Diagnostics{
			Phase:           "Error",
			DesiredReplicas: desired,
			ReadyReplicas:   ready,
			LastError:       err.Error(),
			UpdatedAt:       now,
		}, fmt.Errorf("list pods: %w", err)
	}

	var podReady int32
	var lastErr string
	phase := "Provisioning"
	msg := fmt.Sprintf("%d/%d sandbox replicas ready", ready, desired)
	for _, pod := range pods.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Ready {
				podReady++
			}
			if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
				reason := cs.State.Waiting.Reason
				if reason == "ImagePullBackOff" || reason == "ErrImagePull" || reason == "CrashLoopBackOff" || reason == "CreateContainerConfigError" {
					phase = reason
					lastErr = strings.TrimSpace(reason + ": " + cs.State.Waiting.Message)
				}
			}
			if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason == "OOMKilled" && lastErr == "" {
				phase = "OOMKilled"
				lastErr = "OOMKilled: container exceeded memory limit"
			}
		}
	}
	if podReady > ready {
		ready = podReady
	}
	if desired == 0 {
		phase = "ScaledToZero"
		msg = "Deployment scaled to 0 replicas"
	} else if lastErr != "" {
		msg = lastErr
	} else if ready >= desired {
		phase = "Running"
		msg = fmt.Sprintf("%d/%d sandbox replicas ready", ready, desired)
	}

	return Diagnostics{
		Phase:           phase,
		DesiredReplicas: desired,
		ReadyReplicas:   ready,
		Message:         msg,
		LastError:       lastErr,
		UpdatedAt:       now,
	}, nil
}

// Delete removes every Deployment, Secret, NetworkPolicy, and KEDA ScaledObject labeled with installationID.
func (p *K8sProvisioner) Delete(ctx context.Context, installationID string) error {
	ns := p.cfg.Namespace
	selector := fmt.Sprintf("%s=%s", LabelInstallationID, installationID)
	listOpts := metav1.ListOptions{LabelSelector: selector}

	if deps, err := p.kube.AppsV1().Deployments(ns).List(ctx, listOpts); err == nil {
		for _, d := range deps.Items {
			if err := p.kube.AppsV1().Deployments(ns).Delete(ctx, d.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete deployment %s: %w", d.Name, err)
			}
		}
	} else {
		return fmt.Errorf("list deployments for delete: %w", err)
	}

	if secs, err := p.kube.CoreV1().Secrets(ns).List(ctx, listOpts); err == nil {
		for _, s := range secs.Items {
			if err := p.kube.CoreV1().Secrets(ns).Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete secret %s: %w", s.Name, err)
			}
		}
	} else {
		return fmt.Errorf("list secrets for delete: %w", err)
	}

	if nps, err := p.kube.NetworkingV1().NetworkPolicies(ns).List(ctx, listOpts); err == nil {
		for _, np := range nps.Items {
			if err := p.kube.NetworkingV1().NetworkPolicies(ns).Delete(ctx, np.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete networkpolicy %s: %w", np.Name, err)
			}
		}
	} else {
		return fmt.Errorf("list networkpolicies for delete: %w", err)
	}

	if p.cfg.EnableKEDA && p.dyn != nil {
		if sos, err := p.dyn.Resource(kedaScaledObjectGVR).Namespace(ns).List(ctx, listOpts); err == nil {
			for _, so := range sos.Items {
				if err := p.dyn.Resource(kedaScaledObjectGVR).Namespace(ns).Delete(ctx, so.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
					return fmt.Errorf("delete scaledobject %s: %w", so.GetName(), err)
				}
			}
		} else if !apierrors.IsNotFound(err) {
			return fmt.Errorf("list scaledobjects for delete: %w", err)
		}
	}
	return nil
}

func ptrBool(v bool) *bool { return &v }

func toAnyMap(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
