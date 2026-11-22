package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func newTestK8sProvisioner(t *testing.T, enableKEDA bool) (*K8sProvisioner, *fake.Clientset, *dynfake.FakeDynamicClient) {
	t.Helper()
	kube := fake.NewSimpleClientset()
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		kedaScaledObjectGVR: "ScaledObjectList",
	})
	cfg := K8sConfig{
		Namespace:               "secflow-sandbox",
		OrchestratorAddr:        "orchestrator.secflow-core.svc.cluster.local:50051",
		OrchestratorNamespace:   "secflow-core",
		GarageEndpoint:          "http://garage.secflow-core.svc.cluster.local:3900",
		GarageNamespace:         "secflow-core",
		GarageReadOnlyAccessKey: "ro-access-key",
		GarageReadOnlySecretKey: "ro-secret-key",
		ImageRegistryAllowlist:  []string{"ghcr.io/secflow", "registry.internal.corp/plugins"},
		Production:              true,
		EnableKEDA:              enableKEDA,
		PrometheusAddress:       "http://prometheus.secflow-observability.svc.cluster.local:9090",
	}
	prov := NewK8sProvisioner(kube, dyn, cfg)
	prov.resolve = func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "hooks.slack.com":
			return []string{"54.192.18.10"}, nil
		case "rebind.evil.example":
			return []string{"169.254.169.254"}, nil
		default:
			return nil, errors.New("nxdomain")
		}
	}
	return prov, kube, dyn
}

func TestK8sProvisioner_InternalOnlyHardeningScaleAndDelete(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	prov, kube, dyn := newTestK8sProvisioner(t, true)

	spec := InstallationSpec{
		ID:              "plginst_spring01",
		Name:            "spring-config",
		SourceMode:      SourceModePreset,
		PresetID:        "spring-config-hardening",
		ImageRef:        "ghcr.io/secflow/demo-spring-config:1.0.0",
		SandboxProfile:  ProfileInternalOnly,
		DesiredReplicas: 2,
		ResourceLimits: ResourceLimits{
			CPURequest:    "100m",
			CPULimit:      "8", // Exceeds ceiling -> must clamp to 2
			MemoryRequest: "128Mi",
			MemoryLimit:   "16Gi", // Exceeds ceiling -> must clamp to 2Gi
			MinReplicas:   1,
			MaxReplicas:   99, // Exceeds ceiling -> must clamp to 5
		},
		Status:      StatusActive,
		PluginIDs:   []string{"scan.spring-config"},
		PluginToken: "sf_plg_secret_token_123",
	}

	diag, err := prov.Reconcile(ctx, spec)
	if err != nil {
		t.Fatalf("Reconcile INTERNAL_ONLY: %v", err)
	}
	if diag.DesiredReplicas != 2 {
		t.Fatalf("diag.DesiredReplicas = %d, want 2", diag.DesiredReplicas)
	}

	base := resourceBaseName(spec.ID)
	dep, err := kube.AppsV1().Deployments("secflow-sandbox").Get(ctx, base, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if dep.Labels[LabelInstallationID] != spec.ID {
		t.Fatalf("deployment missing installation label: %+v", dep.Labels)
	}
	if dep.Spec.Template.Spec.AutomountServiceAccountToken == nil || *dep.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("automountServiceAccountToken must be false")
	}
	if len(dep.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(dep.Spec.Template.Spec.Containers))
	}
	c := dep.Spec.Template.Spec.Containers[0]
	if len(c.Ports) != 0 {
		t.Fatalf("sandbox container must expose 0 inbound ports, got %+v", c.Ports)
	}
	sc := c.SecurityContext
	if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot ||
		sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem ||
		sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation ||
		sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("container securityContext not hardened: %+v", sc)
	}
	if gotCPU := c.Resources.Limits.Cpu().String(); gotCPU != "2" {
		t.Fatalf("cpu limit = %s, want clamped 2", gotCPU)
	}
	if gotMem := c.Resources.Limits.Memory().String(); gotMem != "2Gi" {
		t.Fatalf("memory limit = %s, want clamped 2Gi", gotMem)
	}

	// Secret must hold PLUGIN_TOKEN and read-only Garage creds for INTERNAL_ONLY.
	sec, err := kube.CoreV1().Secrets("secflow-sandbox").Get(ctx, base+"-env", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(sec.Data["PLUGIN_TOKEN"]) != "sf_plg_secret_token_123" ||
		string(sec.Data["GARAGE_ACCESS_KEY_ID"]) != "ro-access-key" ||
		string(sec.Data["GARAGE_SECRET_ACCESS_KEY"]) != "ro-secret-key" {
		t.Fatalf("unexpected INTERNAL_ONLY secret keys: %+v", sec.Data)
	}

	// NetworkPolicy: empty ingress, egress only CoreDNS + orchestrator + garage (3 rules).
	np, err := kube.NetworkingV1().NetworkPolicies("secflow-sandbox").Get(ctx, base+"-netpol", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get networkpolicy: %v", err)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 3 {
		t.Fatalf("INTERNAL_ONLY netpol ingress=%d egress=%d, want 0/3", len(np.Spec.Ingress), len(np.Spec.Egress))
	}

	// KEDA ScaledObject created and references orchestrator_queue_depth.
	so, err := dyn.Resource(kedaScaledObjectGVR).Namespace("secflow-sandbox").Get(ctx, base+"-keda", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scaledobject: %v", err)
	}
	if so.GetLabels()[LabelInstallationID] != spec.ID {
		t.Fatalf("scaledobject missing installation label")
	}

	// Pod diagnostics: simulate ImagePullBackOff pod.
	_, err = kube.CoreV1().Pods("secflow-sandbox").Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      base + "-pod-1",
			Namespace: "secflow-sandbox",
			Labels:    map[string]string{LabelInstallationID: spec.ID},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "plugin",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "ImagePullBackOff",
							Message: "pull access denied",
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create fake pod: %v", err)
	}
	diagErr, err := prov.Reconcile(ctx, spec)
	if err != nil {
		t.Fatalf("reconcile with failing pod: %v", err)
	}
	if diagErr.Phase != "ImagePullBackOff" || !strings.Contains(diagErr.LastError, "ImagePullBackOff") {
		t.Fatalf("expected ImagePullBackOff diagnostics, got %+v", diagErr)
	}

	// DISABLED -> scales deployment to 0 and removes ScaledObject.
	spec.Status = StatusDisabled
	diagDis, err := prov.Reconcile(ctx, spec)
	if err != nil {
		t.Fatalf("Reconcile DISABLED: %v", err)
	}
	depDis, _ := kube.AppsV1().Deployments("secflow-sandbox").Get(ctx, base, metav1.GetOptions{})
	if depDis.Spec.Replicas == nil || *depDis.Spec.Replicas != 0 || diagDis.Phase != "ScaledToZero" {
		t.Fatalf("expected replicas=0 ScaledToZero, got replicas=%v diag=%+v", depDis.Spec.Replicas, diagDis)
	}
	if _, err := dyn.Resource(kedaScaledObjectGVR).Namespace("secflow-sandbox").Get(ctx, base+"-keda", metav1.GetOptions{}); err == nil {
		t.Fatal("ScaledObject should be deleted when installation is DISABLED")
	}

	// DELETING -> removes Deployment, Secret, NetworkPolicy by installation label.
	if err := prov.Delete(ctx, spec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	deps, _ := kube.AppsV1().Deployments("secflow-sandbox").List(ctx, metav1.ListOptions{LabelSelector: LabelInstallationID + "=" + spec.ID})
	secs, _ := kube.CoreV1().Secrets("secflow-sandbox").List(ctx, metav1.ListOptions{LabelSelector: LabelInstallationID + "=" + spec.ID})
	nps, _ := kube.NetworkingV1().NetworkPolicies("secflow-sandbox").List(ctx, metav1.ListOptions{LabelSelector: LabelInstallationID + "=" + spec.ID})
	if len(deps.Items) != 0 || len(secs.Items) != 0 || len(nps.Items) != 0 {
		t.Fatalf("resources left behind after Delete: deps=%d secs=%d nps=%d", len(deps.Items), len(secs.Items), len(nps.Items))
	}
}

func TestK8sProvisioner_EgressExternalActionHasNoGarageAccess(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	prov, kube, _ := newTestK8sProvisioner(t, false)

	spec := InstallationSpec{
		ID:              "plginst_action01",
		Name:            "jira-action",
		SourceMode:      SourceModeOCIImage,
		ImageRef:        "registry.internal.corp/plugins/jira-notifier:1.2.0",
		SandboxProfile:  ProfileEgressExternal,
		EgressAllowlist: []string{"198.51.100.10/32", "https://hooks.slack.com:443"},
		DesiredReplicas: 1,
		Status:          StatusActive,
		PluginIDs:       []string{"action.jira"},
		PluginToken:     "sf_plg_action_tok",
	}

	// Note: 198.51.100.10/32 is TEST-NET-2 (blocked by RFC 5737 SSRF prefixes); use a real public IP CIDR.
	spec.EgressAllowlist = []string{"93.184.216.34/32", "https://hooks.slack.com:443"}

	if _, err := prov.Reconcile(ctx, spec); err != nil {
		t.Fatalf("Reconcile EGRESS_EXTERNAL: %v", err)
	}

	base := resourceBaseName(spec.ID)
	sec, err := kube.CoreV1().Secrets("secflow-sandbox").Get(ctx, base+"-env", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if _, hasKey := sec.Data["GARAGE_ACCESS_KEY_ID"]; hasKey {
		t.Fatal("EGRESS_EXTERNAL ACTION secret must NEVER contain GARAGE_ACCESS_KEY_ID")
	}
	if _, hasSec := sec.Data["GARAGE_SECRET_ACCESS_KEY"]; hasSec {
		t.Fatal("EGRESS_EXTERNAL ACTION secret must NEVER contain GARAGE_SECRET_ACCESS_KEY")
	}

	dep, err := kube.AppsV1().Deployments("secflow-sandbox").Get(ctx, base, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	for _, env := range dep.Spec.Template.Spec.Containers[0].Env {
		if strings.HasPrefix(env.Name, "GARAGE_") {
			t.Fatalf("EGRESS_EXTERNAL ACTION container must NEVER get %s env", env.Name)
		}
	}

	np, err := kube.NetworkingV1().NetworkPolicies("secflow-sandbox").Get(ctx, base+"-netpol", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get netpol: %v", err)
	}
	// Expect CoreDNS + orchestrator + 2 approved egress targets, and NO garage rule.
	if len(np.Spec.Egress) != 4 {
		t.Fatalf("expected 4 egress rules (DNS, orchestrator, 2 targets), got %d", len(np.Spec.Egress))
	}
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.PodSelector != nil && peer.PodSelector.MatchLabels["app"] == "garage" {
				t.Fatal("EGRESS_EXTERNAL ACTION netpol must NOT allow egress to garage")
			}
		}
	}
}

func TestPolicy_ImageAndSSRFRejection(t *testing.T) {
	t.Parallel()
	allow := []string{"ghcr.io/secflow"}

	imageCases := []struct {
		name    string
		ref     string
		prod    bool
		wantErr bool
	}{
		{name: "valid semver allowlisted", ref: "ghcr.io/secflow/demo-risk-router:1.0.0", prod: true, wantErr: false},
		{name: "valid digest allowlisted", ref: "ghcr.io/secflow/demo-risk-router@sha256:0123456789abcdef0123456789abcdef", prod: true, wantErr: false},
		{name: "untrusted registry rejected", ref: "docker.io/evil/plugin:1.0.0", prod: true, wantErr: true},
		{name: "latest rejected in prod", ref: "ghcr.io/secflow/demo:latest", prod: true, wantErr: true},
		{name: "untagged rejected in prod", ref: "ghcr.io/secflow/demo", prod: true, wantErr: true},
		{name: "latest allowed in dev", ref: "ghcr.io/secflow/demo:latest", prod: false, wantErr: false},
		{name: "prohibited scanner rejected", ref: "ghcr.io/secflow/trivy-wrapper:1.0.0", prod: true, wantErr: true},
	}
	for _, tc := range imageCases {
		t.Run("image/"+tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateImageRef(tc.ref, allow, tc.prod)
			if tc.wantErr && !errors.Is(err, ErrImageDenied) {
				t.Fatalf("ValidateImageRef(%q) = %v, want ErrImageDenied", tc.ref, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateImageRef(%q) unexpected err = %v", tc.ref, err)
			}
		})
	}

	egressCases := []struct {
		name    string
		profile string
		entries []string
		wantErr bool
	}{
		{name: "internal only empty ok", profile: ProfileInternalOnly, entries: nil, wantErr: false},
		{name: "internal only non-empty denied", profile: ProfileInternalOnly, entries: []string{"hooks.slack.com"}, wantErr: true},
		{name: "external public host ok", profile: ProfileEgressExternal, entries: []string{"hooks.slack.com", "93.184.216.34/32"}, wantErr: false},
		{name: "loopback ip denied", profile: ProfileEgressExternal, entries: []string{"127.0.0.1"}, wantErr: true},
		{name: "metadata ip denied", profile: ProfileEgressExternal, entries: []string{"169.254.169.254"}, wantErr: true},
		{name: "private cidr denied", profile: ProfileEgressExternal, entries: []string{"10.0.0.0/8"}, wantErr: true},
		{name: "rfc1918 192.168 denied", profile: ProfileEgressExternal, entries: []string{"https://192.168.1.50/hook"}, wantErr: true},
		{name: "cluster.local denied", profile: ProfileEgressExternal, entries: []string{"orchestrator.secflow-core.svc.cluster.local"}, wantErr: true},
		{name: "gcp metadata host denied", profile: ProfileEgressExternal, entries: []string{"metadata.google.internal"}, wantErr: true},
		{name: "localhost denied", profile: ProfileEgressExternal, entries: []string{"http://localhost:8080"}, wantErr: true},
	}
	for _, tc := range egressCases {
		t.Run("egress/"+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateEgressAllowlist(tc.profile, tc.entries)
			if tc.wantErr && !errors.Is(err, ErrEgressDenied) {
				t.Fatalf("ValidateEgressAllowlist(%q, %v) = %v, want ErrEgressDenied", tc.profile, tc.entries, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateEgressAllowlist(%q, %v) unexpected err = %v", tc.profile, tc.entries, err)
			}
		})
	}
}

type memInstallationStore struct {
	specs     []InstallationSpec
	diags     map[string]Diagnostics
	markedErr map[string]bool
	deleted   []string
}

func (m *memInstallationStore) ListInstallations(_ context.Context) ([]InstallationSpec, error) {
	return m.specs, nil
}

func (m *memInstallationStore) UpdateDiagnostics(_ context.Context, id string, diag Diagnostics, markError bool) error {
	m.diags[id] = diag
	m.markedErr[id] = markError
	return nil
}

func (m *memInstallationStore) FinalizeDelete(_ context.Context, id string) error {
	m.deleted = append(m.deleted, id)
	return nil
}

func TestReconciler_ConvergesAndFinalizesDelete(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	prov, _, _ := newTestK8sProvisioner(t, false)
	store := &memInstallationStore{
		specs: []InstallationSpec{
			{
				ID:             "inst-ok",
				Name:           "ok",
				SourceMode:     SourceModePreset,
				ImageRef:       "ghcr.io/secflow/demo-spring-config:1.0.0",
				SandboxProfile: ProfileInternalOnly,
				Status:         StatusProvisioning,
			},
			{
				ID:             "inst-bad",
				Name:           "bad",
				SourceMode:     SourceModeOCIImage,
				ImageRef:       "docker.io/untrusted/img:latest",
				SandboxProfile: ProfileInternalOnly,
				Status:         StatusProvisioning,
			},
			{
				ID:     "inst-del",
				Name:   "del",
				Status: StatusDeleting,
			},
		},
		diags:     map[string]Diagnostics{},
		markedErr: map[string]bool{},
	}

	rec := NewReconciler(store, prov, 0)
	_ = rec.ReconcileAll(ctx)

	if store.markedErr["inst-ok"] {
		t.Fatalf("inst-ok should not be marked error, diag=%+v", store.diags["inst-ok"])
	}
	if !store.markedErr["inst-bad"] || store.diags["inst-bad"].Phase != "Error" {
		t.Fatalf("inst-bad should be marked error, diag=%+v", store.diags["inst-bad"])
	}
	if len(store.deleted) != 1 || store.deleted[0] != "inst-del" {
		t.Fatalf("expected inst-del finalized, got %v", store.deleted)
	}
}

func TestK8sProvisioner_HostnameResolutionFailsClosedAndProtoJSONDecoding(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	prov, _, _ := newTestK8sProvisioner(t, false)

	// Hostname resolving to AWS metadata IP must fail closed with ErrEgressDenied (never 0.0.0.0/0).
	_, err := prov.Reconcile(ctx, InstallationSpec{
		ID:              "plginst_rebind",
		Name:            "rebind",
		SourceMode:      SourceModeOCIImage,
		ImageRef:        "ghcr.io/secflow/jira-notifier:1.0.0",
		SandboxProfile:  ProfileEgressExternal,
		EgressAllowlist: []string{"https://rebind.evil.example"},
		Status:          StatusActive,
	})
	if !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("rebind hostname err = %v, want ErrEgressDenied", err)
	}

	// Unresolvable hostname must fail closed with ErrEgressDenied.
	_, err = prov.Reconcile(ctx, InstallationSpec{
		ID:              "plginst_nx",
		Name:            "nx",
		SourceMode:      SourceModeOCIImage,
		ImageRef:        "ghcr.io/secflow/jira-notifier:1.0.0",
		SandboxProfile:  ProfileEgressExternal,
		EgressAllowlist: []string{"https://missing.example.invalid"},
		Status:          StatusActive,
	})
	if !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("unresolvable hostname err = %v, want ErrEgressDenied", err)
	}

	// Verify protojson camelCase decoding for resource_limits and approved_manifests_json.
	rl := decodeResourceLimitsJSON([]byte(`{"cpuRequest":"200m","cpuLimit":"1","memoryRequest":"128Mi","memoryLimit":"512Mi","minReplicas":1,"maxReplicas":4}`))
	if rl.CPULimit != "1" || rl.MemoryLimit != "512Mi" || rl.MaxReplicas != 4 {
		t.Fatalf("unexpected camelCase resource_limits: %+v", rl)
	}
	pids := decodeManifestPluginIDsJSON([]byte(`[{"pluginId":"logic.risk-router"},{"plugin_id":"scan.spring-config"}]`))
	if len(pids) != 2 || pids[0] != "logic.risk-router" || pids[1] != "scan.spring-config" {
		t.Fatalf("unexpected decoded plugin_ids: %v", pids)
	}
}

func TestK8sProvisioner_DeclarativeSkipsImageProvisioning(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	prov, _, _ := newTestK8sProvisioner(t, true)

	tests := []struct {
		name      string
		status    string
		wantPhase string
		wantReady int32
	}{
		{name: "active declarative", status: StatusActive, wantPhase: "DeclarativeRuntime", wantReady: 1},
		{name: "disabled declarative", status: StatusDisabled, wantPhase: "ScaledToZero", wantReady: 0},
		{name: "draft declarative", status: StatusDraft, wantPhase: "Pending", wantReady: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			diag, err := prov.Reconcile(ctx, InstallationSpec{
				ID:              "inst_decl_" + tc.status,
				Name:            "Custom Rule",
				SourceMode:      SourceModeDeclarative,
				ImageRef:        "",
				SandboxProfile:  ProfileInternalOnly,
				DesiredReplicas: 1,
				Status:          tc.status,
			})
			if err != nil {
				t.Fatalf("Reconcile(DECLARATIVE, %s) unexpected err: %v", tc.status, err)
			}
			if diag.Phase != tc.wantPhase || diag.ReadyReplicas != tc.wantReady {
				t.Fatalf("diag = %+v, want phase=%s ready=%d", diag, tc.wantPhase, tc.wantReady)
			}
		})
	}
}
