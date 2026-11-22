package main

import (
	"context"
	"strings"
	"time"
)

const (
	LabelInstallationID = "secflow.io/installation-id"
	LabelManagedBy      = "secflow.io/managed-by"
	LabelSandboxProfile = "secflow.io/sandbox-profile"
	ManagedByValue      = "plugin-provisioner"

	ProfileInternalOnly   = "INTERNAL_ONLY"
	ProfileEgressExternal = "EGRESS_EXTERNAL"

	SourceModePreset       = "PRESET"
	SourceModeOCIImage     = "OCI_IMAGE"
	SourceModeExternalPull = "EXTERNAL_PULL"
	SourceModeDeclarative  = "DECLARATIVE"

	StatusDraft           = "DRAFT"
	StatusProvisioning    = "PROVISIONING"
	StatusPendingApproval = "PENDING_APPROVAL"
	StatusActive          = "ACTIVE"
	StatusDisabled        = "DISABLED"
	StatusError           = "ERROR"
	StatusDeleting        = "DELETING"
)

// ResourceLimits specifies bounded container resource requests/limits and replica bounds.
type ResourceLimits struct {
	CPURequest    string `json:"cpu_request,omitempty"`
	CPULimit      string `json:"cpu_limit,omitempty"`
	MemoryRequest string `json:"memory_request,omitempty"`
	MemoryLimit   string `json:"memory_limit,omitempty"`
	MinReplicas   int32  `json:"min_replicas,omitempty"`
	MaxReplicas   int32  `json:"max_replicas,omitempty"`
}

// InstallationSpec is the desired state of a Plugin Installation reconciled by plugin-provisioner.
type InstallationSpec struct {
	ID              string
	Name            string
	SourceMode      string
	PresetID        string
	ImageRef        string
	SandboxProfile  string
	EgressAllowlist []string
	ResourceLimits  ResourceLimits
	DesiredReplicas int32
	Status          string
	PluginIDs       []string
	PluginToken     string // Optional plaintext token injected into K8s Secret on creation/rotation.
}

// Diagnostics captures live sandbox workload status written back to plugin_installations.runtime_diagnostics.
type Diagnostics struct {
	Phase           string    `json:"phase"`
	DesiredReplicas int32     `json:"desired_replicas"`
	ReadyReplicas   int32     `json:"ready_replicas"`
	Message         string    `json:"message"`
	LastError       string    `json:"last_error"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// RuntimeProvisioner abstracts the sandbox deployment backend (k8s vs noop/external).
type RuntimeProvisioner interface {
	Driver() string
	Reconcile(ctx context.Context, spec InstallationSpec) (Diagnostics, error)
	Delete(ctx context.Context, installationID string) error
}

// NoopProvisioner handles local Docker Compose / external Pull-worker mode without Kubernetes.
type NoopProvisioner struct {
	driverName string
}

// NewNoopProvisioner returns a RuntimeProvisioner that leaves workload execution to external processes.
func NewNoopProvisioner(driverName string) *NoopProvisioner {
	name := strings.TrimSpace(driverName)
	if name == "" {
		name = "noop"
	}
	return &NoopProvisioner{driverName: name}
}

func (n *NoopProvisioner) Driver() string { return n.driverName }

func declarativeDiagnostics(spec InstallationSpec, now time.Time) Diagnostics {
	switch spec.Status {
	case StatusActive:
		replicas := spec.DesiredReplicas
		if replicas <= 0 {
			replicas = 1
		}
		return Diagnostics{
			Phase:           "DeclarativeRuntime",
			DesiredReplicas: replicas,
			ReadyReplicas:   replicas,
			Message:         "Served by declarative sandbox runtime pool",
			UpdatedAt:       now,
		}
	case StatusDisabled:
		return Diagnostics{
			Phase:           "ScaledToZero",
			DesiredReplicas: 0,
			ReadyReplicas:   0,
			Message:         "Declarative plugin disabled",
			UpdatedAt:       now,
		}
	default:
		return Diagnostics{
			Phase:           "Pending",
			DesiredReplicas: 0,
			ReadyReplicas:   0,
			Message:         "Declarative plugin awaiting approval",
			UpdatedAt:       now,
		}
	}
}

func (n *NoopProvisioner) Reconcile(_ context.Context, spec InstallationSpec) (Diagnostics, error) {
	now := time.Now().UTC()
	if spec.SourceMode == SourceModeDeclarative {
		return declarativeDiagnostics(spec, now), nil
	}
	if spec.Status == StatusDisabled {
		return Diagnostics{
			Phase:           "ScaledToZero",
			DesiredReplicas: 0,
			ReadyReplicas:   0,
			Message:         "Installation disabled (noop/external driver)",
			UpdatedAt:       now,
		}, nil
	}
	return Diagnostics{
		Phase:           "ExternalPull",
		DesiredReplicas: spec.DesiredReplicas,
		ReadyReplicas:   0,
		Message:         "Awaiting external Pull worker connection via WorkerService.Connect",
		UpdatedAt:       now,
	}, nil
}

func (n *NoopProvisioner) Delete(_ context.Context, _ string) error {
	return nil
}
