package main

import (
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/riskrouter"
)

func TestDemoRiskRouterManifestContract(t *testing.T) {
	t.Parallel()
	m := riskrouter.Manifest()
	if m.GetPluginId() != "logic.risk-router" {
		t.Fatalf("pluginId=%q, want logic.risk-router", m.GetPluginId())
	}
	if m.GetCategory() != secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC ||
		m.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY ||
		!m.GetIsExternal() {
		t.Fatalf("unexpected manifest category/profile/external: %+v", m)
	}
	if len(m.GetOutputPorts()) != 3 {
		t.Fatalf("outputPorts=%d, want 3 (BLOCK, REVIEW, OK)", len(m.GetOutputPorts()))
	}
}
