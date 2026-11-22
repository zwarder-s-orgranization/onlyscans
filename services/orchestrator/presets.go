package main

import (
	"slices"

	"google.golang.org/protobuf/proto"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/riskrouter"
)

const springConfigPresetParamsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "checkActuatorExposure": {
      "type": "boolean",
      "default": true,
      "description": "Detect Spring Boot Actuator endpoints exposed with a wildcard (*)."
    },
    "checkPlaintextPasswords": {
      "type": "boolean",
      "default": true,
      "description": "Detect hardcoded plaintext datasource or property passwords in Spring configuration."
    },
    "severity": {
      "type": "string",
      "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      "default": "HIGH",
      "description": "Severity assigned to Spring configuration hardening findings."
    },
    "includePaths": {
      "type": "array",
      "items": {
        "type": "string",
        "minLength": 1
      },
      "default": [],
      "description": "Optional relative path prefixes or glob patterns to include (empty scans all application config files)."
    },
    "excludePaths": {
      "type": "array",
      "items": {
        "type": "string",
        "minLength": 1
      },
      "default": [],
      "description": "Optional relative path prefixes or glob patterns to skip (e.g. src/test/, fixtures/)."
    }
  }
}`

type builtinPresetSpec struct {
	preset    *secflowv1.PluginPreset
	manifests []*secflowv1.PluginManifest
}

func builtinPluginPresets() []builtinPresetSpec {
	springImage := envutil.Get("PLUGIN_PRESET_SPRING_CONFIG_IMAGE", "ghcr.io/secflow/demo-spring-config:1.0.0")
	riskRouterImage := envutil.Get("PLUGIN_PRESET_RISK_ROUTER_IMAGE", "ghcr.io/secflow/demo-risk-router:1.0.0")
	defaultPort := &secflowv1.PortDefinition{Id: "default", Label: "default"}
	defaultLimits := &secflowv1.PluginResourceLimits{
		CpuRequest:    "100m",
		CpuLimit:      "500m",
		MemoryRequest: "64Mi",
		MemoryLimit:   "256Mi",
		MinReplicas:   1,
		MaxReplicas:   2,
	}
	springManifest := &secflowv1.PluginManifest{
		PluginId:         "scan.spring-config",
		Version:          "1.0.0",
		DisplayName:      "Spring Config Hardening",
		Description:      "External Go analyzer detecting exposed Spring Boot Actuator endpoints and plaintext datasource passwords in application.{yml,yaml,properties}.",
		Category:         secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
		Capabilities:     []string{"analyzer"},
		ParamsJsonSchema: []byte(springConfigPresetParamsSchema),
		InputPorts:       []*secflowv1.PortDefinition{defaultPort},
		OutputPorts:      []*secflowv1.PortDefinition{defaultPort},
		RuntimeLanguage:  "go",
		SandboxProfile:   secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:       true,
		MaxConcurrency:   4,
	}
	riskManifest := riskrouter.Manifest()
	return []builtinPresetSpec{
		{
			preset: &secflowv1.PluginPreset{
				Id:                     "spring-config-hardening",
				Name:                   "Spring Config Hardening",
				Description:            "External Go analyzer detecting exposed Spring Boot Actuator endpoints and plaintext datasource passwords in application.{yml,yaml,properties}.",
				ImageRef:               springImage,
				Category:               secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER,
				SandboxProfile:         secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
				PluginIds:              []string{"scan.spring-config"},
				OutputPorts:            []*secflowv1.PortDefinition{defaultPort},
				RequiredSecretKeys:     nil,
				DefaultEgressAllowlist: nil,
				DefaultResourceLimits:  defaultLimits,
				AutoApproveSupported:   true,
			},
			manifests: []*secflowv1.PluginManifest{springManifest},
		},
		{
			preset: &secflowv1.PluginPreset{
				Id:                     "risk-router",
				Name:                   "Risk Router",
				Description:            riskManifest.GetDescription(),
				ImageRef:               riskRouterImage,
				Category:               secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC,
				SandboxProfile:         secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
				PluginIds:              []string{riskrouter.PluginID},
				OutputPorts:            riskrouter.OutputPorts(),
				RequiredSecretKeys:     nil,
				DefaultEgressAllowlist: nil,
				DefaultResourceLimits:  defaultLimits,
				AutoApproveSupported:   true,
			},
			manifests: []*secflowv1.PluginManifest{riskManifest},
		},
	}
}

func lookupPluginPreset(presetID string) (builtinPresetSpec, bool) {
	for _, spec := range builtinPluginPresets() {
		if spec.preset.GetId() == presetID {
			return clonePresetSpec(spec), true
		}
	}
	return builtinPresetSpec{}, false
}

func clonePresetSpec(spec builtinPresetSpec) builtinPresetSpec {
	out := builtinPresetSpec{}
	if spec.preset != nil {
		if cp, ok := proto.Clone(spec.preset).(*secflowv1.PluginPreset); ok {
			out.preset = cp
		}
	}
	out.manifests = clonePluginManifests(spec.manifests)
	return out
}

func clonePluginManifests(in []*secflowv1.PluginManifest) []*secflowv1.PluginManifest {
	if len(in) == 0 {
		return nil
	}
	out := make([]*secflowv1.PluginManifest, 0, len(in))
	for _, m := range in {
		if cp := clonePluginManifest(m); cp != nil {
			out = append(out, cp)
		}
	}
	return out
}

func manifestPluginIDs(manifests []*secflowv1.PluginManifest) []string {
	out := make([]string, 0, len(manifests))
	for _, m := range manifests {
		if pid := m.GetPluginId(); pid != "" && !slices.Contains(out, pid) {
			out = append(out, pid)
		}
	}
	return out
}
