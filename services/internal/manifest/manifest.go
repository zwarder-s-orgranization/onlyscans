package manifest

import secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"

// One builds a plugin manifest with a single default port.
func One(id, display string, category secflowv1.PluginCategory, caps []string, external bool) *secflowv1.PluginManifest {
	return &secflowv1.PluginManifest{
		PluginId: id, Version: "1.0.0", DisplayName: display, Category: category, Capabilities: caps,
		InputPorts: []*secflowv1.PortDefinition{{Id: "default"}}, OutputPorts: []*secflowv1.PortDefinition{{Id: "default"}},
		RuntimeLanguage: "go", IsExternal: external,
	}
}
