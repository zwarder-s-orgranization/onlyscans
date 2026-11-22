package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/urlguard"
)

func TestSpringConfigManifest_SchemaValidatesWithParamSchema(t *testing.T) {
	t.Parallel()

	m := springConfigManifest()
	if m.GetPluginId() != springConfigPluginID {
		t.Fatalf("PluginId = %q, want %q", m.GetPluginId(), springConfigPluginID)
	}
	if !m.GetIsExternal() {
		t.Fatal("expected IsExternal=true")
	}
	if m.GetCategory() != secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER {
		t.Fatalf("Category = %v, want ANALYZER", m.GetCategory())
	}
	if m.GetSandboxProfile() != secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY {
		t.Fatalf("SandboxProfile = %v, want INTERNAL_ONLY", m.GetSandboxProfile())
	}
	if urlguard.Denied(m.GetPluginId() + " " + m.GetDisplayName() + " " + m.GetDescription()) {
		t.Fatal("manifest unexpectedly blocked by urlguard.Denied")
	}

	tests := []struct {
		name    string
		params  map[string]any
		wantErr bool
	}{
		{
			name:    "empty params valid",
			params:  map[string]any{},
			wantErr: false,
		},
		{
			name: "full valid options",
			params: map[string]any{
				"checkActuatorExposure":   false,
				"checkPlaintextPasswords": true,
				"severity":                "CRITICAL",
				"includePaths":            []any{"src/main/resources/"},
				"excludePaths":            []any{"src/test/"},
			},
			wantErr: false,
		},
		{
			name: "invalid severity enum",
			params: map[string]any{
				"severity": "EXTREME",
			},
			wantErr: true,
		},
		{
			name: "unknown additional property rejected",
			params: map[string]any{
				"unknownField": "x",
			},
			wantErr: true,
		},
		{
			name: "wrong type for checkActuatorExposure",
			params: map[string]any{
				"checkActuatorExposure": "yes",
			},
			wantErr: true,
		},
		{
			name: "empty string in includePaths rejected",
			params: map[string]any{
				"includePaths": []any{""},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := paramschema.CheckSchema(springConfigPluginID, m.GetParamsJsonSchema(), tt.params)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckSchema(%v) err = %v, wantErr = %v", tt.params, err, tt.wantErr)
			}
		})
	}
}

func TestHandleSpringConfigTask(t *testing.T) {
	t.Parallel()

	writeSampleRepo := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		mainDir := filepath.Join(dir, "src", "main", "resources")
		testDir := filepath.Join(dir, "src", "test", "resources")
		if err := os.MkdirAll(mainDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(testDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mainDir, "application.yml"), []byte("spring:\n  datasource:\n    password: clear\nmanagement:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(testDir, "application.properties"), []byte("spring.datasource.password=${TEST_PW}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	tests := []struct {
		name         string
		paramsJSON   []byte
		emptyRoot    bool
		wantStatus   secflowv1.NodeRunStatus
		wantErrCode  string
		wantFindings int
		wantSev      secflowv1.Severity
	}{
		{
			name:         "default scan finds both issues with HIGH severity",
			paramsJSON:   nil,
			wantStatus:   secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			wantFindings: 2,
			wantSev:      secflowv1.Severity_SEVERITY_HIGH,
		},
		{
			name:         "toggle off actuator exposure and set CRITICAL",
			paramsJSON:   []byte(`{"checkActuatorExposure":false,"severity":"CRITICAL"}`),
			wantStatus:   secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			wantFindings: 1,
			wantSev:      secflowv1.Severity_SEVERITY_CRITICAL,
		},
		{
			name:         "exclude src/main yields zero findings",
			paramsJSON:   []byte(`{"excludePaths":["src/main/"]}`),
			wantStatus:   secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			wantFindings: 0,
		},
		{
			name:        "invalid severity param fails cleanly",
			paramsJSON:  []byte(`{"severity":"BOGUS"}`),
			wantStatus:  secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			wantErrCode: "INVALID_PARAMS",
		},
		{
			name:        "lowercase severity param rejected strictly",
			paramsJSON:  []byte(`{"severity":"low"}`),
			wantStatus:  secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			wantErrCode: "INVALID_PARAMS",
		},
		{
			name:        "unknown field rejected strictly",
			paramsJSON:  []byte(`{"unknownField":123}`),
			wantStatus:  secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			wantErrCode: "INVALID_PARAMS",
		},
		{
			name:        "missing source returns MISSING_SOURCE",
			emptyRoot:   true,
			wantStatus:  secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			wantErrCode: "MISSING_SOURCE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := ""
			if !tt.emptyRoot {
				root = writeSampleRepo(t)
			}
			task := &secflowv1.NodeTask{
				RunId:      "run_1",
				NodeRunId:  "nr_1",
				NodeId:     "spring_node",
				PluginId:   springConfigPluginID,
				ParamsJson: tt.paramsJSON,
			}
			res := handleSpringConfigTask(t.Context(), task, func(context.Context, []byte) (string, func()) {
				return root, func() {}
			})
			if res.GetStatus() != tt.wantStatus {
				t.Fatalf("status = %v, want %v (err=%s: %s)", res.GetStatus(), tt.wantStatus, res.GetErrorCode(), res.GetErrorMessage())
			}
			if tt.wantErrCode != "" && res.GetErrorCode() != tt.wantErrCode {
				t.Fatalf("errorCode = %q, want %q", res.GetErrorCode(), tt.wantErrCode)
			}
			if tt.wantStatus == secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
				if len(res.GetFindings()) != tt.wantFindings {
					t.Fatalf("findings len = %d, want %d", len(res.GetFindings()), tt.wantFindings)
				}
				for _, f := range res.GetFindings() {
					if f.GetSourceNodeId() != "spring_node" {
						t.Fatalf("SourceNodeId = %q, want spring_node", f.GetSourceNodeId())
					}
					if f.GetSeverity() != tt.wantSev {
						t.Fatalf("Severity = %v, want %v", f.GetSeverity(), tt.wantSev)
					}
				}
			}
		})
	}
}
