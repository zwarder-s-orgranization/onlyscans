package riskrouter

import (
	"encoding/json"
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
)

func TestEvaluate_RoutingAndPatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		paramsJSON string
		findings   []engine.Finding
		wantPort   string
		wantGate   string
		wantScore  string
	}{
		{
			name:       "no findings routes to OK",
			paramsJSON: `{}`,
			findings:   nil,
			wantPort:   PortOK,
			wantGate:   "PASS",
			wantScore:  "0",
		},
		{
			name:       "medium and high findings route to REVIEW",
			paramsJSON: `{"blockThreshold":15,"reviewThreshold":5}`,
			findings: []engine.Finding{
				{ID: "f1", Severity: "HIGH"},
				{ID: "f2", Severity: "MEDIUM"},
			},
			wantPort:  PortReview,
			wantGate:  "WARN",
			wantScore: "7",
		},
		{
			name:       "two critical findings route to BLOCK",
			paramsJSON: `{"criticalWeight":10,"blockThreshold":15,"reviewThreshold":5}`,
			findings: []engine.Finding{
				{ID: "f1", Severity: "CRITICAL"},
				{ID: "f2", Severity: "CRITICAL"},
			},
			wantPort:  PortBlock,
			wantGate:  "FAIL",
			wantScore: "20",
		},
		{
			name:       "custom weights trigger BLOCK on low findings",
			paramsJSON: `{"lowWeight":4,"blockThreshold":8,"reviewThreshold":4}`,
			findings: []engine.Finding{
				{ID: "f1", Severity: "LOW"},
				{ID: "f2", Severity: "LOW"},
			},
			wantPort:  PortBlock,
			wantGate:  "FAIL",
			wantScore: "8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			envRaw, _ := json.Marshal(engine.Envelope{Findings: tc.findings})
			res := Evaluate(&secflowv1.NodeTask{
				RunId:        "run_1",
				NodeRunId:    "nr_1",
				NodeId:       "risk_1",
				PluginId:     PluginID,
				ParamsJson:   []byte(tc.paramsJSON),
				EnvelopeJson: envRaw,
			})
			if res.GetStatus() != secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
				t.Fatalf("status=%v err=%q", res.GetStatus(), res.GetErrorMessage())
			}
			if len(res.GetFindings()) != 0 {
				t.Fatalf("LOGIC plugin must emit 0 findings, got %d", len(res.GetFindings()))
			}
			if len(res.GetActiveOutputPorts()) != 1 || res.GetActiveOutputPorts()[0] != tc.wantPort {
				t.Fatalf("activeOutputPorts=%v, want [%s]", res.GetActiveOutputPorts(), tc.wantPort)
			}
			var patch envelopePatch
			if err := json.Unmarshal(res.GetEnvelopePatchJson(), &patch); err != nil {
				t.Fatalf("unmarshal patch: %v", err)
			}
			if patch.Gate == nil || patch.Gate.Status != tc.wantGate {
				t.Fatalf("gate=%+v, want %s", patch.Gate, tc.wantGate)
			}
			if patch.Vars["score"] != tc.wantScore || patch.Vars["route"] != tc.wantPort {
				t.Fatalf("vars=%+v, want score=%s route=%s", patch.Vars, tc.wantScore, tc.wantPort)
			}
		})
	}
}

func TestParseParams_RejectsInvalid(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"unknownField": 1}`,
		`{"criticalWeight": -1}`,
		`{"blockThreshold": 0}`,
		`{"blockThreshold": 5, "reviewThreshold": 10}`,
		`[]`,
	} {
		if _, err := ParseParams([]byte(raw)); err == nil {
			t.Fatalf("ParseParams(%s) expected error, got nil", raw)
		}
	}
}
