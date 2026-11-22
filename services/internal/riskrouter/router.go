// Package riskrouter implements the reference external LOGIC plugin (logic.risk-router)
// that computes weighted risk scores from Envelope.findings, patches branch-local
// Envelope.gate and Envelope.vars, and routes execution across BLOCK / REVIEW / OK ports.
package riskrouter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/engine"
)

const (
	PluginID = "logic.risk-router"

	PortBlock  = "BLOCK"
	PortReview = "REVIEW"
	PortOK     = "OK"
)

const ParamsSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "criticalWeight": {
      "type": "integer",
      "minimum": 0,
      "default": 10,
      "description": "Risk score weight added for each CRITICAL finding."
    },
    "highWeight": {
      "type": "integer",
      "minimum": 0,
      "default": 5,
      "description": "Risk score weight added for each HIGH finding."
    },
    "mediumWeight": {
      "type": "integer",
      "minimum": 0,
      "default": 2,
      "description": "Risk score weight added for each MEDIUM finding."
    },
    "lowWeight": {
      "type": "integer",
      "minimum": 0,
      "default": 1,
      "description": "Risk score weight added for each LOW finding."
    },
    "blockThreshold": {
      "type": "integer",
      "minimum": 1,
      "default": 15,
      "description": "Minimum weighted score that activates the BLOCK output port and sets Gate=FAIL."
    },
    "reviewThreshold": {
      "type": "integer",
      "minimum": 0,
      "default": 5,
      "description": "Minimum weighted score (below blockThreshold) that activates REVIEW and sets Gate=WARN."
    }
  }
}`

// Params defines the validated configuration for logic.risk-router.
type Params struct {
	CriticalWeight  int `json:"criticalWeight"`
	HighWeight      int `json:"highWeight"`
	MediumWeight    int `json:"mediumWeight"`
	LowWeight       int `json:"lowWeight"`
	BlockThreshold  int `json:"blockThreshold"`
	ReviewThreshold int `json:"reviewThreshold"`
}

// DefaultParams returns balanced default severity weights and thresholds.
func DefaultParams() Params {
	return Params{
		CriticalWeight:  10,
		HighWeight:      5,
		MediumWeight:    2,
		LowWeight:       1,
		BlockThreshold:  15,
		ReviewThreshold: 5,
	}
}

type rawParams struct {
	CriticalWeight  *int `json:"criticalWeight"`
	HighWeight      *int `json:"highWeight"`
	MediumWeight    *int `json:"mediumWeight"`
	LowWeight       *int `json:"lowWeight"`
	BlockThreshold  *int `json:"blockThreshold"`
	ReviewThreshold *int `json:"reviewThreshold"`
}

// ParseParams decodes and validates node params JSON for logic.risk-router.
func ParseParams(raw []byte) (Params, error) {
	p := DefaultParams()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return p, nil
	}
	if trimmed[0] != '{' {
		return p, fmt.Errorf("invalid params JSON: expected JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var in rawParams
	if err := dec.Decode(&in); err != nil {
		return p, fmt.Errorf("invalid params JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return p, fmt.Errorf("invalid params JSON: unexpected trailing data")
	}
	if in.CriticalWeight != nil {
		p.CriticalWeight = *in.CriticalWeight
	}
	if in.HighWeight != nil {
		p.HighWeight = *in.HighWeight
	}
	if in.MediumWeight != nil {
		p.MediumWeight = *in.MediumWeight
	}
	if in.LowWeight != nil {
		p.LowWeight = *in.LowWeight
	}
	if in.BlockThreshold != nil {
		p.BlockThreshold = *in.BlockThreshold
	}
	if in.ReviewThreshold != nil {
		p.ReviewThreshold = *in.ReviewThreshold
	}
	if p.CriticalWeight < 0 || p.HighWeight < 0 || p.MediumWeight < 0 || p.LowWeight < 0 {
		return p, fmt.Errorf("severity weights must be >= 0")
	}
	if p.BlockThreshold < 1 {
		return p, fmt.Errorf("blockThreshold must be >= 1")
	}
	if p.ReviewThreshold < 0 || p.ReviewThreshold > p.BlockThreshold {
		return p, fmt.Errorf("reviewThreshold must be between 0 and blockThreshold")
	}
	return p, nil
}

// OutputPorts returns the dynamic output ports advertised by logic.risk-router.
func OutputPorts() []*secflowv1.PortDefinition {
	return []*secflowv1.PortDefinition{
		{Id: PortBlock, Label: "Block", Description: "Activated when weighted risk score >= blockThreshold (Gate=FAIL)"},
		{Id: PortReview, Label: "Review", Description: "Activated when reviewThreshold <= weighted risk score < blockThreshold (Gate=WARN)"},
		{Id: PortOK, Label: "OK", Description: "Activated when weighted risk score < reviewThreshold (Gate=PASS)"},
	}
}

// Manifest returns the self-describing PluginManifest for demo-risk-router.
func Manifest() *secflowv1.PluginManifest {
	return &secflowv1.PluginManifest{
		PluginId:         PluginID,
		Version:          "1.0.0",
		DisplayName:      "Risk Router",
		Description:      "External LOGIC plugin that computes weighted risk score over Envelope.findings, patches branch-local gate/vars, and routes along BLOCK / REVIEW / OK ports.",
		Category:         secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC,
		Capabilities:     []string{"logic", "routing", "risk-scoring"},
		ParamsJsonSchema: []byte(ParamsSchemaJSON),
		InputPorts:       []*secflowv1.PortDefinition{{Id: "default", Label: "Input"}},
		OutputPorts:      OutputPorts(),
		RuntimeLanguage:  "go",
		SandboxProfile:   secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		IsExternal:       true,
		MaxConcurrency:   8,
	}
}

type envelopePatch struct {
	Gate *engine.GateInfo  `json:"gate,omitempty"`
	Vars map[string]string `json:"vars,omitempty"`
}

// Evaluate computes the weighted risk score from task.EnvelopeJson and returns a NodeResult
// that never mutates Run Findings and activates exactly one of BLOCK / REVIEW / OK.
func Evaluate(task *secflowv1.NodeTask) *secflowv1.NodeResult {
	start := time.Now()
	fail := func(code, msg string) *secflowv1.NodeResult {
		return &secflowv1.NodeResult{
			NodeRunId:    task.GetNodeRunId(),
			RunId:        task.GetRunId(),
			NodeId:       task.GetNodeId(),
			PluginId:     PluginID,
			Status:       secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
			ErrorCode:    code,
			ErrorMessage: msg,
		}
	}

	params, err := ParseParams(task.GetParamsJson())
	if err != nil {
		return fail("INVALID_PARAMS", err.Error())
	}

	var env engine.Envelope
	if len(task.GetEnvelopeJson()) > 0 {
		if err := json.Unmarshal(task.GetEnvelopeJson(), &env); err != nil {
			return fail("INVALID_ENVELOPE", fmt.Sprintf("unmarshal envelope: %v", err))
		}
	}

	score := 0
	for _, f := range env.Findings {
		switch strings.ToUpper(strings.TrimSpace(f.Severity)) {
		case "CRITICAL":
			score += params.CriticalWeight
		case "HIGH":
			score += params.HighWeight
		case "MEDIUM":
			score += params.MediumWeight
		case "LOW":
			score += params.LowWeight
		default:
			score += params.LowWeight
		}
	}

	route := PortOK
	gateStatus := "PASS"
	reason := fmt.Sprintf("weighted risk score %d < reviewThreshold %d (%d findings)", score, params.ReviewThreshold, len(env.Findings))
	if score >= params.BlockThreshold {
		route = PortBlock
		gateStatus = "FAIL"
		reason = fmt.Sprintf("weighted risk score %d >= blockThreshold %d (%d findings)", score, params.BlockThreshold, len(env.Findings))
	} else if score >= params.ReviewThreshold {
		route = PortReview
		gateStatus = "WARN"
		reason = fmt.Sprintf("weighted risk score %d >= reviewThreshold %d (%d findings)", score, params.ReviewThreshold, len(env.Findings))
	}

	patch := envelopePatch{
		Gate: &engine.GateInfo{
			Status:      gateStatus,
			Reason:      reason,
			NodeID:      task.GetNodeId(),
			EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Vars: map[string]string{
			"score":             strconv.Itoa(score),
			"route":             route,
			"findingsEvaluated": strconv.Itoa(len(env.Findings)),
			"blockThreshold":    strconv.Itoa(params.BlockThreshold),
			"reviewThreshold":   strconv.Itoa(params.ReviewThreshold),
		},
	}
	patchJSON, _ := json.Marshal(patch)
	previewJSON, _ := json.Marshal(map[string]any{
		"route":             route,
		"score":             score,
		"gate":              gateStatus,
		"findingsEvaluated": len(env.Findings),
	})

	return &secflowv1.NodeResult{
		NodeRunId:           task.GetNodeRunId(),
		RunId:               task.GetRunId(),
		NodeId:              task.GetNodeId(),
		PluginId:            PluginID,
		Status:              secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
		Findings:            nil, // LOGIC plugins never emit or mutate Run Findings.
		EnvelopePatchJson:   patchJSON,
		ActiveOutputPorts:   []string{route},
		RedactedPreviewJson: previewJSON,
		Metrics: &secflowv1.NodeTaskMetrics{
			DurationMs: time.Since(start).Milliseconds(),
		},
	}
}
