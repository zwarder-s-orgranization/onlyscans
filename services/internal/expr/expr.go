// Package expr evaluates the safe {{ ... }} template subset. It does not eval arbitrary code.
package expr

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var token = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)

var aliases = map[string][]string{
	"envelope.stats.total":              {"envelope.total"},
	"envelope.total":                    {"envelope.stats.total"},
	"envelope.stats.newCount":           {"envelope.stats.newVsBaselineCount", "envelope.newCount"},
	"envelope.stats.newVsBaselineCount": {"envelope.stats.newCount", "envelope.newCount"},
	"envelope.newCount":                 {"envelope.stats.newCount", "envelope.stats.newVsBaselineCount"},
	"envelope.stats.critical":           {"envelope.critical"},
	"envelope.critical":                 {"envelope.stats.critical"},
	"envelope.stats.high":               {"envelope.high"},
	"envelope.high":                     {"envelope.stats.high"},
	"envelope.stats.medium":             {"envelope.medium"},
	"envelope.medium":                   {"envelope.stats.medium"},
	"envelope.stats.low":                {"envelope.low"},
	"envelope.low":                      {"envelope.stats.low"},
	"envelope.stats.secretCount":        {"envelope.secretCount"},
	"envelope.secretCount":              {"envelope.stats.secretCount"},
	"envelope.stats.sastCount":          {"envelope.sastCount"},
	"envelope.sastCount":                {"envelope.stats.sastCount"},
	"envelope.stats.scaCount":           {"envelope.scaCount"},
	"envelope.scaCount":                 {"envelope.stats.scaCount"},
	"envelope.stats.maxSeverity":        {"envelope.maxSeverity"},
	"envelope.maxSeverity":              {"envelope.stats.maxSeverity"},
	"ai.executiveSummary":               {"ai.summary"},
	"ai.summary":                        {"ai.executiveSummary"},
	"ai.releaseDecision":                {"ai.decision"},
	"ai.decision":                       {"ai.releaseDecision"},
	"run.id":                            {"runId"},
	"runId":                             {"run.id"},
}

func lookupVar(vars map[string]string, key string) (string, bool) {
	if len(vars) == 0 {
		return "", false
	}
	if v, ok := vars[key]; ok {
		return v, true
	}
	for _, alt := range aliases[key] {
		if v, ok := vars[alt]; ok {
			return v, true
		}
	}
	return "", false
}

// Eval replaces {{ $trigger.x }}, {{ $envelope.x }}, {{ $ai.x }}, and {{ $run.x }}.
// Unknown tokens evaluate to an empty string for backwards compatibility.
func Eval(input string, vars map[string]string) string {
	return evalString(input, vars, false)
}

// EvalPreserveUnknown replaces known {{ ... }} tokens and leaves unknown tokens intact
// so callers can detect unresolved expressions or defer them to downstream workers.
func EvalPreserveUnknown(input string, vars map[string]string) string {
	return evalString(input, vars, true)
}

func evalString(input string, vars map[string]string, preserveUnknown bool) string {
	if !strings.Contains(input, "{{") {
		return input
	}
	return token.ReplaceAllStringFunc(input, func(match string) string {
		sub := token.FindStringSubmatch(match)
		if len(sub) < 2 {
			if preserveUnknown {
				return match
			}
			return ""
		}
		inner := strings.TrimSpace(sub[1])
		inner = strings.TrimPrefix(inner, "$")
		if v, ok := lookupVar(vars, inner); ok {
			return v
		}
		if preserveUnknown {
			return match
		}
		return ""
	})
}

// EvalValue recursively evaluates strings inside maps and slices using Eval.
func EvalValue(v any, vars map[string]string) any {
	return evalValue(v, vars, false)
}

// EvalValuePreserveUnknown recursively evaluates strings inside maps and slices
// while leaving unknown {{ ... }} expressions intact.
func EvalValuePreserveUnknown(v any, vars map[string]string) any {
	return evalValue(v, vars, true)
}

func evalValue(v any, vars map[string]string, preserveUnknown bool) any {
	switch t := v.(type) {
	case string:
		return evalString(t, vars, preserveUnknown)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			out[k] = evalValue(item, vars, preserveUnknown)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = evalValue(item, vars, preserveUnknown)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, item := range t {
			out[i] = evalString(item, vars, preserveUnknown)
		}
		return out
	default:
		return v
	}
}

// EvalMap returns a deep-evaluated copy of params where unknown tokens resolve to "".
func EvalMap(params map[string]any, vars map[string]string) map[string]any {
	if params == nil {
		return nil
	}
	out, _ := EvalValue(params, vars).(map[string]any)
	return out
}

// EvalMapPreserveUnknown returns a deep-evaluated copy of params leaving unknown tokens intact.
func EvalMapPreserveUnknown(params map[string]any, vars map[string]string) map[string]any {
	if params == nil {
		return nil
	}
	out, _ := EvalValuePreserveUnknown(params, vars).(map[string]any)
	return out
}

// HasUnresolved reports whether v contains any remaining {{ ... }} template token.
func HasUnresolved(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		if m := token.FindString(t); m != "" {
			return m, true
		}
		if strings.Contains(t, "{{") {
			return t, true
		}
		return "", false
	case map[string]any:
		for _, item := range t {
			if m, ok := HasUnresolved(item); ok {
				return m, true
			}
		}
		return "", false
	case []any:
		for _, item := range t {
			if m, ok := HasUnresolved(item); ok {
				return m, true
			}
		}
		return "", false
	case []string:
		for _, item := range t {
			if m, ok := HasUnresolved(item); ok {
				return m, true
			}
		}
		return "", false
	default:
		return "", false
	}
}

// VarsFromEnvelopeJSON extracts canonical template variables ($trigger.*, $envelope.stats.*,
// $envelope.sourceRef.*, $envelope.gate.*, $ai.*, $run.*) from a serialized Envelope JSON blob.
func VarsFromEnvelopeJSON(raw []byte, runID string) map[string]string {
	vars := map[string]string{}
	if runID != "" {
		vars["run.id"] = runID
		vars["runId"] = runID
	}
	if len(raw) == 0 {
		return vars
	}
	var env struct {
		Trigger *struct {
			Type            string `json:"type"`
			RepoURL         string `json:"repoUrl"`
			Branch          string `json:"branch"`
			CommitSHA       string `json:"commitSha"`
			PRNumber        *int   `json:"prNumber"`
			GitProvider     string `json:"gitProvider"`
			DeliveryID      string `json:"deliveryId"`
			TriggeredBy     string `json:"triggeredBy"`
			CommitStatusURL string `json:"commitStatusUrl"`
			TriggeredAt     string `json:"triggeredAt"`
		} `json:"trigger"`
		SourceRef *struct {
			SourceID  string `json:"sourceId"`
			Bucket    string `json:"bucket"`
			Key       string `json:"key"`
			SHA256    string `json:"sha256"`
			RepoName  string `json:"repoName"`
			RepoURL   string `json:"repoUrl"`
			GitRef    string `json:"gitRef"`
			CommitSHA string `json:"commitSha"`
			SizeBytes int64  `json:"sizeBytes"`
			FileCount int    `json:"fileCount"`
		} `json:"sourceRef"`
		SbomRef *struct {
			Bucket             string `json:"bucket"`
			Key                string `json:"key"`
			Digest             string `json:"digest"`
			SpecVersion        string `json:"specVersion"`
			ComponentCount     int    `json:"componentCount"`
			VulnerabilityCount int    `json:"vulnerabilityCount"`
			GeneratedAt        string `json:"generatedAt"`
		} `json:"sbomRef"`
		AIReport *struct {
			Quality          string `json:"quality"`
			ReleaseDecision  string `json:"releaseDecision"`
			ExecutiveSummary string `json:"executiveSummary"`
			ModelID          string `json:"modelId"`
			ProviderMode     string `json:"providerMode"`
			PrivacyMode      string `json:"privacyMode"`
		} `json:"aiReport"`
		Gate *struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
			NodeID string `json:"nodeId"`
		} `json:"gate"`
		Stats *struct {
			Total       int    `json:"total"`
			NewCount    int    `json:"newCount"`
			Critical    int    `json:"critical"`
			High        int    `json:"high"`
			Medium      int    `json:"medium"`
			Low         int    `json:"low"`
			SecretCount int    `json:"secretCount"`
			SastCount   int    `json:"sastCount"`
			ScaCount    int    `json:"scaCount"`
			MaxSeverity string `json:"maxSeverity"`
		} `json:"stats"`
		Vars map[string]string `json:"vars"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return vars
	}
	if env.Vars != nil {
		if id := env.Vars["runId"]; id != "" && vars["run.id"] == "" {
			vars["run.id"] = id
			vars["runId"] = id
		}
		for k, v := range env.Vars {
			if !strings.HasPrefix(k, "_") {
				vars["envelope.vars."+k] = v
			}
		}
	}
	if env.Trigger != nil {
		setIfNonEmpty(vars, "trigger.type", env.Trigger.Type)
		setIfNonEmpty(vars, "trigger.repoUrl", env.Trigger.RepoURL)
		setIfNonEmpty(vars, "trigger.branch", env.Trigger.Branch)
		setIfNonEmpty(vars, "trigger.commitSha", env.Trigger.CommitSHA)
		if env.Trigger.PRNumber != nil {
			vars["trigger.prNumber"] = strconv.Itoa(*env.Trigger.PRNumber)
		}
		setIfNonEmpty(vars, "trigger.gitProvider", env.Trigger.GitProvider)
		setIfNonEmpty(vars, "trigger.deliveryId", env.Trigger.DeliveryID)
		setIfNonEmpty(vars, "trigger.triggeredBy", env.Trigger.TriggeredBy)
		setIfNonEmpty(vars, "trigger.commitStatusUrl", env.Trigger.CommitStatusURL)
		setIfNonEmpty(vars, "trigger.triggeredAt", env.Trigger.TriggeredAt)
	}
	if env.SourceRef != nil {
		setIfNonEmpty(vars, "envelope.sourceRef.sourceId", env.SourceRef.SourceID)
		setIfNonEmpty(vars, "envelope.sourceRef.bucket", env.SourceRef.Bucket)
		setIfNonEmpty(vars, "envelope.sourceRef.key", env.SourceRef.Key)
		setIfNonEmpty(vars, "envelope.sourceRef.sha256", env.SourceRef.SHA256)
		setIfNonEmpty(vars, "envelope.sourceRef.repoName", env.SourceRef.RepoName)
		setIfNonEmpty(vars, "envelope.sourceRef.repoUrl", env.SourceRef.RepoURL)
		setIfNonEmpty(vars, "envelope.sourceRef.gitRef", env.SourceRef.GitRef)
		setIfNonEmpty(vars, "envelope.sourceRef.commitSha", env.SourceRef.CommitSHA)
		vars["envelope.sourceRef.sizeBytes"] = strconv.FormatInt(env.SourceRef.SizeBytes, 10)
		vars["envelope.sourceRef.fileCount"] = strconv.Itoa(env.SourceRef.FileCount)
	}
	if env.SbomRef != nil {
		setIfNonEmpty(vars, "envelope.sbomRef.bucket", env.SbomRef.Bucket)
		setIfNonEmpty(vars, "envelope.sbomRef.key", env.SbomRef.Key)
		setIfNonEmpty(vars, "envelope.sbomRef.digest", env.SbomRef.Digest)
		setIfNonEmpty(vars, "envelope.sbomRef.specVersion", env.SbomRef.SpecVersion)
		vars["envelope.sbomRef.componentCount"] = strconv.Itoa(env.SbomRef.ComponentCount)
		vars["envelope.sbomRef.vulnerabilityCount"] = strconv.Itoa(env.SbomRef.VulnerabilityCount)
		setIfNonEmpty(vars, "envelope.sbomRef.generatedAt", env.SbomRef.GeneratedAt)
	}
	if env.Gate != nil {
		setIfNonEmpty(vars, "envelope.gate.status", env.Gate.Status)
		setIfNonEmpty(vars, "envelope.gate.reason", env.Gate.Reason)
		setIfNonEmpty(vars, "envelope.gate.nodeId", env.Gate.NodeID)
		setIfNonEmpty(vars, "gate.status", env.Gate.Status)
		setIfNonEmpty(vars, "gate.reason", env.Gate.Reason)
	}
	if env.Stats != nil {
		vars["envelope.stats.total"] = strconv.Itoa(env.Stats.Total)
		vars["envelope.stats.newCount"] = strconv.Itoa(env.Stats.NewCount)
		vars["envelope.stats.newVsBaselineCount"] = strconv.Itoa(env.Stats.NewCount)
		vars["envelope.stats.critical"] = strconv.Itoa(env.Stats.Critical)
		vars["envelope.stats.high"] = strconv.Itoa(env.Stats.High)
		vars["envelope.stats.medium"] = strconv.Itoa(env.Stats.Medium)
		vars["envelope.stats.low"] = strconv.Itoa(env.Stats.Low)
		vars["envelope.stats.secretCount"] = strconv.Itoa(env.Stats.SecretCount)
		vars["envelope.stats.sastCount"] = strconv.Itoa(env.Stats.SastCount)
		vars["envelope.stats.scaCount"] = strconv.Itoa(env.Stats.ScaCount)
		vars["envelope.stats.maxSeverity"] = env.Stats.MaxSeverity
	}
	if env.AIReport != nil {
		setIfNonEmpty(vars, "ai.quality", env.AIReport.Quality)
		setIfNonEmpty(vars, "ai.releaseDecision", env.AIReport.ReleaseDecision)
		setIfNonEmpty(vars, "ai.decision", env.AIReport.ReleaseDecision)
		setIfNonEmpty(vars, "ai.executiveSummary", env.AIReport.ExecutiveSummary)
		setIfNonEmpty(vars, "ai.summary", env.AIReport.ExecutiveSummary)
		setIfNonEmpty(vars, "ai.modelId", env.AIReport.ModelID)
		setIfNonEmpty(vars, "ai.providerMode", env.AIReport.ProviderMode)
		setIfNonEmpty(vars, "ai.privacyMode", env.AIReport.PrivacyMode)
	}
	if explainRaw := strings.TrimSpace(env.Vars["explain"]); explainRaw != "" {
		var aiDoc struct {
			Quality          string `json:"quality"`
			ReleaseDecision  string `json:"releaseDecision"`
			ExecutiveSummary string `json:"executiveSummary"`
			Explain          string `json:"explain"`
			ModelID          string `json:"modelId"`
			ProviderMode     string `json:"providerMode"`
			PrivacyMode      string `json:"privacyMode"`
		}
		if json.Unmarshal([]byte(explainRaw), &aiDoc) == nil {
			if vars["ai.quality"] == "" {
				setIfNonEmpty(vars, "ai.quality", aiDoc.Quality)
			}
			if vars["ai.releaseDecision"] == "" {
				setIfNonEmpty(vars, "ai.releaseDecision", aiDoc.ReleaseDecision)
				setIfNonEmpty(vars, "ai.decision", aiDoc.ReleaseDecision)
			}
			summary := aiDoc.ExecutiveSummary
			if summary == "" {
				summary = aiDoc.Explain
			}
			if vars["ai.executiveSummary"] == "" {
				setIfNonEmpty(vars, "ai.executiveSummary", summary)
				setIfNonEmpty(vars, "ai.summary", summary)
			}
			if vars["ai.modelId"] == "" {
				setIfNonEmpty(vars, "ai.modelId", aiDoc.ModelID)
			}
			if vars["ai.providerMode"] == "" {
				setIfNonEmpty(vars, "ai.providerMode", aiDoc.ProviderMode)
			}
			if vars["ai.privacyMode"] == "" {
				setIfNonEmpty(vars, "ai.privacyMode", aiDoc.PrivacyMode)
			}
		} else if vars["ai.executiveSummary"] == "" {
			vars["ai.executiveSummary"] = explainRaw
			vars["ai.summary"] = explainRaw
		}
	}
	return vars
}

func setIfNonEmpty(dst map[string]string, k, v string) {
	if v != "" {
		dst[k] = v
	}
}
