package declarativeplugin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/secflow/secflow/services/internal/engine"
)

// LogicResult is the deterministic output of EvaluateLogic.
type LogicResult struct {
	ActivePorts      []string          `json:"activePorts"`
	Gate             string            `json:"gate,omitempty"`
	Vars             map[string]string `json:"vars,omitempty"`
	FilteredFindings *[]engine.Finding `json:"filteredFindings,omitempty"`
	MatchedRoute     string            `json:"matchedRoute,omitempty"`
}

// EnvelopePatchJSON serializes LogicResult into the orchestrator's externalEnvelopePatch JSON format.
func (r LogicResult) EnvelopePatchJSON() ([]byte, error) {
	patch := map[string]any{}
	if len(r.Vars) > 0 {
		patch["vars"] = r.Vars
	}
	if r.Gate != "" {
		patch["gate"] = map[string]any{
			"status": r.Gate,
			"reason": "declarative logic route: " + r.MatchedRoute,
		}
	}
	if r.FilteredFindings != nil {
		patch["findings"] = *r.FilteredFindings
	}
	return json.Marshal(patch)
}

// EvaluateLogic deterministically evaluates computedVars and ordered routes against env.
func EvaluateLogic(spec Spec, params map[string]any, env engine.Envelope) (LogicResult, error) {
	if spec.Category != CategoryLogic || spec.Logic == nil {
		return LogicResult{}, fmt.Errorf("spec %q is not a LOGIC plugin", spec.PluginID)
	}
	normEnv := env.Normalize()
	mergedParams := mergeParamDefaults(spec.Params, params)
	vars := make(map[string]string, len(normEnv.Vars)+len(spec.Logic.ComputedVars))
	for k, v := range normEnv.Vars {
		vars[k] = v
	}

	computed := make(map[string]string, len(spec.Logic.ComputedVars))
	for _, cv := range spec.Logic.ComputedVars {
		val := evalComputedVar(cv, normEnv, mergedParams, vars)
		vars[cv.Name] = val
		computed[cv.Name] = val
	}

	for _, route := range spec.Logic.Routes {
		if matchRoute(route, normEnv, mergedParams, vars) {
			outVars := make(map[string]string, len(computed)+len(route.SetVars))
			for k, v := range computed {
				outVars[k] = v
			}
			for k, tmpl := range route.SetVars {
				outVars[k] = interpolateSimple(tmpl, mergedParams, &normEnv, vars, nil)
			}
			var filtered *[]engine.Finding
			if route.FilterFindings != nil {
				f := filterEnvelopeFindings(normEnv.Findings, *route.FilterFindings)
				filtered = &f
			}
			name := route.Name
			if name == "" {
				name = route.OutputPort
			}
			return LogicResult{
				ActivePorts:      []string{route.OutputPort},
				Gate:             strings.ToUpper(strings.TrimSpace(route.Gate)),
				Vars:             outVars,
				FilteredFindings: filtered,
				MatchedRoute:     name,
			}, nil
		}
	}

	outVars := make(map[string]string, len(computed)+len(spec.Logic.FallbackVars))
	for k, v := range computed {
		outVars[k] = v
	}
	for k, tmpl := range spec.Logic.FallbackVars {
		outVars[k] = interpolateSimple(tmpl, mergedParams, &normEnv, vars, nil)
	}
	return LogicResult{
		ActivePorts:  []string{spec.Logic.FallbackPort},
		Gate:         strings.ToUpper(strings.TrimSpace(spec.Logic.FallbackGate)),
		Vars:         outVars,
		MatchedRoute: "fallback:" + spec.Logic.FallbackPort,
	}, nil
}

func evalComputedVar(cv ComputedVar, env engine.Envelope, params map[string]any, vars map[string]string) string {
	switch cv.Kind {
	case ComputedWeightedScore:
		score := env.Stats.Critical*cv.CriticalWeight +
			env.Stats.High*cv.HighWeight +
			env.Stats.Medium*cv.MediumWeight +
			env.Stats.Low*cv.LowWeight
		return strconv.Itoa(score)
	case ComputedFindingCount:
		count := 0
		for _, f := range env.Findings {
			if cv.FilterCategory != "" && !strings.EqualFold(f.Category, cv.FilterCategory) {
				continue
			}
			if cv.FilterSeverity != "" && !strings.EqualFold(f.Severity, cv.FilterSeverity) {
				continue
			}
			if cv.FilterRuleID != "" && !strings.EqualFold(f.Class, cv.FilterRuleID) {
				continue
			}
			count++
		}
		return strconv.Itoa(count)
	case ComputedTemplate:
		return interpolateSimple(cv.Template, params, &env, vars, nil)
	default:
		return ""
	}
}

func matchRoute(route LogicRoute, env engine.Envelope, params map[string]any, vars map[string]string) bool {
	if len(route.Conditions) == 0 {
		return true
	}
	anyMode := strings.EqualFold(strings.TrimSpace(route.MatchMode), "ANY")
	for _, cond := range route.Conditions {
		actual := resolveLogicField(cond.Field, env, params, vars)
		expected := interpolateSimple(cond.Value, params, &env, vars, nil)
		ok := evalCondition(actual, cond.Operator, expected)
		if anyMode && ok {
			return true
		}
		if !anyMode && !ok {
			return false
		}
	}
	return !anyMode
}

func resolveLogicField(field string, env engine.Envelope, params map[string]any, vars map[string]string) string {
	f := strings.TrimSpace(field)
	switch f {
	case "stats.total":
		return strconv.Itoa(env.Stats.Total)
	case "stats.critical":
		return strconv.Itoa(env.Stats.Critical)
	case "stats.high":
		return strconv.Itoa(env.Stats.High)
	case "stats.medium":
		return strconv.Itoa(env.Stats.Medium)
	case "stats.low":
		return strconv.Itoa(env.Stats.Low)
	case "gate", "gate.status":
		if env.Gate != nil {
			return env.Gate.Status
		}
		return ""
	}
	if key, ok := strings.CutPrefix(f, "vars."); ok {
		return vars[key]
	}
	if key, ok := strings.CutPrefix(f, "params."); ok {
		if v, exists := params[key]; exists && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	return ""
}

func evalCondition(actual, op, expected string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "eq", "==":
		if a, b, ok := parseNumPair(actual, expected); ok {
			return a == b
		}
		return strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expected))
	case "neq", "!=":
		if a, b, ok := parseNumPair(actual, expected); ok {
			return a != b
		}
		return !strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expected))
	case "gt", ">":
		a, b, ok := parseNumPair(actual, expected)
		return ok && a > b
	case "gte", ">=":
		a, b, ok := parseNumPair(actual, expected)
		return ok && a >= b
	case "lt", "<":
		a, b, ok := parseNumPair(actual, expected)
		return ok && a < b
	case "lte", "<=":
		a, b, ok := parseNumPair(actual, expected)
		return ok && a <= b
	case "contains":
		return strings.Contains(strings.ToLower(actual), strings.ToLower(expected))
	case "matches":
		if len(expected) > MaxRegexLength {
			return false
		}
		re, err := regexp.Compile(expected)
		if err != nil {
			return false
		}
		return re.MatchString(actual)
	default:
		return false
	}
}

func parseNumPair(a, b string) (float64, float64, bool) {
	af, errA := strconv.ParseFloat(strings.TrimSpace(a), 64)
	bf, errB := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if errA != nil || errB != nil {
		return 0, 0, false
	}
	return af, bf, true
}

func filterEnvelopeFindings(findings []engine.Finding, ff FindingFilter) []engine.Finding {
	minRank := severityRank(ff.MinSeverity)
	catSet := map[string]bool{}
	for _, c := range ff.Categories {
		catSet[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	out := make([]engine.Finding, 0, len(findings))
	for _, f := range findings {
		if minRank > 0 && severityRank(f.Severity) < minRank {
			continue
		}
		if len(catSet) > 0 && !catSet[strings.ToUpper(strings.TrimSpace(f.Category))] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return 0
	}
}
