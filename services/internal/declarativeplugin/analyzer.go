package declarativeplugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

// EvaluateAnalyzer runs all deterministic ANALYZER rules in spec over files.
func EvaluateAnalyzer(
	ctx context.Context,
	spec Spec,
	params map[string]any,
	files []VirtualFile,
	sourceNodeID string,
) ([]*secflowv1.Finding, error) {
	if spec.Category != CategoryAnalyzer || spec.Analyzer == nil {
		return nil, fmt.Errorf("spec %q is not an ANALYZER", spec.PluginID)
	}
	mergedParams := mergeParamDefaults(spec.Params, params)
	var out []*secflowv1.Finding

	for _, rule := range spec.Analyzer.Rules {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if rule.EnabledParam != "" {
			if enabled, ok := toBoolParam(mergedParams[rule.EnabledParam]); ok && !enabled {
				continue
			}
		}
		sev := resolveSeverity(rule.Severity, mergedParams)
		cat := findingCategoryProto(rule.Category)

		excludes := make([]*regexp.Regexp, 0, len(rule.ExcludePatterns))
		for _, ep := range rule.ExcludePatterns {
			re, err := regexp.Compile(ep)
			if err != nil {
				return nil, fmt.Errorf("compile excludePattern for %s: %w", rule.RuleID, err)
			}
			excludes = append(excludes, re)
		}

		matchedCount := 0
		switch rule.MatcherType {
		case MatcherFilePresence:
			var matchedPaths []string
			for _, f := range files {
				norm := normalizeRelPath(f.Path)
				if matchesGlobs(norm, rule.IncludeGlobs, rule.ExcludeGlobs) {
					matchedPaths = append(matchedPaths, norm)
				}
			}
			if rule.PresenceMode == PresenceAbsent && len(matchedPaths) == 0 {
				target := strings.Join(rule.IncludeGlobs, ", ")
				out = append(out, buildFinding(spec.PluginID, sourceNodeID, rule, cat, sev, target, 1, "missing required file: "+target))
			} else if rule.PresenceMode == PresenceExists {
				for _, p := range matchedPaths {
					if matchedCount >= MaxMatchesPerRule {
						break
					}
					out = append(out, buildFinding(spec.PluginID, sourceNodeID, rule, cat, sev, p, 1, "prohibited file present: "+p))
					matchedCount++
				}
			}

		case MatcherRegex:
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("compile regex for %s: %w", rule.RuleID, err)
			}
			for _, f := range files {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if matchedCount >= MaxMatchesPerRule {
					break
				}
				if len(f.Content) > MaxScannedFileBytes {
					continue
				}
				norm := normalizeRelPath(f.Path)
				if !matchesGlobs(norm, rule.IncludeGlobs, rule.ExcludeGlobs) {
					continue
				}
				if rule.Multiline {
					locs := re.FindAllStringIndex(f.Content, MaxMatchesPerRule-matchedCount)
					for _, loc := range locs {
						snippet := f.Content[loc[0]:loc[1]]
						lineNum := 1 + strings.Count(f.Content[:loc[0]], "\n")
						if matchesAnyRegex(snippet, excludes) {
							continue
						}
						out = append(out, buildFinding(spec.PluginID, sourceNodeID, rule, cat, sev, norm, lineNum, maskSnippet(rule.Category, snippet, re)))
						matchedCount++
					}
					continue
				}
				lines := strings.Split(f.Content, "\n")
				for idx, line := range lines {
					if matchedCount >= MaxMatchesPerRule {
						break
					}
					if !re.MatchString(line) || matchesAnyRegex(line, excludes) {
						continue
					}
					out = append(out, buildFinding(spec.PluginID, sourceNodeID, rule, cat, sev, norm, idx+1, maskSnippet(rule.Category, strings.TrimSpace(line), re)))
					matchedCount++
				}
			}

		case MatcherConfigKey:
			var valRe *regexp.Regexp
			if rule.ConfigValuePattern != "" {
				var err error
				valRe, err = regexp.Compile(rule.ConfigValuePattern)
				if err != nil {
					return nil, fmt.Errorf("compile configValuePattern for %s: %w", rule.RuleID, err)
				}
			}
			for _, f := range files {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if matchedCount >= MaxMatchesPerRule {
					break
				}
				if len(f.Content) > MaxScannedFileBytes {
					continue
				}
				norm := normalizeRelPath(f.Path)
				if !matchesGlobs(norm, rule.IncludeGlobs, rule.ExcludeGlobs) {
					continue
				}
				entries := extractConfigEntries(norm, f.Content)
				for _, entry := range entries {
					if matchedCount >= MaxMatchesPerRule {
						break
					}
					if !strings.EqualFold(entry.Key, rule.ConfigKey) {
						continue
					}
					if valRe != nil && !valRe.MatchString(entry.Value) {
						continue
					}
					if matchesAnyRegex(entry.Value, excludes) || matchesAnyRegex(entry.RawLine, excludes) {
						continue
					}
					snip := entry.Key + " = " + entry.Value
					if rule.Category == "SECRET" {
						snip = entry.Key + " = ***"
					}
					out = append(out, buildFinding(spec.PluginID, sourceNodeID, rule, cat, sev, norm, entry.Line, snip))
					matchedCount++
				}
			}
		}
	}
	return out, nil
}

type configEntry struct {
	Key     string
	Value   string
	Line    int
	RawLine string
}

func extractConfigEntries(relPath, content string) []configEntry {
	lower := strings.ToLower(relPath)
	switch {
	case strings.HasSuffix(lower, ".properties"):
		return parsePropertiesEntries(content)
	case strings.HasSuffix(lower, ".json"):
		return parseJSONEntries(content)
	case strings.HasSuffix(lower, ".yml"), strings.HasSuffix(lower, ".yaml"):
		return parseYAMLEntries(content)
	default:
		if strings.HasPrefix(strings.TrimSpace(content), "{") {
			return parseJSONEntries(content)
		}
		if entries := parseYAMLEntries(content); len(entries) > 0 {
			return entries
		}
		return parsePropertiesEntries(content)
	}
}

func parsePropertiesEntries(content string) []configEntry {
	var out []configEntry
	for idx, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		sep := strings.IndexAny(line, "=:")
		if sep <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:sep])
		v := strings.Trim(strings.TrimSpace(line[sep+1:]), `"'`)
		out = append(out, configEntry{Key: k, Value: v, Line: idx + 1, RawLine: line})
	}
	return out
}

func parseJSONEntries(content string) []configEntry {
	var root any
	if err := json.Unmarshal([]byte(content), &root); err != nil {
		return nil
	}
	var out []configEntry
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch cur := v.(type) {
		case map[string]any:
			for k, child := range cur {
				next := k
				if prefix != "" {
					next = prefix + "." + k
				}
				walk(next, child)
			}
		case []any:
			parts := make([]string, 0, len(cur))
			for _, elem := range cur {
				parts = append(parts, fmt.Sprint(elem))
			}
			out = append(out, configEntry{Key: prefix, Value: strings.Join(parts, ","), Line: findKeyLine(content, prefix), RawLine: prefix})
		default:
			if prefix != "" {
				out = append(out, configEntry{Key: prefix, Value: fmt.Sprint(cur), Line: findKeyLine(content, prefix), RawLine: fmt.Sprint(cur)})
			}
		}
	}
	walk("", root)
	return out
}

func parseYAMLEntries(content string) []configEntry {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	var out []configEntry
	var walk func(prefix string, node *yaml.Node)
	walk = func(prefix string, node *yaml.Node) {
		if node == nil {
			return
		}
		switch node.Kind {
		case yaml.DocumentNode:
			for _, child := range node.Content {
				walk(prefix, child)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				k := strings.TrimSpace(node.Content[i].Value)
				next := k
				if prefix != "" {
					next = prefix + "." + k
				}
				walk(next, node.Content[i+1])
			}
		case yaml.SequenceNode:
			parts := make([]string, 0, len(node.Content))
			for _, elem := range node.Content {
				parts = append(parts, elem.Value)
			}
			out = append(out, configEntry{Key: prefix, Value: strings.Join(parts, ","), Line: max(1, node.Line), RawLine: strings.Join(parts, ",")})
		case yaml.ScalarNode:
			if prefix != "" {
				out = append(out, configEntry{Key: prefix, Value: node.Value, Line: max(1, node.Line), RawLine: node.Value})
			}
		}
	}
	walk("", &doc)
	return out
}

func findKeyLine(content, dottedKey string) int {
	leaf := dottedKey
	if i := strings.LastIndexByte(dottedKey, '.'); i >= 0 {
		leaf = dottedKey[i+1:]
	}
	for idx, line := range strings.Split(content, "\n") {
		if strings.Contains(line, leaf) {
			return idx + 1
		}
	}
	return 1
}

func buildFinding(
	pluginID, sourceNodeID string,
	rule AnalyzerRule,
	cat secflowv1.FindingCategory,
	sev secflowv1.Severity,
	relPath string,
	line int,
	snippet string,
) *secflowv1.Finding {
	if line < 1 {
		line = 1
	}
	fpRaw := fmt.Sprintf("%s|%s|%s|%d", pluginID, rule.RuleID, relPath, line)
	fpHash := sha256.Sum256([]byte(fpRaw))
	fp := hex.EncodeToString(fpHash[:16])
	id := "f_" + fp[:16]
	desc := rule.Description
	if desc == "" {
		desc = rule.Title
	}
	line32 := int32(line)
	return &secflowv1.Finding{
		FindingId:     id,
		Fingerprint:   fp,
		SourceNodeId:  sourceNodeID,
		FindingClass:  rule.RuleID,
		Category:      cat,
		Severity:      sev,
		Path:          relPath,
		Line:          &line32,
		EndLine:       &line32,
		Description:   desc,
		Remediation:   rule.Remediation,
		MaskedSnippet: snippet,
		PluginId:      pluginID,
	}
}

func maskSnippet(category, snippet string, re *regexp.Regexp) string {
	s := strings.TrimSpace(snippet)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if category != "SECRET" || re == nil {
		return s
	}
	return re.ReplaceAllStringFunc(s, func(match string) string {
		if len(match) <= 6 {
			return "***"
		}
		return match[:3] + "***" + match[len(match)-2:]
	})
}

func matchesAnyRegex(s string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func normalizeRelPath(p string) string {
	clean := strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, "/")
	return clean
}

func matchesGlobs(relPath string, includes, excludes []string) bool {
	for _, ex := range excludes {
		if matchGlob(ex, relPath) {
			return false
		}
	}
	if len(includes) == 0 {
		return true
	}
	for _, inc := range includes {
		if matchGlob(inc, relPath) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, target string) bool {
	pattern = normalizeRelPath(pattern)
	target = normalizeRelPath(target)
	if pattern == "" || pattern == "*" || pattern == "**" || pattern == "**/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(target, pattern)
	}
	if !strings.Contains(pattern, "**") {
		if ok, err := path.Match(pattern, target); err == nil && ok {
			return true
		}
		if !strings.Contains(pattern, "/") {
			if ok, err := path.Match(pattern, path.Base(target)); err == nil && ok {
				return true
			}
		}
		return false
	}
	// Convert ** glob to linear-time RE2 expression.
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		if strings.HasPrefix(pattern[i:], "**/") {
			b.WriteString("(?:.*/)?")
			i += 3
		} else if strings.HasPrefix(pattern[i:], "**") {
			b.WriteString(".*")
			i += 2
		} else if pattern[i] == '*' {
			b.WriteString("[^/]*")
			i++
		} else if pattern[i] == '?' {
			b.WriteString("[^/]")
			i++
		} else {
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			i++
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(target)
}

func mergeParamDefaults(defs []ParamField, overrides map[string]any) map[string]any {
	out := make(map[string]any, len(defs)+len(overrides))
	for _, d := range defs {
		if d.Default != nil {
			out[d.Key] = d.Default
		}
	}
	for k, v := range overrides {
		if v != nil {
			out[k] = v
		}
	}
	return out
}

func resolveSeverity(expr string, params map[string]any) secflowv1.Severity {
	resolved := interpolateSimple(expr, params, nil, nil, nil)
	switch strings.ToUpper(strings.TrimSpace(resolved)) {
	case "CRITICAL":
		return secflowv1.Severity_SEVERITY_CRITICAL
	case "HIGH":
		return secflowv1.Severity_SEVERITY_HIGH
	case "MEDIUM":
		return secflowv1.Severity_SEVERITY_MEDIUM
	case "LOW":
		return secflowv1.Severity_SEVERITY_LOW
	default:
		return secflowv1.Severity_SEVERITY_HIGH
	}
}

func findingCategoryProto(cat string) secflowv1.FindingCategory {
	switch strings.ToUpper(strings.TrimSpace(cat)) {
	case "SECRET":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SECRET
	case "SCA":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SCA
	default:
		return secflowv1.FindingCategory_FINDING_CATEGORY_SAST
	}
}

func toBoolParam(v any) (bool, bool) {
	switch val := v.(type) {
	case bool:
		return val, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(val))
		return b, err == nil
	default:
		return false, false
	}
}
