// Package report builds submission.json from the immutable Run Findings ledger.
package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const maxLineSpan = 14

var (
	relativePathRe = regexp.MustCompile(`^[^/:\\][^:]*$`)
	dotDotSegRe    = regexp.MustCompile(`(^|[\\/])\.\.([\\/]|$)`)
	advisoryIDRe   = regexp.MustCompile(`^(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$`)
)

// Finding is the submission shape. Empty optional fields are omitted.
type Finding struct {
	Category    string `json:"category"`
	Path        string `json:"path"`
	Class       string `json:"class,omitempty"`
	Line        int    `json:"line,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	Group       string `json:"group,omitempty"`
	Artifact    string `json:"artifact,omitempty"`
	Version     string `json:"version,omitempty"`
	AdvisoryID  string `json:"advisoryId,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type codeOrSecretSubmission struct {
	Category    string `json:"category"`
	Path        string `json:"path"`
	Class       string `json:"class"`
	Line        int    `json:"line"`
	EndLine     int    `json:"endLine,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type scaSubmission struct {
	Category    string `json:"category"`
	Path        string `json:"path"`
	Group       string `json:"group"`
	Artifact    string `json:"artifact"`
	Version     string `json:"version"`
	AdvisoryID  string `json:"advisoryId"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// SubmissionJSON renders {"findings":[...]} strictly compliant with
// packages/contracts/schemas/submission-report.schema.json.
// SCA findings never serialize "line", "endLine", or "class"; SECRET/SAST
// findings validate relative POSIX paths, line >= 1, endLine >= line, and
// clamp endLine <= line + 14.
func SubmissionJSON(findings []Finding) ([]byte, error) {
	items := make([]any, 0, len(findings))
	for i, f := range findings {
		entry, err := normalizeFinding(f)
		if err != nil {
			return nil, fmt.Errorf("finding[%d]: %w", i, err)
		}
		items = append(items, entry)
	}
	body := struct {
		Findings []any `json:"findings"`
	}{Findings: items}
	return json.Marshal(body)
}

func normalizeFinding(f Finding) (any, error) {
	category := strings.ToUpper(strings.TrimSpace(f.Category))
	path, err := validateRelativePath(f.Path)
	if err != nil {
		return nil, err
	}
	severity, err := validateSeverity(f.Severity)
	if err != nil {
		return nil, err
	}
	description := strings.TrimSpace(f.Description)
	remediation := strings.TrimSpace(f.Remediation)

	switch category {
	case "SECRET", "SAST":
		class := strings.TrimSpace(f.Class)
		if class == "" {
			return nil, fmt.Errorf("%s finding requires non-empty class", category)
		}
		if f.Line < 1 {
			return nil, fmt.Errorf("%s finding line must be >= 1, got %d", category, f.Line)
		}
		endLine := f.EndLine
		if endLine != 0 {
			if endLine < f.Line {
				return nil, fmt.Errorf("%s finding endLine (%d) < line (%d)", category, endLine, f.Line)
			}
			if endLine > f.Line+maxLineSpan {
				endLine = f.Line + maxLineSpan
			}
		}
		return codeOrSecretSubmission{
			Category:    category,
			Path:        path,
			Class:       class,
			Line:        f.Line,
			EndLine:     endLine,
			Severity:    severity,
			Description: description,
			Remediation: remediation,
		}, nil

	case "SCA":
		group := strings.TrimSpace(f.Group)
		artifact := strings.TrimSpace(f.Artifact)
		version := strings.TrimSpace(f.Version)
		advisoryID := strings.TrimSpace(f.AdvisoryID)
		if group == "" {
			return nil, fmt.Errorf("SCA finding requires non-empty group")
		}
		if artifact == "" {
			return nil, fmt.Errorf("SCA finding requires non-empty artifact")
		}
		if version == "" {
			return nil, fmt.Errorf("SCA finding requires non-empty version")
		}
		if !advisoryIDRe.MatchString(advisoryID) {
			return nil, fmt.Errorf("SCA finding advisoryId %q does not match CVE/GHSA pattern", advisoryID)
		}
		return scaSubmission{
			Category:    "SCA",
			Path:        path,
			Group:       group,
			Artifact:    artifact,
			Version:     version,
			AdvisoryID:  advisoryID,
			Severity:    severity,
			Description: description,
			Remediation: remediation,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported finding category %q", f.Category)
	}
}

func validateRelativePath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("path must be non-empty")
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, `\`) || strings.Contains(trimmed, ":") {
		return "", fmt.Errorf("path %q must be a relative POSIX path without leading slash or colon", raw)
	}
	if dotDotSegRe.MatchString(trimmed) {
		return "", fmt.Errorf("path %q must not contain '..' segments", raw)
	}
	normalized := strings.ReplaceAll(trimmed, `\`, "/")
	for strings.HasPrefix(normalized, "./") {
		normalized = strings.TrimPrefix(normalized, "./")
	}
	if normalized == "" || normalized == "." || !relativePathRe.MatchString(normalized) || dotDotSegRe.MatchString(normalized) {
		return "", fmt.Errorf("path %q is not a valid relative POSIX path", raw)
	}
	return normalized, nil
}

func validateSeverity(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return "", nil
	}
	switch s {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return s, nil
	default:
		return "", fmt.Errorf("invalid severity %q", raw)
	}
}
