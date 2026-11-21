// Package protoconv centralizes severity, category, and enum conversions between strings and protobuf types.
package protoconv

import (
	"strings"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

// SeverityProto maps a string severity name to the protobuf Severity enum.
func SeverityProto(name string) secflowv1.Severity {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "LOW":
		return secflowv1.Severity_SEVERITY_LOW
	case "MEDIUM":
		return secflowv1.Severity_SEVERITY_MEDIUM
	case "HIGH":
		return secflowv1.Severity_SEVERITY_HIGH
	case "CRITICAL":
		return secflowv1.Severity_SEVERITY_CRITICAL
	default:
		return secflowv1.Severity_SEVERITY_UNSPECIFIED
	}
}

// SeverityName returns the short uppercase severity name (e.g. HIGH) for a protobuf Severity.
func SeverityName(sev secflowv1.Severity) string {
	name := TrimEnum(sev.String(), "SEVERITY_")
	if name == "" || name == "UNSPECIFIED" {
		return "MEDIUM"
	}
	return name
}

// SeverityRank returns a comparable numeric rank where CRITICAL > HIGH > MEDIUM > LOW > INFO.
func SeverityRank(name string) int {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// CategoryProto maps a string category name to the protobuf FindingCategory enum.
func CategoryProto(name string) secflowv1.FindingCategory {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SECRET":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SECRET
	case "SAST":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SAST
	case "SCA":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SCA
	default:
		return secflowv1.FindingCategory_FINDING_CATEGORY_UNSPECIFIED
	}
}

// CategoryName returns the short uppercase finding category name (SECRET, SCA, SAST).
func CategoryName(cat secflowv1.FindingCategory) string {
	return TrimEnum(cat.String(), "FINDING_CATEGORY_")
}

// TrimEnum strips a protobuf enum prefix from its string representation.
func TrimEnum(value, prefix string) string {
	return strings.TrimPrefix(value, prefix)
}
