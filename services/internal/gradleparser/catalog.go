package gradleparser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Advisory is one catalog record matched against a resolved dependency.
type Advisory struct {
	ID       string
	Aliases  []string
	Group    string
	Artifact string
	Severity string
	Ranges   []Range
}

// Range is an inclusive/exclusive version interval.
type Range struct {
	Lower          *string `json:"lower"`
	LowerInclusive bool    `json:"lowerInclusive"`
	Upper          string  `json:"upper"`
	UpperInclusive bool    `json:"upperInclusive"`
}

type rawRange struct {
	Lower          *string `json:"lower"`
	LowerInclusive *bool   `json:"lowerInclusive"`
	Upper          string  `json:"upper"`
	UpperInclusive *bool   `json:"upperInclusive"`
}

type rawEntry struct {
	ID             string     `json:"id"`
	Aliases        []string   `json:"aliases"`
	Group          string     `json:"group"`
	Artifact       string     `json:"artifact"`
	Severity       string     `json:"severity"`
	Ranges         []rawRange `json:"ranges"`
	AffectedRanges []rawRange `json:"affectedRanges"`
}

type catalogFile struct {
	Vulnerabilities []rawEntry `json:"vulnerabilities"`
	Advisories      []rawEntry `json:"advisories"`
}

// LoadCatalog reads a Maven vulnerability catalog JSON document from disk.
func LoadCatalog(path string) ([]Advisory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog %s: %w", path, err)
	}
	return LoadCatalogBytes(raw)
}

// LoadCatalogBytes parses a Maven vulnerability catalog JSON payload directly from memory.
// Supports both the `{vulnerabilities:[{ranges:[...]}]}` format and the
// `{advisories:[{affectedRanges:[...]}]}` schema accepted by CatalogService.
func LoadCatalogBytes(raw []byte) ([]Advisory, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty vulnerability catalog")
	}
	var doc catalogFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal vulnerability catalog: %w", err)
	}
	entries := make([]rawEntry, 0, len(doc.Vulnerabilities)+len(doc.Advisories))
	entries = append(entries, doc.Vulnerabilities...)
	entries = append(entries, doc.Advisories...)

	out := make([]Advisory, 0, len(entries))
	for _, v := range entries {
		rawRanges := v.Ranges
		if len(rawRanges) == 0 {
			rawRanges = v.AffectedRanges
		}
		ranges := make([]Range, 0, len(rawRanges))
		for _, rr := range rawRanges {
			lowerInc := true
			if rr.LowerInclusive != nil {
				lowerInc = *rr.LowerInclusive
			}
			upperInc := false
			if rr.UpperInclusive != nil {
				upperInc = *rr.UpperInclusive
			}
			ranges = append(ranges, Range{
				Lower:          rr.Lower,
				LowerInclusive: lowerInc,
				Upper:          strings.TrimSpace(rr.Upper),
				UpperInclusive: upperInc,
			})
		}
		out = append(out, Advisory{
			ID:       strings.TrimSpace(v.ID),
			Aliases:  v.Aliases,
			Group:    strings.TrimSpace(v.Group),
			Artifact: strings.TrimSpace(v.Artifact),
			Severity: strings.TrimSpace(v.Severity),
			Ranges:   ranges,
		})
	}
	return out, nil
}

// Finding is one vulnerable dependency match. AdvisoryID prefers a CVE alias.
type Finding struct {
	Group      string
	Artifact   string
	Version    string
	Path       string
	Line       int
	AdvisoryID string
	Severity   string
}

// Match returns one deduplicated finding per advisory whose range contains the dependency version.
func Match(deps []Dependency, advisories []Advisory) []Finding {
	seen := make(map[string]struct{}, len(deps))
	var out []Finding
	for _, dep := range deps {
		for _, adv := range advisories {
			if adv.Group != dep.Group || adv.Artifact != dep.Artifact {
				continue
			}
			if !affected(dep.Version, adv.Ranges) {
				continue
			}
			advID := preferCVE(adv)
			key := dep.Path + "|" + dep.Group + ":" + dep.Artifact + ":" + dep.Version + "|" + advID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Finding{
				Group: dep.Group, Artifact: dep.Artifact, Version: dep.Version,
				Path: dep.Path, Line: dep.Line,
				AdvisoryID: advID, Severity: adv.Severity,
			})
		}
	}
	return out
}

func affected(version string, ranges []Range) bool {
	for _, r := range ranges {
		if InRange(version, r.Lower, r.LowerInclusive, r.Upper, r.UpperInclusive) {
			return true
		}
	}
	return false
}

func preferCVE(a Advisory) string {
	for _, alias := range a.Aliases {
		trimmed := strings.TrimSpace(alias)
		if strings.HasPrefix(trimmed, "CVE-") {
			return trimmed
		}
	}
	return a.ID
}
