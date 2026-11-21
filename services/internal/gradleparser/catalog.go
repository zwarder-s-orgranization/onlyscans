package gradleparser

import (
	"encoding/json"
	"fmt"
	"os"
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

// Range is an inclusive/exclusive numeric version interval.
type Range struct {
	Lower          *string `json:"lower"`
	LowerInclusive bool    `json:"lowerInclusive"`
	Upper          string  `json:"upper"`
	UpperInclusive bool    `json:"upperInclusive"`
}

type catalogFile struct {
	Vulnerabilities []struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Group    string   `json:"group"`
		Artifact string   `json:"artifact"`
		Severity string   `json:"severity"`
		Ranges   []Range  `json:"ranges"`
	} `json:"vulnerabilities"`
}

// LoadCatalog reads a mentor vulnerabilities.json document from disk.
func LoadCatalog(path string) ([]Advisory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog %s: %w", path, err)
	}
	return LoadCatalogBytes(raw)
}

// LoadCatalogBytes parses a Maven vulnerability catalog JSON payload directly from memory.
func LoadCatalogBytes(raw []byte) ([]Advisory, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty vulnerability catalog")
	}
	var doc catalogFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal vulnerability catalog: %w", err)
	}
	out := make([]Advisory, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		out = append(out, Advisory{
			ID: v.ID, Aliases: v.Aliases, Group: v.Group, Artifact: v.Artifact,
			Severity: v.Severity, Ranges: v.Ranges,
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

// Match returns one finding per advisory whose range contains the dependency version.
func Match(deps []Dependency, advisories []Advisory) []Finding {
	var out []Finding
	for _, dep := range deps {
		for _, adv := range advisories {
			if adv.Group != dep.Group || adv.Artifact != dep.Artifact {
				continue
			}
			if !affected(dep.Version, adv.Ranges) {
				continue
			}
			out = append(out, Finding{
				Group: dep.Group, Artifact: dep.Artifact, Version: dep.Version,
				Path: dep.Path, Line: dep.Line,
				AdvisoryID: preferCVE(adv), Severity: adv.Severity,
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
		if len(alias) >= 4 && alias[:4] == "CVE-" {
			return alias
		}
	}
	return a.ID
}
