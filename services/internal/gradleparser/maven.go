package gradleparser

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type mavenPOM struct {
	Parent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	GroupID              string        `xml:"groupId"`
	ArtifactID           string        `xml:"artifactId"`
	Version              string        `xml:"version"`
	Properties           mavenPropsXML `xml:"properties"`
	DependencyManagement struct {
		Dependencies []mavenDep `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Dependencies []mavenDep `xml:"dependencies>dependency"`
}

type mavenDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type mavenPropsXML struct {
	Entries map[string]string
}

func (m *mavenPropsXML) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	m.Entries = make(map[string]string)
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &t); err != nil {
				return err
			}
			m.Entries[t.Name.Local] = strings.TrimSpace(val)
		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		}
	}
}

var mavenPropRefRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func parseMavenProjects(root string) ([]Dependency, int, error) {
	var pomPaths []string
	walked := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		walked++
		if walked > maxWalkEntries {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p != root && skipGradleDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || d.Name() != "pom.xml" {
			return nil
		}
		if len(pomPaths) >= maxGradleProjects {
			return filepath.SkipAll
		}
		pomPaths = append(pomPaths, p)
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("walk maven projects in %s: %w", root, err)
	}
	if len(pomPaths) == 0 {
		return nil, 0, nil
	}

	// Read root pom.xml properties and dependencyManagement first for child inheritance.
	rootProps := map[string]string{}
	rootManaged := map[string]string{}
	if rawRoot, err := readRegularFile(filepath.Join(root, "pom.xml")); err == nil {
		if rootPom, perr := decodePOM(rawRoot); perr == nil {
			rootProps = buildMavenProps(rootPom, nil)
			for _, d := range rootPom.DependencyManagement.Dependencies {
				g := resolveMavenExpr(strings.TrimSpace(d.GroupID), rootProps)
				a := resolveMavenExpr(strings.TrimSpace(d.ArtifactID), rootProps)
				v := resolveMavenExpr(strings.TrimSpace(d.Version), rootProps)
				if g != "" && a != "" && v != "" && !strings.Contains(v, "$") {
					rootManaged[g+":"+a] = v
				}
			}
		}
	}

	var all []Dependency
	for _, pomPath := range pomPaths {
		raw, err := readRegularFile(pomPath)
		if err != nil {
			continue
		}
		pom, err := decodePOM(raw)
		if err != nil {
			continue
		}
		rel, relErr := filepath.Rel(root, pomPath)
		if relErr != nil || !filepath.IsLocal(rel) {
			continue
		}
		relSlash := filepath.ToSlash(rel)

		props := buildMavenProps(pom, rootProps)
		managed := make(map[string]string, len(rootManaged)+len(pom.DependencyManagement.Dependencies))
		for k, v := range rootManaged {
			managed[k] = v
		}
		for _, d := range pom.DependencyManagement.Dependencies {
			g := resolveMavenExpr(strings.TrimSpace(d.GroupID), props)
			a := resolveMavenExpr(strings.TrimSpace(d.ArtifactID), props)
			v := resolveMavenExpr(strings.TrimSpace(d.Version), props)
			if g != "" && a != "" && v != "" && !strings.Contains(v, "$") {
				managed[g+":"+a] = v
			}
		}

		indexByKey := map[string]int{}
		var deps []Dependency
		for _, d := range pom.Dependencies {
			g := resolveMavenExpr(strings.TrimSpace(d.GroupID), props)
			a := resolveMavenExpr(strings.TrimSpace(d.ArtifactID), props)
			v := resolveMavenExpr(strings.TrimSpace(d.Version), props)
			if v == "" {
				v = managed[g+":"+a]
			}
			if g == "" || a == "" || v == "" || strings.Contains(v, "$") {
				continue
			}
			scope := strings.TrimSpace(d.Scope)
			if scope == "" {
				scope = "compile"
			}
			isDev := strings.EqualFold(scope, "test")
			key := g + ":" + a + ":" + v
			if idx, exists := indexByKey[key]; exists {
				if deps[idx].IsDev && !isDev {
					deps[idx].IsDev = false
					deps[idx].Scope = scope
				}
				continue
			}
			indexByKey[key] = len(deps)
			deps = append(deps, Dependency{
				Group:    g,
				Artifact: a,
				Version:  v,
				Path:     relSlash,
				Line:     findMavenDepLine(string(raw), a),
				Scope:    scope,
				IsDev:    isDev,
			})
		}
		all = append(all, deps...)
	}
	return all, len(pomPaths), nil
}

func decodePOM(raw []byte) (mavenPOM, error) {
	var pom mavenPOM
	if err := xml.Unmarshal(raw, &pom); err != nil {
		return pom, err
	}
	return pom, nil
}

func buildMavenProps(pom mavenPOM, inherited map[string]string) map[string]string {
	props := make(map[string]string, len(inherited)+len(pom.Properties.Entries)+6)
	for k, v := range inherited {
		props[k] = v
	}
	if v := strings.TrimSpace(pom.Parent.Version); v != "" {
		props["project.parent.version"] = v
		props["parent.version"] = v
	}
	if g := strings.TrimSpace(pom.Parent.GroupID); g != "" {
		props["project.parent.groupId"] = g
	}
	ver := strings.TrimSpace(pom.Version)
	if ver == "" {
		ver = strings.TrimSpace(pom.Parent.Version)
	}
	if ver != "" {
		props["project.version"] = ver
		props["pom.version"] = ver
	}
	grp := strings.TrimSpace(pom.GroupID)
	if grp == "" {
		grp = strings.TrimSpace(pom.Parent.GroupID)
	}
	if grp != "" {
		props["project.groupId"] = grp
		props["pom.groupId"] = grp
	}
	for k, v := range pom.Properties.Entries {
		props[k] = v
	}
	// Resolve chained property references up to 3 passes
	for pass := 0; pass < 3; pass++ {
		changed := false
		for k, v := range props {
			resolved := resolveMavenExpr(v, props)
			if resolved != v {
				props[k] = resolved
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return props
}

func resolveMavenExpr(s string, props map[string]string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return mavenPropRefRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := mavenPropRefRe.FindStringSubmatch(m)
		if v, ok := props[strings.TrimSpace(sub[1])]; ok {
			return v
		}
		return m
	})
}

func findMavenDepLine(raw, artifact string) int {
	needle := "<artifactId>" + artifact + "</artifactId>"
	for idx, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, needle) {
			return idx + 1
		}
	}
	return 1
}
