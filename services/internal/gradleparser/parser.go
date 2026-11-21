package gradleparser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dependency is one resolved Maven coordinate declared in a Gradle build.
type Dependency struct {
	Group    string
	Artifact string
	Version  string
	Path     string
	Line     int
	Scope    string
	IsDev    bool
}

const scopePattern = `(?:implementation|api|runtimeOnly|compileOnly|testImplementation|testApi|testRuntimeOnly|testCompileOnly|androidTestImplementation|integrationTestImplementation|functionalTestImplementation)`

var (
	depsHeaderRe = regexp.MustCompile(`(?m)^\s*dependencies\s*\{`)

	depParenCall = regexp.MustCompile(`(?m)\b(` + scopePattern + `)\s*\(\s*["']([^"']+)["']\s*\)`)
	depGroovy    = regexp.MustCompile(`(?m)^\s*(` + scopePattern + `)\s+["']([^"']+)["']`)
	addCall      = regexp.MustCompile(`(?s)\badd\s*\(\s*["'](` + scopePattern + `)["']\s*,\s*["']([^"']+)["']\s*,?\s*\)`)

	libsParenCall = regexp.MustCompile(`(?m)\b(` + scopePattern + `)\s*\(\s*libs\.([A-Za-z0-9_.]+)\s*\)`)
	libsGroovy    = regexp.MustCompile(`(?m)^\s*(` + scopePattern + `)\s+libs\.([A-Za-z0-9_.]+)`)
	libsAddCall   = regexp.MustCompile(`(?s)\badd\s*\(\s*["'](` + scopePattern + `)["']\s*,\s*libs\.([A-Za-z0-9_.]+)\s*,?\s*\)`)

	valLit         = regexp.MustCompile(`(?m)\b(?:val|var|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*["']([^"']*)["']`)
	valGradleProp  = regexp.MustCompile(`(?m)\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?=\s*providers\.gradleProperty\(\s*["']([^"']+)["']\s*\)\.(?:get\(\)|orNull)`)
	valFindProp    = regexp.MustCompile(`(?m)\b(?:val|var|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?=\s*(?:project\.)?(?:findProperty|property)\(\s*["']([^"']+)["']\s*\)`)
	valByProject   = regexp.MustCompile(`(?m)\bval\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?\s+by\s+project\b`)
	valByExtra     = regexp.MustCompile(`(?m)\bval\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?\s+by\s+extra\b(?:\(\s*["']([^"']*)["']\s*\))?`)
	extraBracket   = regexp.MustCompile(`(?m)\bextra\[\s*["']([^"']+)["']\s*\]\s*=\s*["']([^"']*)["']`)
	interp         = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	inlineFindProp = regexp.MustCompile(`\$\{(?:project\.)?(?:findProperty|property)\(\s*["']([^"']+)["']\s*\)\}`)
	inlineGradProp = regexp.MustCompile(`\$\{providers\.gradleProperty\(\s*["']([^"']+)["']\s*\)\.(?:get\(\)|orNull)\}`)
)

const (
	maxGradleProjects = 64
	maxWalkEntries    = 5000
)

type gradleProject struct {
	dir  string
	name string
}

// ParseProject reads build.gradle.kts (or build.gradle), gradle.properties,
// gradle/libs.versions.toml, and an optional gradle.lockfile across the root
// and any nested Gradle submodules, keeping dependency paths relative to root.
func ParseProject(root string) ([]Dependency, error) {
	projects, err := gradleProjects(root)
	if err != nil {
		return nil, err
	}
	if len(projects) == 0 {
		return nil, fmt.Errorf("read gradle build file in %s: %w", root, os.ErrNotExist)
	}
	var all []Dependency
	for _, project := range projects {
		rel, relErr := filepath.Rel(root, project.dir)
		if relErr != nil || !filepath.IsLocal(rel) {
			continue
		}
		deps, err := parseBuildFile(root, project.dir, project.name)
		if err != nil {
			return nil, err
		}
		if rel != "" && rel != "." {
			prefix := filepath.ToSlash(rel)
			for i := range deps {
				deps[i].Path = prefix + "/" + filepath.ToSlash(deps[i].Path)
			}
		}
		all = append(all, deps...)
	}
	return all, nil
}

func gradleProjects(root string) ([]gradleProject, error) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		if err == nil {
			err = fmt.Errorf("not a directory")
		}
		return nil, fmt.Errorf("read gradle build file in %s: %w", root, err)
	}
	seenDirs := map[string]struct{}{}
	var projectDirs []string
	walked := 0
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		walked++
		if walked > maxWalkEntries {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if path != root && skipGradleDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if d.Name() != "build.gradle.kts" && d.Name() != "build.gradle" {
			return nil
		}
		dir := filepath.Dir(path)
		if _, exists := seenDirs[dir]; !exists {
			if len(projectDirs) >= maxGradleProjects {
				return filepath.SkipAll
			}
			seenDirs[dir] = struct{}{}
			projectDirs = append(projectDirs, dir)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read gradle build file in %s: %w", root, err)
	}
	found := make([]gradleProject, 0, len(projectDirs))
	for _, dir := range projectDirs {
		if name, ok := buildFileName(dir); ok {
			found = append(found, gradleProject{dir: dir, name: name})
		}
	}
	return found, nil
}

func isRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return os.ReadFile(path)
}

func buildFileName(dir string) (string, bool) {
	if isRegularFile(filepath.Join(dir, "build.gradle.kts")) {
		return "build.gradle.kts", true
	}
	if isRegularFile(filepath.Join(dir, "build.gradle")) {
		return "build.gradle", true
	}
	return "", false
}

func skipGradleDir(name string) bool {
	switch name {
	case ".git", ".gradle", "build", "node_modules", ".idea":
		return true
	default:
		return false
	}
}

func parseBuildFile(root, projectDir, buildName string) ([]Dependency, error) {
	buildPath := filepath.Join(projectDir, buildName)
	raw, err := readRegularFile(buildPath)
	if err != nil {
		return nil, fmt.Errorf("read gradle build file in %s: %w", projectDir, err)
	}
	text := string(raw)
	props := readProperties(filepath.Join(root, "gradle.properties"))
	if projectDir != root {
		for k, v := range readProperties(filepath.Join(projectDir, "gradle.properties")) {
			props[k] = v
		}
	}
	vars := extractVars(text, props)
	catalog := readVersionCatalog(filepath.Join(projectDir, "gradle", "libs.versions.toml"))
	if len(catalog) == 0 && projectDir != root {
		catalog = readVersionCatalog(filepath.Join(root, "gradle", "libs.versions.toml"))
	}

	block, blockLine := dependenciesBlock(text)
	if block == "" {
		return nil, nil
	}
	cleaned := stripLineComments(block)

	var deps []Dependency
	indexByKey := make(map[string]int)

	addDep := func(scope, g, a, v, relPath string, absLine int) {
		if g == "" || a == "" || v == "" || strings.Contains(v, "$") {
			return
		}
		isDev := isDevScope(scope)
		key := g + ":" + a + ":" + v
		if idx, exists := indexByKey[key]; exists {
			// If a dependency is declared in both dev and runtime scopes, prefer runtime.
			if deps[idx].IsDev && !isDev {
				deps[idx].IsDev = false
				deps[idx].Scope = scope
			}
			return
		}
		indexByKey[key] = len(deps)
		deps = append(deps, Dependency{
			Group:    g,
			Artifact: a,
			Version:  v,
			Path:     relPath,
			Line:     absLine,
			Scope:    scope,
			IsDev:    isDev,
		})
	}

	addCoord := func(scope, coord string, absLine int) {
		g, a, v, ok := splitCoord(resolve(coord, vars, props))
		if !ok {
			return
		}
		addDep(scope, g, a, v, buildName, absLine)
	}

	for _, re := range []*regexp.Regexp{depParenCall, depGroovy, addCall} {
		for _, m := range re.FindAllStringSubmatchIndex(cleaned, -1) {
			scope := cleaned[m[2]:m[3]]
			coord := cleaned[m[4]:m[5]]
			line := blockLine + lineAt(cleaned, m[0]) - 1
			addCoord(scope, coord, line)
		}
	}

	for _, re := range []*regexp.Regexp{libsParenCall, libsGroovy, libsAddCall} {
		for _, m := range re.FindAllStringSubmatchIndex(cleaned, -1) {
			scope := cleaned[m[2]:m[3]]
			accessor := cleaned[m[4]:m[5]]
			line := blockLine + lineAt(cleaned, m[0]) - 1
			if entry, ok := lookupCatalogLib(catalog, accessor); ok {
				addDep(scope, entry.group, entry.artifact, entry.version, buildName, line)
			}
		}
	}

	applyLock(root, projectDir, deps)
	return deps, nil
}

func isDevScope(scope string) bool {
	low := strings.ToLower(scope)
	return strings.HasPrefix(low, "test") || strings.Contains(low, "test")
}

func extractVars(text string, props map[string]string) map[string]string {
	vars := make(map[string]string, len(props)+8)
	for _, m := range valLit.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[2]
	}
	for _, m := range extraBracket.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[2]
	}
	for _, m := range valGradleProp.FindAllStringSubmatch(text, -1) {
		if v, ok := props[m[2]]; ok {
			vars[m[1]] = v
		}
	}
	for _, m := range valFindProp.FindAllStringSubmatch(text, -1) {
		if v, ok := props[m[2]]; ok {
			vars[m[1]] = v
		}
	}
	for _, m := range valByProject.FindAllStringSubmatch(text, -1) {
		if v, ok := props[m[1]]; ok {
			vars[m[1]] = v
		}
	}
	for _, m := range valByExtra.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if len(m) > 2 && m[2] != "" {
			vars[name] = m[2]
		} else if v, ok := props[name]; ok {
			vars[name] = v
		}
	}
	return vars
}

func stripLineComments(block string) string {
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		if idx := findCommentStart(line); idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

func findCommentStart(line string) int {
	inDouble := false
	inSingle := false
	for i := 0; i < len(line)-1; i++ {
		ch := line[i]
		if ch == '\\' && (inDouble || inSingle) {
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if !inDouble && !inSingle && ch == '/' && line[i+1] == '/' {
			return i
		}
	}
	return -1
}

type catalogLib struct {
	group    string
	artifact string
	version  string
}

var (
	tomlKVRe      = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*=\s*(.+)$`)
	tomlStrRe     = regexp.MustCompile(`^["']([^"']*)["']$`)
	tomlFieldRe   = regexp.MustCompile(`([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]*)\})`)
	tomlNestedVer = regexp.MustCompile(`(?:strictly|require|prefer)\s*=\s*["']([^"']+)["']`)
)

func readVersionCatalog(path string) map[string]catalogLib {
	raw, err := readRegularFile(path)
	if err != nil {
		return nil
	}
	versions := make(map[string]string)
	rawLibs := make(map[string]string)
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(stripTomlComment(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		m := tomlKVRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		switch section {
		case "versions":
			if sm := tomlStrRe.FindStringSubmatch(val); sm != nil {
				versions[key] = sm[1]
			} else if strings.HasPrefix(val, "{") {
				if nm := tomlNestedVer.FindStringSubmatch(val); nm != nil {
					versions[key] = nm[1]
				}
			}
		case "libraries":
			rawLibs[key] = val
		}
	}

	out := make(map[string]catalogLib, len(rawLibs))
	for alias, val := range rawLibs {
		entry, ok := parseCatalogLibValue(val, versions)
		if !ok {
			continue
		}
		out[normalizeCatalogKey(alias)] = entry
	}
	return out
}

func parseCatalogLibValue(val string, versions map[string]string) (catalogLib, bool) {
	if sm := tomlStrRe.FindStringSubmatch(val); sm != nil {
		g, a, v, ok := splitCoord(sm[1])
		if !ok {
			return catalogLib{}, false
		}
		return catalogLib{group: g, artifact: a, version: v}, true
	}
	if !strings.HasPrefix(val, "{") || !strings.HasSuffix(val, "}") {
		return catalogLib{}, false
	}
	inner := val[1 : len(val)-1]
	fields := make(map[string]string)
	for _, m := range tomlFieldRe.FindAllStringSubmatch(inner, -1) {
		k := strings.TrimSpace(m[1])
		v := m[2]
		if v == "" {
			v = m[3]
		}
		if v == "" && m[4] != "" {
			if nm := tomlNestedVer.FindStringSubmatch(m[4]); nm != nil {
				v = nm[1]
			}
		}
		fields[k] = v
	}
	var group, artifact string
	if mod := fields["module"]; mod != "" {
		g, a, ok := strings.Cut(mod, ":")
		if !ok {
			return catalogLib{}, false
		}
		group, artifact = g, a
	} else {
		group, artifact = fields["group"], fields["name"]
	}
	version := fields["version"]
	if version == "" {
		if ref := fields["version.ref"]; ref != "" {
			version = versions[ref]
		}
	}
	if group == "" || artifact == "" || version == "" {
		return catalogLib{}, false
	}
	return catalogLib{group: group, artifact: artifact, version: version}, true
}

func normalizeCatalogKey(key string) string {
	r := strings.NewReplacer("-", ".", "_", ".")
	return strings.ToLower(r.Replace(strings.TrimSpace(key)))
}

func lookupCatalogLib(catalog map[string]catalogLib, accessor string) (catalogLib, bool) {
	if len(catalog) == 0 {
		return catalogLib{}, false
	}
	entry, ok := catalog[normalizeCatalogKey(accessor)]
	return entry, ok
}

func stripTomlComment(line string) string {
	inDouble := false
	inSingle := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '\\' && inDouble {
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if !inDouble && !inSingle && ch == '#' {
			return line[:i]
		}
	}
	return line
}

func dependenciesBlock(text string) (string, int) {
	idx := -1
	if loc := depsHeaderRe.FindStringIndex(text); loc != nil {
		idx = loc[0]
	} else {
		idx = strings.Index(text, "dependencies")
	}
	if idx < 0 {
		return "", 1
	}
	rest := text[idx:]
	brace := strings.Index(rest, "{")
	if brace < 0 {
		return "", 1
	}
	depth := 0
	start := -1
	for i, r := range rest[brace:] {
		switch r {
		case '{':
			depth++
			if start < 0 {
				start = brace + i + 1
			}
		case '}':
			depth--
			if depth == 0 {
				block := rest[start : brace+i]
				return block, lineAt(text, idx+start)
			}
		}
	}
	return "", 1
}

func lineAt(text string, bytePos int) int {
	if bytePos < 0 {
		return 1
	}
	if bytePos > len(text) {
		bytePos = len(text)
	}
	return strings.Count(text[:bytePos], "\n") + 1
}

func resolve(coord string, vars, props map[string]string) string {
	coord = inlineGradProp.ReplaceAllStringFunc(coord, func(m string) string {
		sub := inlineGradProp.FindStringSubmatch(m)
		if v, ok := props[sub[1]]; ok {
			return v
		}
		return m
	})
	coord = inlineFindProp.ReplaceAllStringFunc(coord, func(m string) string {
		sub := inlineFindProp.FindStringSubmatch(m)
		if v, ok := props[sub[1]]; ok {
			return v
		}
		return m
	})
	return interp.ReplaceAllStringFunc(coord, func(m string) string {
		sub := interp.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[2]
		}
		if v, ok := vars[name]; ok {
			return v
		}
		if v, ok := props[name]; ok {
			return v
		}
		return m
	})
}

func splitCoord(coord string) (string, string, string, bool) {
	parts := strings.Split(coord, ":")
	if len(parts) < 3 {
		return "", "", "", false
	}
	version := strings.Join(parts[2:], ":")
	if version == "" || strings.Contains(version, "$") {
		return "", "", "", false
	}
	return parts[0], parts[1], version, true
}

func readProperties(path string) map[string]string {
	out := map[string]string{}
	raw, err := readRegularFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			k, v, ok = strings.Cut(line, ":")
		}
		if ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func applyLock(root, projectDir string, deps []Dependency) {
	raw, err := readRegularFile(filepath.Join(projectDir, "gradle.lockfile"))
	if err != nil && projectDir != root {
		raw, err = readRegularFile(filepath.Join(root, "gradle.lockfile"))
	}
	if err != nil {
		return
	}
	locked := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		// group:artifact:version=configurations
		left, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parts := strings.Split(left, ":")
		if len(parts) < 3 {
			continue
		}
		locked[parts[0]+":"+parts[1]] = parts[2]
	}
	for i := range deps {
		if v, ok := locked[deps[i].Group+":"+deps[i].Artifact]; ok {
			deps[i].Version = v
		}
	}
}
