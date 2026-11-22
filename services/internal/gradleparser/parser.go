package gradleparser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dependency is one resolved Maven coordinate declared in a Gradle or Maven build.
type Dependency struct {
	Group    string
	Artifact string
	Version  string
	Path     string
	Line     int
	Scope    string
	IsDev    bool
}

const scopePattern = `(?:implementation|api|runtimeOnly|compileOnly|compile|runtime|kapt|ksp|annotationProcessor|developmentOnly|providedCompile|providedRuntime|testImplementation|testApi|testRuntimeOnly|testCompileOnly|testCompile|androidTestImplementation|integrationTestImplementation|functionalTestImplementation)`

var (
	depsHeaderRe        = regexp.MustCompile(`\bdependencies\s*\{`)
	buildscriptHeaderRe = regexp.MustCompile(`\bbuildscript\s*\{`)

	depParenCall    = regexp.MustCompile(`(?m)\b(` + scopePattern + `)\s*\(\s*(?:(?:platform|enforcedPlatform|testFixtures)\s*\(\s*)?["']([^"']+)["']\s*\)?`)
	depGroovy       = regexp.MustCompile(`(?m)^\s*(` + scopePattern + `)\s+(?:(?:platform|enforcedPlatform)\s*\(\s*)?["']([^"']+)["']`)
	addCall         = regexp.MustCompile(`(?s)\badd\s*\(\s*["'](` + scopePattern + `)["']\s*,\s*["']([^"']+)["']\s*,?\s*\)`)
	depThreeArgCall = regexp.MustCompile(`(?m)\b(` + scopePattern + `)\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)`)
	depNamedArgCall = regexp.MustCompile(`(?s)\b(` + scopePattern + `)\s*\(\s*group\s*=\s*["']([^"']+)["']\s*,\s*name\s*=\s*["']([^"']+)["'](?:\s*,\s*version\s*=\s*["']([^"']*)["'])?\s*,?\s*\)`)
	depGroovyMap    = regexp.MustCompile(`(?m)\b(` + scopePattern + `)\s+group\s*:\s*["']([^"']+)["']\s*,\s*name\s*:\s*["']([^"']+)["'](?:\s*,\s*version\s*:\s*["']([^"']*)["'])?`)

	libsParenCall    = regexp.MustCompile(`(?m)\b(` + scopePattern + `)\s*\(\s*(?:(?:platform|enforcedPlatform)\s*\(\s*)?libs\.([A-Za-z0-9_.]+)\s*\)?`)
	libsGroovy       = regexp.MustCompile(`(?m)^\s*(` + scopePattern + `)\s+libs\.([A-Za-z0-9_.]+)`)
	libsAddCall      = regexp.MustCompile(`(?s)\badd\s*\(\s*["'](` + scopePattern + `)["']\s*,\s*libs\.([A-Za-z0-9_.]+)\s*,?\s*\)`)
	inlineCatalogVer = regexp.MustCompile(`\$\{libs\.versions\.([A-Za-z0-9_.]+)\.get\(\)\}`)

	valLit         = regexp.MustCompile(`(?m)\b(?:val|var|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*["']([^"']*)["']`)
	valGradleProp  = regexp.MustCompile(`(?m)\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?=\s*providers\.gradleProperty\(\s*["']([^"']+)["']\s*\)\.(?:get\(\)|orNull)`)
	valFindProp    = regexp.MustCompile(`(?m)\b(?:val|var|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?=\s*(?:project\.)?(?:findProperty|property)\(\s*["']([^"']+)["']\s*\)`)
	valByProject   = regexp.MustCompile(`(?m)\bval\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?\s+by\s+project\b`)
	valByExtra     = regexp.MustCompile(`(?m)\bval\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?\s+by\s+extra\b(?:\(\s*["']([^"']*)["']\s*\))?`)
	extraBracket   = regexp.MustCompile(`(?m)\bextra\[\s*["']([^"']+)["']\s*\]\s*=\s*["']([^"']*)["']`)
	extraSetCall   = regexp.MustCompile(`(?m)\bextra\.set\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']\s*\)`)
	extDotAssign   = regexp.MustCompile(`(?m)\bext\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']*)["']`)
	extBlockRe     = regexp.MustCompile(`(?s)\bext\s*\{([^}]*)\}`)
	extBlockKVRe   = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']*)["']`)
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

// ParseProject reads Gradle (build.gradle.kts / build.gradle, gradle.properties,
// gradle/libs.versions.toml, gradle.lockfile) and/or Maven (pom.xml) build files
// across the root and nested submodules, keeping paths relative to root.
func ParseProject(root string) ([]Dependency, error) {
	projects, err := gradleProjects(root)
	if err != nil {
		return nil, err
	}
	mavenDeps, mavenCount, mavenErr := parseMavenProjects(root)
	if mavenErr != nil {
		return nil, mavenErr
	}
	if len(projects) == 0 && mavenCount == 0 {
		return nil, fmt.Errorf("read gradle/maven build file in %s: %w", root, os.ErrNotExist)
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
	all = append(all, mavenDeps...)
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
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
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
		if !d.Type().IsRegular() {
			return nil
		}
		if d.Name() != "build.gradle.kts" && d.Name() != "build.gradle" {
			return nil
		}
		dir := filepath.Dir(p)
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
	case ".git", ".gradle", "build", "node_modules", ".idea", "target":
		return true
	default:
		return false
	}
}

type depBlock struct {
	content   string
	startLine int
}

func parseBuildFile(root, projectDir, buildName string) ([]Dependency, error) {
	buildPath := filepath.Join(projectDir, buildName)
	raw, err := readRegularFile(buildPath)
	if err != nil {
		return nil, fmt.Errorf("read gradle build file in %s: %w", projectDir, err)
	}
	text := stripCommentsPreserveLines(string(raw))

	props := readProperties(filepath.Join(root, "gradle.properties"))
	if projectDir != root {
		for k, v := range readProperties(filepath.Join(projectDir, "gradle.properties")) {
			props[k] = v
		}
	}
	vars := extractVars(text, props)
	catalog := readVersionCatalog(filepath.Join(projectDir, "gradle", "libs.versions.toml"))
	if len(catalog.libs) == 0 && len(catalog.versions) == 0 && projectDir != root {
		catalog = readVersionCatalog(filepath.Join(root, "gradle", "libs.versions.toml"))
	}
	locked := readLockfile(root, projectDir)

	blocks := dependenciesBlocks(text)
	if len(blocks) == 0 {
		return nil, nil
	}

	var deps []Dependency
	indexByKey := make(map[string]int)

	addDep := func(scope, g, a, v, relPath string, absLine int) {
		g = strings.TrimSpace(g)
		a = strings.TrimSpace(a)
		v = strings.TrimSpace(v)
		if g == "" || a == "" {
			return
		}
		// Resolve versionless (BOM-managed) or locked version via gradle.lockfile
		if lv, ok := locked[g+":"+a]; ok && lv != "" {
			v = lv
		}
		if v == "" || strings.Contains(v, "$") {
			return
		}
		isDev := isDevScope(scope)
		key := g + ":" + a + ":" + v
		if idx, exists := indexByKey[key]; exists {
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
		resolved := resolve(coord, vars, props, catalog.versions)
		g, a, v, ok := splitCoordAllowVersionless(resolved)
		if !ok {
			return
		}
		addDep(scope, g, a, v, buildName, absLine)
	}

	for _, blk := range blocks {
		cleaned := blk.content
		blockLine := blk.startLine

		for _, re := range []*regexp.Regexp{depParenCall, depGroovy, addCall} {
			for _, m := range re.FindAllStringSubmatchIndex(cleaned, -1) {
				scope := cleaned[m[2]:m[3]]
				coord := cleaned[m[4]:m[5]]
				line := blockLine + lineAt(cleaned, m[0]) - 1
				addCoord(scope, coord, line)
			}
		}

		for _, m := range depThreeArgCall.FindAllStringSubmatchIndex(cleaned, -1) {
			scope := cleaned[m[2]:m[3]]
			g := resolve(cleaned[m[4]:m[5]], vars, props, catalog.versions)
			a := resolve(cleaned[m[6]:m[7]], vars, props, catalog.versions)
			v := resolve(cleaned[m[8]:m[9]], vars, props, catalog.versions)
			line := blockLine + lineAt(cleaned, m[0]) - 1
			addDep(scope, g, a, v, buildName, line)
		}

		for _, re := range []*regexp.Regexp{depNamedArgCall, depGroovyMap} {
			for _, m := range re.FindAllStringSubmatchIndex(cleaned, -1) {
				scope := cleaned[m[2]:m[3]]
				g := resolve(cleaned[m[4]:m[5]], vars, props, catalog.versions)
				a := resolve(cleaned[m[6]:m[7]], vars, props, catalog.versions)
				v := ""
				if m[8] >= 0 && m[9] >= 0 {
					v = resolve(cleaned[m[8]:m[9]], vars, props, catalog.versions)
				}
				line := blockLine + lineAt(cleaned, m[0]) - 1
				addDep(scope, g, a, v, buildName, line)
			}
		}

		for _, re := range []*regexp.Regexp{libsParenCall, libsGroovy, libsAddCall} {
			for _, m := range re.FindAllStringSubmatchIndex(cleaned, -1) {
				scope := cleaned[m[2]:m[3]]
				accessor := cleaned[m[4]:m[5]]
				line := blockLine + lineAt(cleaned, m[0]) - 1
				if strings.HasPrefix(accessor, "bundles.") {
					bundleKey := strings.TrimPrefix(accessor, "bundles.")
					for _, entry := range lookupCatalogBundle(catalog, bundleKey) {
						addDep(scope, entry.group, entry.artifact, entry.version, buildName, line)
					}
					continue
				}
				if entry, ok := lookupCatalogLib(catalog.libs, accessor); ok {
					addDep(scope, entry.group, entry.artifact, entry.version, buildName, line)
				}
			}
		}
	}

	return deps, nil
}

func isDevScope(scope string) bool {
	low := strings.ToLower(scope)
	return strings.HasPrefix(low, "test") || strings.Contains(low, "test") || low == "developmentonly"
}

func extractVars(text string, props map[string]string) map[string]string {
	vars := make(map[string]string, len(props)+16)
	for _, m := range valLit.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[2]
	}
	for _, m := range extraBracket.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[2]
	}
	for _, m := range extraSetCall.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[2]
	}
	for _, m := range extDotAssign.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[2]
	}
	for _, bm := range extBlockRe.FindAllStringSubmatch(text, -1) {
		for _, kv := range extBlockKVRe.FindAllStringSubmatch(bm[1], -1) {
			vars[kv[1]] = kv[2]
		}
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

// stripCommentsPreserveLines removes // line comments and /* ... */ block comments
// while preserving newlines so line numbers remain exact.
func stripCommentsPreserveLines(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	inDouble := false
	inSingle := false
	inBlock := false
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if inBlock {
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlock = false
				b.WriteString("  ")
				i++
			} else if ch == '\n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if (inDouble || inSingle) && ch == '\\' && i+1 < len(src) {
			b.WriteByte(ch)
			b.WriteByte(src[i+1])
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			b.WriteByte(ch)
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			b.WriteByte(ch)
			continue
		}
		if !inDouble && !inSingle && ch == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				for i < len(src) && src[i] != '\n' {
					b.WriteByte(' ')
					i++
				}
				if i < len(src) && src[i] == '\n' {
					b.WriteByte('\n')
				}
				continue
			}
			if src[i+1] == '*' {
				inBlock = true
				b.WriteString("  ")
				i++
				continue
			}
		}
		b.WriteByte(ch)
	}
	return b.String()
}

type catalogLib struct {
	group    string
	artifact string
	version  string
}

type versionCatalog struct {
	versions map[string]string
	libs     map[string]catalogLib
	bundles  map[string][]string
}

var (
	tomlKVRe      = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*=\s*(.+)$`)
	tomlStrRe     = regexp.MustCompile(`^["']([^"']*)["']$`)
	tomlFieldRe   = regexp.MustCompile(`([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]*)\})`)
	tomlNestedVer = regexp.MustCompile(`(?:strictly|require|prefer)\s*=\s*["']([^"']+)["']`)
	tomlQuotedRe  = regexp.MustCompile(`["']([^"']+)["']`)
)

func readVersionCatalog(path string) versionCatalog {
	cat := versionCatalog{
		versions: make(map[string]string),
		libs:     make(map[string]catalogLib),
		bundles:  make(map[string][]string),
	}
	raw, err := readRegularFile(path)
	if err != nil {
		return cat
	}
	rawLibs := make(map[string]string)
	section := ""
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripTomlComment(lines[i]))
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
		// Handle multi-line array values in [bundles]
		if section == "bundles" && strings.HasPrefix(val, "[") && !strings.Contains(val, "]") {
			var sb strings.Builder
			sb.WriteString(val)
			for i+1 < len(lines) {
				i++
				next := strings.TrimSpace(stripTomlComment(lines[i]))
				sb.WriteByte(' ')
				sb.WriteString(next)
				if strings.Contains(next, "]") {
					break
				}
			}
			val = sb.String()
		}
		switch section {
		case "versions":
			if sm := tomlStrRe.FindStringSubmatch(val); sm != nil {
				cat.versions[normalizeCatalogKey(key)] = sm[1]
				cat.versions[key] = sm[1]
			} else if strings.HasPrefix(val, "{") {
				if nm := tomlNestedVer.FindStringSubmatch(val); nm != nil {
					cat.versions[normalizeCatalogKey(key)] = nm[1]
					cat.versions[key] = nm[1]
				}
			}
		case "libraries":
			rawLibs[key] = val
		case "bundles":
			var refs []string
			for _, qm := range tomlQuotedRe.FindAllStringSubmatch(val, -1) {
				refs = append(refs, normalizeCatalogKey(qm[1]))
			}
			if len(refs) > 0 {
				cat.bundles[normalizeCatalogKey(key)] = refs
			}
		}
	}

	for alias, val := range rawLibs {
		entry, ok := parseCatalogLibValue(val, cat.versions)
		if !ok {
			continue
		}
		cat.libs[normalizeCatalogKey(alias)] = entry
	}
	return cat
}

func parseCatalogLibValue(val string, versions map[string]string) (catalogLib, bool) {
	if sm := tomlStrRe.FindStringSubmatch(val); sm != nil {
		g, a, v, ok := splitCoordAllowVersionless(sm[1])
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
			if version == "" {
				version = versions[normalizeCatalogKey(ref)]
			}
		}
	}
	if group == "" || artifact == "" {
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

func lookupCatalogBundle(cat versionCatalog, bundleAccessor string) []catalogLib {
	refs := cat.bundles[normalizeCatalogKey(bundleAccessor)]
	if len(refs) == 0 {
		return nil
	}
	out := make([]catalogLib, 0, len(refs))
	for _, ref := range refs {
		if entry, ok := cat.libs[ref]; ok {
			out = append(out, entry)
		}
	}
	return out
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

// dependenciesBlocks returns all project dependencies { ... } blocks in text,
// skipping buildscript { dependencies { ... } } blocks and respecting string quotes.
func dependenciesBlocks(text string) []depBlock {
	// Identify buildscript { ... } ranges to skip buildscript classpath blocks.
	var skipRanges [][2]int
	for _, loc := range buildscriptHeaderRe.FindAllStringIndex(text, -1) {
		bracePos := loc[1] - 1
		if endPos := findMatchingBrace(text, bracePos); endPos > bracePos {
			skipRanges = append(skipRanges, [2]int{loc[0], endPos})
		}
	}
	inSkip := func(pos int) bool {
		for _, r := range skipRanges {
			if pos >= r[0] && pos <= r[1] {
				return true
			}
		}
		return false
	}

	var blocks []depBlock
	for _, loc := range depsHeaderRe.FindAllStringIndex(text, -1) {
		if inSkip(loc[0]) {
			continue
		}
		bracePos := loc[1] - 1
		endPos := findMatchingBrace(text, bracePos)
		if endPos <= bracePos {
			continue
		}
		blocks = append(blocks, depBlock{
			content:   text[bracePos+1 : endPos],
			startLine: lineAt(text, bracePos+1),
		})
	}
	return blocks
}

func findMatchingBrace(text string, openBrace int) int {
	depth := 0
	inDouble := false
	inSingle := false
	for i := openBrace; i < len(text); i++ {
		ch := text[i]
		if (inDouble || inSingle) && ch == '\\' && i+1 < len(text) {
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if inDouble || inSingle {
			continue
		}
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
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

func resolve(coord string, vars, props, catalogVersions map[string]string) string {
	coord = inlineCatalogVer.ReplaceAllStringFunc(coord, func(m string) string {
		sub := inlineCatalogVer.FindStringSubmatch(m)
		if v, ok := catalogVersions[normalizeCatalogKey(sub[1])]; ok {
			return v
		}
		return m
	})
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

func splitCoordAllowVersionless(coord string) (string, string, string, bool) {
	parts := strings.Split(strings.TrimSpace(coord), ":")
	if len(parts) < 2 {
		return "", "", "", false
	}
	g, a := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if g == "" || a == "" || strings.Contains(g, " ") || strings.Contains(a, " ") {
		return "", "", "", false
	}
	if len(parts) == 2 {
		return g, a, "", true
	}
	// Trim optional Maven classifier/packaging suffix like `1.2.3@jar`
	ver := strings.TrimSpace(parts[2])
	if at := strings.IndexByte(ver, '@'); at >= 0 {
		ver = ver[:at]
	}
	return g, a, ver, true
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

func readLockfile(root, projectDir string) map[string]string {
	locked := map[string]string{}
	load := func(p string) {
		raw, err := readRegularFile(p)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
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
	}
	if projectDir != root {
		load(filepath.Join(root, "gradle.lockfile"))
	}
	load(filepath.Join(projectDir, "gradle.lockfile"))
	return locked
}
