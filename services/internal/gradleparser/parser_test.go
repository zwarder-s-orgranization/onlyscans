package gradleparser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrainingProjectSCA(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	deps, err := ParseProject(filepath.Join(root, "tests", "data", "repos", "mentor-training", "training-project"))
	if err != nil {
		t.Fatal(err)
	}
	advisories, err := LoadCatalog(filepath.Join(root, "tests", "data", "repos", "mentor-training", "vulnerability-database", "vulnerabilities.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := Match(deps, advisories)
	want := []struct{ g, a, v, id string }{
		{"org.apache.commons", "commons-text", "1.9", "CVE-2022-42889"},
		{"org.jsoup", "jsoup", "1.14.1", "CVE-2021-37714"},
		{"org.apache.commons", "commons-compress", "1.25.0", "CVE-2024-25710"},
		{"commons-net", "commons-net", "3.8.0", "CVE-2021-37533"},
		{"org.json", "json", "20230227", "CVE-2023-5072"},
	}
	for _, w := range want {
		if !has(findings, w.g, w.a, w.v, w.id) {
			t.Errorf("missing %s:%s:%s %s", w.g, w.a, w.v, w.id)
		}
	}
	for _, f := range findings {
		if f.Artifact == "commons-lang3" {
			t.Errorf("false positive on commons-lang3 %s %s", f.Version, f.AdvisoryID)
		}
	}
}

func TestParseProject_VersionCatalogAndPropertyBindingsAndScopes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "gradle"), 0o755); err != nil {
		t.Fatal(err)
	}

	props := "jsoupVer=1.14.1\nbyProjVer=1.25.0\nextraVer=3.8.0\n"
	if err := os.WriteFile(filepath.Join(dir, "gradle.properties"), []byte(props), 0o600); err != nil {
		t.Fatal(err)
	}

	toml := `[versions]
commonsText = "1.9"
junit = "5.10.2"

[libraries]
commons-text = { module = "org.apache.commons:commons-text", version.ref = "commonsText" }
json-lib = { group = "org.json", name = "json", version = "20230227" }
junit-jupiter = { group = "org.junit.jupiter", name = "junit-jupiter", version.ref = "junit" }
`
	if err := os.WriteFile(filepath.Join(dir, "gradle", "libs.versions.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	build := `
val jsoupVersion = findProperty("jsoupVer") as String
val byProjVer: String by project
val extraVer: String by extra

dependencies {
    implementation(libs.commons.text)
    api(libs.json.lib)
    implementation("org.jsoup:jsoup:$jsoupVersion")
    runtimeOnly("org.apache.commons:commons-compress:${byProjVer}")
    implementation("commons-net:commons-net:$extraVer")
    testImplementation(libs.junit.jupiter)
    testImplementation("org.mockito:mockito-core:5.11.0")
    // implementation("org.ignored:commented:1.0.0")
}
`
	if err := os.WriteFile(filepath.Join(dir, "build.gradle.kts"), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}

	deps, err := ParseProject(dir)
	if err != nil {
		t.Fatalf("ParseProject() error = %v", err)
	}

	type wantDep struct {
		group    string
		artifact string
		version  string
		isDev    bool
	}
	want := []wantDep{
		{"org.apache.commons", "commons-text", "1.9", false},
		{"org.json", "json", "20230227", false},
		{"org.jsoup", "jsoup", "1.14.1", false},
		{"org.apache.commons", "commons-compress", "1.25.0", false},
		{"commons-net", "commons-net", "3.8.0", false},
		{"org.junit.jupiter", "junit-jupiter", "5.10.2", true},
		{"org.mockito", "mockito-core", "5.11.0", true},
	}

	if len(deps) != len(want) {
		t.Fatalf("deps count = %d (%+v), want %d", len(deps), deps, len(want))
	}
	byKey := make(map[string]Dependency, len(deps))
	for _, d := range deps {
		byKey[d.Group+":"+d.Artifact] = d
	}
	for _, w := range want {
		got, ok := byKey[w.group+":"+w.artifact]
		if !ok {
			t.Errorf("missing dependency %s:%s", w.group, w.artifact)
			continue
		}
		if got.Version != w.version {
			t.Errorf("%s:%s version = %q, want %q", w.group, w.artifact, got.Version, w.version)
		}
		if got.IsDev != w.isDev {
			t.Errorf("%s:%s isDev = %v, want %v (scope=%q)", w.group, w.artifact, got.IsDev, w.isDev, got.Scope)
		}
	}
}

func TestLoadCatalogBytes(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"vulnerabilities":[{"id":"GHSA-599f-7c49-w659","aliases":["CVE-2022-42889"],"group":"org.apache.commons","artifact":"commons-text","severity":"CRITICAL","ranges":[{"lower":"1.5","lowerInclusive":true,"upper":"1.10.0","upperInclusive":false}]}]}`)
	advs, err := LoadCatalogBytes(raw)
	if err != nil {
		t.Fatalf("LoadCatalogBytes() error = %v", err)
	}
	if len(advs) != 1 || advs[0].Group != "org.apache.commons" || advs[0].Artifact != "commons-text" {
		t.Fatalf("unexpected advisories: %+v", advs)
	}
	if _, err := LoadCatalogBytes(nil); err == nil {
		t.Fatal("expected error for empty bytes")
	}
}

func TestParseProject_NestedGradleProject(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	project := filepath.Join(root, "training-project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	build := `
dependencies {
    implementation("org.jsoup:jsoup:1.14.1")
}
`
	if err := os.WriteFile(filepath.Join(project, "build.gradle.kts"), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}

	deps, err := ParseProject(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %+v", deps)
	}
	if deps[0].Path != "training-project/build.gradle.kts" {
		t.Fatalf("path = %q", deps[0].Path)
	}
	if deps[0].Artifact != "jsoup" || deps[0].Version != "1.14.1" {
		t.Fatalf("dep = %+v", deps[0])
	}
}

func TestParseProject_MultiModuleRootAndSubmodules(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatal(err)
	}

	rootBuild := `
dependencies {
    implementation("org.apache.commons:commons-text:1.9")
}
`
	appBuild := `
dependencies {
    implementation("org.jsoup:jsoup:1.14.1")
}
`
	// core has both build.gradle and build.gradle.kts; kts must win.
	coreGroovy := `
dependencies {
    implementation("org.ignored:groovy-only:0.0.1")
}
`
	coreKts := `
dependencies {
    implementation("org.json:json:20230227")
}
`
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte(rootBuild), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "build.gradle.kts"), []byte(appBuild), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coreDir, "build.gradle"), []byte(coreGroovy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coreDir, "build.gradle.kts"), []byte(coreKts), 0o600); err != nil {
		t.Fatal(err)
	}

	deps, err := ParseProject(root)
	if err != nil {
		t.Fatalf("ParseProject() error = %v", err)
	}

	got := map[string]Dependency{}
	for _, d := range deps {
		got[d.Group+":"+d.Artifact] = d
	}
	if len(got) != 3 {
		t.Fatalf("deps = %+v, want 3 dependencies across root + app + core", deps)
	}
	if d := got["org.apache.commons:commons-text"]; d.Path != "build.gradle.kts" || d.Version != "1.9" {
		t.Errorf("root dep = %+v", d)
	}
	if d := got["org.jsoup:jsoup"]; d.Path != "app/build.gradle.kts" || d.Version != "1.14.1" {
		t.Errorf("app dep = %+v", d)
	}
	if d := got["org.json:json"]; d.Path != "core/build.gradle.kts" || d.Version != "20230227" {
		t.Errorf("core dep = %+v", d)
	}
}

func TestParseProject_SubmoduleInheritsRootCatalogPropertiesAndLockfile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(filepath.Join(root, "gradle"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte("plugins {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "gradle.properties"), []byte("rootProp=1.14.1\noverrideProp=1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "gradle.properties"), []byte("overrideProp=3.8.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	toml := `[versions]
commonsText = "1.9"

[libraries]
commons-text = { module = "org.apache.commons:commons-text", version.ref = "commonsText" }
`
	if err := os.WriteFile(filepath.Join(root, "gradle", "libs.versions.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "gradle.lockfile"), []byte("org.json:json:20230227=compileClasspath\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	appBuild := `
val rootProp: String by project
val overrideProp: String by project

dependencies {
    implementation(libs.commons.text)
    implementation("org.jsoup:jsoup:$rootProp")
    implementation("commons-net:commons-net:$overrideProp")
    implementation("org.json:json:20220924")
}
`
	if err := os.WriteFile(filepath.Join(appDir, "build.gradle.kts"), []byte(appBuild), 0o600); err != nil {
		t.Fatal(err)
	}

	deps, err := ParseProject(root)
	if err != nil {
		t.Fatalf("ParseProject() error = %v", err)
	}
	byKey := map[string]Dependency{}
	for _, d := range deps {
		byKey[d.Group+":"+d.Artifact] = d
	}
	want := map[string]string{
		"org.apache.commons:commons-text": "1.9",
		"org.jsoup:jsoup":                 "1.14.1",
		"commons-net:commons-net":         "3.8.0",
		"org.json:json":                   "20230227",
	}
	for k, wantVer := range want {
		d, ok := byKey[k]
		if !ok {
			t.Errorf("missing dependency %s in %+v", k, deps)
			continue
		}
		if d.Version != wantVer {
			t.Errorf("%s version = %q, want %q", k, d.Version, wantVer)
		}
		if d.Path != "app/build.gradle.kts" {
			t.Errorf("%s path = %q, want app/build.gradle.kts", k, d.Path)
		}
	}
}

func TestParseProject_RejectsSymlinkAndDirNamedBuildFile(t *testing.T) {
	t.Parallel()

	// Directory named build.gradle.kts must not be treated as a build file.
	dirRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirRoot, "build.gradle.kts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProject(dirRoot); err == nil {
		t.Fatal("expected error when only a directory named build.gradle.kts exists")
	}

	// Symlink build.gradle.kts must be ignored/rejected.
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.kts")
	if err := os.WriteFile(target, []byte("dependencies {\n implementation(\"org.evil:leak:1.0.0\")\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkRoot := t.TempDir()
	if err := os.Symlink(target, filepath.Join(linkRoot, "build.gradle.kts")); err != nil {
		t.Skipf("os.Symlink not permitted in this environment: %v", err)
	}
	if _, ok := buildFileName(linkRoot); ok {
		t.Fatal("buildFileName accepted symlink build.gradle.kts")
	}
	if _, err := ParseProject(linkRoot); err == nil {
		t.Fatal("ParseProject accepted symlink build.gradle.kts")
	}
}

func has(fs []Finding, g, a, v, id string) bool {
	for _, f := range fs {
		if f.Group == g && f.Artifact == a && f.Version == v && f.AdvisoryID == id {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "tests", "data", "repos", "mentor-training")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("tests/data/repos/mentor-training not found")
		}
		dir = parent
	}
}
