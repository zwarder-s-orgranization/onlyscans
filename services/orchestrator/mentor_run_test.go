package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secflow/secflow/services/internal/engine"
)

func TestMentorRunFifteenFindings(t *testing.T) {
	root := repoRoot(t)
	project := filepath.Join(root, "tests", "data", "repos", "mentor-training", "training-project")
	catalog := filepath.Join(root, "tests", "data", "repos", "mentor-training", "vulnerability-database", "vulnerabilities.json")
	t.Setenv("SOURCE_ROOT", project)
	t.Setenv("CATALOG_PATH", catalog)
	t.Setenv("ALLOW_INPROCESS_ANALYZERS", "1")

	g := engine.Graph{
		Nodes: []engine.Node{
			{ID: "t", PluginID: "trigger.manual"},
			{ID: "s", PluginID: "source.upload"},
			{ID: "sec", PluginID: "scan.secrets"},
			{ID: "sast", PluginID: "scan.sast.kotlin"},
			{ID: "sca", PluginID: "scan.sca"},
		},
		Edges: []engine.Edge{
			{ID: "e1", Source: "t", SourceHandle: "default", Target: "s", TargetHandle: "default"},
			{ID: "e2", Source: "s", SourceHandle: "default", Target: "sec", TargetHandle: "default"},
			{ID: "e3", Source: "s", SourceHandle: "default", Target: "sast", TargetHandle: "default"},
			{ID: "e4", Source: "s", SourceHandle: "default", Target: "sca", TargetHandle: "default"},
		},
	}
	s := newServer()
	got, _, _, err := engine.Run(g, s.handlers(""), engine.Envelope{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 15 {
		t.Fatalf("findings = %d, want 15", len(got))
	}
	counts := map[string]int{}
	for _, f := range got {
		counts[f.Category]++
	}
	if counts["SECRET"] != 5 || counts["SAST"] != 5 || counts["SCA"] != 5 {
		t.Fatalf("counts = %#v", counts)
	}
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
			t.Skip("optional mentor-training fixture directory is not present")
		}
		dir = parent
	}
}
