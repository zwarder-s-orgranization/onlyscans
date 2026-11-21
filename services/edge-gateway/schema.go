package main

import (
	"os"
	"path/filepath"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

func loadSchema() (*ast.Schema, error) {
	raw, err := os.ReadFile(schemaPath())
	if err != nil {
		return nil, err
	}
	return gqlparser.LoadSchema(&ast.Source{Name: "schema.graphqls", Input: string(raw)})
}

func schemaPath() string {
	if p := os.Getenv("GRAPHQL_SCHEMA"); p != "" {
		return p
	}
	if _, err := os.Stat("/schema.graphqls"); err == nil {
		return "/schema.graphqls"
	}
	dir, _ := os.Getwd()
	for {
		candidate := filepath.Join(dir, "packages", "graphql", "schema.graphqls")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "schema.graphqls"
		}
		dir = parent
	}
}
