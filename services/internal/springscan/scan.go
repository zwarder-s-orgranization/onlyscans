// Package springscan finds open actuator exposure and plaintext datasource passwords.
package springscan

import (
	"os"
	"path/filepath"
	"strings"
)

// Finding is a config hardening result. Secret values are not copied.
type Finding struct {
	Path        string
	Line        int
	Class       string
	Description string
}

// Scan walks YAML and properties files.
func Scan(root string) []Finding {
	if root == "" {
		return nil
	}
	var out []Finding
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.Contains(name, "application") {
			return nil
		}
		if !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".properties")) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out = append(out, inspect(filepath.ToSlash(rel), string(raw))...)
		return nil
	})
	return out
}

func inspect(path, text string) []Finding {
	var out []Finding
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		low := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(low, "management.endpoints") && strings.Contains(low, "*") {
			out = append(out, Finding{Path: path, Line: i + 1, Class: "actuator-exposure", Description: "Actuator endpoints are exposed with a wildcard"})
		}
		if strings.Contains(low, "exposure:") && i+1 < len(lines) && strings.Contains(lines[i+1], "*") && strings.Contains(text, "management") {
			out = append(out, Finding{Path: path, Line: i + 2, Class: "actuator-exposure", Description: "Actuator endpoints are exposed with a wildcard"})
		}
		if strings.Contains(low, "password") && strings.Contains(low, ":") {
			value := strings.TrimSpace(line[strings.Index(line, ":")+1:])
			value = strings.Trim(value, `"' `)
			if value != "" && !strings.HasPrefix(value, "${") && !strings.HasPrefix(value, "#") {
				out = append(out, Finding{Path: path, Line: i + 1, Class: "plaintext-password", Description: "Datasource password is stored in the clear"})
			}
		}
		if strings.Contains(low, "password=") {
			value := strings.TrimSpace(line[strings.Index(strings.ToLower(line), "password=")+len("password="):])
			if value != "" && !strings.HasPrefix(value, "${") {
				out = append(out, Finding{Path: path, Line: i + 1, Class: "plaintext-password", Description: "Datasource password is stored in the clear"})
			}
		}
	}
	return dedupe(out)
}

func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range in {
		key := f.Path + ":" + f.Class
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
