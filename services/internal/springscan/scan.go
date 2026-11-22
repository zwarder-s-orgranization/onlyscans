// Package springscan finds open Spring Boot Actuator exposure and plaintext
// passwords across Spring configuration files (YAML and .properties) using
// structural YAML AST parsing and properties key/value inspection.
package springscan

import (
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Finding is a config hardening result. Secret values are not copied.
type Finding struct {
	Path        string
	Line        int
	Class       string
	Description string
}

// Options configures Spring configuration hardening checks and relative path filters.
type Options struct {
	CheckActuatorExposure   bool
	CheckPlaintextPasswords bool
	IncludePaths            []string
	ExcludePaths            []string
}

// DefaultOptions returns the default springscan configuration with all checks enabled.
func DefaultOptions() Options {
	return Options{
		CheckActuatorExposure:   true,
		CheckPlaintextPasswords: true,
	}
}

// Scan walks YAML and properties files with DefaultOptions.
func Scan(root string) []Finding {
	return ScanWithOptions(root, DefaultOptions())
}

// ScanWithOptions walks YAML and properties files under root according to opts.
func ScanWithOptions(root string, opts Options) []Finding {
	if root == "" || (!opts.CheckActuatorExposure && !opts.CheckPlaintextPasswords) {
		return nil
	}
	var out []Finding
	_ = filepath.WalkDir(root, func(filePath string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.Contains(name, "application") && !strings.Contains(name, "bootstrap") {
			return nil
		}
		isYAML := strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
		isProps := strings.HasSuffix(name, ".properties")
		if !isYAML && !isProps {
			return nil
		}
		rel, relErr := filepath.Rel(root, filePath)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if !pathAllowed(relSlash, opts.IncludePaths, opts.ExcludePaths) {
			return nil
		}
		raw, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return nil
		}
		if isYAML {
			out = append(out, inspectYAML(relSlash, raw, opts)...)
		} else {
			out = append(out, inspectProperties(relSlash, string(raw), opts)...)
		}
		return nil
	})
	return out
}

func pathAllowed(relPath string, includes, excludes []string) bool {
	for _, pat := range excludes {
		if matchesPattern(relPath, pat) {
			return false
		}
	}
	if len(includes) == 0 {
		return true
	}
	for _, pat := range includes {
		if matchesPattern(relPath, pat) {
			return true
		}
	}
	return false
}

func matchesPattern(relPath, rawPattern string) bool {
	pat := filepath.ToSlash(strings.TrimSpace(rawPattern))
	pat = strings.TrimLeft(pat, "/")
	if pat == "" {
		return false
	}
	pat = path.Clean(pat)
	if pat == "" || pat == "." {
		return false
	}
	if relPath == pat || strings.HasPrefix(relPath, pat+"/") {
		return true
	}
	if ok, _ := path.Match(pat, relPath); ok {
		return true
	}
	if ok, _ := path.Match(pat, path.Base(relPath)); ok {
		return true
	}
	return false
}

var (
	placeholderEnvRe = regexp.MustCompile(`^(?:\$\{[^}:]+:?\s*\}|\$\{\{.*\}\}|\{\{.*\}\}|ENC\(.*\))$`)
	envDefaultRe     = regexp.MustCompile(`^\$\{[^}:]+:([^}]+)\}$`)
	jdbcPasswordRe   = regexp.MustCompile(`(?i)[?&;]password=([^&;\s]+)`)
)

func inspectYAML(filePath string, raw []byte, opts Options) []Finding {
	var out []Finding
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			// Fallback to properties line scan if YAML has templating syntax
			out = append(out, inspectProperties(filePath, string(raw), opts)...)
			break
		}
		walkYAMLNode(filePath, "", &doc, opts, &out)
	}
	return dedupe(out)
}

func walkYAMLNode(filePath, keyPath string, node *yaml.Node, opts Options, out *[]Finding) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walkYAMLNode(filePath, keyPath, child, opts, out)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k := strings.TrimSpace(node.Content[i].Value)
			next := k
			if keyPath != "" {
				next = keyPath + "." + k
			}
			walkYAMLNode(filePath, next, node.Content[i+1], opts, out)
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			walkYAMLNode(filePath, keyPath, item, opts, out)
		}
	case yaml.ScalarNode:
		line := node.Line
		if line < 1 {
			line = 1
		}
		checkEntry(filePath, keyPath, node.Value, line, opts, out)
	}
}

func inspectProperties(filePath, text string, opts Options) []Finding {
	var out []Finding
	for i, rawLine := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		sep := strings.IndexAny(trimmed, "=:")
		if sep <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:sep])
		val := strings.TrimSpace(trimmed[sep+1:])
		checkEntry(filePath, key, val, i+1, opts, &out)
	}
	return dedupe(out)
}

func checkEntry(filePath, keyPath, rawVal string, line int, opts Options, out *[]Finding) {
	lowKey := strings.ToLower(strings.TrimSpace(keyPath))
	val := strings.Trim(strings.TrimSpace(rawVal), `"'`)

	if opts.CheckActuatorExposure && isActuatorExposureKey(lowKey) && containsWildcardEndpoint(val) {
		*out = append(*out, Finding{
			Path:        filePath,
			Line:        line,
			Class:       "actuator-exposure",
			Description: "Actuator endpoints are exposed with a wildcard",
		})
	}

	if opts.CheckPlaintextPasswords {
		if m := jdbcPasswordRe.FindStringSubmatch(val); m != nil {
			if hasPlaintextPasswordValue(m[1]) {
				*out = append(*out, Finding{
					Path:        filePath,
					Line:        line,
					Class:       "plaintext-password",
					Description: "Datasource password is stored in the clear",
				})
				return
			}
		}
		if isPasswordLeafKey(lowKey) && hasPlaintextPasswordValue(val) {
			*out = append(*out, Finding{
				Path:        filePath,
				Line:        line,
				Class:       "plaintext-password",
				Description: "Datasource password is stored in the clear",
			})
		}
	}
}

func isActuatorExposureKey(lowKey string) bool {
	return strings.Contains(lowKey, "management.endpoints") && strings.Contains(lowKey, "exposure.include")
}

func containsWildcardEndpoint(val string) bool {
	for _, tok := range strings.Split(val, ",") {
		if strings.TrimSpace(tok) == "*" {
			return true
		}
	}
	return false
}

func isPasswordLeafKey(lowKey string) bool {
	leaf := lowKey
	if dot := strings.LastIndexByte(leaf, '.'); dot >= 0 {
		leaf = leaf[dot+1:]
	}
	if !strings.Contains(leaf, "password") && !strings.Contains(leaf, "passwd") {
		return false
	}
	norm := strings.NewReplacer("-", "", "_", "").Replace(leaf)
	for _, nonSecret := range []string{"policy", "encoder", "hash", "length", "minlength", "maxlength", "regex", "pattern", "header", "field", "param", "env", "enabled", "disabled", "expiry", "expiration", "ttl", "timeout"} {
		if len(norm) > len(nonSecret) && strings.HasSuffix(norm, nonSecret) {
			return false
		}
	}
	return true
}

func hasPlaintextPasswordValue(raw string) bool {
	value := strings.Trim(strings.TrimSpace(raw), `"' `)
	if value == "" || strings.HasPrefix(value, "#") || placeholderEnvRe.MatchString(value) {
		return false
	}
	if m := envDefaultRe.FindStringSubmatch(value); m != nil {
		value = strings.TrimSpace(m[1])
		if value == "" {
			return false
		}
	}
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		return false
	}
	low := strings.ToLower(value)
	switch low {
	case "true", "false", "null", "none", "change_me", "changeme", "placeholder", "example":
		return false
	}
	for _, ph := range []string{"change_me", "changeme", "placeholder", "your_"} {
		if strings.Contains(low, ph) {
			return false
		}
	}
	return true
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
