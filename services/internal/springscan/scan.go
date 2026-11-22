// Package springscan finds open actuator exposure and plaintext datasource passwords.
package springscan

import (
	"os"
	"path"
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
		if !strings.Contains(name, "application") {
			return nil
		}
		if !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".properties")) {
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
		out = append(out, inspectWithOptions(relSlash, string(raw), opts)...)
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

func inspectWithOptions(filePath, text string, opts Options) []Finding {
	var out []Finding
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		low := strings.ToLower(trimmed)
		if opts.CheckActuatorExposure {
			if strings.Contains(low, "management.endpoints") && strings.Contains(low, "*") {
				out = append(out, Finding{Path: filePath, Line: i + 1, Class: "actuator-exposure", Description: "Actuator endpoints are exposed with a wildcard"})
			}
			if strings.Contains(low, "exposure:") && strings.Contains(text, "management") {
				for j := i + 1; j < len(lines); j++ {
					nextTrimmed := strings.TrimSpace(lines[j])
					if nextTrimmed == "" || strings.HasPrefix(nextTrimmed, "#") {
						continue
					}
					if strings.Contains(nextTrimmed, "*") {
						out = append(out, Finding{Path: filePath, Line: j + 1, Class: "actuator-exposure", Description: "Actuator endpoints are exposed with a wildcard"})
					}
					break
				}
			}
		}
		if opts.CheckPlaintextPasswords && lineHasPlaintextPassword(low) {
			out = append(out, Finding{Path: filePath, Line: i + 1, Class: "plaintext-password", Description: "Datasource password is stored in the clear"})
		}
	}
	return dedupe(out)
}

func hasPlaintextPasswordValue(raw string) bool {
	value := strings.TrimSpace(raw)
	value = strings.Trim(value, `"' `)
	return value != "" && !strings.HasPrefix(value, "${") && !strings.HasPrefix(value, "#")
}

func lineHasPlaintextPassword(low string) bool {
	if idx := strings.Index(low, "password="); idx >= 0 {
		rawVal := low[idx+len("password="):]
		if idx > 0 && (low[idx-1] == '?' || low[idx-1] == '&') {
			if amp := strings.IndexByte(rawVal, '&'); amp >= 0 {
				rawVal = rawVal[:amp]
			}
		}
		return hasPlaintextPasswordValue(rawVal)
	}
	eqIdx := strings.IndexByte(low, '=')
	colonIdx := strings.IndexByte(low, ':')
	if eqIdx >= 0 && (colonIdx < 0 || eqIdx < colonIdx) {
		if strings.Contains(low[:eqIdx], "password") {
			return hasPlaintextPasswordValue(low[eqIdx+1:])
		}
		return false
	}
	if colonIdx >= 0 && strings.Contains(low[:colonIdx], "password") {
		return hasPlaintextPasswordValue(low[colonIdx+1:])
	}
	return false
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
