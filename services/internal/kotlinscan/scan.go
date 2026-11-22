// Package kotlinscan implements the deterministic SecFlow Kotlin/YAML/SQL
// analyzer rules for scan.secrets and scan.sast.kotlin (used as a pure-Go
// engine/fallback when the JVM Kotlin PSI engine is unavailable).
// It does not wrap Semgrep, Gitleaks, or detekt.
package kotlinscan

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// FilterOptions narrows findings according to node params (includePaths, excludePaths, enabledRules).
type FilterOptions struct {
	IncludePaths []string `json:"includePaths"`
	ExcludePaths []string `json:"excludePaths"`
	EnabledRules []string `json:"enabledRules"`
}

// FilterFindings returns findings matching IncludePaths, ExcludePaths, and EnabledRules.
func FilterFindings(findings []Finding, opts FilterOptions) []Finding {
	if len(opts.IncludePaths) == 0 && len(opts.ExcludePaths) == 0 && len(opts.EnabledRules) == 0 {
		return findings
	}
	var allowedRules map[string]struct{}
	if len(opts.EnabledRules) > 0 {
		allowedRules = make(map[string]struct{}, len(opts.EnabledRules))
		for _, r := range opts.EnabledRules {
			if k := strings.ToLower(strings.TrimSpace(r)); k != "" {
				allowedRules[k] = struct{}{}
			}
		}
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if len(allowedRules) > 0 {
			if _, ok := allowedRules[strings.ToLower(strings.TrimSpace(f.Class))]; !ok {
				continue
			}
		}
		if len(opts.IncludePaths) > 0 && !matchesAnyPath(f.Path, opts.IncludePaths) {
			continue
		}
		if len(opts.ExcludePaths) > 0 && matchesAnyPath(f.Path, opts.ExcludePaths) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func matchesAnyPath(relPath string, patterns []string) bool {
	normPath := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(relPath)), "./")
	for _, raw := range patterns {
		if matchPathPattern(normPath, raw) {
			return true
		}
	}
	return false
}

func matchPathPattern(relPath, rawPattern string) bool {
	p := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rawPattern)), "./")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return false
	}
	if relPath == p {
		return true
	}
	dirPrefix := strings.TrimSuffix(p, "/")
	if !strings.ContainsAny(dirPrefix, "*?[") && strings.HasPrefix(relPath, dirPrefix+"/") {
		return true
	}
	if strings.Contains(p, "**") {
		reStr := globToRegex(p)
		if re, err := regexp.Compile(reStr); err == nil && re.MatchString(relPath) {
			return true
		}
	}
	if ok, err := path.Match(p, relPath); err == nil && ok {
		return true
	}
	if !strings.Contains(p, "/") {
		if ok, err := path.Match(p, path.Base(relPath)); err == nil && ok {
			return true
		}
	}
	return false
}

func globToRegex(glob string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		if i+1 < len(glob) && glob[i] == '*' && glob[i+1] == '*' {
			if i+2 < len(glob) && glob[i+2] == '/' {
				b.WriteString("(?:.*/)?")
				i += 2
			} else {
				b.WriteString(".*")
				i++
			}
			continue
		}
		switch glob[i] {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		}
	}
	b.WriteString("$")
	return b.String()
}

// Finding is one deterministic analyzer result. Secret values are never copied
// into Description.
type Finding struct {
	Category    string `json:"category"`
	Class       string `json:"class"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	EndLine     int    `json:"endLine"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// Scan walks a project tree and returns SECRET and SAST findings.
func Scan(root string) ([]Finding, error) {
	var files []string
	err := filepath.WalkDir(root, func(filePath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "build" || base == ".gradle" || base == "node_modules" || base == "target" || base == ".idea" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(filePath)) {
		case ".kt", ".kts", ".yml", ".yaml", ".properties", ".sql":
			files = append(files, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	textFiles := make([]sourceFile, 0, len(files))
	for _, filePath := range files {
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return nil, err
		}
		norm := strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\r", "\n")
		textFiles = append(textFiles, sourceFile{Path: filepath.ToSlash(rel), Text: norm})
	}
	var out []Finding
	out = append(out, scanSecrets(textFiles)...)
	out = append(out, scanSAST(textFiles)...)
	return dedupeFindings(out), nil
}

func dedupeFindings(in []Finding) []Finding {
	seen := make(map[string]struct{}, len(in))
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		if f.Line < 1 {
			f.Line = 1
		}
		if f.EndLine < f.Line {
			f.EndLine = f.Line
		}
		if f.EndLine > f.Line+14 {
			f.EndLine = f.Line + 14
		}
		key := f.Category + ":" + f.Class + ":" + f.Path + ":" + intToStr(f.Line)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

type sourceFile struct {
	Path string
	Text string
}

// ============================================================================
// SECRET RULES
// ============================================================================

var (
	envOnlyRe      = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_.-]*:?\s*\}$`)
	envDefaultRe   = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_.-]*):([^}]+)\}$`)
	templateExprRe = regexp.MustCompile(`(?i)^(\$\{\{.*\}\}|\{\{.*\}\}|\$\(.*\)|%\{.*\}|ENC\(.*\)|vault:.*|aws-sm:.*|k8s:.*)$`)
	pureNumberRe   = regexp.MustCompile(`^-?\d+(?:\.\d+)?$`)
	durationRe     = regexp.MustCompile(`(?i)^\d+\s*(?:ms|s|m|h|d|ns|us)$`)
	urlWithCredsRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@`)
	jdbcPasswordRe = regexp.MustCompile(`(?i)[?&;]password=([^&;\s]+)`)

	propDeclRe       = regexp.MustCompile(`^[ \t]*(?:(?:private|internal|public|protected|override|const|open|final)\s+)*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?=\s*"([^"]*)"`)
	paramDefaultRe   = regexp.MustCompile(`(?:val|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*String\??\s*=\s*"([^"]*)"`)
	directAssignRe   = regexp.MustCompile(`^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"`)
	namedArgRe       = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"`)
	headerCallRe     = regexp.MustCompile(`\b(?:header|addHeader|set|put|add)\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)`)
	headerBracketRe  = regexp.MustCompile(`\[\s*(?:"([^"]+)"|HttpHeaders\.([A-Za-z_]+))\s*\]\s*=\s*"([^"]+)"`)
	headerToPairRe   = regexp.MustCompile(`"([^"]+)"\s+to\s+"([^"]+)"`)
	bearerLiteralRe  = regexp.MustCompile(`\b(?:setBearerAuth|bearerAuth)\s*\(\s*"([^"]+)"\s*\)`)
	basicLiteralRe   = regexp.MustCompile(`\b(?:setBasicAuth|basicAuth)\s*\(\s*"[^"]*"\s*,\s*"([^"]+)"\s*\)`)
	elvisEnvRe       = regexp.MustCompile(`(?:System\.(?:getenv|getProperty)|[A-Za-z_]*[Ee]nv[A-Za-z_]*\.getProperty)\(\s*"([^"]+)"\s*\)(?:\?\.[A-Za-z0-9_]+\([^)]*\)|\?\.[A-Za-z0-9_]+\s*\{[^}]*\})*\s*\?:\s*"([^"]+)"`)
	getOrDefEnvRe    = regexp.MustCompile(`(?:getenv\(\)|getProperties\(\)|env)\.getOrDefault\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)`)
	twoArgGetPropRe  = regexp.MustCompile(`(?:System|[A-Za-z_]*[Ee]nv[A-Za-z_]*)\.getProperty\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)`)
	ifBlankEnvRe     = regexp.MustCompile(`(?:System\.(?:getenv|getProperty)|[A-Za-z_]*[Ee]nv[A-Za-z_]*\.getProperty)\(\s*"([^"]+)"\s*\)\??\.(?:orEmpty\(\)\.)?if(?:Blank|Empty)\s*\{\s*"([^"]+)"\s*\}`)
	valueDefaultRe   = regexp.MustCompile(`@Value\(\s*"{1,3}\\?\$\{([A-Za-z_][A-Za-z0-9_.-]*):([^"}]+)\}"{1,3}\s*\)`)
	valAssignRe      = regexp.MustCompile(`^[ \t]*(?:(?:private|internal|public|protected|const)\s+)*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\??\s*)?=\s*(.+)$`)
	strLitRe         = regexp.MustCompile(`^"([^"$]*)"$`)
	listOfStrRe      = regexp.MustCompile(`^(?:listOf|arrayOf|mutableListOf)\((.+)\)$`)
	joinToStrRe      = regexp.MustCompile(`^(.+)\.joinToString\(\s*(?:"([^"]*)")?\s*\)$`)
	base64DecodeRe   = regexp.MustCompile(`Base64\.getDecoder\(\)\.decode\(\s*"([^"]+)"\s*\)`)
	templateVarRe    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	envVarAssignRe   = regexp.MustCompile(`^[ \t]*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:System\.(?:getenv|getProperty)|[A-Za-z_]*[Ee]nv[A-Za-z_]*\.getProperty)\(\s*"([^"]+)"\s*\)`)
	varElvisRe       = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\?:\s*"([^"]+)"`)
	propNameOnLineRe = regexp.MustCompile(`\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
)

var metadataSuffixes = []string{
	"headername", "header", "fieldname", "field", "paramname", "parameter", "param",
	"envvar", "envkey", "envname", "env", "propname", "property", "prop",
	"filepath", "path", "file", "location", "url", "uri", "endpoint",
	"prefix", "suffix", "label", "message", "msg", "error", "hint", "description",
	"regex", "pattern", "format", "type", "length", "minlength", "maxlength", "count",
	"timeout", "ttl", "expiry", "expiration", "lifetime", "duration", "interval",
	"algorithm", "alg", "hash", "encoder", "column", "table", "query",
	"policy", "mode", "enabled", "disabled", "provider", "issuer", "audience",
	"scopes", "scope", "realm", "granttype", "clientid", "username", "driver",
	"host", "port", "classname", "class", "cookie", "cookiename", "name",
}

var genericLeafKeys = map[string]bool{
	"value": true, "val": true, "key": true, "default": true,
	"raw": true, "literal": true, "credentials": true, "credential": true, "auth": true,
}

func scanSecrets(files []sourceFile) []Finding {
	var out []Finding
	for _, f := range files {
		low := strings.ToLower(f.Path)
		if strings.HasSuffix(low, ".md") {
			continue
		}
		switch {
		case strings.HasSuffix(low, ".kt"):
			out = append(out, secretKotlin(f)...)
		case strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml"):
			out = append(out, secretYAML(f)...)
		case strings.HasSuffix(low, ".properties"):
			out = append(out, secretProperties(f)...)
		}
	}
	return out
}

func secretKotlin(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	var out []Finding
	reported := map[int]bool{}
	envVarKeys := map[string]string{}

	for _, line := range lines {
		if m := envVarAssignRe.FindStringSubmatch(line); m != nil {
			envVarKeys[m[1]] = m[2]
		}
	}

	for i, rawLine := range lines {
		line := stripKotlinLineComment(rawLine)
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "*") {
			continue
		}
		lineNum := i + 1

		// 1. Property declarations & parameter defaults
		if m := propDeclRe.FindStringSubmatch(line); m != nil {
			name, value := m[1], m[2]
			if emitNamedSecret(&out, reported, f.Path, lineNum, name, value) {
				continue
			}
		} else if m := paramDefaultRe.FindStringSubmatch(line); m != nil {
			name, value := m[1], m[2]
			if emitNamedSecret(&out, reported, f.Path, lineNum, name, value) {
				continue
			}
		} else if m := directAssignRe.FindStringSubmatch(line); m != nil {
			name, value := m[1], m[2]
			if emitNamedSecret(&out, reported, f.Path, lineNum, name, value) {
				continue
			}
		}

		// Named args in constructor/function calls
		if !reported[lineNum] {
			for _, m := range namedArgRe.FindAllStringSubmatch(line, -1) {
				if emitNamedSecret(&out, reported, f.Path, lineNum, m[1], m[2]) {
					break
				}
			}
		}

		// Direct HTTP header / auth sinks
		if !reported[lineNum] {
			if m := headerCallRe.FindStringSubmatch(line); m != nil {
				if isAuthHeaderKey(strings.ToLower(m[1])) && secretLiteral(stripAuthSchemePrefix(m[2])) {
					out = append(out, Finding{
						Category: "SECRET", Class: "api-key", Path: f.Path, Line: lineNum, EndLine: lineNum,
						Severity:    "MEDIUM",
						Description: "Встроенный API-ключ передаётся литералом в HTTP-заголовок.",
						Remediation: "Передавать ключ через настройки окружения и маскировать его в журналах.",
					})
					reported[lineNum] = true
				}
			} else if m := headerBracketRe.FindStringSubmatch(line); m != nil {
				key := m[1]
				if key == "" {
					key = m[2]
				}
				if isAuthHeaderKey(strings.ToLower(key)) && secretLiteral(stripAuthSchemePrefix(m[3])) {
					out = append(out, Finding{
						Category: "SECRET", Class: "api-key", Path: f.Path, Line: lineNum, EndLine: lineNum,
						Severity:    "MEDIUM",
						Description: "Встроенный API-ключ передаётся литералом в HTTP-заголовок.",
						Remediation: "Передавать ключ через настройки окружения и маскировать его в журналах.",
					})
					reported[lineNum] = true
				}
			} else if m := headerToPairRe.FindStringSubmatch(line); m != nil {
				if isAuthHeaderKey(strings.ToLower(m[1])) && secretLiteral(stripAuthSchemePrefix(m[2])) {
					out = append(out, Finding{
						Category: "SECRET", Class: "api-key", Path: f.Path, Line: lineNum, EndLine: lineNum,
						Severity:    "MEDIUM",
						Description: "Встроенный API-ключ передаётся литералом в пару HTTP-заголовка.",
						Remediation: "Передавать ключ через настройки окружения и маскировать его в журналах.",
					})
					reported[lineNum] = true
				}
			} else if m := bearerLiteralRe.FindStringSubmatch(line); m != nil && secretLiteral(m[1]) {
				out = append(out, Finding{
					Category: "SECRET", Class: "api-key", Path: f.Path, Line: lineNum, EndLine: lineNum,
					Severity:    "MEDIUM",
					Description: "Встроенный Bearer-токен передаётся литералом в заголовок авторизации.",
					Remediation: "Передавать токен через настройки окружения.",
				})
				reported[lineNum] = true
			} else if m := basicLiteralRe.FindStringSubmatch(line); m != nil && secretLiteral(m[1]) {
				out = append(out, Finding{
					Category: "SECRET", Class: "password", Path: f.Path, Line: lineNum, EndLine: lineNum,
					Severity:    "HIGH",
					Description: "Встроенный пароль Basic Auth передаётся литералом.",
					Remediation: "Читать пароль из окружения или хранилища секретов.",
				})
				reported[lineNum] = true
			}
		}

		// Secret fallbacks (credential-gated to avoid FP on e.g. APP_REGION or server.port)
		enclosingName := ""
		if pm := propNameOnLineRe.FindStringSubmatch(line); pm != nil {
			enclosingName = pm[1]
		}
		if m := elvisEnvRe.FindStringSubmatch(line); m != nil {
			if (looksCredentialIdentifier(m[1]) || looksCredentialIdentifier(enclosingName)) && secretLiteral(m[2]) {
				out = append(out, fallbackFinding(f.Path, lineNum))
			}
		} else if m := getOrDefEnvRe.FindStringSubmatch(line); m != nil {
			if (looksCredentialIdentifier(m[1]) || looksCredentialIdentifier(enclosingName)) && secretLiteral(m[2]) {
				out = append(out, fallbackFinding(f.Path, lineNum))
			}
		} else if m := twoArgGetPropRe.FindStringSubmatch(line); m != nil {
			if (looksCredentialIdentifier(m[1]) || looksCredentialIdentifier(enclosingName)) && secretLiteral(m[2]) {
				out = append(out, fallbackFinding(f.Path, lineNum))
			}
		} else if m := ifBlankEnvRe.FindStringSubmatch(line); m != nil {
			if (looksCredentialIdentifier(m[1]) || looksCredentialIdentifier(enclosingName)) && secretLiteral(m[2]) {
				out = append(out, fallbackFinding(f.Path, lineNum))
			}
		} else if m := varElvisRe.FindStringSubmatch(line); m != nil {
			if envKey, ok := envVarKeys[m[1]]; ok {
				if (looksCredentialIdentifier(envKey) || looksCredentialIdentifier(enclosingName)) && secretLiteral(m[2]) {
					out = append(out, fallbackFinding(f.Path, lineNum))
				}
			}
		}

		if m := valueDefaultRe.FindStringSubmatch(line); m != nil {
			propKey, defVal := m[1], strings.TrimSpace(m[2])
			targetName := enclosingName
			if targetName == "" && i+1 < len(lines) {
				if pm := propNameOnLineRe.FindStringSubmatch(lines[i+1]); pm != nil {
					targetName = pm[1]
				}
			}
			if (looksCredentialIdentifier(propKey) || looksCredentialIdentifier(targetName)) && secretLiteral(defVal) {
				out = append(out, Finding{
					Category: "SECRET", Class: "secret-fallback", Path: f.Path, Line: lineNum, EndLine: lineNum,
					Severity:    "LOW",
					Description: "Аннотация @Value содержит секретный литерал по умолчанию.",
					Remediation: "Убрать литерал по умолчанию из @Value.",
				})
			}
		}
	}

	out = append(out, recoverableTokens(f)...)
	return out
}

func emitNamedSecret(out *[]Finding, reported map[int]bool, relPath string, lineNum int, name, value string) bool {
	if reported[lineNum] || !secretLiteral(value) {
		return false
	}
	if passwordName(name) {
		*out = append(*out, Finding{
			Category: "SECRET", Class: "password", Path: relPath, Line: lineNum, EndLine: lineNum,
			Severity:    "HIGH",
			Description: "Встроенный пароль хранится строковым литералом в исходнике.",
			Remediation: "Читать пароль из окружения или хранилища секретов без литерала по умолчанию.",
		})
		reported[lineNum] = true
		return true
	}
	if apiKeyName(name) {
		*out = append(*out, Finding{
			Category: "SECRET", Class: "api-key", Path: relPath, Line: lineNum, EndLine: lineNum,
			Severity:    "MEDIUM",
			Description: "Встроенный API-ключ задан строковым литералом.",
			Remediation: "Передавать ключ через настройки окружения и маскировать его в журналах.",
		})
		reported[lineNum] = true
		return true
	}
	return false
}

func fallbackFinding(relPath string, lineNum int) Finding {
	return Finding{
		Category: "SECRET", Class: "secret-fallback", Path: relPath, Line: lineNum, EndLine: lineNum,
		Severity:    "LOW",
		Description: "При отсутствии переменной окружения используется встроенный секрет.",
		Remediation: "Удалить fallback. При отсутствии переменной отключать интеграцию.",
	}
}

func isMetadataIdentifier(name string) bool {
	norm := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(name)))
	if norm == "" {
		return false
	}
	for _, suf := range metadataSuffixes {
		if len(norm) > len(suf) && strings.HasSuffix(norm, suf) {
			return true
		}
	}
	return false
}

func passwordName(name string) bool {
	if isMetadataIdentifier(name) {
		return false
	}
	n := strings.ToLower(name)
	return strings.Contains(n, "password") || strings.Contains(n, "passwd") || n == "pwd" || strings.HasSuffix(n, "pwd") || strings.HasSuffix(n, "_pwd")
}

func apiKeyName(name string) bool {
	if isMetadataIdentifier(name) {
		return false
	}
	n := strings.ToLower(name)
	for _, kw := range []string{"apikey", "api_key", "apitoken", "api_token", "accesskey", "access_key", "secret", "authtoken", "auth_token", "bearertoken", "bearer_token", "privatekey", "private_key", "signingkey", "signing_key"} {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

func looksCredentialIdentifier(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	leaf := name
	if dot := strings.LastIndexByte(leaf, '.'); dot >= 0 {
		leaf = leaf[dot+1:]
	}
	if isMetadataIdentifier(leaf) {
		return false
	}
	low := strings.ToLower(leaf)
	for _, kw := range []string{"token", "secret", "key", "pass", "pwd", "auth", "cred", "bearer", "signing", "jwt"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func isAuthHeaderKey(keyLower string) bool {
	switch keyLower {
	case "x-api-key", "api-key", "x-auth-token", "x-access-token", "private-token", "authorization":
		return true
	}
	return strings.Contains(keyLower, "authorization") ||
		strings.Contains(keyLower, "api-key") ||
		strings.Contains(keyLower, "api_key") ||
		strings.Contains(keyLower, "x-auth") ||
		strings.Contains(keyLower, "private-token")
}

func stripAuthSchemePrefix(v string) string {
	t := strings.TrimSpace(v)
	low := strings.ToLower(t)
	for _, pref := range []string{"bearer ", "basic ", "token "} {
		if strings.HasPrefix(low, pref) {
			return strings.TrimSpace(t[len(pref):])
		}
	}
	return t
}

func secretLiteral(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < 4 {
		return false
	}
	if envOnlyRe.MatchString(v) || templateExprRe.MatchString(v) {
		return false
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return false
	}
	if strings.HasPrefix(v, "/") && !strings.Contains(v, " ") {
		return false
	}
	low := strings.ToLower(v)
	for _, ph := range []string{"change_me", "changeme", "replace_me", "replace-me", "placeholder", "example", "your_", "your-", "todo", "fixme", "dummy", "sample", "not-set", "not_set", "unset", "redact", "******", "xxxxxx"} {
		if strings.Contains(low, ph) {
			return false
		}
	}
	switch low {
	case "true", "false", "null", "none", "undefined", "empty", "bearer", "basic", "authorization", "x-api-key", "api-key", "password", "secret", "token":
		return false
	}
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		if !urlWithCredsRe.MatchString(v) {
			return false
		}
	}
	if (strings.HasPrefix(v, "X-") || strings.HasPrefix(v, "x-")) && !strings.Contains(v, " ") && !containsDigit(v) {
		return false
	}
	if !strings.HasPrefix(low, "bearer ") && !strings.HasPrefix(low, "basic ") && strings.Count(v, " ") >= 3 {
		return false
	}
	return true
}

func containsDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

type foldedVal struct {
	value    string
	start    int
	end      int
	combined bool
}

func recoverableTokens(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	consts := map[string]foldedVal{}
	lists := map[string][]foldedVal{}

	// Pass 1: collect buildString blocks and val/var string assignments.
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripKotlinLineComment(lines[i]))
		if m := valAssignRe.FindStringSubmatch(line); m != nil {
			name, expr := m[1], strings.TrimSpace(m[2])
			if strings.HasPrefix(expr, "buildString") && strings.Contains(expr, "{") {
				if fv, endIdx, ok := evalBuildStringBlock(lines, i, consts); ok {
					consts[name] = fv
					i = endIdx
					continue
				}
			}
			if fv, ok := evalGoFoldedExpr(expr, i+1, consts, lists); ok {
				consts[name] = fv
				continue
			}
			if lm := listOfStrRe.FindStringSubmatch(expr); lm != nil {
				if parts, ok := evalFoldedArgList(lm[1], i+1, consts, lists); ok && len(parts) >= 2 {
					lists[name] = parts
				}
			}
		}
	}

	var out []Finding
	seen := map[int]bool{}
	for i, rawLine := range lines {
		line := stripKotlinLineComment(rawLine)
		sinkExpr, ok := extractGoSinkExpr(line)
		if !ok {
			continue
		}
		fv, ok := evalGoFoldedExpr(sinkExpr, i+1, consts, lists)
		if !ok || !fv.combined {
			continue
		}
		if !secretLiteral(stripAuthSchemePrefix(fv.value)) {
			continue
		}
		end := i + 1
		if fv.end > end {
			end = fv.end
		}
		if seen[fv.start] {
			continue
		}
		seen[fv.start] = true
		out = append(out, Finding{
			Category: "SECRET", Class: "recoverable-token", Path: f.Path,
			Line: fv.start, EndLine: end, Severity: "MEDIUM",
			Description: "Токен собирается из строковых фрагментов в исходнике и уходит в заголовок авторизации.",
			Remediation: "Подставлять цельный токен из окружения или хранилища секретов.",
		})
	}
	return out
}

func evalBuildStringBlock(lines []string, startIdx int, consts map[string]foldedVal) (foldedVal, int, bool) {
	appendRe := regexp.MustCompile(`append\(\s*(.+?)\s*\)`)
	var sb strings.Builder
	minLine := startIdx + 1
	maxLine := startIdx + 1
	count := 0
	depth := strings.Count(lines[startIdx], "{") - strings.Count(lines[startIdx], "}")
	j := startIdx + 1
	for j < len(lines) && depth > 0 {
		l := stripKotlinLineComment(lines[j])
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if m := appendRe.FindStringSubmatch(l); m != nil {
			fv, ok := evalGoFoldedExpr(strings.TrimSpace(m[1]), j+1, consts, nil)
			if !ok {
				return foldedVal{}, j, false
			}
			sb.WriteString(fv.value)
			if fv.start < minLine {
				minLine = fv.start
			}
			maxLine = j + 1
			count++
		}
		j++
	}
	if count < 2 {
		return foldedVal{}, j - 1, false
	}
	return foldedVal{value: sb.String(), start: minLine, end: maxLine, combined: true}, j - 1, true
}

func evalFoldedArgList(inner string, lineNum int, consts map[string]foldedVal, lists map[string][]foldedVal) ([]foldedVal, bool) {
	rawParts := splitTopLevelComma(inner)
	out := make([]foldedVal, 0, len(rawParts))
	for _, p := range rawParts {
		fv, ok := evalGoFoldedExpr(strings.TrimSpace(p), lineNum, consts, lists)
		if !ok {
			return nil, false
		}
		out = append(out, fv)
	}
	return out, len(out) > 0
}

func evalGoFoldedExpr(expr string, lineNum int, consts map[string]foldedVal, lists map[string][]foldedVal) (foldedVal, bool) {
	expr = strings.TrimSpace(expr)
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	if expr == "" {
		return foldedVal{}, false
	}
	// Base64 decode
	if bm := base64DecodeRe.FindStringSubmatch(expr); bm != nil {
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bm[1])); err == nil && len(dec) > 0 {
			return foldedVal{value: string(dec), start: lineNum, end: lineNum, combined: true}, true
		}
	}
	// Pure string literal
	if sm := strLitRe.FindStringSubmatch(expr); sm != nil {
		return foldedVal{value: sm[1], start: lineNum, end: lineNum, combined: false}, true
	}
	// Variable reference
	if fv, ok := consts[expr]; ok {
		return fv, true
	}
	// joinToString
	if jm := joinToStrRe.FindStringSubmatch(expr); jm != nil {
		recv, sep := strings.TrimSpace(jm[1]), jm[2]
		var parts []foldedVal
		if lm := listOfStrRe.FindStringSubmatch(recv); lm != nil {
			var ok bool
			parts, ok = evalFoldedArgList(lm[1], lineNum, consts, lists)
			if !ok {
				return foldedVal{}, false
			}
		} else if lp, ok := lists[recv]; ok {
			parts = lp
		}
		if len(parts) >= 2 {
			var sb strings.Builder
			minL, maxL := lineNum, lineNum
			for idx, p := range parts {
				if idx > 0 {
					sb.WriteString(sep)
				}
				sb.WriteString(p.value)
				if p.start < minL {
					minL = p.start
				}
				if p.end > maxL {
					maxL = p.end
				}
			}
			return foldedVal{value: sb.String(), start: minL, end: maxL, combined: true}, true
		}
	}
	// Plus concatenation (2 or more terms)
	if plusParts := splitTopLevelPlus(expr); len(plusParts) >= 2 {
		var sb strings.Builder
		minL, maxL := lineNum, lineNum
		anyCombined := false
		for _, p := range plusParts {
			fv, ok := evalGoFoldedExpr(p, lineNum, consts, lists)
			if !ok {
				return foldedVal{}, false
			}
			sb.WriteString(fv.value)
			if fv.start < minL {
				minL = fv.start
			}
			if fv.end > maxL {
				maxL = fv.end
			}
			if fv.combined {
				anyCombined = true
			}
		}
		justScheme := len(plusParts) == 2 && !anyCombined &&
			(strings.EqualFold(strings.TrimSpace(plusParts[0]), `"Bearer "`) || strings.EqualFold(strings.TrimSpace(plusParts[0]), `"Basic "`))
		return foldedVal{value: sb.String(), start: minL, end: maxL, combined: !justScheme}, true
	}
	// String template interpolation `"$a$b"`
	if strings.HasPrefix(expr, `"`) && strings.HasSuffix(expr, `"`) && strings.Contains(expr, "$") {
		inner := expr[1 : len(expr)-1]
		minL, maxL := lineNum, lineNum
		varCount := 0
		anyCombined := false
		okAll := true
		resolved := templateVarRe.ReplaceAllStringFunc(inner, func(tok string) string {
			sub := templateVarRe.FindStringSubmatch(tok)
			name := sub[1]
			if name == "" {
				name = sub[2]
			}
			fv, ok := consts[name]
			if !ok {
				okAll = false
				return tok
			}
			if fv.start < minL {
				minL = fv.start
			}
			if fv.end > maxL {
				maxL = fv.end
			}
			if fv.combined {
				anyCombined = true
			}
			varCount++
			return fv.value
		})
		if okAll && varCount > 0 {
			combined := anyCombined || varCount >= 2
			return foldedVal{value: resolved, start: minL, end: maxL, combined: combined}, true
		}
	}
	return foldedVal{}, false
}

func extractGoSinkExpr(line string) (string, bool) {
	if idx := strings.Index(line, "setBearerAuth("); idx >= 0 {
		return extractFirstCallArg(line[idx+len("setBearerAuth("):])
	}
	if idx := strings.Index(line, "bearerAuth("); idx >= 0 {
		return extractFirstCallArg(line[idx+len("bearerAuth("):])
	}
	for _, fn := range []string{"header(", "addHeader(", "set(", "put(", "add("} {
		if idx := strings.Index(line, fn); idx >= 0 {
			args := splitTopLevelComma(extractBalancedParenBody(line[idx+len(fn):]))
			if len(args) >= 2 && isAuthHeaderKey(strings.ToLower(strings.Trim(strings.TrimSpace(args[0]), `"`))) {
				return strings.TrimSpace(args[1]), true
			}
		}
	}
	if idx := strings.Index(line, "]"); idx > 0 {
		if open := strings.LastIndex(line[:idx], "["); open >= 0 {
			key := strings.ToLower(strings.Trim(strings.TrimSpace(line[open+1:idx]), `"`))
			if isAuthHeaderKey(key) {
				rest := strings.TrimSpace(line[idx+1:])
				if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
					return strings.TrimSpace(rest[1:]), true
				}
			}
		}
	}
	return "", false
}

func extractFirstCallArg(afterOpen string) (string, bool) {
	body := extractBalancedParenBody(afterOpen)
	if body == "" {
		return "", false
	}
	args := splitTopLevelComma(body)
	if len(args) == 0 {
		return "", false
	}
	return strings.TrimSpace(args[0]), true
}

func extractBalancedParenBody(s string) string {
	depth := 1
	inStr := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && inStr {
			i++
			continue
		}
		if ch == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				return s[:i]
			}
		}
	}
	return ""
}

func splitTopLevelComma(s string) []string {
	return splitTopLevelChar(s, ',')
}

func splitTopLevelPlus(s string) []string {
	return splitTopLevelChar(s, '+')
}

func splitTopLevelChar(s string, sep byte) []string {
	var parts []string
	depth := 0
	inStr := false
	start := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && inStr {
			i++
			continue
		}
		if ch == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch ch {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if ch == sep && depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func stripKotlinLineComment(line string) string {
	inStr := false
	for i := 0; i < len(line)-1; i++ {
		if line[i] == '\\' && inStr {
			i++
			continue
		}
		if line[i] == '"' {
			inStr = !inStr
			continue
		}
		if !inStr && line[i] == '/' && line[i+1] == '/' {
			return line[:i]
		}
	}
	return line
}

// Structural YAML secret detection (multi-document via yaml.v3 AST)
func secretYAML(f sourceFile) []Finding {
	var out []Finding
	dec := yaml.NewDecoder(bytes.NewReader([]byte(f.Text)))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		walkYAMLSecretNode(f.Path, "", &doc, &out)
	}
	return out
}

func walkYAMLSecretNode(relPath, keyPath string, node *yaml.Node, out *[]Finding) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walkYAMLSecretNode(relPath, keyPath, child, out)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k := strings.TrimSpace(node.Content[i].Value)
			next := k
			if keyPath != "" {
				next = keyPath + "." + k
			}
			walkYAMLSecretNode(relPath, next, node.Content[i+1], out)
		}
	case yaml.SequenceNode:
		for idx, item := range node.Content {
			walkYAMLSecretNode(relPath, keyPath+"["+intToStr(idx)+"]", item, out)
		}
	case yaml.ScalarNode:
		line := node.Line
		if line < 1 {
			line = 1
		}
		checkConfigSecretEntry(relPath, keyPath, strings.TrimSpace(node.Value), line, out)
	}
}

func secretProperties(f sourceFile) []Finding {
	var out []Finding
	for i, rawLine := range strings.Split(f.Text, "\n") {
		trim := strings.TrimSpace(rawLine)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "!") {
			continue
		}
		sep := strings.IndexAny(trim, "=:")
		if sep <= 0 {
			continue
		}
		key := strings.TrimSpace(trim[:sep])
		val := strings.Trim(strings.TrimSpace(trim[sep+1:]), `"'`)
		checkConfigSecretEntry(f.Path, key, val, i+1, &out)
	}
	return out
}

func checkConfigSecretEntry(relPath, keyPath, value string, line int, out *[]Finding) {
	if value == "" || envOnlyRe.MatchString(value) || templateExprRe.MatchString(value) {
		return
	}
	if m := jdbcPasswordRe.FindStringSubmatch(value); m != nil {
		pwd := strings.TrimSpace(m[1])
		if !envOnlyRe.MatchString(pwd) && !templateExprRe.MatchString(pwd) && secretLiteral(pwd) {
			*out = append(*out, Finding{
				Category: "SECRET", Class: "configuration-token", Path: relPath, Line: line, EndLine: line,
				Severity:    "HIGH",
				Description: "В строке подключения конфигурации записан пароль литералом.",
				Remediation: "Передавать пароль отдельно через переменную окружения без встроенного значения.",
			})
			return
		}
	}
	if m := urlWithCredsRe.FindStringSubmatch(value); m != nil {
		pwd := strings.TrimSpace(m[1])
		if !envOnlyRe.MatchString(pwd) && !templateExprRe.MatchString(pwd) && secretLiteral(pwd) {
			*out = append(*out, Finding{
				Category: "SECRET", Class: "configuration-token", Path: relPath, Line: line, EndLine: line,
				Severity:    "HIGH",
				Description: "В URL конфигурации записаны учётные данные литералом.",
				Remediation: "Убрать пароль из URL и передавать учётные данные через переменные окружения.",
			})
			return
		}
	}

	effective := value
	if m := envDefaultRe.FindStringSubmatch(value); m != nil {
		effective = strings.TrimSpace(m[2])
	}
	if effective == "" || envOnlyRe.MatchString(effective) || templateExprRe.MatchString(effective) {
		return
	}

	lowEff := strings.ToLower(effective)
	bearerOrBasic := strings.HasPrefix(lowEff, "bearer ") || strings.HasPrefix(lowEff, "basic ")
	if bearerOrBasic {
		tok := strings.TrimSpace(effective[strings.IndexByte(effective, ' ')+1:])
		if tok == "" || envOnlyRe.MatchString(tok) || templateExprRe.MatchString(tok) || !secretLiteral(tok) {
			return
		}
	} else {
		if !configSecretKey(keyPath) {
			return
		}
		if !secretLiteral(effective) || isNonSecretConfigValue(effective) {
			return
		}
	}
	*out = append(*out, Finding{
		Category: "SECRET", Class: "configuration-token", Path: relPath, Line: line, EndLine: line,
		Severity:    "HIGH",
		Description: "В конфигурации записан токен или секрет литералом.",
		Remediation: "Задать свойство через переменную окружения без встроенного значения.",
	})
}

func isNonSecretConfigValue(value string) bool {
	v := strings.TrimSpace(value)
	switch strings.ToLower(v) {
	case "true", "false", "yes", "no", "on", "off":
		return true
	}
	if pureNumberRe.MatchString(v) && len(v) <= 6 {
		return true
	}
	return durationRe.MatchString(v)
}

func configSecretKey(keyPath string) bool {
	rawParts := strings.Split(keyPath, ".")
	parts := make([]string, 0, len(rawParts))
	for _, p := range rawParts {
		if br := strings.IndexByte(p, '['); br >= 0 {
			p = p[:br]
		}
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return false
	}
	leaf := parts[len(parts)-1]
	leafNorm := strings.NewReplacer("-", "", "_", "").Replace(leaf)
	for _, suf := range metadataSuffixes {
		if leafNorm == suf {
			return false
		}
	}
	if isMetadataIdentifier(leaf) {
		return false
	}
	secretKeywords := []string{"token", "secret", "authorization", "password", "passwd", "apikey", "api-key", "api_key", "privatekey", "private-key", "accesskey", "access-key"}
	for _, kw := range secretKeywords {
		if strings.Contains(leaf, kw) {
			return true
		}
	}
	if genericLeafKeys[leaf] && len(parts) >= 2 {
		parent := parts[len(parts)-2]
		for _, kw := range secretKeywords {
			if strings.Contains(parent, kw) {
				return true
			}
		}
	}
	return false
}

// ============================================================================
// SAST RULES
// ============================================================================

var (
	sqlVerbRe       = regexp.MustCompile(`(?i)\b(select|insert|update|delete|merge)\b`)
	sqlClauseRe     = regexp.MustCompile(`(?i)\b(from|into|set|where|values|join)\b`)
	sqlCallRe       = regexp.MustCompile(`\b(queryForList|queryForObject|queryForMap|queryForRowSet|queryForStream|query|update|batchUpdate|execute|createNativeQuery|createQuery|executeQuery|executeUpdate|prepareStatement|sql)\s*\(`)
	constValStrRe   = regexp.MustCompile(`(?m)\b(?:const\s+)?val\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*"([^"$]*)"`)
	springMapRe     = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:(?:value|path)\s*=\s*)?"([^"]+)"`)
	requestMapClsRe = regexp.MustCompile(`@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?"([^"]+)"`)
	kotlinFunRe     = regexp.MustCompile(`\bfun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	kotlinClassRe   = regexp.MustCompile(`\b(?:data\s+|open\s+|abstract\s+|internal\s+|private\s+|public\s+)*(?:class|interface)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	createTableRe   = regexp.MustCompile(`(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?["` + "`" + `\[]?([A-Za-z0-9_]+)["` + "`" + `\]]?\s*\((.*?)\)`)
	sqlTableRe      = regexp.MustCompile(`(?i)\b(?:from|update|delete\s+from)\s+["` + "`" + `\[]?([A-Za-z0-9_]+)["` + "`" + `\]]?`)
	jpaRepoRe       = regexp.MustCompile(`(?:JpaRepository|CrudRepository|PagingAndSortingRepository|ListCrudRepository|CoroutineCrudRepository)\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*,`)
	sqlCrudVerbRe   = regexp.MustCompile(`(?i)\b(select|update|delete)\b`)
	ctorParamTypeRe = regexp.MustCompile(`\b(?:private\s+|internal\s+|public\s+|protected\s+)?(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)`)
)

func scanSAST(files []sourceFile) []Finding {
	var out []Finding
	for _, f := range files {
		if !strings.HasSuffix(strings.ToLower(f.Path), ".kt") {
			continue
		}
		out = append(out, sqlInjection(f)...)
		out = append(out, tlsBypass(f)...)
		out = append(out, credentialedCORS(f)...)
	}
	secRules := collectGoSecurityRules(files)
	out = append(out, routeAuth(files, secRules)...)
	out = append(out, objectAuth(files, secRules)...)
	return out
}

func containsSQL(s string) bool {
	return sqlVerbRe.MatchString(s) && sqlClauseRe.MatchString(s)
}

func sqlInjection(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	pureConsts := map[string]bool{}
	for _, m := range constValStrRe.FindAllStringSubmatch(f.Text, -1) {
		pureConsts[m[1]] = true
	}

	dynamicVars := map[string]bool{}
	// Collect local dynamic SQL variables (including multiline triple-quoted strings + .trimIndent() + String.format + concat)
	for i := 0; i < len(lines); i++ {
		line := stripKotlinLineComment(lines[i])
		m := valAssignRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		varName, rhs := m[1], strings.TrimSpace(m[2])
		// Gather multiline triple-quoted block if started on this line
		exprText := rhs
		if strings.Count(rhs, `"""`) == 1 {
			var sb strings.Builder
			sb.WriteString(rhs)
			for j := i + 1; j < len(lines); j++ {
				sb.WriteByte('\n')
				sb.WriteString(lines[j])
				if strings.Contains(lines[j], `"""`) {
					i = j
					break
				}
			}
			exprText = sb.String()
		}
		if isGoDynamicSQLExpr(exprText, dynamicVars, pureConsts) {
			dynamicVars[varName] = true
		}
	}

	var out []Finding
	for i := 0; i < len(lines); i++ {
		line := stripKotlinLineComment(lines[i])
		loc := sqlCallRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		// Gather call span across up to 8 lines to handle multiline SQL arguments
		callChunk := line[loc[0]:]
		endLine := i + 1
		if !hasBalancedParens(callChunk) {
			var sb strings.Builder
			sb.WriteString(callChunk)
			for j := i + 1; j < len(lines) && j < i+12; j++ {
				sb.WriteByte('\n')
				sb.WriteString(stripKotlinLineComment(lines[j]))
				endLine = j + 1
				if hasBalancedParens(sb.String()) {
					break
				}
			}
			callChunk = sb.String()
		}
		openIdx := strings.IndexByte(callChunk, '(')
		if openIdx < 0 {
			continue
		}
		argBody := extractBalancedParenBody(callChunk[openIdx+1:])
		args := splitTopLevelComma(argBody)
		if len(args) == 0 {
			continue
		}
		sqlArg := strings.TrimSpace(args[0])
		if eq := strings.Index(sqlArg, "="); eq > 0 && strings.TrimSpace(sqlArg[:eq]) == "sql" {
			sqlArg = strings.TrimSpace(sqlArg[eq+1:])
		}
		if !isGoDynamicSQLExpr(sqlArg, dynamicVars, pureConsts) {
			continue
		}
		start := i + 1
		if i > 0 && strings.Contains(lines[i-1], "fun ") && strings.Contains(lines[i-1], "=") {
			start = i
		}
		out = append(out, Finding{
			Category: "SAST", Class: "sql-injection", Path: f.Path, Line: start, EndLine: endLine,
			Severity:    "HIGH",
			Description: "Параметр запроса подставляется в SQL без параметризации.",
			Remediation: "Использовать ? и передать значение отдельным аргументом.",
		})
	}
	return out
}

func hasBalancedParens(s string) bool {
	depth := 0
	seen := false
	inStr := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && inStr {
			i++
			continue
		}
		if ch == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if ch == '(' {
			depth++
			seen = true
		} else if ch == ')' {
			depth--
			if seen && depth == 0 {
				return true
			}
		}
	}
	return false
}

func isGoDynamicSQLExpr(expr string, dynamicVars, pureConsts map[string]bool) bool {
	e := strings.TrimSpace(expr)
	for _, suf := range []string{".trimIndent()", ".trimMargin()", ".trim()", ".toString()"} {
		e = strings.TrimSuffix(e, suf)
	}
	e = strings.TrimSpace(e)
	if dynamicVars[e] {
		return true
	}
	if !containsSQL(e) {
		return false
	}
	// String.format("SELECT ... %s", arg) or "...".format(arg)
	if strings.Contains(e, "String.format(") || strings.Contains(e, ".format(") {
		return true
	}
	// Interpolation: check that at least one interpolated var is NOT a pure constant
	if strings.Contains(e, "$") {
		matches := templateVarRe.FindAllStringSubmatch(e, -1)
		for _, m := range matches {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			if !pureConsts[name] {
				return true
			}
		}
		if strings.Contains(e, "${") && len(matches) == 0 {
			// Complex expression like ${req.query}
			return true
		}
	}
	// Concatenation with `+` where at least one operand is non-constant
	if parts := splitTopLevelPlus(e); len(parts) >= 2 {
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if !strLitRe.MatchString(p) && !pureConsts[p] {
				return true
			}
		}
	}
	return false
}

var (
	samHostnameRe = regexp.MustCompile(`hostnameVerifier\s*=\s*\{[^}]*->\s*true\s*\}`)
	insecureTLSRe = regexp.MustCompile(`\b(NoopHostnameVerifier|InsecureTrustManagerFactory|TrustAllStrategy)\b`)
)

func tlsBypass(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	var out []Finding
	for i := 0; i < len(lines); i++ {
		line := stripKotlinLineComment(lines[i])
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "import ") {
			continue
		}
		window := line
		endLine := i + 1
		if strings.Contains(line, "HostnameVerifier") || strings.Contains(line, "hostnameVerifier") {
			for j := i + 1; j < len(lines) && j < i+4; j++ {
				if strings.Contains(window, "}") {
					break
				}
				window += " " + stripKotlinLineComment(lines[j])
				endLine = j + 1
			}
			compact := strings.ReplaceAll(strings.ReplaceAll(window, " ", ""), "\t", "")
			if (strings.Contains(window, "HostnameVerifier") || strings.Contains(window, "hostnameVerifier")) &&
				strings.Contains(compact, "->true}") && !strings.Contains(window, "if ") && !strings.Contains(window, "when ") {
				out = append(out, Finding{
					Category: "SAST", Class: "tls-verification", Path: f.Path, Line: i + 1, EndLine: endLine,
					Severity:    "MEDIUM",
					Description: "Проверка имени хоста в TLS отключена безусловным true.",
					Remediation: "Использовать штатную проверку имени и корректный сертификат.",
				})
				continue
			}
			if samHostnameRe.MatchString(window) {
				out = append(out, Finding{
					Category: "SAST", Class: "tls-verification", Path: f.Path, Line: i + 1, EndLine: endLine,
					Severity:    "MEDIUM",
					Description: "Проверка имени хоста в TLS отключена безусловным true.",
					Remediation: "Использовать штатную проверку имени и корректный сертификат.",
				})
				continue
			}
		}
		if strings.Contains(line, "fun verify(") && strings.Contains(f.Text, "HostnameVerifier") {
			w := line
			eLine := i + 1
			for j := i + 1; j < len(lines) && j < i+5 && !strings.Contains(w, "}"); j++ {
				w += " " + stripKotlinLineComment(lines[j])
				eLine = j + 1
			}
			compact := strings.ReplaceAll(w, " ", "")
			if (strings.Contains(compact, "=true") || strings.Contains(compact, "returntrue")) && !strings.Contains(w, "if ") {
				out = append(out, Finding{
					Category: "SAST", Class: "tls-verification", Path: f.Path, Line: i + 1, EndLine: eLine,
					Severity:    "MEDIUM",
					Description: "Проверка имени хоста в TLS отключена безусловным true.",
					Remediation: "Использовать штатную проверку имени и корректный сертификат.",
				})
				continue
			}
		}
		if strings.Contains(line, "checkServerTrusted") {
			w := line
			eLine := i + 1
			for j := i + 1; j < len(lines) && j < i+4 && !strings.Contains(w, "}"); j++ {
				w += " " + stripKotlinLineComment(lines[j])
				eLine = j + 1
			}
			if open := strings.IndexByte(w, '{'); open >= 0 {
				if closeIdx := strings.IndexByte(w[open+1:], '}'); closeIdx >= 0 {
					body := strings.TrimSpace(w[open+1 : open+1+closeIdx])
					if body == "" || body == "return" {
						out = append(out, Finding{
							Category: "SAST", Class: "tls-verification", Path: f.Path, Line: i + 1, EndLine: eLine,
							Severity:    "MEDIUM",
							Description: "TrustManager принимает любой сертификат сервера.",
							Remediation: "Не подменять проверку цепочки сертификатов.",
						})
						continue
					}
				}
			}
		}
		if m := insecureTLSRe.FindStringSubmatch(line); m != nil {
			out = append(out, Finding{
				Category: "SAST", Class: "tls-verification", Path: f.Path, Line: i + 1, EndLine: i + 1,
				Severity:    "MEDIUM",
				Description: "Используется небезопасная реализация TLS-проверки (" + m[1] + ").",
				Remediation: "Включить стандартную проверку цепочки сертификатов и имени хоста.",
			})
		}
	}
	return out
}

var (
	corsOriginPropRe = regexp.MustCompile(`(?:([A-Za-z_][A-Za-z0-9_]*)\.)?(?:allowedOriginPatterns|allowedOrigins|setAllowedOriginPatterns|setAllowedOrigins|addAllowedOriginPattern|addAllowedOrigin)\s*(?:=|\()`)
	corsCredPropRe   = regexp.MustCompile(`(?:([A-Za-z_][A-Za-z0-9_]*)\.)?(?:allowCredentials|setAllowCredentials)\s*(?:=|\()\s*true\b`)
	wildcardLitRe    = regexp.MustCompile(`"(?:\*|\*://\*|https?://\*(?:\.\*)?(?::\*)?/?)"`)
	crossOriginRe    = regexp.MustCompile(`@CrossOrigin\(([^)]*)\)`)
)

func credentialedCORS(f sourceFile) []Finding {
	var out []Finding
	lines := strings.Split(f.Text, "\n")

	// 1. @CrossOrigin annotation
	for i, line := range lines {
		if m := crossOriginRe.FindStringSubmatch(line); m != nil {
			args := m[1]
			hasCred := strings.Contains(args, `allowCredentials = "true"`) || strings.Contains(args, `allowCredentials="true"`)
			if !hasCred {
				continue
			}
			hasExplicitOrigins := strings.Contains(args, "origins") || strings.Contains(args, "originPatterns") || strings.Contains(args, "value")
			if wildcardLitRe.MatchString(args) || !hasExplicitOrigins {
				out = append(out, Finding{
					Category: "SAST", Class: "credentialed-cors", Path: f.Path, Line: i + 1, EndLine: i + 1,
					Severity:    "MEDIUM",
					Description: "Аннотация @CrossOrigin одновременно разрешает любой origin и передачу учётных данных.",
					Remediation: "Ограничить origin доверенным клиентом или отключить credentials.",
				})
			}
		}
	}

	if !strings.Contains(f.Text, "CorsConfiguration") && !strings.Contains(f.Text, "CorsRegistry") && !strings.Contains(f.Text, "addMapping") {
		return out
	}

	// Track per-receiver (e.g. `cfg` vs `publicCors` vs `privateCors`) inside each function/block
	originLine := map[string]int{}
	credLine := map[string]int{}
	scopeID := 0
	for i, rawLine := range lines {
		line := stripKotlinLineComment(rawLine)
		if kotlinFunRe.MatchString(line) || strings.Contains(line, "addMapping(") {
			emitCORSMatches(f.Path, originLine, credLine, &out)
			originLine = map[string]int{}
			credLine = map[string]int{}
			scopeID++
		}
		if m := corsOriginPropRe.FindStringSubmatch(line); m != nil && wildcardLitRe.MatchString(line) {
			recv := m[1]
			if recv == "" {
				recv = "scope_" + intToStr(scopeID)
			}
			if originLine[recv] == 0 {
				originLine[recv] = i + 1
			}
		}
		if m := corsCredPropRe.FindStringSubmatch(line); m != nil {
			recv := m[1]
			if recv == "" {
				recv = "scope_" + intToStr(scopeID)
			}
			if credLine[recv] == 0 {
				credLine[recv] = i + 1
			}
		}
	}
	emitCORSMatches(f.Path, originLine, credLine, &out)
	return out
}

func emitCORSMatches(relPath string, originLine, credLine map[string]int, out *[]Finding) {
	for recv, oLine := range originLine {
		cLine := credLine[recv]
		if oLine == 0 || cLine == 0 {
			continue
		}
		start, end := oLine, cLine
		if end < start {
			start, end = end, start
		}
		*out = append(*out, Finding{
			Category: "SAST", Class: "credentialed-cors", Path: relPath, Line: start, EndLine: end,
			Severity:    "MEDIUM",
			Description: "CORS одновременно разрешает любой origin и передачу учётных данных.",
			Remediation: "Ограничить origin доверенным клиентом или отключить credentials.",
		})
	}
}

// ============================================================================
// Cross-file Security Rules, Route Authorization & Object Authorization
// ============================================================================

type goSecurityRule struct {
	path       string
	line       int
	pattern    string
	httpMethod string
	access     string
	roles      []string
}

var (
	javaMatcherRe  = regexp.MustCompile(`(?:requestMatchers|antMatchers|mvcMatchers)\(([^)]+)\)\.(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\(([^)]*)\)`)
	kotlinDslSecRe = regexp.MustCompile(`authorize\(([^)]+),\s*(permitAll|authenticated|(?:hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\([^)]*\))\)`)
	quotedLitRe    = regexp.MustCompile(`"([^"]+)"`)
	httpMethodRe   = regexp.MustCompile(`\b(?:HttpMethod\.)?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b`)
)

func collectGoSecurityRules(files []sourceFile) []goSecurityRule {
	var rules []goSecurityRule
	for _, f := range files {
		if !strings.HasSuffix(strings.ToLower(f.Path), ".kt") {
			continue
		}
		if !strings.Contains(f.Text, "authorizeHttpRequests") && !strings.Contains(f.Text, "authorizeRequests") {
			continue
		}
		lines := strings.Split(f.Text, "\n")
		for i, rawLine := range lines {
			line := stripKotlinLineComment(rawLine)
			if m := javaMatcherRe.FindStringSubmatch(line); m != nil {
				matcherArgs, access, accessArgs := m[1], m[2], m[3]
				method := ""
				if hm := httpMethodRe.FindStringSubmatch(matcherArgs); hm != nil {
					method = hm[1]
				}
				roles := extractAllQuoted(accessArgs)
				for _, route := range extractAllQuoted(matcherArgs) {
					rules = append(rules, goSecurityRule{
						path: f.Path, line: i + 1, pattern: route, httpMethod: method, access: access, roles: roles,
					})
				}
			}
			if m := kotlinDslSecRe.FindStringSubmatch(line); m != nil {
				matcherArgs, accessRaw := m[1], m[2]
				method := ""
				if hm := httpMethodRe.FindStringSubmatch(matcherArgs); hm != nil {
					method = hm[1]
				}
				access := accessRaw
				var roles []string
				if idx := strings.IndexByte(accessRaw, '('); idx > 0 {
					access = accessRaw[:idx]
					roles = extractAllQuoted(accessRaw[idx+1:])
				}
				for _, route := range extractAllQuoted(matcherArgs) {
					rules = append(rules, goSecurityRule{
						path: f.Path, line: i + 1, pattern: route, httpMethod: method, access: access, roles: roles,
					})
				}
			}
		}
	}
	return rules
}

func extractAllQuoted(s string) []string {
	matches := quotedLitRe.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

type goHandler struct {
	path         string
	className    string
	funName      string
	fullRoute    string
	httpMethod   string
	hasLocalAuth bool
	isAdminOnly  bool
	hasPathVar   bool
	hasPrincipal bool
	startLine    int
	body         string
	propTypes    map[string]string
}

var publicRouteHints = []string{
	"/health", "/livez", "/readyz", "/ping", "/version", "/status",
	"/login", "/logout", "/signin", "/signout", "/register", "/signup",
	"/auth/", "/oauth2/", "/token", "/forgot-password", "/reset-password",
	"/swagger", "/v3/api-docs", "/openapi", "/docs", "/public/", "/static/",
	"/assets/", "/error", "/favicon", "/webhook",
}

var sensitiveRouteSegments = map[string]bool{
	"admin": true, "internal": true, "export": true, "staff": true, "backoffice": true,
	"audit": true, "debug": true, "backup": true, "private": true, "secret": true,
	"secrets": true, "billing": true, "invoice": true, "invoices": true, "payment": true,
	"payments": true, "payroll": true, "employee": true, "employees": true,
}

var sensitiveDataTokens = []string{
	"customer_id", "customerid", "user_id", "userid", "owner_id", "ownerid",
	"account_id", "accountid", "client_id", "clientid", "employee_id", "employeeid",
	"member_id", "memberid", "tenant_id", "tenantid", "patient_id", "patientid",
	"email", "phone", "ssn", "passport", "salary", "iban", "card_number", "cardnumber",
	"password_hash", "passwordhash", "secret_key", "secretkey", "access_token",
	"internal_note", "internalnote", "private_note", "privatenote", "audit_log",
}

var ownerTokens = []string{
	"customer_id", "customerid", "user_id", "userid", "owner_id", "ownerid",
	"account_id", "accountid", "client_id", "clientid", "member_id", "memberid",
	"employee_id", "employeeid", "tenant_id", "tenantid", "author_id", "authorid",
	"created_by", "createdby", "holder_id", "holderid", "patient_id", "patientid",
	"subscriber_id", "subscriberid",
}

func indexGoHandlers(files []sourceFile) []goHandler {
	var out []goHandler
	for _, f := range files {
		if !strings.HasSuffix(strings.ToLower(f.Path), ".kt") {
			continue
		}
		if !strings.Contains(f.Text, "@RestController") && !strings.Contains(f.Text, "@Controller") {
			continue
		}
		classBlocks := splitTopLevelClasses(f.Text)
		for _, cb := range classBlocks {
			if !strings.Contains(cb.header, "@RestController") && !strings.Contains(cb.header, "@Controller") {
				continue
			}
			classPrefix := ""
			if m := requestMapClsRe.FindStringSubmatch(cb.header); m != nil {
				classPrefix = m[1]
			}
			clsHasAuth := containsAuthAnnotation(cb.header)
			clsIsAdmin := containsAdminAnnotation(cb.header)
			propTypes := map[string]string{}
			for _, pm := range ctorParamTypeRe.FindAllStringSubmatch(cb.header, -1) {
				propTypes[pm[1]] = pm[2]
			}

			lines := strings.Split(cb.body, "\n")
			for i, line := range lines {
				m := springMapRe.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				kind, routePart := m[1], m[2]
				httpMethod := ""
				switch kind {
				case "Get":
					httpMethod = "GET"
				case "Post":
					httpMethod = "POST"
				case "Put":
					httpMethod = "PUT"
				case "Delete":
					httpMethod = "DELETE"
				case "Patch":
					httpMethod = "PATCH"
				}
				fullRoute := joinPath(classPrefix, routePart)
				annStart := max(0, i-3)
				end := len(lines)
				for j := i + 1; j < len(lines); j++ {
					if springMapRe.MatchString(lines[j]) {
						end = j
						break
					}
				}
				fnChunk := strings.Join(lines[annStart:end], "\n")
				fnName := ""
				if fm := kotlinFunRe.FindStringSubmatch(fnChunk); fm != nil {
					fnName = fm[1]
				}
				hasPrincipal := strings.Contains(fnChunk, "Principal") ||
					strings.Contains(fnChunk, "@AuthenticationPrincipal") ||
					strings.Contains(fnChunk, "SecurityContextHolder") ||
					strings.Contains(fnChunk, "Authentication") ||
					strings.Contains(fnChunk, "UserDetails")
				hasLocalAuth := clsHasAuth || containsAuthAnnotation(fnChunk) || hasPrincipal
				isAdminOnly := clsIsAdmin || containsAdminAnnotation(fnChunk)
				out = append(out, goHandler{
					path:         f.Path,
					className:    cb.name,
					funName:      fnName,
					fullRoute:    fullRoute,
					httpMethod:   httpMethod,
					hasLocalAuth: hasLocalAuth,
					isAdminOnly:  isAdminOnly,
					hasPathVar:   strings.Contains(fnChunk, "@PathVariable"),
					hasPrincipal: hasPrincipal,
					startLine:    cb.startLine + i,
					body:         fnChunk,
					propTypes:    propTypes,
				})
			}
		}
	}
	return out
}

type classBlock struct {
	name      string
	startLine int
	header    string
	body      string
}

func splitTopLevelClasses(text string) []classBlock {
	lines := strings.Split(text, "\n")
	var starts []int
	var names []string
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "//") {
			continue
		}
		if m := kotlinClassRe.FindStringSubmatch(line); m != nil {
			starts = append(starts, i)
			names = append(names, m[1])
		}
	}
	if len(starts) == 0 {
		return nil
	}
	blocks := make([]classBlock, 0, len(starts))
	for idx, s := range starts {
		annStart := s
		for annStart > 0 {
			prev := strings.TrimSpace(lines[annStart-1])
			if strings.HasPrefix(prev, "@") {
				annStart--
			} else {
				break
			}
		}
		end := len(lines)
		if idx+1 < len(starts) {
			nextAnn := starts[idx+1]
			for nextAnn > s+1 && strings.HasPrefix(strings.TrimSpace(lines[nextAnn-1]), "@") {
				nextAnn--
			}
			end = nextAnn
		}
		// Header runs until first `{` of class body
		bodyStart := s
		for j := s; j < end; j++ {
			if strings.Contains(lines[j], "{") {
				bodyStart = j
				break
			}
		}
		blocks = append(blocks, classBlock{
			name:      names[idx],
			startLine: annStart + 1,
			header:    strings.Join(lines[annStart:bodyStart+1], "\n"),
			body:      strings.Join(lines[annStart:end], "\n"),
		})
	}
	return blocks
}

func containsAuthAnnotation(s string) bool {
	return strings.Contains(s, "@PreAuthorize") || strings.Contains(s, "@Secured") || strings.Contains(s, "@RolesAllowed")
}

func containsAdminAnnotation(s string) bool {
	if !containsAuthAnnotation(s) {
		return false
	}
	low := strings.ToLower(s)
	for _, r := range []string{"admin", "staff", "operator", "moderator", "support", "manager"} {
		if strings.Contains(low, r) {
			return true
		}
	}
	return false
}

func routeAuth(files []sourceFile, rules []goSecurityRule) []Finding {
	if len(rules) == 0 {
		return nil
	}
	handlers := indexGoHandlers(files)
	if len(handlers) == 0 {
		return nil
	}

	var rolePrefixes []string
	for _, r := range rules {
		switch r.access {
		case "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority":
			rolePrefixes = append(rolePrefixes, r.pattern)
		}
	}

	var out []Finding
	for _, rule := range rules {
		if rule.access != "permitAll" || isPublicRoute(rule.pattern) {
			continue
		}
		vulnerable := false
		for _, h := range handlers {
			if !goRoutesMatch(rule.pattern, h.fullRoute) {
				continue
			}
			if rule.httpMethod != "" && h.httpMethod != "" && rule.httpMethod != h.httpMethod {
				continue
			}
			if h.hasLocalAuth || isPublicRoute(h.fullRoute) {
				continue
			}
			underRolePrefix := false
			for _, pref := range rolePrefixes {
				if isSpecificDomainPrefix(pref) && goRouteMatchesAnt(h.fullRoute, pref) {
					underRolePrefix = true
					break
				}
			}
			mutating := h.httpMethod == "POST" || h.httpMethod == "PUT" || h.httpMethod == "PATCH" || h.httpMethod == "DELETE"
			if underRolePrefix || mutating || hasSensitiveRouteSegment(h.fullRoute) || hasSensitiveRouteSegment(rule.pattern) || bodyAccessesSensitiveData(h.body) {
				vulnerable = true
				break
			}
		}
		if !vulnerable {
			continue
		}
		out = append(out, Finding{
			Category: "SAST", Class: "route-authorization", Path: rule.path, Line: rule.line, EndLine: rule.line,
			Severity:    "HIGH",
			Description: "Открытый маршрут отдаёт служебные или клиентские данные без проверки роли.",
			Remediation: "Требовать роль и проверить доступ для гостя, клиента и сотрудника.",
		})
	}
	return out
}

func isPublicRoute(route string) bool {
	low := strings.ToLower(route)
	for _, h := range publicRouteHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

func isSpecificDomainPrefix(pattern string) bool {
	if !strings.HasSuffix(pattern, "/**") && !strings.HasSuffix(pattern, "/*") {
		return false
	}
	base := strings.Trim(strings.TrimSuffix(strings.TrimSuffix(pattern, "/**"), "/*"), "/")
	if base == "" {
		return false
	}
	segs := strings.Split(base, "/")
	if len(segs) == 1 {
		switch strings.ToLower(segs[0]) {
		case "api", "v1", "v2", "v3", "rest":
			return false
		}
	}
	return true
}

func hasSensitiveRouteSegment(route string) bool {
	for _, seg := range strings.Split(strings.ToLower(route), "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		if sensitiveRouteSegments[seg] {
			return true
		}
	}
	return false
}

func bodyAccessesSensitiveData(body string) bool {
	low := strings.ToLower(body)
	for _, tok := range sensitiveDataTokens {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

func goRoutesMatch(a, b string) bool {
	return a == b || goRouteMatchesAnt(b, a) || goRouteMatchesAnt(a, b)
}

func goRouteMatchesAnt(route, pattern string) bool {
	nr := normalizeRoute(route)
	np := normalizeRoute(pattern)
	if nr == np {
		return true
	}
	re, err := regexp.Compile(antToRegex(np))
	return err == nil && re.MatchString(nr)
}

func normalizeRoute(r string) string {
	r = strings.TrimSpace(r)
	if !strings.HasPrefix(r, "/") {
		r = "/" + r
	}
	if len(r) > 1 {
		r = strings.TrimRight(r, "/")
	}
	return r
}

func antToRegex(pat string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pat); {
		switch {
		case strings.HasPrefix(pat[i:], "/**"):
			b.WriteString("(?:/.*)?")
			i += 3
		case strings.HasPrefix(pat[i:], "**"):
			b.WriteString(".*")
			i += 2
		case pat[i] == '*':
			b.WriteString("[^/]*")
			i++
		case pat[i] == '{':
			if closeIdx := strings.IndexByte(pat[i:], '}'); closeIdx > 0 {
				b.WriteString("[^/]+")
				i += closeIdx + 1
			} else {
				b.WriteString(`\{`)
				i++
			}
		default:
			b.WriteString(regexp.QuoteMeta(pat[i : i+1]))
			i++
		}
	}
	b.WriteString("$")
	return b.String()
}

func joinPath(prefix, method string) string {
	if prefix == "" {
		return method
	}
	if method == "" {
		return prefix
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(method, "/")
}

type goRepoMethod struct {
	className string
	funName   string
	path      string
	start     int
	end       int
	sql       string
	jpaEntity string
}

func objectAuth(files []sourceFile, rules []goSecurityRule) []Finding {
	// 1. Discover tables & entities with owner columns from .sql & Kotlin classes
	ownedTables := map[string]bool{}
	ownedEntities := map[string]bool{}
	jpaRepoEntity := map[string]string{}

	for _, f := range files {
		lowPath := strings.ToLower(f.Path)
		if strings.HasSuffix(lowPath, ".sql") {
			for _, m := range createTableRe.FindAllStringSubmatch(f.Text, -1) {
				if ownerColumn(strings.ToLower(m[2])) {
					ownedTables[strings.ToLower(m[1])] = true
				}
			}
			continue
		}
		if !strings.HasSuffix(lowPath, ".kt") {
			continue
		}
		for _, cb := range splitTopLevelClasses(f.Text) {
			if jm := jpaRepoRe.FindStringSubmatch(cb.header); jm != nil && cb.name != "" {
				jpaRepoEntity[cb.name] = jm[1]
			}
			if ownerColumn(strings.ToLower(cb.header)) {
				ln := strings.ToLower(cb.name)
				ownedEntities[ln] = true
				ownedTables[ln] = true
				ownedTables[ln+"s"] = true
			}
		}
	}

	// 2. Collect repository/service SQL methods & service delegation map
	var repos []goRepoMethod
	serviceBodyByKey := map[string]struct {
		body      string
		propTypes map[string]string
	}{}

	for _, f := range files {
		if !strings.HasSuffix(strings.ToLower(f.Path), ".kt") {
			continue
		}
		for _, cb := range splitTopLevelClasses(f.Text) {
			isRepoOrSvc := strings.Contains(cb.header, "@Repository") ||
				strings.Contains(cb.header, "@Service") ||
				strings.Contains(cb.body, "JdbcTemplate") ||
				strings.Contains(cb.body, "JdbcClient") ||
				strings.Contains(cb.body, "EntityManager")
			if !isRepoOrSvc {
				continue
			}
			propTypes := map[string]string{}
			for _, pm := range ctorParamTypeRe.FindAllStringSubmatch(cb.header, -1) {
				propTypes[pm[1]] = pm[2]
			}
			lines := strings.Split(cb.body, "\n")
			for i, line := range lines {
				m := kotlinFunRe.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				end := len(lines)
				for j := i + 1; j < len(lines); j++ {
					if kotlinFunRe.MatchString(lines[j]) {
						end = j
						break
					}
				}
				chunk := strings.Join(lines[i:end], "\n")
				serviceBodyByKey[cb.name+"."+m[1]] = struct {
					body      string
					propTypes map[string]string
				}{body: chunk, propTypes: propTypes}
				if sqlCrudVerbRe.MatchString(chunk) && strings.Contains(strings.ToLower(chunk), "where") {
					absStart := cb.startLine + i
					repos = append(repos, goRepoMethod{
						className: cb.name,
						funName:   m[1],
						path:      f.Path,
						start:     absStart,
						end:       absStart + 1,
						sql:       chunk,
					})
				}
			}
		}
	}

	isUncheckedSQL := func(sql string) bool {
		low := strings.ToLower(sql)
		idx := strings.Index(low, "where")
		if idx < 0 {
			return false
		}
		if ownerColumn(low[idx:]) {
			return false
		}
		if ownerColumn(low) {
			return true
		}
		for _, m := range sqlTableRe.FindAllStringSubmatch(low, -1) {
			if ownedTables[strings.ToLower(m[1])] {
				return true
			}
		}
		return false
	}

	resolveHits := func(body string, propTypes map[string]string, fallbackPath string, fallbackLine int) []goRepoMethod {
		var matched []goRepoMethod
		for _, r := range repos {
			if !strings.Contains(body, r.funName+"(") {
				continue
			}
			matched = append(matched, r)
		}
		for prop, typ := range propTypes {
			if entity, ok := jpaRepoEntity[typ]; ok && ownedEntities[strings.ToLower(entity)] {
				for _, mName := range []string{"findById(", "findByIdOrNull(", "getReferenceById(", "deleteById("} {
					if strings.Contains(body, prop+"."+mName) {
						matched = append(matched, goRepoMethod{
							className: typ, funName: strings.TrimSuffix(mName, "("),
							path: fallbackPath, start: fallbackLine, end: fallbackLine,
							jpaEntity: entity,
						})
					}
				}
			}
		}
		return matched
	}

	handlers := indexGoHandlers(files)
	var out []Finding
	seen := map[string]bool{}
	callExprRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

	for _, h := range handlers {
		if !h.hasPathVar || !strings.Contains(h.fullRoute, "{") {
			continue
		}
		if h.hasPrincipal || h.isAdminOnly || isGoAdminProtectedRoute(h.fullRoute, h.httpMethod, rules) {
			continue
		}

		// Inline SQL inside controller
		if sqlCrudVerbRe.MatchString(h.body) && isUncheckedSQL(h.body) {
			key := h.path + ":" + h.funName
			if !seen[key] {
				seen[key] = true
				out = append(out, Finding{
					Category: "SAST", Class: "object-authorization", Path: h.path,
					Line: h.startLine, EndLine: h.startLine + 1, Severity: "HIGH",
					Description: "Аутентифицированный маршрут обращается к записи по идентификатору без фильтра владельца.",
					Remediation: "Добавить в запрос идентификатор владельца из Principal.",
				})
			}
			continue
		}

		// 1-hop Controller -> Repository
		candidates := resolveHits(h.body, h.propTypes, h.path, h.startLine)
		// 2-hop Controller -> Service -> Repository
		if len(candidates) == 0 {
			for _, cm := range callExprRe.FindAllStringSubmatch(h.body, -1) {
				recvType := h.propTypes[cm[1]]
				if recvType == "" {
					continue
				}
				if svc, ok := serviceBodyByKey[recvType+"."+cm[2]]; ok {
					candidates = append(candidates, resolveHits(svc.body, svc.propTypes, h.path, h.startLine)...)
				}
			}
		}

		for _, repo := range candidates {
			if repo.jpaEntity == "" && !isUncheckedSQL(repo.sql) {
				continue
			}
			key := repo.path + ":" + repo.funName
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				Category: "SAST", Class: "object-authorization", Path: repo.path,
				Line: repo.start, EndLine: repo.end, Severity: "HIGH",
				Description: "Аутентифицированный маршрут читает или изменяет запись по идентификатору без фильтра владельца.",
				Remediation: "Добавить в запрос идентификатор владельца из Principal.",
			})
		}
	}
	return out
}

func isGoAdminProtectedRoute(route, httpMethod string, rules []goSecurityRule) bool {
	adminRoles := []string{"admin", "staff", "operator", "moderator", "support", "manager"}
	for _, r := range rules {
		switch r.access {
		case "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority":
		default:
			continue
		}
		if r.httpMethod != "" && httpMethod != "" && r.httpMethod != httpMethod {
			continue
		}
		if !goRouteMatchesAnt(route, r.pattern) {
			continue
		}
		for _, role := range r.roles {
			lr := strings.ToLower(role)
			for _, a := range adminRoles {
				if strings.Contains(lr, a) {
					return true
				}
			}
		}
	}
	return false
}

func ownerColumn(sqlLower string) bool {
	for _, col := range ownerTokens {
		if strings.Contains(sqlLower, col) {
			return true
		}
	}
	return false
}
