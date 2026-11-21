// Package kotlinscan implements the SecFlow Kotlin/YAML rules for scan.secrets
// and scan.sast.kotlin. It does not wrap Semgrep, Gitleaks, or detekt.
package kotlinscan

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
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
	// Directory prefix match (e.g. "src/main/kotlin" or "src/main/kotlin/").
	dirPrefix := strings.TrimSuffix(p, "/")
	if !strings.ContainsAny(dirPrefix, "*?[") && strings.HasPrefix(relPath, dirPrefix+"/") {
		return true
	}
	// Glob match with optional "**" recursive wildcard support.
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
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "build" || base == ".gradle" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".kt", ".kts", ".yml", ".yaml", ".properties", ".sql":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var textFiles []sourceFile
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		textFiles = append(textFiles, sourceFile{Path: filepath.ToSlash(rel), Text: string(raw)})
	}
	var out []Finding
	out = append(out, scanSecrets(textFiles)...)
	out = append(out, scanSAST(textFiles)...)
	return out, nil
}

type sourceFile struct {
	Path string
	Text string
}

func scanSecrets(files []sourceFile) []Finding {
	var out []Finding
	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Path), ".md") {
			continue
		}
		switch {
		case strings.HasSuffix(f.Path, ".kt"):
			out = append(out, secretKotlin(f)...)
		case strings.HasSuffix(f.Path, ".yml") || strings.HasSuffix(f.Path, ".yaml") || strings.HasSuffix(f.Path, ".properties"):
			out = append(out, secretConfig(f)...)
		}
	}
	return out
}

var (
	passwordDecl = regexp.MustCompile(`(?m)^[ \t]*(?:private|internal|public|protected)?[ \t]*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*"([^"]*)"`)
	elvisLit     = regexp.MustCompile(`System\.getenv\([^)]*\)\s*\?:\s*"([^"]+)"`)
	valueDefault = regexp.MustCompile(`@Value\(\s*"\$\{[^":]+:([^"}]+)\}"\s*\)`)
)

func secretKotlin(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	var out []Finding
	for i, line := range lines {
		if m := passwordDecl.FindStringSubmatch(line); m != nil {
			name, value := m[1], m[2]
			if passwordName(name) && secretLiteral(value) {
				out = append(out, Finding{
					Category: "SECRET", Class: "password", Path: f.Path, Line: i + 1, EndLine: i + 1,
					Severity:    "HIGH",
					Description: "Встроенный пароль хранится строковым литералом в исходнике.",
					Remediation: "Читать пароль из окружения или хранилища секретов без литерала по умолчанию.",
				})
			}
			if apiKeyName(name) && secretLiteral(value) {
				out = append(out, Finding{
					Category: "SECRET", Class: "api-key", Path: f.Path, Line: i + 1, EndLine: i + 1,
					Severity:    "MEDIUM",
					Description: "Встроенный API-ключ задан строковым литералом.",
					Remediation: "Передавать ключ через настройки окружения и маскировать его в журналах.",
				})
			}
		}
		if m := elvisLit.FindStringSubmatch(line); m != nil && secretLiteral(m[1]) {
			out = append(out, Finding{
				Category: "SECRET", Class: "secret-fallback", Path: f.Path, Line: i + 1, EndLine: i + 1,
				Severity:    "LOW",
				Description: "При отсутствии переменной окружения используется встроенный секрет.",
				Remediation: "Удалить fallback. При отсутствии переменной отключать интеграцию.",
			})
		}
		if m := valueDefault.FindStringSubmatch(line); m != nil && secretLiteral(m[1]) {
			out = append(out, Finding{
				Category: "SECRET", Class: "secret-fallback", Path: f.Path, Line: i + 1, EndLine: i + 1,
				Severity:    "LOW",
				Description: "Аннотация @Value содержит секретный литерал по умолчанию.",
				Remediation: "Убрать литерал по умолчанию из @Value.",
			})
		}
	}
	if rec, ok := recoverable(f); ok {
		out = append(out, rec)
	}
	return out
}

func passwordName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "password") || strings.Contains(n, "passwd") || strings.Contains(n, "pwd")
}

func apiKeyName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "apikey") || strings.Contains(n, "api_key") || strings.Contains(n, "secret")
}

func secretLiteral(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	low := strings.ToLower(v)
	if strings.Contains(low, "change_me") || strings.Contains(low, "placeholder") || strings.Contains(low, "example") || strings.Contains(low, "your_") {
		return false
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return false
	}
	return true
}

var (
	valAssign = regexp.MustCompile(`(?m)^[ \t]*val\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)
	strLit    = regexp.MustCompile(`^"([^"]*)"$`)
	plusFold  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)$`)
)

func recoverable(f sourceFile) (Finding, bool) {
	lines := strings.Split(f.Text, "\n")
	consts := map[string]string{}
	origin := map[string][2]int{}
	folded := map[string]bool{}
	for i, line := range lines {
		m := valAssign.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		name, expr := m[1], strings.TrimSpace(m[2])
		if sm := strLit.FindStringSubmatch(expr); sm != nil {
			consts[name] = sm[1]
			origin[name] = [2]int{i + 1, i + 1}
			continue
		}
		if pm := plusFold.FindStringSubmatch(expr); pm != nil {
			a, aok := consts[pm[1]]
			b, bok := consts[pm[2]]
			if aok && bok {
				consts[name] = a + b
				start := origin[pm[1]][0]
				end := i + 1
				if origin[pm[2]][0] < start {
					start = origin[pm[2]][0]
				}
				origin[name] = [2]int{start, end}
				folded[name] = true
			}
		}
	}
	for i, line := range lines {
		if !strings.Contains(line, "setBearerAuth") && !strings.Contains(line, "X-Api-Key") && !strings.Contains(line, "Authorization") {
			continue
		}
		for name, ok := range folded {
			if !ok {
				continue
			}
			if strings.Contains(line, name) {
				span := origin[name]
				end := i + 1
				if span[1] > end {
					end = span[1]
				}
				return Finding{
					Category: "SECRET", Class: "recoverable-token", Path: f.Path,
					Line: span[0], EndLine: end, Severity: "MEDIUM",
					Description: "Токен собирается из строковых фрагментов в исходнике и уходит в заголовок авторизации.",
					Remediation: "Подставлять цельный токен из окружения или хранилища секретов.",
				}, true
			}
		}
	}
	return Finding{}, false
}

func secretConfig(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	var out []Finding
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		key, value, ok := strings.Cut(trim, ":")
		if !ok {
			key, value, ok = strings.Cut(trim, "=")
		}
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if !configKey(key) {
			continue
		}
		if envOnly(value) || !secretLiteral(value) {
			continue
		}
		out = append(out, Finding{
			Category: "SECRET", Class: "configuration-token", Path: f.Path, Line: i + 1, EndLine: i + 1,
			Severity:    "HIGH",
			Description: "В конфигурации записан токен или секрет литералом.",
			Remediation: "Задать свойство через переменную окружения без встроенного значения.",
		})
	}
	return out
}

func configKey(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "authorization") || strings.Contains(k, "password")
}

var (
	envOnlyRe        = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)
	springMapRe      = regexp.MustCompile(`@(?:Get|Post|Put|Delete|Patch)?Mapping\(\s*"([^"]+)"\s*\)`)
	requestMappingRe = regexp.MustCompile(`@RequestMapping\(\s*"([^"]+)"\s*\)`)
	kotlinFunRe      = regexp.MustCompile(`fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
)

func envOnly(value string) bool {
	return envOnlyRe.MatchString(strings.TrimSpace(value))
}

func scanSAST(files []sourceFile) []Finding {
	var out []Finding
	byPath := map[string]sourceFile{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Path, ".kt") {
			continue
		}
		out = append(out, sqlInjection(f)...)
		out = append(out, tlsBypass(f)...)
		out = append(out, credentialedCORS(f)...)
	}
	out = append(out, routeAuth(files)...)
	out = append(out, objectAuth(files)...)
	return out
}

func sqlInjection(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	var out []Finding
	for i, line := range lines {
		if !strings.Contains(line, "queryForList") && !strings.Contains(line, "createNativeQuery") && !strings.Contains(line, ".execute") && !strings.Contains(line, ".query(") {
			continue
		}
		if !strings.Contains(line, "$") {
			continue
		}
		start := i + 1
		if i > 0 && strings.Contains(lines[i-1], "fun ") {
			start = i
		}
		out = append(out, Finding{
			Category: "SAST", Class: "sql-injection", Path: f.Path, Line: start, EndLine: i + 1,
			Severity:    "HIGH",
			Description: "Параметр запроса подставляется в SQL без параметризации.",
			Remediation: "Использовать ? и передать значение отдельным аргументом.",
		})
	}
	return out
}

func tlsBypass(f sourceFile) []Finding {
	lines := strings.Split(f.Text, "\n")
	for i, line := range lines {
		compact := strings.ReplaceAll(line, " ", "")
		if strings.Contains(line, "HostnameVerifier") && strings.Contains(compact, "->true") {
			return []Finding{{
				Category: "SAST", Class: "tls-verification", Path: f.Path, Line: i + 1, EndLine: i + 1,
				Severity:    "MEDIUM",
				Description: "Проверка имени хоста в TLS отключена безусловным true.",
				Remediation: "Использовать штатную проверку имени и корректный сертификат.",
			}}
		}
		if strings.Contains(line, "checkServerTrusted") && strings.Contains(line, "{}") {
			return []Finding{{
				Category: "SAST", Class: "tls-verification", Path: f.Path, Line: i + 1, EndLine: i + 1,
				Severity:    "MEDIUM",
				Description: "TrustManager принимает любой сертификат сервера.",
				Remediation: "Не подменять проверку цепочки сертификатов.",
			}}
		}
	}
	return nil
}

func credentialedCORS(f sourceFile) []Finding {
	if !strings.Contains(f.Text, "CorsConfiguration") && !strings.Contains(f.Text, "CorsRegistry") {
		return nil
	}
	hasCred := strings.Contains(f.Text, "allowCredentials = true") || strings.Contains(f.Text, "allowCredentials(true)") || strings.Contains(f.Text, "setAllowCredentials(true)")
	if !hasCred {
		return nil
	}
	if !strings.Contains(f.Text, `"*"`) && !strings.Contains(f.Text, `listOf("*")`) {
		return nil
	}
	lines := strings.Split(f.Text, "\n")
	originLine, credLine := 0, 0
	for i, line := range lines {
		if (strings.Contains(line, "allowedOriginPatterns") || strings.Contains(line, "allowedOrigins") || strings.Contains(line, "setAllowedOrigin")) && strings.Contains(line, `"*"`) {
			if originLine == 0 {
				originLine = i + 1
			}
		}
		if strings.Contains(line, "allowCredentials") || strings.Contains(line, "setAllowCredentials") {
			if strings.Contains(line, "true") && credLine == 0 {
				credLine = i + 1
			}
		}
	}
	start, end := originLine, credLine
	if start == 0 && end == 0 {
		start, end = 1, 1
	} else if start == 0 {
		start = end
	} else if end == 0 {
		end = start
	}
	if end < start {
		start, end = end, start
	}
	if end > start+14 {
		end = start + 14
	}
	return []Finding{{
		Category: "SAST", Class: "credentialed-cors", Path: f.Path, Line: start, EndLine: end,
		Severity:    "MEDIUM",
		Description: "CORS одновременно разрешает любой origin и передачу учётных данных.",
		Remediation: "Ограничить origin доверенным клиентом или отключить credentials.",
	}}
}

var permitAll = regexp.MustCompile(`requestMatchers\((?:GET,\s*)?"([^"]+)"\)\.permitAll\(\)`)

func routeAuth(files []sourceFile) []Finding {
	var security sourceFile
	for _, f := range files {
		if strings.Contains(f.Text, "permitAll()") && strings.Contains(f.Text, "authorizeHttpRequests") {
			security = f
			break
		}
	}
	if security.Path == "" {
		return nil
	}
	handlers := indexHandlers(files)
	lines := strings.Split(security.Text, "\n")
	var out []Finding
	for i, line := range lines {
		m := permitAll.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		path := m[1]
		h, ok := handlers[path]
		if !ok || !privateExport(h.body) {
			continue
		}
		out = append(out, Finding{
			Category: "SAST", Class: "route-authorization", Path: security.Path, Line: i + 1, EndLine: i + 1,
			Severity:    "HIGH",
			Description: "Открытый маршрут отдаёт служебные или клиентские данные без проверки роли.",
			Remediation: "Требовать роль и проверить доступ для гостя, клиента и сотрудника.",
		})
	}
	return out
}

type handler struct {
	body string
}

func indexHandlers(files []sourceFile) map[string]handler {
	out := map[string]handler{}
	for _, f := range files {
		if !strings.Contains(f.Text, "@RestController") && !strings.Contains(f.Text, "@Controller") {
			continue
		}
		classPrefix := ""
		if m := requestMappingRe.FindStringSubmatch(f.Text); m != nil {
			classPrefix = m[1]
		}
		lines := strings.Split(f.Text, "\n")
		for i, line := range lines {
			m := springMapRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			path := joinPath(classPrefix, m[1])
			body := strings.Join(lines[i:], "\n")
			if next := strings.Index(body[len(line):], "\n    @"); next > 0 {
				body = body[:len(line)+next]
			}
			out[path] = handler{body: body}
		}
	}
	return out
}

func joinPath(prefix, method string) string {
	if prefix == "" {
		return method
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(method, "/")
}

func privateExport(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "customer_id") || strings.Contains(low, "customerid") || strings.Contains(low, "work_note") || strings.Contains(low, "counter_note") {
		return true
	}
	return false
}

func objectAuth(files []sourceFile) []Finding {
	repos := map[string]struct {
		path       string
		start, end int
		sql        string
	}{}
	for _, f := range files {
		if !strings.Contains(f.Text, "@Repository") && !strings.Contains(f.Text, "JdbcTemplate") {
			continue
		}
		lines := strings.Split(f.Text, "\n")
		for i, line := range lines {
			m := kotlinFunRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			end := min(i+12, len(lines))
			for j := i + 1; j < end; j++ {
				if kotlinFunRe.FindStringSubmatch(lines[j]) != nil {
					end = j
					break
				}
			}
			chunk := strings.Join(lines[i:end], "\n")
			if !strings.Contains(strings.ToLower(chunk), "select") {
				continue
			}
			repos[m[1]] = struct {
				path       string
				start, end int
				sql        string
			}{path: f.Path, start: i + 1, end: end, sql: chunk}
		}
	}
	var out []Finding
	seen := map[string]bool{}
	for _, f := range files {
		if !strings.Contains(f.Text, "@RestController") {
			continue
		}
		lines := strings.Split(f.Text, "\n")
		for i, line := range lines {
			if !strings.Contains(line, "@PathVariable") && !strings.Contains(line, "{") {
				continue
			}
			window := strings.Join(lines[max(0, i-2):min(len(lines), i+4)], "\n")
			if !strings.Contains(window, "@PathVariable") || !strings.Contains(window, "{") {
				continue
			}
			if strings.Contains(window, "Principal") || strings.Contains(window, "@AuthenticationPrincipal") {
				continue
			}
			for name, repo := range repos {
				if !strings.Contains(window, name+"(") {
					continue
				}
				sql := strings.ToLower(repo.sql)
				if !ownerColumn(sql) {
					continue
				}
				where := ""
				if idx := strings.Index(sql, "where"); idx >= 0 {
					where = sql[idx:]
				}
				if ownerColumn(where) {
					continue
				}
				key := repo.path + ":" + name
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Finding{
					Category: "SAST", Class: "object-authorization", Path: repo.path,
					Line: repo.start, EndLine: repo.start + 1, Severity: "HIGH",
					Description: "Аутентифицированный маршрут читает запись по идентификатору без фильтра владельца.",
					Remediation: "Добавить в запрос идентификатор владельца из Principal.",
				})
			}
		}
	}
	return out
}

func ownerColumn(sql string) bool {
	for _, col := range []string{"customer_id", "user_id", "owner_id", "account_id"} {
		if strings.Contains(sql, col) {
			return true
		}
	}
	return false
}
