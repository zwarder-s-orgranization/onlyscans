package secflow

import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment
import org.jetbrains.kotlin.com.intellij.openapi.util.Disposer
import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.PsiManager
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.com.intellij.testFramework.LightVirtualFile
import org.jetbrains.kotlin.config.CompilerConfiguration
import org.jetbrains.kotlin.idea.KotlinFileType
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtArrayAccessExpression
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBlockExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtClassInitializer
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtEscapeStringTemplateEntry
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtForExpression
import org.jetbrains.kotlin.psi.KtIfExpression
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectDeclaration
import org.jetbrains.kotlin.psi.KtObjectLiteralExpression
import org.jetbrains.kotlin.psi.KtParameter
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtReturnExpression
import org.jetbrains.kotlin.psi.KtSafeQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateEntryWithExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.KtThrowExpression
import org.jetbrains.kotlin.psi.KtTryExpression
import org.jetbrains.kotlin.psi.KtWhenExpression
import org.jetbrains.kotlin.psi.KtWhileExpression
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.nodes.MappingNode
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.ScalarNode
import org.yaml.snakeyaml.nodes.SequenceNode
import java.io.File
import java.io.StringReader
import java.util.Base64

data class Hit(
    val category: String,
    val `class`: String,
    val path: String,
    val line: Int,
    val endLine: Int,
    val severity: String,
    val description: String,
    val remediation: String,
)

enum class ScanMode { ALL, SAST, SECRETS }

private class LineIndex(text: String) {
    private val lineStarts: IntArray

    init {
        val starts = ArrayList<Int>(256)
        starts.add(0)
        for (i in text.indices) {
            if (text[i] == '\n') {
                starts.add(i + 1)
            }
        }
        lineStarts = starts.toIntArray()
    }

    fun lineOf(offset: Int): Int {
        if (offset <= 0) return 1
        var lo = 0
        var hi = lineStarts.size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (lineStarts[mid] <= offset) {
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return maxOf(1, hi + 1)
    }

    fun rangeOf(element: PsiElement): Pair<Int, Int> {
        val tr = element.textRange
        val start = lineOf(tr.startOffset)
        val endOffset = if (tr.endOffset > tr.startOffset) tr.endOffset - 1 else tr.startOffset
        val end = maxOf(start, lineOf(endOffset))
        return start to end
    }
}

private data class ParsedKtFile(
    val path: String,
    val text: String,
    val lines: LineIndex,
    val ktFile: KtFile,
)

private data class ConfigFile(
    val path: String,
    val ext: String,
    val text: String,
)

private data class SqlFile(
    val path: String,
    val text: String,
)

fun main(args: Array<String>) {
    var mode = ScanMode.ALL
    var rootArg: String? = null
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--mode" -> {
                if (i + 1 >= args.size) {
                    System.err.println("--mode requires sast|secrets|all")
                    kotlin.system.exitProcess(2)
                }
                mode = parseMode(args[i + 1])
                i += 2
            }
            else -> {
                if (args[i].startsWith("--mode=")) {
                    mode = parseMode(args[i].substringAfter("="))
                } else if (rootArg == null) {
                    rootArg = args[i]
                }
                i++
            }
        }
    }
    if (rootArg.isNullOrBlank()) {
        System.err.println("usage: secflow-psi.jar [--mode sast|secrets|all] <root>")
        kotlin.system.exitProcess(2)
    }
    try {
        val bytes = render(scanRoot(File(rootArg), mode)).toByteArray(Charsets.UTF_8)
        System.out.write(bytes)
        System.out.flush()
    } catch (err: Throwable) {
        System.err.println(err.message ?: err.javaClass.simpleName)
        kotlin.system.exitProcess(2)
    }
}

private fun parseMode(raw: String): ScanMode = when (raw.trim().lowercase()) {
    "sast" -> ScanMode.SAST
    "secrets" -> ScanMode.SECRETS
    "all" -> ScanMode.ALL
    else -> {
        System.err.println("unsupported --mode: $raw")
        kotlin.system.exitProcess(2)
    }
}

fun scanRoot(root: File, mode: ScanMode = ScanMode.ALL): List<Hit> {
    val disposable = Disposer.newDisposable()
    try {
        val env = KotlinCoreEnvironment.createForProduction(
            disposable,
            CompilerConfiguration(),
            EnvironmentConfigFiles.JVM_CONFIG_FILES,
        )
        val psiManager = PsiManager.getInstance(env.project)
        val ktFiles = mutableListOf<ParsedKtFile>()
        val configFiles = mutableListOf<ConfigFile>()
        val sqlFiles = mutableListOf<SqlFile>()

        root.walkTopDown()
            .onEnter { dir ->
                val name = dir.name
                name != ".git" && name != "build" && name != ".gradle" &&
                    name != "node_modules" && name != "target" && name != ".idea"
            }
            .filter { it.isFile }
            .forEach { file ->
                val ext = file.extension.lowercase()
                val rel = root.toPath().relativize(file.toPath()).toString().replace('\\', '/')
                when (ext) {
                    "kt" -> {
                        val text = file.readText(Charsets.UTF_8).replace("\r\n", "\n").replace('\r', '\n')
                        val virtual = LightVirtualFile(file.name, KotlinFileType.INSTANCE, text)
                        val kt = psiManager.findFile(virtual) as? KtFile ?: return@forEach
                        ktFiles += ParsedKtFile(rel, text, LineIndex(text), kt)
                    }
                    "yml", "yaml", "properties" -> {
                        val text = file.readText(Charsets.UTF_8).replace("\r\n", "\n").replace('\r', '\n')
                        configFiles += ConfigFile(rel, ext, text)
                    }
                    "sql" -> {
                        val text = file.readText(Charsets.UTF_8).replace("\r\n", "\n").replace('\r', '\n')
                        sqlFiles += SqlFile(rel, text)
                    }
                }
            }

        val out = mutableListOf<Hit>()
        if (mode == ScanMode.ALL || mode == ScanMode.SECRETS) {
            out += detectSecrets(ktFiles, configFiles)
        }
        if (mode == ScanMode.ALL || mode == ScanMode.SAST) {
            out += detectSast(ktFiles, sqlFiles)
        }
        return out
            .map { clampHit(it) }
            .distinctBy { "${it.category}:${it.`class`}:${it.path}:${it.line}" }
    } finally {
        Disposer.dispose(disposable)
    }
}

private fun clampHit(hit: Hit): Hit {
    val line = maxOf(1, hit.line)
    val end = minOf(maxOf(line, hit.endLine), line + 14)
    return if (line == hit.line && end == hit.endLine) hit else hit.copy(line = line, endLine = end)
}

// ============================================================================
// SECRET RULES (Kotlin PSI + SnakeYAML + .properties)
// ============================================================================

private val ENV_ONLY_RE = Regex("""^\$\{[A-Za-z_][A-Za-z0-9_.-]*:?\s*\}$""")
private val ENV_DEFAULT_RE = Regex("""^\$\{([A-Za-z_][A-Za-z0-9_.-]*):([^}]+)\}$""")
private val TEMPLATE_EXPR_RE = Regex("""^(\$\{\{.*\}\}|\{\{.*\}\}|\$\(.*\)|%\{.*\}|ENC\(.*\)|vault:.*|aws-sm:.*|k8s:.*)$""", RegexOption.IGNORE_CASE)
private val PURE_NUMBER_RE = Regex("""^-?\d+(?:\.\d+)?$""")
private val DURATION_RE = Regex("""^\d+\s*(?:ms|s|m|h|d|ns|us)$""", RegexOption.IGNORE_CASE)
private val URL_WITH_CREDS_RE = Regex("""^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@""")
private val JDBC_PASSWORD_RE = Regex("""[?&;]password=([^&;\s]+)""", RegexOption.IGNORE_CASE)

private val AUTH_HEADER_KEYS = setOf(
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "private-token",
    "authorization",
)

private val METADATA_SUFFIXES = listOf(
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
)

private val GENERIC_VALUE_LEAF_KEYS = setOf(
    "value", "val", "key", "default", "raw", "literal", "credentials", "credential", "auth",
)

private fun detectSecrets(ktFiles: List<ParsedKtFile>, configFiles: List<ConfigFile>): List<Hit> {
    val out = mutableListOf<Hit>()
    for (file in ktFiles) {
        out += detectKotlinSecrets(file)
    }
    for (cfg in configFiles) {
        when (cfg.ext) {
            "yml", "yaml" -> out += detectYamlSecrets(cfg)
            "properties" -> out += detectPropertiesSecrets(cfg)
        }
    }
    return out
}

private fun detectKotlinSecrets(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()
    val reportedLines = mutableSetOf<Int>()

    // Collect single-literal properties for sink tracing (even with generic variable names).
    val literalProps = mutableMapOf<String, Pair<String, Pair<Int, Int>>>()

    // 1. Property declarations: password & api-key
    for (prop in PsiTreeUtil.collectElementsOfType(file.ktFile, KtProperty::class.java)) {
        val name = prop.name ?: continue
        val init = prop.initializer ?: continue
        val literal = extractPureStringLiteral(init) ?: continue
        val range = file.lines.rangeOf(prop)
        literalProps[name] = literal to range
        if (!isSecretLiteral(literal)) continue
        val (line, endLine) = range
        when {
            isPasswordName(name) -> {
                out += Hit(
                    category = "SECRET",
                    `class` = "password",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "HIGH",
                    description = "Встроенный пароль хранится строковым литералом в исходнике.",
                    remediation = "Читать пароль из окружения или хранилища секретов без литерала по умолчанию.",
                )
                reportedLines += line
            }
            isApiKeyName(name) -> {
                out += Hit(
                    category = "SECRET",
                    `class` = "api-key",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "MEDIUM",
                    description = "Встроенный API-ключ задан строковым литералом.",
                    remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
                )
                reportedLines += line
            }
        }
    }

    // 2. Parameter default values: password & api-key
    for (param in PsiTreeUtil.collectElementsOfType(file.ktFile, KtParameter::class.java)) {
        val name = param.name ?: continue
        val defVal = param.defaultValue ?: continue
        val literal = extractPureStringLiteral(defVal) ?: continue
        if (!isSecretLiteral(literal)) continue
        val (line, endLine) = file.lines.rangeOf(param)
        when {
            isPasswordName(name) -> {
                out += Hit(
                    category = "SECRET",
                    `class` = "password",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "HIGH",
                    description = "Встроенный пароль задан значением параметра по умолчанию.",
                    remediation = "Читать пароль из окружения или хранилища секретов без литерала по умолчанию.",
                )
                reportedLines += line
            }
            isApiKeyName(name) -> {
                out += Hit(
                    category = "SECRET",
                    `class` = "api-key",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "MEDIUM",
                    description = "Встроенный API-ключ задан значением параметра по умолчанию.",
                    remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
                )
                reportedLines += line
            }
        }
    }

    // 3. Direct assignments & bracket header assignments (e.g. this.password = "...", headers["X-Api-Key"] = "...")
    for (bin in PsiTreeUtil.collectElementsOfType(file.ktFile, KtBinaryExpression::class.java)) {
        if (bin.operationToken != KtTokens.EQ) continue
        val lhs = unwrapParens(bin.left) ?: continue
        val rhs = unwrapParens(bin.right) ?: continue
        val literal = extractPureStringLiteral(rhs) ?: continue
        val (line, endLine) = file.lines.rangeOf(bin)
        if (line in reportedLines) continue

        if (lhs is KtArrayAccessExpression) {
            val keyExpr = lhs.indexExpressions.firstOrNull()
            val keyText = (extractPureStringLiteral(keyExpr) ?: keyExpr?.text.orEmpty()).lowercase()
            if (isAuthHeaderKey(keyText)) {
                val effective = stripAuthSchemePrefix(literal)
                if (isSecretLiteral(effective)) {
                    out += Hit(
                        category = "SECRET",
                        `class` = "api-key",
                        path = file.path,
                        line = line,
                        endLine = endLine,
                        severity = "MEDIUM",
                        description = "Встроенный секретный ключ передаётся литералом в HTTP-заголовок.",
                        remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
                    )
                    reportedLines += line
                }
            }
            continue
        }

        val targetName = lhs.text.substringAfterLast('.')
        if (!isSecretLiteral(literal)) continue
        when {
            isPasswordName(targetName) -> {
                out += Hit(
                    category = "SECRET",
                    `class` = "password",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "HIGH",
                    description = "Встроенный пароль присваивается строковым литералом.",
                    remediation = "Читать пароль из окружения или хранилища секретов без литерала по умолчанию.",
                )
                reportedLines += line
            }
            isApiKeyName(targetName) -> {
                out += Hit(
                    category = "SECRET",
                    `class` = "api-key",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "MEDIUM",
                    description = "Встроенный API-ключ присваивается строковым литералом.",
                    remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
                )
                reportedLines += line
            }
        }
    }

    // 4. Direct literal credentials in HTTP header sinks, setBearerAuth/setBasicAuth, `to` pairs, and named call args
    for (call in PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)) {
        val callee = call.calleeExpression?.text ?: continue
        val args = call.valueArguments

        // Named arguments in constructor/function calls (e.g. ClientConfig(apiKey = "...", password = "..."))
        for (arg in args) {
            val argName = arg.getArgumentName()?.asName?.asString() ?: continue
            val literal = extractPureStringLiteral(arg.getArgumentExpression()) ?: continue
            if (!isSecretLiteral(literal)) continue
            val (line, endLine) = file.lines.rangeOf(arg)
            if (line in reportedLines) continue
            when {
                isPasswordName(argName) -> {
                    out += Hit(
                        category = "SECRET",
                        `class` = "password",
                        path = file.path,
                        line = line,
                        endLine = endLine,
                        severity = "HIGH",
                        description = "Встроенный пароль передаётся литералом в аргумент вызова.",
                        remediation = "Читать пароль из окружения или хранилища секретов без литерала по умолчанию.",
                    )
                    reportedLines += line
                }
                isApiKeyName(argName) -> {
                    out += Hit(
                        category = "SECRET",
                        `class` = "api-key",
                        path = file.path,
                        line = line,
                        endLine = endLine,
                        severity = "MEDIUM",
                        description = "Встроенный API-ключ передаётся литералом в аргумент вызова.",
                        remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
                    )
                    reportedLines += line
                }
            }
        }

        val sinkArg = extractSecuritySinkArg(call)
        if (sinkArg != null) {
            val directLit = extractPureStringLiteral(sinkArg)
            val resolved = if (directLit != null) {
                directLit to file.lines.rangeOf(call)
            } else {
                val refName = (unwrapParens(sinkArg) as? KtNameReferenceExpression)?.getReferencedName()
                refName?.let { literalProps[it] }
            }
            if (resolved != null) {
                val effective = stripAuthSchemePrefix(resolved.first)
                val (line, endLine) = resolved.second
                if (isSecretLiteral(effective) && line !in reportedLines) {
                    val cls = if (callee == "setBasicAuth") "password" else "api-key"
                    val sev = if (cls == "password") "HIGH" else "MEDIUM"
                    out += Hit(
                        category = "SECRET",
                        `class` = cls,
                        path = file.path,
                        line = line,
                        endLine = endLine,
                        severity = sev,
                        description = "Встроенный секретный ключ передаётся литералом в заголовок авторизации.",
                        remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
                    )
                    reportedLines += line
                }
            }
        }
    }

    // 5. Pair infix `"X-Api-Key" to "literal"`
    for (bin in PsiTreeUtil.collectElementsOfType(file.ktFile, KtBinaryExpression::class.java)) {
        if (bin.operationReference.getReferencedName() != "to") continue
        val headerName = extractPureStringLiteral(bin.left)?.lowercase() ?: continue
        if (!isAuthHeaderKey(headerName)) continue
        val literalVal = extractPureStringLiteral(bin.right) ?: continue
        val effective = stripAuthSchemePrefix(literalVal)
        if (!isSecretLiteral(effective)) continue
        val (line, endLine) = file.lines.rangeOf(bin)
        if (line in reportedLines) continue
        out += Hit(
            category = "SECRET",
            `class` = "api-key",
            path = file.path,
            line = line,
            endLine = endLine,
            severity = "MEDIUM",
            description = "Встроенный API-ключ передаётся литералом в пару HTTP-заголовка.",
            remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
        )
        reportedLines += line
    }

    // 6. Secret fallback: Elvis (System.getenv/getProperty), local env var Elvis, getOrDefault,
    //    2-arg getProperty(key, default), ifBlank { "literal" }, and @Value("${cred:literal}")
    val envVarSources = mutableMapOf<String, String>()
    for (prop in PsiTreeUtil.collectElementsOfType(file.ktFile, KtProperty::class.java)) {
        val name = prop.name ?: continue
        val init = prop.initializer ?: continue
        val key = extractEnvLookupKey(init)
        if (key != null) {
            envVarSources[name] = key
        }
    }

    for (bin in PsiTreeUtil.collectElementsOfType(file.ktFile, KtBinaryExpression::class.java)) {
        if (bin.operationToken != KtTokens.ELVIS) continue
        val left = bin.left ?: continue
        val right = bin.right ?: continue
        val envKey = extractEnvLookupKey(left)
            ?: (unwrapParens(left) as? KtNameReferenceExpression)?.getReferencedName()?.let { envVarSources[it] }
            ?: continue
        val fallbackLiteral = extractPureStringLiteral(right) ?: continue
        if (!isSecretLiteral(fallbackLiteral)) continue
        val enclosingName = PsiTreeUtil.getParentOfType(bin, KtProperty::class.java)?.name.orEmpty()
        if (!looksCredentialIdentifier(envKey) && !looksCredentialIdentifier(enclosingName)) continue
        val (line, endLine) = file.lines.rangeOf(bin)
        out += Hit(
            category = "SECRET",
            `class` = "secret-fallback",
            path = file.path,
            line = line,
            endLine = endLine,
            severity = "LOW",
            description = "При отсутствии переменной окружения используется встроенный секрет.",
            remediation = "Удалить fallback. При отсутствии переменной отключать интеграцию.",
        )
    }

    for (call in PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)) {
        val callee = call.calleeExpression?.text ?: continue
        val parentDot = call.parent as? KtDotQualifiedExpression
        val parentSafe = call.parent as? KtSafeQualifiedExpression
        val recv = parentDot?.receiverExpression ?: parentSafe?.receiverExpression

        when (callee) {
            "getOrDefault" -> {
                val recvText = recv?.text.orEmpty()
                if (!recvText.contains("getenv") && !recvText.contains("getProperties") && !recvText.contains("env", ignoreCase = true)) continue
                val args = call.valueArguments
                if (args.size < 2) continue
                val envKey = extractPureStringLiteral(args[0].getArgumentExpression()).orEmpty()
                val fallbackLiteral = extractPureStringLiteral(args[1].getArgumentExpression()) ?: continue
                if (!isSecretLiteral(fallbackLiteral)) continue
                val enclosingName = PsiTreeUtil.getParentOfType(call, KtProperty::class.java)?.name.orEmpty()
                if (!looksCredentialIdentifier(envKey) && !looksCredentialIdentifier(enclosingName)) continue
                val (line, endLine) = file.lines.rangeOf(call)
                out += Hit(
                    category = "SECRET",
                    `class` = "secret-fallback",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "LOW",
                    description = "При отсутствии переменной окружения используется встроенный секрет.",
                    remediation = "Удалить fallback. При отсутствии переменной отключать интеграцию.",
                )
            }
            "getProperty" -> {
                val recvText = recv?.text.orEmpty()
                if (recvText != "System" && !recvText.contains("env", ignoreCase = true) && !recvText.contains("environment", ignoreCase = true)) continue
                val args = call.valueArguments
                if (args.size < 2) continue
                val propKey = extractPureStringLiteral(args[0].getArgumentExpression()).orEmpty()
                val fallbackLiteral = extractPureStringLiteral(args[1].getArgumentExpression()) ?: continue
                if (!isSecretLiteral(fallbackLiteral)) continue
                val enclosingName = PsiTreeUtil.getParentOfType(call, KtProperty::class.java)?.name.orEmpty()
                if (!looksCredentialIdentifier(propKey) && !looksCredentialIdentifier(enclosingName)) continue
                val (line, endLine) = file.lines.rangeOf(call)
                out += Hit(
                    category = "SECRET",
                    `class` = "secret-fallback",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "LOW",
                    description = "При отсутствии свойства окружения используется встроенный секрет.",
                    remediation = "Удалить fallback. При отсутствии свойства отключать интеграцию.",
                )
            }
            "ifBlank", "ifEmpty" -> {
                if (recv == null) continue
                val envKey = extractEnvLookupKey(recv)
                    ?: (unwrapParens(recv) as? KtNameReferenceExpression)?.getReferencedName()?.let { envVarSources[it] }
                    ?: continue
                val lambda = call.lambdaArguments.firstOrNull()?.getLambdaExpression()
                    ?: call.valueArguments.firstOrNull()?.getArgumentExpression() as? KtLambdaExpression
                    ?: continue
                val lastStmt = lambda.bodyExpression?.statements?.lastOrNull() ?: continue
                val fallbackLiteral = extractPureStringLiteral(lastStmt) ?: continue
                if (!isSecretLiteral(fallbackLiteral)) continue
                val enclosingName = PsiTreeUtil.getParentOfType(call, KtProperty::class.java)?.name.orEmpty()
                if (!looksCredentialIdentifier(envKey) && !looksCredentialIdentifier(enclosingName)) continue
                val (line, endLine) = file.lines.rangeOf(parentDot ?: parentSafe ?: call)
                out += Hit(
                    category = "SECRET",
                    `class` = "secret-fallback",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "LOW",
                    description = "При пустой переменной окружения используется встроенный секрет.",
                    remediation = "Удалить fallback. При отсутствии переменной отключать интеграцию.",
                )
            }
        }
    }

    for (ann in PsiTreeUtil.collectElementsOfType(file.ktFile, KtAnnotationEntry::class.java)) {
        if (ann.shortName?.asString() != "Value") continue
        val expr = ann.valueArguments.firstOrNull()?.getArgumentExpression() ?: continue
        val raw = extractStringTemplateRaw(expr) ?: continue
        val m = ENV_DEFAULT_RE.find(raw.trim()) ?: continue
        val propKey = m.groupValues[1].trim()
        val defaultVal = m.groupValues[2].trim()
        if (!isSecretLiteral(defaultVal)) continue
        val targetName = PsiTreeUtil.getParentOfType(ann, KtProperty::class.java)?.name
            ?: PsiTreeUtil.getParentOfType(ann, KtParameter::class.java)?.name
            ?: ""
        if (!looksCredentialIdentifier(propKey) && !looksCredentialIdentifier(targetName)) continue
        val (line, endLine) = file.lines.rangeOf(ann)
        out += Hit(
            category = "SECRET",
            `class` = "secret-fallback",
            path = file.path,
            line = line,
            endLine = endLine,
            severity = "LOW",
            description = "Аннотация @Value содержит секретный литерал по умолчанию.",
            remediation = "Убрать литерал по умолчанию из @Value.",
        )
    }

    // 7. Recoverable token (constant folding across file/class/function fragments flowing to auth sinks)
    out += detectRecoverableTokens(file)

    return out
}

private data class FoldedConst(
    val value: String,
    val startLine: Int,
    val endLine: Int,
    val combined: Boolean,
)

private fun detectRecoverableTokens(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()
    val reportedSinks = mutableSetOf<Int>()

    // File-level & class/object-level constants visible inside methods
    val fileConsts = mutableMapOf<String, FoldedConst>()
    val fileLists = mutableMapOf<String, Pair<List<FoldedConst>, Int>>()

    fun collectScopeProps(props: Collection<KtProperty>, consts: MutableMap<String, FoldedConst>, lists: MutableMap<String, Pair<List<FoldedConst>, Int>>) {
        for (prop in props.sortedBy { it.textRange.startOffset }) {
            val name = prop.name ?: continue
            val init = prop.initializer ?: continue
            val (propLine, propEnd) = file.lines.rangeOf(prop)
            val evaluated = evalFoldedString(init, consts, lists, file.lines)
            if (evaluated != null) {
                consts[name] = evaluated.copy(
                    startLine = minOf(evaluated.startLine, propLine),
                    endLine = maxOf(evaluated.endLine, propEnd),
                )
                continue
            }
            val listParts = evalFoldedList(init, consts, lists, file.lines)
            if (listParts != null) {
                lists[name] = listParts to propLine
            }
        }
    }

    val topLevelProps = file.ktFile.declarations.filterIsInstance<KtProperty>()
    collectScopeProps(topLevelProps, fileConsts, fileLists)

    // Collect per-class/object member constants
    val classConstsMap = mutableMapOf<KtClassOrObject, Pair<Map<String, FoldedConst>, Map<String, Pair<List<FoldedConst>, Int>>>>()
    val allClassLike = PsiTreeUtil.collectElementsOfType(file.ktFile, KtClassOrObject::class.java)
    for (cls in allClassLike) {
        val cMap = fileConsts.toMutableMap()
        val lMap = fileLists.toMutableMap()
        val memberProps = cls.declarations.filterIsInstance<KtProperty>().toMutableList()
        for (comp in cls.declarations.filterIsInstance<KtObjectDeclaration>()) {
            memberProps += comp.declarations.filterIsInstance<KtProperty>()
        }
        collectScopeProps(memberProps, cMap, lMap)
        classConstsMap[cls] = cMap to lMap
    }

    for (fn in PsiTreeUtil.collectElementsOfType(file.ktFile, KtNamedFunction::class.java)) {
        val enclosingCls = PsiTreeUtil.getParentOfType(fn, KtClassOrObject::class.java)
        val base = enclosingCls?.let { classConstsMap[it] }
        val consts = (base?.first ?: fileConsts).toMutableMap()
        val lists = (base?.second ?: fileLists).toMutableMap()

        val localProps = PsiTreeUtil.collectElementsOfType(fn, KtProperty::class.java)
        collectScopeProps(localProps, consts, lists)

        // Check calls to security sinks
        for (call in PsiTreeUtil.collectElementsOfType(fn, KtCallExpression::class.java)) {
            val sinkArg = extractSecuritySinkArg(call) ?: continue
            val evaluated = evalFoldedString(sinkArg, consts, lists, file.lines) ?: continue
            val effective = stripAuthSchemePrefix(evaluated.value)
            if (!evaluated.combined || !isSecretLiteral(effective)) continue
            val (_, callEnd) = file.lines.rangeOf(call)
            if (!reportedSinks.add(evaluated.startLine)) continue
            out += Hit(
                category = "SECRET",
                `class` = "recoverable-token",
                path = file.path,
                line = evaluated.startLine,
                endLine = maxOf(evaluated.endLine, callEnd),
                severity = "MEDIUM",
                description = "Токен собирается из строковых фрагментов в исходнике и уходит в заголовок авторизации.",
                remediation = "Подставлять цельный токен из окружения или хранилища секретов.",
            )
        }

        // Check bracket header assignments `headers["Authorization"] = ...`
        for (bin in PsiTreeUtil.collectElementsOfType(fn, KtBinaryExpression::class.java)) {
            if (bin.operationToken != KtTokens.EQ) continue
            val lhs = unwrapParens(bin.left) as? KtArrayAccessExpression ?: continue
            val keyExpr = lhs.indexExpressions.firstOrNull()
            val keyText = (extractPureStringLiteral(keyExpr) ?: keyExpr?.text.orEmpty()).lowercase()
            if (!isAuthHeaderKey(keyText)) continue
            val evaluated = evalFoldedString(bin.right, consts, lists, file.lines) ?: continue
            val effective = stripAuthSchemePrefix(evaluated.value)
            if (!evaluated.combined || !isSecretLiteral(effective)) continue
            val (_, assignEnd) = file.lines.rangeOf(bin)
            if (!reportedSinks.add(evaluated.startLine)) continue
            out += Hit(
                category = "SECRET",
                `class` = "recoverable-token",
                path = file.path,
                line = evaluated.startLine,
                endLine = maxOf(evaluated.endLine, assignEnd),
                severity = "MEDIUM",
                description = "Токен собирается из строковых фрагментов в исходнике и записывается в заголовок авторизации.",
                remediation = "Подставлять цельный токен из окружения или хранилища секретов.",
            )
        }
    }
    return out
}

private fun evalFoldedList(
    expr: KtExpression?,
    consts: Map<String, FoldedConst>,
    lists: Map<String, Pair<List<FoldedConst>, Int>>,
    lines: LineIndex,
): List<FoldedConst>? {
    val unwrapped = unwrapParens(expr) ?: return null
    val call = unwrapped as? KtCallExpression ?: return null
    if (call.calleeExpression?.text !in setOf("listOf", "arrayOf", "mutableListOf")) return null
    val parts = call.valueArguments.map {
        evalFoldedString(it.getArgumentExpression(), consts, lists, lines) ?: return null
    }
    return if (parts.size >= 2) parts else null
}

private fun evalFoldedString(
    expr: KtExpression?,
    consts: Map<String, FoldedConst>,
    lists: Map<String, Pair<List<FoldedConst>, Int>>,
    lines: LineIndex,
): FoldedConst? {
    val unwrapped = unwrapParens(expr) ?: return null
    val (line, endLine) = lines.rangeOf(unwrapped)
    return when (unwrapped) {
        is KtStringTemplateExpression -> {
            if (!unwrapped.hasInterpolation()) {
                val lit = extractPureStringLiteral(unwrapped) ?: return null
                FoldedConst(lit, line, endLine, combined = false)
            } else {
                val sb = StringBuilder()
                var minLine = line
                var maxLine = endLine
                var parts = 0
                var hadCombined = false
                var nonEmptyLiterals = 0
                for (entry in unwrapped.entries) {
                    when (entry) {
                        is KtLiteralStringTemplateEntry -> {
                            sb.append(entry.text)
                            if (entry.text.isNotBlank()) nonEmptyLiterals++
                        }
                        is KtEscapeStringTemplateEntry -> {
                            sb.append(entry.unescapedValue)
                            if (entry.unescapedValue.isNotBlank()) nonEmptyLiterals++
                        }
                        is KtStringTemplateEntryWithExpression -> {
                            val sub = evalFoldedString(entry.expression, consts, lists, lines) ?: return null
                            sb.append(sub.value)
                            minLine = minOf(minLine, sub.startLine)
                            maxLine = maxOf(maxLine, sub.endLine)
                            parts++
                            if (sub.combined) hadCombined = true
                        }
                        else -> return null
                    }
                }
                val isCombined = hadCombined || parts >= 2 || (parts >= 1 && nonEmptyLiterals >= 1 && !sb.toString().startsWith("Bearer ", ignoreCase = true) && !sb.toString().startsWith("Basic ", ignoreCase = true))
                FoldedConst(sb.toString(), minLine, maxLine, combined = isCombined)
            }
        }
        is KtNameReferenceExpression -> consts[unwrapped.getReferencedName()]
        is KtBinaryExpression -> {
            if (unwrapped.operationToken != KtTokens.PLUS) return null
            val left = evalFoldedString(unwrapped.left, consts, lists, lines) ?: return null
            val right = evalFoldedString(unwrapped.right, consts, lists, lines) ?: return null
            val leftTrim = left.value.trim().lowercase()
            val justAuthPrefix = (leftTrim == "bearer" || leftTrim == "basic") && !left.combined && !right.combined
            FoldedConst(
                value = left.value + right.value,
                startLine = minOf(left.startLine, right.startLine),
                endLine = maxOf(left.endLine, right.endLine, endLine),
                combined = !justAuthPrefix,
            )
        }
        is KtCallExpression -> {
            val callee = unwrapped.calleeExpression?.text ?: return null
            when (callee) {
                "buildString" -> evalBuildString(unwrapped, consts, lists, lines)
                "String" -> {
                    val arg = unwrapped.valueArguments.firstOrNull()?.getArgumentExpression() ?: return null
                    evalBase64Decode(arg, consts, lists, lines)
                }
                else -> null
            }
        }
        is KtDotQualifiedExpression -> {
            val sel = unwrapped.selectorExpression as? KtCallExpression ?: return null
            val selName = sel.calleeExpression?.text ?: return null
            when (selName) {
                "joinToString" -> {
                    val sep = sel.valueArguments.firstOrNull()?.let { extractPureStringLiteral(it.getArgumentExpression()) } ?: ", "
                    val recv = unwrapParens(unwrapped.receiverExpression)
                    val parts = evalFoldedList(recv, consts, lists, lines)
                        ?: (recv as? KtNameReferenceExpression)?.getReferencedName()?.let { lists[it]?.first }
                        ?: return null
                    if (parts.size < 2) return null
                    FoldedConst(
                        value = parts.joinToString(sep) { it.value },
                        startLine = parts.minOf { it.startLine },
                        endLine = maxOf(parts.maxOf { it.endLine }, endLine),
                        combined = true,
                    )
                }
                "toString" -> {
                    evalStringBuilderChain(unwrapped.receiverExpression, consts, lists, lines)
                }
                "plus" -> {
                    val left = evalFoldedString(unwrapped.receiverExpression, consts, lists, lines) ?: return null
                    val right = evalFoldedString(sel.valueArguments.firstOrNull()?.getArgumentExpression(), consts, lists, lines) ?: return null
                    FoldedConst(
                        value = left.value + right.value,
                        startLine = minOf(left.startLine, right.startLine),
                        endLine = maxOf(left.endLine, right.endLine, endLine),
                        combined = true,
                    )
                }
                "reversed" -> {
                    val inner = evalFoldedString(unwrapped.receiverExpression, consts, lists, lines) ?: return null
                    FoldedConst(inner.value.reversed(), inner.startLine, maxOf(inner.endLine, endLine), combined = true)
                }
                "decodeToString" -> evalBase64Decode(unwrapped.receiverExpression, consts, lists, lines)
                "trim", "trimIndent", "trimMargin" -> {
                    val inner = evalFoldedString(unwrapped.receiverExpression, consts, lists, lines) ?: return null
                    inner.copy(value = inner.value.trim(), endLine = maxOf(inner.endLine, endLine))
                }
                else -> null
            }
        }
        else -> null
    }
}

private fun evalBuildString(
    call: KtCallExpression,
    consts: Map<String, FoldedConst>,
    lists: Map<String, Pair<List<FoldedConst>, Int>>,
    lines: LineIndex,
): FoldedConst? {
    val lambda = call.lambdaArguments.firstOrNull()?.getLambdaExpression()
        ?: call.valueArguments.firstOrNull()?.getArgumentExpression() as? KtLambdaExpression
        ?: return null
    val stmts = lambda.bodyExpression?.statements ?: return null
    val sb = StringBuilder()
    var minLine = lines.rangeOf(call).first
    var maxLine = lines.rangeOf(call).second
    var count = 0
    for (stmt in stmts) {
        val appendCall = when (stmt) {
            is KtCallExpression -> if (stmt.calleeExpression?.text == "append") stmt else return null
            is KtDotQualifiedExpression -> (stmt.selectorExpression as? KtCallExpression)?.takeIf { it.calleeExpression?.text == "append" } ?: return null
            else -> return null
        }
        val arg = appendCall.valueArguments.firstOrNull()?.getArgumentExpression() ?: return null
        val sub = evalFoldedString(arg, consts, lists, lines) ?: return null
        sb.append(sub.value)
        minLine = minOf(minLine, sub.startLine)
        maxLine = maxOf(maxLine, sub.endLine)
        count++
    }
    if (count < 2) return null
    return FoldedConst(sb.toString(), minLine, maxLine, combined = true)
}

private fun evalStringBuilderChain(
    expr: KtExpression?,
    consts: Map<String, FoldedConst>,
    lists: Map<String, Pair<List<FoldedConst>, Int>>,
    lines: LineIndex,
): FoldedConst? {
    val parts = mutableListOf<FoldedConst>()
    var cur = unwrapParens(expr)
    var sawBuilder = false
    while (cur != null) {
        when (cur) {
            is KtDotQualifiedExpression -> {
                val sel = cur.selectorExpression as? KtCallExpression ?: return null
                if (sel.calleeExpression?.text != "append") return null
                val arg = sel.valueArguments.firstOrNull()?.getArgumentExpression() ?: return null
                val sub = evalFoldedString(arg, consts, lists, lines) ?: return null
                parts += sub
                cur = unwrapParens(cur.receiverExpression)
            }
            is KtCallExpression -> {
                if (cur.calleeExpression?.text != "StringBuilder") return null
                sawBuilder = true
                val initArg = cur.valueArguments.firstOrNull()?.getArgumentExpression()
                if (initArg != null) {
                    val sub = evalFoldedString(initArg, consts, lists, lines) ?: return null
                    parts += sub
                }
                cur = null
            }
            else -> return null
        }
    }
    if (!sawBuilder || parts.size < 2) return null
    parts.reverse()
    return FoldedConst(
        value = parts.joinToString("") { it.value },
        startLine = parts.minOf { it.startLine },
        endLine = parts.maxOf { it.endLine },
        combined = true,
    )
}

private fun evalBase64Decode(
    expr: KtExpression?,
    consts: Map<String, FoldedConst>,
    lists: Map<String, Pair<List<FoldedConst>, Int>>,
    lines: LineIndex,
): FoldedConst? {
    val dot = unwrapParens(expr) as? KtDotQualifiedExpression ?: return null
    val sel = dot.selectorExpression as? KtCallExpression ?: return null
    if (sel.calleeExpression?.text != "decode") return null
    if (!dot.receiverExpression.text.contains("Base64", ignoreCase = true)) return null
    val arg = sel.valueArguments.firstOrNull()?.getArgumentExpression() ?: return null
    val raw = evalFoldedString(arg, consts, lists, lines) ?: return null
    val decoded = try {
        String(Base64.getDecoder().decode(raw.value.trim()), Charsets.UTF_8)
    } catch (_: Throwable) {
        return null
    }
    if (decoded.any { it.code < 0x20 && it != '\t' }) return null
    val (_, endLine) = lines.rangeOf(dot)
    return FoldedConst(decoded, raw.startLine, maxOf(raw.endLine, endLine), combined = true)
}

private fun extractSecuritySinkArg(call: KtCallExpression): KtExpression? {
    val callee = call.calleeExpression?.text ?: return null
    val args = call.valueArguments
    return when (callee) {
        "setBearerAuth", "bearerAuth" -> args.firstOrNull()?.getArgumentExpression()
        "setBasicAuth", "basicAuth" -> args.lastOrNull()?.getArgumentExpression()
        "header", "addHeader", "set", "put", "add" -> {
            if (args.size < 2) return null
            val keyExpr = args[0].getArgumentExpression()
            val keyText = (extractPureStringLiteral(keyExpr) ?: keyExpr?.text.orEmpty()).lowercase()
            if (isAuthHeaderKey(keyText)) {
                args[1].getArgumentExpression()
            } else {
                null
            }
        }
        else -> null
    }
}

private fun isAuthHeaderKey(keyTextLower: String): Boolean {
    if (keyTextLower in AUTH_HEADER_KEYS) return true
    return keyTextLower.contains("authorization") ||
        keyTextLower.contains("api-key") ||
        keyTextLower.contains("api_key") ||
        keyTextLower.contains("x-auth") ||
        keyTextLower.contains("private-token")
}

private fun stripAuthSchemePrefix(value: String): String {
    val trimmed = value.trim()
    return when {
        trimmed.startsWith("Bearer ", ignoreCase = true) -> trimmed.substringAfter(' ').trim()
        trimmed.startsWith("Basic ", ignoreCase = true) -> trimmed.substringAfter(' ').trim()
        trimmed.startsWith("Token ", ignoreCase = true) -> trimmed.substringAfter(' ').trim()
        else -> trimmed
    }
}

private fun detectYamlSecrets(cfg: ConfigFile): List<Hit> {
    val out = mutableListOf<Hit>()
    val docs = try {
        Yaml().composeAll(StringReader(cfg.text)).toList()
    } catch (_: Throwable) {
        emptyList()
    }
    if (docs.isEmpty()) return emptyList()

    fun walk(node: Node, keyPath: String) {
        when (node) {
            is MappingNode -> {
                for (tuple in node.value) {
                    val keyScalar = tuple.keyNode as? ScalarNode ?: continue
                    val key = keyScalar.value.trim()
                    val nextPath = if (keyPath.isEmpty()) key else "$keyPath.$key"
                    walk(tuple.valueNode, nextPath)
                }
            }
            is SequenceNode -> {
                node.value.forEachIndexed { idx, item ->
                    walk(item, "$keyPath[$idx]")
                }
            }
            is ScalarNode -> {
                val value = node.value.trim()
                val line = (node.startMark?.line ?: 0) + 1
                checkConfigSecretEntry(cfg.path, keyPath, value, line, out)
            }
        }
    }

    for (doc in docs) {
        walk(doc, "")
    }
    return out
}

private fun detectPropertiesSecrets(cfg: ConfigFile): List<Hit> {
    val out = mutableListOf<Hit>()
    cfg.text.split('\n').forEachIndexed { idx, rawLine ->
        val trim = rawLine.trim()
        if (trim.isEmpty() || trim.startsWith("#") || trim.startsWith("!")) return@forEachIndexed
        val eq = trim.indexOf('=')
        val colon = trim.indexOf(':')
        val sep = when {
            eq >= 0 && (colon < 0 || eq < colon) -> eq
            colon >= 0 -> colon
            else -> -1
        }
        if (sep <= 0) return@forEachIndexed
        val key = trim.substring(0, sep).trim()
        val value = trim.substring(sep + 1).trim().trim('"', '\'')
        checkConfigSecretEntry(cfg.path, key, value, idx + 1, out)
    }
    return out
}

private fun checkConfigSecretEntry(path: String, keyPath: String, value: String, line: Int, out: MutableList<Hit>) {
    if (value.isEmpty() || ENV_ONLY_RE.matches(value) || TEMPLATE_EXPR_RE.matches(value)) return

    // Check embedded password in JDBC/service URLs even when key is e.g. `datasource.url`
    val jdbcPwd = JDBC_PASSWORD_RE.find(value)?.groupValues?.getOrNull(1)?.trim()
    if (jdbcPwd != null && !ENV_ONLY_RE.matches(jdbcPwd) && !TEMPLATE_EXPR_RE.matches(jdbcPwd) && isSecretLiteral(jdbcPwd)) {
        out += Hit(
            category = "SECRET",
            `class` = "configuration-token",
            path = path,
            line = line,
            endLine = line,
            severity = "HIGH",
            description = "В строке подключения конфигурации записан пароль литералом.",
            remediation = "Передавать пароль отдельно через переменную окружения без встроенного значения.",
        )
        return
    }
    val urlPwd = URL_WITH_CREDS_RE.find(value)?.groupValues?.getOrNull(1)?.trim()
    if (urlPwd != null && !ENV_ONLY_RE.matches(urlPwd) && !TEMPLATE_EXPR_RE.matches(urlPwd) && isSecretLiteral(urlPwd)) {
        out += Hit(
            category = "SECRET",
            `class` = "configuration-token",
            path = path,
            line = line,
            endLine = line,
            severity = "HIGH",
            description = "В URL конфигурации записаны учётные данные литералом.",
            remediation = "Убрать пароль из URL и передавать учётные данные через переменные окружения.",
        )
        return
    }

    val envDefault = ENV_DEFAULT_RE.find(value)?.groupValues?.getOrNull(2)?.trim()
    val effectiveVal = envDefault ?: value
    if (effectiveVal.isEmpty() || ENV_ONLY_RE.matches(effectiveVal) || TEMPLATE_EXPR_RE.matches(effectiveVal)) return

    val bearerOrBasic = effectiveVal.startsWith("Bearer ", ignoreCase = true) ||
        effectiveVal.startsWith("Basic ", ignoreCase = true)
    if (bearerOrBasic) {
        val tokenPart = effectiveVal.substringAfter(' ').trim()
        if (tokenPart.isEmpty() || ENV_ONLY_RE.matches(tokenPart) || TEMPLATE_EXPR_RE.matches(tokenPart) || !isSecretLiteral(tokenPart)) {
            return
        }
    } else {
        if (!isConfigSecretKey(keyPath)) return
        if (!isSecretLiteral(effectiveVal) || isNonSecretConfigValue(effectiveVal)) return
    }

    out += Hit(
        category = "SECRET",
        `class` = "configuration-token",
        path = path,
        line = line,
        endLine = line,
        severity = "HIGH",
        description = "В конфигурации записан токен или секрет литералом.",
        remediation = "Задать свойство через переменную окружения без встроенного значения.",
    )
}

private fun isNonSecretConfigValue(value: String): Boolean {
    val v = value.trim()
    val low = v.lowercase()
    if (low == "true" || low == "false" || low == "yes" || low == "no" || low == "on" || low == "off") return true
    if (PURE_NUMBER_RE.matches(v) && v.length <= 6) return true
    if (DURATION_RE.matches(v)) return true
    return false
}

// ============================================================================
// SAST RULES (Kotlin PSI AST — single-file & cross-file)
// ============================================================================

private val SQL_CALL_NAMES = setOf(
    "queryForList",
    "queryForObject",
    "queryForMap",
    "queryForRowSet",
    "queryForStream",
    "query",
    "update",
    "batchUpdate",
    "execute",
    "createNativeQuery",
    "createQuery",
    "executeQuery",
    "executeUpdate",
    "prepareStatement",
    "sql",
)

private val SQL_VERB_RE = Regex("""\b(select|insert|update|delete|merge)\b""", RegexOption.IGNORE_CASE)
private val SQL_CLAUSE_RE = Regex("""\b(from|into|set|where|values|join)\b""", RegexOption.IGNORE_CASE)

private fun containsSqlStatement(text: String): Boolean =
    SQL_VERB_RE.containsMatchIn(text) && SQL_CLAUSE_RE.containsMatchIn(text)

private fun detectSast(ktFiles: List<ParsedKtFile>, sqlFiles: List<SqlFile>): List<Hit> {
    val out = mutableListOf<Hit>()
    for (file in ktFiles) {
        out += detectSqlInjection(file)
        out += detectTlsBypass(file)
        out += detectCredentialedCors(file)
    }
    val securityRules = collectSecurityRules(ktFiles)
    out += detectRouteAuthorization(ktFiles, securityRules)
    out += detectObjectAuthorization(ktFiles, sqlFiles, securityRules)
    return out
}

private fun detectSqlInjection(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()

    // Collect file-level and class-level pure constant string names to avoid FP on constant SQL fragments.
    val filePureConsts = mutableSetOf<String>()
    for (prop in file.ktFile.declarations.filterIsInstance<KtProperty>()) {
        val name = prop.name ?: continue
        if (isPureConstantExpr(prop.initializer, filePureConsts)) {
            filePureConsts += name
        }
    }

    for (fn in PsiTreeUtil.collectElementsOfType(file.ktFile, KtNamedFunction::class.java)) {
        val pureConsts = filePureConsts.toMutableSet()
        val enclosingCls = PsiTreeUtil.getParentOfType(fn, KtClassOrObject::class.java)
        if (enclosingCls != null) {
            val memberProps = enclosingCls.declarations.filterIsInstance<KtProperty>().toMutableList()
            for (comp in enclosingCls.declarations.filterIsInstance<KtObjectDeclaration>()) {
                memberProps += comp.declarations.filterIsInstance<KtProperty>()
            }
            for (prop in memberProps) {
                val name = prop.name ?: continue
                if (isPureConstantExpr(prop.initializer, pureConsts)) {
                    pureConsts += name
                }
            }
        }

        val dynamicSqlVars = mutableSetOf<String>()
        val sqlConstVars = mutableSetOf<String>()
        for (prop in PsiTreeUtil.collectElementsOfType(fn, KtProperty::class.java).sortedBy { it.textRange.startOffset }) {
            val name = prop.name ?: continue
            val init = prop.initializer ?: continue
            if (isDynamicSqlExpr(init, dynamicSqlVars, pureConsts)) {
                dynamicSqlVars += name
            } else if (!prop.isVar && isPureConstantExpr(init, pureConsts)) {
                pureConsts += name
                if (containsSqlStatement(init.text)) {
                    sqlConstVars += name
                }
            } else if (containsSqlStatement(init.text)) {
                sqlConstVars += name
            }
        }

        // Track `sql += ...` mutations on local var SQL builders
        for (bin in PsiTreeUtil.collectElementsOfType(fn, KtBinaryExpression::class.java)) {
            if (bin.operationToken != KtTokens.PLUSEQ) continue
            val target = (unwrapParens(bin.left) as? KtNameReferenceExpression)?.getReferencedName() ?: continue
            if (target in sqlConstVars || target in dynamicSqlVars) {
                if (!isPureConstantExpr(bin.right, pureConsts)) {
                    dynamicSqlVars += target
                }
            }
        }

        // Track `StringBuilder.append(...)` on a local SQL StringBuilder var
        for (dot in PsiTreeUtil.collectElementsOfType(fn, KtDotQualifiedExpression::class.java)) {
            val sel = dot.selectorExpression as? KtCallExpression ?: continue
            if (sel.calleeExpression?.text != "append") continue
            val target = (unwrapParens(dot.receiverExpression) as? KtNameReferenceExpression)?.getReferencedName() ?: continue
            if (target in sqlConstVars || target in dynamicSqlVars) {
                val arg = sel.valueArguments.firstOrNull()?.getArgumentExpression()
                if (arg != null && !isPureConstantExpr(arg, pureConsts)) {
                    dynamicSqlVars += target
                }
            }
        }

        val fnStart = file.lines.lineOf((fn.funKeyword ?: fn).textRange.startOffset)
        for (call in PsiTreeUtil.collectElementsOfType(fn, KtCallExpression::class.java)) {
            val callee = call.calleeExpression?.text ?: continue
            if (callee !in SQL_CALL_NAMES) continue
            val sqlArg = call.valueArguments.firstOrNull {
                it.getArgumentName()?.asName?.asString() == "sql"
            }?.getArgumentExpression()
                ?: call.valueArguments.firstOrNull()?.getArgumentExpression()
                ?: continue
            if (!isDynamicSqlExpr(sqlArg, dynamicSqlVars, pureConsts)) continue
            val (callStart, callEnd) = file.lines.rangeOf(call)
            val startLine = if (!fn.hasBlockBody() && callStart - fnStart in 0..2) fnStart else callStart
            out += Hit(
                category = "SAST",
                `class` = "sql-injection",
                path = file.path,
                line = startLine,
                endLine = callEnd,
                severity = "HIGH",
                description = "Параметр запроса подставляется в SQL без параметризации.",
                remediation = "Использовать ? и передать значение отдельным аргументом.",
            )
        }
    }
    return out
}

private fun unwrapStringTransforms(expr: KtExpression?): KtExpression? {
    var cur = unwrapParens(expr)
    while (cur is KtDotQualifiedExpression) {
        val sel = cur.selectorExpression as? KtCallExpression ?: break
        val name = sel.calleeExpression?.text ?: break
        if (name in setOf("trimIndent", "trimMargin", "trim", "replaceIndent", "toString")) {
            cur = unwrapParens(cur.receiverExpression)
        } else {
            break
        }
    }
    return cur
}

private fun isDynamicSqlExpr(
    expr: KtExpression?,
    dynamicVars: Set<String>,
    pureConsts: Set<String>,
): Boolean {
    val unwrapped = unwrapStringTransforms(expr) ?: return false
    return when (unwrapped) {
        is KtStringTemplateExpression -> {
            if (!unwrapped.hasInterpolation()) return false
            if (!containsSqlStatement(unwrapped.text)) return false
            unwrapped.entries
                .filterIsInstance<KtStringTemplateEntryWithExpression>()
                .any { !isPureConstantExpr(it.expression, pureConsts) }
        }
        is KtBinaryExpression -> {
            if (unwrapped.operationToken != KtTokens.PLUS) return false
            val hasSql = containsSqlStatement(unwrapped.text)
            val hasDynamicPart = !isPureConstantExpr(unwrapped.left, pureConsts) ||
                !isPureConstantExpr(unwrapped.right, pureConsts)
            hasSql && hasDynamicPart
        }
        is KtCallExpression -> {
            val callee = unwrapped.calleeExpression?.text ?: return false
            if (callee == "buildString") {
                val lambda = unwrapped.lambdaArguments.firstOrNull()?.getLambdaExpression()
                    ?: unwrapped.valueArguments.firstOrNull()?.getArgumentExpression() as? KtLambdaExpression
                    ?: return false
                if (!containsSqlStatement(lambda.text)) return false
                val appends = PsiTreeUtil.collectElementsOfType(lambda, KtCallExpression::class.java)
                    .filter { it.calleeExpression?.text == "append" }
                appends.any { c ->
                    val arg = c.valueArguments.firstOrNull()?.getArgumentExpression()
                    arg != null && !isPureConstantExpr(arg, pureConsts)
                }
            } else {
                false
            }
        }
        is KtDotQualifiedExpression -> {
            val sel = unwrapped.selectorExpression as? KtCallExpression ?: return false
            val selName = sel.calleeExpression?.text ?: return false
            when (selName) {
                "format" -> {
                    val args = sel.valueArguments
                    if (unwrapped.receiverExpression.text == "String") {
                        if (args.size < 2) return false
                        val fmt = args[0].getArgumentExpression() ?: return false
                        containsSqlStatement(fmt.text) &&
                            args.drop(1).any { !isPureConstantExpr(it.getArgumentExpression(), pureConsts) }
                    } else {
                        containsSqlStatement(unwrapped.receiverExpression.text) &&
                            args.any { !isPureConstantExpr(it.getArgumentExpression(), pureConsts) }
                    }
                }
                else -> false
            }
        }
        is KtNameReferenceExpression -> unwrapped.getReferencedName() in dynamicVars
        else -> false
    }
}

private fun isPureConstantExpr(expr: KtExpression?, pureConsts: Set<String> = emptySet()): Boolean {
    val unwrapped = unwrapStringTransforms(expr) ?: return true
    return when (unwrapped) {
        is KtStringTemplateExpression -> {
            if (!unwrapped.hasInterpolation()) {
                true
            } else {
                unwrapped.entries
                    .filterIsInstance<KtStringTemplateEntryWithExpression>()
                    .all { isPureConstantExpr(it.expression, pureConsts) }
            }
        }
        is KtConstantExpression -> true
        is KtNameReferenceExpression -> unwrapped.getReferencedName() in pureConsts
        is KtBinaryExpression -> unwrapped.operationToken == KtTokens.PLUS &&
            isPureConstantExpr(unwrapped.left, pureConsts) &&
            isPureConstantExpr(unwrapped.right, pureConsts)
        else -> false
    }
}

private fun detectTlsBypass(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()
    val reportedLines = mutableSetOf<Int>()

    // 1. HostnameVerifier { _, _ -> true } and OkHttp/setter `hostnameVerifier { _, _ -> true }` / `setHostnameVerifier { ... }`
    for (call in PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)) {
        val callee = call.calleeExpression?.text ?: continue
        if (callee !in setOf("HostnameVerifier", "hostnameVerifier", "setHostnameVerifier")) continue
        val lambda = call.lambdaArguments.firstOrNull()?.getLambdaExpression()
            ?: call.valueArguments.firstOrNull()?.getArgumentExpression() as? KtLambdaExpression
            ?: continue
        if (lambdaAlwaysReturnsTrue(lambda)) {
            val (line, endLine) = file.lines.rangeOf(call)
            if (reportedLines.add(line)) {
                out += Hit(
                    category = "SAST",
                    `class` = "tls-verification",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "MEDIUM",
                    description = "Проверка имени хоста в TLS отключена безусловным true.",
                    remediation = "Использовать штатную проверку имени и корректный сертификат.",
                )
            }
        }
    }

    // 2. SAM assignment: `conn.hostnameVerifier = { _, _ -> true }`
    for (bin in PsiTreeUtil.collectElementsOfType(file.ktFile, KtBinaryExpression::class.java)) {
        if (bin.operationToken != KtTokens.EQ) continue
        val lhs = bin.left?.text?.substringAfterLast('.') ?: continue
        if (lhs != "hostnameVerifier") continue
        val rhs = unwrapParens(bin.right)
        if (rhs is KtLambdaExpression && lambdaAlwaysReturnsTrue(rhs)) {
            val (line, endLine) = file.lines.rangeOf(bin)
            if (reportedLines.add(line)) {
                out += Hit(
                    category = "SAST",
                    `class` = "tls-verification",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "MEDIUM",
                    description = "Проверка имени хоста в TLS отключена безусловным true.",
                    remediation = "Использовать штатную проверку имени и корректный сертификат.",
                )
            }
        }
    }

    // 3. object : HostnameVerifier / X509TrustManager or class implementing them
    val classesAndObjects = mutableListOf<KtClassOrObject>()
    classesAndObjects += PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)
    classesAndObjects += PsiTreeUtil.collectElementsOfType(file.ktFile, KtObjectLiteralExpression::class.java)
        .map { it.objectDeclaration }

    for (cls in classesAndObjects) {
        val supertypes = cls.superTypeListEntries.mapNotNull { it.typeReference?.text }
        val isHostnameVerifier = supertypes.any { it.contains("HostnameVerifier") }
        val isTrustManager = supertypes.any { it.contains("TrustManager") }
        if (!isHostnameVerifier && !isTrustManager) continue

        for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
            if (isHostnameVerifier && fn.name == "verify" && functionAlwaysReturnsTrue(fn)) {
                val (line, endLine) = file.lines.rangeOf(fn)
                if (reportedLines.add(line)) {
                    out += Hit(
                        category = "SAST",
                        `class` = "tls-verification",
                        path = file.path,
                        line = line,
                        endLine = endLine,
                        severity = "MEDIUM",
                        description = "Проверка имени хоста в TLS отключена безусловным true.",
                        remediation = "Использовать штатную проверку имени и корректный сертификат.",
                    )
                }
            }
            if (isTrustManager && fn.name == "checkServerTrusted" && isTrustCheckNoOp(fn)) {
                val (line, endLine) = file.lines.rangeOf(fn)
                if (reportedLines.add(line)) {
                    out += Hit(
                        category = "SAST",
                        `class` = "tls-verification",
                        path = file.path,
                        line = line,
                        endLine = endLine,
                        severity = "MEDIUM",
                        description = "TrustManager принимает любой сертификат сервера.",
                        remediation = "Не подменять проверку цепочки сертификатов.",
                    )
                }
            }
        }
    }

    // 4. Known insecure TLS bypass types (NoopHostnameVerifier, InsecureTrustManagerFactory, TrustAllStrategy)
    val insecureRefs = setOf("NoopHostnameVerifier", "InsecureTrustManagerFactory", "TrustAllStrategy")
    for (ref in PsiTreeUtil.collectElementsOfType(file.ktFile, KtNameReferenceExpression::class.java)) {
        val name = ref.getReferencedName()
        if (name !in insecureRefs) continue
        if (PsiTreeUtil.getParentOfType(ref, org.jetbrains.kotlin.psi.KtImportDirective::class.java) != null) continue
        val (line, endLine) = file.lines.rangeOf(ref)
        if (reportedLines.add(line)) {
            out += Hit(
                category = "SAST",
                `class` = "tls-verification",
                path = file.path,
                line = line,
                endLine = endLine,
                severity = "MEDIUM",
                description = "Используется небезопасная реализация TLS-проверки ($name).",
                remediation = "Включить стандартную проверку цепочки сертификатов и имени хоста.",
            )
        }
    }

    return out
}

private fun hasControlFlowBranching(element: PsiElement): Boolean =
    PsiTreeUtil.findChildrenOfAnyType(
        element,
        KtIfExpression::class.java,
        KtWhenExpression::class.java,
        KtForExpression::class.java,
        KtWhileExpression::class.java,
        KtTryExpression::class.java,
        KtThrowExpression::class.java,
    ).isNotEmpty()

private fun lambdaAlwaysReturnsTrue(lambda: KtLambdaExpression): Boolean {
    val body = lambda.bodyExpression ?: return false
    val stmts = body.statements
    if (stmts.isEmpty() || hasControlFlowBranching(body)) return false
    return isBooleanTrueExpr(stmts.last())
}

private fun functionAlwaysReturnsTrue(fn: KtNamedFunction): Boolean {
    val body = fn.bodyExpression ?: return false
    if (hasControlFlowBranching(body)) return false
    if (body is KtBlockExpression) {
        val stmts = body.statements
        if (stmts.isEmpty()) return false
        val ret = stmts.last() as? KtReturnExpression ?: return false
        return isBooleanTrueExpr(ret.returnedExpression)
    }
    return isBooleanTrueExpr(body)
}

private fun isTrustCheckNoOp(fn: KtNamedFunction): Boolean {
    val body = fn.bodyExpression as? KtBlockExpression ?: return false
    val stmts = body.statements
    if (stmts.isEmpty()) return true
    if (PsiTreeUtil.findChildrenOfType(body, KtThrowExpression::class.java).isNotEmpty()) return false
    val calls = PsiTreeUtil.collectElementsOfType(body, KtCallExpression::class.java)
    if (calls.isEmpty()) {
        return stmts.all { it is KtReturnExpression }
    }
    val logCallees = setOf("debug", "info", "warn", "trace", "error", "println", "print")
    return calls.all { (it.calleeExpression?.text ?: "") in logCallees }
}

private fun isBooleanTrueExpr(expr: KtExpression?): Boolean {
    val unwrapped = unwrapParens(expr)
    return unwrapped is KtConstantExpression && unwrapped.text == "true"
}

private val CORS_ORIGIN_METHODS = setOf(
    "allowedOriginPatterns",
    "allowedOrigins",
    "setAllowedOriginPatterns",
    "setAllowedOrigins",
    "addAllowedOrigin",
    "addAllowedOriginPattern",
)

private val CORS_CRED_METHODS = setOf(
    "allowCredentials",
    "setAllowCredentials",
)

private fun detectCredentialedCors(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()
    val reported = mutableSetOf<Int>()

    // 1. @CrossOrigin annotation with wildcard origin and allowCredentials = "true"
    for (ann in PsiTreeUtil.collectElementsOfType(file.ktFile, KtAnnotationEntry::class.java)) {
        if (ann.shortName?.asString() != "CrossOrigin") continue
        var hasWildcard = false
        var hasCred = false
        var hasExplicitOrigins = false
        for (arg in ann.valueArguments) {
            val argName = arg.getArgumentName()?.asName?.asString()
            val argExpr = arg.getArgumentExpression()
            when (argName) {
                null, "value", "origins", "originPatterns" -> {
                    hasExplicitOrigins = true
                    if (exprContainsWildcardOrigin(argExpr, emptyMap())) hasWildcard = true
                }
                "allowCredentials" -> {
                    val lit = extractPureStringLiteral(argExpr)?.lowercase()
                    if (lit == "true" || isBooleanTrueExpr(argExpr)) hasCred = true
                }
            }
        }
        // In Spring @CrossOrigin, omitting origins defaults to all origins (`*`).
        if (hasCred && (hasWildcard || !hasExplicitOrigins)) {
            val (line, endLine) = file.lines.rangeOf(ann)
            if (reported.add(line)) {
                out += Hit(
                    category = "SAST",
                    `class` = "credentialed-cors",
                    path = file.path,
                    line = line,
                    endLine = endLine,
                    severity = "MEDIUM",
                    description = "Аннотация @CrossOrigin одновременно разрешает любой origin и передачу учётных данных.",
                    remediation = "Ограничить origin доверенным клиентом или отключить allowCredentials.",
                )
            }
        }
    }

    // 2. Inspect functions, init blocks, and property initializers containing CORS configuration
    val scopes = mutableListOf<PsiElement>()
    scopes += PsiTreeUtil.collectElementsOfType(file.ktFile, KtNamedFunction::class.java)
    scopes += PsiTreeUtil.collectElementsOfType(file.ktFile, KtClassInitializer::class.java)
    scopes += PsiTreeUtil.collectElementsOfType(file.ktFile, KtProperty::class.java)
        .filter { PsiTreeUtil.getParentOfType(it, KtNamedFunction::class.java) == null }

    for (scope in scopes) {
        val text = scope.text
        if (!text.contains("CorsConfiguration") && !text.contains("CorsRegistry") && !text.contains("addMapping")) {
            continue
        }
        val wildcardVars = mutableMapOf<String, Boolean>()
        for (prop in PsiTreeUtil.collectElementsOfType(scope, KtProperty::class.java)) {
            val name = prop.name ?: continue
            if (exprContainsWildcardOrigin(prop.initializer, wildcardVars)) {
                wildcardVars[name] = true
            }
        }

        // Group origin & credentials lines by receiver/chain identity to avoid FP across distinct CORS configs.
        val originByGroup = mutableMapOf<String, Int>()
        val credByGroup = mutableMapOf<String, Int>()

        for (bin in PsiTreeUtil.collectElementsOfType(scope, KtBinaryExpression::class.java)) {
            if (bin.operationToken != KtTokens.EQ) continue
            val lhsText = bin.left?.text ?: continue
            val propName = lhsText.substringAfterLast('.')
            val group = corsGroupKey(bin, lhsText)
            val rhs = bin.right ?: continue
            if ((propName == "allowedOriginPatterns" || propName == "allowedOrigins") &&
                exprContainsWildcardOrigin(rhs, wildcardVars)
            ) {
                originByGroup.putIfAbsent(group, file.lines.rangeOf(bin).first)
            }
            if (propName == "allowCredentials" && isBooleanTrueExpr(rhs)) {
                credByGroup.putIfAbsent(group, file.lines.rangeOf(bin).first)
            }
        }

        for (call in PsiTreeUtil.collectElementsOfType(scope, KtCallExpression::class.java)) {
            val callee = call.calleeExpression?.text ?: continue
            val args = call.valueArguments
            val group = corsCallGroupKey(call)
            if (callee in CORS_ORIGIN_METHODS) {
                if (args.any { exprContainsWildcardOrigin(it.getArgumentExpression(), wildcardVars) }) {
                    originByGroup.putIfAbsent(group, file.lines.rangeOf(call).first)
                }
            }
            if (callee in CORS_CRED_METHODS) {
                if (args.any { isBooleanTrueExpr(it.getArgumentExpression()) }) {
                    credByGroup.putIfAbsent(group, file.lines.rangeOf(call).first)
                }
            }
        }

        for ((group, originLine) in originByGroup) {
            val credLine = credByGroup[group] ?: continue
            val start = minOf(originLine, credLine)
            val end = maxOf(originLine, credLine)
            if (reported.add(start)) {
                out += Hit(
                    category = "SAST",
                    `class` = "credentialed-cors",
                    path = file.path,
                    line = start,
                    endLine = end,
                    severity = "MEDIUM",
                    description = "CORS одновременно разрешает любой origin и передачу учётных данных.",
                    remediation = "Ограничить origin доверенным клиентом или отключить credentials.",
                )
            }
        }
    }
    return out
}

private fun corsGroupKey(bin: KtBinaryExpression, lhsText: String): String {
    if (lhsText.contains('.')) {
        return "recv:${lhsText.substringBeforeLast('.')}"
    }
    val lambda = PsiTreeUtil.getParentOfType(bin, KtLambdaExpression::class.java)
    if (lambda != null) {
        return "lambda:${lambda.textRange.startOffset}"
    }
    return "default"
}

private fun corsCallGroupKey(call: KtCallExpression): String {
    // Walk up fluent chaining (e.g. registry.addMapping("/api/**").allowedOrigins("*").allowCredentials(true))
    var top: PsiElement = call
    while (top.parent is KtDotQualifiedExpression) {
        top = top.parent
    }
    val rootDot = top as? KtDotQualifiedExpression
    if (rootDot != null) {
        var leftmost: KtExpression = rootDot.receiverExpression
        while (leftmost is KtDotQualifiedExpression) {
            leftmost = leftmost.receiverExpression
        }
        val firstCall = (rootDot.receiverExpression as? KtDotQualifiedExpression)?.selectorExpression as? KtCallExpression
            ?: (rootDot.receiverExpression as? KtCallExpression)
        if (firstCall?.calleeExpression?.text == "addMapping") {
            return "chain:${firstCall.textRange.startOffset}"
        }
        val addMappingCall = PsiTreeUtil.collectElementsOfType(rootDot, KtCallExpression::class.java)
            .firstOrNull { it.calleeExpression?.text == "addMapping" }
        if (addMappingCall != null) {
            return "chain:${addMappingCall.textRange.startOffset}"
        }
        return "recv:${leftmost.text}"
    }
    val lambda = PsiTreeUtil.getParentOfType(call, KtLambdaExpression::class.java)
    if (lambda != null) {
        return "lambda:${lambda.textRange.startOffset}"
    }
    return "default"
}

private fun isWildcardOriginString(raw: String): Boolean {
    val s = raw.trim().lowercase()
    if (s == "*" || s == "*://*" || s == "http://*" || s == "https://*" || s == "http://*.*" || s == "https://*.*") {
        return true
    }
    return Regex("""^(?:https?|\*)://\*(?::\*)?/?$""").matches(s)
}

private fun exprContainsWildcardOrigin(expr: KtExpression?, wildcardVars: Map<String, Boolean>): Boolean {
    val unwrapped = unwrapParens(expr) ?: return false
    if (unwrapped is KtNameReferenceExpression && wildcardVars[unwrapped.getReferencedName()] == true) {
        return true
    }
    if (unwrapped is KtStringTemplateExpression) {
        val lit = extractPureStringLiteral(unwrapped)
        if (lit != null && isWildcardOriginString(lit)) return true
    }
    for (str in PsiTreeUtil.collectElementsOfType(unwrapped, KtStringTemplateExpression::class.java)) {
        val lit = extractPureStringLiteral(str) ?: continue
        if (isWildcardOriginString(lit)) return true
    }
    return false
}

// ============================================================================
// SECURITY RULES INDEX (Spring Security Java & Kotlin DSL)
// ============================================================================

private data class SecurityRule(
    val file: ParsedKtFile,
    val pattern: String,
    val httpMethod: String?, // null = any method
    val access: String,      // "permitAll", "authenticated", "hasRole", "hasAuthority", ...
    val roles: List<String>,
    val element: PsiElement,
)

private fun collectSecurityRules(ktFiles: List<ParsedKtFile>): List<SecurityRule> {
    val rules = mutableListOf<SecurityRule>()
    for (file in ktFiles) {
        val hasSecurityChain = PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)
            .any { it.calleeExpression?.text in setOf("authorizeHttpRequests", "authorizeRequests") }
        if (!hasSecurityChain) continue

        // 1. Java-style builder: `.requestMatchers(HttpMethod.GET, "/path").permitAll()`
        for (dot in PsiTreeUtil.collectElementsOfType(file.ktFile, KtDotQualifiedExpression::class.java)) {
            val selCall = dot.selectorExpression as? KtCallExpression ?: continue
            val selName = selCall.calleeExpression?.text ?: continue
            if (selName !in setOf("permitAll", "authenticated", "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority")) continue
            val reqCall = extractRequestMatchersCall(dot.receiverExpression) ?: continue
            val (method, routes) = extractMatcherMethodAndRoutes(reqCall)
            val roles = selCall.valueArguments.mapNotNull { extractPureStringLiteral(it.getArgumentExpression()) }
            for (route in routes) {
                rules += SecurityRule(file, route, method, selName, roles, dot)
            }
        }

        // 2. Spring Security Kotlin DSL: `authorize("/path", permitAll)` / `authorize(HttpMethod.GET, "/path", hasRole("ADMIN"))`
        for (call in PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)) {
            if (call.calleeExpression?.text != "authorize") continue
            val args = call.valueArguments
            if (args.size < 2) continue
            val accessExpr = args.last().getArgumentExpression() ?: continue
            val accessText = accessExpr.text.trim()
            val (access, roles) = parseKotlinDslAccess(accessExpr, accessText) ?: continue
            val method = extractHttpMethodArg(args.first().getArgumentExpression())
            val routes = args.dropLast(1).mapNotNull { extractPureStringLiteral(it.getArgumentExpression()) }
            for (route in routes) {
                rules += SecurityRule(file, route, method, access, roles, call)
            }
        }
    }
    return rules
}

private fun parseKotlinDslAccess(expr: KtExpression, text: String): Pair<String, List<String>>? = when {
    text == "permitAll" -> "permitAll" to emptyList()
    text == "authenticated" -> "authenticated" to emptyList()
    expr is KtCallExpression -> {
        val name = expr.calleeExpression?.text ?: return null
        if (name in setOf("hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority")) {
            val roles = expr.valueArguments.mapNotNull { extractPureStringLiteral(it.getArgumentExpression()) }
            name to roles
        } else {
            null
        }
    }
    else -> null
}

private fun extractRequestMatchersCall(expr: KtExpression?): KtCallExpression? = when (expr) {
    is KtCallExpression -> if (expr.calleeExpression?.text in setOf("requestMatchers", "antMatchers", "mvcMatchers")) expr else null
    is KtDotQualifiedExpression -> extractRequestMatchersCall(expr.selectorExpression)
    else -> null
}

private fun extractMatcherMethodAndRoutes(call: KtCallExpression): Pair<String?, List<String>> {
    var method: String? = null
    val routes = mutableListOf<String>()
    for (arg in call.valueArguments) {
        val expr = arg.getArgumentExpression()
        val lit = extractPureStringLiteral(expr)
        if (lit != null) {
            routes += lit
        } else if (method == null) {
            method = extractHttpMethodArg(expr)
        }
    }
    return method to routes
}

private val HTTP_METHODS = setOf("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

private fun extractHttpMethodArg(expr: KtExpression?): String? {
    val raw = expr?.text?.substringAfterLast('.')?.trim()?.uppercase() ?: return null
    return if (raw in HTTP_METHODS) raw else null
}

// ============================================================================
// Cross-file Route Authorization (A-SAST-04)
// ============================================================================

private data class ControllerHandler(
    val path: String,
    val className: String,
    val funName: String,
    val fullRoute: String,
    val httpMethod: String?,
    val hasLocalAuth: Boolean,
    val isAdminOnly: Boolean,
    val bodyText: String,
    val propTypes: Map<String, String>,
    val fn: KtNamedFunction,
)

private val MAPPING_ANNOTATIONS = mapOf(
    "GetMapping" to "GET",
    "PostMapping" to "POST",
    "PutMapping" to "PUT",
    "DeleteMapping" to "DELETE",
    "PatchMapping" to "PATCH",
    "RequestMapping" to null,
)

private val LOCAL_AUTH_ANNOTATIONS = setOf("PreAuthorize", "Secured", "RolesAllowed")

private val PUBLIC_ROUTE_HINTS = listOf(
    "/health", "/livez", "/readyz", "/ping", "/version", "/status",
    "/login", "/logout", "/signin", "/signout", "/register", "/signup",
    "/auth/", "/oauth2/", "/token", "/forgot-password", "/reset-password",
    "/swagger", "/v3/api-docs", "/openapi", "/docs", "/public/", "/static/",
    "/assets/", "/error", "/favicon", "/webhook",
)

private val SENSITIVE_ROUTE_SEGMENTS = setOf(
    "admin", "internal", "export", "staff", "backoffice", "audit",
    "debug", "backup", "private", "secret", "secrets", "billing",
    "invoice", "invoices", "payment", "payments", "payroll", "employee", "employees",
)

private val SENSITIVE_DATA_TOKENS = listOf(
    "customer_id", "customerid", "user_id", "userid", "owner_id", "ownerid",
    "account_id", "accountid", "client_id", "clientid", "employee_id", "employeeid",
    "member_id", "memberid", "tenant_id", "tenantid", "patient_id", "patientid",
    "email", "phone", "ssn", "passport", "salary", "iban", "card_number", "cardnumber",
    "password_hash", "passwordhash", "secret_key", "secretkey", "access_token",
    "internal_note", "internalnote", "private_note", "privatenote", "audit_log",
)

private fun collectControllerHandlers(ktFiles: List<ParsedKtFile>): List<ControllerHandler> {
    val handlers = mutableListOf<ControllerHandler>()
    for (file in ktFiles) {
        for (cls in PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)) {
            val clsAnns = cls.annotationEntries.mapNotNull { it.shortName?.asString() }
            if ("RestController" !in clsAnns && "Controller" !in clsAnns) continue
            val clsHasAuth = clsAnns.any { it in LOCAL_AUTH_ANNOTATIONS }
            val clsIsAdmin = cls.annotationEntries.any { isAdminAuthAnnotation(it) }
            val classPrefix = cls.annotationEntries
                .firstOrNull { it.shortName?.asString() == "RequestMapping" }
                ?.let { extractAnnotationPath(it) }
                .orEmpty()

            val propTypes = mutableMapOf<String, String>()
            for (param in cls.primaryConstructorParameters) {
                val pName = param.name ?: continue
                val pType = param.typeReference?.text?.substringBefore('<')?.trim() ?: continue
                propTypes[pName] = pType
            }

            for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
                val fnAnns = fn.annotationEntries
                val mapAnn = fnAnns.firstOrNull { it.shortName?.asString() in MAPPING_ANNOTATIONS.keys } ?: continue
                val annName = mapAnn.shortName?.asString() ?: continue
                val methodPath = extractAnnotationPath(mapAnn)
                val fullRoute = joinRoutePath(classPrefix, methodPath)
                if (fullRoute.isEmpty()) continue
                val httpMethod = MAPPING_ANNOTATIONS[annName] ?: extractRequestMappingMethod(mapAnn)
                val hasLocalAuth = clsHasAuth ||
                    fnAnns.any { it.shortName?.asString() in LOCAL_AUTH_ANNOTATIONS } ||
                    fn.valueParameters.any { isPrincipalParam(it) } ||
                    fn.text.contains("SecurityContextHolder")
                val isAdminOnly = clsIsAdmin || fnAnns.any { isAdminAuthAnnotation(it) }
                handlers += ControllerHandler(
                    path = file.path,
                    className = cls.name.orEmpty(),
                    funName = fn.name.orEmpty(),
                    fullRoute = fullRoute,
                    httpMethod = httpMethod,
                    hasLocalAuth = hasLocalAuth,
                    isAdminOnly = isAdminOnly,
                    bodyText = fn.text,
                    propTypes = propTypes,
                    fn = fn,
                )
            }
        }
    }
    return handlers
}

private fun isAdminAuthAnnotation(ann: KtAnnotationEntry): Boolean {
    if (ann.shortName?.asString() !in LOCAL_AUTH_ANNOTATIONS) return false
    val low = ann.text.lowercase()
    return listOf("admin", "staff", "operator", "moderator", "support", "manager").any { low.contains(it) }
}

private fun extractRequestMappingMethod(ann: KtAnnotationEntry): String? {
    for (arg in ann.valueArguments) {
        if (arg.getArgumentName()?.asName?.asString() == "method") {
            return extractHttpMethodArg(arg.getArgumentExpression())
        }
    }
    return null
}

private fun detectRouteAuthorization(
    ktFiles: List<ParsedKtFile>,
    securityRules: List<SecurityRule>,
): List<Hit> {
    if (securityRules.isEmpty()) return emptyList()
    val handlers = collectControllerHandlers(ktFiles)
    if (handlers.isEmpty()) return emptyList()

    // Index service/repository method bodies so controller->service delegation is also inspected.
    val helperBodies = mutableMapOf<String, String>()
    for (file in ktFiles) {
        for (cls in PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)) {
            val clsName = cls.name.orEmpty()
            for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
                val fnName = fn.name ?: continue
                helperBodies["$clsName.$fnName"] = fn.text
                helperBodies.putIfAbsent(fnName, fn.text)
            }
        }
    }

    val roleProtectedPrefixes = securityRules
        .filter { it.access in setOf("hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority") }
        .map { it.pattern }

    val out = mutableListOf<Hit>()
    for (rule in securityRules) {
        if (rule.access != "permitAll") continue
        if (isExplicitPublicRoute(rule.pattern)) continue

        val matchedHandlers = handlers.filter { h ->
            routesMatch(rule.pattern, h.fullRoute) &&
                (rule.httpMethod == null || h.httpMethod == null || rule.httpMethod == h.httpMethod)
        }
        if (matchedHandlers.isEmpty()) continue

        val vulnerable = matchedHandlers.any { h ->
            if (h.hasLocalAuth || isExplicitPublicRoute(h.fullRoute)) return@any false

            val underRoleProtectedDomainPrefix = roleProtectedPrefixes.any { pref ->
                isSpecificDomainPrefix(pref) && routeMatchesAnt(h.fullRoute, pref)
            }
            val mutatingMethod = h.httpMethod in setOf("POST", "PUT", "PATCH", "DELETE")
            val sensitiveRoute = hasSensitiveRouteSegment(h.fullRoute) || hasSensitiveRouteSegment(rule.pattern)
            val combinedBody = buildHandlerEffectiveBody(h, helperBodies)
            val accessesSensitiveData = bodyAccessesSensitiveData(combinedBody)

            underRoleProtectedDomainPrefix || mutatingMethod || sensitiveRoute || accessesSensitiveData
        }

        if (!vulnerable) continue
        val (line, endLine) = rule.file.lines.rangeOf(rule.element)
        out += Hit(
            category = "SAST",
            `class` = "route-authorization",
            path = rule.file.path,
            line = line,
            endLine = endLine,
            severity = "HIGH",
            description = "Открытый маршрут отдаёт служебные или клиентские данные без проверки роли.",
            remediation = "Требовать роль и проверить доступ для гостя, клиента и сотрудника.",
        )
    }
    return out
}

private fun buildHandlerEffectiveBody(handler: ControllerHandler, helperBodies: Map<String, String>): String {
    val sb = StringBuilder(handler.bodyText)
    for (call in PsiTreeUtil.collectElementsOfType(handler.fn, KtCallExpression::class.java)) {
        val callee = call.calleeExpression?.text ?: continue
        val recvName = (call.parent as? KtDotQualifiedExpression)?.receiverExpression?.text
        val recvType = recvName?.let { handler.propTypes[it] }
        val body = (recvType?.let { helperBodies["$it.$callee"] }) ?: helperBodies[callee]
        if (body != null) {
            sb.append('\n').append(body)
        }
    }
    return sb.toString()
}

private fun isExplicitPublicRoute(route: String): Boolean {
    val low = route.lowercase()
    return PUBLIC_ROUTE_HINTS.any { low.contains(it) }
}

private fun isSpecificDomainPrefix(pattern: String): Boolean {
    if (!pattern.endsWith("/**") && !pattern.endsWith("/*")) return false
    val base = pattern.removeSuffix("/**").removeSuffix("/*").trim('/')
    if (base.isEmpty()) return false
    val segments = base.split('/').filter { it.isNotEmpty() }
    // Generic root catch-alls like `/api/**` or `/v1/**` are NOT domain-specific role prefixes.
    if (segments.size == 1 && segments[0].lowercase() in setOf("api", "v1", "v2", "v3", "rest")) {
        return false
    }
    return true
}

private fun hasSensitiveRouteSegment(route: String): Boolean {
    val segs = route.lowercase().split('/').map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("{") }
    return segs.any { it in SENSITIVE_ROUTE_SEGMENTS }
}

private fun bodyAccessesSensitiveData(body: String): Boolean {
    val low = body.lowercase()
    return SENSITIVE_DATA_TOKENS.any { low.contains(it) }
}

private fun routesMatch(securityPattern: String, handlerRoute: String): Boolean {
    if (securityPattern == handlerRoute) return true
    return routeMatchesAnt(handlerRoute, securityPattern) || routeMatchesAnt(securityPattern, handlerRoute)
}

private fun routeMatchesAnt(route: String, pattern: String): Boolean {
    if (route == pattern) return true
    val normRoute = normalizeRoute(route)
    val normPat = normalizeRoute(pattern)
    if (normRoute == normPat) return true
    val regex = antPatternToRegex(normPat)
    return regex.matches(normRoute)
}

private fun normalizeRoute(r: String): String {
    val trimmed = r.trim()
    val prefixed = if (trimmed.startsWith("/")) trimmed else "/$trimmed"
    return if (prefixed.length > 1) prefixed.trimEnd('/') else prefixed
}

private fun antPatternToRegex(pattern: String): Regex {
    val sb = StringBuilder("^")
    var i = 0
    while (i < pattern.length) {
        when {
            pattern.startsWith("/**", i) -> {
                sb.append("(?:/.*)?")
                i += 3
            }
            pattern.startsWith("**", i) -> {
                sb.append(".*")
                i += 2
            }
            pattern[i] == '*' -> {
                sb.append("[^/]*")
                i++
            }
            pattern[i] == '{' -> {
                val close = pattern.indexOf('}', i)
                if (close > i) {
                    sb.append("[^/]+")
                    i = close + 1
                } else {
                    sb.append(Regex.escape("{"))
                    i++
                }
            }
            else -> {
                sb.append(Regex.escape(pattern[i].toString()))
                i++
            }
        }
    }
    sb.append("$")
    return Regex(sb.toString())
}

// ============================================================================
// Cross-file Object Authorization / IDOR / BOLA (A-SAST-05)
// ============================================================================

private data class DataAccessMethod(
    val className: String,
    val funName: String,
    val path: String,
    val startLine: Int,
    val endLine: Int,
    val sql: String,
    val jpaEntity: String?,
)

private val OWNER_TOKENS = listOf(
    "customer_id", "customerid",
    "user_id", "userid",
    "owner_id", "ownerid",
    "account_id", "accountid",
    "client_id", "clientid",
    "member_id", "memberid",
    "employee_id", "employeeid",
    "tenant_id", "tenantid",
    "author_id", "authorid",
    "created_by", "createdby",
    "holder_id", "holderid",
    "patient_id", "patientid",
    "subscriber_id", "subscriberid",
)

private val CREATE_TABLE_RE = Regex(
    """create\s+table\s+(?:if\s+not\s+exists\s+)?[`"\[]?([A-Za-z0-9_]+)[`"\]]?\s*\((.*?)\)""",
    setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
)

private val SQL_TABLE_RE = Regex(
    """\b(?:from|update|delete\s+from)\s+[`"\[]?([A-Za-z0-9_]+)[`"\]]?""",
    RegexOption.IGNORE_CASE,
)

private val JPA_REPO_RE = Regex(
    """(?:JpaRepository|CrudRepository|PagingAndSortingRepository|ListCrudRepository|CoroutineCrudRepository)\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*,""",
)

private val SQL_CRUD_VERB_RE = Regex("""\b(select|update|delete)\b""", RegexOption.IGNORE_CASE)

private fun detectObjectAuthorization(
    ktFiles: List<ParsedKtFile>,
    sqlFiles: List<SqlFile>,
    securityRules: List<SecurityRule>,
): List<Hit> {
    // 1. Discover tables & entities that have an owner column/field (from schema.sql & Kotlin classes/entities)
    val ownedTables = mutableSetOf<String>()
    for (sqlFile in sqlFiles) {
        for (m in CREATE_TABLE_RE.findAll(sqlFile.text)) {
            val tableName = m.groupValues[1].lowercase()
            val body = m.groupValues[2].lowercase()
            if (hasOwnerToken(body)) {
                ownedTables += tableName
            }
        }
    }

    val ownedEntities = mutableSetOf<String>()
    for (file in ktFiles) {
        for (cls in PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)) {
            val clsName = cls.name ?: continue
            val fieldsText = buildString {
                for (p in cls.primaryConstructorParameters) {
                    append(p.name.orEmpty()).append(' ')
                }
                for (prop in cls.declarations.filterIsInstance<KtProperty>()) {
                    append(prop.name.orEmpty()).append(' ')
                }
            }.lowercase()
            if (hasOwnerToken(fieldsText)) {
                ownedEntities += clsName.lowercase()
                ownedTables += clsName.lowercase()
                ownedTables += clsName.lowercase() + "s"
            }
        }
    }

    // 2. Collect repository & service data-access methods (SQL CRUD + JPA repositories)
    val directDataMethods = mutableListOf<DataAccessMethod>()
    val jpaRepoEntityByType = mutableMapOf<String, String>()
    val serviceDelegates = mutableMapOf<String, MutableList<Pair<String?, String>>>() // "Class.fn" -> [(recvType, callee)]

    for (file in ktFiles) {
        for (cls in PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)) {
            val clsName = cls.name.orEmpty()
            val superText = cls.superTypeListEntries.joinToString(" ") { it.text }
            val jpaMatch = JPA_REPO_RE.find(superText)
            if (jpaMatch != null && clsName.isNotEmpty()) {
                jpaRepoEntityByType[clsName] = jpaMatch.groupValues[1]
            }

            val clsAnns = cls.annotationEntries.mapNotNull { it.shortName?.asString() }
            val isRepoOrService = "Repository" in clsAnns || "Service" in clsAnns ||
                cls.text.contains("JdbcTemplate") || cls.text.contains("JdbcClient") || cls.text.contains("EntityManager")
            if (!isRepoOrService) continue

            val propTypes = mutableMapOf<String, String>()
            for (param in cls.primaryConstructorParameters) {
                val pName = param.name ?: continue
                val pType = param.typeReference?.text?.substringBefore('<')?.trim() ?: continue
                propTypes[pName] = pType
            }

            for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
                val fnName = fn.name ?: continue
                val sqlLiterals = PsiTreeUtil.collectElementsOfType(fn, KtStringTemplateExpression::class.java)
                    .mapNotNull { extractPureStringLiteral(it) }
                    .filter { SQL_CRUD_VERB_RE.containsMatchIn(it) && it.lowercase().contains("where") }
                if (sqlLiterals.isNotEmpty()) {
                    val combinedSql = sqlLiterals.joinToString("\n")
                    val fnStart = file.lines.lineOf((fn.funKeyword ?: fn).textRange.startOffset)
                    val firstSqlNode = PsiTreeUtil.collectElementsOfType(fn, KtStringTemplateExpression::class.java)
                        .first { SQL_CRUD_VERB_RE.containsMatchIn(it.text) }
                    val (sqlStart, _) = file.lines.rangeOf(firstSqlNode)
                    directDataMethods += DataAccessMethod(
                        className = clsName,
                        funName = fnName,
                        path = file.path,
                        startLine = fnStart,
                        endLine = maxOf(fnStart, minOf(sqlStart, fnStart + 1)),
                        sql = combinedSql,
                        jpaEntity = null,
                    )
                }

                // Record calls inside @Service methods for 2-hop Controller -> Service -> Repo resolution
                val delegates = mutableListOf<Pair<String?, String>>()
                for (call in PsiTreeUtil.collectElementsOfType(fn, KtCallExpression::class.java)) {
                    val callee = call.calleeExpression?.text ?: continue
                    val recvName = (call.parent as? KtDotQualifiedExpression)?.receiverExpression?.text
                    val recvType = recvName?.let { propTypes[it] }
                    delegates += recvType to callee
                }
                if (delegates.isNotEmpty()) {
                    serviceDelegates["$clsName.$fnName"] = delegates
                }
            }
        }
    }

    val handlers = collectControllerHandlers(ktFiles)
    val out = mutableListOf<Hit>()
    val seen = mutableSetOf<String>()

    fun isSqlUncheckedIdor(sql: String): Boolean {
        val sqlLow = sql.lowercase()
        val wherePart = sqlLow.substringAfter("where", "")
        if (wherePart.isEmpty()) return false
        if (hasOwnerToken(wherePart)) return false
        if (hasOwnerToken(sqlLow)) return true
        val referencedTables = SQL_TABLE_RE.findAll(sqlLow).map { it.groupValues[1].lowercase() }.toList()
        return referencedTables.any { it in ownedTables }
    }

    fun resolveDirectHits(recvType: String?, callee: String, fallbackFile: String, fallbackLine: Int): List<DataAccessMethod> {
        val matched = directDataMethods.filter { r ->
            r.funName == callee && (recvType == null || r.className.isEmpty() || r.className == recvType)
        }
        if (matched.isNotEmpty()) return matched
        // JPA repository lookup by ID (findById / getReferenceById / deleteById) on owned entity
        if (recvType != null && callee in setOf("findById", "findByIdOrNull", "getReferenceById", "getById", "deleteById")) {
            val entity = jpaRepoEntityByType[recvType]
            if (entity != null && entity.lowercase() in ownedEntities) {
                return listOf(
                    DataAccessMethod(
                        className = recvType,
                        funName = callee,
                        path = fallbackFile,
                        startLine = fallbackLine,
                        endLine = fallbackLine,
                        sql = "",
                        jpaEntity = entity,
                    ),
                )
            }
        }
        return emptyList()
    }

    for (h in handlers) {
        val hasPathVarParam = h.fn.valueParameters.any { p ->
            p.annotationEntries.any { it.shortName?.asString() == "PathVariable" }
        }
        if (!hasPathVarParam || !h.fullRoute.contains("{")) continue
        // Skip if handler takes Principal / Authentication / SecurityContextHolder
        if (h.fn.valueParameters.any { isPrincipalParam(it) } || h.bodyText.contains("SecurityContextHolder")) {
            continue
        }
        // Skip admin/staff-only endpoints (admin reading arbitrary record by ID is expected)
        if (h.isAdminOnly || isAdminProtectedRoute(h.fullRoute, h.httpMethod, securityRules)) {
            continue
        }

        // Case A: Inline SQL directly inside the controller method
        val inlineSqls = PsiTreeUtil.collectElementsOfType(h.fn, KtStringTemplateExpression::class.java)
            .mapNotNull { extractPureStringLiteral(it) }
            .filter { SQL_CRUD_VERB_RE.containsMatchIn(it) && it.lowercase().contains("where") }
        if (inlineSqls.isNotEmpty() && isSqlUncheckedIdor(inlineSqls.joinToString("\n"))) {
            val fnStart = h.fn.containingKtFile.let {
                // Find line from ParsedKtFile
                ktFiles.firstOrNull { pf -> pf.path == h.path }?.lines?.lineOf((h.fn.funKeyword ?: h.fn).textRange.startOffset) ?: 1
            }
            val key = "${h.path}:${h.funName}"
            if (seen.add(key)) {
                out += Hit(
                    category = "SAST",
                    `class` = "object-authorization",
                    path = h.path,
                    line = fnStart,
                    endLine = fnStart + 1,
                    severity = "HIGH",
                    description = "Аутентифицированный маршрут обращается к записи по идентификатору без фильтра владельца.",
                    remediation = "Добавить проверку владельца по Principal в запрос или сервис.",
                )
            }
            continue
        }

        // Case B: Controller -> Repository (1-hop) or Controller -> Service -> Repository (2-hop)
        val controllerFile = ktFiles.firstOrNull { it.path == h.path }
        val fnStart = controllerFile?.lines?.lineOf((h.fn.funKeyword ?: h.fn).textRange.startOffset) ?: 1

        for (call in PsiTreeUtil.collectElementsOfType(h.fn, KtCallExpression::class.java)) {
            val callee = call.calleeExpression?.text ?: continue
            val recvName = (call.parent as? KtDotQualifiedExpression)?.receiverExpression?.text
            val recvType = recvName?.let { h.propTypes[it] }

            val candidates = mutableListOf<DataAccessMethod>()
            candidates += resolveDirectHits(recvType, callee, h.path, fnStart)

            // 2-hop via @Service
            if (candidates.isEmpty() && recvType != null) {
                val svcCalls = serviceDelegates["$recvType.$callee"].orEmpty()
                for ((hopRecvType, hopCallee) in svcCalls) {
                    candidates += resolveDirectHits(hopRecvType, hopCallee, h.path, fnStart)
                }
            }

            for (repo in candidates) {
                val vulnerable = if (repo.jpaEntity != null) true else isSqlUncheckedIdor(repo.sql)
                if (!vulnerable) continue
                val key = "${repo.path}:${repo.funName}"
                if (!seen.add(key)) continue
                out += Hit(
                    category = "SAST",
                    `class` = "object-authorization",
                    path = repo.path,
                    line = repo.startLine,
                    endLine = repo.endLine,
                    severity = "HIGH",
                    description = "Аутентифицированный маршрут читает или изменяет запись по идентификатору без фильтра владельца.",
                    remediation = "Добавить в запрос идентификатор владельца из Principal.",
                )
            }
        }
    }
    return out
}

private fun isAdminProtectedRoute(route: String, httpMethod: String?, securityRules: List<SecurityRule>): Boolean {
    val adminRoles = setOf("admin", "staff", "operator", "moderator", "support", "manager")
    for (rule in securityRules) {
        if (rule.access !in setOf("hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority")) continue
        if (rule.httpMethod != null && httpMethod != null && rule.httpMethod != httpMethod) continue
        if (!routeMatchesAnt(route, rule.pattern)) continue
        if (rule.roles.any { r -> adminRoles.any { a -> r.lowercase().contains(a) } }) {
            return true
        }
    }
    return false
}

// ============================================================================
// PSI & LEXICAL HELPERS
// ============================================================================

private fun unwrapParens(expr: KtExpression?): KtExpression? {
    var cur = expr
    while (cur is KtParenthesizedExpression) {
        cur = cur.expression
    }
    return cur
}

private fun extractPureStringLiteral(expr: KtExpression?): String? {
    val str = unwrapParens(expr) as? KtStringTemplateExpression ?: return null
    if (str.hasInterpolation()) return null
    return extractStringTemplateRaw(str)
}

private fun extractStringTemplateRaw(expr: KtExpression?): String? {
    val str = unwrapParens(expr) as? KtStringTemplateExpression ?: return null
    val sb = StringBuilder()
    for (entry in str.entries) {
        when (entry) {
            is KtLiteralStringTemplateEntry -> sb.append(entry.text)
            is KtEscapeStringTemplateEntry -> sb.append(entry.unescapedValue)
            else -> sb.append(entry.text)
        }
    }
    return sb.toString()
}

private fun extractEnvLookupKey(expr: KtExpression): String? {
    val unwrapped = unwrapParens(expr) ?: return null
    // Unwrap `.takeIf { ... }` / `.orEmpty()` chains on env lookup
    if (unwrapped is KtDotQualifiedExpression) {
        val sel = unwrapped.selectorExpression as? KtCallExpression
        val selName = sel?.calleeExpression?.text
        if (selName in setOf("takeIf", "orEmpty", "trim")) {
            return extractEnvLookupKey(unwrapped.receiverExpression)
        }
    }
    if (unwrapped is KtSafeQualifiedExpression) {
        val sel = unwrapped.selectorExpression as? KtCallExpression
        val selName = sel?.calleeExpression?.text
        if (selName in setOf("takeIf", "orEmpty", "trim")) {
            return extractEnvLookupKey(unwrapped.receiverExpression)
        }
    }
    val call: KtCallExpression? = when (unwrapped) {
        is KtDotQualifiedExpression -> {
            val sel = unwrapped.selectorExpression as? KtCallExpression
            val recv = unwrapped.receiverExpression.text
            if (sel != null && (recv == "System" || recv.contains("env", ignoreCase = true))) sel else null
        }
        is KtCallExpression -> unwrapped
        else -> null
    }
    val callee = call?.calleeExpression?.text ?: return null
    if (callee !in setOf("getenv", "getProperty")) return null
    return extractPureStringLiteral(call.valueArguments.firstOrNull()?.getArgumentExpression()) ?: ""
}

private fun extractAnnotationPath(ann: KtAnnotationEntry): String {
    for (arg in ann.valueArguments) {
        val name = arg.getArgumentName()?.asName?.asString()
        if (name == null || name == "value" || name == "path") {
            val lit = extractPureStringLiteral(arg.getArgumentExpression())
            if (lit != null) return lit
        }
    }
    return ""
}

private fun joinRoutePath(prefix: String, method: String): String {
    if (prefix.isEmpty()) return method
    if (method.isEmpty()) return prefix
    return prefix.trimEnd('/') + "/" + method.trimStart('/')
}

private fun isPrincipalParam(param: KtParameter): Boolean {
    val typeName = param.typeReference?.text.orEmpty()
    if (typeName == "Principal" || typeName.endsWith(".Principal") ||
        typeName == "Authentication" || typeName == "UserDetails" || typeName == "Jwt" ||
        typeName.endsWith(".Authentication") || typeName.endsWith(".UserDetails") || typeName.endsWith(".Jwt")
    ) {
        return true
    }
    return param.annotationEntries.any { it.shortName?.asString() == "AuthenticationPrincipal" }
}

private fun isMetadataIdentifier(name: String): Boolean {
    val norm = name.lowercase().replace("_", "").replace("-", "")
    if (norm.isEmpty()) return false
    return METADATA_SUFFIXES.any { suffix -> norm.length > suffix.length && norm.endsWith(suffix) }
}

private fun isPasswordName(name: String): Boolean {
    if (isMetadataIdentifier(name)) return false
    val low = name.lowercase()
    return low.contains("password") || low.contains("passwd") || low == "pwd" || low.endsWith("pwd") || low.endsWith("_pwd")
}

private fun isApiKeyName(name: String): Boolean {
    if (isMetadataIdentifier(name)) return false
    val low = name.lowercase()
    return low.contains("apikey") || low.contains("api_key") ||
        low.contains("apitoken") || low.contains("api_token") ||
        low.contains("accesskey") || low.contains("access_key") ||
        low.contains("secret") || low.contains("authtoken") || low.contains("auth_token") ||
        low.contains("bearertoken") || low.contains("bearer_token") ||
        low.contains("privatekey") || low.contains("private_key") ||
        low.contains("signingkey") || low.contains("signing_key")
}

private fun isConfigSecretKey(keyPath: String): Boolean {
    val parts = keyPath.split('.').map { it.substringBefore('[').trim().lowercase() }.filter { it.isNotEmpty() }
    if (parts.isEmpty()) return false
    val leaf = parts.last()
    val leafNorm = leaf.replace("-", "").replace("_", "")
    // Explicitly reject non-secret metadata leaf keys even if nested under `token.*` or `password.*`.
    if (leafNorm in METADATA_SUFFIXES || isMetadataIdentifier(leaf)) return false

    val secretKeywords = listOf("token", "secret", "authorization", "password", "passwd", "apikey", "api-key", "api_key", "privatekey", "private-key", "accesskey", "access-key")
    if (secretKeywords.any { leaf.contains(it) }) return true

    // If leaf is generic (`value`, `key`, `default`, etc.), check immediate parent segment.
    if (leaf in GENERIC_VALUE_LEAF_KEYS && parts.size >= 2) {
        val parent = parts[parts.size - 2]
        if (secretKeywords.any { parent.contains(it) }) return true
    }
    return false
}

private fun looksCredentialIdentifier(name: String): Boolean {
    if (name.isBlank()) return false
    val leaf = name.substringAfterLast('.').trim()
    if (isMetadataIdentifier(leaf)) return false
    val low = leaf.lowercase()
    return listOf("token", "secret", "key", "pass", "pwd", "auth", "cred", "bearer", "signing", "jwt")
        .any { low.contains(it) }
}

private fun isSecretLiteral(value: String): Boolean {
    val v = value.trim()
    if (v.length < 4) return false
    if (ENV_ONLY_RE.matches(v) || TEMPLATE_EXPR_RE.matches(v)) return false
    if (v.startsWith("<") && v.endsWith(">")) return false
    if (v.startsWith("/") && !v.contains(' ')) return false // filesystem or route path

    val low = v.lowercase()
    val placeholders = listOf(
        "change_me", "changeme", "replace_me", "replace-me", "placeholder",
        "example", "your_", "your-", "todo", "fixme", "dummy", "sample",
        "not-set", "not_set", "unset", "redact", "******", "xxxxxx",
    )
    if (placeholders.any { low.contains(it) }) return false
    if (low in setOf("true", "false", "null", "none", "undefined", "empty", "bearer", "basic", "authorization", "x-api-key", "api-key", "password", "secret", "token")) {
        return false
    }
    if (low.startsWith("http://") || low.startsWith("https://")) {
        if (!URL_WITH_CREDS_RE.containsMatchIn(v)) return false
    }
    if (v.startsWith("X-", ignoreCase = true) && !v.contains(' ') && v.count { it == '-' } in 1..3 && v.none { it.isDigit() }) {
        return false
    }
    // Reject human-readable prose sentences (unless auth scheme header)
    if (!low.startsWith("bearer ") && !low.startsWith("basic ") && v.count { it == ' ' } >= 3) {
        return false
    }
    return true
}

private fun hasOwnerToken(textLower: String): Boolean =
    OWNER_TOKENS.any { textLower.contains(it) }

// ============================================================================
// JSON SERIALIZATION (strict control-character escaping)
// ============================================================================

fun render(hits: List<Hit>): String {
    val body = hits.joinToString(",") { hit ->
        """{"category":${json(hit.category)},"class":${json(hit.`class`)},"path":${json(hit.path)},"line":${hit.line},"endLine":${hit.endLine},"severity":${json(hit.severity)},"description":${json(hit.description)},"remediation":${json(hit.remediation)}}"""
    }
    return "[$body]"
}

fun json(value: String): String {
    val sb = StringBuilder(value.length + 2)
    sb.append('"')
    for (ch in value) {
        when (ch) {
            '\\' -> sb.append("\\\\")
            '"' -> sb.append("\\\"")
            '\b' -> sb.append("\\b")
            '\u000C' -> sb.append("\\f")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (ch.code < 0x20) {
                sb.append(String.format("\\u%04x", ch.code))
            } else {
                sb.append(ch)
            }
        }
    }
    sb.append('"')
    return sb.toString()
}
