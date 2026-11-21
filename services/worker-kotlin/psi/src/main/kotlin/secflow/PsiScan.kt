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
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBlockExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtEscapeStringTemplateEntry
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectLiteralExpression
import org.jetbrains.kotlin.psi.KtParameter
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtReturnExpression
import org.jetbrains.kotlin.psi.KtStringTemplateEntryWithExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.nodes.MappingNode
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.ScalarNode
import org.yaml.snakeyaml.nodes.SequenceNode
import java.io.File
import java.io.StringReader

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

fun main(args: Array<String>) {
    if (args.size == 2 && args[0] == "--mentor") {
        verifyMentor(File(args[1]))
        return
    }
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

private fun verifyMentor(root: File) {
    val hits = scanRoot(root, ScanMode.ALL)
    val sastHits = hits.filter { it.category == "SAST" }
    val secretHits = hits.filter { it.category == "SECRET" }

    val wantSast = setOf(
        "sql-injection" to "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt",
        "tls-verification" to "src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt",
        "credentialed-cors" to "src/main/kotlin/lab/repairdesk/config/RepairCors.kt",
        "route-authorization" to "src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt",
        "object-authorization" to "src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt",
    )
    val wantSecrets = setOf(
        "password" to "src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt",
        "api-key" to "src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
        "configuration-token" to "src/main/resources/application.yml",
        "secret-fallback" to "src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt",
        "recoverable-token" to "src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt",
    )
    val controls = listOf(
        Triple("api-key", "README.md", 9),
        Triple("configuration-token", "src/main/resources/application.yml", 17),
        Triple("sql-injection", "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt", 17),
        Triple("route-authorization", "src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt", 17),
        Triple("tls-verification", "src/main/kotlin/lab/repairdesk/integration/ManualsHttpsClient.kt", 7),
    )

    val gotSast = sastHits.map { it.`class` to it.path }.toSet()
    val gotSecrets = secretHits.map { it.`class` to it.path }.toSet()
    val corsHit = sastHits.firstOrNull { it.`class` == "credentialed-cors" }
    val corsRangeOk = corsHit != null && corsHit.line == 13 && corsHit.endLine == 14
    val falsePositive = hits.any { hit ->
        controls.any { it.first == hit.`class` && it.second == hit.path && it.third == hit.line }
    }

    if (gotSast != wantSast || gotSecrets != wantSecrets || !corsRangeOk || falsePositive) {
        System.err.println(
            "psi mentor mismatch: sast=$gotSast secrets=$gotSecrets cors=${corsHit?.line}..${corsHit?.endLine} falsePositive=$falsePositive",
        )
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

        root.walkTopDown()
            .onEnter { dir ->
                val name = dir.name
                name != ".git" && name != "build" && name != ".gradle" && name != "node_modules" && name != "target"
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
                }
            }

        val out = mutableListOf<Hit>()
        if (mode == ScanMode.ALL || mode == ScanMode.SECRETS) {
            out += detectSecrets(ktFiles, configFiles)
        }
        if (mode == ScanMode.ALL || mode == ScanMode.SAST) {
            out += detectSast(ktFiles)
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

private val ENV_ONLY_RE = Regex("""^\$\{[A-Za-z_][A-Za-z0-9_.-]*\}$""")
private val ENV_DEFAULT_RE = Regex("""^\$\{[A-Za-z_][A-Za-z0-9_.-]*:([^}]+)\}$""")

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
    val reportedHeaderLines = mutableSetOf<Int>()

    // 1. Property declarations: password & api-key
    for (prop in PsiTreeUtil.collectElementsOfType(file.ktFile, KtProperty::class.java)) {
        val name = prop.name ?: continue
        val init = prop.initializer ?: continue
        val literal = extractPureStringLiteral(init) ?: continue
        if (!isSecretLiteral(literal)) continue
        val (line, endLine) = file.lines.rangeOf(prop)
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
                reportedHeaderLines += line
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
                reportedHeaderLines += line
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
            isPasswordName(name) -> out += Hit(
                category = "SECRET",
                `class` = "password",
                path = file.path,
                line = line,
                endLine = endLine,
                severity = "HIGH",
                description = "Встроенный пароль задан значением параметра по умолчанию.",
                remediation = "Читать пароль из окружения или хранилища секретов без литерала по умолчанию.",
            )
            isApiKeyName(name) -> out += Hit(
                category = "SECRET",
                `class` = "api-key",
                path = file.path,
                line = line,
                endLine = endLine,
                severity = "MEDIUM",
                description = "Встроенный API-ключ задан значением параметра по умолчанию.",
                remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
            )
        }
    }

    // 3. Direct literal API key passed into HTTP header sinks
    for (call in PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)) {
        val callee = call.calleeExpression?.text ?: continue
        if (callee !in setOf("header", "addHeader", "set", "put")) continue
        val args = call.valueArguments
        if (args.size < 2) continue
        val headerName = extractPureStringLiteral(args[0].getArgumentExpression())?.lowercase() ?: continue
        if (headerName != "x-api-key" && headerName != "api-key") continue
        val literalVal = extractPureStringLiteral(args[1].getArgumentExpression()) ?: continue
        if (!isSecretLiteral(literalVal)) continue
        val (line, endLine) = file.lines.rangeOf(call)
        if (line in reportedHeaderLines) continue
        out += Hit(
            category = "SECRET",
            `class` = "api-key",
            path = file.path,
            line = line,
            endLine = endLine,
            severity = "MEDIUM",
            description = "Встроенный API-ключ передаётся литералом в HTTP-заголовок.",
            remediation = "Передавать ключ через настройки окружения и маскировать его в журналах.",
        )
    }

    // 4. Secret fallback via Elvis (System.getenv(...) ?: "literal") & getOrDefault & @Value("${...:literal}")
    for (bin in PsiTreeUtil.collectElementsOfType(file.ktFile, KtBinaryExpression::class.java)) {
        if (bin.operationToken != KtTokens.ELVIS) continue
        val left = bin.left ?: continue
        val right = bin.right ?: continue
        val envKey = extractEnvLookupKey(left) ?: continue
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
        if (callee != "getOrDefault") continue
        val parentDot = call.parent as? KtDotQualifiedExpression ?: continue
        val recvText = parentDot.receiverExpression.text
        if (!recvText.contains("getenv") && !recvText.contains("getProperties")) continue
        val args = call.valueArguments
        if (args.size < 2) continue
        val envKey = extractPureStringLiteral(args[0].getArgumentExpression()).orEmpty()
        val fallbackLiteral = extractPureStringLiteral(args[1].getArgumentExpression()) ?: continue
        if (!isSecretLiteral(fallbackLiteral)) continue
        if (!looksCredentialIdentifier(envKey)) continue
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

    for (ann in PsiTreeUtil.collectElementsOfType(file.ktFile, KtAnnotationEntry::class.java)) {
        if (ann.shortName?.asString() != "Value") continue
        val expr = ann.valueArguments.firstOrNull()?.getArgumentExpression() ?: continue
        val raw = extractStringTemplateRaw(expr) ?: continue
        val m = ENV_DEFAULT_RE.find(raw.trim()) ?: continue
        val defaultVal = m.groupValues[1].trim()
        if (!isSecretLiteral(defaultVal)) continue
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

    // 5. Recoverable token (constant folding of local val fragments flowing to auth/header sink)
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
    for (fn in PsiTreeUtil.collectElementsOfType(file.ktFile, KtNamedFunction::class.java)) {
        val consts = mutableMapOf<String, FoldedConst>()
        val props = PsiTreeUtil.collectElementsOfType(fn, KtProperty::class.java)
            .sortedBy { it.textRange.startOffset }
        for (prop in props) {
            val name = prop.name ?: continue
            val init = prop.initializer ?: continue
            val evaluated = evalFoldedString(init, consts, file.lines) ?: continue
            val (propLine, propEnd) = file.lines.rangeOf(prop)
            consts[name] = evaluated.copy(
                startLine = minOf(evaluated.startLine, propLine),
                endLine = maxOf(evaluated.endLine, propEnd),
            )
        }
        if (consts.values.none { it.combined }) continue

        val calls = PsiTreeUtil.collectElementsOfType(fn, KtCallExpression::class.java)
        for (call in calls) {
            val sinkArg = extractSecuritySinkArg(call) ?: continue
            val evaluated = evalFoldedString(sinkArg, consts, file.lines) ?: continue
            if (!evaluated.combined || !isSecretLiteral(evaluated.value)) continue
            val (_, callEnd) = file.lines.rangeOf(call)
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
            break
        }
    }
    return out
}

private fun evalFoldedString(
    expr: KtExpression?,
    consts: Map<String, FoldedConst>,
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
                for (entry in unwrapped.entries) {
                    when (entry) {
                        is KtLiteralStringTemplateEntry -> sb.append(entry.text)
                        is KtEscapeStringTemplateEntry -> sb.append(entry.unescapedValue)
                        is KtStringTemplateEntryWithExpression -> {
                            val sub = evalFoldedString(entry.expression, consts, lines) ?: return null
                            sb.append(sub.value)
                            minLine = minOf(minLine, sub.startLine)
                            maxLine = maxOf(maxLine, sub.endLine)
                            parts++
                            if (sub.combined) hadCombined = true
                        }
                        else -> return null
                    }
                }
                FoldedConst(sb.toString(), minLine, maxLine, combined = hadCombined || parts >= 2)
            }
        }
        is KtNameReferenceExpression -> consts[unwrapped.getReferencedName()]
        is KtBinaryExpression -> {
            if (unwrapped.operationToken != KtTokens.PLUS) return null
            val left = evalFoldedString(unwrapped.left, consts, lines) ?: return null
            val right = evalFoldedString(unwrapped.right, consts, lines) ?: return null
            FoldedConst(
                value = left.value + right.value,
                startLine = minOf(left.startLine, right.startLine),
                endLine = maxOf(left.endLine, right.endLine, endLine),
                combined = true,
            )
        }
        is KtDotQualifiedExpression -> {
            val sel = unwrapped.selectorExpression as? KtCallExpression ?: return null
            val selName = sel.calleeExpression?.text ?: return null
            if (selName == "joinToString") {
                val recvCall = unwrapped.receiverExpression as? KtCallExpression ?: return null
                if (recvCall.calleeExpression?.text !in setOf("listOf", "arrayOf", "mutableListOf")) return null
                val sep = sel.valueArguments.firstOrNull()?.let { extractPureStringLiteral(it.getArgumentExpression()) } ?: ""
                val parts = recvCall.valueArguments.map { evalFoldedString(it.getArgumentExpression(), consts, lines) ?: return null }
                if (parts.size < 2) return null
                FoldedConst(
                    value = parts.joinToString(sep) { it.value },
                    startLine = parts.minOf { it.startLine },
                    endLine = maxOf(parts.maxOf { it.endLine }, endLine),
                    combined = true,
                )
            } else {
                null
            }
        }
        else -> null
    }
}

private fun extractSecuritySinkArg(call: KtCallExpression): KtExpression? {
    val callee = call.calleeExpression?.text ?: return null
    val args = call.valueArguments
    return when (callee) {
        "setBearerAuth" -> args.firstOrNull()?.getArgumentExpression()
        "setBasicAuth" -> args.lastOrNull()?.getArgumentExpression()
        "header", "addHeader", "set", "put" -> {
            if (args.size < 2) return null
            val keyExpr = args[0].getArgumentExpression()
            val keyText = (extractPureStringLiteral(keyExpr) ?: keyExpr?.text.orEmpty()).lowercase()
            if (keyText.contains("authorization") || keyText.contains("api-key") || keyText.contains("x-auth") || keyText.contains("token")) {
                args[1].getArgumentExpression()
            } else {
                null
            }
        }
        else -> null
    }
}

private fun detectYamlSecrets(cfg: ConfigFile): List<Hit> {
    val out = mutableListOf<Hit>()
    val rootNode = try {
        Yaml().compose(StringReader(cfg.text))
    } catch (_: Throwable) {
        null
    } ?: return emptyList()

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

    walk(rootNode, "")
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
    if (value.isEmpty() || ENV_ONLY_RE.matches(value)) return
    val envDefault = ENV_DEFAULT_RE.find(value)?.groupValues?.getOrNull(1)?.trim()
    val effectiveVal = envDefault ?: value
    if (!isSecretLiteral(effectiveVal)) return
    val bearerOrBasic = effectiveVal.startsWith("Bearer ", ignoreCase = true) || effectiveVal.startsWith("Basic ", ignoreCase = true)
    if (bearerOrBasic) {
        val tokenPart = effectiveVal.substringAfter(' ').trim()
        if (tokenPart.isEmpty() || ENV_ONLY_RE.matches(tokenPart) || !isSecretLiteral(tokenPart)) return
    }
    if (!isConfigSecretKey(keyPath) && !bearerOrBasic) return
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

// ============================================================================
// SAST RULES (Kotlin PSI AST — single-file & cross-file)
// ============================================================================

private val SQL_CALL_NAMES = setOf(
    "queryForList",
    "queryForObject",
    "queryForMap",
    "query",
    "update",
    "execute",
    "createNativeQuery",
    "executeQuery",
    "executeUpdate",
)

private val SQL_KEYWORDS = listOf("select ", "insert ", "update ", "delete ", "from ", "where ")

private fun detectSast(ktFiles: List<ParsedKtFile>): List<Hit> {
    val out = mutableListOf<Hit>()
    for (file in ktFiles) {
        out += detectSqlInjection(file)
        out += detectTlsBypass(file)
        out += detectCredentialedCors(file)
    }
    out += detectRouteAuthorization(ktFiles)
    out += detectObjectAuthorization(ktFiles)
    return out
}

private fun detectSqlInjection(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()
    for (fn in PsiTreeUtil.collectElementsOfType(file.ktFile, KtNamedFunction::class.java)) {
        val dynamicSqlVars = mutableSetOf<String>()
        for (prop in PsiTreeUtil.collectElementsOfType(fn, KtProperty::class.java)) {
            val name = prop.name ?: continue
            val init = prop.initializer ?: continue
            if (isDynamicSqlExpr(init, dynamicSqlVars)) {
                dynamicSqlVars += name
            }
        }
        val fnStart = file.lines.lineOf((fn.funKeyword ?: fn).textRange.startOffset)
        for (call in PsiTreeUtil.collectElementsOfType(fn, KtCallExpression::class.java)) {
            val callee = call.calleeExpression?.text ?: continue
            if (callee !in SQL_CALL_NAMES) continue
            val sqlArg = call.valueArguments.firstOrNull()?.getArgumentExpression() ?: continue
            if (!isDynamicSqlExpr(sqlArg, dynamicSqlVars)) continue
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

private fun isDynamicSqlExpr(expr: KtExpression?, dynamicVars: Set<String>): Boolean {
    val unwrapped = unwrapParens(expr) ?: return false
    return when (unwrapped) {
        is KtStringTemplateExpression -> {
            if (!unwrapped.hasInterpolation()) return false
            val low = unwrapped.text.lowercase()
            SQL_KEYWORDS.any { low.contains(it) }
        }
        is KtBinaryExpression -> {
            if (unwrapped.operationToken != KtTokens.PLUS) return false
            val low = unwrapped.text.lowercase()
            val hasSql = SQL_KEYWORDS.any { low.contains(it) }
            val hasDynamicPart = !isPureConstantExpr(unwrapped.left) || !isPureConstantExpr(unwrapped.right)
            hasSql && hasDynamicPart
        }
        is KtNameReferenceExpression -> unwrapped.getReferencedName() in dynamicVars
        else -> false
    }
}

private fun isPureConstantExpr(expr: KtExpression?): Boolean {
    val unwrapped = unwrapParens(expr) ?: return true
    return when (unwrapped) {
        is KtStringTemplateExpression -> !unwrapped.hasInterpolation()
        is KtConstantExpression -> true
        is KtBinaryExpression -> unwrapped.operationToken == KtTokens.PLUS &&
            isPureConstantExpr(unwrapped.left) && isPureConstantExpr(unwrapped.right)
        else -> false
    }
}

private fun detectTlsBypass(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()

    // 1. HostnameVerifier { _, _ -> true }
    for (call in PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)) {
        val callee = call.calleeExpression?.text ?: continue
        if (callee != "HostnameVerifier") continue
        val lambda = call.lambdaArguments.firstOrNull()?.getLambdaExpression()
            ?: call.valueArguments.firstOrNull()?.getArgumentExpression() as? KtLambdaExpression
            ?: continue
        if (lambdaAlwaysReturnsTrue(lambda)) {
            val (line, endLine) = file.lines.rangeOf(call)
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

    // 2. object : HostnameVerifier / X509TrustManager or class implementing them
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
            if (isTrustManager && fn.name == "checkServerTrusted" && functionBodyIsEmpty(fn)) {
                val (line, endLine) = file.lines.rangeOf(fn)
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

    return out
}

private fun lambdaAlwaysReturnsTrue(lambda: KtLambdaExpression): Boolean {
    val stmts = lambda.bodyExpression?.statements ?: return false
    if (stmts.isEmpty()) return false
    return isBooleanTrueExpr(stmts.last())
}

private fun functionAlwaysReturnsTrue(fn: KtNamedFunction): Boolean {
    val body = fn.bodyExpression ?: return false
    if (body is KtBlockExpression) {
        val stmts = body.statements
        if (stmts.size != 1) return false
        val ret = stmts.first() as? KtReturnExpression ?: return false
        return isBooleanTrueExpr(ret.returnedExpression)
    }
    return isBooleanTrueExpr(body)
}

private fun functionBodyIsEmpty(fn: KtNamedFunction): Boolean {
    val body = fn.bodyExpression as? KtBlockExpression ?: return false
    return body.statements.isEmpty()
}

private fun isBooleanTrueExpr(expr: KtExpression?): Boolean {
    val unwrapped = unwrapParens(expr)
    return unwrapped is KtConstantExpression && unwrapped.text == "true"
}

private fun detectCredentialedCors(file: ParsedKtFile): List<Hit> {
    val out = mutableListOf<Hit>()
    for (fn in PsiTreeUtil.collectElementsOfType(file.ktFile, KtNamedFunction::class.java)) {
        val fnText = fn.text
        if (!fnText.contains("CorsConfiguration") && !fnText.contains("CorsRegistry") && !fnText.contains("addMapping")) {
            continue
        }
        var originLine: Int? = null
        var credLine: Int? = null

        for (bin in PsiTreeUtil.collectElementsOfType(fn, KtBinaryExpression::class.java)) {
            if (bin.operationToken != KtTokens.EQ) continue
            val lhs = bin.left?.text?.substringAfterLast('.') ?: continue
            val rhs = bin.right ?: continue
            if ((lhs == "allowedOriginPatterns" || lhs == "allowedOrigins") && exprContainsWildcardOrigin(rhs)) {
                if (originLine == null) originLine = file.lines.rangeOf(bin).first
            }
            if (lhs == "allowCredentials" && isBooleanTrueExpr(rhs)) {
                if (credLine == null) credLine = file.lines.rangeOf(bin).first
            }
        }

        for (call in PsiTreeUtil.collectElementsOfType(fn, KtCallExpression::class.java)) {
            val callee = call.calleeExpression?.text ?: continue
            val args = call.valueArguments
            if (callee in setOf("allowedOriginPatterns", "allowedOrigins", "setAllowedOriginPatterns", "setAllowedOrigins")) {
                if (args.any { exprContainsWildcardOrigin(it.getArgumentExpression()) }) {
                    if (originLine == null) originLine = file.lines.rangeOf(call).first
                }
            }
            if (callee in setOf("allowCredentials", "setAllowCredentials")) {
                if (args.any { isBooleanTrueExpr(it.getArgumentExpression()) }) {
                    if (credLine == null) credLine = file.lines.rangeOf(call).first
                }
            }
        }

        if (originLine != null && credLine != null) {
            val start = minOf(originLine, credLine)
            val end = maxOf(originLine, credLine)
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
    return out
}

private fun exprContainsWildcardOrigin(expr: KtExpression?): Boolean {
    if (expr == null) return false
    for (str in PsiTreeUtil.collectElementsOfType(expr, KtStringTemplateExpression::class.java)) {
        val lit = extractPureStringLiteral(str)?.trim() ?: continue
        if (lit == "*" || lit == "http://*" || lit == "https://*") return true
    }
    if (expr is KtStringTemplateExpression) {
        val lit = extractPureStringLiteral(expr)?.trim()
        if (lit == "*" || lit == "http://*" || lit == "https://*") return true
    }
    return false
}

// --- Cross-file Route Authorization (A-SAST-04) ---

private data class ControllerHandler(
    val path: String,
    val fullRoute: String,
    val hasLocalAuth: Boolean,
    val bodyText: String,
)

private val MAPPING_ANNOTATIONS = setOf(
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
    "RequestMapping",
)

private val LOCAL_AUTH_ANNOTATIONS = setOf("PreAuthorize", "Secured", "RolesAllowed")

private fun detectRouteAuthorization(ktFiles: List<ParsedKtFile>): List<Hit> {
    val handlers = mutableMapOf<String, ControllerHandler>()
    for (file in ktFiles) {
        for (cls in PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)) {
            val clsAnns = cls.annotationEntries.mapNotNull { it.shortName?.asString() }
            if ("RestController" !in clsAnns && "Controller" !in clsAnns) continue
            val clsHasAuth = clsAnns.any { it in LOCAL_AUTH_ANNOTATIONS }
            val classPrefix = cls.annotationEntries
                .firstOrNull { it.shortName?.asString() == "RequestMapping" }
                ?.let { extractAnnotationPath(it) }
                .orEmpty()

            for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
                val fnAnns = fn.annotationEntries
                val mapAnn = fnAnns.firstOrNull { it.shortName?.asString() in MAPPING_ANNOTATIONS } ?: continue
                val methodPath = extractAnnotationPath(mapAnn)
                val fullRoute = joinRoutePath(classPrefix, methodPath)
                if (fullRoute.isEmpty()) continue
                val hasLocalAuth = clsHasAuth ||
                    fnAnns.any { it.shortName?.asString() in LOCAL_AUTH_ANNOTATIONS } ||
                    fn.valueParameters.any { isPrincipalParam(it) } ||
                    fn.text.contains("SecurityContextHolder")
                handlers[fullRoute] = ControllerHandler(
                    path = file.path,
                    fullRoute = fullRoute,
                    hasLocalAuth = hasLocalAuth,
                    bodyText = fn.text,
                )
            }
        }
    }

    val out = mutableListOf<Hit>()
    for (file in ktFiles) {
        val hasSecurityChain = PsiTreeUtil.collectElementsOfType(file.ktFile, KtCallExpression::class.java)
            .any { it.calleeExpression?.text == "authorizeHttpRequests" }
        if (!hasSecurityChain) continue

        val protectedPrefixes = mutableListOf<String>()
        val permitCalls = mutableListOf<Pair<String, PsiElement>>()

        for (dot in PsiTreeUtil.collectElementsOfType(file.ktFile, KtDotQualifiedExpression::class.java)) {
            val selCall = dot.selectorExpression as? KtCallExpression ?: continue
            val selName = selCall.calleeExpression?.text ?: continue
            val reqCall = extractRequestMatchersCall(dot.receiverExpression) ?: continue
            val routes = reqCall.valueArguments.mapNotNull { extractPureStringLiteral(it.getArgumentExpression()) }
            when (selName) {
                "permitAll" -> routes.forEach { permitCalls += it to dot }
                "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority", "authenticated" -> {
                    routes.forEach { protectedPrefixes += it }
                }
            }
        }

        for ((route, expr) in permitCalls) {
            val handler = handlers[route] ?: continue
            if (handler.hasLocalAuth) continue
            val sensitive = isPrivateHandlerBody(handler.bodyText)
            val underProtectedPrefix = protectedPrefixes.any { prefixMatches(route, it) }
            if (!sensitive && !underProtectedPrefix) continue
            val (line, endLine) = file.lines.rangeOf(expr)
            out += Hit(
                category = "SAST",
                `class` = "route-authorization",
                path = file.path,
                line = line,
                endLine = endLine,
                severity = "HIGH",
                description = "Открытый маршрут отдаёт служебные или клиентские данные без проверки роли.",
                remediation = "Требовать роль и проверить доступ для гостя, клиента и сотрудника.",
            )
        }
    }
    return out
}

private fun extractRequestMatchersCall(expr: KtExpression?): KtCallExpression? = when (expr) {
    is KtCallExpression -> if (expr.calleeExpression?.text in setOf("requestMatchers", "antMatchers", "mvcMatchers")) expr else null
    is KtDotQualifiedExpression -> extractRequestMatchersCall(expr.selectorExpression)
    else -> null
}

private fun prefixMatches(route: String, pattern: String): Boolean {
    if (!pattern.endsWith("/**")) return false
    val base = pattern.removeSuffix("/**")
    return route == base || route.startsWith("$base/")
}

private fun isPrivateHandlerBody(body: String): Boolean {
    val low = body.lowercase()
    return listOf("customer_id", "customerid", "work_note", "counter_note", "user_id", "owner_id", "account_id")
        .any { low.contains(it) }
}

// --- Cross-file Object Authorization / IDOR (A-SAST-05) ---

private data class RepoMethod(
    val className: String,
    val funName: String,
    val path: String,
    val startLine: Int,
    val endLine: Int,
    val sql: String,
)

private fun detectObjectAuthorization(ktFiles: List<ParsedKtFile>): List<Hit> {
    val repos = mutableListOf<RepoMethod>()
    for (file in ktFiles) {
        for (cls in PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)) {
            val clsAnns = cls.annotationEntries.mapNotNull { it.shortName?.asString() }
            val isRepoOrService = "Repository" in clsAnns || "Service" in clsAnns || cls.text.contains("JdbcTemplate")
            if (!isRepoOrService) continue
            val clsName = cls.name.orEmpty()
            for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
                val fnName = fn.name ?: continue
                val sqlLiterals = PsiTreeUtil.collectElementsOfType(fn, KtStringTemplateExpression::class.java)
                    .mapNotNull { extractPureStringLiteral(it) }
                    .filter { it.lowercase().contains("select") }
                if (sqlLiterals.isEmpty()) continue
                val combinedSql = sqlLiterals.joinToString("\n")
                val fnStart = file.lines.lineOf((fn.funKeyword ?: fn).textRange.startOffset)
                val firstSqlNode = PsiTreeUtil.collectElementsOfType(fn, KtStringTemplateExpression::class.java)
                    .first { it.text.lowercase().contains("select") }
                val (sqlStart, _) = file.lines.rangeOf(firstSqlNode)
                repos += RepoMethod(
                    className = clsName,
                    funName = fnName,
                    path = file.path,
                    startLine = fnStart,
                    endLine = maxOf(fnStart, minOf(sqlStart, fnStart + 1)),
                    sql = combinedSql,
                )
            }
        }
    }

    val out = mutableListOf<Hit>()
    val seen = mutableSetOf<String>()
    for (file in ktFiles) {
        for (cls in PsiTreeUtil.collectElementsOfType(file.ktFile, KtClass::class.java)) {
            val clsAnns = cls.annotationEntries.mapNotNull { it.shortName?.asString() }
            if ("RestController" !in clsAnns && "Controller" !in clsAnns) continue

            // Map constructor property names to their declared type names (e.g. reader -> RepairTicketReader).
            val propTypes = mutableMapOf<String, String>()
            for (param in cls.primaryConstructorParameters) {
                val pName = param.name ?: continue
                val pType = param.typeReference?.text?.substringBefore('<')?.trim() ?: continue
                propTypes[pName] = pType
            }

            for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
                val mapAnn = fn.annotationEntries.firstOrNull { it.shortName?.asString() in MAPPING_ANNOTATIONS } ?: continue
                val route = extractAnnotationPath(mapAnn)
                val hasPathVarParam = fn.valueParameters.any { p ->
                    p.annotationEntries.any { it.shortName?.asString() == "PathVariable" }
                }
                if (!hasPathVarParam || !route.contains("{")) continue
                if (fn.valueParameters.any { isPrincipalParam(it) } || fn.text.contains("SecurityContextHolder")) {
                    continue
                }

                for (call in PsiTreeUtil.collectElementsOfType(fn, KtCallExpression::class.java)) {
                    val callee = call.calleeExpression?.text ?: continue
                    val recvName = (call.parent as? KtDotQualifiedExpression)?.receiverExpression?.text
                    val recvType = recvName?.let { propTypes[it] }

                    val matchedRepos = repos.filter { r ->
                        r.funName == callee && (recvType == null || r.className.isEmpty() || r.className == recvType)
                    }
                    for (repo in matchedRepos) {
                        val sqlLow = repo.sql.lowercase()
                        if (!hasOwnerColumn(sqlLow)) continue
                        val wherePart = sqlLow.substringAfter("where", "")
                        if (hasOwnerColumn(wherePart)) continue
                        val key = "${repo.path}:${repo.funName}"
                        if (!seen.add(key)) continue
                        out += Hit(
                            category = "SAST",
                            `class` = "object-authorization",
                            path = repo.path,
                            line = repo.startLine,
                            endLine = repo.endLine,
                            severity = "HIGH",
                            description = "Аутентифицированный маршрут читает запись по идентификатору без фильтра владельца.",
                            remediation = "Добавить в запрос идентификатор владельца из Principal.",
                        )
                    }
                }
            }
        }
    }
    return out
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
        typeName == "Authentication" || typeName == "UserDetails" || typeName == "Jwt"
    ) {
        return true
    }
    return param.annotationEntries.any { it.shortName?.asString() == "AuthenticationPrincipal" }
}

private fun isPasswordName(name: String): Boolean {
    val low = name.lowercase()
    return low.contains("password") || low.contains("passwd") || low.contains("pwd")
}

private fun isApiKeyName(name: String): Boolean {
    val low = name.lowercase()
    return low.contains("apikey") || low.contains("api_key") || low.contains("secret")
}

private fun isConfigSecretKey(key: String): Boolean {
    val low = key.lowercase()
    return listOf("token", "secret", "authorization", "password", "passwd", "apikey", "api-key", "api_key")
        .any { low.contains(it) }
}

private fun looksCredentialIdentifier(name: String): Boolean {
    val low = name.lowercase()
    return listOf("token", "secret", "key", "pass", "pwd", "auth", "cred", "access")
        .any { low.contains(it) }
}

private fun isSecretLiteral(value: String): Boolean {
    val v = value.trim()
    if (v.isEmpty()) return false
    val low = v.lowercase()
    if (low.contains("change_me") || low.contains("placeholder") || low.contains("example") || low.contains("your_")) {
        return false
    }
    if (v.startsWith("<") && v.endsWith(">")) return false
    return true
}

private fun hasOwnerColumn(sql: String): Boolean =
    listOf("customer_id", "user_id", "owner_id", "account_id").any { sql.contains(it) }

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
