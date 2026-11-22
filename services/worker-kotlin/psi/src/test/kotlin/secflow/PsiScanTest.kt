package secflow

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class PsiScanTest {

    private fun writeFile(root: Path, rel: String, content: String): File {
        val f = root.resolve(rel).toFile()
        f.parentFile.mkdirs()
        f.writeText(content.trimIndent() + "\n", Charsets.UTF_8)
        return f
    }

    @Test
    fun `detects secrets across diverse Kotlin and config patterns without false positives`(@TempDir tmp: Path) {
        writeFile(
            tmp,
            "src/main/kotlin/app/Secrets.kt",
            """
            package app

            import org.springframework.beans.factory.annotation.Value
            import org.springframework.http.HttpHeaders

            data class SmtpConfig(
                val host: String = "smtp.internal",
                val password: String = "SmtpP@ssw0rd2026",
                val passwordHeader: String = "X-Password",
                val passwordErrorMessage: String = "Password must be at least 12 characters long",
            )

            class BillingClient(
                @Value("\${'$'}{server.port:8080}") val port: String,
                @Value("\${'$'}{billing.api-key:bk_live_9876543210}") val billingKey: String,
            ) {
                private val partA = "tok_part_"
                private val partB = "alpha9912"

                fun buildHeaders(): HttpHeaders {
                    val h = HttpHeaders()
                    h.setBearerAuth(partA + partB)
                    h["X-Api-Key"] = "ak_direct_551234"
                    return h
                }

                fun envFallback(): String {
                    val region = System.getenv("APP_REGION") ?: "eu-central-1"
                    val token = System.getenv("GATEWAY_SECRET")?.ifBlank { "fallback_gw_secret_99" } ?: "fallback_gw_secret_99"
                    return region + token
                }

                fun builderToken(): HttpHeaders {
                    val assembled = buildString {
                        append("sk_")
                        append("live_builder_7711")
                    }
                    val h = HttpHeaders()
                    h.set("Authorization", "Bearer " + assembled)
                    return h
                }
            }
            """,
        )

        writeFile(
            tmp,
            "src/main/resources/application.yml",
            """
            auth:
              token:
                ttl: 3600
                header: X-Auth-Token
                issuer: https://auth.internal.local
                enabled: true
                secret: "${'$'}{AUTH_SECRET}"
            ---
            spring:
              profiles:
                active: prod
              datasource:
                url: jdbc:postgresql://db:5432/app?password=DbPlainPassword99
            integration:
              api-token: "prod_cfg_tok_882211"
              safe-token: "${'$'}{INTEGRATION_TOKEN}"
            """,
        )

        writeFile(
            tmp,
            ".github/workflows/ci.yml",
            """
            name: CI
            jobs:
              build:
                env:
                  GITHUB_TOKEN: "${'$'}{{ secrets.GITHUB_TOKEN }}"
            """,
        )

        val hits = scanRoot(tmp.toFile(), ScanMode.SECRETS)
        val classes = hits.map { it.`class` to it.path }

        assertTrue(classes.contains("password" to "src/main/kotlin/app/Secrets.kt"), "expected password hit, got $hits")
        assertTrue(classes.contains("api-key" to "src/main/kotlin/app/Secrets.kt"), "expected api-key hit, got $hits")
        assertTrue(classes.count { it.first == "secret-fallback" } >= 2, "expected secret-fallback hits, got $hits")
        assertTrue(classes.count { it.first == "recoverable-token" } >= 2, "expected recoverable-token hits, got $hits")
        assertEquals(
            2,
            hits.count { it.`class` == "configuration-token" && it.path == "src/main/resources/application.yml" },
            "expected exactly 2 config secrets (jdbc password + api-token), got $hits",
        )
        assertFalse(hits.any { it.path == ".github/workflows/ci.yml" }, "must not FP on GitHub Actions expressions: $hits")
        assertFalse(hits.any { it.line == 9 || it.line == 10 }, "must not FP on passwordHeader/passwordErrorMessage: $hits")
        assertFalse(hits.any { it.line == 14 }, "must not FP on @Value server.port: $hits")
        assertFalse(hits.any { it.line == 28 }, "must not FP on non-credential env APP_REGION: $hits")
    }

    @Test
    fun `detects SQLi including multiline trimIndent while ignoring pure constant fragments`(@TempDir tmp: Path) {
        writeFile(
            tmp,
            "src/main/kotlin/app/SearchRepo.kt",
            """
            package app

            import org.springframework.jdbc.core.JdbcTemplate

            class SearchRepo(private val jdbc: JdbcTemplate) {
                companion object {
                    private const val TABLE = "orders"
                }

                fun unsafeMultiline(term: String): List<Map<String, Any>> {
                    val sql = ${"\"\"\""}
                        SELECT id, total
                        FROM orders
                        WHERE status = '${'$'}term'
                    ${"\"\"\""}.trimIndent()
                    return jdbc.queryForList(sql)
                }

                fun unsafeFormat(code: String): List<Map<String, Any>> =
                    jdbc.queryForList(String.format("SELECT id FROM orders WHERE code = '%s'", code))

                fun safeConstantTable(id: Long): List<Map<String, Any>> =
                    jdbc.queryForList("SELECT id, total FROM ${'$'}TABLE WHERE id = ?", id)
            }
            """,
        )

        val hits = scanRoot(tmp.toFile(), ScanMode.SAST).filter { it.`class` == "sql-injection" }
        assertEquals(2, hits.size, "expected 2 SQLi hits (multiline + String.format) and 0 on constant TABLE, got $hits")
    }

    @Test
    fun `detects TLS bypass variants and scopes CORS per receiver`(@TempDir tmp: Path) {
        writeFile(
            tmp,
            "src/main/kotlin/app/NetConfig.kt",
            """
            package app

            import javax.net.ssl.HttpsURLConnection
            import org.springframework.web.cors.CorsConfiguration

            class NetConfig {
                fun unsafeSam(conn: HttpsURLConnection) {
                    conn.hostnameVerifier = { _, _ -> true }
                }

                fun safeSeparateCors(): Pair<CorsConfiguration, CorsConfiguration> {
                    val publicCors = CorsConfiguration()
                    publicCors.allowedOrigins = listOf("*")
                    publicCors.allowCredentials = false

                    val privateCors = CorsConfiguration()
                    privateCors.allowedOrigins = listOf("https://portal.example.org")
                    privateCors.allowCredentials = true
                    return publicCors to privateCors
                }

                fun unsafeCors(): CorsConfiguration {
                    val cfg = CorsConfiguration()
                    cfg.addAllowedOriginPattern("https://*")
                    cfg.allowCredentials = true
                    return cfg
                }
            }
            """,
        )

        val hits = scanRoot(tmp.toFile(), ScanMode.SAST)
        assertEquals(1, hits.count { it.`class` == "tls-verification" }, "expected 1 TLS bypass, got $hits")
        val corsHits = hits.filter { it.`class` == "credentialed-cors" }
        assertEquals(1, corsHits.size, "expected only 1 CORS hit on unsafeCors, not safeSeparateCors: $hits")
        assertTrue(corsHits.first().line >= 20, "CORS hit should point to unsafeCors, got $corsHits")
    }

    @Test
    fun `detects universal route-authorization and multi-hop IDOR with schema awareness`(@TempDir tmp: Path) {
        writeFile(
            tmp,
            "src/main/resources/schema.sql",
            """
            CREATE TABLE invoices (
                id BIGINT PRIMARY KEY,
                owner_id BIGINT NOT NULL,
                amount NUMERIC NOT NULL
            );
            CREATE TABLE products (
                id BIGINT PRIMARY KEY,
                title VARCHAR(255) NOT NULL
            );
            """,
        )

        writeFile(
            tmp,
            "src/main/kotlin/app/SecurityConfig.kt",
            """
            package app

            import org.springframework.security.config.annotation.web.builders.HttpSecurity

            class SecurityConfig {
                fun configure(http: HttpSecurity) {
                    http.authorizeHttpRequests { auth ->
                        auth.requestMatchers("/api/catalog").permitAll()
                        auth.requestMatchers("/api/billing/export").permitAll()
                        auth.requestMatchers("/api/billing/**").hasRole("FINANCE")
                        auth.requestMatchers("/api/admin/**").hasRole("ADMIN")
                        auth.requestMatchers("/api/**").authenticated()
                    }
                }
            }
            """,
        )

        writeFile(
            tmp,
            "src/main/kotlin/app/Controllers.kt",
            """
            package app

            import org.springframework.jdbc.core.JdbcTemplate
            import org.springframework.stereotype.Repository
            import org.springframework.stereotype.Service
            import org.springframework.web.bind.annotation.*
            import java.security.Principal

            @RestController
            class PublicCatalogController(private val jdbc: JdbcTemplate) {
                @GetMapping("/api/catalog")
                fun list() = jdbc.queryForList("SELECT id, title FROM products")
            }

            @RestController
            class BillingExportController(private val jdbc: JdbcTemplate) {
                @GetMapping("/api/billing/export")
                fun export() = jdbc.queryForList("SELECT id, owner_id, amount FROM invoices")
            }

            @Repository
            class InvoiceRepository(private val jdbc: JdbcTemplate) {
                fun findRaw(id: Long) = jdbc.queryForMap("SELECT * FROM invoices WHERE id = ?", id)
                fun findOwned(id: Long, ownerId: Long) = jdbc.queryForMap("SELECT * FROM invoices WHERE id = ? AND owner_id = ?", id, ownerId)
            }

            @Service
            class InvoiceService(private val repo: InvoiceRepository) {
                fun load(id: Long) = repo.findRaw(id)
                fun loadForUser(id: Long, ownerId: Long) = repo.findOwned(id, ownerId)
            }

            @RestController
            @RequestMapping("/api/invoices")
            class InvoiceController(private val service: InvoiceService) {
                @GetMapping("/{id}")
                fun getOne(@PathVariable id: Long) = service.load(id)

                @GetMapping("/mine/{id}")
                fun getMine(@PathVariable id: Long, principal: Principal) = service.loadForUser(id, principal.name.toLong())
            }

            @RestController
            @RequestMapping("/api/admin/invoices")
            class AdminInvoiceController(private val repo: InvoiceRepository) {
                @GetMapping("/{id}")
                fun adminGet(@PathVariable id: Long) = repo.findRaw(id)
            }
            """,
        )

        val hits = scanRoot(tmp.toFile(), ScanMode.SAST)
        val routeHits = hits.filter { it.`class` == "route-authorization" }
        assertEquals(1, routeHits.size, "expected 1 route-auth hit on /api/billing/export and 0 on /api/catalog: $routeHits")

        val idorHits = hits.filter { it.`class` == "object-authorization" }
        assertEquals(1, idorHits.size, "expected 1 multi-hop IDOR hit via SELECT * + schema.sql: $idorHits")
    }
}
