package kotlinscan

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProjectFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestScan_UniversalSecretsAndAntiFalsePositives(t *testing.T) {
	t.Parallel()

	root := writeProjectFiles(t, map[string]string{
		"src/main/kotlin/app/Secrets.kt": `package app

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders

data class MailSettings(
    val password: String = "MailP@ss2026!",
    val passwordHeader: String = "X-Password",
    val passwordErrorMessage: String = "Password must be at least 12 characters long",
)

class BillingClient(
    @Value("${server.port:8080}") val port: String,
    @Value("${billing.api-key:bk_live_9876543210}") val billingKey: String,
) {
    private val partA = "tok_part_"
    private val partB = "alpha9912"

    fun send(): HttpHeaders {
        val h = HttpHeaders()
        h.setBearerAuth(partA + partB)
        h["X-Api-Key"] = "ak_direct_551234"
        return h
    }

    fun envFallback(): String {
        val region = System.getenv("APP_REGION") ?: "eu-central-1"
        val token = System.getenv("GATEWAY_SECRET") ?: "fallback_gw_secret_99"
        return region + token
    }
}
`,
		"src/main/resources/application.yml": `auth:
  token:
    ttl: 3600
    header: X-Auth-Token
    issuer: https://auth.internal.local
    enabled: true
    secret: "${AUTH_SECRET}"
---
spring:
  datasource:
    url: jdbc:postgresql://db:5432/app?password=DbPlainPassword99
integration:
  api-token: "prod_cfg_tok_882211"
  safe-token: "${INTEGRATION_TOKEN}"
`,
		".github/workflows/ci.yml": `name: CI
jobs:
  build:
    env:
      GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}"
`,
	})

	findings, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	countByClass := map[string]int{}
	for _, f := range findings {
		if f.Path == ".github/workflows/ci.yml" {
			t.Errorf("false positive on GitHub Actions expression: %+v", f)
		}
		if f.Path == "src/main/kotlin/app/Secrets.kt" && (f.Line == 8 || f.Line == 9 || f.Line == 13 || f.Line == 27) {
			t.Errorf("false positive on non-secret metadata/non-cred env line %d: %+v", f.Line, f)
		}
		countByClass[f.Class]++
	}

	if countByClass["password"] != 1 {
		t.Errorf("password count = %d, want 1 (all: %+v)", countByClass["password"], findings)
	}
	if countByClass["api-key"] != 1 {
		t.Errorf("api-key count = %d, want 1 (all: %+v)", countByClass["api-key"], findings)
	}
	if countByClass["secret-fallback"] != 2 {
		t.Errorf("secret-fallback count = %d, want 2 (all: %+v)", countByClass["secret-fallback"], findings)
	}
	if countByClass["recoverable-token"] != 1 {
		t.Errorf("recoverable-token count = %d, want 1 (all: %+v)", countByClass["recoverable-token"], findings)
	}
	if countByClass["configuration-token"] != 2 {
		t.Errorf("configuration-token count = %d, want 2 (all: %+v)", countByClass["configuration-token"], findings)
	}
}

func TestScan_UniversalSASTPatternsAndControls(t *testing.T) {
	t.Parallel()

	root := writeProjectFiles(t, map[string]string{
		"src/main/resources/schema.sql": `CREATE TABLE invoices (
    id BIGINT PRIMARY KEY,
    owner_id BIGINT NOT NULL,
    amount NUMERIC NOT NULL
);
CREATE TABLE products (
    id BIGINT PRIMARY KEY,
    title VARCHAR(255) NOT NULL
);
`,
		"src/main/kotlin/app/SearchRepo.kt": `package app

import org.springframework.jdbc.core.JdbcTemplate

class SearchRepo(private val jdbc: JdbcTemplate) {
    private val TABLE = "orders"

    fun unsafeMultiline(term: String): List<Map<String, Any>> {
        val sql = """
            SELECT id, total
            FROM orders
            WHERE status = '$term'
        """.trimIndent()
        return jdbc.queryForList(sql)
    }

    fun unsafeConcat(code: String) =
        jdbc.queryForList("SELECT id FROM orders WHERE code = '" + code + "'")

    fun safeConstantTable(id: Long) =
        jdbc.queryForList("SELECT id, total FROM $TABLE WHERE id = ?", id)
}
`,
		"src/main/kotlin/app/NetConfig.kt": `package app

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
`,
		"src/main/kotlin/app/SecurityConfig.kt": `package app

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
`,
		"src/main/kotlin/app/Controllers.kt": `package app

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
`,
	})

	findings, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	sastCounts := map[string]int{}
	for _, f := range findings {
		if f.Category == "SAST" {
			sastCounts[f.Class]++
		}
	}

	if sastCounts["sql-injection"] != 2 {
		t.Errorf("sql-injection count = %d, want 2 (all: %+v)", sastCounts["sql-injection"], findings)
	}
	if sastCounts["tls-verification"] != 1 {
		t.Errorf("tls-verification count = %d, want 1 (all: %+v)", sastCounts["tls-verification"], findings)
	}
	if sastCounts["credentialed-cors"] != 1 {
		t.Errorf("credentialed-cors count = %d, want 1 (all: %+v)", sastCounts["credentialed-cors"], findings)
	}
	if sastCounts["route-authorization"] != 1 {
		t.Errorf("route-authorization count = %d, want 1 (all: %+v)", sastCounts["route-authorization"], findings)
	}
	if sastCounts["object-authorization"] != 1 {
		t.Errorf("object-authorization count = %d, want 1 (all: %+v)", sastCounts["object-authorization"], findings)
	}
}
