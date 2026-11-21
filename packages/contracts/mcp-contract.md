# SecFlow Dual MCP Contract (ADR-0003 / T10)

This contract defines both directions of SecFlow's Dual MCP architecture so that `edge-gateway`, `mcp-bridge`, `packages/mcp-stdio`, and `services/web` stay strictly aligned while preserving all brief and security invariants.

---

## 1. Inbound — `SecFlow MCP Server` (`POST / GET /mcp` on `edge-gateway`)

- **Transport**: MCP Streamable HTTP (`POST /mcp` JSON-RPC 2.0 + `GET /mcp` SSE with `Mcp-Session-Id` and W3C `traceparent`) plus optional local `packages/mcp-stdio` thin bridge forwarding stdio JSON-RPC to `/mcp`.
- **Auth & RBAC**: Uses the exact same `Authorization: Bearer <jwt|scoped_token>` middleware as `/graphql`.
  - Required scopes for scoped MCP tokens:
    - `mcp:read` — list/get workflows, templates, runs, findings, AI report, SBOM, submission JSON, resources.
    - `mcp:run` — trigger `run_workflow` (still enforces `source-ingester` repository allowlist and rate limits).
    - `mcp:write` — `clone_template` (creates a sanitized workflow copy in the actor's workspace).
- **Internal Boundary**: Every tool and resource handler translates exclusively into internal gRPC calls (`WorkflowService`, `RunService`, `PluginRegistryService`, `AIService`).

### 1.1 MCP Tools

| Tool Name | Required Scope / Min Role | Internal gRPC Mapping | Input Parameters (JSON Schema summary) | Output Summary |
|-----------|---------------------------|-----------------------|----------------------------------------|----------------|
| `list_workflows` | `mcp:read` / `viewer` | `WorkflowService.ListWorkflows` | `{ search?: string, limit?: int, cursor?: string }` | `{ workflows: [{ id, name, description, version, updatedAt }], pageInfo }` |
| `list_templates` | `mcp:read` / `viewer` | `WorkflowService.ListTemplates` | `{ search?: string, tags?: string[], limit?: int, cursor?: string }` | `{ templates: [{ id, slug, name, problemSolved, tags, isBuiltin }], pageInfo }` |
| `clone_template` | `mcp:write` / `editor` | `WorkflowService.CloneTemplate` | `{ templateId: string, newWorkflowName: string }` | `{ workflowId, name, validationIssues }` (zero secrets/local URLs) |
| `generate_workflow_preview` | `mcp:read` / `viewer` | `AIService.GenerateWorkflow` | `{ prompt: string, locale?: "ru"\|"en" }` | `{ suggestedName, graph, missingFields }` (**preview only, never saved or executed**) |
| `run_workflow` | `mcp:run` / `editor` | `RunService.StartRun` | `{ workflowId: string, sourceIdOverride?: string, repoUrlOverride?: string, gitRefOverride?: string, commitShaOverride?: string }` | `{ runId, status, traceId }` (rejects non-allowlisted `repoUrlOverride`) |
| `get_run_status` | `mcp:read` / `viewer` | `RunService.GetRun` | `{ runId: string }` | `{ runId, status, gateResult, findingsStats, nodeStatuses[] }` |
| `get_findings` | `mcp:read` / `viewer` | `RunService.ListFindings` | `{ runId: string, category?: "SECRET"\|"SAST"\|"SCA", minSeverity?: Severity, limit?: int (default 25, max 100), cursor?: string }` | `{ findings[], stats, pageInfo }` (from immutable `Run Findings`, secrets masked) |
| `get_ai_report` | `mcp:read` / `viewer` | `RunService.GetAIReport` | `{ runId: string }` | `{ quality, releaseDecision, executiveSummary, groups[], items[] }` |
| `export_submission_json` | `mcp:read` / `viewer` | `RunService.GetSubmissionReport` | `{ runId: string }` | Exact UTF-8 `{"findings": [...]}` matching `submission-format.md` |
| `get_sbom` | `mcp:read` / `viewer` | `RunService.GetSbom` | `{ runId: string, includeContent?: bool }` | `{ digest, specVersion: "1.6", componentCount, cyclonedxJson? }` |

### 1.2 MCP Resources

| Resource URI | Required Scope | Internal gRPC Mapping | MIME Type |
|--------------|----------------|-----------------------|-----------|
| `secflow://plugins` | `mcp:read` | `PluginRegistryService.ListPlugins` | `application/json` |
| `secflow://templates` | `mcp:read` | `WorkflowService.ListTemplates` | `application/json` |
| `secflow://runs/{runId}/submission.json` | `mcp:read` | `RunService.GetSubmissionReport` | `application/json` |
| `secflow://runs/{runId}/report.md` | `mcp:read` | `RunService.GetReadableReport(MARKDOWN)` | `text/markdown` |
| `secflow://runs/{runId}/sbom.cdx.json` | `mcp:read` | `RunService.GetSbom(include_content=true)` | `application/vnd.cyclonedx+json` |

---

## 2. Outbound — `MCP Connection` + `mcp-bridge` + `mcp.tool` Node

### 2.1 Hard Security & Compliance Invariants (ADR-0003)

1. **`ai.explain` Isolation**: `ai-service` has **zero network access** and **zero gRPC permissions** to `MCPRegistryService` or `mcp-bridge`. LLMs NEVER autonomously invoke MCP tools; all external side effects occur ONLY through an explicit `mcp.tool` node placed on the Workflow DAG.
2. **Global Scanner Deny-List** (enforced on BOTH `MCPRegistryService.RegisterConnection` / `ListConnectionTools` AND runtime execution inside `mcp-bridge`):
   - Any external MCP server name, URL, tool name, or description matching prohibited third-party security scanners is **hard-blocked** (`DENYLIST_BLOCKED`):
     - `semgrep`, `gitleaks`, `trivy`, `detekt`, `osv-scanner`, `grype`, `syft`, `snyk`, `bandit`, `sonarqube`, `checkmarx`, `codeql`, `trufflehog`.
3. **Allowlist & SSRF Protection**: `MCPConnection.config.endpoint_url` MUST pass the outbound MCP allowlist and SSRF check (no loopback/link-local/metadata IP in production; local fake MCP server explicitly allowlisted in test/dev overlay).
4. **Scoped Secrets**: Auth credentials for an `MCPConnection` live in `SecretStore` (`SECRET_KIND_MCP_AUTH_HEADER`) and are resolved exclusively by `mcp-bridge` via `SecretService.ResolveScopedSecret` using `MCPDiscoverySecretScope` (for `tools/list`/`TestConnection`) or `NodeTaskSecretScope` with orchestrator-signed `task_lease_token` (during `mcp.tool` execution).

### 2.2 `mcp.tool` Node Parameter Contract (Frontend Inspector ↔ `orchestrator` ↔ `mcp-bridge`)

```json
{
  "connectionId": "conn_github_issues",
  "toolName": "create_issue",
  "arguments": {
    "title": "[SecFlow] {{ $envelope.stats.maxSeverity }} findings in {{ $trigger.repoUrl }}",
    "body": "{{ $ai.executiveSummary }}"
  },
  "outputVarKey": "githubIssue"
}
```

1. **UI Discovery Flow**:
   - User selects `connectionId` from GraphQL `mcpConnections`.
   - Frontend calls GraphQL `mcpConnectionTools(connectionId)` → `edge-gateway` → gRPC `MCPRegistryService.ListConnectionTools` → `mcp-bridge` calls external MCP `tools/list` → filters against allowlist & global scanner deny-list → returns `{ name, description, inputSchema }[]`.
   - Frontend renders the `arguments` sub-form dynamically from the selected tool's JSON `inputSchema`, enabling safe `{{ $trigger.* }}`, `{{ $envelope.* }}`, `{{ $ai.* }}`, `{{ $run.* }}` template bindings.
2. **Runtime Execution Flow**:
   - `orchestrator` evaluates safe `{{ ... }}` expressions in `arguments` (without arbitrary `eval`), then dispatches `NodeTask(plugin_id="mcp.tool", task_lease_token=...)` over `WorkerService.Connect`.
   - `mcp-bridge` re-validates connection allowlist + tool deny-list, resolves `auth_secret_ref` via `SecretService.ResolveScopedSecret`, executes deterministic MCP `tools/call`, redacts any secrets from the response, and returns `NodeResult` writing sanitized tool output into `Envelope.vars[outputVarKey]`.
