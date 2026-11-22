import type { UserRole } from "./workflows-workspace-data";

export type SettingsTabId =
  | "profile"
  | "secrets"
  | "tokens"
  | "ai"
  | "mcp"
  | "plugins";

export interface SettingsTabMeta {
  id: SettingsTabId;
  label: string;
  shortLabel: string;
  description: string;
}

export const SETTINGS_TABS: SettingsTabMeta[] = [
  {
    id: "profile",
    label: "Профиль",
    shortLabel: "Профиль",
    description: "Аккаунт, роль доступа (RBAC) и управление сессией",
  },
  {
    id: "secrets",
    label: "Секреты",
    shortLabel: "Секреты",
    description: "Хранилище masked-секретов с привязкой к узлам (least-privilege)",
  },
  {
    id: "tokens",
    label: "Токены",
    shortLabel: "Токены",
    description: "Scoped Tokens для CI/CD и внешних MCP-клиентов",
  },
  {
    id: "ai",
    label: "AI-провайдер",
    shortLabel: "AI",
    description: "Подключение ai-service, строгий grounding и журнал AI Audit",
  },
  {
    id: "mcp",
    label: "MCP-подключения",
    shortLabel: "MCP",
    description: "Регистрация внешних Outbound MCP-подключений и инспекция tools",
  },
  {
    id: "plugins",
    label: "Плагины",
    shortLabel: "Плагины",
    description:
      "Управляемые sandbox-установки (secflow-sandbox): пресеты, OCI-образы, одобрение и диагностика",
  },
];

export function normalizeSettingsTab(raw: string | null | undefined): SettingsTabId {
  if (!raw) return "secrets";
  const found = SETTINGS_TABS.find((t) => t.id === raw);
  return found ? found.id : "secrets";
}

export type SecretBindingScope =
  | "source.git"
  | "ai.explain"
  | "notify.telegram"
  | "notify.webhook"
  | "notify.smtp"
  | "notify.commit_status"
  | "trigger.webhook"
  | "mcp.tool"
  | "generic";

export const SECRET_BINDING_OPTIONS: Array<{ value: SecretBindingScope; label: string }> = [
  { value: "source.git", label: "source.git (доступ к Git)" },
  { value: "ai.explain", label: "ai.explain (LLM API Key)" },
  { value: "notify.telegram", label: "notify.telegram (Bot Token)" },
  { value: "notify.webhook", label: "notify.webhook (HMAC / Bearer)" },
  { value: "notify.smtp", label: "notify.smtp (SMTP Password)" },
  { value: "notify.commit_status", label: "notify.commit_status (Git Status)" },
  { value: "trigger.webhook", label: "trigger.webhook (HMAC-подпись)" },
  { value: "mcp.tool", label: "mcp.tool (Outbound MCP Auth)" },
  { value: "generic", label: "generic (общий секрет)" },
];

export interface SecretRecord {
  id: string;
  name: string;
  maskedValue: string;
  binding: SecretBindingScope;
  updatedAt: string;
  createdBy: string;
}

export type TokenScope =
  | "ci:startRun"
  | "ci:readRun"
  | "mcp:read"
  | "mcp:run"
  | "mcp:write";

export const ALL_TOKEN_SCOPES: Array<{ scope: TokenScope; description: string }> = [
  { scope: "ci:startRun", description: "Запуск привязанного workflow из CI/CD" },
  { scope: "ci:readRun", description: "Чтение статуса, отчётов и вердикта Policy Gate" },
  { scope: "mcp:read", description: "Чтение workflow, находок и SBOM через MCP" },
  { scope: "mcp:run", description: "Запуск workflow через Inbound MCP Tool" },
  { scope: "mcp:write", description: "Клонирование шаблонов через MCP" },
];

export interface ScopedTokenRecord {
  id: string;
  name: string;
  prefix: string;
  scopes: TokenScope[];
  workflowScope: string;
  expiresAt: string;
  lastUsedAt: string;
  status: "ACTIVE" | "REVOKED";
}

export type AiProviderMode = "openai-compatible" | "local-ollama" | "deterministic-only";

export interface AiProviderConfig {
  mode: AiProviderMode;
  endpointUrl: string;
  model: string;
  secretRef: string;
  timeoutSec: number;
  strictGrounding: boolean;
  allowTextToWorkflow: boolean;
  status: "HEALTHY" | "DEGRADED" | "DISABLED";
  lastCheckedAt: string;
  lastLatencyMs: number;
}

export interface AiAuditLogRecord {
  id: string;
  timestamp: string;
  operation: "ai.explain" | "GenerateWorkflow";
  runId: string;
  model: string;
  findingsGrounded: string;
  hallucinatedCve: number;
  latencyMs: number;
  status: "OK" | "FALLBACK";
}

export interface McpToolInfo {
  name: string;
  description: string;
  inputHint: string;
}

export interface McpConnectionRecord {
  id: string;
  name: string;
  transport: "Streamable HTTP" | "SSE";
  endpointUrl: string;
  authSecretRef: string;
  status: "CONNECTED" | "ERROR" | "TESTING" | "UNTESTED";
  lastTestedAt: string;
  latencyMs: number;
  tools: McpToolInfo[];
}

export interface RbacCapabilityRow {
  area: string;
  detail: string;
  viewer: "allow" | "readonly" | "deny";
  editor: "allow" | "readonly" | "deny";
  owner: "allow" | "readonly" | "deny";
}

export const RBAC_MATRIX: RbacCapabilityRow[] = [
  {
    area: "Workflows и запуски",
    detail: "Просмотр, редактирование графа, запуск и отмена прогонов",
    viewer: "readonly",
    editor: "allow",
    owner: "allow",
  },
  {
    area: "Отчёты, SBOM и AI Explain",
    detail: "Чтение submission.json, CycloneDX 1.6, AI Audit и Webhook Inspector",
    viewer: "readonly",
    editor: "allow",
    owner: "allow",
  },
  {
    area: "Секреты (masked)",
    detail: "Просмотр метаданных, добавление и удаление (без plaintext)",
    viewer: "deny",
    editor: "allow",
    owner: "allow",
  },
  {
    area: "Scoped Tokens (CI / MCP)",
    detail: "Выпуск, просмотр и отзыв токенов доступа",
    viewer: "deny",
    editor: "deny",
    owner: "allow",
  },
  {
    area: "MCP-подключения",
    detail: "Регистрация, изменение, тест и удаление внешних MCP-подключений",
    viewer: "readonly",
    editor: "readonly",
    owner: "allow",
  },
  {
    area: "Плагины (secflow-sandbox)",
    detail: "Установка пресетов/OCI-образов, одобрение манифестов, включение/отключение и удаление",
    viewer: "readonly",
    editor: "readonly",
    owner: "allow",
  },
];

export const INITIAL_SECRETS: SecretRecord[] = [
  {
    id: "sec-git-token",
    name: "GIT_TOKEN",
    maskedValue: "•••• 4f2a",
    binding: "source.git",
    updatedAt: "Сегодня, 02:14",
    createdBy: "Анна Соколова",
  },
  {
    id: "sec-llm-api-key",
    name: "LLM_API_KEY",
    maskedValue: "•••• 9c1b",
    binding: "ai.explain",
    updatedAt: "Вчера, 19:40",
    createdBy: "Анна Соколова",
  },
  {
    id: "sec-tg-token",
    name: "TG_TOKEN",
    maskedValue: "•••• 7e0d",
    binding: "notify.telegram",
    updatedAt: "Вчера, 18:05",
    createdBy: "Дмитрий Волков",
  },
  {
    id: "sec-webhook-hmac",
    name: "WEBHOOK_HMAC_SECRET",
    maskedValue: "•••• b318",
    binding: "notify.webhook",
    updatedAt: "2 дня назад",
    createdBy: "Анна Соколова",
  },
  {
    id: "sec-mcp-tracker",
    name: "MCP_TRACKER_BEARER",
    maskedValue: "•••• 2a9e",
    binding: "mcp.tool",
    updatedAt: "3 дня назад",
    createdBy: "Анна Соколова",
  },
];

export const INITIAL_SCOPED_TOKENS: ScopedTokenRecord[] = [
  {
    id: "tok-gitlab-pr",
    name: "GitLab CI — PR Gate",
    prefix: "sf_tok_8e41…",
    scopes: ["ci:startRun", "ci:readRun"],
    workflowScope: "CI/CD Gate для Pull Request",
    expiresAt: "2027-02-20",
    lastUsedAt: "48 мин назад",
    status: "ACTIVE",
  },
  {
    id: "tok-ide-mcp",
    name: "Cursor / IDE MCP Reader",
    prefix: "sf_tok_3c9d…",
    scopes: ["mcp:read", "mcp:run"],
    workflowScope: "Все workflow",
    expiresAt: "2027-01-15",
    lastUsedAt: "2 ч назад",
    status: "ACTIVE",
  },
  {
    id: "tok-legacy-runner",
    name: "Старый nightly runner",
    prefix: "sf_tok_1a07…",
    scopes: ["ci:startRun"],
    workflowScope: "Ночной аудит зависимостей и SBOM",
    expiresAt: "2026-10-01",
    lastUsedAt: "14 дней назад",
    status: "REVOKED",
  },
];

export const INITIAL_AI_CONFIG: AiProviderConfig = {
  mode: "openai-compatible",
  endpointUrl: "https://llm-gateway.centrinvest.local/v1",
  model: "gpt-4.1-mini",
  secretRef: "LLM_API_KEY",
  timeoutSec: 25,
  strictGrounding: true,
  allowTextToWorkflow: true,
  status: "HEALTHY",
  lastCheckedAt: "12 мин назад",
  lastLatencyMs: 184,
};

export const INITIAL_AI_AUDIT_LOGS: AiAuditLogRecord[] = [
  {
    id: "aiaudit-01",
    timestamp: "Сегодня, 03:48",
    operation: "ai.explain",
    runId: "run_9f4c2b81",
    model: "gpt-4.1-mini",
    findingsGrounded: "15 / 15 findingId",
    hallucinatedCve: 0,
    latencyMs: 1080,
    status: "OK",
  },
  {
    id: "aiaudit-02",
    timestamp: "Сегодня, 03:12",
    operation: "GenerateWorkflow",
    runId: "draft_7a2c10",
    model: "gpt-4.1-mini",
    findingsGrounded: "6 узлов валидированы",
    hallucinatedCve: 0,
    latencyMs: 840,
    status: "OK",
  },
  {
    id: "aiaudit-03",
    timestamp: "Вчера, 21:16",
    operation: "ai.explain",
    runId: "run_2d88e10a",
    model: "deterministic-template",
    findingsGrounded: "15 / 15 (fallback)",
    hallucinatedCve: 0,
    latencyMs: 22,
    status: "FALLBACK",
  },
];

export const INITIAL_MCP_CONNECTIONS: McpConnectionRecord[] = [
  {
    id: "mcp-tracker",
    name: "tracker-mcp-internal",
    transport: "Streamable HTTP",
    endpointUrl: "https://mcp-tracker.centrinvest.local/mcp",
    authSecretRef: "MCP_TRACKER_BEARER",
    status: "CONNECTED",
    lastTestedAt: "18 мин назад",
    latencyMs: 92,
    tools: [
      {
        name: "create_security_issue",
        description: "Создаёт задачу в трекере с привязкой к findingId и файлу",
        inputHint: "{ projectKey, title, severity, findingId }",
      },
      {
        name: "comment_on_release",
        description: "Публикует сводку Policy Gate и ссылку на SBOM",
        inputHint: "{ releaseTag, verdict, summaryMd }",
      },
    ],
  },
  {
    id: "mcp-kb",
    name: "appsec-runbooks-mcp",
    transport: "SSE",
    endpointUrl: "https://kb-mcp.centrinvest.local/sse",
    authSecretRef: "",
    status: "CONNECTED",
    lastTestedAt: "1 ч назад",
    latencyMs: 134,
    tools: [
      {
        name: "lookup_remediation_guide",
        description: "Возвращает внутренний стандарт банка по CWE / Spring Security",
        inputHint: "{ cweId, stack }",
      },
    ],
  },
];

export function canManageSecrets(role: UserRole): boolean {
  return role === "owner" || role === "editor";
}

export function canManageOwnerOnly(role: UserRole): boolean {
  return role === "owner";
}
