import type { CanvasNodeTemplate } from "./canvas-nodes-catalog";
import {
  extractDefaultConfigFromSchema,
  iconKeyForCategory,
  mapPluginCategoryToFamily,
  type GqlPluginCategory,
  type JsonSchemaObject,
  type JsonSchemaProperty,
  type PluginPortDefinition,
} from "./plugins-data";

export type DeclarativeCategory = "ANALYZER" | "LOGIC" | "ACTION";
export type DeclarativeParamType = "string" | "enum" | "integer" | "number" | "boolean" | "array";
export type DeclarativeMatcherType = "regex" | "config_key" | "file_presence";

export interface DeclarativeParamField {
  key: string;
  type: DeclarativeParamType;
  description?: string;
  required?: boolean;
  default?: unknown;
  enum?: string[];
  minimum?: number;
  maximum?: number;
}

export interface DeclarativeAnalyzerRule {
  ruleId: string;
  category: "SECRET" | "SAST" | "SCA";
  severity: string;
  title: string;
  description?: string;
  remediation?: string;
  includeGlobs?: string[];
  excludeGlobs?: string[];
  matcherType: DeclarativeMatcherType;
  pattern?: string;
  multiline?: boolean;
  excludePatterns?: string[];
  configKey?: string;
  configValuePattern?: string;
  presenceMode?: "exists" | "absent";
  enabledParam?: string;
}

export interface DeclarativeComputedVar {
  name: string;
  kind: "weighted_score" | "finding_count" | "template";
  criticalWeight?: number;
  highWeight?: number;
  mediumWeight?: number;
  lowWeight?: number;
  filterCategory?: string;
  filterSeverity?: string;
  filterRuleId?: string;
  template?: string;
}

export interface DeclarativeLogicCondition {
  field: string;
  operator: "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "contains" | "matches";
  value: string;
}

export interface DeclarativeLogicRoute {
  name?: string;
  matchMode?: "ALL" | "ANY";
  conditions: DeclarativeLogicCondition[];
  outputPort: string;
  gate?: "" | "PASS" | "WARN" | "FAIL";
  setVars?: Record<string, string>;
  filterFindings?: {
    minSeverity?: string;
    categories?: string[];
  };
}

export interface DeclarativeLogicSpec {
  computedVars?: DeclarativeComputedVar[];
  routes: DeclarativeLogicRoute[];
  fallbackPort: string;
  fallbackGate?: "" | "PASS" | "WARN" | "FAIL";
  fallbackVars?: Record<string, string>;
}

export interface DeclarativeActionSpec {
  method: "POST" | "PUT" | "PATCH" | "GET";
  url: string;
  headers?: Record<string, string>;
  bodyTemplate?: string;
  expectedStatuses?: number[];
  timeoutSeconds?: number;
  extractVars?: Record<string, string>;
}

export interface DeclarativePluginSpec {
  pluginId: string;
  version?: string;
  displayName: string;
  description?: string;
  category: DeclarativeCategory;
  params?: DeclarativeParamField[];
  outputPorts?: PluginPortDefinition[];
  requiredSecretKeys?: string[];
  egressAllowlist?: string[];
  analyzer?: {
    rules: DeclarativeAnalyzerRule[];
  };
  logic?: DeclarativeLogicSpec;
  action?: DeclarativeActionSpec;
}

export interface DeclarativeBlueprintRecord {
  id: string;
  name: string;
  description: string;
  spec: DeclarativePluginSpec;
}

export interface VirtualFileFixture {
  path: string;
  content: string;
}

export interface TestDeclarativePluginInput {
  declarativeSpec: DeclarativePluginSpec;
  params?: Record<string, unknown>;
  files?: VirtualFileFixture[];
  envelope?: Record<string, unknown>;
}

export interface TestDeclarativePluginFinding {
  findingId?: string;
  findingClass?: string;
  category?: string;
  severity?: string;
  path?: string;
  line?: number | null;
  description?: string;
  maskedSnippet?: string;
}

export interface TestDeclarativePluginResult {
  ok: boolean;
  validationErrors: string[];
  findings: TestDeclarativePluginFinding[];
  activeOutputPorts: string[];
  envelopePatch?: Record<string, unknown> | null;
  dryRunHttp?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    allowed: boolean;
    policyReason?: string;
    matchedHostRule?: string;
  } | null;
  durationMs: number;
  summary: string;
}

export interface SavedNodeRecord {
  id: string;
  name: string;
  description: string;
  pluginId: string;
  params: Record<string, unknown>;
  canonicalParamsHash: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export const DECLARATIVE_STARTER_BLUEPRINTS: DeclarativeBlueprintRecord[] = [
  {
    id: "spring-yaml-config-check",
    name: "Spring / YAML Config Check",
    description:
      "Ищет открытый Actuator wildcard (*) в YAML/properties и проверяет наличие SECURITY.md.",
    spec: {
      pluginId: "custom.scan.spring-config-guard",
      version: "1.0.0",
      displayName: "Spring Config Guard",
      description: "Декларативная проверка конфигурации Spring Boot и политики репозитория.",
      category: "ANALYZER",
      params: [
        {
          key: "severity",
          type: "enum",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          default: "HIGH",
          description: "Критичность находок конфигурации.",
        },
        {
          key: "checkSecurityPolicy",
          type: "boolean",
          default: true,
          description: "Проверять наличие SECURITY.md в корне репозитория.",
        },
      ],
      analyzer: {
        rules: [
          {
            ruleId: "SPRING-ACTUATOR-WILDCARD",
            category: "SAST",
            severity: "{{ params.severity }}",
            title: "Spring Actuator exposed with wildcard (*)",
            description: "Wildcard exposure opens sensitive Actuator endpoints (/env, /heapdump).",
            remediation: "Limit management.endpoints.web.exposure.include to health,info.",
            includeGlobs: ["**/application*.yml", "**/application*.yaml", "**/application*.properties"],
            matcherType: "config_key",
            configKey: "management.endpoints.web.exposure.include",
            configValuePattern: "^\\*$",
            excludePatterns: ["\\$\\{.*\\}"],
          },
          {
            ruleId: "REPO-SECURITY-MD",
            category: "SAST",
            severity: "LOW",
            title: "Missing SECURITY.md policy file",
            description: "Repository does not declare a vulnerability reporting policy.",
            remediation: "Add SECURITY.md at the repository root.",
            includeGlobs: ["SECURITY.md"],
            matcherType: "file_presence",
            presenceMode: "absent",
            enabledParam: "checkSecurityPolicy",
          },
        ],
      },
    },
  },
  {
    id: "weighted-risk-router",
    name: "Weighted Risk Router",
    description: "Считает взвешенный риск-скор и маршрутизирует поток на порты BLOCK / REVIEW / OK.",
    spec: {
      pluginId: "custom.logic.weighted-risk-router",
      version: "1.0.0",
      displayName: "Weighted Risk Router",
      description: "Маршрутизация релиза по взвешенному риск-скору находок.",
      category: "LOGIC",
      outputPorts: [
        { id: "BLOCK", label: "BLOCK", description: "Блокировка релиза" },
        { id: "REVIEW", label: "REVIEW", description: "Требуется AppSec-ревью" },
        { id: "OK", label: "OK", description: "Допустимый уровень риска" },
      ],
      params: [
        { key: "blockThreshold", type: "integer", default: 15, description: "Порог для BLOCK" },
        { key: "reviewThreshold", type: "integer", default: 5, description: "Порог для REVIEW" },
      ],
      logic: {
        computedVars: [
          {
            name: "riskScore",
            kind: "weighted_score",
            criticalWeight: 10,
            highWeight: 5,
            mediumWeight: 2,
            lowWeight: 1,
          },
        ],
        routes: [
          {
            name: "Block release",
            matchMode: "ALL",
            outputPort: "BLOCK",
            gate: "FAIL",
            setVars: { riskDecision: "BLOCK" },
            conditions: [{ field: "vars.riskScore", operator: "gte", value: "{{ params.blockThreshold }}" }],
          },
          {
            name: "Require AppSec review",
            matchMode: "ALL",
            outputPort: "REVIEW",
            gate: "WARN",
            setVars: { riskDecision: "REVIEW" },
            conditions: [{ field: "vars.riskScore", operator: "gte", value: "{{ params.reviewThreshold }}" }],
          },
        ],
        fallbackPort: "OK",
        fallbackGate: "PASS",
        fallbackVars: { riskDecision: "OK" },
      },
    },
  },
  {
    id: "webhook-issue-ticket",
    name: "Webhook / Issue Ticket",
    description: "Отправляет JSON-запрос во внешний трекер с Secret Reference и сохраняет ключ тикета.",
    spec: {
      pluginId: "custom.action.issue-ticket",
      version: "1.0.0",
      displayName: "Create Issue Ticket",
      description: "Создание задачи во внешнем трекере по итогам сканирования.",
      category: "ACTION",
      requiredSecretKeys: ["apiToken"],
      egressAllowlist: ["tracker.example.com"],
      params: [
        { key: "projectKey", type: "string", default: "APPSEC", required: true, description: "Ключ проекта" },
      ],
      action: {
        method: "POST",
        url: "https://tracker.example.com/api/v1/issues",
        headers: {
          Authorization: "Bearer {{ secrets.apiToken }}",
          "Content-Type": "application/json",
        },
        bodyTemplate:
          '{"project":"{{ params.projectKey }}","summary":"SecFlow: {{ envelope.stats.total }} findings"}',
        expectedStatuses: [200, 201, 202],
        timeoutSeconds: 10,
        extractVars: { ticketKey: "key", ticketUrl: "url" },
      },
    },
  },
];

export function prefixForCategory(cat: DeclarativeCategory): string {
  if (cat === "ANALYZER") return "custom.scan.";
  if (cat === "LOGIC") return "custom.logic.";
  return "custom.action.";
}

export function slugifyName(raw: string): string {
  const cleaned = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 42);
  return cleaned.length >= 2 ? cleaned : "my-plugin";
}

export function emptySpecForCategory(cat: DeclarativeCategory): DeclarativePluginSpec {
  const prefix = prefixForCategory(cat);
  if (cat === "ANALYZER") {
    return {
      pluginId: `${prefix}custom-rule`,
      version: "1.0.0",
      displayName: "Новый анализатор",
      description: "Детерминированная проверка по исходному коду или конфигам.",
      category: "ANALYZER",
      params: [
        {
          key: "severity",
          type: "enum",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          default: "HIGH",
          description: "Критичность находки",
        },
      ],
      analyzer: {
        rules: [
          {
            ruleId: "CUSTOM-001",
            category: "SAST",
            severity: "{{ params.severity }}",
            title: "Запрещённый паттерн",
            description: "Обнаружен небезопасный паттерн в коде.",
            remediation: "Замените небезопасную конструкцию.",
            includeGlobs: ["**/*.kt", "**/*.yml"],
            matcherType: "regex",
            pattern: "TODO_REPLACE_PATTERN",
            excludePatterns: [],
          },
        ],
      },
    };
  }
  if (cat === "LOGIC") {
    return {
      pluginId: `${prefix}custom-router`,
      version: "1.0.0",
      displayName: "Новый маршрутизатор",
      description: "Детерминированная маршрутизация Envelope по условиям.",
      category: "LOGIC",
      outputPorts: [
        { id: "ALERT", label: "ALERT" },
        { id: "OK", label: "OK" },
      ],
      params: [{ key: "threshold", type: "integer", default: 1, description: "Порог срабатывания" }],
      logic: {
        computedVars: [],
        routes: [
          {
            name: "Trigger alert",
            matchMode: "ALL",
            outputPort: "ALERT",
            gate: "FAIL",
            conditions: [{ field: "stats.critical", operator: "gte", value: "{{ params.threshold }}" }],
          },
        ],
        fallbackPort: "OK",
        fallbackGate: "PASS",
      },
    };
  }
  return {
    pluginId: `${prefix}custom-webhook`,
    version: "1.0.0",
    displayName: "Новый HTTP Action",
    description: "Исходящий HTTP-запрос по allowlist (секреты опциональны).",
    category: "ACTION",
    requiredSecretKeys: [],
    egressAllowlist: ["hooks.example.com"],
    params: [{ key: "channel", type: "string", default: "appsec", required: true, description: "Канал или проект" }],
    action: {
      method: "POST",
      url: "https://hooks.example.com/v1/events",
      headers: {
        "Content-Type": "application/json",
      },
      bodyTemplate: '{"channel":"{{ params.channel }}","total":{{ envelope.stats.total }}}',
      expectedStatuses: [200, 201, 202],
      timeoutSeconds: 10,
      extractVars: { externalId: "id" },
    },
  };
}

export function specToJsonSchema(spec: DeclarativePluginSpec): JsonSchemaObject {
  const properties: Record<string, JsonSchemaProperty> = {};
  const required: string[] = [];
  for (const field of spec.params ?? []) {
    if (!field.key.trim()) continue;
    const prop: JsonSchemaProperty = {
      description: field.description || undefined,
      default: field.default,
    };
    if (field.type === "enum") {
      prop.type = "string";
      prop.enum = field.enum && field.enum.length > 0 ? field.enum : ["HIGH"];
    } else if (field.type === "array") {
      prop.type = "array";
      prop.items = { type: "string", minLength: 1 };
    } else {
      prop.type = field.type;
      if (field.minimum !== undefined) prop.minimum = field.minimum;
      if (field.maximum !== undefined) prop.maximum = field.maximum;
    }
    properties[field.key.trim()] = prop;
    if (field.required) required.push(field.key.trim());
  }
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    ...(required.length > 0 ? { required } : {}),
    properties,
  };
}

export function specToCanvasTemplate(
  spec: DeclarativePluginSpec,
  installationId?: string,
): CanvasNodeTemplate {
  const gqlCat: GqlPluginCategory = spec.category;
  const family = mapPluginCategoryToFamily(gqlCat);
  const schema = specToJsonSchema(spec);
  const outputs =
    spec.category === "LOGIC" && spec.outputPorts && spec.outputPorts.length > 0
      ? spec.outputPorts.map((p) => p.id)
      : ["default"];

  return {
    pluginId: spec.pluginId,
    family,
    label: spec.displayName || spec.pluginId,
    shortLabel: (spec.displayName || spec.pluginId).slice(0, 28),
    purposeTag: spec.description || `Declarative ${spec.category}`,
    description: spec.description || `Declarative ${spec.category} plugin`,
    runtime: "Declarative Sandbox",
    durationMs: 250,
    iconKey: iconKeyForCategory(gqlCat),
    inputs: 1,
    outputs,
    requiredSecretKeys: spec.category === "ACTION" ? spec.requiredSecretKeys ?? [] : [],
    defaultConfig: extractDefaultConfigFromSchema(schema),
    sampleOutput: {
      pluginId: spec.pluginId,
      mode: "declarative",
      category: spec.category,
    },
    isExternal: true,
    sandboxProfile: spec.category === "ACTION" ? "EGRESS_EXTERNAL" : "INTERNAL_ONLY",
    paramsJsonSchema: schema,
    installationId,
  };
}

const SECRET_KEY_SUBSTRINGS = [
  "secret",
  "token",
  "password",
  "passwd",
  "apikey",
  "api_key",
  "authorization",
  "credential",
  "privatekey",
  "private_key",
  "hmac",
];

function isSecretKey(k: string): boolean {
  const lk = k.toLowerCase().trim();
  return SECRET_KEY_SUBSTRINGS.some((s) => lk.includes(s));
}

export function stripSecretsFromParams(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(input).sort()) {
    if (isSecretKey(key)) continue;
    const val = input[key];
    if (val && typeof val === "object" && !Array.isArray(val)) {
      out[key] = stripSecretsFromParams(val as Record<string, unknown>);
    } else {
      out[key] = val;
    }
  }
  return out;
}

export function canonicalizeParamsObject(input: Record<string, unknown>): string {
  return JSON.stringify(stripSecretsFromParams(input));
}

export function configToTypedParams(config: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, raw] of Object.entries(config)) {
    if (raw === "true") out[k] = true;
    else if (raw === "false") out[k] = false;
    else if (raw.trim() !== "" && !Number.isNaN(Number(raw)) && /^-?\d+(\.\d+)?$/.test(raw.trim())) {
      out[k] = Number(raw);
    } else if ((raw.startsWith("[") && raw.endsWith("]")) || (raw.startsWith("{") && raw.endsWith("}"))) {
      try {
        out[k] = JSON.parse(raw);
      } catch {
        out[k] = raw;
      }
    } else {
      out[k] = raw;
    }
  }
  return out;
}

export function paramsToConfigStrings(params: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v === undefined || v === null) continue;
    out[k] = typeof v === "string" ? v : JSON.stringify(v);
  }
  return out;
}

export async function sha256HexClient(text: string): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Fallback deterministic fingerprint for non-secure contexts.
  let h = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `fnv_${(h >>> 0).toString(16)}`;
}
