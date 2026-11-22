import type {
  CanvasNodeTemplate,
  NodeIconKey,
} from "./canvas-nodes-catalog";
import type { NodeFamily } from "./workflows-workspace-data";

export type GqlPluginCategory =
  | "TRIGGER"
  | "SOURCE"
  | "ANALYZER"
  | "LOGIC"
  | "AI_REPORT"
  | "ACTION";

export type GqlSandboxProfile =
  | "ORCHESTRATOR_BUILTIN"
  | "INTERNAL_ONLY"
  | "EGRESS_EXTERNAL";

export type PluginInstallationStatus =
  | "DRAFT"
  | "PROVISIONING"
  | "PENDING_APPROVAL"
  | "ACTIVE"
  | "DISABLED"
  | "ERROR"
  | "DELETING";

export type PluginSourceMode = "PRESET" | "OCI_IMAGE" | "EXTERNAL_PULL" | "DECLARATIVE";

export interface PluginPortDefinition {
  id: string;
  label: string;
  description?: string | null;
}

export interface JsonSchemaProperty {
  type?: "string" | "number" | "integer" | "boolean" | "array" | "object";
  description?: string;
  default?: unknown;
  enum?: string[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  items?: {
    type?: string;
    enum?: string[];
    minLength?: number;
  };
}

export interface JsonSchemaObject {
  $schema?: string;
  type?: string;
  additionalProperties?: boolean;
  required?: string[];
  properties?: Record<string, JsonSchemaProperty>;
}

export interface PluginManifestRecord {
  pluginId: string;
  version: string;
  displayName: string;
  description: string;
  category: GqlPluginCategory;
  capabilities: string[];
  paramsJsonSchema: JsonSchemaObject;
  inputPorts: PluginPortDefinition[];
  outputPorts: PluginPortDefinition[];
  runtimeLanguage: string;
  sandboxProfile: GqlSandboxProfile;
  isExternal: boolean;
  requiredSecretKeys: string[];
  maxConcurrency?: number;
}

export interface PluginResourceLimits {
  cpuRequest: string;
  cpuLimit: string;
  memoryRequest: string;
  memoryLimit: string;
  minReplicas: number;
  maxReplicas: number;
}

export interface PluginRuntimeDiagnostics {
  phase: string;
  desiredReplicas: number;
  readyReplicas: number;
  message: string;
  lastError: string;
  updatedAt?: string | null;
}

export interface PluginInstallationRecord {
  id: string;
  name: string;
  sourceMode: PluginSourceMode;
  presetId?: string | null;
  imageRef: string;
  sandboxProfile: GqlSandboxProfile;
  egressAllowlist: string[];
  resourceLimits: PluginResourceLimits;
  desiredReplicas: number;
  status: PluginInstallationStatus;
  statusReason?: string | null;
  autoApprove: boolean;
  approvedManifestDigest?: string | null;
  manifests: PluginManifestRecord[];
  pendingManifests: PluginManifestRecord[];
  pluginIds: string[];
  runtimeDiagnostics: PluginRuntimeDiagnostics;
  createdBy: string;
  approvedBy?: string | null;
  createdAt: string;
  updatedAt: string;
  approvedAt?: string | null;
  privilegeEscalation?: boolean;
  declarativeSpec?: Record<string, unknown> | null;
  pendingDeclarativeSpec?: Record<string, unknown> | null;
  pluginVersion?: string;
}

export interface PluginPresetRecord {
  id: string;
  name: string;
  description: string;
  imageRef: string;
  category: GqlPluginCategory;
  sandboxProfile: GqlSandboxProfile;
  pluginIds: string[];
  outputPorts: PluginPortDefinition[];
  requiredSecretKeys: string[];
  defaultEgressAllowlist: string[];
  defaultResourceLimits: PluginResourceLimits;
  autoApproveSupported: boolean;
  sampleManifests?: PluginManifestRecord[];
}

export interface LivePluginRecord {
  pluginId: string;
  version: string;
  displayName: string;
  description: string;
  category: GqlPluginCategory;
  capabilities: string[];
  paramsJsonSchema: JsonSchemaObject;
  inputPorts: PluginPortDefinition[];
  outputPorts: PluginPortDefinition[];
  runtimeLanguage: string;
  sandboxProfile: GqlSandboxProfile;
  isExternal: boolean;
  requiredSecretKeys: string[];
  status: "ONLINE" | "DEGRADED" | "OFFLINE";
  activeWorkers: number;
  queueDepth: number;
  installationId?: string | null;
  enabled: boolean;
  approvalPending: boolean;
  registeredAt: string;
  lastSeenAt: string;
}

export interface InstallPluginFormInput {
  name: string;
  sourceMode: PluginSourceMode;
  presetId?: string;
  imageRef?: string;
  sandboxProfile?: GqlSandboxProfile;
  egressAllowlist?: string[];
  resourceLimits?: Partial<PluginResourceLimits>;
  desiredReplicas?: number;
  autoApprove?: boolean;
  declarativeSpec?: Record<string, unknown>;
  saveAsDraft?: boolean;
}

export interface UpdatePluginInstallationFormInput {
  installationId: string;
  imageRef?: string;
  sandboxProfile?: GqlSandboxProfile;
  egressAllowlist?: string[];
  resourceLimits?: Partial<PluginResourceLimits>;
  desiredReplicas?: number;
  rotateToken?: boolean;
  declarativeSpec?: Record<string, unknown>;
  submitForApproval?: boolean;
  approveImmediately?: boolean;
}

export const DEFAULT_RESOURCE_LIMITS: PluginResourceLimits = {
  cpuRequest: "100m",
  cpuLimit: "500m",
  memoryRequest: "64Mi",
  memoryLimit: "256Mi",
  minReplicas: 1,
  maxReplicas: 2,
};

export const SPRING_CONFIG_MANIFEST: PluginManifestRecord = {
  pluginId: "scan.spring-config",
  version: "1.0.0",
  displayName: "Spring Config Hardening",
  description:
    "Детерминированный Go-анализатор конфигураций Spring Boot: проверяет открытые Actuator endpoints (*) и открытые пароли datasource в application.{yml,yaml,properties}.",
  category: "ANALYZER",
  capabilities: ["analyzer"],
  paramsJsonSchema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    properties: {
      checkActuatorExposure: {
        type: "boolean",
        default: true,
        description: "Обнаруживать Spring Boot Actuator endpoints, открытые через wildcard (*).",
      },
      checkPlaintextPasswords: {
        type: "boolean",
        default: true,
        description: "Обнаруживать незашифрованные пароли datasource в конфигах Spring.",
      },
      severity: {
        type: "string",
        enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default: "HIGH",
        description: "Уровень критичности находок анализатора.",
      },
      includePaths: {
        type: "array",
        items: { type: "string", minLength: 1 },
        default: [],
        description: "Префиксы путей или glob-шаблоны для включения (пусто = все конфиги).",
      },
      excludePaths: {
        type: "array",
        items: { type: "string", minLength: 1 },
        default: [],
        description: "Пути для пропуска (например src/test/, fixtures/).",
      },
    },
  },
  inputPorts: [{ id: "default", label: "Источник" }],
  outputPorts: [{ id: "default", label: "Envelope" }],
  runtimeLanguage: "go",
  sandboxProfile: "INTERNAL_ONLY",
  isExternal: true,
  requiredSecretKeys: [],
  maxConcurrency: 4,
};

export const RISK_ROUTER_MANIFEST: PluginManifestRecord = {
  pluginId: "logic.risk-router",
  version: "1.0.0",
  displayName: "Risk Router",
  description:
    "Внешний LOGIC-плагин взвешенной оценки риска по Envelope.findings: патчит gate и vars, направляет поток по портам BLOCK / REVIEW / OK без изменения Run Findings.",
  category: "LOGIC",
  capabilities: ["logic", "routing", "risk-scoring"],
  paramsJsonSchema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    required: ["blockThreshold", "reviewThreshold"],
    properties: {
      criticalWeight: {
        type: "integer",
        minimum: 0,
        default: 10,
        description: "Вес каждой находки уровня CRITICAL.",
      },
      highWeight: {
        type: "integer",
        minimum: 0,
        default: 5,
        description: "Вес каждой находки уровня HIGH.",
      },
      mediumWeight: {
        type: "integer",
        minimum: 0,
        default: 2,
        description: "Вес каждой находки уровня MEDIUM.",
      },
      lowWeight: {
        type: "integer",
        minimum: 0,
        default: 1,
        description: "Вес каждой находки уровня LOW.",
      },
      blockThreshold: {
        type: "integer",
        minimum: 1,
        default: 15,
        description: "Порог риска для активации ветки BLOCK (Gate = FAIL).",
      },
      reviewThreshold: {
        type: "integer",
        minimum: 0,
        default: 5,
        description: "Порог риска для ветки REVIEW (Gate = WARN); ниже — OK (PASS).",
      },
    },
  },
  inputPorts: [{ id: "default", label: "Вход" }],
  outputPorts: [
    { id: "BLOCK", label: "BLOCK", description: "Риск >= blockThreshold (Gate = FAIL)" },
    { id: "REVIEW", label: "REVIEW", description: "Риск >= reviewThreshold (Gate = WARN)" },
    { id: "OK", label: "OK", description: "Риск < reviewThreshold (Gate = PASS)" },
  ],
  runtimeLanguage: "go",
  sandboxProfile: "INTERNAL_ONLY",
  isExternal: true,
  requiredSecretKeys: [],
  maxConcurrency: 8,
};

export const JIRA_NOTIFIER_MANIFEST: PluginManifestRecord = {
  pluginId: "action.jira-notifier",
  version: "1.0.0",
  displayName: "Jira Security Notifier",
  description:
    "Внешний ACTION-плагин в профиле EGRESS_EXTERNAL: создаёт тикет в Jira по итогам прогона без доступа к исходному коду (secflow-sources).",
  category: "ACTION",
  capabilities: ["action", "notify"],
  paramsJsonSchema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    required: ["projectKey"],
    properties: {
      projectKey: {
        type: "string",
        default: "APPSEC",
        description: "Ключ проекта Jira (например APPSEC или SEC).",
      },
      issueType: {
        type: "string",
        enum: ["Security Bug", "Task", "Incident"],
        default: "Security Bug",
        description: "Тип создаваемой задачи в Jira.",
      },
      includeAiSummary: {
        type: "boolean",
        default: true,
        description: "Прикреплять grounded executiveSummary из AI Report.",
      },
      labels: {
        type: "array",
        items: { type: "string", minLength: 1 },
        default: ["secflow", "appsec"],
        description: "Метки задачи Jira.",
      },
    },
  },
  inputPorts: [{ id: "default", label: "Вход" }],
  outputPorts: [{ id: "default", label: "Результат" }],
  runtimeLanguage: "go",
  sandboxProfile: "EGRESS_EXTERNAL",
  isExternal: true,
  requiredSecretKeys: ["jiraApiToken"],
  maxConcurrency: 2,
};

export const BUILTIN_PLUGIN_PRESETS: PluginPresetRecord[] = [
  {
    id: "spring-config-hardening",
    name: "Spring Config Hardening",
    description:
      "Детерминированный анализатор конфигураций Spring Boot (Actuator wildcard и открытые пароли datasource).",
    imageRef: "ghcr.io/secflow/demo-spring-config:1.0.0",
    category: "ANALYZER",
    sandboxProfile: "INTERNAL_ONLY",
    pluginIds: ["scan.spring-config"],
    outputPorts: [{ id: "default", label: "Envelope" }],
    requiredSecretKeys: [],
    defaultEgressAllowlist: [],
    defaultResourceLimits: { ...DEFAULT_RESOURCE_LIMITS },
    autoApproveSupported: true,
    sampleManifests: [SPRING_CONFIG_MANIFEST],
  },
  {
    id: "risk-router",
    name: "Risk Router",
    description:
      "Внешний LOGIC-маршрутизатор с настраиваемыми весами severity и тремя динамическими портами BLOCK / REVIEW / OK.",
    imageRef: "ghcr.io/secflow/demo-risk-router:1.0.0",
    category: "LOGIC",
    sandboxProfile: "INTERNAL_ONLY",
    pluginIds: ["logic.risk-router"],
    outputPorts: RISK_ROUTER_MANIFEST.outputPorts,
    requiredSecretKeys: [],
    defaultEgressAllowlist: [],
    defaultResourceLimits: { ...DEFAULT_RESOURCE_LIMITS },
    autoApproveSupported: true,
    sampleManifests: [RISK_ROUTER_MANIFEST],
  },
  {
    id: "jira-security-notifier",
    name: "Jira Security Notifier",
    description:
      "Внешнее действие доставки результатов в корпоративный Jira (EGRESS_EXTERNAL, без доступа к secflow-sources).",
    imageRef: "ghcr.io/secflow/jira-notifier:1.0.0",
    category: "ACTION",
    sandboxProfile: "EGRESS_EXTERNAL",
    pluginIds: ["action.jira-notifier"],
    outputPorts: [{ id: "default", label: "Результат" }],
    requiredSecretKeys: ["jiraApiToken"],
    defaultEgressAllowlist: ["jira.centrinvest.example:443"],
    defaultResourceLimits: { ...DEFAULT_RESOURCE_LIMITS },
    autoApproveSupported: false,
    sampleManifests: [JIRA_NOTIFIER_MANIFEST],
  },
];

export function mapPluginCategoryToFamily(category: GqlPluginCategory): NodeFamily {
  switch (category) {
    case "TRIGGER":
      return "trigger";
    case "SOURCE":
      return "source";
    case "ANALYZER":
      return "analyzer";
    case "LOGIC":
      return "logic";
    case "AI_REPORT":
      return "ai";
    case "ACTION":
      return "action";
  }
}

export function iconKeyForCategory(category: GqlPluginCategory): NodeIconKey {
  switch (category) {
    case "TRIGGER":
      return "play";
    case "SOURCE":
      return "git";
    case "ANALYZER":
      return "shield-code";
    case "LOGIC":
      return "git-branch";
    case "AI_REPORT":
      return "sparkles";
    case "ACTION":
      return "globe";
  }
}

export function extractDefaultConfigFromSchema(
  schema?: JsonSchemaObject | null,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!schema?.properties) return out;
  for (const [key, prop] of Object.entries(schema.properties)) {
    if (prop.default === undefined || prop.default === null) {
      if (prop.type === "boolean") out[key] = "false";
      else if (prop.type === "array") out[key] = "[]";
      else out[key] = "";
    } else if (typeof prop.default === "string") {
      out[key] = prop.default;
    } else {
      out[key] = JSON.stringify(prop.default);
    }
  }
  return out;
}

export function livePluginToCanvasTemplate(plugin: LivePluginRecord): CanvasNodeTemplate {
  const family = mapPluginCategoryToFamily(plugin.category);
  const outputs =
    plugin.outputPorts.length > 0
      ? plugin.outputPorts.map((p) => p.id)
      : ["default"];

  return {
    pluginId: plugin.pluginId,
    family,
    label: plugin.displayName || plugin.pluginId,
    shortLabel: plugin.displayName || plugin.pluginId,
    purposeTag: plugin.isExternal ? "Sandbox · v" + plugin.version : "Встроенный",
    description: plugin.description || `Плагин ${plugin.pluginId}`,
    runtime: plugin.isExternal
      ? `secflow-sandbox (${plugin.runtimeLanguage || "oci"})`
      : plugin.runtimeLanguage || "orchestrator",
    durationMs: family === "analyzer" ? 420 : family === "logic" ? 45 : 180,
    iconKey: iconKeyForCategory(plugin.category),
    inputs: plugin.inputPorts.length > 0 ? plugin.inputPorts.length : 1,
    outputs,
    defaultConfig: extractDefaultConfigFromSchema(plugin.paramsJsonSchema),
    sampleOutput: {
      pluginId: plugin.pluginId,
      sandboxProfile: plugin.sandboxProfile,
      ports: outputs,
      status: "SUCCEEDED",
    },
    isExternal: plugin.isExternal,
    sandboxProfile: plugin.sandboxProfile,
    paramsJsonSchema: plugin.paramsJsonSchema,
    requiredSecretKeys: plugin.requiredSecretKeys,
    installationId: plugin.installationId ?? undefined,
  };
}
