import type {
  GqlSandboxProfile,
  JsonSchemaObject,
} from "./plugins-data";
import type {
  NodeFamily,
  PolicyVerdict,
  StarterTemplateRecord,
  WorkflowRecord,
} from "./workflows-workspace-data";

export type NodeIconKey =
  | "play"
  | "webhook"
  | "clock"
  | "archive"
  | "git"
  | "key"
  | "package"
  | "shield-code"
  | "file-json"
  | "scale"
  | "git-branch"
  | "filter"
  | "regex"
  | "split"
  | "diff"
  | "sparkles"
  | "file-text"
  | "send"
  | "globe"
  | "mail"
  | "plug";

export interface NodeCategoryMeta {
  id: NodeFamily;
  label: string;
  shortLabel: string;
  purpose: string;
  flowmappPastel: string;
}

export interface SecretBindingRef {
  paramKey: string;
  secretRef: string;
}

export interface CanvasNodeTemplate {
  pluginId: string;
  family: NodeFamily;
  label: string;
  shortLabel: string;
  purposeTag: string;
  description: string;
  runtime: string;
  durationMs: number;
  iconKey: NodeIconKey;
  inputs: number;
  outputs: string[];
  requiredSecretKeys?: string[];
  optionalSecretKeys?: string[];
  defaultConfig: Record<string, string>;
  sampleOutput: Record<string, string | number | boolean | string[]>;
  isExternal?: boolean;
  sandboxProfile?: GqlSandboxProfile;
  paramsJsonSchema?: JsonSchemaObject;
  installationId?: string;
}

export type NodePluginHealth = "OK" | "PLUGIN_DISABLED" | "PLUGIN_UNREGISTERED";
export type CanvasNodeCatalogItem = CanvasNodeTemplate;

export type CanvasNodeRunStatus = "idle" | "running" | "succeeded" | "warning" | "failed";

export function getSwitchOutputPorts(mode?: string): string[] {
  return mode === "category"
    ? ["SECRET", "SAST", "SCA", "CLEAN"]
    : ["CRITICAL", "HIGH", "MEDIUM_LOW", "CLEAN"];
}

export function resolveNodeRunOutcome(
  pluginId: string,
  policyGate: PolicyVerdict = "PASS",
): {
  canvasStatus: "succeeded" | "warning" | "failed";
  stepStatus: "SUCCEEDED" | "WARNING" | "FAILED";
} {
  if (pluginId === "gate.policy") {
    if (policyGate === "FAIL") return { canvasStatus: "failed", stepStatus: "FAILED" };
    if (policyGate === "WARN") return { canvasStatus: "warning", stepStatus: "WARNING" };
    return { canvasStatus: "succeeded", stepStatus: "SUCCEEDED" };
  }
  if (policyGate === "FAIL") {
    if (pluginId === "scan.secrets" || pluginId === "scan.sast.kotlin") {
      return { canvasStatus: "failed", stepStatus: "FAILED" };
    }
    if (pluginId === "scan.sca") {
      return { canvasStatus: "warning", stepStatus: "WARNING" };
    }
  }
  if (policyGate === "WARN") {
    if (pluginId === "scan.sast.kotlin" || pluginId === "scan.sca") {
      return { canvasStatus: "warning", stepStatus: "WARNING" };
    }
  }
  return { canvasStatus: "succeeded", stepStatus: "SUCCEEDED" };
}

export interface CanvasBoardNodeData extends Record<string, unknown> {
  pluginId: string;
  family: NodeFamily;
  label: string;
  shortLabel: string;
  purposeTag: string;
  description: string;
  runtime: string;
  durationMs: number;
  iconKey: NodeIconKey;
  inputs: number;
  outputs: string[];
  requiredSecretKeys?: string[];
  optionalSecretKeys?: string[];
  secretBindings?: SecretBindingRef[];
  config: Record<string, string>;
  /** Typed node params. Config is the string form shown in the inspector. */
  params?: Record<string, unknown>;
  sampleOutput: Record<string, string | number | boolean | string[]>;
  runStatus: CanvasNodeRunStatus;
  findingsEmitted?: number;
  isExternal?: boolean;
  sandboxProfile?: GqlSandboxProfile;
  paramsJsonSchema?: JsonSchemaObject;
  installationId?: string;
  pluginHealth?: NodePluginHealth;
  /** Declarative Plugin unsaved draft or bound spec on canvas (ADR-0011). */
  declarativeSpec?: Record<string, unknown>;
  declarativeUnsaved?: boolean;
  declarativeDirty?: boolean;
  /** Saved Node binding for built-in/external Node deduplication. */
  savedNodeId?: string;
  savedCanonicalParams?: string;
}

export interface CanvasBoardNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: CanvasBoardNodeData;
}

export interface CanvasBoardEdge {
  id: string;
  source: string;
  target: string;
  sourceHandle?: string | null;
  targetHandle?: string | null;
  label?: string;
}

export const DND_NODE_MIME = "application/secflow-node-plugin";

export const NODE_CATEGORY_META: NodeCategoryMeta[] = [
  {
    id: "trigger",
    label: "Триггеры",
    shortLabel: "Триггер",
    purpose: "Точка старта графа: вручную, по расписанию или из Git Webhook",
    flowmappPastel: "#fff3c4",
  },
  {
    id: "source",
    label: "Источники кода",
    shortLabel: "Источник",
    purpose: "Загрузка ZIP-архива или allowlisted Git-репозитория в Garage S3",
    flowmappPastel: "#c8f0d8",
  },
  {
    id: "analyzer",
    label: "Анализаторы",
    shortLabel: "Анализ",
    purpose: "Собственные детерминированные сканеры Kotlin PSI, Go SCA и SBOM",
    flowmappPastel: "#ffd6e0",
  },
  {
    id: "logic",
    label: "Логика и Policy",
    shortLabel: "Логика",
    purpose: "Пороги Policy Gate, условные ветки If и фильтрация находок",
    flowmappPastel: "#ffe0c4",
  },
  {
    id: "ai",
    label: "AI и Отчёты",
    shortLabel: "AI / Отчёт",
    purpose: "Grounded AI Explain (0 выдуманных CVE) и экспорт submission.json",
    flowmappPastel: "#c5e0fb",
  },
  {
    id: "action",
    label: "Действия и MCP",
    shortLabel: "Действие",
    purpose: "Доставка в Telegram, CI Webhook, SMTP и Outbound MCP-инструменты",
    flowmappPastel: "#e0d4ff",
  },
];

export const CATEGORY_BY_ID: Record<NodeFamily, NodeCategoryMeta> = NODE_CATEGORY_META.reduce(
  (acc, item) => {
    acc[item.id] = item;
    return acc;
  },
  {} as Record<NodeFamily, NodeCategoryMeta>,
);

export const CANVAS_NODE_CATALOG: CanvasNodeTemplate[] = [
  {
    pluginId: "trigger.manual",
    family: "trigger",
    label: "Ручной запуск",
    shortLabel: "Manual",
    purposeTag: "Старт вручную",
    description: "Запускает прогон по кнопке из UI, API или MCP, выдаёт runId и открывает live-поток.",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 35,
    iconKey: "play",
    inputs: 0,
    outputs: ["out"],
    defaultConfig: {
      description: "",
    },
    sampleOutput: {
      runId: "run_9f4c2b81",
      trigger: "MANUAL",
      initiatedBy: "anna.sokolova@centrinvest.local",
    },
  },
  {
    pluginId: "trigger.webhook",
    family: "trigger",
    label: "Git Webhook",
    shortLabel: "Git Webhook",
    purposeTag: "Событие PR / Push",
    description: "Принимает входящий Webhook от GitHub/GitLab с проверкой HMAC-подписи.",
    runtime: "edge-gateway (Go 1.27)",
    durationMs: 42,
    iconKey: "webhook",
    inputs: 0,
    outputs: ["out"],
    requiredSecretKeys: ["webhookSecret"],
    optionalSecretKeys: ["gitStatusToken"],
    defaultConfig: {
      gitProvider: "GITHUB",
      events: "push, pull_request",
      branchFilter: "main",
      reportCommitStatus: "true",
      commitStatusContext: "secflow/security-gate",
    },
    sampleOutput: {
      event: "pull_request",
      branch: "feat/checkout-api",
      commitSha: "4a9e1c7b",
    },
  },
  {
    pluginId: "trigger.schedule",
    family: "trigger",
    label: "Расписание (Cron)",
    shortLabel: "Schedule",
    purposeTag: "Ночной / недельный",
    description: "Регламентный запуск по cron-выражению в заданном часовом поясе.",
    runtime: "orchestrator-cron (Go 1.27)",
    durationMs: 28,
    iconKey: "clock",
    inputs: 0,
    outputs: ["out"],
    defaultConfig: {
      cron: "0 3 * * *",
      timezone: "UTC",
      enabled: "true",
    },
    sampleOutput: {
      schedule: "0 3 * * *",
      firedAt: "03:00:00 UTC",
      queueSlot: "nightly-01",
    },
  },
  {
    pluginId: "source.upload",
    family: "source",
    label: "Source ZIP-архив",
    shortLabel: "Source ZIP",
    purposeTag: "Загрузка архива",
    description: "Принимает ZIP-снапшот проекта в S3 Garage 2.5 и индексирует Kotlin/Gradle/YAML.",
    runtime: "source-ingester → Garage 2.5",
    durationMs: 180,
    iconKey: "archive",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      sourceId: "",
    },
    sampleOutput: {
      sourceRef: "s3://secflow-sources/repair-desk-main.tar.gz",
      filesIndexed: 34,
      languages: ["kotlin", "gradle-kts", "yaml"],
    },
  },
  {
    pluginId: "source.git",
    family: "source",
    label: "Source Git-репозиторий",
    shortLabel: "Source Git",
    purposeTag: "Клон allowlist",
    description: "Выгружает учебный репозиторий из allowlist по ветке или коммиту без запуска кода.",
    runtime: "source-ingester → Garage 2.5",
    durationMs: 220,
    iconKey: "git",
    inputs: 1,
    outputs: ["out"],
    optionalSecretKeys: ["gitToken"],
    defaultConfig: {
      repoUrl: "https://github.com/TBagirov/training",
      gitRef: "main",
    },
    sampleOutput: {
      repoUrl: "https://github.com/TBagirov/training",
      allowlisted: true,
      filesIndexed: 34,
    },
  },
  {
    pluginId: "scan.secrets",
    family: "analyzer",
    label: "Secrets Scanner (PSI + YAML)",
    shortLabel: "Secrets",
    purposeTag: "Поиск утечек",
    description: "Собственный детерминированный разбор паролей, API-ключей, env-fallback и склеенных токенов.",
    runtime: "worker-kotlin (JDK 21)",
    durationMs: 410,
    iconKey: "key",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      includePaths: "",
      excludePaths: "",
    },
    sampleOutput: {
      findingsCount: 5,
      controlsIgnored: 2,
      masked: true,
      findingIds: ["A-SEC-01", "A-SEC-02", "A-SEC-03", "A-SEC-04", "A-SEC-05"],
    },
  },
  {
    pluginId: "scan.sca",
    family: "analyzer",
    label: "SCA Gradle (Go)",
    shortLabel: "SCA Gradle",
    purposeTag: "Уязвимые пакеты",
    description: "Собственный Go-парсер build.gradle.kts, $var и gradle.lockfile по базе CVE/GHSA.",
    runtime: "worker-sca (Go 1.27)",
    durationMs: 290,
    iconKey: "package",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      catalogId: "default",
    },
    sampleOutput: {
      findingsCount: 5,
      controlsIgnored: 1,
      advisories: ["CVE-2022-42889", "CVE-2024-25710", "CVE-2023-5072"],
    },
  },
  {
    pluginId: "scan.sast.kotlin",
    family: "analyzer",
    label: "SAST Kotlin / Spring (PSI)",
    shortLabel: "SAST Kotlin",
    purposeTag: "Анализ AST кода",
    description: "Дерево Kotlin PSI: SQLi, отключённый TLS verifier, CORS+credentials, permitAll, IDOR.",
    runtime: "worker-kotlin (Kotlin 2.2 PSI)",
    durationMs: 540,
    iconKey: "shield-code",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      enabledRules:
        "sql-injection, tls-verification, credentialed-cors, route-authorization, object-authorization",
    },
    sampleOutput: {
      findingsCount: 5,
      controlsIgnored: 3,
      findingIds: ["A-SAST-01", "A-SAST-02", "A-SAST-03", "A-SAST-04", "A-SAST-05"],
    },
  },
  {
    pluginId: "sbom.generate",
    family: "analyzer",
    label: "SBOM CycloneDX 1.6",
    shortLabel: "SBOM CDX 1.6",
    purposeTag: "Инвентарь пакетов",
    description: "Генерирует граф зависимостей и лицензий в формате CycloneDX 1.6 JSON.",
    runtime: "sbom-service (Go 1.27)",
    durationMs: 165,
    iconKey: "file-json",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      includeDevDependencies: "false",
    },
    sampleOutput: {
      format: "CycloneDX-1.6-JSON",
      componentsCount: 42,
      sha256: "8e1c4a9b...f02d",
    },
  },
  {
    pluginId: "gate.policy",
    family: "logic",
    label: "Policy Gate",
    shortLabel: "Policy Gate",
    purposeTag: "Порог релиза",
    description: "Сверяет найденные риски с порогом severity и направляет поток в ветки PASS / WARN / FAIL.",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 18,
    iconKey: "scale",
    inputs: 1,
    outputs: ["PASS", "WARN", "FAIL"],
    defaultConfig: {
      failOnSeverity: "HIGH",
      warnOnSeverity: "MEDIUM",
      failOnAnySecret: "true",
      maxAllowedFindings: "",
      onlyNewVsBaseline: "false",
    },
    sampleOutput: {
      verdict: "FAIL",
      criticalCount: 4,
      highCount: 10,
      branch: "FAIL",
    },
  },
  {
    pluginId: "logic.if",
    family: "logic",
    label: "Условие If",
    shortLabel: "If",
    purposeTag: "Ветвление потока",
    description: "Проверяет правила над Envelope (например, stats.total > 0) и разделяет маршрут на true / false.",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 12,
    iconKey: "git-branch",
    inputs: 1,
    outputs: ["true", "false"],
    defaultConfig: {
      combinator: "AND",
      conditions: JSON.stringify([{ field: "stats.total", operator: "gt", value: 0 }]),
    },
    sampleOutput: {
      evaluated: true,
      branch: "true",
      matchedCount: 15,
    },
  },
  {
    pluginId: "logic.filter",
    family: "logic",
    label: "Фильтр находок",
    shortLabel: "Filter",
    purposeTag: "Отбор по риску",
    description: "Оставляет в локальном Envelope только находки выбранной серьёзности или категории.",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 14,
    iconKey: "filter",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      categories: "SECRET, SCA, SAST",
      minSeverity: "HIGH",
      onlyNewVsBaseline: "false",
      findingClasses: "",
      pathPrefixes: "",
    },
    sampleOutput: {
      inputCount: 15,
      passedCount: 14,
      filteredOut: 1,
    },
  },
  {
    pluginId: "logic.regex",
    family: "logic",
    label: "Regex-фильтр путей",
    shortLabel: "Regex",
    purposeTag: "Разделение по RE2",
    description: "Отбирает или разделяет находки в ветки match / nomatch по RE2-выражению над полем находки.",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 11,
    iconKey: "regex",
    inputs: 1,
    outputs: ["match", "nomatch"],
    defaultConfig: {
      field: "path",
      pattern: "^src/main/",
      splitEnvelope: "true",
    },
    sampleOutput: {
      matchedCount: 5,
      excludedCount: 2,
      pattern: "^src/main/",
    },
  },
  {
    pluginId: "logic.switch",
    family: "logic",
    label: "Маршрутизатор Switch",
    shortLabel: "Switch",
    purposeTag: "Ветвление по риску",
    description: "Направляет Envelope по maxSeverity (CRITICAL/HIGH/MEDIUM_LOW/CLEAN) или по category (SECRET/SAST/SCA/CLEAN).",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 14,
    iconKey: "split",
    inputs: 1,
    outputs: ["CRITICAL", "HIGH", "MEDIUM_LOW", "CLEAN"],
    defaultConfig: {
      mode: "maxSeverity",
    },
    sampleOutput: {
      maxSeverity: "CRITICAL",
      selectedBranch: "CRITICAL",
      findingsCount: 15,
    },
  },
  {
    pluginId: "logic.merge",
    family: "logic",
    label: "Свести находки",
    shortLabel: "Merge",
    purposeTag: "Сведение веток",
    description: "Собирает находки нескольких анализаторов в один конверт с дедупликацией по fingerprint.",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 8,
    iconKey: "git-branch",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      deduplicateByFingerprint: "true",
    },
    sampleOutput: {
      mergedBranches: 3,
    },
  },
  {
    pluginId: "logic.compare",
    family: "logic",
    label: "Сравнение с Baseline",
    shortLabel: "Baseline Diff",
    purposeTag: "Только новые риски",
    description: "Сравнивает текущий прогон с предыдущим baseline или порогом и маршрутизирует в true / false.",
    runtime: "orchestrator (Go 1.27)",
    durationMs: 22,
    iconKey: "diff",
    inputs: 1,
    outputs: ["true", "false"],
    defaultConfig: {
      mode: "baselineDiff",
      baselineScope: "previous_succeeded_run",
      minNewFindingsForTrue: "1",
      minSeverity: "",
    },
    sampleOutput: {
      baselineFindings: 14,
      currentFindings: 15,
      newFindingsCount: 1,
    },
  },
  {
    pluginId: "ai.explain",
    family: "ai",
    label: "AI Explain (Grounded)",
    shortLabel: "AI Explain",
    purposeTag: "Объяснение рисков",
    description: "Объясняет только подтверждённые findingId и предлагает фикс. Строгий JSON Schema + grounding.",
    runtime: "ai-service (Cloud / Ollama)",
    durationMs: 1080,
    iconKey: "sparkles",
    inputs: 1,
    outputs: ["out"],
    optionalSecretKeys: ["llmApiKey"],
    defaultConfig: {
      privacyMode: "REDACTED_SNIPPET",
      locale: "ru",
      maxFindings: "50",
      baseUrl: "",
      model: "",
    },
    sampleOutput: {
      groundedFindings: 15,
      hallucinatedCveBlocked: 0,
      schemaValid: true,
    },
  },
  {
    pluginId: "report.export",
    family: "ai",
    label: "Экспорт отчёта",
    shortLabel: "Report Export",
    purposeTag: "submission.json + MD",
    description: "Формирует обязательный submission.json (UTF-8) и читаемый Markdown/HTML отчёт.",
    runtime: "orchestrator → Garage 2.5",
    durationMs: 95,
    iconKey: "file-text",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      title: "onlyscans Security Report",
      notes: "",
      formats: "MARKDOWN, HTML",
    },
    sampleOutput: {
      artifacts: ["submission.json", "report.md", "report.html"],
      findingsExported: 15,
      parityVerified: true,
    },
  },
  {
    pluginId: "notify.telegram",
    family: "action",
    label: "Telegram-уведомление",
    shortLabel: "Telegram",
    purposeTag: "Алерт в чат",
    description: "Отправляет структурированную сводку вердикта Policy Gate и топ-находок в Telegram.",
    runtime: "notify-service (Go 1.27)",
    durationMs: 210,
    iconKey: "send",
    inputs: 1,
    outputs: ["out"],
    requiredSecretKeys: ["botToken"],
    defaultConfig: {
      chatId: "@appsec-alerts-team",
      messageTemplate: "",
    },
    sampleOutput: {
      channel: "telegram",
      delivered: true,
      messageId: "tg_84712",
    },
  },
  {
    pluginId: "notify.webhook",
    family: "action",
    label: "HTTP / CI Webhook",
    shortLabel: "CI Webhook",
    purposeTag: "Статус в CI/CD",
    description: "Отправляет JSON-отчёт с HMAC-подписью на внешний endpoint или в Webhook Inspector.",
    runtime: "notify-service (Go 1.27)",
    durationMs: 175,
    iconKey: "globe",
    inputs: 1,
    outputs: ["out"],
    optionalSecretKeys: ["hmacSecret"],
    defaultConfig: {
      url: "http://edge-gateway:8080/webhooks/inspector/demo",
      bodyTemplate: "",
    },
    sampleOutput: {
      httpStatus: 200,
      delivered: true,
      commitStatus: "failure",
    },
  },
  {
    pluginId: "notify.smtp",
    family: "action",
    label: "Email (SMTP)",
    shortLabel: "SMTP Email",
    purposeTag: "Письмо с отчётом",
    description: "Рассылает сводку безопасности по списку получателей через SMTP.",
    runtime: "notify-service (Go 1.27)",
    durationMs: 260,
    iconKey: "mail",
    inputs: 1,
    outputs: ["out"],
    requiredSecretKeys: ["smtpPassword"],
    defaultConfig: {
      to: "sec-team@secflow.local",
      subject: "[onlyscans] Отчёт безопасности",
      bodyTemplate: "",
      smtpAddr: "",
      smtpUser: "",
      smtpFrom: "",
    },
    sampleOutput: {
      channel: "smtp",
      delivered: true,
      recipientsCount: 1,
    },
  },
  {
    pluginId: "mcp.tool",
    family: "action",
    label: "MCP Tool Node",
    shortLabel: "MCP Tool",
    purposeTag: "Тикеты через MCP",
    description: "Вызывает инструмент зарегистрированного MCP-подключения по подтверждённым findingId.",
    runtime: "orchestrator-mcp (Go 1.27)",
    durationMs: 310,
    iconKey: "plug",
    inputs: 1,
    outputs: ["out"],
    defaultConfig: {
      connectionId: "",
      toolName: "",
      arguments: "{}",
      outputVarKey: "mcpToolResult",
    },
    sampleOutput: {
      mcpConnection: "tracker-mcp-internal",
      issuesCreated: 2,
      groundedOnly: true,
    },
  },
];

export const TEMPLATE_BY_PLUGIN_ID: Record<string, CanvasNodeTemplate> = CANVAS_NODE_CATALOG.reduce(
  (acc, tpl) => {
    acc[tpl.pluginId] = tpl;
    return acc;
  },
  {} as Record<string, CanvasNodeTemplate>,
);

export function createCanvasNodeFromTemplate(
  tpl: CanvasNodeTemplate,
  position: { x: number; y: number },
  customId?: string,
  overrideLabel?: string,
): CanvasBoardNode {
  const id =
    customId ??
    `${tpl.pluginId.replace(/\./g, "-")}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`;
  return {
    id,
    type: "secflowNode",
    position,
    data: {
      pluginId: tpl.pluginId,
      family: tpl.family,
      label: overrideLabel ?? tpl.label,
      shortLabel: tpl.shortLabel,
      purposeTag: tpl.purposeTag,
      description: tpl.description,
      runtime: tpl.runtime,
      durationMs: tpl.durationMs,
      iconKey: tpl.iconKey,
      inputs: tpl.inputs,
      outputs: [...tpl.outputs],
      requiredSecretKeys: tpl.requiredSecretKeys ? [...tpl.requiredSecretKeys] : [],
      optionalSecretKeys: tpl.optionalSecretKeys ? [...tpl.optionalSecretKeys] : [],
      secretBindings: [],
      config: { ...tpl.defaultConfig },
      sampleOutput: { ...tpl.sampleOutput },
      runStatus: "idle",
      isExternal: tpl.isExternal,
      sandboxProfile: tpl.sandboxProfile,
      paramsJsonSchema: tpl.paramsJsonSchema,
      installationId: tpl.installationId,
    },
  };
}

export function buildGraphFromWorkflow(wf: WorkflowRecord): {
  nodes: CanvasBoardNode[];
  edges: CanvasBoardEdge[];
} {
  if (wf.nodes.length === 0) {
    const startTpl = TEMPLATE_BY_PLUGIN_ID["trigger.manual"];
    return {
      nodes: [createCanvasNodeFromTemplate(startTpl, { x: 80, y: 180 }, `${wf.id}-n1`)],
      edges: [],
    };
  }

  // Group into n8n-style horizontal columns: trigger -> source -> analyzers (stacked) -> logic -> ai -> action
  const stageOrder: NodeFamily[] = ["trigger", "source", "analyzer", "logic", "ai", "action"];
  const grouped = new Map<NodeFamily, typeof wf.nodes>();
  for (const fam of stageOrder) {
    grouped.set(fam, []);
  }
  for (const chip of wf.nodes) {
    const bucket = grouped.get(chip.family) ?? [];
    bucket.push(chip);
    grouped.set(chip.family, bucket);
  }

  const activeStages = stageOrder.filter((fam) => (grouped.get(fam)?.length ?? 0) > 0);
  const nodes: CanvasBoardNode[] = [];
  const stageNodeIds: string[][] = [];
  const colSpacing = 290;
  const rowSpacing = 148;
  const centerY = 210;

  activeStages.forEach((fam, colIdx) => {
    const items = grouped.get(fam) ?? [];
    const totalHeight = (items.length - 1) * rowSpacing;
    const startY = Math.max(48, Math.round(centerY - totalHeight / 2));
    const colIds: string[] = [];

    items.forEach((chip, rowIdx) => {
      const tpl =
        TEMPLATE_BY_PLUGIN_ID[chip.pluginId] ??
        CANVAS_NODE_CATALOG.find((item) => item.family === chip.family) ??
        CANVAS_NODE_CATALOG[0];
      const nodeId = `${wf.id}-${chip.id}`;
      colIds.push(nodeId);
      nodes.push(
        createCanvasNodeFromTemplate(
          tpl,
          { x: 64 + colIdx * colSpacing, y: startY + rowIdx * rowSpacing },
          nodeId,
          chip.label.length > tpl.shortLabel.length ? chip.label : tpl.label,
        ),
      );
    });
    stageNodeIds.push(colIds);
  });

  const edges: CanvasBoardEdge[] = [];
  for (let i = 0; i < stageNodeIds.length - 1; i++) {
    const fromIds = stageNodeIds[i];
    const toIds = stageNodeIds[i + 1];
    for (const src of fromIds) {
      const srcNode = nodes.find((n) => n.id === src);
      const isBranch = (srcNode?.data.outputs.length ?? 1) > 1;
      for (const tgt of toIds) {
        const branchHandle =
          srcNode?.data.pluginId === "gate.policy"
            ? "FAIL"
            : srcNode?.data.outputs[0] ?? "out";
        edges.push({
          id: `e-${src}-${tgt}`,
          source: src,
          target: tgt,
          sourceHandle: isBranch ? branchHandle : "out",
          targetHandle: "in",
          label: isBranch ? branchHandle : undefined,
        });
      }
    }
  }

  return { nodes, edges };
}

export function autoLayoutBoard(
  nodes: CanvasBoardNode[],
  edges: CanvasBoardEdge[],
): CanvasBoardNode[] {
  if (nodes.length === 0) return nodes;
  const inDegree = new Map<string, number>();
  const adj = new Map<string, string[]>();
  for (const n of nodes) {
    inDegree.set(n.id, 0);
    adj.set(n.id, []);
  }
  for (const e of edges) {
    if (adj.has(e.source) && inDegree.has(e.target)) {
      adj.get(e.source)!.push(e.target);
      inDegree.set(e.target, (inDegree.get(e.target) ?? 0) + 1);
    }
  }

  const level = new Map<string, number>();
  const queue: string[] = [];
  for (const n of nodes) {
    if ((inDegree.get(n.id) ?? 0) === 0) {
      level.set(n.id, 0);
      queue.push(n.id);
    }
  }

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const currLvl = level.get(curr) ?? 0;
    for (const next of adj.get(curr) ?? []) {
      const prevLvl = level.get(next) ?? 0;
      if (currLvl + 1 > prevLvl) {
        level.set(next, currLvl + 1);
      }
      const rem = (inDegree.get(next) ?? 1) - 1;
      inDegree.set(next, rem);
      if (rem <= 0) {
        queue.push(next);
      }
    }
  }

  // Fallback for cyclic or disconnected nodes
  const familyFallback: Record<NodeFamily, number> = {
    trigger: 0,
    source: 1,
    analyzer: 2,
    logic: 3,
    ai: 4,
    action: 5,
  };
  const cols = new Map<number, CanvasBoardNode[]>();
  for (const n of nodes) {
    const col = level.has(n.id) ? level.get(n.id)! : familyFallback[n.data.family] ?? 0;
    const list = cols.get(col) ?? [];
    list.push(n);
    cols.set(col, list);
  }

  const sortedColKeys = Array.from(cols.keys()).sort((a, b) => a - b);
  const posMap = new Map<string, { x: number; y: number }>();
  const colSpacing = 316;
  const rowSpacing = 168;
  const centerY = 210;

  sortedColKeys.forEach((colKey, visualColIdx) => {
    const items = cols.get(colKey) ?? [];
    const totalHeight = (items.length - 1) * rowSpacing;
    const startY = Math.max(48, Math.round(centerY - totalHeight / 2));
    items.forEach((item, idx) => {
      posMap.set(item.id, {
        x: 64 + visualColIdx * colSpacing,
        y: startY + idx * rowSpacing,
      });
    });
  });

  return nodes.map((n) => ({
    ...n,
    position: posMap.get(n.id) ?? n.position,
  }));
}

const SANITIZED_CONFIG_KEYS = new Set([
  "sourceId",
  "repoUrl",
  "chatId",
  "url",
  "to",
  "connectionId",
]);

export function sanitizeNodeConfigForTemplate(
  config: Record<string, string>,
): Record<string, string> {
  const next: Record<string, string> = {};
  for (const [key, value] of Object.entries(config)) {
    next[key] = SANITIZED_CONFIG_KEYS.has(key) ? "<указать на канвасе>" : value;
  }
  return next;
}

export function buildGraphFromTemplate(
  tpl: StarterTemplateRecord,
  idPrefix = tpl.id,
  options?: { sanitized?: boolean },
): {
  nodes: CanvasBoardNode[];
  edges: CanvasBoardEdge[];
} {
  const shouldSanitize = options?.sanitized ?? false;

  if (!tpl.edges || tpl.edges.length === 0) {
    const built = buildGraphFromWorkflow({
      id: idPrefix,
      name: tpl.name,
      description: tpl.description,
      trigger: tpl.trigger,
      triggerDetail: tpl.trigger,
      lastRunId: "—",
      lastRunStatus: "NONE",
      policyGate: "PASS",
      critCount: 0,
      highCount: 0,
      mediumCount: 0,
      updatedAt: "—",
      updatedSortOrder: 0,
      sourceLabel: "",
      durationLabel: "—",
      sbomComponents: 0,
      nodes: tpl.nodes,
      highlights: [],
    });
    if (!shouldSanitize) return built;
    return {
      nodes: built.nodes.map((node) => ({
        ...node,
        data: {
          ...node.data,
          config: sanitizeNodeConfigForTemplate(node.data.config),
        },
      })),
      edges: built.edges,
    };
  }

  const nodeIdMap = new Map<string, string>();
  const rawNodes: CanvasBoardNode[] = tpl.nodes.map((chip, idx) => {
    const nodeTpl =
      TEMPLATE_BY_PLUGIN_ID[chip.pluginId] ??
      CANVAS_NODE_CATALOG.find((item) => item.family === chip.family) ??
      CANVAS_NODE_CATALOG[0];
    const mappedId = `${idPrefix}-${chip.id}`;
    nodeIdMap.set(chip.id, mappedId);
    const created = createCanvasNodeFromTemplate(
      nodeTpl,
      { x: 64 + idx * 240, y: 180 },
      mappedId,
      chip.label,
    );
    if (shouldSanitize) {
      created.data.config = sanitizeNodeConfigForTemplate(created.data.config);
    }
    return created;
  });

  const nodeById = new Map(rawNodes.map((n) => [n.id, n]));
  const edges: CanvasBoardEdge[] = tpl.edges
    .map((edge, idx) => {
      const source = nodeIdMap.get(edge.source);
      const target = nodeIdMap.get(edge.target);
      if (!source || !target) return null;
      const srcNode = nodeById.get(source);
      const sourceHandle = edge.sourceHandle ?? srcNode?.data.outputs[0] ?? "out";
      return {
        id: `e-${source}-${target}-${idx}`,
        source,
        target,
        sourceHandle,
        targetHandle: "in",
        label: edge.label,
      } as CanvasBoardEdge;
    })
    .filter((item): item is CanvasBoardEdge => item !== null);

  const laidOutNodes = autoLayoutBoard(rawNodes, edges);
  return { nodes: laidOutNodes, edges };
}
