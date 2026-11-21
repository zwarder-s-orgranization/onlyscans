export type UserRole = "owner" | "editor" | "viewer";
export type TriggerKind = "Manual" | "Schedule" | "Webhook" | "CI API" | "MCP" | "Rerun";
export type RunStatus = "SUCCEEDED" | "FAILED" | "RUNNING" | "QUEUED" | "CANCELLED" | "NONE";
export type PolicyVerdict = "PASS" | "WARN" | "FAIL" | "NONE";

export type NodeFamily = "trigger" | "source" | "analyzer" | "logic" | "ai" | "action";

export interface WorkflowNodeChip {
  id: string;
  family: NodeFamily;
  pluginId: string;
  label: string;
}

export interface RunSbomInfo {
  digest: string;
  specVersion: string;
  componentCount: number;
  vulnerabilityCount: number;
  downloadUrl: string;
  generatedAt: string;
  format?: string;
  s3Key?: string;
}

export interface RunFindingsStats {
  total: number;
  newCount: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  secretCount: number;
  sastCount: number;
  scaCount: number;
  maxSeverity?: string | null;
}

export interface RunAIReportGroup {
  title: string;
  maxSeverity: string;
  findingIds: string[];
  summary: string;
}

export interface RunAIReportGroundedFinding {
  category: string;
  path: string;
  line?: number | null;
  endLine?: number | null;
  findingClass?: string | null;
  group?: string | null;
  artifact?: string | null;
  version?: string | null;
  advisoryId?: string | null;
  severity?: string | null;
}

export interface RunAIReportItem {
  findingId: string;
  priorityRank: number;
  plainLanguageRisk: string;
  businessImpact: string;
  remediationSteps: string[];
  referencedAdvisories: string[];
  finding: RunAIReportGroundedFinding;
}

export interface RunAIReportInfo {
  quality: "VERIFIED" | "DEGRADED" | "FALLBACK";
  releaseDecision: "PASS" | "WARN" | "BLOCK";
  executiveSummary: string;
  groups: RunAIReportGroup[];
  items: RunAIReportItem[];
  modelId: string;
  providerMode: string;
  privacyMode: string;
  strippedHallucinatedAdvisories: number;
  cached: boolean;
  promptHash?: string;
  tokensIn?: number;
  tokensOut?: number;
  latencyMs?: number;
  createdAt?: string;
}

export interface WorkflowRunStep {
  id: string;
  nodeRunId?: string;
  nodeId?: string;
  nodeLabel: string;
  pluginId: string;
  family: NodeFamily;
  status: "IDLE" | "SUCCEEDED" | "WARNING" | "FAILED" | "RUNNING";
  durationMs: number;
  summary: string;
  activeOutputPorts?: string[];
  redactedPreview?: unknown;
  findingsEmitted?: number;
}

export interface WorkflowRunRecord {
  id: string;
  workflowId: string;
  workflowName: string;
  trigger: TriggerKind;
  status: RunStatus;
  policyGate: PolicyVerdict;
  startedAt: string;
  durationLabel: string;
  sourceLabel: string;
  initiatedBy: string;
  critCount: number;
  highCount: number;
  mediumCount: number;
  lowCount?: number;
  nodesCount: number;
  wavesCount: number;
  steps: WorkflowRunStep[];
  findingsStats?: RunFindingsStats;
  sbom?: RunSbomInfo | null;
  aiReport?: RunAIReportInfo | null;
  submissionDownloadUrl?: string;
  markdownReportDownloadUrl?: string;
  htmlReportDownloadUrl?: string;
  parentRunId?: string | null;
  rerunFromNodeId?: string | null;
  errorMessage?: string | null;
  lastSeqId?: number;
}

export interface WorkflowRecord {
  id: string;
  name: string;
  description: string;
  trigger: TriggerKind;
  triggerDetail: string;
  lastRunId: string;
  lastRunStatus: RunStatus;
  policyGate: PolicyVerdict;
  critCount: number;
  highCount: number;
  mediumCount: number;
  updatedAt: string;
  updatedSortOrder: number;
  sourceLabel: string;
  durationLabel: string;
  sbomComponents: number;
  nodes: WorkflowNodeChip[];
  highlights: string[];
}

export type TemplateCategory = "benchmark" | "gate" | "ci-cd" | "secrets" | "sca-sbom";

export interface TemplateEdgeSpec {
  source: string;
  target: string;
  sourceHandle?: string;
  label?: string;
}

export interface TemplateRequiredParam {
  node: string;
  field: string;
  hint: string;
}

export interface StarterTemplateRecord {
  id: string;
  slug: string;
  name: string;
  description: string;
  problemSolved: string;
  trigger: TriggerKind;
  category: TemplateCategory;
  tags: string[];
  isBuiltin: boolean;
  authorSubject: string;
  cloneCount: number;
  createdAt: string;
  nodes: WorkflowNodeChip[];
  edges?: TemplateEdgeSpec[];
  boardGraph?: {
    nodes: import("./canvas-nodes-catalog").CanvasBoardNode[];
    edges: import("./canvas-nodes-catalog").CanvasBoardEdge[];
  };
  requiredParams: TemplateRequiredParam[];
  featured?: boolean;
}

export interface TextToWorkflowPreset {
  id: string;
  label: string;
  prompt: string;
  generatedName: string;
  generatedDescription: string;
  trigger: TriggerKind;
  triggerDetail: string;
  nodes: WorkflowNodeChip[];
  missingFields: {
    node: string;
    field: string;
    hint: string;
  }[];
}

export interface WorkspaceVariantMeta {
  id: string;
  slug: string;
  system: "subframe" | "flowmapp";
  systemLabel: string;
  indexInSystem: number;
  globalNumber: string;
  name: string;
  layoutKind: string;
  summary: string;
  palette: [string, string, string, string];
}

export const INITIAL_WORKFLOWS: WorkflowRecord[] = [
  {
    id: "wf-repair-desk-audit",
    name: "Repair Desk — Полный аудит безопасности",
    description:
      "Детерминированный разбор Kotlin PSI (Secrets + SAST), Go SCA по Gradle, CycloneDX 1.6 SBOM и grounded AI Explain.",
    trigger: "Manual",
    triggerDetail: "Ручной запуск · ZIP / Git",
    lastRunId: "run_9f4c2b81",
    lastRunStatus: "FAILED",
    policyGate: "FAIL",
    critCount: 4,
    highCount: 10,
    mediumCount: 1,
    updatedAt: "12 мин назад",
    updatedSortOrder: 1,
    sourceLabel: "repair-desk-main.zip",
    durationLabel: "2.4 с",
    sbomComponents: 42,
    nodes: [
      { id: "n1", family: "trigger", pluginId: "trigger.manual", label: "Manual" },
      { id: "n2", family: "source", pluginId: "source.upload", label: "Source ZIP" },
      { id: "n3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets" },
      { id: "n4", family: "analyzer", pluginId: "scan.sca", label: "SCA + SBOM" },
      { id: "n5", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST Kotlin" },
      { id: "n6", family: "logic", pluginId: "gate.policy", label: "Policy Gate" },
      { id: "n7", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "n8", family: "action", pluginId: "notify.telegram", label: "Telegram" },
    ],
    highlights: [
      "A-SAST-01 · SQLi в RepairLookupController.kt:13–14",
      "A-SCA-01 · CVE-2022-42889 (commons-text:1.9)",
      "A-SEC-05 · Составной токен в WarrantyHeaders.kt:7–10",
    ],
  },
  {
    id: "wf-pr-security-gate",
    name: "CI/CD Gate для Pull Request",
    description:
      "Входящий Git Webhook проверяет SAST и утечки секретов, блокирует merge при CRITICAL и публикует статус коммита.",
    trigger: "Webhook",
    triggerDetail: "POST /webhooks/git/wf-pr-security-gate",
    lastRunId: "run_7e12a09d",
    lastRunStatus: "SUCCEEDED",
    policyGate: "WARN",
    critCount: 0,
    highCount: 2,
    mediumCount: 3,
    updatedAt: "48 мин назад",
    updatedSortOrder: 2,
    sourceLabel: "git: feat/checkout-api @ 4a9e1c",
    durationLabel: "1.8 с",
    sbomComponents: 28,
    nodes: [
      { id: "n1", family: "trigger", pluginId: "trigger.webhook", label: "Git Webhook" },
      { id: "n2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "n3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets" },
      { id: "n4", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST Kotlin" },
      { id: "n5", family: "logic", pluginId: "gate.policy", label: "Policy Gate" },
      { id: "n6", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "n7", family: "action", pluginId: "notify.webhook", label: "CI Webhook" },
    ],
    highlights: [
      "A-SAST-03 · Открытый CORS (*) с credentials",
      "A-SAST-02 · Отключена проверка hostname TLS",
    ],
  },
  {
    id: "wf-nightly-sca-sbom",
    name: "Ночной SCA + CycloneDX 1.6 SBOM",
    description:
      "Ежедневный аудит build.gradle.kts и gradle.lockfile по версионируемому каталогу CVE/GHSA с выгрузкой SBOM и отчёта.",
    trigger: "Schedule",
    triggerDetail: "Cron 0 3 * * * (03:00 MSK)",
    lastRunId: "run_5b81c440",
    lastRunStatus: "SUCCEEDED",
    policyGate: "FAIL",
    critCount: 1,
    highCount: 3,
    mediumCount: 1,
    updatedAt: "Сегодня, 03:00",
    updatedSortOrder: 3,
    sourceLabel: "git: main @ 9c3f01",
    durationLabel: "1.1 с",
    sbomComponents: 67,
    nodes: [
      { id: "n1", family: "trigger", pluginId: "trigger.schedule", label: "Schedule" },
      { id: "n2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "n3", family: "analyzer", pluginId: "scan.sca", label: "SCA Gradle" },
      { id: "n4", family: "analyzer", pluginId: "sbom.generate", label: "SBOM CDX 1.6" },
      { id: "n5", family: "logic", pluginId: "gate.policy", label: "Policy Gate" },
      { id: "n6", family: "ai", pluginId: "report.export", label: "Export MD" },
      { id: "n7", family: "action", pluginId: "notify.smtp", label: "SMTP" },
    ],
    highlights: [
      "CVE-2022-42889 · org.apache.commons:commons-text:1.9",
      "CVE-2024-25710 · commons-compress:1.25.0 ($compressVersion)",
    ],
  },
  {
    id: "wf-secrets-premerge",
    name: "Ловушка утечек секретов (Pre-merge)",
    description:
      "Быстрая проверка паролей, X-Api-Key, Bearer в application.yml, env-fallback и конкатенации строковых фрагментов.",
    trigger: "Webhook",
    triggerDetail: "GitLab Push Hook · branch: release/*",
    lastRunId: "run_3a04d218",
    lastRunStatus: "SUCCEEDED",
    policyGate: "PASS",
    critCount: 0,
    highCount: 0,
    mediumCount: 0,
    updatedAt: "3 ч назад",
    updatedSortOrder: 4,
    sourceLabel: "git: release/2.4 @ d18a77",
    durationLabel: "0.7 с",
    sbomComponents: 19,
    nodes: [
      { id: "n1", family: "trigger", pluginId: "trigger.webhook", label: "Webhook" },
      { id: "n2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "n3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets PSI" },
      { id: "n4", family: "logic", pluginId: "logic.if", label: "If > 0" },
      { id: "n5", family: "action", pluginId: "notify.telegram", label: "Telegram" },
    ],
    highlights: ["Утечек не обнаружено · 2 безопасных контроля подтверждены (0 FP)"],
  },
  {
    id: "wf-release-mcp-bridge",
    name: "Релизный контроль + MCP тикетинг",
    description:
      "Полный прогон релизной ветки с проверкой Policy Gate и передачей подтверждённых findingId во внешний MCP-сервер трекера.",
    trigger: "Manual",
    triggerDetail: "Ручной запуск перед релизом",
    lastRunId: "run_1c90f671",
    lastRunStatus: "SUCCEEDED",
    policyGate: "PASS",
    critCount: 0,
    highCount: 0,
    mediumCount: 2,
    updatedAt: "Вчера, 19:40",
    updatedSortOrder: 5,
    sourceLabel: "git: tag v1.12.0",
    durationLabel: "3.1 с",
    sbomComponents: 54,
    nodes: [
      { id: "n1", family: "trigger", pluginId: "trigger.manual", label: "Manual" },
      { id: "n2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "n3", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST + SCA" },
      { id: "n4", family: "logic", pluginId: "gate.policy", label: "Policy Gate" },
      { id: "n5", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "n6", family: "action", pluginId: "mcp.tool", label: "MCP Tool" },
    ],
    highlights: ["Релиз одобрен Policy Gate · 2 минорных замечания отправлены через MCP"],
  },
  {
    id: "wf-sandbox-kotlin-weekly",
    name: "Еженедельный аудит учебного стенда",
    description:
      "Регламентная проверка песочницы с выгрузкой submission.json, HTML-отчёта и проверкой доставки в Webhook Inspector.",
    trigger: "Schedule",
    triggerDetail: "Каждый понедельник, 09:00 MSK",
    lastRunId: "run_0f23b114",
    lastRunStatus: "QUEUED",
    policyGate: "WARN",
    critCount: 0,
    highCount: 1,
    mediumCount: 2,
    updatedAt: "2 дня назад",
    updatedSortOrder: 6,
    sourceLabel: "sandbox-kotlin-demo.zip",
    durationLabel: "1.5 с",
    sbomComponents: 31,
    nodes: [
      { id: "n1", family: "trigger", pluginId: "trigger.schedule", label: "Schedule" },
      { id: "n2", family: "source", pluginId: "source.upload", label: "Source ZIP" },
      { id: "n3", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST" },
      { id: "n4", family: "logic", pluginId: "logic.filter", label: "Filter >= HIGH" },
      { id: "n5", family: "ai", pluginId: "report.export", label: "Report HTML" },
      { id: "n6", family: "action", pluginId: "notify.webhook", label: "Webhook" },
    ],
    highlights: ["A-SAST-04 · permitAll() на внутреннем маршруте выгрузки"],
  },
];

export const STARTER_TEMPLATES: StarterTemplateRecord[] = [
  {
    id: "tpl-mentor-benchmark",
    slug: "mentor-benchmark-repair-desk",
    name: "Mentor Benchmark / Compliance Export (Repair Desk)",
    description:
      "Эталонный граф под учебный репозиторий организаторов (15 TP / 6 controls / 0 FP): параллельные Secrets, SCA и SAST → grounded AI Explain → экспорт submission.json + Markdown → Webhook.",
    problemSolved:
      "Воспроизводимый аудит Kotlin/Spring Boot/Gradle за 1 клик с обязательным submission.json и читаемым отчётом",
    trigger: "Manual",
    category: "benchmark",
    tags: ["Repair Desk", "Kotlin PSI", "submission.json", "AI Explain"],
    isBuiltin: true,
    authorSubject: "SecFlow Built-in",
    cloneCount: 38,
    createdAt: "Встроенный · v1.0",
    featured: true,
    nodes: [
      { id: "t1", family: "trigger", pluginId: "trigger.manual", label: "Ручной запуск" },
      { id: "t2", family: "source", pluginId: "source.upload", label: "Source ZIP" },
      { id: "t3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets Scanner" },
      { id: "t4", family: "analyzer", pluginId: "scan.sca", label: "SCA Gradle" },
      { id: "t5", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST Kotlin" },
      { id: "t6", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "t7", family: "ai", pluginId: "report.export", label: "submission.json + MD" },
      { id: "t8", family: "action", pluginId: "notify.webhook", label: "Webhook" },
    ],
    edges: [
      { source: "t1", target: "t2" },
      { source: "t2", target: "t3" },
      { source: "t2", target: "t4" },
      { source: "t2", target: "t5" },
      { source: "t3", target: "t6" },
      { source: "t4", target: "t6" },
      { source: "t5", target: "t6" },
      { source: "t6", target: "t7" },
      { source: "t7", target: "t8" },
    ],
    requiredParams: [
      {
        node: "source.upload",
        field: "sourceId",
        hint: "Загрузите ZIP-архив учебного проекта Repair Desk",
      },
      {
        node: "notify.webhook",
        field: "targetUrl",
        hint: "Укажите URL локального Webhook Inspector или приёмника",
      },
    ],
  },
  {
    id: "tpl-full-prerelease-gate",
    slug: "full-pre-release-appsec-gate",
    name: "Full Pre-Release AppSec Gate",
    description:
      "Полный предрелизный контроль: параллельные Secrets, SCA, SAST и CycloneDX 1.6 SBOM → Policy Gate (fail >= HIGH). При провале запускается AI Explain, Telegram и отчёт; при успехе — Webhook «Passed».",
    problemSolved:
      "Единый релизный шлюз с разделением веток FAIL / PASS, выпуском SBOM и AI-разбором рисков",
    trigger: "Manual",
    category: "gate",
    tags: ["Policy Gate", "SBOM", "Telegram", "AI Explain"],
    isBuiltin: true,
    authorSubject: "SecFlow Built-in",
    cloneCount: 29,
    createdAt: "Встроенный · v1.0",
    nodes: [
      { id: "t1", family: "trigger", pluginId: "trigger.manual", label: "Ручной запуск" },
      { id: "t2", family: "source", pluginId: "source.upload", label: "Source ZIP" },
      { id: "t3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets" },
      { id: "t4", family: "analyzer", pluginId: "scan.sca", label: "SCA Gradle" },
      { id: "t5", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST Kotlin" },
      { id: "t6", family: "analyzer", pluginId: "sbom.generate", label: "SBOM CDX 1.6" },
      { id: "t7", family: "logic", pluginId: "gate.policy", label: "Policy Gate (>= HIGH)" },
      { id: "t8", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "t9", family: "action", pluginId: "notify.telegram", label: "Telegram Alert" },
      { id: "t10", family: "ai", pluginId: "report.export", label: "Export MD + JSON" },
      { id: "t11", family: "action", pluginId: "notify.webhook", label: "Webhook Passed" },
    ],
    edges: [
      { source: "t1", target: "t2" },
      { source: "t2", target: "t3" },
      { source: "t2", target: "t4" },
      { source: "t2", target: "t5" },
      { source: "t2", target: "t6" },
      { source: "t3", target: "t7" },
      { source: "t4", target: "t7" },
      { source: "t5", target: "t7" },
      { source: "t6", target: "t7" },
      { source: "t7", target: "t8", sourceHandle: "fail", label: "FAIL" },
      { source: "t8", target: "t9" },
      { source: "t8", target: "t10" },
      { source: "t7", target: "t11", sourceHandle: "pass", label: "PASS" },
    ],
    requiredParams: [
      {
        node: "source.upload",
        field: "sourceId",
        hint: "Привяжите ZIP-архив релизной сборки",
      },
      {
        node: "notify.telegram",
        field: "secretBindings.botToken",
        hint: "Выберите Secret Reference для Telegram-бота и chatId",
      },
      {
        node: "notify.webhook",
        field: "targetUrl",
        hint: "Укажите URL для уведомления о статусе Passed",
      },
    ],
  },
  {
    id: "tpl-fast-pr-ci-gate",
    slug: "fast-pr-commit-ci-gate",
    name: "Fast PR / Commit CI Gate (★2)",
    description:
      "Входящий Git Webhook подставляет {{ $trigger.repoUrl }} и {{ $trigger.commitSha }}, проверяет Secrets + SCA, применяет Policy Gate (блок на SECRET | CRITICAL) и возвращает Commit Status в PR.",
    problemSolved:
      "Автоматическая блокировка уязвимых Pull Request до слияния в main с публикацией Commit Status API",
    trigger: "Webhook",
    category: "ci-cd",
    tags: ["CI/CD", "Webhook", "Secrets", "SCA"],
    isBuiltin: true,
    authorSubject: "SecFlow Built-in",
    cloneCount: 24,
    createdAt: "Встроенный · v1.0",
    nodes: [
      { id: "t1", family: "trigger", pluginId: "trigger.webhook", label: "Git Webhook" },
      { id: "t2", family: "source", pluginId: "source.git", label: "Source Git (PR)" },
      { id: "t3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets" },
      { id: "t4", family: "analyzer", pluginId: "scan.sca", label: "SCA Gradle" },
      { id: "t5", family: "logic", pluginId: "gate.policy", label: "Policy Gate" },
      { id: "t6", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "t7", family: "action", pluginId: "notify.webhook", label: "PR Commit Status" },
    ],
    edges: [
      { source: "t1", target: "t2" },
      { source: "t2", target: "t3" },
      { source: "t2", target: "t4" },
      { source: "t3", target: "t5" },
      { source: "t4", target: "t5" },
      { source: "t5", target: "t6", sourceHandle: "fail", label: "SECRET / CRIT" },
      { source: "t6", target: "t7" },
      { source: "t5", target: "t7", sourceHandle: "pass", label: "PASS" },
    ],
    requiredParams: [
      {
        node: "trigger.webhook",
        field: "secretBindings.hmacSecret",
        hint: "Привяжите HMAC-секрет для проверки подписи Git Webhook",
      },
      {
        node: "source.git",
        field: "repoUrl",
        hint: "Проверьте allowlist URL учебного репозитория",
      },
      {
        node: "notify.webhook",
        field: "secretBindings.gitStatusToken",
        hint: "Привяжите Secret Reference для отправки Commit Status",
      },
    ],
  },
  {
    id: "tpl-nightly-secret-watch",
    slug: "nightly-scheduled-secret-watch",
    name: "Nightly Scheduled Secret Watch",
    description:
      "Регламентный скан по Cron (14:00): проверяет утечки секретов, исключает README и тестовые фикстуры через logic.regex, проверяет count > 0, формирует AI Explain и отправляет отчёт по SMTP.",
    problemSolved:
      "Ежедневный мониторинг утечек ключей и паролей без ложных срабатываний на документации",
    trigger: "Schedule",
    category: "secrets",
    tags: ["Secrets", "Cron", "Regex", "SMTP"],
    isBuiltin: true,
    authorSubject: "SecFlow Built-in",
    cloneCount: 19,
    createdAt: "Встроенный · v1.0",
    nodes: [
      { id: "t1", family: "trigger", pluginId: "trigger.schedule", label: "Cron 0 14 * * *" },
      { id: "t2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "t3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets PSI" },
      { id: "t4", family: "logic", pluginId: "logic.regex", label: "Exclude README/test" },
      { id: "t5", family: "logic", pluginId: "logic.if", label: "If count > 0" },
      { id: "t6", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "t7", family: "action", pluginId: "notify.smtp", label: "SMTP Email" },
    ],
    edges: [
      { source: "t1", target: "t2" },
      { source: "t2", target: "t3" },
      { source: "t3", target: "t4" },
      { source: "t4", target: "t5", sourceHandle: "matched", label: "active" },
      { source: "t5", target: "t6", sourceHandle: "true", label: "count > 0" },
      { source: "t6", target: "t7" },
    ],
    requiredParams: [
      {
        node: "source.git",
        field: "repoUrl",
        hint: "Укажите allowlisted Git-репозиторий и ветку",
      },
      {
        node: "notify.smtp",
        field: "recipients",
        hint: "Задайте список получателей и SMTP Secret Reference",
      },
    ],
  },
  {
    id: "tpl-severity-escalation-router",
    slug: "severity-escalation-router",
    name: "Severity Escalation Router",
    description:
      "Трёхуровневая маршрутизация по maxSeverity через logic.switch: CRITICAL уходит в AI Explain → Telegram + MCP-тикет, HIGH/MEDIUM — в SMTP, а CLEAN — тихо логируется в Webhook.",
    problemSolved:
      "Разделение каналов эскалации по критичности: срочные алерты и тикеты только на CRITICAL",
    trigger: "Manual",
    category: "gate",
    tags: ["Switch", "MCP", "Telegram", "SAST"],
    isBuiltin: true,
    authorSubject: "SecFlow Built-in",
    cloneCount: 17,
    createdAt: "Встроенный · v1.0",
    nodes: [
      { id: "t1", family: "trigger", pluginId: "trigger.manual", label: "Ручной запуск" },
      { id: "t2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "t3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets" },
      { id: "t4", family: "analyzer", pluginId: "scan.sca", label: "SCA Gradle" },
      { id: "t5", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST Kotlin" },
      { id: "t6", family: "logic", pluginId: "logic.switch", label: "Switch (maxSeverity)" },
      { id: "t7", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "t8", family: "action", pluginId: "notify.telegram", label: "Telegram" },
      { id: "t9", family: "action", pluginId: "mcp.tool", label: "MCP Issue" },
      { id: "t10", family: "action", pluginId: "notify.smtp", label: "SMTP Digest" },
      { id: "t11", family: "action", pluginId: "notify.webhook", label: "Webhook Clean" },
    ],
    edges: [
      { source: "t1", target: "t2" },
      { source: "t2", target: "t3" },
      { source: "t2", target: "t4" },
      { source: "t2", target: "t5" },
      { source: "t3", target: "t6" },
      { source: "t4", target: "t6" },
      { source: "t5", target: "t6" },
      { source: "t6", target: "t7", sourceHandle: "CRITICAL", label: "CRITICAL" },
      { source: "t7", target: "t8" },
      { source: "t7", target: "t9" },
      { source: "t6", target: "t10", sourceHandle: "HIGH", label: "HIGH / MED" },
      { source: "t6", target: "t11", sourceHandle: "CLEAN", label: "CLEAN" },
    ],
    requiredParams: [
      {
        node: "source.git",
        field: "repoUrl",
        hint: "Укажите учебный репозиторий для аудита",
      },
      {
        node: "mcp.tool",
        field: "connectionId",
        hint: "Выберите подключённый Outbound MCP Connection и toolName",
      },
      {
        node: "notify.telegram",
        field: "chatId",
        hint: "Задайте чат эскалации и Secret Reference бота",
      },
    ],
  },
  {
    id: "tpl-weekly-supply-chain-sbom",
    slug: "weekly-supply-chain-sbom-audit",
    name: "Weekly Supply-Chain & SBOM Audit",
    description:
      "Еженедельный аудит зависимостей Gradle по версионируемому каталогу CVE/GHSA с генерацией Product SBOM (CycloneDX 1.6), фильтрацией severity >= HIGH, AI Explain и сводкой в Telegram.",
    problemSolved:
      "Регулярный контроль цепочки поставок, лицензий и новых CVE в транзитивных зависимостях",
    trigger: "Schedule",
    category: "sca-sbom",
    tags: ["SCA", "SBOM", "CycloneDX 1.6", "Cron"],
    isBuiltin: true,
    authorSubject: "SecFlow Built-in",
    cloneCount: 21,
    createdAt: "Встроенный · v1.0",
    nodes: [
      { id: "t1", family: "trigger", pluginId: "trigger.schedule", label: "Schedule Weekly" },
      { id: "t2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "t3", family: "analyzer", pluginId: "scan.sca", label: "SCA Gradle" },
      { id: "t4", family: "analyzer", pluginId: "sbom.generate", label: "SBOM CDX 1.6" },
      { id: "t5", family: "logic", pluginId: "logic.filter", label: "Filter >= HIGH" },
      { id: "t6", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "t7", family: "action", pluginId: "notify.telegram", label: "Telegram" },
    ],
    edges: [
      { source: "t1", target: "t2" },
      { source: "t2", target: "t3" },
      { source: "t2", target: "t4" },
      { source: "t3", target: "t5" },
      { source: "t4", target: "t5" },
      { source: "t5", target: "t6" },
      { source: "t6", target: "t7" },
    ],
    requiredParams: [
      {
        node: "source.git",
        field: "repoUrl",
        hint: "Укажите репозиторий с build.gradle.kts / gradle.lockfile",
      },
      {
        node: "notify.telegram",
        field: "chatId",
        hint: "Привяжите Telegram-канал и Secret Reference",
      },
    ],
  },
  {
    id: "tpl-regression-baseline-watch",
    slug: "regression-new-findings-watch",
    name: "Regression / New-Findings-Only Watch",
    description:
      "Сравнивает текущий скан (Secrets + SCA + SAST) с предыдущим baseline-прогоном через logic.compare и оповещает в Telegram только при появлении новых уязвимостей (newCount > 0).",
    problemSolved:
      "Снятие alert fatigue: команда получает уведомления строго о новых регрессиях безопасности",
    trigger: "Schedule",
    category: "gate",
    tags: ["Baseline Diff", "SAST", "Secrets", "Schedule"],
    isBuiltin: true,
    authorSubject: "SecFlow Built-in",
    cloneCount: 14,
    createdAt: "Встроенный · v1.0",
    nodes: [
      { id: "t1", family: "trigger", pluginId: "trigger.schedule", label: "Schedule Daily" },
      { id: "t2", family: "source", pluginId: "source.git", label: "Source Git" },
      { id: "t3", family: "analyzer", pluginId: "scan.secrets", label: "Secrets" },
      { id: "t4", family: "analyzer", pluginId: "scan.sca", label: "SCA Gradle" },
      { id: "t5", family: "analyzer", pluginId: "scan.sast.kotlin", label: "SAST Kotlin" },
      { id: "t6", family: "logic", pluginId: "logic.compare", label: "Baseline Diff" },
      { id: "t7", family: "logic", pluginId: "logic.if", label: "If newCount > 0" },
      { id: "t8", family: "ai", pluginId: "ai.explain", label: "AI Explain" },
      { id: "t9", family: "action", pluginId: "notify.telegram", label: "Telegram" },
    ],
    edges: [
      { source: "t1", target: "t2" },
      { source: "t2", target: "t3" },
      { source: "t2", target: "t4" },
      { source: "t2", target: "t5" },
      { source: "t3", target: "t6" },
      { source: "t4", target: "t6" },
      { source: "t5", target: "t6" },
      { source: "t6", target: "t7" },
      { source: "t7", target: "t8", sourceHandle: "true", label: "new > 0" },
      { source: "t8", target: "t9" },
    ],
    requiredParams: [
      {
        node: "source.git",
        field: "repoUrl",
        hint: "Укажите отслеживаемую ветку учебного репозитория",
      },
      {
        node: "notify.telegram",
        field: "chatId",
        hint: "Укажите чат для уведомлений о регрессиях",
      },
    ],
  },
];

export const AI_TEXT_PRESETS: TextToWorkflowPreset[] = [
  {
    id: "preset-repair-desk",
    label: "Аудит Repair Desk + Telegram",
    prompt:
      "Проверь учебный проект Repair Desk на утечки секретов, уязвимые зависимости Gradle (SCA + SBOM) и SAST. Если Policy Gate выявит HIGH или CRITICAL — сформируй AI-разбор и отправь отчёт в Telegram.",
    generatedName: "Аудит Repair Desk (AI-сборка)",
    generatedDescription:
      "Собран из текстового описания: полный детерминированный анализ Secrets/SCA/SAST + SBOM → Policy Gate → AI Explain → Telegram.",
    trigger: "Manual",
    triggerDetail: "Ручной запуск · ZIP-архив",
    nodes: [
      { id: "g1", family: "trigger", pluginId: "trigger.manual", label: "trigger.manual" },
      { id: "g2", family: "source", pluginId: "source.upload", label: "source.upload" },
      { id: "g3", family: "analyzer", pluginId: "scan.secrets", label: "scan.secrets" },
      { id: "g4", family: "analyzer", pluginId: "scan.sca", label: "scan.sca" },
      { id: "g5", family: "analyzer", pluginId: "scan.sast.kotlin", label: "scan.sast.kotlin" },
      { id: "g6", family: "analyzer", pluginId: "sbom.generate", label: "sbom.generate" },
      { id: "g7", family: "logic", pluginId: "gate.policy", label: "gate.policy" },
      { id: "g8", family: "ai", pluginId: "ai.explain", label: "ai.explain" },
      { id: "g9", family: "action", pluginId: "notify.telegram", label: "notify.telegram" },
    ],
    missingFields: [
      {
        node: "source.upload",
        field: "sourceId",
        hint: "Загрузите ZIP-архив Repair Desk в инспекторе ноды",
      },
      {
        node: "notify.telegram",
        field: "secretBindings.botToken",
        hint: "Привяжите секрет TELEGRAM_BOT_TOKEN (без plaintext)",
      },
    ],
  },
  {
    id: "preset-pr-webhook",
    label: "PR Gate по Git Webhook",
    prompt:
      "На каждый Pull Request по Git Webhook запускай Secrets и SAST Kotlin. При CRITICAL проваливай Policy Gate, объясняй риски без исходников (metadata_only) и шли статус в Webhook.",
    generatedName: "PR Security Gate (AI-сборка)",
    generatedDescription:
      "Собран из текстового описания: Git Webhook → Secrets + SAST Kotlin → Policy Gate (CRITICAL) → AI Explain → Webhook.",
    trigger: "Webhook",
    triggerDetail: "POST /webhooks/git/{workflowId}",
    nodes: [
      { id: "g1", family: "trigger", pluginId: "trigger.webhook", label: "trigger.webhook" },
      { id: "g2", family: "source", pluginId: "source.git", label: "source.git" },
      { id: "g3", family: "analyzer", pluginId: "scan.secrets", label: "scan.secrets" },
      { id: "g4", family: "analyzer", pluginId: "scan.sast.kotlin", label: "scan.sast.kotlin" },
      { id: "g5", family: "logic", pluginId: "gate.policy", label: "gate.policy" },
      { id: "g6", family: "ai", pluginId: "ai.explain", label: "ai.explain" },
      { id: "g7", family: "action", pluginId: "notify.webhook", label: "notify.webhook" },
    ],
    missingFields: [
      {
        node: "source.git",
        field: "repoUrl",
        hint: "Укажите разрешённый URL учебного репозитория",
      },
      {
        node: "notify.webhook",
        field: "targetUrl",
        hint: "Укажите URL приёмника или канал Webhook Inspector",
      },
    ],
  },
  {
    id: "preset-nightly-sbom",
    label: "Ночной SBOM + MCP-задача",
    prompt:
      "Каждую ночь в 03:00 проверяй зависимости Gradle по справочнику CVE, собирай CycloneDX 1.6 SBOM и при наличии уязвимостей создавай тикет через MCP Tool.",
    generatedName: "Ночной SBOM + MCP (AI-сборка)",
    generatedDescription:
      "Собран из текстового описания: Schedule Cron → SCA + CycloneDX 1.6 SBOM → If > 0 → MCP Tool.",
    trigger: "Schedule",
    triggerDetail: "Cron 0 3 * * *",
    nodes: [
      { id: "g1", family: "trigger", pluginId: "trigger.schedule", label: "trigger.schedule" },
      { id: "g2", family: "source", pluginId: "source.git", label: "source.git" },
      { id: "g3", family: "analyzer", pluginId: "scan.sca", label: "scan.sca" },
      { id: "g4", family: "analyzer", pluginId: "sbom.generate", label: "sbom.generate" },
      { id: "g5", family: "logic", pluginId: "logic.if", label: "logic.if" },
      { id: "g6", family: "action", pluginId: "mcp.tool", label: "mcp.tool" },
    ],
    missingFields: [
      {
        node: "mcp.tool",
        field: "connectionId",
        hint: "Выберите подключённый Outbound MCP Connection",
      },
    ],
  },
];

export const WORKSPACE_VARIANTS: WorkspaceVariantMeta[] = [
  {
    id: "flowmapp-11",
    slug: "/",
    system: "flowmapp",
    systemLabel: "Flowmapp",
    indexInSystem: 1,
    globalNumber: "11",
    name: "SecFlow Workflows",
    layoutKind: "Единый реестр + Canvas-верстак",
    summary:
      "Финальный выбранный интерфейс SecFlow Workflows с единым поиском, фильтрами, модалкой создания досок и интерактивным канвасом с гибкими связями и правым 2-вкладочным сайдбаром.",
    palette: ["#ffffff", "#0080ff", "#c5e0fb", "#000000"],
  },
];

export const RUN_STATUS_LABELS: Record<RunStatus, string> = {
  SUCCEEDED: "Завершён",
  FAILED: "Остановлен",
  RUNNING: "Выполняется",
  QUEUED: "В очереди",
  CANCELLED: "Отменён",
  NONE: "Не запускался",
};

export const ROLE_LABELS: Record<UserRole, { short: string; name: string; email: string }> = {
  owner: { short: "owner", name: "Анна Соколова", email: "anna.sokolova@centrinvest.local" },
  editor: { short: "editor", name: "Дмитрий Волков", email: "d.volkov@centrinvest.local" },
  viewer: { short: "viewer", name: "Игорь Петров", email: "i.petrov@centrinvest.local" },
};

export const INITIAL_RUN_HISTORY: WorkflowRunRecord[] = [
  {
    id: "run_9f4c2b81",
    workflowId: "wf-repair-desk-audit",
    workflowName: "Repair Desk — Полный аудит безопасности",
    trigger: "Manual",
    status: "FAILED",
    policyGate: "FAIL",
    startedAt: "12 мин назад",
    durationLabel: "2.4 с",
    sourceLabel: "repair-desk-main.zip",
    initiatedBy: "Анна Соколова",
    critCount: 4,
    highCount: 10,
    mediumCount: 1,
    nodesCount: 8,
    wavesCount: 6,
    steps: [
      { id: "s1", nodeLabel: "Ручной запуск", pluginId: "trigger.manual", family: "trigger", status: "SUCCEEDED", durationMs: 35, summary: "Инициализирован прогон run_9f4c2b81" },
      { id: "s2", nodeLabel: "Source ZIP-архив", pluginId: "source.upload", family: "source", status: "SUCCEEDED", durationMs: 180, summary: "34 файла индексировано в Garage S3" },
      { id: "s3", nodeLabel: "Secrets Scanner (PSI + YAML)", pluginId: "scan.secrets", family: "analyzer", status: "FAILED", durationMs: 410, summary: "5 подтверждённых утечек (маскированы), 0 FP" },
      { id: "s4", nodeLabel: "SCA Gradle (Go)", pluginId: "scan.sca", family: "analyzer", status: "WARNING", durationMs: 290, summary: "5 CVE (CVE-2022-42889, CVE-2024-25710 и др.)" },
      { id: "s5", nodeLabel: "SAST Kotlin / Spring (PSI)", pluginId: "scan.sast.kotlin", family: "analyzer", status: "FAILED", durationMs: 540, summary: "5 уязвимостей (SQLi, TLS, CORS, permitAll, IDOR)" },
      { id: "s6", nodeLabel: "Policy Gate", pluginId: "gate.policy", family: "logic", status: "FAILED", durationMs: 18, summary: "Порог CRITICAL > 0 нарушен (4 CRIT / 10 HIGH)" },
      { id: "s7", nodeLabel: "AI Explain (Grounded)", pluginId: "ai.explain", family: "ai", status: "SUCCEEDED", durationMs: 1080, summary: "15/15 findingId объяснены · 0 выдуманных CVE" },
      { id: "s8", nodeLabel: "Telegram-уведомление", pluginId: "notify.telegram", family: "action", status: "SUCCEEDED", durationMs: 210, summary: "Отчёт доставлен в @appsec-alerts-team" },
    ],
  },
  {
    id: "run_7e12a09d",
    workflowId: "wf-pr-security-gate",
    workflowName: "CI/CD Gate для Pull Request",
    trigger: "Webhook",
    status: "SUCCEEDED",
    policyGate: "WARN",
    startedAt: "48 мин назад",
    durationLabel: "1.8 с",
    sourceLabel: "git: feat/checkout-api @ 4a9e1c",
    initiatedBy: "GitLab PR Hook",
    critCount: 0,
    highCount: 2,
    mediumCount: 3,
    nodesCount: 7,
    wavesCount: 6,
    steps: [
      { id: "s1", nodeLabel: "Git Webhook", pluginId: "trigger.webhook", family: "trigger", status: "SUCCEEDED", durationMs: 42, summary: "HMAC-SHA256 подпись проверена" },
      { id: "s2", nodeLabel: "Source Git-репозиторий", pluginId: "source.git", family: "source", status: "SUCCEEDED", durationMs: 220, summary: "Ветка feat/checkout-api проверена по allowlist" },
      { id: "s3", nodeLabel: "Secrets Scanner (PSI + YAML)", pluginId: "scan.secrets", family: "analyzer", status: "SUCCEEDED", durationMs: 360, summary: "Утечек секретов не найдено" },
      { id: "s4", nodeLabel: "SAST Kotlin / Spring (PSI)", pluginId: "scan.sast.kotlin", family: "analyzer", status: "WARNING", durationMs: 490, summary: "2 HIGH (CORS + TLS hostname), 3 MEDIUM" },
      { id: "s5", nodeLabel: "Policy Gate", pluginId: "gate.policy", family: "logic", status: "WARNING", durationMs: 16, summary: "Вердикт WARN · merge разрешён с замечаниями" },
      { id: "s6", nodeLabel: "HTTP / CI Webhook", pluginId: "notify.webhook", family: "action", status: "SUCCEEDED", durationMs: 175, summary: "Commit Status опубликован (HTTP 200)" },
    ],
  },
  {
    id: "run_5b81c440",
    workflowId: "wf-nightly-sca-sbom",
    workflowName: "Ночной SCA + CycloneDX 1.6 SBOM",
    trigger: "Schedule",
    status: "SUCCEEDED",
    policyGate: "FAIL",
    startedAt: "Сегодня, 03:00",
    durationLabel: "1.1 с",
    sourceLabel: "git: main @ 9c3f01",
    initiatedBy: "Cron 0 3 * * *",
    critCount: 1,
    highCount: 3,
    mediumCount: 1,
    nodesCount: 7,
    wavesCount: 6,
    steps: [
      { id: "s1", nodeLabel: "Расписание (Cron)", pluginId: "trigger.schedule", family: "trigger", status: "SUCCEEDED", durationMs: 28, summary: "Регламентный слот nightly-01" },
      { id: "s2", nodeLabel: "Source Git-репозиторий", pluginId: "source.git", family: "source", status: "SUCCEEDED", durationMs: 210, summary: "Индексированы build.gradle.kts и gradle.lockfile" },
      { id: "s3", nodeLabel: "SCA Gradle (Go)", pluginId: "scan.sca", family: "analyzer", status: "WARNING", durationMs: 290, summary: "Выявлено 5 CVE в транзитивных и $var пакетах" },
      { id: "s4", nodeLabel: "SBOM CycloneDX 1.6", pluginId: "sbom.generate", family: "analyzer", status: "SUCCEEDED", durationMs: 165, summary: "Собран sbom.cdx.json (67 компонентов)" },
      { id: "s5", nodeLabel: "Email (SMTP)", pluginId: "notify.smtp", family: "action", status: "SUCCEEDED", durationMs: 260, summary: "Сводка и SBOM отправлены 3 получателям" },
    ],
  },
  {
    id: "run_3a04d218",
    workflowId: "wf-secrets-premerge",
    workflowName: "Ловушка утечек секретов (Pre-merge)",
    trigger: "Webhook",
    status: "SUCCEEDED",
    policyGate: "PASS",
    startedAt: "3 ч назад",
    durationLabel: "0.7 с",
    sourceLabel: "git: release/2.4 @ d18a77",
    initiatedBy: "GitLab Push Hook",
    critCount: 0,
    highCount: 0,
    mediumCount: 0,
    nodesCount: 5,
    wavesCount: 5,
    steps: [
      { id: "s1", nodeLabel: "Git Webhook", pluginId: "trigger.webhook", family: "trigger", status: "SUCCEEDED", durationMs: 38, summary: "Push в ветку release/2.4" },
      { id: "s2", nodeLabel: "Source Git-репозиторий", pluginId: "source.git", family: "source", status: "SUCCEEDED", durationMs: 195, summary: "19 файлов проверено" },
      { id: "s3", nodeLabel: "Secrets Scanner (PSI + YAML)", pluginId: "scan.secrets", family: "analyzer", status: "SUCCEEDED", durationMs: 310, summary: "Утечек нет · 2 безопасных контроля подтверждены" },
      { id: "s4", nodeLabel: "Условие If", pluginId: "logic.if", family: "logic", status: "SUCCEEDED", durationMs: 12, summary: "Ветка false (findings == 0) · алерт пропущен" },
    ],
  },
  {
    id: "run_2d88e10a",
    workflowId: "wf-repair-desk-audit",
    workflowName: "Repair Desk — Полный аудит безопасности",
    trigger: "Manual",
    status: "FAILED",
    policyGate: "FAIL",
    startedAt: "Вчера, 21:15",
    durationLabel: "2.5 с",
    sourceLabel: "repair-desk-main.zip",
    initiatedBy: "Дмитрий Волков",
    critCount: 4,
    highCount: 10,
    mediumCount: 1,
    nodesCount: 8,
    wavesCount: 6,
    steps: [
      { id: "s1", nodeLabel: "Ручной запуск", pluginId: "trigger.manual", family: "trigger", status: "SUCCEEDED", durationMs: 36, summary: "Контрольный прогон перед демо" },
      { id: "s2", nodeLabel: "Secrets + SCA + SAST", pluginId: "scan.sast.kotlin", family: "analyzer", status: "SUCCEEDED", durationMs: 560, summary: "15 TP / 6 controls / 0 FP подтверждены" },
      { id: "s3", nodeLabel: "Policy Gate", pluginId: "gate.policy", family: "logic", status: "FAILED", durationMs: 18, summary: "Вердикт FAIL · сформирован submission.json" },
    ],
  },
  {
    id: "run_1c90f671",
    workflowId: "wf-release-mcp-bridge",
    workflowName: "Релизный контроль + MCP тикетинг",
    trigger: "Manual",
    status: "SUCCEEDED",
    policyGate: "PASS",
    startedAt: "Вчера, 19:40",
    durationLabel: "3.1 с",
    sourceLabel: "git: tag v1.12.0",
    initiatedBy: "Анна Соколова",
    critCount: 0,
    highCount: 0,
    mediumCount: 2,
    nodesCount: 6,
    wavesCount: 6,
    steps: [
      { id: "s1", nodeLabel: "Ручной запуск", pluginId: "trigger.manual", family: "trigger", status: "SUCCEEDED", durationMs: 34, summary: "Релизный аудит тега v1.12.0" },
      { id: "s2", nodeLabel: "SAST Kotlin / Spring (PSI)", pluginId: "scan.sast.kotlin", family: "analyzer", status: "SUCCEEDED", durationMs: 515, summary: "0 CRIT, 0 HIGH, 2 MEDIUM" },
      { id: "s3", nodeLabel: "Policy Gate", pluginId: "gate.policy", family: "logic", status: "SUCCEEDED", durationMs: 15, summary: "Релиз одобрен (PASS)" },
      { id: "s4", nodeLabel: "Outbound MCP Tool", pluginId: "mcp.tool", family: "action", status: "SUCCEEDED", durationMs: 310, summary: "Создано 2 задачи в tracker-mcp-internal" },
    ],
  },
];
