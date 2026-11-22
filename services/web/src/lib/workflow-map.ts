import {
  createCanvasNodeFromTemplate,
  getSwitchOutputPorts,
  TEMPLATE_BY_PLUGIN_ID,
  type CanvasBoardEdge,
  type CanvasBoardNode,
  type CanvasNodeRunStatus,
  type SecretBindingRef,
} from "@/data/canvas-nodes-catalog";
import type {
  PolicyVerdict,
  RunAIReportInfo,
  RunFindingsStats,
  RunSbomInfo,
  RunStatus,
  StarterTemplateRecord,
  TemplateCategory,
  TriggerKind,
  WorkflowNodeChip,
  WorkflowRecord,
  WorkflowRunRecord,
  WorkflowRunStep,
} from "@/data/workflows-workspace-data";

export interface BoardShape {
  nodes: CanvasBoardNode[];
  edges: CanvasBoardEdge[];
}

export interface ServerGraph {
  schemaVersion?: number;
  nodes?: Array<{
    id: string;
    pluginId: string;
    label: string;
    position?: { x: number; y: number };
    params?: Record<string, unknown> | null;
    secretBindings?: SecretBindingRef[];
  }>;
  edges?: Array<{
    id: string;
    sourceNodeId: string;
    sourceHandle?: string;
    targetNodeId: string;
    targetHandle?: string;
  }>;
}

export interface ServerWorkflow {
  id: string;
  name: string;
  description: string;
  version: number;
  updatedAt?: string;
  webhookPath?: string | null;
  cronExpression?: string | null;
  graph: ServerGraph;
}

export interface ServerTemplate {
  id: string;
  slug: string;
  name: string;
  description: string;
  problemSolved: string;
  tags: string[];
  isBuiltin: boolean;
  authorSubject: string;
  cloneCount: number;
  createdAt?: string | null;
  updatedAt?: string | null;
  sanitizedGraph: ServerGraph;
}

export interface ServerSbom {
  digest?: string;
  specVersion?: string;
  componentCount?: number;
  vulnerabilityCount?: number;
  downloadUrl?: string;
  generatedAt?: string;
  format?: string;
  s3Key?: string;
}

export interface ServerAIReport {
  quality: "VERIFIED" | "DEGRADED" | "FALLBACK";
  releaseDecision: "PASS" | "WARN" | "BLOCK";
  executiveSummary: string;
  groups?: Array<{
    title: string;
    maxSeverity: string;
    findingIds: string[];
    summary: string;
  }>;
  items?: Array<{
    findingId: string;
    priorityRank: number;
    plainLanguageRisk: string;
    businessImpact: string;
    remediationSteps: string[];
    referencedAdvisories: string[];
    finding: {
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
    };
  }>;
  modelId: string;
  providerMode: string;
  privacyMode: string;
  strippedHallucinatedAdvisories: number;
  cached: boolean;
  promptHash?: string;
  tokensIn?: number;
  tokensOut?: number;
  latencyMs?: number | string;
  createdAt?: string;
}

export interface ServerRun {
  id: string;
  workflowId: string;
  workflowVersion?: number;
  workflowName: string;
  status: RunStatus;
  createdAt?: string;
  startedAt?: string | null;
  finishedAt?: string | null;
  errorMessage?: string | null;
  parentRunId?: string | null;
  rerunFromNodeId?: string | null;
  traceId?: string | null;
  lastSeqId?: number | string | null;
  submissionDownloadUrl?: string | null;
  markdownReportDownloadUrl?: string | null;
  htmlReportDownloadUrl?: string | null;
  trigger?: {
    type?: string;
    repoUrl?: string | null;
    branch?: string | null;
    commitSha?: string | null;
    prNumber?: number | null;
    gitProvider?: string | null;
    triggeredBy?: string | null;
    triggeredAt?: string | null;
  };
  gateResult?: { status?: PolicyVerdict; reason?: string; nodeId?: string } | null;
  findingsStats?: {
    total?: number;
    newCount?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    secretCount?: number;
    sastCount?: number;
    scaCount?: number;
    maxSeverity?: string | null;
  } | null;
  sourceRef?: {
    sourceId?: string;
    sha256?: string;
    repoName?: string;
    repoUrl?: string | null;
    gitRef?: string | null;
    commitSha?: string | null;
    sizeBytes?: number | string;
    fileCount?: number;
  } | null;
  sbom?: ServerSbom | null;
  aiReport?: ServerAIReport | null;
  nodeRuns?: Array<{
    nodeRunId?: string;
    nodeId: string;
    pluginId: string;
    status: string;
    attempt?: number;
    workerId?: string | null;
    activeOutputPorts?: string[];
    redactedPreview?: unknown;
    durationMs?: number | string;
    errorMessage?: string | null;
    findingsEmitted?: number;
    startedAt?: string | null;
    finishedAt?: string | null;
  }>;
}

export type ParamFieldKind = "string" | "boolean" | "integer" | "number" | "string[]" | "json";

export interface ParamFieldSpec {
  type: ParamFieldKind;
  required?: boolean;
  preserveWhitespace?: boolean;
  defaultJson?: unknown;
}

/**
 * Canonical per-plugin parameter schema mirror of `packages/contracts/schemas/node-params.schema.json`.
 * All built-in plugins enforce `additionalProperties: false` on the backend.
 */
export const NODE_PARAM_SPECS: Record<string, Record<string, ParamFieldSpec>> = {
  "trigger.manual": {
    description: { type: "string", preserveWhitespace: true },
  },
  "trigger.schedule": {
    cron: { type: "string", required: true },
    timezone: { type: "string" },
    enabled: { type: "boolean" },
  },
  "trigger.webhook": {
    gitProvider: { type: "string", required: true },
    events: { type: "string[]" },
    branchFilter: { type: "string" },
    reportCommitStatus: { type: "boolean" },
    commitStatusContext: { type: "string" },
  },
  "source.upload": {
    sourceId: { type: "string", required: true },
  },
  "source.git": {
    repoUrl: { type: "string", required: true },
    gitRef: { type: "string" },
  },
  "scan.secrets": {
    includePaths: { type: "string[]" },
    excludePaths: { type: "string[]" },
  },
  "scan.sca": {
    catalogId: { type: "string" },
  },
  "scan.sast.kotlin": {
    enabledRules: { type: "string[]" },
  },
  "sbom.generate": {
    includeDevDependencies: { type: "boolean" },
  },
  "logic.if": {
    combinator: { type: "string", required: true },
    conditions: { type: "json", required: true },
  },
  "logic.switch": {
    mode: { type: "string", required: true },
  },
  "logic.compare": {
    mode: { type: "string", required: true },
    baselineScope: { type: "string" },
    minNewFindingsForTrue: { type: "integer" },
    minSeverity: { type: "string" },
  },
  "logic.filter": {
    categories: { type: "string[]" },
    minSeverity: { type: "string" },
    onlyNewVsBaseline: { type: "boolean" },
    findingClasses: { type: "string[]" },
    pathPrefixes: { type: "string[]" },
  },
  "logic.regex": {
    field: { type: "string", required: true },
    pattern: { type: "string", required: true, preserveWhitespace: true },
    splitEnvelope: { type: "boolean" },
  },
  "logic.merge": {
    deduplicateByFingerprint: { type: "boolean" },
  },
  "gate.policy": {
    failOnSeverity: { type: "string" },
    warnOnSeverity: { type: "string" },
    failOnAnySecret: { type: "boolean" },
    maxAllowedFindings: { type: "integer" },
    onlyNewVsBaseline: { type: "boolean" },
  },
  "ai.explain": {
    baseUrl: { type: "string" },
    model: { type: "string" },
    privacyMode: { type: "string" },
    locale: { type: "string" },
    maxFindings: { type: "integer" },
  },
  "report.export": {
    title: { type: "string", preserveWhitespace: true },
    notes: { type: "string", preserveWhitespace: true },
    formats: { type: "string[]" },
  },
  "notify.telegram": {
    chatId: { type: "string", required: true },
    messageTemplate: { type: "string", preserveWhitespace: true },
  },
  "notify.webhook": {
    url: { type: "string", required: true },
    bodyTemplate: { type: "string", preserveWhitespace: true },
  },
  "notify.smtp": {
    to: { type: "string[]", required: true },
    subject: { type: "string", required: true, preserveWhitespace: true },
    bodyTemplate: { type: "string", preserveWhitespace: true },
    smtpAddr: { type: "string" },
    smtpUser: { type: "string" },
    smtpFrom: { type: "string" },
  },
  "mcp.tool": {
    connectionId: { type: "string", required: true },
    toolName: { type: "string", required: true },
    arguments: { type: "json", required: true, defaultJson: {} },
    outputVarKey: { type: "string" },
  },
};

function familyOf(pluginId: string): WorkflowNodeChip["family"] {
  return TEMPLATE_BY_PLUGIN_ID[pluginId]?.family ?? "logic";
}

function triggerOf(graph: ServerGraph): TriggerKind {
  const plugin = graph.nodes?.find((node) => node.pluginId.startsWith("trigger."))?.pluginId;
  if (plugin === "trigger.webhook") return "Webhook";
  if (plugin === "trigger.schedule") return "Schedule";
  return "Manual";
}

export function mapTriggerType(triggerType?: string | null): TriggerKind {
  switch ((triggerType || "").toUpperCase()) {
    case "WEBHOOK":
      return "Webhook";
    case "SCHEDULE":
      return "Schedule";
    case "CI_API":
      return "CI API";
    case "MCP":
      return "MCP";
    case "RERUN":
      return "Rerun";
    case "MANUAL":
    default:
      return "Manual";
  }
}

function sourceLabel(graph: ServerGraph): string {
  for (const node of graph.nodes ?? []) {
    const params = node.params ?? {};
    if (typeof params.repoUrl === "string" && params.repoUrl) return params.repoUrl;
    if (typeof params.sourceId === "string" && params.sourceId) return `ZIP: ${params.sourceId}`;
    if (typeof params.repoName === "string" && params.repoName) return params.repoName;
  }
  return "Источник не задан";
}

export function formatWhen(iso?: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function displayParam(value: unknown, fieldSpec?: ParamFieldSpec): string {
  if (value == null) return "";
  if (fieldSpec?.type === "string[]" && Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean).join(", ");
  }
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function asConfig(
  params: Record<string, unknown> | null | undefined,
  pluginId?: string,
): Record<string, string> {
  const spec = pluginId ? NODE_PARAM_SPECS[pluginId] : undefined;
  const config: Record<string, string> = {};
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value == null) continue;
    if (spec && !(key in spec)) continue;
    config[key] = displayParam(value, spec?.[key]);
  }
  return config;
}

function parseStringArray(raw: string): string[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (Array.isArray(parsed)) {
        return parsed.map((item) => String(item).trim()).filter(Boolean);
      }
    } catch {
      // fall through to comma/newline split
    }
  }
  return trimmed
    .split(/[,\n]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseBoolean(raw: string): boolean | undefined {
  const low = raw.trim().toLowerCase();
  if (low === "true" || low === "1" || low === "yes") return true;
  if (low === "false" || low === "0" || low === "no") return false;
  return undefined;
}

/**
 * Schema-aware serializer from Inspector string config to typed JSON params matching
 * `packages/contracts/schemas/node-params.schema.json`.
 *
 * - Strips unknown keys for built-in plugins (`additionalProperties: false`).
 * - Never blindly coerces string fields (regex patterns, chatIds, templates) into booleans/arrays.
 * - Omits empty optional fields so minLength/format/enum/minItems validators pass cleanly.
 */
export function serializeNodeParams(
  pluginId: string,
  config: Record<string, string>,
  original?: Record<string, unknown>,
  paramsJsonSchema?: { properties?: Record<string, { type?: string }> } | Record<string, unknown>,
): Record<string, unknown> {
  const spec = NODE_PARAM_SPECS[pluginId];
  if (!spec) {
    // External / Declarative plugin: coerce typed values using paramsJsonSchema when available.
    const schemaProps =
      paramsJsonSchema &&
      typeof paramsJsonSchema.properties === "object" &&
      paramsJsonSchema.properties !== null
        ? (paramsJsonSchema.properties as Record<string, { type?: string }>)
        : undefined;
    const out: Record<string, unknown> = {};
    for (const [key, raw] of Object.entries(config)) {
      const propType = schemaProps?.[key]?.type;
      const trimmed = raw.trim();
      if (propType === "boolean") {
        if (trimmed === "") continue;
        const parsed = parseBoolean(trimmed);
        if (parsed !== undefined) {
          out[key] = parsed;
        }
        continue;
      }
      if (propType === "integer" || propType === "number") {
        if (trimmed === "") continue;
        const parsed = Number(trimmed);
        if (Number.isFinite(parsed)) {
          out[key] = propType === "integer" ? Math.trunc(parsed) : parsed;
        }
        continue;
      }
      if (propType === "array") {
        const items = parseStringArray(raw);
        if (items.length > 0) {
          out[key] = items;
        }
        continue;
      }
      const prev = original?.[key];
      if (prev !== undefined && typeof prev !== "string" && displayParam(prev) === raw) {
        out[key] = prev;
        continue;
      }
      if (trimmed === "") continue;
      if (
        (trimmed.startsWith("[") && trimmed.endsWith("]")) ||
        (trimmed.startsWith("{") && trimmed.endsWith("}"))
      ) {
        try {
          out[key] = JSON.parse(trimmed) as unknown;
          continue;
        } catch {
          // keep as string
        }
      }
      out[key] = raw;
    }
    return out;
  }

  const out: Record<string, unknown> = {};
  for (const [key, fieldSpec] of Object.entries(spec)) {
    const raw = config[key];
    if (raw === undefined) {
      if (original?.[key] !== undefined) {
        out[key] = original[key];
      } else if (fieldSpec.defaultJson !== undefined) {
        out[key] = fieldSpec.defaultJson;
      }
      continue;
    }

    const trimmed = raw.trim();

    switch (fieldSpec.type) {
      case "string": {
        if (trimmed === "") continue;
        out[key] = fieldSpec.preserveWhitespace ? raw : trimmed;
        break;
      }
      case "boolean": {
        if (trimmed === "") continue;
        const parsed = parseBoolean(trimmed);
        if (parsed !== undefined) {
          out[key] = parsed;
        }
        break;
      }
      case "integer":
      case "number": {
        if (trimmed === "") continue;
        const parsed = Number(trimmed);
        if (Number.isFinite(parsed)) {
          out[key] = fieldSpec.type === "integer" ? Math.trunc(parsed) : parsed;
        }
        break;
      }
      case "string[]": {
        const items = parseStringArray(raw);
        if (items.length === 0) continue;
        out[key] = items;
        break;
      }
      case "json": {
        if (trimmed === "") {
          if (fieldSpec.defaultJson !== undefined) {
            out[key] = fieldSpec.defaultJson;
          }
          continue;
        }
        try {
          out[key] = JSON.parse(trimmed) as unknown;
        } catch {
          if (original?.[key] !== undefined) {
            out[key] = original[key];
          } else if (fieldSpec.defaultJson !== undefined) {
            out[key] = fieldSpec.defaultJson;
          }
        }
        break;
      }
    }
  }

  return out;
}

export function boardFromGraph(graph: ServerGraph): BoardShape {
  const nodes: CanvasBoardNode[] = (graph.nodes ?? []).map((node, index) => {
    const position = node.position ?? { x: 80 + (index % 4) * 240, y: 80 + Math.floor(index / 4) * 160 };
    const secretBindings: SecretBindingRef[] = (node.secretBindings ?? [])
      .filter((binding) => Boolean(binding?.paramKey && binding?.secretRef))
      .map((binding) => ({ paramKey: binding.paramKey, secretRef: binding.secretRef }));
    const tpl = TEMPLATE_BY_PLUGIN_ID[node.pluginId];
    if (!tpl) {
      return {
        id: node.id,
        type: "secflowNode",
        position,
        data: {
          pluginId: node.pluginId,
          family: "logic",
          label: node.label || node.pluginId,
          shortLabel: node.label || node.pluginId,
          purposeTag: "plugin",
          description: node.pluginId,
          runtime: "",
          durationMs: 0,
          iconKey: "plug",
          inputs: 1,
          outputs: ["default"],
          requiredSecretKeys: [],
          optionalSecretKeys: [],
          secretBindings,
          config: asConfig(node.params, node.pluginId),
          params: { ...(node.params ?? {}) },
          sampleOutput: {},
          runStatus: "idle",
        },
      };
    }
    const created = createCanvasNodeFromTemplate(tpl, position, node.id, node.label || tpl.label);
    const params = { ...(node.params ?? {}) };
    const mergedConfig = { ...tpl.defaultConfig, ...asConfig(params, node.pluginId) };
    const outputs =
      node.pluginId === "logic.switch"
        ? getSwitchOutputPorts(mergedConfig.mode)
        : created.data.outputs;
    return {
      ...created,
      data: {
        ...created.data,
        outputs,
        config: mergedConfig,
        params,
        secretBindings,
      },
    };
  });
  const outputsByNode = new Map(nodes.map((node) => [node.id, node.data.outputs]));
  const edges: CanvasBoardEdge[] = (graph.edges ?? []).map((edge) => ({
    id: edge.id,
    source: edge.sourceNodeId,
    target: edge.targetNodeId,
    sourceHandle: canvasSourceHandle(edge.sourceHandle, outputsByNode.get(edge.sourceNodeId)),
    targetHandle: canvasTargetHandle(edge.targetHandle),
  }));
  return { nodes, edges };
}

export function graphFromBoard(board: BoardShape): ServerGraph {
  return {
    schemaVersion: 1,
    nodes: board.nodes.map((node) => ({
      id: node.id,
      pluginId: node.data.pluginId,
      label: node.data.label,
      position: { x: node.position.x, y: node.position.y },
      params: serializeNodeParams(
        node.data.pluginId,
        node.data.config,
        node.data.params,
        node.data.paramsJsonSchema,
      ),
      secretBindings: (node.data.secretBindings ?? [])
        .filter((binding) => Boolean(binding?.paramKey?.trim() && binding?.secretRef?.trim()))
        .map((binding) => ({
          paramKey: binding.paramKey.trim(),
          secretRef: binding.secretRef.trim(),
        })),
    })),
    edges: board.edges.map((edge) => ({
      id: edge.id,
      sourceNodeId: edge.source,
      sourceHandle: serverHandle(edge.sourceHandle),
      targetNodeId: edge.target,
      targetHandle: serverHandle(edge.targetHandle),
    })),
  };
}

function chips(graph: ServerGraph): WorkflowNodeChip[] {
  return (graph.nodes ?? []).map((node) => ({
    id: node.id,
    family: familyOf(node.pluginId),
    pluginId: node.pluginId,
    label: node.label || node.pluginId,
  }));
}

function canvasSourceHandle(handle: string | undefined, outputs?: string[]): string {
  if (handle && handle !== "default") return handle;
  if (!outputs || outputs.length === 0) return "out";
  if (outputs.length === 1) return outputs[0];
  if (outputs.includes("default")) return "default";
  return outputs[0];
}

function canvasTargetHandle(handle?: string): string {
  if (!handle || handle === "default") return "in";
  return handle;
}

function serverHandle(handle?: string | null): string {
  if (!handle || handle === "default" || handle === "out" || handle === "in") return "default";
  return handle;
}

function gateVerdict(status?: string): PolicyVerdict {
  if (status === "FAIL" || status === "WARN" || status === "PASS") return status;
  return "NONE";
}

export function workflowRecord(wf: ServerWorkflow, latest?: ServerRun): WorkflowRecord {
  const stats = latest?.findingsStats;
  return {
    id: wf.id,
    name: wf.name,
    description: wf.description || "",
    trigger: triggerOf(wf.graph),
    triggerDetail: wf.cronExpression || wf.webhookPath || "Ручной запуск",
    lastRunId: latest?.id ?? "—",
    lastRunStatus: latest?.status ?? "NONE",
    policyGate: gateVerdict(latest?.gateResult?.status),
    critCount: stats?.critical ?? 0,
    highCount: stats?.high ?? 0,
    mediumCount: stats?.medium ?? 0,
    updatedAt: formatWhen(wf.updatedAt),
    updatedSortOrder: wf.updatedAt ? Date.parse(wf.updatedAt) : 0,
    sourceLabel: latest?.sourceRef?.repoName || latest?.sourceRef?.repoUrl || sourceLabel(wf.graph),
    durationLabel: durationLabel(latest),
    sbomComponents: latest?.sbom?.componentCount ?? 0,
    nodes: chips(wf.graph),
    highlights: latest?.errorMessage ? [latest.errorMessage] : [],
  };
}

function durationLabel(run?: ServerRun): string {
  if (!run?.startedAt || !run.finishedAt) return "—";
  const ms = Date.parse(run.finishedAt) - Date.parse(run.startedAt);
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${ms} мс`;
  return `${(ms / 1000).toFixed(1)} с`;
}

function categoryOf(graph: ServerGraph): TemplateCategory {
  const ids = new Set((graph.nodes ?? []).map((node) => node.pluginId));
  if (ids.has("trigger.webhook")) return "ci-cd";
  if (ids.has("scan.secrets") && !ids.has("scan.sca") && !ids.has("scan.sast.kotlin")) return "secrets";
  if (ids.has("sbom.generate") || ids.has("scan.sca")) return "sca-sbom";
  if (ids.has("gate.policy")) return "gate";
  return "benchmark";
}

export function templateRecord(tpl: ServerTemplate): StarterTemplateRecord {
  const board = boardFromGraph(tpl.sanitizedGraph);
  return {
    id: tpl.id,
    slug: tpl.slug,
    name: tpl.name,
    description: tpl.description,
    problemSolved: tpl.problemSolved,
    trigger: triggerOf(tpl.sanitizedGraph),
    category: categoryOf(tpl.sanitizedGraph),
    tags: tpl.tags ?? [],
    isBuiltin: tpl.isBuiltin,
    authorSubject: tpl.authorSubject,
    cloneCount: tpl.cloneCount,
    createdAt: tpl.createdAt ? formatWhen(tpl.createdAt) : "",
    nodes: chips(tpl.sanitizedGraph),
    edges: board.edges.map((edge) => ({
      source: edge.source,
      target: edge.target,
      sourceHandle: edge.sourceHandle ?? undefined,
      label: edge.label,
    })),
    boardGraph: board,
    requiredParams: [],
  };
}

function stepStatus(status: string): WorkflowRunStep["status"] {
  if (status === "RUNNING") return "RUNNING";
  if (status === "FAILED" || status === "CANCELLED") return "FAILED";
  if (status === "SKIPPED") return "WARNING";
  if (status === "SUCCEEDED") return "SUCCEEDED";
  return "IDLE";
}

export function canvasStatus(status: string): CanvasNodeRunStatus {
  if (status === "RUNNING") return "running";
  if (status === "FAILED" || status === "CANCELLED") return "failed";
  if (status === "SKIPPED") return "warning";
  if (status === "SUCCEEDED") return "succeeded";
  return "idle";
}

function mapFindingsStats(stats: ServerRun["findingsStats"]): RunFindingsStats | undefined {
  if (!stats) return undefined;
  return {
    total: stats.total ?? 0,
    newCount: stats.newCount ?? 0,
    critical: stats.critical ?? 0,
    high: stats.high ?? 0,
    medium: stats.medium ?? 0,
    low: stats.low ?? 0,
    secretCount: stats.secretCount ?? 0,
    sastCount: stats.sastCount ?? 0,
    scaCount: stats.scaCount ?? 0,
    maxSeverity: stats.maxSeverity ?? null,
  };
}

function mapSbom(sbom: ServerSbom | null | undefined, runId: string): RunSbomInfo | null {
  if (!sbom) return null;
  return {
    digest: sbom.digest ?? "",
    specVersion: sbom.specVersion || "1.6",
    componentCount: sbom.componentCount ?? 0,
    vulnerabilityCount: sbom.vulnerabilityCount ?? 0,
    downloadUrl: sbom.downloadUrl || `/runs/${runId}/sbom.cdx.json`,
    generatedAt: sbom.generatedAt ?? "",
    format: sbom.format || "CycloneDX",
    s3Key: sbom.s3Key,
  };
}

function mapAIReport(report: ServerAIReport | null | undefined): RunAIReportInfo | null {
  if (!report) return null;
  return {
    quality: report.quality,
    releaseDecision: report.releaseDecision,
    executiveSummary: report.executiveSummary,
    groups: (report.groups ?? []).map((g) => ({
      title: g.title,
      maxSeverity: g.maxSeverity,
      findingIds: g.findingIds ?? [],
      summary: g.summary,
    })),
    items: (report.items ?? []).map((item) => ({
      findingId: item.findingId,
      priorityRank: item.priorityRank,
      plainLanguageRisk: item.plainLanguageRisk,
      businessImpact: item.businessImpact,
      remediationSteps: item.remediationSteps ?? [],
      referencedAdvisories: item.referencedAdvisories ?? [],
      finding: {
        category: item.finding.category,
        path: item.finding.path,
        line: item.finding.line ?? null,
        endLine: item.finding.endLine ?? null,
        findingClass: item.finding.findingClass ?? null,
        group: item.finding.group ?? null,
        artifact: item.finding.artifact ?? null,
        version: item.finding.version ?? null,
        advisoryId: item.finding.advisoryId ?? null,
        severity: item.finding.severity ?? null,
      },
    })),
    modelId: report.modelId,
    providerMode: report.providerMode,
    privacyMode: report.privacyMode,
    strippedHallucinatedAdvisories: report.strippedHallucinatedAdvisories ?? 0,
    cached: Boolean(report.cached),
    promptHash: report.promptHash,
    tokensIn: report.tokensIn,
    tokensOut: report.tokensOut,
    latencyMs: report.latencyMs != null ? Number(report.latencyMs) : undefined,
    createdAt: report.createdAt,
  };
}

function summarizeNodeRun(node: NonNullable<ServerRun["nodeRuns"]>[number]): string {
  if (node.errorMessage) return node.errorMessage;
  if (node.pluginId === "ai.explain" && node.redactedPreview && typeof node.redactedPreview === "object") {
    const preview = node.redactedPreview as Record<string, unknown>;
    const errStatus = typeof preview.errorStatus === "number" ? preview.errorStatus : 0;
    const errCode = typeof preview.errorCode === "string" ? preview.errorCode.trim() : "";
    const errMsg = typeof preview.errorMessage === "string" ? preview.errorMessage.trim() : "";
    if (errStatus > 0 || errMsg) {
      const prefix = errStatus > 0 ? `HTTP ${errStatus}` : errCode || "LLM error";
      return errMsg ? `${prefix}: ${errMsg}` : prefix;
    }
  }
  return node.findingsEmitted ? `Находок: ${node.findingsEmitted}` : node.status;
}

export function runRecord(run: ServerRun): WorkflowRunRecord {
  const steps: WorkflowRunStep[] = (run.nodeRuns ?? []).map((node) => ({
    id: node.nodeRunId || node.nodeId,
    nodeRunId: node.nodeRunId,
    nodeId: node.nodeId,
    nodeLabel: TEMPLATE_BY_PLUGIN_ID[node.pluginId]?.label ?? node.pluginId,
    pluginId: node.pluginId,
    family: familyOf(node.pluginId),
    status: stepStatus(node.status),
    durationMs: Number(node.durationMs ?? 0),
    summary: summarizeNodeRun(node),
    activeOutputPorts: node.activeOutputPorts ?? [],
    redactedPreview: node.redactedPreview,
    findingsEmitted: node.findingsEmitted ?? 0,
  }));
  const trigger = mapTriggerType(run.trigger?.type);
  return {
    id: run.id,
    workflowId: run.workflowId,
    workflowName: run.workflowName || run.workflowId,
    trigger,
    status: run.status,
    policyGate: gateVerdict(run.gateResult?.status),
    startedAt: formatWhen(run.startedAt || run.createdAt),
    durationLabel: durationLabel(run),
    sourceLabel: run.sourceRef?.repoName || run.sourceRef?.repoUrl || "—",
    initiatedBy: run.trigger?.triggeredBy || "—",
    critCount: run.findingsStats?.critical ?? 0,
    highCount: run.findingsStats?.high ?? 0,
    mediumCount: run.findingsStats?.medium ?? 0,
    lowCount: run.findingsStats?.low ?? 0,
    nodesCount: steps.length,
    wavesCount: steps.length,
    steps,
    findingsStats: mapFindingsStats(run.findingsStats),
    sbom: mapSbom(run.sbom, run.id),
    aiReport: mapAIReport(run.aiReport),
    submissionDownloadUrl: run.submissionDownloadUrl || `/runs/${run.id}/submission.json`,
    markdownReportDownloadUrl: run.markdownReportDownloadUrl || `/runs/${run.id}/report.md`,
    htmlReportDownloadUrl: run.htmlReportDownloadUrl || `/runs/${run.id}/report.html`,
    parentRunId: run.parentRunId ?? null,
    rerunFromNodeId: run.rerunFromNodeId ?? null,
    errorMessage: run.errorMessage ?? null,
    lastSeqId: run.lastSeqId != null ? Number(run.lastSeqId) : undefined,
  };
}

export interface NodeRunPaint {
  status: CanvasNodeRunStatus;
  durationMs?: number;
  findings?: number;
  activeOutputPorts?: string[];
  redactedPreview?: unknown;
}

export function statusesFromRun(run: ServerRun): Record<string, NodeRunPaint> {
  const out: Record<string, NodeRunPaint> = {};
  for (const node of run.nodeRuns ?? []) {
    out[node.nodeId] = {
      status: canvasStatus(node.status),
      durationMs: Number(node.durationMs ?? 0),
      findings: node.findingsEmitted ?? 0,
      activeOutputPorts: node.activeOutputPorts,
      redactedPreview: node.redactedPreview,
    };
  }
  return out;
}
