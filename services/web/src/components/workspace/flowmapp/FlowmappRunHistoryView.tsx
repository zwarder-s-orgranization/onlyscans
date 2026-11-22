"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Handle,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  Copy,
  Download,
  FileJson,
  FileText,
  GitBranch,
  History,
  Maximize2,
  Package,
  Play,
  RotateCcw,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Square,
  X,
} from "lucide-react";
import {
  buildGraphFromWorkflow,
  CATEGORY_BY_ID,
  createCanvasNodeFromTemplate,
  TEMPLATE_BY_PLUGIN_ID,
  CANVAS_NODE_CATALOG,
  type CanvasBoardEdge,
  type CanvasBoardNode,
  type CanvasBoardNodeData,
} from "@/data/canvas-nodes-catalog";
import type {
  PolicyVerdict,
  RunStatus,
  TriggerKind,
  WorkflowRecord,
  WorkflowRunRecord,
  WorkflowRunStep,
} from "@/data/workflows-workspace-data";
import { downloadArtifact, gql, QUERIES } from "@/lib/api";
import { NodeCategoryIcon } from "../NodeCategoryIcon";
import {
  FlowmappPastelTriggerIcon,
  FlowmappPolicyPill,
  FlowmappRunStatusText,
} from "./FlowmappChrome";
import { MarkdownReportView } from "./MarkdownReportView";

export interface PreviewNodeData extends CanvasBoardNodeData {
  stepSummary?: string;
  redactedPreview?: unknown;
}

type PreviewFlowNode = Node<PreviewNodeData, "historyPreviewNode">;

type RunDetailTab = "canvas" | "findings" | "report" | "ai" | "sbom";

interface AiExplainErrorInfo {
  status?: number;
  code?: string;
  message: string;
  attemptedModelId?: string;
}

function extractAiExplainError(run: WorkflowRunRecord): AiExplainErrorInfo | null {
  const aiStep = run.steps.find((step) => step.pluginId === "ai.explain");
  if (aiStep?.redactedPreview && typeof aiStep.redactedPreview === "object") {
    const preview = aiStep.redactedPreview as Record<string, unknown>;
    const rawStatus = typeof preview.errorStatus === "number" ? preview.errorStatus : undefined;
    const rawCode = typeof preview.errorCode === "string" ? preview.errorCode.trim() : undefined;
    const rawMessage = typeof preview.errorMessage === "string" ? preview.errorMessage.trim() : "";
    const attemptedModelId =
      typeof preview.attemptedModelId === "string" ? preview.attemptedModelId.trim() : undefined;
    if ((rawStatus && rawStatus > 0) || rawCode || rawMessage) {
      return {
        status: rawStatus && rawStatus > 0 ? rawStatus : undefined,
        code: rawCode || undefined,
        message: rawMessage || rawCode || `HTTP ${rawStatus}`,
        attemptedModelId: attemptedModelId || undefined,
      };
    }
  }
  const summary = run.aiReport?.executiveSummary ?? "";
  const match = summary.match(/^Ошибка ИИ-анализа(?:\s*\(([^)]+)\))?:\s*([^\n]+)/);
  if (match) {
    const tag = (match[1] ?? "").trim();
    const httpMatch = tag.match(/HTTP\s+(\d{3})/i);
    return {
      status: httpMatch ? Number(httpMatch[1]) : undefined,
      code: !httpMatch && tag ? tag : undefined,
      message: match[2].trim(),
    };
  }
  return null;
}

function stripLeadingAiErrorLine(summary: string): string {
  return summary.replace(/^Ошибка ИИ-анализа(?:\s*\([^)]+\))?:\s*[^\n]+(?:\n+)?/, "").trim();
}

function aiQualityBadgeClass(quality: string, hasError: boolean): string {
  if (quality === "VERIFIED") return "bg-[#c8f0d8] text-[#0f5132]";
  if (quality === "FALLBACK" && hasError) return "bg-[#ffd6e0] text-[#842029]";
  return "bg-[#fff3c4] text-[#664d03]";
}

function preferredDetailTab(run: WorkflowRunRecord): RunDetailTab {
  const total = run.findingsStats?.total ?? run.critCount + run.highCount + run.mediumCount + (run.lowCount ?? 0);
  return total > 0 ? "findings" : "canvas";
}

interface ServerFindingItem {
  findingId: string;
  fingerprint: string;
  sourceNodeId: string;
  pluginId: string;
  category: string;
  path: string;
  findingClass?: string | null;
  line?: number | null;
  endLine?: number | null;
  group?: string | null;
  artifact?: string | null;
  version?: string | null;
  advisoryId?: string | null;
  severity?: string | null;
  description?: string | null;
  remediation?: string | null;
  maskedSnippet?: string | null;
  isNewVsBaseline?: boolean;
}

interface ServerNodeRunPayload {
  runId: string;
  nodeId: string;
  pluginId: string;
  status: string;
  inputEnvelope?: unknown;
  outputEnvelope?: unknown;
  activeOutputPorts?: string[];
  portOutputs?: Array<{ sourceHandle: string; outputEnvelope: unknown }>;
}

const RUN_STATUS_FILTER_OPTIONS: Array<{ id: "ALL" | RunStatus; label: string }> = [
  { id: "ALL", label: "Любой статус" },
  { id: "SUCCEEDED", label: "Завершён" },
  { id: "FAILED", label: "Остановлен" },
  { id: "RUNNING", label: "Выполняется" },
  { id: "QUEUED", label: "В очереди" },
  { id: "CANCELLED", label: "Отменён" },
];

const TRIGGER_FILTER_OPTIONS: Array<{
  id: "ALL" | TriggerKind;
  label: string;
  dot?: string;
}> = [
  { id: "ALL", label: "Все триггеры" },
  { id: "Manual", label: "Manual", dot: "#fff3c4" },
  { id: "Webhook", label: "Webhook", dot: "#c8f0d8" },
  { id: "Schedule", label: "Schedule", dot: "#ffe0c4" },
  { id: "CI API", label: "CI API", dot: "#c8f0d8" },
  { id: "MCP", label: "MCP", dot: "#e0d4ff" },
  { id: "Rerun", label: "Rerun", dot: "#c5e0fb" },
];

const GATE_FILTER_OPTIONS: Array<{ id: "ALL" | PolicyVerdict; label: string }> = [
  { id: "ALL", label: "Любой Gate" },
  { id: "FAIL", label: "FAIL" },
  { id: "WARN", label: "WARN" },
  { id: "PASS", label: "PASS" },
];

function pluralRu(count: number, one: string, few: string, many: string): string {
  const mod100 = Math.abs(count) % 100;
  const mod10 = mod100 % 10;
  if (mod100 > 10 && mod100 < 20) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

function getBranchPillTone(port: string): string {
  const normalized = port.toLowerCase();
  if (normalized === "fail" || normalized === "critical") {
    return "bg-[#ffd6e0] text-[#000000] border-[#8c9baa]/50";
  }
  if (normalized === "pass" || normalized === "clean") {
    return "bg-[#c8f0d8] text-[#000000] border-[#8c9baa]/50";
  }
  if (normalized === "warn" || normalized === "high" || normalized === "medium_low") {
    return "bg-[#fff3c4] text-[#000000] border-[#8c9baa]/50";
  }
  if (
    normalized === "true" ||
    normalized === "match" ||
    normalized === "secret" ||
    normalized === "sast" ||
    normalized === "sca"
  ) {
    return "bg-[#c5e0fb] text-[#000000] border-[#8c9baa]/50";
  }
  return "bg-[#ffffff] text-[#222222] border-[#8c9baa]/60";
}

function severityBadgeClass(severity?: string | null): string {
  const sev = (severity || "").toUpperCase();
  if (sev === "CRITICAL") return "bg-[#000000] text-[#ffffff]";
  if (sev === "HIGH") return "bg-[#ffd6e0] text-[#842029]";
  if (sev === "MEDIUM") return "bg-[#fff3c4] text-[#664d03]";
  if (sev === "LOW") return "bg-[#c5e0fb]/70 text-[#000000]";
  return "border border-[#8c9baa]/60 bg-[#ffffff] text-[#636f7b]";
}

function HistoryPreviewNode({ data, selected }: NodeProps<PreviewFlowNode>) {
  const category = CATEGORY_BY_ID[data.family];
  const isRunning = data.runStatus === "running";
  const isSucceeded = data.runStatus === "succeeded";
  const isWarning = data.runStatus === "warning";
  const isFailed = data.runStatus === "failed";
  const hasFinalStatus = isSucceeded || isWarning || isFailed;
  const showBeamRotor = Boolean(isRunning || (selected && !hasFinalStatus));
  const outputs = data.outputs.length > 0 ? data.outputs : ["out"];
  const isMultiOutput = outputs.length > 1;

  const statusBorderClass = isRunning
    ? "border border-[#0080ff]/25"
    : isFailed
      ? "border-[2px] border-[#dc2626] outline outline-2 outline-offset-1 outline-[#dc2626]/25 shadow-[0_2px_8px_rgba(0,0,0,0.06)]"
      : isWarning
        ? "border-[2px] border-[#eab308] outline outline-2 outline-offset-1 outline-[#eab308]/30 shadow-[0_2px_8px_rgba(0,0,0,0.06)]"
        : isSucceeded
          ? "border-[2px] border-[#16a34a] outline outline-2 outline-offset-1 outline-[#16a34a]/25 shadow-[0_2px_8px_rgba(0,0,0,0.06)]"
          : selected
            ? "border border-[#0080ff]/25"
            : "border border-[#8c9baa] hover:border-[#000000]";

  return (
    <div className="relative w-[232px]">
      {showBeamRotor && (
        <>
          <div
            aria-hidden="true"
            className={`pointer-events-none absolute -inset-[5px] z-0 overflow-hidden rounded-[21px] blur-[5px] transition-opacity duration-200 ${
              isRunning ? "opacity-85" : "opacity-55"
            }`}
          >
            <div className={`fm-beam-rotor ${isRunning ? "fm-beam-rotor--running" : ""}`} />
          </div>
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -inset-[2.5px] z-0 overflow-hidden rounded-[18.5px]"
          >
            <div className={`fm-beam-rotor ${isRunning ? "fm-beam-rotor--running" : ""}`} />
          </div>
        </>
      )}

      {data.inputs > 0 && (
        <Handle
          id="in"
          type="target"
          position={Position.Left}
          isConnectable={false}
          className="!z-20"
          style={{ left: -6 }}
        />
      )}

      <div
        className={`relative z-10 flex w-full flex-col rounded-[16px] bg-[#ffffff] text-[#000000] transition-[border-color,box-shadow] duration-200 ${statusBorderClass} ${
          selected && hasFinalStatus ? "ring-2 ring-[#0080ff]/65 ring-offset-2" : ""
        }`}
      >
        <div
          className={`flex items-center justify-between gap-2 rounded-t-[14px] border-b border-[#8c9baa]/35 px-3 py-1.5 ${
            isRunning
              ? "bg-[#c5e0fb]/45"
              : isFailed
                ? "bg-[#ffd6e0]/65"
                : isWarning
                  ? "bg-[#fff3c4]/70"
                  : isSucceeded
                    ? "bg-[#c8f0d8]/50"
                    : "bg-[#ffffff]"
          }`}
        >
          <div className="flex min-w-0 items-center gap-1.5">
            <span
              aria-hidden="true"
              className={`h-2 w-2 shrink-0 rounded-full ${
                isRunning
                  ? "bg-[#0080ff] animate-pulse"
                  : isFailed
                    ? "bg-[#dc2626]"
                    : isWarning
                      ? "bg-[#d97706]"
                      : isSucceeded
                        ? "bg-[#16a34a]"
                        : "border border-[#8c9baa] bg-[#ffffff]"
              }`}
            />
            <span className="truncate text-[11px] font-semibold tracking-[-0.01em] text-[#636f7b]">
              {category.shortLabel}
            </span>
            {isRunning && (
              <span className="fm-tnum shrink-0 text-[11px] font-semibold uppercase leading-none tracking-[0.03em] text-[#0066e6]">
                RUN
              </span>
            )}
            {isSucceeded && (
              <span className="fm-tnum shrink-0 rounded-full bg-[#c8f0d8] px-1.5 py-0.5 text-[11px] font-semibold uppercase leading-none tracking-[0.03em] text-[#0f5132]">
                PASS
              </span>
            )}
            {isWarning && (
              <span className="fm-tnum shrink-0 rounded-full bg-[#fff3c4] px-1.5 py-0.5 text-[11px] font-semibold uppercase leading-none tracking-[0.03em] text-[#664d03]">
                WARN
              </span>
            )}
            {isFailed && (
              <span className="fm-tnum shrink-0 rounded-full bg-[#ffd6e0] px-1.5 py-0.5 text-[11px] font-semibold uppercase leading-none tracking-[0.03em] text-[#842029]">
                FAIL
              </span>
            )}
          </div>
          <span className="fm-tnum shrink-0 rounded-full border border-[#8c9baa]/50 bg-[#ffffff] px-2 py-0.5 text-[11px] font-medium leading-none text-[#222222]">
            {data.durationMs} ms
          </span>
        </div>

        <div
          className={`flex flex-1 flex-col justify-between px-3 py-2.5 ${
            outputs.length >= 4
              ? "min-h-[126px] pr-[96px]"
              : outputs.length === 3
                ? "min-h-[96px] pr-[74px]"
                : isMultiOutput
                  ? "pr-[68px]"
                  : ""
          }`}
        >
          <div className="flex items-start gap-2.5">
            <span
              aria-hidden="true"
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full"
              style={{ backgroundColor: category.flowmappPastel }}
            >
              <NodeCategoryIcon
                iconKey={data.iconKey}
                className="h-3.5 w-3.5 stroke-[1.7] text-[#000000]"
              />
            </span>
            <div className="min-w-0 flex-1">
              <p
                title={data.label}
                className="line-clamp-2 [overflow-wrap:anywhere] text-[13px] font-semibold leading-[1.25] tracking-[-0.015em] text-[#000000]"
              >
                {data.label}
              </p>
              <p title={data.purposeTag} className="mt-0.5 truncate text-[12px] text-[#636f7b]">
                {data.purposeTag}
              </p>
            </div>
          </div>

          <div className="mt-2.5 flex items-center gap-1.5">
            <span
              title={data.pluginId}
              className="fm-mono min-w-0 truncate rounded-[8px] border border-[#8c9baa]/45 bg-[#ffffff] px-2 py-0.5 text-[11px] text-[#636f7b]"
            >
              {data.pluginId}
            </span>
          </div>
        </div>

        {isMultiOutput ? (
          outputs.map((port, idx) => {
            const startPercent = outputs.length >= 4 ? 37 : outputs.length === 2 ? 44 : 41;
            const endPercent = outputs.length >= 4 ? 88 : outputs.length === 2 ? 78 : 85;
            const topPercent = Math.round(
              startPercent + (idx * (endPercent - startPercent)) / Math.max(1, outputs.length - 1),
            );
            return (
              <div key={port}>
                <span
                  className={`fm-mono pointer-events-none absolute right-2.5 -translate-y-1/2 rounded-full border px-1.5 py-0.5 text-[10px] font-semibold uppercase leading-none ${getBranchPillTone(port)}`}
                  style={{ top: `${topPercent}%` }}
                >
                  {port}
                </span>
                <Handle
                  id={port}
                  type="source"
                  position={Position.Right}
                  isConnectable={false}
                  className="!z-20"
                  style={{ top: `${topPercent}%`, right: -6 }}
                />
              </div>
            );
          })
        ) : (
          <Handle
            id={outputs[0]}
            type="source"
            position={Position.Right}
            isConnectable={false}
            className="!z-20"
            style={{ right: -6 }}
          />
        )}
      </div>
    </div>
  );
}

const PREVIEW_NODE_TYPES = {
  historyPreviewNode: HistoryPreviewNode,
};

function buildPreviewGraphForRun(
  run: WorkflowRunRecord,
  workflow: WorkflowRecord | undefined,
  liveBoardGraph?: { nodes: CanvasBoardNode[]; edges: CanvasBoardEdge[] } | null,
): { nodes: PreviewFlowNode[]; edges: Edge[] } {
  const stepByNodeId = new Map<string, WorkflowRunStep>();
  const stepByPlugin = new Map<string, WorkflowRunStep>();
  for (const step of run.steps) {
    if (step.nodeId) {
      stepByNodeId.set(step.nodeId, step);
    }
    stepByPlugin.set(step.pluginId, step);
  }

  let baseNodes: CanvasBoardNode[] = [];
  let baseEdges: CanvasBoardEdge[] = [];

  if (liveBoardGraph && liveBoardGraph.nodes.length > 0) {
    baseNodes = liveBoardGraph.nodes;
    baseEdges = liveBoardGraph.edges;
  } else if (workflow) {
    const built = buildGraphFromWorkflow(workflow);
    baseNodes = built.nodes;
    baseEdges = built.edges;
  } else {
    baseNodes = run.steps.map((step, idx) => {
      const tpl =
        TEMPLATE_BY_PLUGIN_ID[step.pluginId] ??
        CANVAS_NODE_CATALOG.find((item) => item.family === step.family) ??
        CANVAS_NODE_CATALOG[0];
      return createCanvasNodeFromTemplate(
        tpl,
        { x: 64 + idx * 280, y: 180 },
        step.nodeId ?? `${run.id}-${step.id}`,
        step.nodeLabel,
      );
    });
    for (let i = 0; i < baseNodes.length - 1; i++) {
      baseEdges.push({
        id: `e-${baseNodes[i].id}-${baseNodes[i + 1].id}`,
        source: baseNodes[i].id,
        target: baseNodes[i + 1].id,
        sourceHandle: baseNodes[i].data.outputs[0] ?? "out",
        targetHandle: "in",
      });
    }
  }

  const runningNodeIds = new Set<string>();
  const flowNodes: PreviewFlowNode[] = baseNodes.map((n) => {
    const matchedStep = stepByNodeId.get(n.id) ?? stepByPlugin.get(n.data.pluginId);
    const derivedStatus = matchedStep
      ? matchedStep.status === "FAILED"
        ? "failed"
        : matchedStep.status === "WARNING"
          ? "warning"
          : matchedStep.status === "RUNNING"
            ? "running"
            : matchedStep.status === "IDLE"
              ? "idle"
              : "succeeded"
      : run.status === "RUNNING" || run.status === "QUEUED"
        ? "idle"
        : run.policyGate === "FAIL" && n.data.pluginId === "gate.policy"
          ? "failed"
          : run.policyGate === "WARN" && n.data.pluginId === "gate.policy"
            ? "warning"
            : "succeeded";

    if (derivedStatus === "running") {
      runningNodeIds.add(n.id);
    }

    return {
      id: n.id,
      type: "historyPreviewNode",
      position: n.position,
      data: {
        ...n.data,
        durationMs: matchedStep?.durationMs ?? n.data.durationMs,
        runStatus: derivedStatus,
        stepSummary: matchedStep?.summary ?? n.data.description,
        redactedPreview: matchedStep?.redactedPreview,
      },
    };
  });

  const flowEdges: Edge[] = baseEdges.map((e) => {
    const edgeActive = runningNodeIds.has(e.target);
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      sourceHandle: e.sourceHandle ?? undefined,
      targetHandle: e.targetHandle ?? undefined,
      label: e.label,
      type: "bezier",
      animated: edgeActive,
      style: {
        stroke: edgeActive ? "#0050ff" : "#0080ff",
        strokeWidth: edgeActive ? 2.25 : 1.85,
      },
    };
  });

  return { nodes: flowNodes, edges: flowEdges };
}

function RunCanvasPreviewInner({
  run,
  workflow,
  liveBoardGraph,
  canEdit,
  onOpenEditor,
  onReplayRun,
  onCancelRun,
  onRerunFromNode,
  onNotice,
}: {
  run: WorkflowRunRecord;
  workflow?: WorkflowRecord;
  liveBoardGraph?: { nodes: CanvasBoardNode[]; edges: CanvasBoardEdge[] } | null;
  canEdit: boolean;
  onOpenEditor?: (workflowId: string) => void;
  onReplayRun?: (workflow: WorkflowRecord) => void;
  onCancelRun?: (runId: string) => void;
  onRerunFromNode?: (runId: string, nodeId: string) => void;
  onNotice?: (message: string) => void;
}) {
  const { fitView } = useReactFlow();
  const [detailTab, setDetailTab] = useState<RunDetailTab>(() => preferredDetailTab(run));
  const [reportText, setReportText] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportViewMode, setReportViewMode] = useState<"formatted" | "raw">("formatted");
  const [copiedReport, setCopiedReport] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);

  // Real server nodeRunPayload state
  const [nodePayload, setNodePayload] = useState<ServerNodeRunPayload | null>(null);
  const [nodePayloadLoading, setNodePayloadLoading] = useState(false);
  const [payloadViewMode, setPayloadViewMode] = useState<"output" | "input">("output");

  // Real server findings state
  const [findings, setFindings] = useState<ServerFindingItem[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [findingCategoryFilter, setFindingCategoryFilter] = useState<string>("ALL");
  const [findingsFiltersOpen, setFindingsFiltersOpen] = useState(false);
  const findingsFilterRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!findingsFiltersOpen) return;
    const onMouseDown = (event: MouseEvent) => {
      if (
        findingsFilterRef.current &&
        !findingsFilterRef.current.contains(event.target as globalThis.Node)
      ) {
        setFindingsFiltersOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setFindingsFiltersOpen(false);
    };
    window.addEventListener("mousedown", onMouseDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [findingsFiltersOpen]);

  // Artifact download in-flight indicator
  const [downloadingKey, setDownloadingKey] = useState<string | null>(null);

  const { nodes, edges } = useMemo(
    () => buildPreviewGraphForRun(run, workflow, liveBoardGraph),
    [run, workflow, liveBoardGraph],
  );

  // Re-fit view smoothly whenever the user picks a different run or switches back to canvas tab
  useEffect(() => {
    setSelectedNodeId(null);
    setNodePayload(null);
    setPayloadViewMode("output");
    setFindingCategoryFilter("ALL");
    setDetailTab(preferredDetailTab(run));
    setReportText(null);
    setReportError(null);
    setReportViewMode("formatted");
    setCopiedReport(false);
  }, [run.id]);

  useEffect(() => {
    if (detailTab !== "canvas") return;
    const raf = window.requestAnimationFrame(() => {
      void fitView({ padding: 0.22, maxZoom: 1.05, duration: 220 });
    });
    return () => window.cancelAnimationFrame(raf);
  }, [run.id, detailTab, fitView]);

  // Fetch real nodeRunPayload when a node is selected (H1)
  useEffect(() => {
    if (!selectedNodeId) {
      setNodePayload(null);
      setNodePayloadLoading(false);
      return;
    }
    let cancelled = false;
    setNodePayload(null);
    setNodePayloadLoading(true);
    setPayloadViewMode("output");
    gql<{ nodeRunPayload: ServerNodeRunPayload | null }>(QUERIES.nodeRunPayload, {
      runId: run.id,
      nodeId: selectedNodeId,
    })
      .then((res) => {
        if (!cancelled) {
          setNodePayload(res.nodeRunPayload ?? null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setNodePayload(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setNodePayloadLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [run.id, selectedNodeId]);

  // Fetch real findings for the active run (H1)
  useEffect(() => {
    let cancelled = false;
    setFindings([]);
    setFindingsError(null);
    setFindingsLoading(true);
    gql<{ findings: { items: ServerFindingItem[]; totalCount?: number } }>(QUERIES.findings, {
      runId: run.id,
      limit: 100,
    })
      .then((res) => {
        if (!cancelled) {
          setFindings(res.findings?.items ?? []);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setFindingsError(err instanceof Error ? err.message : "Не удалось загрузить находки");
        }
      })
      .finally(() => {
        if (!cancelled) {
          setFindingsLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [run.id, run.status]);

  useEffect(() => {
    if (detailTab !== "report") return;
    let cancelled = false;
    setReportLoading(true);
    setReportError(null);
    gql<{ readableReport: { content: string; findingCount: number } | null }>(QUERIES.readableReport, {
      runId: run.id,
      format: "MARKDOWN",
    })
      .then((res) => {
        if (!cancelled) setReportText(res.readableReport?.content ?? "");
      })
      .catch((err: unknown) => {
        if (!cancelled) setReportError(err instanceof Error ? err.message : "Не удалось загрузить отчёт");
      })
      .finally(() => {
        if (!cancelled) setReportLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [detailTab, run.id, run.status, run.aiReport?.createdAt, run.aiReport?.quality]);

  const aiExplainError = useMemo(() => extractAiExplainError(run), [run]);
  const aiSummaryBody = useMemo(() => {
    const raw = run.aiReport?.executiveSummary ?? "";
    if (!aiExplainError) return raw;
    return stripLeadingAiErrorLine(raw) || raw;
  }, [run.aiReport?.executiveSummary, aiExplainError]);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId],
  );
  const selectedCategory = selectedNode ? CATEGORY_BY_ID[selectedNode.data.family] : null;

  const displayedEnvelope = useMemo(() => {
    if (nodePayload) {
      if (payloadViewMode === "input") {
        return nodePayload.inputEnvelope ?? { note: "Входной Envelope отсутствует (стартовый узел)" };
      }
      if (nodePayload.outputEnvelope !== undefined && nodePayload.outputEnvelope !== null) {
        return nodePayload.outputEnvelope;
      }
      if (nodePayload.portOutputs && nodePayload.portOutputs.length > 0) {
        return Object.fromEntries(
          nodePayload.portOutputs.map((po) => [po.sourceHandle, po.outputEnvelope]),
        );
      }
    }
    if (selectedNode?.data.redactedPreview !== undefined && selectedNode?.data.redactedPreview !== null) {
      return selectedNode.data.redactedPreview;
    }
    return selectedNode?.data.sampleOutput ?? {};
  }, [nodePayload, payloadViewMode, selectedNode]);

  const isRealServerEnvelope = Boolean(
    nodePayload &&
      ((payloadViewMode === "input" && nodePayload.inputEnvelope != null) ||
        (payloadViewMode === "output" &&
          (nodePayload.outputEnvelope != null || (nodePayload.portOutputs?.length ?? 0) > 0))),
  );

  const handleCopyJson = () => {
    if (!selectedNode) return;
    const text = JSON.stringify(displayedEnvelope, null, 2);
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(text);
    }
    setCopiedJson(true);
    onNotice?.("JSON вывода скопирован");
    window.setTimeout(() => setCopiedJson(false), 1500);
  };

  const handleCopyReport = () => {
    if (!reportText) return;
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(reportText);
    }
    setCopiedReport(true);
    onNotice?.("Markdown отчёт скопирован");
    window.setTimeout(() => setCopiedReport(false), 1500);
  };

  const handleDownload = async (key: string, url: string | undefined, fallbackName: string) => {
    if (!url || downloadingKey) return;
    setDownloadingKey(key);
    try {
      await downloadArtifact(url, fallbackName);
      onNotice?.(`Скачан артефакт ${fallbackName}`);
    } catch (err) {
      onNotice?.(err instanceof Error ? err.message : `Не удалось скачать ${fallbackName}`);
    } finally {
      setDownloadingKey(null);
    }
  };

  const filteredFindings = useMemo(() => {
    if (findingCategoryFilter === "ALL") return findings;
    return findings.filter((f) => f.category === findingCategoryFilter);
  }, [findings, findingCategoryFilter]);

  const findingsBadgeCount = run.findingsStats?.total ?? findings.length;
  const isRunActive = run.status === "RUNNING" || run.status === "QUEUED";

  return (
    <div className="relative flex min-h-0 flex-1 flex-col bg-[#ffffff]">
      {/* Compact Run Context Strip above Tabs */}
      <div className="flex min-h-[61px] flex-wrap items-center justify-between gap-2.5 border-b border-[#8c9baa]/40 bg-[#ffffff] px-4 py-2.5">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span
            title={run.workflowName}
            className="max-w-[240px] truncate text-[15px] font-bold tracking-[-0.02em] text-[#000000] sm:max-w-[340px]"
          >
            {run.workflowName}
          </span>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {canEdit && onCancelRun && isRunActive && (
            <button
              type="button"
              onClick={() => onCancelRun(run.id)}
              className="fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-full border border-[#dc2626]/65 bg-[#ffd6e0]/55 px-3 text-[12px] font-semibold text-[#842029] transition-colors hover:bg-[#ffd6e0]"
            >
              <Square className="h-3 w-3 stroke-[2]" aria-hidden="true" />
              <span>Отменить</span>
            </button>
          )}

          {onOpenEditor && workflow && (
            <button
              type="button"
              onClick={() => onOpenEditor(workflow.id)}
              className="fm-btn-outline fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1 px-3 text-[12px] font-medium text-[#222222]"
            >
              <span>Редактор</span>
              <ArrowUpRight className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            </button>
          )}

          {canEdit && onReplayRun && workflow && (
            <button
              type="button"
              disabled={isRunActive}
              onClick={() => onReplayRun(workflow)}
              className="fm-btn-signal fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 px-3.5 text-[12px] font-semibold disabled:cursor-not-allowed disabled:opacity-55"
            >
              <Play className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
              <span>{isRunActive ? "Выполняется…" : "Повторить"}</span>
            </button>
          )}
        </div>
      </div>

      {/* Sub-navigation Tabs + Authenticated Artifact Download Buttons */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#8c9baa]/35 bg-[#ffffff] px-4 py-2">
        <div
          role="tablist"
          aria-label="Разделы отчёта прогона"
          className="inline-flex flex-wrap items-center gap-1 rounded-full border border-[#8c9baa]/60 bg-[#ffffff] p-0.5"
        >
          <button
            type="button"
            role="tab"
            aria-selected={detailTab === "canvas"}
            onClick={() => setDetailTab("canvas")}
            className={`fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12px] font-semibold transition-colors ${
              detailTab === "canvas"
                ? "bg-[#000000] text-[#ffffff]"
                : "text-[#636f7b] hover:text-[#000000]"
            }`}
          >
            <GitBranch className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            <span>Граф</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={detailTab === "findings"}
            onClick={() => setDetailTab("findings")}
            className={`fm-focus fm-tnum inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12px] font-semibold transition-colors ${
              detailTab === "findings"
                ? "bg-[#000000] text-[#ffffff]"
                : "text-[#636f7b] hover:text-[#000000]"
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            <span>Находки</span>
            <span
              className={`rounded-full px-1.5 py-0.5 text-[10.5px] leading-none ${
                detailTab === "findings"
                  ? "bg-[#ffffff]/20 text-[#ffffff]"
                  : "bg-[#c5e0fb]/55 text-[#000000]"
              }`}
            >
              {findingsBadgeCount}
            </span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={detailTab === "report"}
            onClick={() => setDetailTab("report")}
            className={`fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12px] font-semibold transition-colors ${
              detailTab === "report"
                ? "bg-[#000000] text-[#ffffff]"
                : "text-[#636f7b] hover:text-[#000000]"
            }`}
          >
            <FileText className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            <span>Отчёт</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={detailTab === "ai"}
            onClick={() => setDetailTab("ai")}
            className={`fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12px] font-semibold transition-colors ${
              detailTab === "ai"
                ? "bg-[#000000] text-[#ffffff]"
                : "text-[#636f7b] hover:text-[#000000]"
            }`}
          >
            <Sparkles className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            <span>AI-отчёт</span>
            {run.aiReport && (
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10px] leading-none ${
                  detailTab === "ai"
                    ? "bg-[#ffffff]/20 text-[#ffffff]"
                    : aiQualityBadgeClass(run.aiReport.quality, Boolean(aiExplainError))
                }`}
              >
                {aiExplainError?.status ? `HTTP ${aiExplainError.status}` : run.aiReport.quality}
              </span>
            )}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={detailTab === "sbom"}
            onClick={() => setDetailTab("sbom")}
            className={`fm-focus fm-tnum inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12px] font-semibold transition-colors ${
              detailTab === "sbom"
                ? "bg-[#000000] text-[#ffffff]"
                : "text-[#636f7b] hover:text-[#000000]"
            }`}
          >
            <Package className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            <span>SBOM</span>
            {run.sbom && (
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10.5px] leading-none ${
                  detailTab === "sbom"
                    ? "bg-[#ffffff]/20 text-[#ffffff]"
                    : "bg-[#c5e0fb]/55 text-[#000000]"
                }`}
              >
                {run.sbom.componentCount}
              </span>
            )}
          </button>
        </div>

        {/* Authenticated Artifact Downloads */}
        <div className="flex flex-wrap items-center gap-1.5">
          {run.submissionDownloadUrl && (
            <button
              type="button"
              disabled={downloadingKey !== null}
              onClick={() =>
                void handleDownload("submission", run.submissionDownloadUrl, `submission-${run.id}.json`)
              }
              className="fm-focus fm-mono inline-flex min-h-[30px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/65 bg-[#ffffff] px-2.5 text-[11px] font-medium text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0050ff] disabled:opacity-50"
            >
              <Download className="h-3 w-3 stroke-[1.8]" aria-hidden="true" />
              <span>{downloadingKey === "submission" ? "…" : "submission.json"}</span>
            </button>
          )}
          {run.sbom?.downloadUrl && (
            <button
              type="button"
              disabled={downloadingKey !== null}
              onClick={() =>
                void handleDownload("sbom", run.sbom?.downloadUrl, `sbom-${run.id}.cdx.json`)
              }
              className="fm-focus fm-mono inline-flex min-h-[30px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/65 bg-[#ffffff] px-2.5 text-[11px] font-medium text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0050ff] disabled:opacity-50"
            >
              <Download className="h-3 w-3 stroke-[1.8]" aria-hidden="true" />
              <span>{downloadingKey === "sbom" ? "…" : "sbom.cdx.json"}</span>
            </button>
          )}
          {run.markdownReportDownloadUrl && (
            <button
              type="button"
              disabled={downloadingKey !== null}
              onClick={() =>
                void handleDownload("md", run.markdownReportDownloadUrl, `report-${run.id}.md`)
              }
              className="fm-focus fm-mono inline-flex min-h-[30px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/65 bg-[#ffffff] px-2.5 text-[11px] font-medium text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0050ff] disabled:opacity-50"
            >
              <Download className="h-3 w-3 stroke-[1.8]" aria-hidden="true" />
              <span>{downloadingKey === "md" ? "…" : "report.md"}</span>
            </button>
          )}
          {run.htmlReportDownloadUrl && (
            <button
              type="button"
              disabled={downloadingKey !== null}
              onClick={() =>
                void handleDownload("html", run.htmlReportDownloadUrl, `report-${run.id}.html`)
              }
              className="fm-focus fm-mono inline-flex min-h-[30px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/65 bg-[#ffffff] px-2.5 text-[11px] font-medium text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0050ff] disabled:opacity-50"
            >
              <Download className="h-3 w-3 stroke-[1.8]" aria-hidden="true" />
              <span>{downloadingKey === "html" ? "…" : "report.html"}</span>
            </button>
          )}
        </div>
      </div>

      {/* TAB 1: Interactive Read-Only Canvas Preview */}
      {detailTab === "canvas" && (
        <div className="relative min-h-0 flex-1 bg-[#ffffff]">
          <ReactFlow
            nodes={nodes.map((n) => ({ ...n, selected: n.id === selectedNodeId }))}
            edges={edges}
            nodeTypes={PREVIEW_NODE_TYPES}
            onNodeClick={(_, node) => setSelectedNodeId(node.id)}
            onPaneClick={() => setSelectedNodeId(null)}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable
            fitView
            fitViewOptions={{ padding: 0.22, maxZoom: 1.05 }}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={32} size={1.5} color="#e3ebf3" />
          </ReactFlow>

          {/* Top-left floating Fit View + meta pill on canvas */}
          <div className="pointer-events-none absolute left-3 top-3 z-10 flex flex-wrap items-center gap-2">
            <div className="fm-float pointer-events-auto inline-flex items-center gap-1 rounded-full border border-[#8c9baa]/60 px-2 py-1">
              <button
                type="button"
                onClick={() => void fitView({ padding: 0.22, maxZoom: 1.05, duration: 220 })}
                title="Вписать граф в экран"
                className="fm-focus inline-flex min-h-[28px] cursor-pointer items-center gap-1.5 rounded-full px-2.5 text-[12px] font-medium text-[#222222] transition-colors hover:bg-[#c5e0fb]/35 hover:text-[#0050ff] active:scale-[0.98]"
              >
                <Maximize2 className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                <span>По размеру</span>
              </button>
            </div>
            <span className="fm-tnum fm-float hidden rounded-full border border-[#8c9baa]/55 px-3 py-1.5 text-[12px] font-medium text-[#636f7b] md:inline-flex">
              {run.sourceLabel} · {run.initiatedBy} · {run.wavesCount}{" "}
              {pluralRu(run.wavesCount, "волна", "волны", "волн")}
            </span>
          </div>

          {/* Floating Node Output Inspector when user clicks a node on the Canvas Preview */}
          {selectedNode && selectedCategory && (
            <aside
              aria-label="Результат узла прогона"
              className="fm-float absolute bottom-3 right-3 z-20 w-[min(370px,calc(100%-1.5rem))] rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-4"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2.5">
                  <span
                    aria-hidden="true"
                    className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full"
                    style={{ backgroundColor: selectedCategory.flowmappPastel }}
                  >
                    <NodeCategoryIcon
                      iconKey={selectedNode.data.iconKey}
                      className="h-3.5 w-3.5 stroke-[1.7] text-[#000000]"
                    />
                  </span>
                  <div className="min-w-0">
                    <p className="truncate text-[13px] font-semibold text-[#000000]">
                      {selectedNode.data.label}
                    </p>
                    <p className="fm-mono fm-tnum truncate text-[12px] text-[#636f7b]">
                      {selectedNode.data.pluginId} · {selectedNode.data.durationMs} ms
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedNodeId(null)}
                  aria-label="Закрыть карточку узла"
                  className="fm-focus inline-flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/60 text-[#636f7b] hover:border-[#000000] hover:text-[#000000]"
                >
                  <X className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                </button>
              </div>

              {selectedNode.data.stepSummary && (
                <p className="mt-2.5 [overflow-wrap:anywhere] text-[12px] leading-[1.45] text-[#222222]">
                  {selectedNode.data.stepSummary}
                </p>
              )}

              <div className="mt-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] font-semibold text-[#636f7b]">
                      Envelope узла
                    </span>
                    {nodePayload && (
                      <div className="inline-flex rounded-full border border-[#8c9baa]/55 p-0.5 text-[10px]">
                        <button
                          type="button"
                          onClick={() => setPayloadViewMode("output")}
                          className={`cursor-pointer rounded-full px-2 py-0.5 font-semibold ${
                            payloadViewMode === "output"
                              ? "bg-[#000000] text-[#ffffff]"
                              : "text-[#636f7b]"
                          }`}
                        >
                          out
                        </button>
                        <button
                          type="button"
                          onClick={() => setPayloadViewMode("input")}
                          className={`cursor-pointer rounded-full px-2 py-0.5 font-semibold ${
                            payloadViewMode === "input"
                              ? "bg-[#000000] text-[#ffffff]"
                              : "text-[#636f7b]"
                          }`}
                        >
                          in
                        </button>
                      </div>
                    )}
                    {!nodePayloadLoading && !isRealServerEnvelope && (
                      <span className="rounded-full border border-[#8c9baa]/50 px-1.5 py-0.5 text-[10px] text-[#636f7b]">
                        preview
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={handleCopyJson}
                    className="fm-focus inline-flex min-h-[26px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/65 px-2 text-[10.5px] font-medium text-[#222222] hover:border-[#0080ff] hover:text-[#0050ff]"
                  >
                    {copiedJson ? (
                      <>
                        <Check className="h-3 w-3 stroke-[2]" aria-hidden="true" />
                        Скопировано
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3 stroke-[1.7]" aria-hidden="true" />
                        JSON
                      </>
                    )}
                  </button>
                </div>
                <pre className="fm-mono fm-scroll mt-1.5 max-h-[160px] overflow-auto rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc] p-2.5 text-[10.5px] leading-[1.45] text-[#222222]">
                  {nodePayloadLoading
                    ? "Загружаем Envelope с сервера…"
                    : JSON.stringify(displayedEnvelope, null, 2)}
                </pre>
              </div>

              {canEdit && onRerunFromNode && !isRunActive && (
                <div className="mt-3 border-t border-[#8c9baa]/30 pt-2.5">
                  <button
                    type="button"
                    onClick={() => onRerunFromNode(run.id, selectedNode.id)}
                    className="fm-btn-outline fm-focus inline-flex min-h-[34px] w-full cursor-pointer items-center justify-center gap-1.5 px-3 text-[12px] font-semibold text-[#000000]"
                  >
                    <RotateCcw className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                    <span>Перезапустить с этого узла</span>
                  </button>
                </div>
              )}
            </aside>
          )}
        </div>
      )}

      {/* TAB 2: Real Findings Ledger */}
      {detailTab === "findings" && (
        <div className="fm-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 py-4">
          <div className="relative flex flex-wrap items-center justify-between gap-3 border-b border-[#8c9baa]/30 pb-3">
            <div className="fm-tnum inline-flex min-h-[32px] flex-wrap items-center gap-x-4 gap-y-1 rounded-md border border-[#8c9baa]/40 px-3 text-[12px] text-[#636f7b]">
              {(
                [
                  { label: "critical", count: run.findingsStats?.critical ?? run.critCount, dot: "#d92d20" },
                  { label: "high", count: run.findingsStats?.high ?? run.highCount, dot: "#f97316" },
                  { label: "medium", count: run.findingsStats?.medium ?? run.mediumCount, dot: "#facc15" },
                  { label: "low", count: run.findingsStats?.low ?? run.lowCount ?? 0, dot: "#8c9baa" },
                ] as const
              ).map(({ label, count, dot }) => (
                <span key={label} className="inline-flex items-center gap-1.5">
                  <span
                    aria-hidden="true"
                    className="inline-block h-2 w-2 rounded-full"
                    style={{ backgroundColor: dot }}
                  />
                  {label} <span className="font-semibold text-[#000000]">{count}</span>
                </span>
              ))}
            </div>
            <div ref={findingsFilterRef} className="relative shrink-0">
              <button
                type="button"
                onClick={() => setFindingsFiltersOpen((v) => !v)}
                aria-expanded={findingsFiltersOpen}
                className="fm-focus inline-flex min-h-[32px] cursor-pointer items-center gap-2 rounded-md border border-[#8c9baa]/40 px-3 text-[12px] text-[#000000] hover:bg-[#f1f3f5]"
              >
                Фильтры
                {findingCategoryFilter !== "ALL" && (
                  <span className="text-[#636f7b]">· {findingCategoryFilter}</span>
                )}
              </button>
              {findingsFiltersOpen && (
                <div className="absolute right-0 top-full z-20 mt-1 w-[240px] rounded-md border border-[#8c9baa]/40 bg-[#ffffff] p-3 shadow-lg">
                  <div className="flex flex-col">
                    {(
                      [
                        { cat: "ALL", label: "Все", hint: "Показать находки всех типов" },
                        { cat: "SECRET", label: "SECRET", hint: "Утечки секретов: пароли, токены и ключи в коде" },
                        { cat: "SAST", label: "SAST", hint: "Уязвимости в исходном коде (статический анализ)" },
                        { cat: "SCA", label: "SCA", hint: "Уязвимости в сторонних зависимостях и пакетах" },
                      ] as const
                    ).map(({ cat, label, hint }) => (
                      <button
                        key={cat}
                        type="button"
                        title={hint}
                        onClick={() => {
                          setFindingCategoryFilter(cat);
                          setFindingsFiltersOpen(false);
                        }}
                        className={`fm-focus cursor-pointer rounded px-2 py-1.5 text-left text-[12px] hover:bg-[#f1f3f5] ${
                          findingCategoryFilter === cat ? "font-semibold text-[#000000]" : "text-[#636f7b]"
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {findingsLoading ? (
            <p className="py-10 text-center text-[13px] text-[#636f7b]">Загружаем находки прогона…</p>
          ) : findingsError ? (
            <p className="py-10 text-center text-[13px] text-[#842029]">{findingsError}</p>
          ) : filteredFindings.length === 0 ? (
            <p className="py-10 text-center text-[13px] text-[#636f7b]">Находок не обнаружено</p>
          ) : (
            <ul className="divide-y divide-[#8c9baa]/25">
              {filteredFindings.map((item) => {
                const location = item.path
                  ? `${item.path}${item.line ? `:${item.line}${item.endLine && item.endLine !== item.line ? `–${item.endLine}` : ""}` : ""}`
                  : "";
                const pkg =
                  item.group || item.artifact
                    ? `${item.group ?? ""}${item.group && item.artifact ? ":" : ""}${item.artifact ?? ""}${item.version ? `@${item.version}` : ""}`
                    : "";
                const meta = [
                  item.severity || "INFO",
                  item.category,
                  item.advisoryId || item.findingClass,
                  item.isNewVsBaseline ? "NEW" : null,
                ]
                  .filter(Boolean)
                  .join(" · ");
                const sev = (item.severity || "").toUpperCase();
                const sevDot =
                  sev === "CRITICAL"
                    ? "#d92d20"
                    : sev === "HIGH"
                      ? "#f97316"
                      : sev === "MEDIUM"
                        ? "#facc15"
                        : "#8c9baa";
                return (
                  <li key={item.findingId} className="py-3.5">
                    {(location || pkg) && (
                      <p className="fm-mono [overflow-wrap:anywhere] text-[12px] text-[#636f7b]">
                        {location}
                        {location && pkg ? " · " : ""}
                        {pkg}
                      </p>
                    )}
                    <p className="mt-1 flex items-start gap-2 [overflow-wrap:anywhere] text-[13.5px] font-semibold leading-[1.4] text-[#000000]">
                      <span
                        aria-hidden="true"
                        title={sev || "INFO"}
                        className="mt-[5px] inline-block h-2 w-2 shrink-0 rounded-full"
                        style={{ backgroundColor: sevDot }}
                      />
                      <span>{item.description || item.findingId}</span>
                    </p>
                    <p className="mt-1 [overflow-wrap:anywhere] text-[12px] leading-[1.45] text-[#636f7b]">
                      {meta}
                      {item.remediation ? ` — ${item.remediation}` : ""}
                    </p>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}

      {detailTab === "report" && (
        <div className="fm-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain p-4 sm:p-5">
          {reportLoading ? (
            <p className="py-10 text-center text-[13px] text-[#636f7b]">Загружаем отчёт…</p>
          ) : reportError ? (
            <div className="rounded-[16px] border border-[#dc2626]/40 bg-[#ffd6e0]/35 p-4 text-[13px] text-[#842029]">
              {reportError}
            </div>
          ) : (
            <article className="min-w-0 rounded-[20px] border border-[#8c9baa]/70 bg-[#ffffff] p-4 sm:p-6">
              <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-[#8c9baa]/30 pb-3">
                <h2 className="text-[15px] font-semibold tracking-[-0.02em] text-[#000000]">
                  Читаемый отчёт
                </h2>
                {Boolean(reportText?.trim()) && (
                  <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                    <div
                      role="group"
                      aria-label="Режим отображения отчёта"
                      className="inline-flex rounded-full border border-[#8c9baa]/55 p-0.5 text-[11px]"
                    >
                      <button
                        type="button"
                        aria-pressed={reportViewMode === "formatted"}
                        onClick={() => setReportViewMode("formatted")}
                        className={`fm-focus min-h-[26px] cursor-pointer rounded-full px-2.5 font-semibold transition-colors active:scale-[0.98] ${
                          reportViewMode === "formatted"
                            ? "bg-[#000000] text-[#ffffff]"
                            : "text-[#636f7b] hover:text-[#000000]"
                        }`}
                      >
                        Оформленный
                      </button>
                      <button
                        type="button"
                        aria-pressed={reportViewMode === "raw"}
                        onClick={() => setReportViewMode("raw")}
                        className={`fm-focus fm-mono min-h-[26px] cursor-pointer rounded-full px-2.5 font-semibold transition-colors active:scale-[0.98] ${
                          reportViewMode === "raw"
                            ? "bg-[#000000] text-[#ffffff]"
                            : "text-[#636f7b] hover:text-[#000000]"
                        }`}
                      >
                        .md
                      </button>
                    </div>
                    <button
                      type="button"
                      onClick={handleCopyReport}
                      className="fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/65 bg-[#ffffff] px-2.5 text-[11px] font-medium text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0050ff] active:scale-[0.98]"
                    >
                      {copiedReport ? (
                        <>
                          <Check className="h-3 w-3 stroke-[2]" aria-hidden="true" />
                          <span>Скопировано</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3 stroke-[1.7]" aria-hidden="true" />
                          <span>Копировать</span>
                        </>
                      )}
                    </button>
                  </div>
                )}
              </div>

              {!reportText?.trim() ? (
                <p className="py-10 text-center text-[13px] text-[#636f7b]">Отчёт пуст.</p>
              ) : reportViewMode === "formatted" ? (
                <div className="mt-4">
                  <MarkdownReportView content={reportText} />
                </div>
              ) : (
                <pre className="fm-code-block fm-scroll fm-mono mt-4 overflow-x-auto whitespace-pre-wrap [overflow-wrap:anywhere] rounded-[14px] p-4 text-[12.5px] leading-[1.55]">
                  {reportText}
                </pre>
              )}
            </article>
          )}
        </div>
      )}

      {/* TAB 3: Real Grounded AI Report */}
      {detailTab === "ai" && (
        <div className="fm-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain p-4 sm:p-5">
          {!run.aiReport ? (
            <div className="rounded-[20px] border border-[#8c9baa]/60 p-8 text-center">
              <span
                aria-hidden="true"
                className="mx-auto inline-flex h-11 w-11 items-center justify-center rounded-full bg-[#c5e0fb]/50 text-[#000000]"
              >
                <Sparkles className="h-5 w-5 stroke-[1.7]" />
              </span>
              <p className="mt-3 text-[14px] font-semibold text-[#000000]">
                AI-отчёт не сформирован для этого прогона
              </p>
              <p className="mt-1 text-[12.5px] text-[#636f7b]">
                Добавьте узел <span className="fm-mono">ai.explain</span> в граф workflow и
                запустите прогон повторно.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Executive Summary & Grounding Meta */}
              <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4 sm:p-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-[11.5px] font-semibold ${aiQualityBadgeClass(
                        run.aiReport.quality,
                        Boolean(aiExplainError),
                      )}`}
                    >
                      {run.aiReport.quality}
                    </span>
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-[11.5px] font-semibold ${
                        run.aiReport.releaseDecision === "BLOCK"
                          ? "bg-[#ffd6e0] text-[#842029]"
                          : run.aiReport.releaseDecision === "WARN"
                            ? "bg-[#fff3c4] text-[#664d03]"
                            : "bg-[#c8f0d8] text-[#0f5132]"
                      }`}
                    >
                      Решение: {run.aiReport.releaseDecision}
                    </span>
                    {run.aiReport.strippedHallucinatedAdvisories > 0 && (
                      <span className="fm-tnum rounded-full border border-[#8c9baa]/60 bg-[#fff3c4]/70 px-2.5 py-0.5 text-[11px] font-semibold text-[#664d03]">
                        Отсечено галлюцинаций CVE: {run.aiReport.strippedHallucinatedAdvisories}
                      </span>
                    )}
                  </div>
                  <span className="fm-mono [overflow-wrap:anywhere] text-[11px] text-[#636f7b]">
                    {run.aiReport.modelId} · {run.aiReport.providerMode} · {run.aiReport.privacyMode}
                  </span>
                </div>

                {aiExplainError && (
                  <div
                    role="alert"
                    className="mt-3 rounded-[14px] border border-[#e5a3b3] bg-[#fff5f7] p-3.5 text-[#5c1620]"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <AlertTriangle
                        className="h-4 w-4 shrink-0 stroke-[1.9] text-[#b4233a]"
                        aria-hidden="true"
                      />
                      <span className="text-[12.5px] font-semibold text-[#842029]">
                        Ошибка LLM-провайдера — использован шаблонный отчёт (FALLBACK)
                      </span>
                      {aiExplainError.status && (
                        <span className="fm-mono fm-tnum shrink-0 whitespace-nowrap rounded-full bg-[#ffd6e0] px-2 py-0.5 text-[11px] font-semibold text-[#842029]">
                          HTTP {aiExplainError.status}
                        </span>
                      )}
                      {aiExplainError.code && (
                        <span className="fm-mono shrink-0 whitespace-nowrap rounded-full border border-[#e5a3b3] bg-[#ffffff] px-2 py-0.5 text-[11px] font-medium text-[#842029]">
                          {aiExplainError.code}
                        </span>
                      )}
                      {aiExplainError.attemptedModelId && (
                        <span className="fm-mono [overflow-wrap:anywhere] text-[11px] text-[#7a2835]">
                          модель: {aiExplainError.attemptedModelId}
                        </span>
                      )}
                    </div>
                    <p className="fm-mono mt-2 select-text whitespace-pre-wrap [overflow-wrap:anywhere] text-[12px] leading-[1.5] text-[#5c1620]">
                      {aiExplainError.message}
                    </p>
                  </div>
                )}

                <h3 className="mt-3 text-[15px] font-bold tracking-[-0.02em] text-[#000000]">
                  Сводка AI Explain
                </h3>
                <p className="mt-1.5 [overflow-wrap:anywhere] text-[13.5px] leading-[1.55] text-[#222222]">
                  {aiSummaryBody}
                </p>

                <div className="mt-3 flex items-start gap-2 rounded-[12px] border border-[#8c9baa]/45 bg-[#f6faff] px-3 py-2 text-[11.5px] leading-[1.45] text-[#636f7b]">
                  <AlertTriangle
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 stroke-[1.8] text-[#0080ff]"
                    aria-hidden="true"
                  />
                  <span>
                    LLM используется исключительно для объяснения рисков и рекомендаций по
                    подтверждённым <span className="fm-mono">findingId</span> детерминированных
                    анализаторов. Все координаты и CVE перепроверены сервером (grounding).
                  </span>
                </div>
              </div>

              {/* Groups */}
              {run.aiReport.groups.length > 0 && (
                <div className="space-y-2.5">
                  <h4 className="text-[13px] font-semibold text-[#000000]">
                    Группы рисков ({run.aiReport.groups.length})
                  </h4>
                  <div className="grid gap-3 md:grid-cols-2">
                    {run.aiReport.groups.map((grp, idx) => (
                      <div
                        key={`${grp.title}-${idx}`}
                        className="rounded-[16px] border border-[#8c9baa]/65 bg-[#ffffff] p-3.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[13px] font-semibold text-[#000000]">
                            {grp.title}
                          </span>
                          <span
                            className={`rounded-full px-2 py-0.5 text-[10.5px] font-semibold uppercase ${severityBadgeClass(grp.maxSeverity)}`}
                          >
                            {grp.maxSeverity}
                          </span>
                        </div>
                        <p className="mt-1.5 text-[12.5px] leading-[1.45] text-[#636f7b]">
                          {grp.summary}
                        </p>
                        <p className="fm-mono fm-tnum mt-2 text-[11px] text-[#636f7b]">
                          findingIds: {grp.findingIds.join(", ")}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Grounded Items */}
              {run.aiReport.items.length > 0 && (
                <div className="space-y-2.5">
                  <h4 className="text-[13px] font-semibold text-[#000000]">
                    Приоритизированный разбор ({run.aiReport.items.length})
                  </h4>
                  <ol className="space-y-3">
                    {run.aiReport.items.map((item, itemIdx) => {
                      const f = item.finding;
                      const coord = f.path
                        ? `${f.path}${f.line ? `:${f.line}` : ""}`
                        : f.artifact
                          ? `${f.group ?? ""}:${f.artifact}@${f.version ?? ""}`
                          : item.findingId;
                      return (
                        <li
                          key={`${item.findingId}-${itemIdx}`}
                          className="rounded-[16px] border border-[#8c9baa]/70 bg-[#ffffff] p-4"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="fm-tnum rounded-full bg-[#000000] px-2 py-0.5 text-[11px] font-semibold text-[#ffffff]">
                                #{item.priorityRank}
                              </span>
                              <span
                                className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${severityBadgeClass(f.severity)}`}
                              >
                                {f.severity || f.category}
                              </span>
                              <span className="fm-mono text-[11.5px] font-medium text-[#0050ff]">
                                {coord}
                              </span>
                            </div>
                            <span className="fm-mono text-[11px] text-[#636f7b]">
                              {item.findingId}
                            </span>
                          </div>

                          <p className="mt-2 [overflow-wrap:anywhere] text-[13px] font-medium leading-[1.45] text-[#000000]">
                            {item.plainLanguageRisk}
                          </p>
                          {item.businessImpact && (
                            <p className="mt-1 [overflow-wrap:anywhere] text-[12.5px] leading-[1.45] text-[#636f7b]">
                              <span className="font-semibold text-[#222222]">Влияние: </span>
                              {item.businessImpact}
                            </p>
                          )}

                          {item.remediationSteps.length > 0 && (
                            <div className="mt-2.5 rounded-[12px] bg-[#c8f0d8]/30 p-3">
                              <p className="text-[11.5px] font-semibold text-[#0f5132]">
                                Шаги исправления
                              </p>
                              <ul className="mt-1 list-disc space-y-1 pl-4 text-[12px] leading-[1.45] text-[#222222]">
                                {item.remediationSteps.map((step, idx) => (
                                  <li key={idx} className="[overflow-wrap:anywhere]">
                                    {step}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {item.referencedAdvisories.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {item.referencedAdvisories.map((adv) => (
                                <span
                                  key={adv}
                                  className="fm-mono rounded-full border border-[#8c9baa]/60 bg-[#f6faff] px-2.5 py-0.5 text-[11px] font-medium text-[#0050ff]"
                                >
                                  {adv}
                                </span>
                              ))}
                            </div>
                          )}
                        </li>
                      );
                    })}
                  </ol>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Real Product SBOM */}
      {detailTab === "sbom" && (
        <div className="fm-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain p-4 sm:p-5">
          {!run.sbom ? (
            <div className="rounded-[20px] border border-[#8c9baa]/60 p-8 text-center">
              <span
                aria-hidden="true"
                className="mx-auto inline-flex h-11 w-11 items-center justify-center rounded-full bg-[#c5e0fb]/50 text-[#000000]"
              >
                <FileJson className="h-5 w-5 stroke-[1.7]" />
              </span>
              <p className="mt-3 text-[14px] font-semibold text-[#000000]">
                SBOM не сформирован для этого прогона
              </p>
              <p className="mt-1 text-[12.5px] text-[#636f7b]">
                Добавьте узел <span className="fm-mono">sbom.generate</span> в workflow для
                генерации CycloneDX 1.6 SBOM.
              </p>
            </div>
          ) : (
            <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-[16px] font-bold tracking-[-0.02em] text-[#000000]">
                    Product SBOM ({run.sbom.format || "CycloneDX"} {run.sbom.specVersion})
                  </h3>
                  <p className="mt-1 text-[12.5px] text-[#636f7b]">
                    Инвентарь зависимостей прогона {run.id}
                  </p>
                </div>
                <button
                  type="button"
                  disabled={downloadingKey !== null}
                  onClick={() =>
                    void handleDownload("sbom-tab", run.sbom?.downloadUrl, `sbom-${run.id}.cdx.json`)
                  }
                  className="fm-btn-signal fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-4 text-[12.5px] font-semibold disabled:opacity-50"
                >
                  <Download className="h-4 w-4 stroke-[1.8]" aria-hidden="true" />
                  <span>
                    {downloadingKey === "sbom-tab" ? "Скачивание…" : "Скачать sbom.cdx.json"}
                  </span>
                </button>
              </div>

              <dl className="mt-4 grid gap-3 border-t border-[#8c9baa]/35 pt-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-[14px] border border-[#8c9baa]/50 bg-[#f8fafc] p-3">
                  <dt className="text-[11.5px] text-[#636f7b]">Версия спецификации</dt>
                  <dd className="fm-mono mt-1 text-[16px] font-bold text-[#000000]">
                    CycloneDX {run.sbom.specVersion}
                  </dd>
                </div>
                <div className="rounded-[14px] border border-[#8c9baa]/50 bg-[#f8fafc] p-3">
                  <dt className="text-[11.5px] text-[#636f7b]">Компонентов</dt>
                  <dd className="fm-tnum mt-1 text-[16px] font-bold text-[#000000]">
                    {run.sbom.componentCount}
                  </dd>
                </div>
                <div className="rounded-[14px] border border-[#8c9baa]/50 bg-[#f8fafc] p-3">
                  <dt className="text-[11.5px] text-[#636f7b]">Уязвимостей в SBOM</dt>
                  <dd className="fm-tnum mt-1 text-[16px] font-bold text-[#000000]">
                    {run.sbom.vulnerabilityCount}
                  </dd>
                </div>
                <div className="rounded-[14px] border border-[#8c9baa]/50 bg-[#f8fafc] p-3">
                  <dt className="text-[11.5px] text-[#636f7b]">SHA-256 Digest</dt>
                  <dd
                    title={run.sbom.digest}
                    className="fm-mono mt-1 truncate text-[12px] font-medium text-[#222222]"
                  >
                    {run.sbom.digest || "—"}
                  </dd>
                </div>
              </dl>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export interface FlowmappRunHistoryViewProps {
  runs: WorkflowRunRecord[];
  workflows: WorkflowRecord[];
  boardsMap?: Record<string, { nodes: CanvasBoardNode[]; edges: CanvasBoardEdge[] }>;
  liveBoardGraph?: { nodes: CanvasBoardNode[]; edges: CanvasBoardEdge[] } | null;
  lockedWorkflowId?: string | null;
  initialWorkflowFilterId?: string | null;
  focusRunId?: string | null;
  canEdit: boolean;
  onOpenEditor?: (workflowId: string) => void;
  onReplayRun?: (workflow: WorkflowRecord) => void;
  onCancelRun?: (runId: string) => void;
  onRerunFromNode?: (runId: string, nodeId: string) => void;
  onNotice?: (message: string) => void;
}

export function FlowmappRunHistoryView({
  runs,
  workflows,
  boardsMap,
  liveBoardGraph,
  lockedWorkflowId = null,
  initialWorkflowFilterId = null,
  focusRunId = null,
  canEdit,
  onOpenEditor,
  onReplayRun,
  onCancelRun,
  onRerunFromNode,
  onNotice,
}: FlowmappRunHistoryViewProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | RunStatus>("ALL");
  const [gateFilter, setGateFilter] = useState<"ALL" | PolicyVerdict>("ALL");
  const [triggerFilter, setTriggerFilter] = useState<"ALL" | TriggerKind>("ALL");
  const [workflowFilterId, setWorkflowFilterId] = useState<string | null>(
    lockedWorkflowId ?? initialWorkflowFilterId,
  );
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(focusRunId ?? runs[0]?.id ?? null);

  useEffect(() => {
    if (focusRunId) setSelectedRunId(focusRunId);
  }, [focusRunId]);
  const filterPopoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (lockedWorkflowId) {
      setWorkflowFilterId(lockedWorkflowId);
    } else if (initialWorkflowFilterId !== undefined) {
      setWorkflowFilterId(initialWorkflowFilterId);
    }
  }, [lockedWorkflowId, initialWorkflowFilterId]);

  useEffect(() => {
    if (!filtersOpen) return;
    const onMouseDown = (event: MouseEvent) => {
      if (
        filterPopoverRef.current &&
        !filterPopoverRef.current.contains(event.target as globalThis.Node)
      ) {
        setFiltersOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setFiltersOpen(false);
    };
    window.addEventListener("mousedown", onMouseDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [filtersOpen]);

  const effectiveWorkflowFilter = lockedWorkflowId ?? workflowFilterId;

  const filteredRuns = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return runs.filter((run) => {
      if (effectiveWorkflowFilter && run.workflowId !== effectiveWorkflowFilter) return false;
      if (statusFilter !== "ALL" && run.status !== statusFilter) return false;
      if (gateFilter !== "ALL" && run.policyGate !== gateFilter) return false;
      if (triggerFilter !== "ALL" && run.trigger !== triggerFilter) return false;
      if (!q) return true;
      return (
        run.id.toLowerCase().includes(q) ||
        run.workflowName.toLowerCase().includes(q) ||
        run.sourceLabel.toLowerCase().includes(q) ||
        run.initiatedBy.toLowerCase().includes(q)
      );
    });
  }, [runs, searchQuery, effectiveWorkflowFilter, statusFilter, gateFilter, triggerFilter]);

  const activeRun = useMemo(() => {
    const exact = filteredRuns.find((r) => r.id === selectedRunId);
    return exact ?? filteredRuns[0] ?? null;
  }, [filteredRuns, selectedRunId]);

  // Auto-select latest run when a brand new run arrives at index 0
  const latestRunIdRef = useRef<string | undefined>(runs[0]?.id);
  useEffect(() => {
    if (runs[0]?.id && runs[0].id !== latestRunIdRef.current) {
      latestRunIdRef.current = runs[0].id;
      setSelectedRunId(runs[0].id);
    }
  }, [runs]);

  const activeFiltersCount =
    (statusFilter !== "ALL" ? 1 : 0) +
    (gateFilter !== "ALL" ? 1 : 0) +
    (triggerFilter !== "ALL" ? 1 : 0) +
    (!lockedWorkflowId && workflowFilterId ? 1 : 0);

  const resetFilters = () => {
    setSearchQuery("");
    setStatusFilter("ALL");
    setGateFilter("ALL");
    setTriggerFilter("ALL");
    if (!lockedWorkflowId) {
      setWorkflowFilterId(null);
    }
  };

  const activeWorkflowObj = activeRun
    ? workflows.find((w) => w.id === activeRun.workflowId)
    : undefined;

  const effectiveBoardGraph = activeRun
    ? lockedWorkflowId && activeRun.workflowId === lockedWorkflowId
      ? liveBoardGraph
      : (boardsMap?.[activeRun.workflowId] ?? null)
    : null;

  const filteredWorkflowName =
    !lockedWorkflowId && workflowFilterId
      ? workflows.find((w) => w.id === workflowFilterId)?.name ??
        runs.find((r) => r.workflowId === workflowFilterId)?.workflowName ??
        workflowFilterId
      : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden bg-[#ffffff] md:flex-row">
      {/* LEFT SIDEBAR: Run List */}
      <aside
        aria-label="Список прогонов"
        className="flex max-h-[38dvh] w-full shrink-0 flex-col border-b border-[#8c9baa]/50 bg-[#ffffff] md:max-h-none md:w-[272px] md:border-b-0 md:border-r lg:w-[296px]"
      >
        <div className="flex min-h-[61px] shrink-0 items-center gap-2 border-b border-[#8c9baa]/45 px-3.5 py-3">
          <h1 className="text-[18px] font-bold leading-none tracking-[-0.03em] text-[#000000]">
            Запуски
          </h1>
          <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[12px] font-semibold leading-none text-[#222222]">
            {runs.length}
          </span>
        </div>
        {/* Compact Search + Filter Icon */}
        <div className="shrink-0 border-b border-[#8c9baa]/45 p-3">
          <div className="flex items-center gap-1.5">
            <div className="relative min-w-0 flex-1">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 stroke-[1.7] text-[#636f7b]"
                aria-hidden="true"
              />
              <input
                type="search"
                enterKeyHint="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Поиск прогона..."
                aria-label="Поиск прогона"
                className="fm-focus min-h-[40px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] pl-8 pr-8 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[13px] [&::-webkit-search-cancel-button]:appearance-none"
              />
              {searchQuery.length > 0 && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  aria-label="Очистить поиск"
                  className="fm-focus absolute right-1.5 top-1/2 inline-flex h-7 w-7 -translate-y-1/2 cursor-pointer items-center justify-center rounded-full text-[#636f7b] hover:text-[#000000]"
                >
                  <X className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                </button>
              )}
            </div>

            <div ref={filterPopoverRef} className="relative shrink-0">
              <button
                type="button"
                onClick={() => setFiltersOpen((prev) => !prev)}
                aria-expanded={filtersOpen}
                aria-haspopup="dialog"
                aria-label={
                  activeFiltersCount > 0
                    ? `Фильтры прогонов (${activeFiltersCount})`
                    : "Фильтры прогонов"
                }
                title="Фильтры прогонов"
                className={`fm-focus relative inline-flex h-[40px] min-w-[40px] cursor-pointer items-center justify-center gap-1 rounded-full border px-2.5 text-[12px] font-medium transition-colors active:scale-95 ${
                  filtersOpen || activeFiltersCount > 0
                    ? "border-[#0080ff] bg-[#000000] text-[#ffffff]"
                    : "border-[#8c9baa] bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                }`}
              >
                <SlidersHorizontal className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                {activeFiltersCount > 0 && (
                  <span className="fm-tnum inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-[#0080ff] px-1 text-[10px] font-semibold text-[#ffffff]">
                    {activeFiltersCount}
                  </span>
                )}
              </button>

              {filtersOpen && (
                <div
                  role="dialog"
                  aria-label="Фильтры прогонов"
                  className="fm-float absolute right-0 top-[calc(100%+8px)] z-40 w-[min(320px,calc(100vw-2rem))] rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-4 md:left-0 md:right-auto"
                >
                  <div className="flex items-center justify-between gap-2 border-b border-[#8c9baa]/35 pb-2">
                    <span className="text-[13px] font-semibold text-[#000000]">Фильтры</span>
                    <div className="flex items-center gap-1.5">
                      {activeFiltersCount > 0 && (
                        <button
                          type="button"
                          onClick={resetFilters}
                          className="fm-focus cursor-pointer rounded-full px-2 py-0.5 text-[11.5px] font-medium text-[#0050ff] hover:underline"
                        >
                          Сбросить
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => setFiltersOpen(false)}
                        aria-label="Закрыть фильтры"
                        className="fm-focus inline-flex h-7 w-7 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/60 text-[#636f7b] hover:border-[#000000] hover:text-[#000000]"
                      >
                        <X className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-3 space-y-3">
                    <div>
                      <p className="mb-1.5 text-[11.5px] font-semibold text-[#222222]">Статус</p>
                      <div className="flex flex-wrap gap-1.5">
                        {RUN_STATUS_FILTER_OPTIONS.map((item) => (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => setStatusFilter(item.id)}
                            aria-pressed={statusFilter === item.id}
                            className={`fm-focus min-h-[30px] cursor-pointer rounded-full px-2.5 text-[11.5px] font-medium transition-colors ${
                              statusFilter === item.id
                                ? "bg-[#000000] text-[#ffffff]"
                                : "border border-[#8c9baa]/75 text-[#222222] hover:border-[#0080ff]"
                            }`}
                          >
                            {item.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div>
                      <p className="mb-1.5 text-[11.5px] font-semibold text-[#222222]">Триггер</p>
                      <div className="flex flex-wrap gap-1.5">
                        {TRIGGER_FILTER_OPTIONS.map((item) => (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => setTriggerFilter(item.id)}
                            aria-pressed={triggerFilter === item.id}
                            className={`fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full px-2.5 text-[11.5px] font-medium transition-colors ${
                              triggerFilter === item.id
                                ? "bg-[#000000] text-[#ffffff]"
                                : "border border-[#8c9baa]/75 text-[#222222] hover:border-[#0080ff]"
                            }`}
                          >
                            {item.dot && (
                              <span
                                aria-hidden="true"
                                className="h-2 w-2 rounded-full border border-[#000000]/15"
                                style={{ backgroundColor: item.dot }}
                              />
                            )}
                            {item.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div>
                      <p className="mb-1.5 text-[11.5px] font-semibold text-[#222222]">
                        Policy Gate
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {GATE_FILTER_OPTIONS.map((item) => (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => setGateFilter(item.id)}
                            aria-pressed={gateFilter === item.id}
                            className={`fm-focus fm-tnum min-h-[30px] cursor-pointer rounded-full px-2.5 text-[11.5px] font-semibold transition-colors ${
                              gateFilter === item.id
                                ? "bg-[#0066e6] text-[#ffffff]"
                                : "border border-[#8c9baa]/75 text-[#636f7b] hover:border-[#0080ff] hover:text-[#000000]"
                            }`}
                          >
                            {item.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {filteredWorkflowName && (
            <div className="mt-2 flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setWorkflowFilterId(null)}
                className="fm-focus inline-flex min-h-[26px] max-w-full cursor-pointer items-center gap-1.5 rounded-full bg-[#000000] px-2.5 text-[11px] font-medium text-[#ffffff]"
              >
                <span className="truncate">{filteredWorkflowName}</span>
                <X className="h-3 w-3 shrink-0 stroke-[2]" aria-hidden="true" />
              </button>
            </div>
          )}
        </div>

        {/* Scrollable Vertical Run List */}
        <div className="fm-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain">
          {filteredRuns.length === 0 ? (
            <div className="p-6 text-center">
              <p className="text-[13.5px] font-semibold text-[#000000]">Прогоны не найдены</p>
              <p className="mt-1 text-[12px] text-[#636f7b]">
                Запустите workflow или сбросьте фильтры.
              </p>
              {activeFiltersCount > 0 && (
                <button
                  type="button"
                  onClick={resetFilters}
                  className="fm-btn-outline fm-focus mt-3 min-h-[34px] cursor-pointer px-3.5 text-[12px] font-medium"
                >
                  Сбросить
                </button>
              )}
            </div>
          ) : (
            <ul className="divide-y divide-[#8c9baa]/35 border-b border-[#8c9baa]/35">
              {filteredRuns.map((run, index) => {
                const isSelected = activeRun?.id === run.id;
                const runNumber = filteredRuns.length - index;
                return (
                  <li key={run.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedRunId(run.id)}
                      aria-current={isSelected ? "true" : undefined}
                      className={`fm-focus relative flex w-full cursor-pointer flex-col gap-2 px-3.5 py-3.5 text-left transition-colors ${
                        isSelected
                          ? "bg-[#c5e0fb]/30"
                          : "bg-[#ffffff] hover:bg-[#f6faff]"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex min-w-0 items-center gap-2">
                          <span
                            className={`fm-tnum whitespace-nowrap text-[13px] font-semibold tracking-[-0.015em] ${
                              isSelected ? "text-[#0050ff]" : "text-[#000000]"
                            }`}
                          >
                            Прогон #{runNumber}
                          </span>
                          <span className="fm-mono truncate text-[12px] text-[#636f7b]">
                            {run.id}
                          </span>
                        </div>
                        <FlowmappPolicyPill verdict={run.policyGate} />
                      </div>

                      {!lockedWorkflowId && (
                        <div className="flex items-center gap-2">
                          <FlowmappPastelTriggerIcon trigger={run.trigger} />
                          <span
                            title={run.workflowName}
                            className="min-w-0 flex-1 truncate text-[12.5px] font-medium text-[#222222]"
                          >
                            {run.workflowName}
                          </span>
                        </div>
                      )}

                      <div className="flex items-center justify-between gap-2 text-[12px] text-[#636f7b]">
                        <FlowmappRunStatusText status={run.status} />
                        <span className="fm-tnum shrink-0">
                          {run.durationLabel} · {run.startedAt}
                        </span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </aside>

      {/* RIGHT MAIN AREA: Canvas, Findings, AI Report, SBOM */}
      <section
        aria-label="Детали выбранного прогона"
        className="flex min-h-0 min-w-0 flex-1 flex-col bg-[#ffffff]"
      >
        {activeRun ? (
          <ReactFlowProvider>
            <RunCanvasPreviewInner
              run={activeRun}
              workflow={activeWorkflowObj}
              liveBoardGraph={effectiveBoardGraph}
              canEdit={canEdit}
              onOpenEditor={onOpenEditor}
              onReplayRun={onReplayRun}
              onCancelRun={onCancelRun}
              onRerunFromNode={onRerunFromNode}
              onNotice={onNotice}
            />
          </ReactFlowProvider>
        ) : (
          <div className="flex flex-1 flex-col items-center justify-center p-8 text-center">
            <span
              aria-hidden="true"
              className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-[#c5e0fb]/50 text-[#000000]"
            >
              <History className="h-5 w-5 stroke-[1.7]" />
            </span>
            <p className="mt-3 text-[15px] font-semibold text-[#000000]">
              Выберите прогон слева для предпросмотра на canvas
            </p>
            <p className="mt-1 max-w-[40ch] text-[13px] text-[#636f7b]">
              Здесь отображается интерактивный граф выбранного запуска со статусами каждого узла,
              находками, AI-отчётом и SBOM.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
