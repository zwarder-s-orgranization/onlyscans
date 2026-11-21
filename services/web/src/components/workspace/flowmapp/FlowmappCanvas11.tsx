"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState, type ChangeEvent, type KeyboardEvent } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type NodeProps,
} from "@xyflow/react";
import {
  ArrowLeft,
  Check,
  Copy,
  Info,
  KeyRound,
  LayoutGrid,
  Maximize2,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Plus,
  RotateCcw,
  Search,
  SlidersHorizontal,
  Terminal,
  Trash2,
  Undo2,
  Upload,
  X,
} from "lucide-react";
import {
  CATEGORY_BY_ID,
  NODE_CATEGORY_META,
  TEMPLATE_BY_PLUGIN_ID,
  type CanvasBoardEdge,
  type CanvasBoardNode,
  type CanvasBoardNodeData,
} from "@/data/canvas-nodes-catalog";
import type {
  NodeFamily,
  WorkflowRecord,
  WorkflowRunRecord,
} from "@/data/workflows-workspace-data";
import { uploadSource } from "@/lib/api";
import { NodeCategoryIcon } from "../NodeCategoryIcon";
import {
  useCanvasBoardController,
  type CanvasRunCompletedPayload,
  type FlowCanvasNode,
} from "../useCanvasBoardController";
import type { AvailableSecretItem } from "../useWorkflowsWorkspace";
import { FlowmappRunHistoryView } from "./FlowmappRunHistoryView";

export interface FlowmappCanvas11Props {
  workflow: WorkflowRecord;
  runs: WorkflowRunRecord[];
  initialNodes: CanvasBoardNode[];
  initialEdges: CanvasBoardEdge[];
  canEdit: boolean;
  availableSecrets?: AvailableSecretItem[];
  onBack: () => void;
  onRename: (workflowId: string, newName: string) => void;
  onSyncGraph: (boardId: string, nodes: CanvasBoardNode[], edges: CanvasBoardEdge[]) => void;
  onRunCompleted: (payload: CanvasRunCompletedPayload) => void;
  onNotice: (message: string) => void;
  onServerRun?: () => void;
  onCancelRun?: (runId: string) => void;
  onRerunFromNode?: (runId: string, nodeId: string) => void;
  serverRunning?: boolean;
  openHistoryAt?: number;
  nodeRunStatuses?: Record<string, import("@/lib/workflow-map").NodeRunPaint>;
}

type RightSidebarTab = "catalog" | "inspector";
type CanvasWorkspaceMode = "editor" | "history";

const CATEGORY_GRID_IDS: NodeFamily[] = [
  "trigger",
  "source",
  "analyzer",
  "logic",
  "ai",
  "action",
];

const RUN_STATUS_META = {
  idle: { label: "Ожидает", bg: "#ffffff", border: "#8c9baa" },
  running: { label: "Выполняется", bg: "#c5e0fb", border: "#0080ff" },
  succeeded: { label: "PASS", bg: "#c8f0d8", border: "#16a34a" },
  warning: { label: "WARN", bg: "#fff3c4", border: "#eab308" },
  failed: { label: "FAIL", bg: "#ffd6e0", border: "#dc2626" },
} as const;

function pluralRu(count: number, one: string, few: string, many: string): string {
  const mod100 = Math.abs(count) % 100;
  const mod10 = mod100 % 10;
  if (mod100 > 10 && mod100 < 20) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

function getCategoryPillLabel(id: "ALL" | NodeFamily): string {
  if (id === "ALL") return "Все";
  if (id === "ai") return "AI";
  return CATEGORY_BY_ID[id].shortLabel;
}

function getCategoryFullLabel(id: "ALL" | NodeFamily): string {
  if (id === "ALL") return "Все категории узлов";
  return CATEGORY_BY_ID[id].label;
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

function TechnicalBlueprintNode11({ data, selected }: NodeProps<FlowCanvasNode>) {
  const nodeData = data as CanvasBoardNodeData;
  const category = CATEGORY_BY_ID[nodeData.family];
  const isRunning = nodeData.runStatus === "running";
  const isSucceeded = nodeData.runStatus === "succeeded";
  const isWarning = nodeData.runStatus === "warning";
  const isFailed = nodeData.runStatus === "failed";
  const hasFinalStatus = isSucceeded || isWarning || isFailed;
  const showBeamRotor = Boolean(isRunning || (selected && !hasFinalStatus));
  const outputs = nodeData.outputs.length > 0 ? nodeData.outputs : ["out"];
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
      {/* Animated Luminous Perimeter Contour during Runtime (or idle selection) */}
      {showBeamRotor && (
        <>
          <div
            aria-hidden="true"
            className={`pointer-events-none absolute -inset-[5px] z-0 overflow-hidden rounded-[21px] blur-[5px] transition-opacity duration-200 ${
              isRunning ? "opacity-85" : "opacity-55"
            }`}
          >
            <div
              className={`fm-beam-rotor ${isRunning ? "fm-beam-rotor--running" : ""}`}
            />
          </div>
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -inset-[2.5px] z-0 overflow-hidden rounded-[18.5px]"
          >
            <div
              className={`fm-beam-rotor ${isRunning ? "fm-beam-rotor--running" : ""}`}
            />
          </div>
        </>
      )}

      {nodeData.inputs > 0 && (
        <Handle
          id="in"
          type="target"
          position={Position.Left}
          aria-label="Входной порт узла"
          className="!z-20"
          style={{ left: -6 }}
        />
      )}

      <div
        className={`relative z-10 w-full rounded-[16px] bg-[#ffffff] text-[#000000] transition-[border-color,box-shadow] duration-200 ${statusBorderClass} ${
          selected && hasFinalStatus ? "ring-2 ring-[#0080ff]/65 ring-offset-2" : ""
        }`}
      >
        {/* Top technical status bar */}
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
            {isSucceeded && (nodeData.findingsEmitted ?? 0) > 0 && (
              <span className="fm-tnum shrink-0 rounded-full bg-[#ffd6e0] px-1.5 py-0.5 text-[11px] font-semibold uppercase leading-none tracking-[0.03em] text-[#842029]">
                {nodeData.findingsEmitted}
              </span>
            )}
            {isSucceeded && (nodeData.findingsEmitted ?? 0) === 0 && (
              <span className="fm-tnum shrink-0 rounded-full bg-[#c8f0d8] px-1.5 py-0.5 text-[11px] font-semibold uppercase leading-none tracking-[0.03em] text-[#0f5132]">
                OK
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
            {nodeData.durationMs} ms
          </span>
        </div>

        {/* Main blueprint body */}
        <div
          className={`px-3 py-2.5 ${
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
                iconKey={nodeData.iconKey}
                className="h-3.5 w-3.5 stroke-[1.7] text-[#000000]"
              />
            </span>
            <div className="min-w-0 flex-1">
              <p
                title={nodeData.label}
                className="line-clamp-2 [overflow-wrap:anywhere] text-[13px] font-semibold leading-[1.25] tracking-[-0.015em] text-[#000000]"
              >
                {nodeData.label}
              </p>
              <p title={nodeData.purposeTag} className="mt-0.5 truncate text-[12px] text-[#636f7b]">
                {nodeData.purposeTag}
              </p>
            </div>
          </div>

          <div className="mt-2.5 flex items-center gap-1.5">
            <span
              title={nodeData.pluginId}
              className="fm-mono min-w-0 truncate rounded-[8px] border border-[#8c9baa]/45 bg-[#ffffff] px-2 py-0.5 text-[11px] text-[#636f7b]"
            >
              {nodeData.pluginId}
            </span>
          </div>
        </div>

        {/* Output ports (single or dynamically distributed labeled branch ports) */}
        {isMultiOutput ? (
          outputs.map((port, idx) => {
            const topPercent =
              outputs.length === 1
                ? 56
                : Math.round(26 + (idx * 54) / (outputs.length - 1));
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
                  aria-label={`Выходной порт ${port}`}
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
            aria-label="Выходной порт узла"
            className="!z-20"
            style={{ right: -6 }}
          />
        )}
      </div>
    </div>
  );
}

const NODE_TYPES = {
  secflowNode: TechnicalBlueprintNode11,
};

function FlowmappCanvas11Inner({
  workflow,
  runs,
  initialNodes,
  initialEdges,
  canEdit,
  availableSecrets = [],
  onBack,
  onRename,
  onSyncGraph,
  onRunCompleted,
  onNotice,
  onServerRun,
  onCancelRun,
  onRerunFromNode,
  serverRunning = false,
  openHistoryAt = 0,
  nodeRunStatuses,
}: FlowmappCanvas11Props) {
  const ctrl = useCanvasBoardController({
    boardId: workflow.id,
    initialNodes,
    initialEdges,
    canEdit,
    policyGate: workflow.policyGate,
    edgeType: "bezier",
    edgeColor: "#0080ff",
    activeEdgeColor: "#0050ff",
    onSyncGraph,
    onRunCompleted,
    onNotice,
    nodeRunStatuses,
  });

  const [titleDraft, setTitleDraft] = useState(workflow.name);
  const [workspaceMode, setWorkspaceMode] = useState<CanvasWorkspaceMode>("editor");

  useEffect(() => {
    if (openHistoryAt > 0) setWorkspaceMode("history");
  }, [openHistoryAt]);
  const [sidebarTab, setSidebarTab] = useState<RightSidebarTab>("catalog");
  const [rightSidebarOpen, setRightSidebarOpen] = useState(true);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [infoPinned, setInfoPinned] = useState(false);
  const [uploadingSource, setUploadingSource] = useState(false);
  const [uploadStatusText, setUploadStatusText] = useState<string | null>(null);
  const [uploadErrorText, setUploadErrorText] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setUploadStatusText(null);
    setUploadErrorText(null);
  }, [ctrl.selectedNodeId]);

  useEffect(() => {
    setTitleDraft(workflow.name);
  }, [workflow.id, workflow.name]);

  useEffect(() => {
    if (!mobileSidebarOpen) return;
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        setMobileSidebarOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [mobileSidebarOpen]);

  // Keyboard shortcuts: Delete removes selected node(s)/edge(s); Ctrl+Z (or Cmd+Z) restores via undo stack
  useEffect(() => {
    if (!canEdit) return;
    const isEditableTarget = (target: EventTarget | null): boolean => {
      if (!(target instanceof HTMLElement)) return false;
      const tag = target.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
      return target.isContentEditable || target.closest("[contenteditable='true']") !== null;
    };

    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (isEditableTarget(e.target)) return;

      // Ctrl+Z / Cmd+Z (uses physical KeyZ so Russian keyboard layout Ctrl+Я works too)
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.code === "KeyZ") {
        if (ctrl.canUndo) {
          e.preventDefault();
          ctrl.undo();
        }
        return;
      }

      const isRemoveKey =
        (e.key === "Delete" || e.key === "Backspace") &&
        !e.ctrlKey &&
        !e.metaKey &&
        !e.altKey &&
        !e.shiftKey;
      if (isRemoveKey) {
        const selectedEdgeIds = ctrl.edges.filter((edge) => edge.selected).map((edge) => edge.id);
        const selectedNodeIds = ctrl.nodes.filter((node) => node.selected).map((node) => node.id);
        if (selectedEdgeIds.length > 0) {
          e.preventDefault();
          ctrl.deleteEdgesByIds(selectedEdgeIds);
          return;
        }
        if (selectedNodeIds.length > 0) {
          e.preventDefault();
          ctrl.deleteNodesByIds(selectedNodeIds);
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [canEdit, ctrl]);

  const commitTitle = () => {
    const trimmed = titleDraft.trim();
    if (!trimmed) {
      setTitleDraft(workflow.name);
      return;
    }
    if (trimmed !== workflow.name) {
      onRename(workflow.id, trimmed);
      onNotice(`Доска переименована в «${trimmed}»`);
    }
  };

  const handleTitleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.currentTarget.blur();
    } else if (e.key === "Escape") {
      setTitleDraft(workflow.name);
      e.currentTarget.blur();
    }
  };

  const handleCopySampleOutput = useCallback(() => {
    if (!ctrl.selectedNode) return;
    const text = JSON.stringify(ctrl.selectedNode.data.sampleOutput, null, 2);
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(text);
    }
    setCopiedJson(true);
    onNotice("JSON sampleOutput скопирован");
    window.setTimeout(() => setCopiedJson(false), 1600);
  }, [ctrl.selectedNode, onNotice]);

  const handleSourceFileChange = useCallback(
    async (e: ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      e.target.value = "";
      if (!file || !canEdit || !ctrl.selectedNode) return;
      const targetNodeId = ctrl.selectedNode.id;
      setUploadingSource(true);
      setUploadErrorText(null);
      setUploadStatusText(`Загружаем «${file.name}»…`);
      try {
        const result = await uploadSource(file);
        ctrl.updateNodeConfig(targetNodeId, "sourceId", result.sourceId);
        const dedupNote = result.deduplicatedHit ? " (из кэша)" : "";
        setUploadStatusText(
          `Загружен: ${result.repoName || file.name} · ${result.fileCount} файлов${dedupNote}`,
        );
        onNotice(`Архив загружен (${result.sourceId})`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Не удалось загрузить архив";
        setUploadStatusText(null);
        setUploadErrorText(msg);
        onNotice(msg);
      } finally {
        setUploadingSource(false);
      }
    },
    [canEdit, ctrl, onNotice],
  );

  const selectedNode = ctrl.selectedNode;
  const selectedCategory = selectedNode ? CATEGORY_BY_ID[selectedNode.data.family] : null;
  const selectedStatusMeta = selectedNode ? RUN_STATUS_META[selectedNode.data.runStatus] : null;
  const configEntries = selectedNode ? Object.entries(selectedNode.data.config) : [];
  const selectedTemplate = selectedNode ? TEMPLATE_BY_PLUGIN_ID[selectedNode.data.pluginId] : null;
  const requiredSecretKeys =
    selectedNode?.data.requiredSecretKeys?.length
      ? selectedNode.data.requiredSecretKeys
      : (selectedTemplate?.requiredSecretKeys ?? []);
  const optionalSecretKeys =
    selectedNode?.data.optionalSecretKeys?.length
      ? selectedNode.data.optionalSecretKeys
      : (selectedTemplate?.optionalSecretKeys ?? []);
  const secretKeysToRender = [
    ...requiredSecretKeys.map((paramKey) => ({ paramKey, required: true })),
    ...optionalSecretKeys
      .filter((paramKey) => !requiredSecretKeys.includes(paramKey))
      .map((paramKey) => ({ paramKey, required: false })),
  ];

  const renderUnifiedRightSidebar = (isMobileDrawer: boolean) => (
    <div
      className="flex h-full flex-col bg-[#ffffff]"
      style={
        isMobileDrawer
          ? {
              paddingTop: "env(safe-area-inset-top, 0px)",
              paddingBottom: "env(safe-area-inset-bottom, 0px)",
            }
          : undefined
      }
    >
      {/* Top 2-Tab Pill Switcher (Каталог нод | Инспектор ноды) + Collapse Button */}
      <div className="shrink-0 border-b border-[#8c9baa]/45 px-3.5 py-3">
        <div className="flex items-center justify-between gap-2">
          <div
            role="tablist"
            aria-label="Режим правой панели"
            className="grid flex-1 grid-cols-2 rounded-full border border-[#8c9baa]/70 bg-[#ffffff] p-1"
          >
            <button
              type="button"
              role="tab"
              aria-selected={sidebarTab === "catalog"}
              onClick={() => setSidebarTab("catalog")}
              className={`fm-focus min-h-[34px] cursor-pointer rounded-full px-2 text-[12px] font-semibold transition-colors ${
                sidebarTab === "catalog"
                  ? "bg-[#000000] text-[#ffffff]"
                  : "text-[#636f7b] hover:text-[#000000]"
              }`}
            >
              Каталог нод (DnD)
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={sidebarTab === "inspector"}
              onClick={() => setSidebarTab("inspector")}
              className={`fm-focus inline-flex min-h-[34px] cursor-pointer items-center justify-center gap-1.5 rounded-full px-2 text-[12px] font-semibold transition-colors ${
                sidebarTab === "inspector"
                  ? "bg-[#000000] text-[#ffffff]"
                  : "text-[#636f7b] hover:text-[#000000]"
              }`}
            >
              <span>Инспектор ноды</span>
              {selectedNode && (
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 rounded-full ${
                    sidebarTab === "inspector" ? "bg-[#c5e0fb]" : "bg-[#0080ff]"
                  }`}
                />
              )}
            </button>
          </div>

          {isMobileDrawer ? (
            <button
              type="button"
              onClick={() => setMobileSidebarOpen(false)}
              aria-label="Закрыть панель"
              className="fm-focus inline-flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] text-[#222222] transition-transform active:scale-95 hover:border-[#0080ff]"
            >
              <X className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setRightSidebarOpen(false)}
              aria-label="Свернуть правую панель"
              title="Свернуть панель"
              className="fm-focus inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/75 text-[#636f7b] transition-colors active:scale-95 hover:border-[#0080ff] hover:text-[#0080ff]"
            >
              <PanelRightClose className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      {/* TAB 1: Node Palette from v11 (moved to right sidebar) */}
      {sidebarTab === "catalog" && (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="shrink-0 border-b border-[#8c9baa]/45 px-3.5 pb-3 pt-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[13px] font-semibold tracking-[-0.015em] text-[#000000]">
                Палитра узлов
              </span>
              <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[11px] font-medium text-[#636f7b]">
                {ctrl.filteredCatalog.length} / {ctrl.categoryCounts.ALL}
              </span>
            </div>

            {/* Search box */}
            <div className="relative mt-2.5">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 stroke-[1.7] text-[#636f7b]"
                aria-hidden="true"
              />
              <input
                type="search"
                enterKeyHint="search"
                value={ctrl.paletteQuery}
                onChange={(e) => ctrl.setPaletteQuery(e.target.value)}
                placeholder="Поиск ноды или pluginId..."
                aria-label="Поиск нод в палитре"
                className="fm-focus min-h-[40px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] pl-8 pr-3 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:min-h-[38px] sm:text-[13px]"
              />
            </div>

            {/* Symmetrical Category Grid (Full-width ALL + 2x3 balanced categories) */}
            <div
              role="group"
              aria-label="Фильтр категорий палитры"
              className="mt-2.5 space-y-1.5"
            >
              <button
                type="button"
                title={getCategoryFullLabel("ALL")}
                onClick={() => ctrl.setCategoryFilter("ALL")}
                aria-pressed={ctrl.categoryFilter === "ALL"}
                className={`fm-focus fm-tnum flex min-h-[30px] w-full cursor-pointer items-center justify-between gap-2 rounded-full px-3 text-[11.5px] font-medium transition-colors active:scale-[0.98] ${
                  ctrl.categoryFilter === "ALL"
                    ? "bg-[#000000] text-[#ffffff]"
                    : "border border-[#8c9baa]/65 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                }`}
              >
                <span className="inline-flex min-w-0 items-center gap-1.5">
                  <span
                    aria-hidden="true"
                    className="h-2 w-2 shrink-0 rounded-full border border-[#000000]/15 bg-[#c5e0fb]"
                  />
                  <span className="truncate">Все категории</span>
                </span>
                <span
                  className={
                    ctrl.categoryFilter === "ALL" ? "text-[#c5e0fb]" : "text-[#636f7b]"
                  }
                >
                  {ctrl.categoryCounts.ALL}
                </span>
              </button>

              <div className="grid grid-cols-2 gap-1.5">
                {CATEGORY_GRID_IDS.map((id) => {
                  const active = ctrl.categoryFilter === id;
                  const pastel = CATEGORY_BY_ID[id].flowmappPastel;
                  return (
                    <button
                      key={id}
                      type="button"
                      title={getCategoryFullLabel(id)}
                      onClick={() => ctrl.setCategoryFilter(id)}
                      aria-pressed={active}
                      className={`fm-focus fm-tnum flex min-h-[30px] w-full min-w-0 cursor-pointer items-center justify-between gap-1.5 rounded-full px-2.5 text-[11.5px] font-medium transition-colors active:scale-[0.98] ${
                        active
                          ? "bg-[#000000] text-[#ffffff]"
                          : "border border-[#8c9baa]/65 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                      }`}
                    >
                      <span className="inline-flex min-w-0 items-center gap-1.5">
                        <span
                          aria-hidden="true"
                          className="h-2 w-2 shrink-0 rounded-full border border-[#000000]/15"
                          style={{ backgroundColor: pastel }}
                        />
                        <span className="truncate">{getCategoryPillLabel(id)}</span>
                      </span>
                      <span className={`shrink-0 ${active ? "text-[#c5e0fb]" : "text-[#636f7b]"}`}>
                        {ctrl.categoryCounts[id]}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Dense scannable draggable rows */}
          <div className="fm-scroll flex-1 space-y-1.5 overflow-y-auto overscroll-contain p-3">
            {ctrl.filteredCatalog.length === 0 ? (
              <div className="rounded-[16px] border border-[#8c9baa]/55 p-4 text-center">
                <p className="text-[13px] font-semibold text-[#000000]">Узлы не найдены</p>
                <p className="mt-1 text-[12px] text-[#636f7b]">
                  Сбросьте поиск или переключите категорию.
                </p>
                <button
                  type="button"
                  onClick={() => {
                    ctrl.setPaletteQuery("");
                    ctrl.setCategoryFilter("ALL");
                  }}
                  className="fm-btn-outline fm-focus mt-2.5 min-h-[34px] cursor-pointer px-3 text-[12px] font-medium"
                >
                  Показать все ({NODE_CATEGORY_META.length} групп)
                </button>
              </div>
            ) : (
              ctrl.filteredCatalog.map((tpl) => {
                const cat = CATEGORY_BY_ID[tpl.family];
                return (
                  <div
                    key={tpl.pluginId}
                    draggable={canEdit}
                    onDragStart={(e) => ctrl.onDragStartNode(e, tpl.pluginId)}
                    className={`group flex select-none items-center gap-2.5 rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 py-2 transition-colors ${
                      canEdit
                        ? "cursor-grab hover:border-[#0080ff] hover:bg-[#f6faff] active:cursor-grabbing"
                        : "opacity-85"
                    }`}
                  >
                    <span
                      aria-hidden="true"
                      className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full"
                      style={{ backgroundColor: cat.flowmappPastel }}
                    >
                      <NodeCategoryIcon
                        iconKey={tpl.iconKey}
                        className="h-3.5 w-3.5 stroke-[1.7] text-[#000000]"
                      />
                    </span>

                    <div className="min-w-0 flex-1">
                      <p
                        title={tpl.label}
                        className="truncate text-[13px] font-semibold leading-[1.2] tracking-[-0.015em] text-[#000000]"
                      >
                        {tpl.shortLabel}
                      </p>
                      <p
                        title={tpl.purposeTag}
                        className="mt-0.5 truncate text-[12px] leading-[1.25] text-[#636f7b]"
                      >
                        {tpl.purposeTag}
                      </p>
                      <p
                        title={tpl.pluginId}
                        className="fm-mono mt-0.5 truncate text-[12px] leading-[1.2] text-[#636f7b]"
                      >
                        {tpl.pluginId}
                      </p>
                    </div>

                    <button
                      type="button"
                      disabled={!canEdit}
                      onClick={() => {
                        ctrl.addTemplateNode(tpl);
                        if (isMobileDrawer) setMobileSidebarOpen(false);
                      }}
                      aria-label={`Добавить узел ${tpl.label}`}
                      title={canEdit ? `Добавить «${tpl.label}» на холст` : "Режим просмотра"}
                      className="fm-focus inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/75 bg-[#ffffff] text-[#222222] transition-colors active:scale-95 hover:border-[#0066e6] hover:bg-[#0066e6] hover:text-[#ffffff] disabled:cursor-not-allowed disabled:opacity-40 sm:h-7 sm:w-7"
                    >
                      <Plus className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
                    </button>
                  </div>
                );
              })
            )}
          </div>

          <div className="border-t border-[#8c9baa]/40 px-3.5 py-2 text-[12px] text-[#636f7b]">
            {canEdit
              ? "Перетащите узел на чертёж или нажмите «+» для авто-связи."
              : "Режим просмотра (Viewer): редактирование графа отключено."}
          </div>
        </div>
      )}

      {/* TAB 2: Node Inspector styled like v08 (FlowmappCanvas3) */}
      {sidebarTab === "inspector" && (
        <div
          className="fm-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-4"
          style={{ paddingBottom: "calc(1.25rem + env(safe-area-inset-bottom, 0px))" }}
        >
          {!selectedNode || !selectedCategory || !selectedStatusMeta ? (
            <div className="rounded-[20px] border border-[#8c9baa]/75 p-6 text-center">
              <span
                aria-hidden="true"
                className="mx-auto inline-flex h-10 w-10 items-center justify-center rounded-full bg-[#c5e0fb]/60 text-[#000000]"
              >
                <SlidersHorizontal className="h-4 w-4 stroke-[1.7]" />
              </span>
              <p className="mt-3 text-[15px] font-semibold text-[#000000]">Нода не выбрана</p>
              <p className="mt-1.5 text-[13px] leading-[1.45] text-[#636f7b]">
                Кликните любую ноду на холсте, чтобы изменить её параметры и посмотреть структуру
                вывода.
              </p>
              <button
                type="button"
                onClick={() => setSidebarTab("catalog")}
                className="fm-btn-outline fm-focus mt-4 min-h-[38px] cursor-pointer px-4 text-[13px] font-medium"
              >
                Перейти в каталог нод
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Card 1: Node identity, status pill, editable name, runtime/plugin meta */}
              <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <span
                      aria-hidden="true"
                      className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-[#000000]"
                      style={{ backgroundColor: selectedCategory.flowmappPastel }}
                    >
                      <NodeCategoryIcon
                        iconKey={selectedNode.data.iconKey}
                        className="h-4 w-4 stroke-[1.7]"
                      />
                    </span>
                    <span
                      title={`${selectedCategory.shortLabel} • ${selectedNode.data.purposeTag}`}
                      className="inline-flex max-w-[165px] items-center gap-1 truncate rounded-full border border-[#8c9baa]/70 px-2.5 py-0.5 text-[10px]"
                    >
                      <span className="font-semibold uppercase tracking-[0.03em] text-[#000000]">
                        {selectedCategory.shortLabel}
                      </span>
                      <span className="text-[#8c9baa]" aria-hidden="true">
                        •
                      </span>
                      <span className="truncate font-medium text-[#636f7b]">
                        {selectedNode.data.purposeTag}
                      </span>
                    </span>
                  </div>

                  <span
                    className="inline-flex shrink-0 items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold text-[#000000]"
                    style={{
                      backgroundColor: selectedStatusMeta.bg,
                      borderColor: selectedStatusMeta.border,
                    }}
                  >
                    {selectedStatusMeta.label}
                  </span>
                </div>

                {/* Editable Label */}
                <div className="mt-4">
                  <label
                    htmlFor={`fm11-node-label-${selectedNode.id}`}
                    className="block text-[12px] font-semibold text-[#000000]"
                  >
                    Название ноды
                  </label>
                  <input
                    id={`fm11-node-label-${selectedNode.id}`}
                    type="text"
                    maxLength={120}
                    enterKeyHint="done"
                    value={selectedNode.data.label}
                    readOnly={!canEdit}
                    onChange={(e) => ctrl.updateNodeLabel(selectedNode.id, e.target.value)}
                    className="fm-focus mt-1.5 min-h-[40px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] font-medium text-[#000000] read-only:bg-[#f8fafc] read-only:text-[#636f7b] sm:text-[13px]"
                  />
                </div>

                {/* Runtime & Plugin metadata */}
                <dl className="mt-3.5 grid grid-cols-2 gap-2.5 border-t border-[#8c9baa]/35 pt-3 text-[12px]">
                  <div className="min-w-0">
                    <dt className="text-[11px] text-[#636f7b]">Среда выполнения</dt>
                    <dd
                      title={selectedNode.data.runtime}
                      className="mt-0.5 truncate font-medium text-[#000000]"
                    >
                      {selectedNode.data.runtime}
                    </dd>
                  </div>
                  <div className="min-w-0">
                    <dt className="text-[11px] text-[#636f7b]">Плагин / время</dt>
                    <dd
                      title={`${selectedNode.data.pluginId} · ${selectedNode.data.durationMs} мс`}
                      className="fm-mono fm-tnum mt-0.5 truncate text-[11px] text-[#222222]"
                    >
                      {selectedNode.data.pluginId} · {selectedNode.data.durationMs} мс
                    </dd>
                  </div>
                </dl>
              </div>

              {/* Card 2: Editable Config fields */}
              <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4">
                <h3 className="text-[13px] font-semibold text-[#000000]">Параметры узла</h3>

                {/* ZIP / tar.gz upload for source.upload */}
                {selectedNode.data.pluginId === "source.upload" && (
                  <div className="mt-3 rounded-[14px] border border-[#8c9baa]/60 bg-[#f6faff] p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[12px] font-semibold text-[#000000]">
                        Архив исходного кода
                      </span>
                      <span className="fm-mono text-[11px] text-[#636f7b]">.zip / .tar.gz</span>
                    </div>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".zip,.tar,.tar.gz,.tgz"
                      disabled={!canEdit || uploadingSource}
                      onChange={(e) => void handleSourceFileChange(e)}
                      className="sr-only"
                      aria-label="Выбрать архив проекта для загрузки"
                    />
                    <button
                      type="button"
                      disabled={!canEdit || uploadingSource}
                      onClick={() => fileInputRef.current?.click()}
                      className="fm-btn-ink fm-focus mt-2 inline-flex min-h-[38px] w-full cursor-pointer items-center justify-center gap-2 px-3 text-[12.5px] font-medium disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Upload className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                      <span>
                        {uploadingSource ? "Загрузка архива…" : "Загрузить ZIP / TAR архив"}
                      </span>
                    </button>
                    {uploadStatusText && (
                      <p className="mt-2 [overflow-wrap:anywhere] text-[11.5px] font-medium text-[#0f5132]">
                        {uploadStatusText}
                      </p>
                    )}
                    {uploadErrorText && (
                      <p className="mt-2 [overflow-wrap:anywhere] text-[11.5px] font-medium text-[#dc2626]">
                        {uploadErrorText}
                      </p>
                    )}
                  </div>
                )}

                {configEntries.length === 0 ? (
                  <p className="mt-2 text-[12px] text-[#636f7b]">
                    У этой ноды нет дополнительных параметров.
                  </p>
                ) : (
                  <div className="mt-3 space-y-3">
                    {configEntries.map(([key, value]) => {
                      const inputId = `fm11-cfg-${selectedNode.id}-${key}`;
                      if (selectedNode.data.pluginId === "logic.switch" && key === "mode") {
                        return (
                          <div key={key}>
                            <label
                              htmlFor={inputId}
                              className="fm-mono block truncate text-[11px] font-medium text-[#636f7b]"
                            >
                              {key}
                            </label>
                            <select
                              id={inputId}
                              value={value || "maxSeverity"}
                              disabled={!canEdit}
                              onChange={(e) =>
                                ctrl.updateNodeConfig(selectedNode.id, key, e.target.value)
                              }
                              className="fm-select fm-focus mt-1 min-h-[38px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] disabled:bg-[#f8fafc] disabled:text-[#636f7b] sm:text-[12px]"
                            >
                              <option value="maxSeverity">
                                maxSeverity (CRITICAL / HIGH / MEDIUM_LOW / CLEAN)
                              </option>
                              <option value="category">
                                category (SECRET / SAST / SCA / CLEAN)
                              </option>
                            </select>
                          </div>
                        );
                      }
                      return (
                        <div key={key}>
                          <label
                            htmlFor={inputId}
                            className="fm-mono block truncate text-[11px] font-medium text-[#636f7b]"
                          >
                            {key}
                          </label>
                          <input
                            id={inputId}
                            type="text"
                            autoCapitalize="none"
                            autoCorrect="off"
                            enterKeyHint="done"
                            value={value}
                            readOnly={!canEdit}
                            onChange={(e) =>
                              ctrl.updateNodeConfig(selectedNode.id, key, e.target.value)
                            }
                            className="fm-focus fm-mono mt-1 min-h-[38px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] read-only:bg-[#f8fafc] read-only:text-[#636f7b] sm:text-[12px]"
                          />
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Card 2b: Secret Bindings (when node accepts secrets) */}
              {secretKeysToRender.length > 0 && (
                <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-[#000000]">
                      <KeyRound
                        className="h-3.5 w-3.5 stroke-[1.8] text-[#0080ff]"
                        aria-hidden="true"
                      />
                      <span>Секреты (Secret Bindings)</span>
                    </h3>
                    {canEdit && (
                      <Link
                        href="/settings?tab=secrets"
                        className="fm-focus text-[11px] font-medium text-[#0050ff] hover:underline"
                      >
                        Управление
                      </Link>
                    )}
                  </div>

                  <div className="mt-3 space-y-3">
                    {secretKeysToRender.map(({ paramKey, required }) => {
                      const selectId = `fm11-sec-${selectedNode.id}-${paramKey}`;
                      const boundRef =
                        selectedNode.data.secretBindings?.find((b) => b.paramKey === paramKey)
                          ?.secretRef ?? "";
                      const hasBoundInList =
                        !boundRef || availableSecrets.some((sec) => sec.secretRef === boundRef);
                      return (
                        <div key={paramKey}>
                          <div className="flex items-center justify-between gap-2">
                            <label
                              htmlFor={selectId}
                              className="fm-mono truncate text-[11px] font-medium text-[#222222]"
                            >
                              {paramKey}
                            </label>
                            {required ? (
                              <span className="shrink-0 rounded-full bg-[#ffd6e0] px-2 py-0.5 text-[10px] font-semibold text-[#842029]">
                                Обязательно
                              </span>
                            ) : (
                              <span className="shrink-0 rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[10px] font-medium text-[#636f7b]">
                                Опционально
                              </span>
                            )}
                          </div>
                          <select
                            id={selectId}
                            value={boundRef}
                            disabled={!canEdit}
                            onChange={(e) =>
                              ctrl.updateNodeSecretBinding(
                                selectedNode.id,
                                paramKey,
                                e.target.value,
                              )
                            }
                            className="fm-select fm-focus mt-1 min-h-[38px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] disabled:bg-[#f8fafc] disabled:text-[#636f7b] sm:text-[12px]"
                          >
                            <option value="">Не задан</option>
                            {!hasBoundInList && boundRef && (
                              <option value={boundRef}>{boundRef} (привязан)</option>
                            )}
                            {availableSecrets.map((sec) => (
                              <option key={sec.secretRef} value={sec.secretRef}>
                                {sec.name} ({sec.kind})
                              </option>
                            ))}
                          </select>
                        </div>
                      );
                    })}
                  </div>

                  {availableSecrets.length === 0 && canEdit && (
                    <p className="mt-2.5 text-[11.5px] leading-[1.4] text-[#636f7b]">
                      Нет сохранённых секретов. Создайте их в разделе{" "}
                      <Link
                        href="/settings?tab=secrets"
                        className="font-medium text-[#0050ff] hover:underline"
                      >
                        Настройки → Секреты
                      </Link>
                      .
                    </p>
                  )}
                </div>
              )}

              {/* Card 3: Live sampleOutput JSON block */}
              <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-[13px] font-semibold text-[#000000]">
                    Пример вывода (sampleOutput)
                  </h3>
                  <button
                    type="button"
                    onClick={handleCopySampleOutput}
                    className="fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/70 px-2.5 text-[11px] font-medium text-[#222222] hover:border-[#0080ff] hover:text-[#0050ff]"
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
                <pre className="fm-mono fm-scroll mt-2.5 max-h-[210px] overflow-auto rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc] p-3 text-[11px] leading-[1.55] text-[#222222]">
                  {JSON.stringify(selectedNode.data.sampleOutput, null, 2)}
                </pre>
              </div>

              {/* Card 4: Live Run Log (when run has output) */}
              {ctrl.runLog.length > 0 && (
                <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-[#000000]">
                      <Terminal
                        className="h-3.5 w-3.5 stroke-[1.7] text-[#0080ff]"
                        aria-hidden="true"
                      />
                      Лог прогона
                    </h3>
                    <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[10px] font-semibold text-[#636f7b]">
                      {ctrl.runLog.length}{" "}
                      {pluralRu(ctrl.runLog.length, "запись", "записи", "записей")}
                    </span>
                  </div>
                  <ol className="mt-2.5 space-y-1">
                    {ctrl.runLog.map((entry, idx) => {
                      const isLast = idx === ctrl.runLog.length - 1;
                      return (
                        <li
                          key={`${idx}-${entry}`}
                          className={`fm-mono flex items-start gap-2 rounded-[10px] border px-2 py-1.5 text-[11px] leading-[1.35] ${
                            isLast && ctrl.isRunning
                              ? "border-[#0080ff] bg-[#c5e0fb]/30 text-[#000000]"
                              : "border-[#8c9baa]/40 bg-[#ffffff] text-[#222222]"
                          }`}
                        >
                          <span className="fm-tnum shrink-0 text-[#636f7b]">
                            {String(idx + 1).padStart(2, "0")}
                          </span>
                          <span className="min-w-0 [overflow-wrap:anywhere]">{entry}</span>
                        </li>
                      );
                    })}
                  </ol>
                </div>
              )}

              {/* Delete node action */}
              {canEdit && (
                <button
                  type="button"
                  onClick={() => ctrl.deleteNodeById(selectedNode.id)}
                  className="fm-focus inline-flex min-h-[42px] w-full cursor-pointer items-center justify-center gap-2 rounded-full border border-[#8c9baa] bg-[#ffffff] px-4 text-[13px] font-semibold text-[#222222] transition-colors hover:border-[#000000] hover:bg-[#ffd6e0]/50 hover:text-[#000000]"
                >
                  <Trash2 className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
                  Удалить ноду с холста
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );

  return (
    <div className="flex h-dvh flex-col overflow-hidden overscroll-none bg-[#ffffff] text-[#000000]">
      {/* Top Lab Status Strip (52px) */}
      <header
        className="z-30 flex min-h-[52px] shrink-0 items-center justify-between gap-2 border-b border-[#8c9baa]/50 bg-[#ffffff] px-2.5 sm:px-4"
        style={{ paddingTop: "env(safe-area-inset-top, 0px)" }}
      >
        <div className="flex min-w-0 flex-1 items-center gap-2 sm:gap-2.5">
          <button
            type="button"
            onClick={onBack}
            aria-label="Назад к списку Workflows"
            className="fm-btn-outline fm-focus inline-flex h-[36px] shrink-0 cursor-pointer items-center justify-center gap-1.5 px-2.5 text-[12px] font-medium text-[#222222] sm:h-[34px] sm:px-3"
          >
            <ArrowLeft className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            <span className="hidden sm:inline">Workflows</span>
          </button>

          <span className="hidden h-5 w-px shrink-0 bg-[#8c9baa]/45 md:inline-block" aria-hidden="true" />

          <input
            type="text"
            maxLength={120}
            enterKeyHint="done"
            title={titleDraft}
            value={titleDraft}
            readOnly={!canEdit}
            onChange={(e) => setTitleDraft(e.target.value)}
            onBlur={commitTitle}
            onKeyDown={handleTitleKeyDown}
            aria-label="Название доски Workflow"
            className="fm-focus hidden min-w-0 max-w-[36vw] flex-1 truncate rounded-[10px] border border-transparent bg-transparent px-2.5 py-1 text-[14px] font-semibold tracking-[-0.02em] text-[#000000] transition-colors hover:border-[#8c9baa]/60 focus:border-[#0080ff] focus:bg-[#ffffff] md:block"
          />
        </div>

        <div className="flex shrink-0 items-center gap-1.5 sm:gap-2">
          {/* Editor / History mode switcher in Canvas Header */}
          <div
            role="tablist"
            aria-label="Режим работы с доской"
            className="inline-flex items-center rounded-full border border-[#8c9baa]/70 bg-[#ffffff] p-0.5"
          >
            <button
              type="button"
              role="tab"
              aria-selected={workspaceMode === "editor"}
              onClick={() => setWorkspaceMode("editor")}
              className={`fm-focus min-h-[28px] cursor-pointer whitespace-nowrap rounded-full px-2.5 text-[12px] font-semibold transition-colors ${
                workspaceMode === "editor"
                  ? "bg-[#000000] text-[#ffffff]"
                  : "text-[#636f7b] hover:text-[#000000]"
              }`}
            >
              Редактор
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={workspaceMode === "history"}
              onClick={() => setWorkspaceMode("history")}
              className={`fm-focus fm-tnum inline-flex min-h-[28px] cursor-pointer items-center gap-1 whitespace-nowrap rounded-full px-2.5 text-[12px] font-semibold transition-colors ${
                workspaceMode === "history"
                  ? "bg-[#000000] text-[#ffffff]"
                  : "text-[#636f7b] hover:text-[#000000]"
              }`}
            >
              <span>История</span>
              {runs.length > 0 && (
                <span
                  className={`rounded-full px-1.5 py-0.5 text-[11px] leading-none ${
                    workspaceMode === "history"
                      ? "bg-[#ffffff]/20 text-[#ffffff]"
                      : "bg-[#c5e0fb]/55 text-[#000000]"
                  }`}
                >
                  {runs.length}
                </span>
              )}
            </button>
          </div>

          {/* Compact Status Pill (no "Статус" label) directly to the left of Info icon */}
          <span
            aria-live="polite"
            className={`fm-tnum hidden h-[34px] shrink-0 items-center gap-1.5 rounded-full border px-3 text-[12px] font-semibold tracking-[0.02em] transition-colors sm:inline-flex ${
              ctrl.isRunning || serverRunning
                ? "border-[#0080ff]/60 bg-[#c5e0fb]/45 text-[#000000]"
                : "border-[#8c9baa]/70 bg-[#ffffff] text-[#222222]"
            }`}
          >
            <span
              aria-hidden="true"
              className={`h-2 w-2 rounded-full ${
                ctrl.isRunning || serverRunning ? "bg-[#0080ff] animate-pulse" : "bg-[#636f7b]"
              }`}
            />
            <span>{ctrl.isRunning || serverRunning ? "RUNNING" : "READY"}</span>
          </span>

          {/* Graph Info Icon (hover/focus/click popover) directly to the left of Run */}
          <div
            className="group relative hidden sm:block"
            onMouseLeave={() => setInfoPinned(false)}
          >
            <button
              type="button"
              onClick={() => setInfoPinned((prev) => !prev)}
              aria-label={`Информация о графе: нод ${ctrl.nodes.length}, связей ${ctrl.edges.length}`}
              aria-expanded={infoPinned}
              className="fm-focus inline-flex h-[34px] w-[34px] cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] bg-[#ffffff] text-[#636f7b] transition-colors active:scale-95 hover:border-[#0080ff] hover:bg-[#f6faff] hover:text-[#0080ff]"
            >
              <Info className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
            </button>

            <div
              role="tooltip"
              className={`fm-float pointer-events-none absolute right-0 top-[calc(100%+8px)] z-40 w-[212px] rounded-[16px] border border-[#8c9baa] bg-[#ffffff] p-3 text-left transition-[opacity,transform] duration-150 ${
                infoPinned
                  ? "pointer-events-auto translate-y-0 opacity-100"
                  : "translate-y-1 opacity-0 group-hover:pointer-events-auto group-hover:translate-y-0 group-hover:opacity-100 group-focus-within:pointer-events-auto group-focus-within:translate-y-0 group-focus-within:opacity-100"
              }`}
            >
              <p className="border-b border-[#8c9baa]/35 pb-2 text-[12px] font-semibold tracking-[-0.01em] text-[#000000]">
                Сводка графа
              </p>
              <dl className="mt-2 space-y-1.5 text-[12px]">
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-[#636f7b]">Нод</dt>
                  <dd className="fm-tnum font-semibold text-[#000000]">{ctrl.nodes.length}</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-[#636f7b]">Связей</dt>
                  <dd className="fm-tnum font-semibold text-[#000000]">{ctrl.edges.length}</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-[#636f7b]">Триггер</dt>
                  <dd className="font-medium text-[#222222]">{workflow.trigger}</dd>
                </div>
              </dl>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              if (!canEdit) return;
              if (workspaceMode === "history") {
                setWorkspaceMode("editor");
              }
              if (onServerRun) {
                onServerRun();
                return;
              }
              ctrl.runCanvasSimulation();
            }}
            disabled={!canEdit || ctrl.nodes.length === 0 || ctrl.isRunning || serverRunning}
            title={!canEdit ? "Режим просмотра (viewer): запуск недоступен" : undefined}
            className="fm-btn-signal fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 px-3.5 text-[12px] font-semibold disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
            <span className="hidden sm:inline">
              {ctrl.isRunning || serverRunning ? "Прогон..." : "Запустить прогон"}
            </span>
            <span className="sm:hidden">{ctrl.isRunning || serverRunning ? "..." : "Пуск"}</span>
          </button>
        </div>
      </header>

      {/* Main Content: Either Split Run History Preview OR 2-Zone Canvas Editor */}
      {workspaceMode === "history" ? (
        <FlowmappRunHistoryView
          runs={runs}
          workflows={[workflow]}
          liveBoardGraph={{
            nodes: ctrl.nodes.map((n) => ({
              id: n.id,
              type: "secflowNode",
              position: n.position,
              data: n.data,
            })),
            edges: ctrl.edges.map((e) => ({
              id: e.id,
              source: e.source,
              target: e.target,
              sourceHandle: e.sourceHandle,
              targetHandle: e.targetHandle,
              label: typeof e.label === "string" ? e.label : undefined,
            })),
          }}
          lockedWorkflowId={workflow.id}
          focusRunId={runs[0]?.id ?? null}
          canEdit={canEdit}
          onReplayRun={() => {
            if (!canEdit) return;
            setWorkspaceMode("editor");
            onServerRun?.();
          }}
          onCancelRun={onCancelRun}
          onRerunFromNode={onRerunFromNode}
          onNotice={onNotice}
        />
      ) : (
        <div className="relative flex min-h-0 flex-1 overflow-hidden">
        <main
          aria-label="Технический холст Workflow"
          onDragOver={ctrl.onDragOverCanvas}
          onDragLeave={ctrl.onDragLeaveCanvas}
          onDrop={ctrl.onDropCanvas}
          className={`relative min-w-0 flex-1 bg-[#ffffff] transition-colors ${
            ctrl.isDragOver ? "ring-2 ring-inset ring-[#0080ff]" : ""
          }`}
        >
          {/* Top-left floating canvas action pill (like v08: По размеру + Выровнять + Очистить) */}
          <div className="pointer-events-none absolute left-3 right-16 top-3 z-20 flex items-center lg:right-auto">
            <div className="fm-float fm-scroll pointer-events-auto inline-flex max-w-full items-center gap-1 overflow-x-auto rounded-full border border-[#8c9baa]/60 px-2 py-1">
              <button
                type="button"
                onClick={ctrl.handleFitView}
                disabled={ctrl.nodes.length === 0}
                title="Вписать граф в экран"
                aria-label="Вписать граф в экран"
                className="fm-focus inline-flex min-h-[30px] shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 text-[12px] font-medium text-[#222222] transition-colors hover:bg-[#c5e0fb]/35 hover:text-[#0050ff] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-45"
              >
                <Maximize2 className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                <span className="hidden sm:inline">По размеру</span>
              </button>
              <button
                type="button"
                onClick={() => ctrl.handleAutoLayout({ fit: false })}
                disabled={ctrl.nodes.length === 0}
                title="Выровнять узлы по слоям DAG"
                aria-label="Выровнять узлы по слоям DAG"
                className="fm-focus inline-flex min-h-[30px] shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 text-[12px] font-medium text-[#222222] transition-colors hover:bg-[#c5e0fb]/35 hover:text-[#0050ff] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-45"
              >
                <LayoutGrid className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                <span>Выровнять</span>
              </button>
              {canEdit && (
                <button
                  type="button"
                  onClick={ctrl.undo}
                  disabled={!ctrl.canUndo}
                  title="Отменить последнее действие (Ctrl+Z)"
                  aria-label="Отменить (Ctrl+Z)"
                  className="fm-focus inline-flex min-h-[30px] shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 text-[12px] font-medium text-[#222222] transition-colors hover:bg-[#c5e0fb]/35 hover:text-[#0050ff] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Undo2 className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                  <span className="hidden sm:inline">Отменить</span>
                </button>
              )}
              {canEdit && ctrl.nodes.length > 0 && (
                <button
                  type="button"
                  onClick={ctrl.handleClearCanvas}
                  title="Очистить холст"
                  aria-label="Очистить холст"
                  className="fm-focus inline-flex min-h-[30px] shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 text-[12px] font-medium text-[#636f7b] transition-colors hover:bg-[#ffd6e0]/45 hover:text-[#000000] active:scale-[0.98]"
                >
                  <RotateCcw className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                  <span className="hidden sm:inline">Очистить</span>
                </button>
              )}
            </div>
          </div>

          {/* Floating Circular Toggle Button on Canvas Top-Right when Right Sidebar is Collapsed (Desktop) */}
          {!rightSidebarOpen && (
            <button
              type="button"
              onClick={() => setRightSidebarOpen(true)}
              aria-label="Развернуть панель каталога и инспектора"
              title="Открыть каталог нод и инспектор"
              className="fm-float fm-focus absolute right-3 top-3 z-20 hidden h-11 w-11 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] text-[#000000] transition-colors active:scale-95 hover:border-[#0080ff] hover:text-[#0080ff] lg:inline-flex"
            >
              <PanelRightOpen className="h-4 w-4 stroke-[1.8]" aria-hidden="true" />
            </button>
          )}

          {/* Floating Circular Toggle Button on Canvas Top-Right (Mobile/Tablet) */}
          {!mobileSidebarOpen && (
            <button
              type="button"
              onClick={() => setMobileSidebarOpen(true)}
              aria-label="Открыть каталог нод и инспектор"
              title="Открыть каталог нод и инспектор"
              className="fm-float fm-focus absolute right-3 top-3 z-20 inline-flex h-11 w-11 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] text-[#000000] transition-colors active:scale-95 hover:border-[#0080ff] hover:text-[#0080ff] lg:hidden"
            >
              <PanelRightOpen className="h-4 w-4 stroke-[1.8]" aria-hidden="true" />
            </button>
          )}

          {ctrl.isDragOver && (
            <div className="pointer-events-none absolute left-1/2 top-3 z-20 -translate-x-1/2">
              <span className="fm-float inline-flex items-center gap-1.5 rounded-full border border-[#0080ff] px-3.5 py-1.5 text-[12px] font-semibold text-[#0066e6]">
                Отпустите, чтобы добавить узел на чертёж
              </span>
            </div>
          )}

          {ctrl.nodes.length === 0 && (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center p-4">
              <div className="fm-float pointer-events-auto max-w-[340px] rounded-[20px] border border-[#8c9baa] p-5 text-center">
                <p className="text-[15px] font-semibold tracking-[-0.02em] text-[#000000]">
                  Чертёж пока пуст
                </p>
                <p className="mt-1.5 text-[13px] leading-[1.45] text-[#636f7b]">
                  Перетащите узлы из правого каталога или добавьте стартовый триггер для сборки
                  цепочки проверок.
                </p>
                {canEdit && (
                  <button
                    type="button"
                    onClick={() => ctrl.addTemplateNode(TEMPLATE_BY_PLUGIN_ID["trigger.manual"])}
                    className="fm-btn-signal fm-focus mt-3.5 inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
                  >
                    <Plus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
                    Добавить ручной триггер
                  </button>
                )}
              </div>
            </div>
          )}

          <ReactFlow
            nodes={ctrl.nodes}
            edges={ctrl.edges}
            nodeTypes={NODE_TYPES}
            onNodesChange={ctrl.onNodesChange}
            onEdgesChange={ctrl.onEdgesChange}
            onConnect={ctrl.onConnect}
            onNodeClick={(_, node) => {
              ctrl.selectOnlyNode(node.id);
              setSidebarTab("inspector");
              setRightSidebarOpen(true);
              if (typeof window !== "undefined" && window.innerWidth < 1024) {
                setMobileSidebarOpen(true);
              }
            }}
            onNodesDelete={(deleted) => {
              const removedIds = new Set(deleted.map((n) => n.id));
              const remainingNodes = ctrl.nodes.filter((n) => !removedIds.has(n.id));
              const remainingEdges = ctrl.edges.filter(
                (e) => !removedIds.has(e.source) && !removedIds.has(e.target),
              );
              ctrl.syncToParent(remainingNodes, remainingEdges);
            }}
            onEdgesDelete={(deleted) => {
              const removedIds = new Set(deleted.map((e) => e.id));
              const remainingEdges = ctrl.edges.filter((e) => !removedIds.has(e.id));
              ctrl.syncToParent(ctrl.nodes, remainingEdges);
            }}
            onNodeDragStop={(_, draggedNode) => {
              const updated = ctrl.nodes.map((n) =>
                n.id === draggedNode.id ? { ...n, position: draggedNode.position } : n,
              );
              ctrl.syncToParent(updated, ctrl.edges);
            }}
            onEdgeClick={(_, edge) => ctrl.selectOnlyEdge(edge.id)}
            onPaneClick={() => ctrl.clearSelection()}
            nodesDraggable={canEdit}
            nodesConnectable={canEdit}
            elementsSelectable
            deleteKeyCode={null}
            fitView
            fitViewOptions={{ padding: 0.22, maxZoom: 1.05 }}
            snapToGrid
            snapGrid={[12, 12]}
            defaultEdgeOptions={{
              type: "bezier",
              interactionWidth: 24,
              style: { stroke: "#0080ff", strokeWidth: 1.85 },
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background
              variant={BackgroundVariant.Cross}
              gap={24}
              size={2}
              color="#c5e0fb"
            />
            <Controls showInteractive={false} position="bottom-left" />
            <MiniMap
              position="bottom-right"
              pannable
              zoomable
              nodeColor="#c5e0fb"
              maskColor="rgba(255, 255, 255, 0.75)"
              className="hidden !rounded-[16px] !border !border-[#8c9baa]/60 !bg-[#ffffff] xl:block"
              style={{ width: 148, height: 92 }}
            />
          </ReactFlow>
        </main>

        {/* Single Unified Right Sidebar (Desktop, collapsible to floating circle) */}
        {rightSidebarOpen && (
          <aside
            aria-label="Каталог нод и инспектор"
            className="hidden w-[348px] shrink-0 border-l border-[#8c9baa]/50 bg-[#ffffff] lg:flex lg:flex-col"
          >
            {renderUnifiedRightSidebar(false)}
          </aside>
        )}

        {/* Single Unified Right Sidebar Drawer (Mobile/Tablet) */}
        {mobileSidebarOpen && (
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Каталог нод и инспектор"
            className="fixed inset-0 z-40 flex justify-end bg-[#000000]/20 lg:hidden"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setMobileSidebarOpen(false);
            }}
          >
            <div className="fm-float h-full w-[min(360px,92vw)] border-l border-[#8c9baa]">
              {renderUnifiedRightSidebar(true)}
            </div>
          </div>
        )}
      </div>
      )}
    </div>
  );
}

export function FlowmappCanvas11(props: FlowmappCanvas11Props) {
  return (
    <ReactFlowProvider>
      <FlowmappCanvas11Inner {...props} />
    </ReactFlowProvider>
  );
}
