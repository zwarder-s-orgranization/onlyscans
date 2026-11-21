"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
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
  ArrowLeft,
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Layers,
  Lock,
  Maximize2,
  Pencil,
  Plus,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import {
  buildGraphFromTemplate,
  CATEGORY_BY_ID,
  type CanvasBoardNodeData,
} from "@/data/canvas-nodes-catalog";
import type {
  StarterTemplateRecord,
  TemplateCategory,
  TemplateRequiredParam,
  TriggerKind,
  WorkflowRecord,
} from "@/data/workflows-workspace-data";
import { NodeCategoryIcon } from "../NodeCategoryIcon";
import { FlowmappPastelTriggerIcon } from "./FlowmappChrome";

interface TemplatePreviewNodeData extends CanvasBoardNodeData {
  needsSetup: boolean;
}

type TemplatePreviewFlowNode = Node<TemplatePreviewNodeData, "templatePreviewNode">;

type SourceFilter = "ALL" | "BUILTIN" | "TEAM";

const SOURCE_FILTER_OPTIONS: Array<{ id: SourceFilter; label: string }> = [
  { id: "ALL", label: "Все" },
  { id: "BUILTIN", label: "Встроенные" },
  { id: "TEAM", label: "Командные" },
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
];

const CATEGORY_FILTER_OPTIONS: Array<{
  id: "ALL" | TemplateCategory;
  label: string;
}> = [
  { id: "ALL", label: "Любой сценарий" },
  { id: "benchmark", label: "Эталон Repair Desk" },
  { id: "gate", label: "Релиз и Gate" },
  { id: "ci-cd", label: "CI/CD и PR" },
  { id: "secrets", label: "Секреты" },
  { id: "sca-sbom", label: "SCA и SBOM" },
];

const CATEGORY_LABELS: Record<TemplateCategory, string> = {
  benchmark: "Эталон",
  gate: "Policy Gate",
  "ci-cd": "CI/CD",
  secrets: "Secrets",
  "sca-sbom": "SCA / SBOM",
};

function pluralRu(count: number, one: string, few: string, many: string): string {
  const mod100 = Math.abs(count) % 100;
  const mod10 = mod100 % 10;
  if (mod100 > 10 && mod100 < 20) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

function formatCount(n: number): string {
  return new Intl.NumberFormat("ru-RU").format(n);
}

function getBranchPillTone(port: string): string {
  const normalized = port.toLowerCase();
  if (normalized === "fail" || normalized === "critical") {
    return "bg-[#ffd6e0] text-[#000000] border-[#8c9baa]/50";
  }
  if (normalized === "pass" || normalized === "clean") {
    return "bg-[#c8f0d8] text-[#000000] border-[#8c9baa]/50";
  }
  if (normalized === "high" || normalized === "excluded") {
    return "bg-[#fff3c4] text-[#000000] border-[#8c9baa]/50";
  }
  if (normalized === "true" || normalized === "matched") {
    return "bg-[#c5e0fb] text-[#000000] border-[#8c9baa]/50";
  }
  return "bg-[#ffffff] text-[#222222] border-[#8c9baa]/60";
}

function TemplatePreviewNode({ data, selected }: NodeProps<TemplatePreviewFlowNode>) {
  const category = CATEGORY_BY_ID[data.family];
  const outputs = data.outputs.length > 0 ? data.outputs : ["out"];
  const isMultiOutput = outputs.length > 1;
  const isTripleOutput = outputs.length >= 3;

  return (
    <div className="relative w-[244px]">
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
        className={`relative z-10 w-full rounded-[16px] bg-[#ffffff] text-[#000000] transition-colors duration-150 ${
          selected
            ? "border-[2px] border-[#0080ff] shadow-[0_2px_12px_rgba(0,128,255,0.14)]"
            : "border border-[#8c9baa] hover:border-[#000000]"
        }`}
      >
        <div
          className={`flex items-center justify-between gap-2 rounded-t-[14px] border-b border-[#8c9baa]/35 px-3 py-1.5 ${
            selected ? "bg-[#c5e0fb]/35" : "bg-[#ffffff]"
          }`}
        >
          <div className="flex min-w-0 items-center gap-1.5">
            <span
              aria-hidden="true"
              className="h-2 w-2 shrink-0 rounded-full border border-[#000000]/15"
              style={{ backgroundColor: category.flowmappPastel }}
            />
            <span className="truncate text-[12px] font-semibold tracking-[-0.01em] text-[#636f7b]">
              {category.shortLabel}
            </span>
          </div>
          {data.needsSetup ? (
            <span className="shrink-0 rounded-full bg-[#fff3c4] px-2 py-0.5 text-[12px] font-semibold leading-none text-[#000000]">
              Настроить
            </span>
          ) : (
            <span className="shrink-0 rounded-full border border-[#8c9baa]/45 bg-[#ffffff] px-2 py-0.5 text-[12px] font-medium leading-none text-[#636f7b]">
              Готов
            </span>
          )}
        </div>

        <div
          className={`px-3 py-2.5 ${
            outputs.length >= 4
              ? "min-h-[126px] pr-[96px]"
              : isTripleOutput
                ? "min-h-[104px] pr-[76px]"
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

          <div className="mt-2.5 flex items-center justify-between gap-1.5">
            <span
              title={data.pluginId}
              className="fm-mono min-w-0 truncate rounded-[8px] border border-[#8c9baa]/45 bg-[#ffffff] px-2 py-0.5 text-[12px] text-[#636f7b]"
            >
              {data.pluginId}
            </span>
          </div>
        </div>

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

const TEMPLATE_NODE_TYPES = {
  templatePreviewNode: TemplatePreviewNode,
};

function TemplateCanvasPreviewInner({
  template,
  canEdit,
  onClone,
  onNotice,
}: {
  template: StarterTemplateRecord;
  canEdit: boolean;
  onClone: (tpl: StarterTemplateRecord, openCanvas: boolean, customName?: string) => void;
  onNotice?: (message: string) => void;
}) {
  const { fitView } = useReactFlow();
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [cloneMenuOpen, setCloneMenuOpen] = useState(false);
  const [cloneName, setCloneName] = useState(template.name);
  const [openAfterClone, setOpenAfterClone] = useState(true);
  const [detailsExpanded, setDetailsExpanded] = useState(true);
  const [copiedSlug, setCopiedSlug] = useState(false);

  const clonePopoverRef = useRef<HTMLDivElement>(null);

  const requiredNodePlugins = useMemo(
    () => new Set(template.requiredParams.map((p) => p.node)),
    [template.requiredParams],
  );

  const { nodes, edges } = useMemo(() => {
    const built =
      template.boardGraph && template.boardGraph.nodes.length > 0
        ? template.boardGraph
        : buildGraphFromTemplate(template, template.id, { sanitized: true });
    const flowNodes: TemplatePreviewFlowNode[] = built.nodes.map((node) => ({
      id: node.id,
      type: "templatePreviewNode",
      position: node.position,
      data: {
        ...node.data,
        needsSetup: requiredNodePlugins.has(node.data.pluginId),
      },
    }));
    const flowEdges: Edge[] = built.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      sourceHandle: edge.sourceHandle ?? undefined,
      targetHandle: edge.targetHandle ?? undefined,
      label: edge.label,
      type: "bezier",
      labelStyle: {
        fontSize: 11,
        fontWeight: 600,
        fill: "#222222",
      },
      labelBgStyle: {
        fill: "#ffffff",
        fillOpacity: 0.92,
      },
      labelBgPadding: [6, 3] as [number, number],
      labelBgBorderRadius: 999,
      style: {
        stroke: "#0080ff",
        strokeWidth: 1.85,
      },
    }));
    return { nodes: flowNodes, edges: flowEdges };
  }, [template, requiredNodePlugins]);

  useEffect(() => {
    setSelectedNodeId(null);
    setCloneMenuOpen(false);
    setCloneName(template.name);
    const raf = window.requestAnimationFrame(() => {
      void fitView({ padding: 0.22, maxZoom: 1.02, duration: 200 });
    });
    return () => window.cancelAnimationFrame(raf);
  }, [template.id, template.name, fitView]);

  useEffect(() => {
    if (!cloneMenuOpen) return;
    const onMouseDown = (event: MouseEvent) => {
      if (
        clonePopoverRef.current &&
        !clonePopoverRef.current.contains(event.target as globalThis.Node)
      ) {
        setCloneMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setCloneMenuOpen(false);
    };
    window.addEventListener("mousedown", onMouseDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [cloneMenuOpen]);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId],
  );
  const selectedCategory = selectedNode ? CATEGORY_BY_ID[selectedNode.data.family] : null;
  const selectedNodeRequirements = useMemo<TemplateRequiredParam[]>(() => {
    if (!selectedNode) return [];
    return template.requiredParams.filter((p) => p.node === selectedNode.data.pluginId);
  }, [selectedNode, template.requiredParams]);

  const handleCopySlug = () => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(template.slug);
    }
    setCopiedSlug(true);
    onNotice?.(`Идентификатор ${template.slug} скопирован`);
    window.setTimeout(() => setCopiedSlug(false), 1500);
  };

  const handleCloneSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canEdit) return;
    onClone(template, openAfterClone, cloneName.trim() || template.name);
    setCloneMenuOpen(false);
  };

  return (
    <div className="relative flex min-h-0 flex-1 flex-col bg-[#ffffff]">
      {/* Context Action Strip */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-[#8c9baa]/40 bg-[#ffffff] px-4 py-2.5 xl:flex-nowrap">
        <div className="flex min-w-0 flex-1 items-center gap-2.5">
          <h2
            title={template.name}
            className="min-w-0 truncate text-[15px] font-bold tracking-[-0.02em] text-[#000000]"
          >
            {template.name}
          </h2>
          <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[#c8f0d8]/75 px-2.5 py-0.5 text-[12px] font-semibold text-[#000000]">
            <ShieldCheck className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
            <span>Без секретов и URL</span>
          </span>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {canEdit ? (
            <>
              <div ref={clonePopoverRef} className="relative">
                <button
                  type="button"
                  onClick={() => setCloneMenuOpen((v) => !v)}
                  aria-expanded={cloneMenuOpen}
                  aria-haspopup="dialog"
                  aria-label="Клонировать с произвольным именем"
                  className="fm-btn-outline fm-focus inline-flex min-h-[44px] cursor-pointer items-center gap-1.5 px-3.5 text-[12.5px] font-medium text-[#222222] sm:min-h-[38px]"
                >
                  <Pencil className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                  <span className="hidden sm:inline">С именем…</span>
                </button>

                {cloneMenuOpen && (
                  <div
                    role="dialog"
                    aria-label="Параметры клонирования шаблона"
                    className="fm-float absolute right-0 top-[calc(100%+8px)] z-40 w-[min(340px,calc(100vw-2rem))] origin-top-right rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-4"
                  >
                    <form onSubmit={handleCloneSubmit} className="space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[13px] font-semibold text-[#000000]">
                          Клонировать шаблон
                        </span>
                        <button
                          type="button"
                          onClick={() => setCloneMenuOpen(false)}
                          aria-label="Закрыть форму клонирования"
                          className="fm-focus inline-flex h-7 w-7 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/60 text-[#636f7b] hover:border-[#000000] hover:text-[#000000]"
                        >
                          <X className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                        </button>
                      </div>

                      <div>
                        <label
                          htmlFor="fm-clone-tpl-name"
                          className="block text-[12px] font-semibold text-[#222222]"
                        >
                          Название новой доски
                        </label>
                        <input
                          id="fm-clone-tpl-name"
                          type="text"
                          maxLength={120}
                          enterKeyHint="done"
                          value={cloneName}
                          onChange={(e) => setCloneName(e.target.value)}
                          placeholder={template.name}
                          className="fm-focus mt-1.5 min-h-[42px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[13.5px]"
                        />
                      </div>

                      <label className="flex cursor-pointer items-center gap-2.5 text-[12.5px] font-medium text-[#222222]">
                        <input
                          type="checkbox"
                          checked={openAfterClone}
                          onChange={(e) => setOpenAfterClone(e.target.checked)}
                          className="h-4 w-4 rounded border-[#8c9baa] accent-[#0066e6]"
                        />
                        <span>Сразу открыть на канвасе</span>
                      </label>

                      {template.requiredParams.length > 0 && (
                        <p className="rounded-[12px] bg-[#f6faff] px-3 py-2 text-[12px] leading-[1.45] text-[#636f7b]">
                          После клонирования заполните {template.requiredParams.length}{" "}
                          {pluralRu(
                            template.requiredParams.length,
                            "параметр",
                            "параметра",
                            "параметров",
                          )}{" "}
                          (источник и секреты каналов доставки).
                        </p>
                      )}

                      <div className="flex items-center justify-end gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => setCloneMenuOpen(false)}
                          className="fm-btn-outline fm-focus min-h-[38px] cursor-pointer px-3.5 text-[12.5px] font-medium"
                        >
                          Отмена
                        </button>
                        <button
                          type="submit"
                          className="fm-btn-signal fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-4 text-[12.5px] font-semibold"
                        >
                          <span>Создать доску</span>
                          <ArrowUpRight className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
                        </button>
                      </div>
                    </form>
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={() => onClone(template, true)}
                className="fm-btn-signal fm-focus inline-flex min-h-[44px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold sm:min-h-[38px] sm:text-[12.5px]"
              >
                <span>Использовать</span>
                <ArrowUpRight className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
              </button>
            </>
          ) : (
            <span className="inline-flex min-h-[34px] items-center gap-1.5 rounded-full border border-[#8c9baa]/60 px-3 text-[12px] font-medium text-[#636f7b]">
              <Lock className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
              Только просмотр (viewer)
            </span>
          )}
        </div>
      </div>

      {/* Interactive Read-Only Template DAG Canvas */}
      <div className="relative min-h-[260px] flex-1 bg-[#ffffff]">
        <ReactFlow
          nodes={nodes.map((n) => ({ ...n, selected: n.id === selectedNodeId }))}
          edges={edges}
          nodeTypes={TEMPLATE_NODE_TYPES}
          onNodeClick={(_, node) => setSelectedNodeId(node.id)}
          onPaneClick={() => setSelectedNodeId(null)}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          fitView
          fitViewOptions={{ padding: 0.22, maxZoom: 1.02 }}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Cross} gap={24} size={2} color="#c5e0fb" />
          <Controls showInteractive={false} position="bottom-left" />
        </ReactFlow>

        {/* Top-left floating Fit View + Graph Summary */}
        <div className="pointer-events-none absolute left-3 top-3 z-10 flex flex-wrap items-center gap-2">
          <div className="fm-float pointer-events-auto inline-flex items-center gap-1 rounded-full border border-[#8c9baa]/60 px-2 py-1">
            <button
              type="button"
              onClick={() => void fitView({ padding: 0.22, maxZoom: 1.02, duration: 200 })}
              title="Вписать граф в экран"
              className="fm-focus inline-flex min-h-[28px] cursor-pointer items-center gap-1.5 rounded-full px-2.5 text-[12px] font-medium text-[#222222] transition-colors hover:bg-[#c5e0fb]/35 hover:text-[#0050ff] active:scale-[0.98]"
            >
              <Maximize2 className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
              <span>По размеру</span>
            </button>
          </div>
          <span className="fm-tnum fm-float hidden rounded-full border border-[#8c9baa]/55 px-3 py-1.5 text-[12px] font-medium text-[#636f7b] lg:inline-flex">
            {nodes.length} {pluralRu(nodes.length, "нода", "ноды", "нод")} · {edges.length}{" "}
            {pluralRu(edges.length, "связь", "связи", "связей")} · {formatCount(template.cloneCount)}{" "}
            {pluralRu(template.cloneCount, "клонирование", "клонирования", "клонирований")}
          </span>
        </div>

        {/* Floating Node Sanitized Inspector */}
        {selectedNode && selectedCategory && (
          <aside
            aria-label="Параметры узла шаблона"
            className="fm-float absolute bottom-3 right-3 z-20 w-[min(350px,calc(100%-1.5rem))] rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-4"
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
                  <p className="fm-mono truncate text-[12px] text-[#636f7b]">
                    {selectedNode.data.pluginId} · {selectedNode.data.runtime}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNodeId(null)}
                aria-label="Закрыть инспектор узла"
                className="fm-focus inline-flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/60 text-[#636f7b] hover:border-[#000000] hover:text-[#000000]"
              >
                <X className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
              </button>
            </div>

            <p className="mt-2.5 [overflow-wrap:anywhere] text-[12px] leading-[1.45] text-[#222222]">
              {selectedNode.data.description}
            </p>

            {selectedNodeRequirements.length > 0 && (
              <div className="mt-2.5 rounded-[12px] border border-[#8c9baa]/45 bg-[#fff3c4]/55 p-2.5">
                <p className="text-[12px] font-semibold text-[#000000]">
                  Заполнить после клонирования
                </p>
                <ul className="mt-1 space-y-1">
                  {selectedNodeRequirements.map((req) => (
                    <li key={`${req.node}-${req.field}`} className="text-[12px] text-[#222222]">
                      <span className="fm-mono font-semibold text-[#000000]">{req.field}</span> —{" "}
                      {req.hint}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="mt-3">
              <p className="text-[12px] font-semibold text-[#636f7b]">
                Очищенная конфигурация узла
              </p>
              <dl className="fm-scroll mt-1.5 max-h-[126px] divide-y divide-[#8c9baa]/25 overflow-y-auto overscroll-contain rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc] px-2.5 py-1 text-[12px]">
                {Object.entries(selectedNode.data.config).map(([key, val]) => {
                  const isPlaceholder = val.startsWith("<");
                  return (
                    <div key={key} className="flex items-baseline justify-between gap-2 py-1.5">
                      <dt className="fm-mono shrink-0 text-[#636f7b]">{key}</dt>
                      <dd
                        className={`fm-mono min-w-0 truncate text-right ${
                          isPlaceholder
                            ? "rounded bg-[#fff3c4] px-1.5 py-0.5 font-medium text-[#000000]"
                            : "text-[#222222]"
                        }`}
                        title={val}
                      >
                        {val}
                      </dd>
                    </div>
                  );
                })}
              </dl>
            </div>
          </aside>
        )}
      </div>

      {/* Compact Bottom Specification Drawer */}
      <div
        className="shrink-0 border-t border-[#8c9baa]/45 bg-[#ffffff]"
        style={{ paddingBottom: "env(safe-area-inset-bottom, 0px)" }}
      >
        <div className="flex items-center justify-between gap-2 px-4 py-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2 text-[12px] text-[#636f7b]">
            <span className="font-semibold text-[#000000]">Паспорт шаблона</span>
            {template.authorSubject && (
              <>
                <span aria-hidden="true">·</span>
                <span className="truncate">{template.authorSubject}</span>
              </>
            )}
            {template.createdAt && (
              <>
                <span aria-hidden="true">·</span>
                <span className="fm-tnum">{template.createdAt}</span>
              </>
            )}
            <button
              type="button"
              onClick={handleCopySlug}
              title="Скопировать slug шаблона"
              className="fm-mono fm-focus hidden cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 py-0.5 text-[12px] text-[#636f7b] transition-colors hover:border-[#0080ff] hover:text-[#0050ff] sm:inline-flex"
            >
              <span>{template.slug}</span>
              {copiedSlug ? (
                <Check className="h-3 w-3 stroke-[2] text-[#16a34a]" aria-hidden="true" />
              ) : (
                <Copy className="h-3 w-3 stroke-[1.7]" aria-hidden="true" />
              )}
            </button>
          </div>
          <button
            type="button"
            onClick={() => setDetailsExpanded((v) => !v)}
            aria-expanded={detailsExpanded}
            className="fm-focus inline-flex min-h-[32px] cursor-pointer items-center gap-1 rounded-full border border-[#8c9baa]/60 px-2.5 text-[12px] font-medium text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0050ff]"
          >
            <span>{detailsExpanded ? "Свернуть" : "Подробнее"}</span>
            {detailsExpanded ? (
              <ChevronDown className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            ) : (
              <ChevronUp className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
            )}
          </button>
        </div>

        {detailsExpanded && (
          <div className="fm-scroll grid max-h-[210px] gap-4 overflow-y-auto overscroll-contain border-t border-[#8c9baa]/30 px-4 py-3 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
            <div className="min-w-0">
              <p className="max-w-[68ch] text-[13px] font-semibold leading-[1.4] text-[#000000]">
                {template.problemSolved}
              </p>
              <p className="mt-1 max-w-[68ch] text-[12.5px] leading-[1.45] text-[#636f7b]">
                {template.description}
              </p>
              <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                <span className="rounded-full bg-[#c5e0fb]/45 px-2.5 py-0.5 text-[12px] font-semibold text-[#000000]">
                  {CATEGORY_LABELS[template.category]}
                </span>
                {template.tags.map((tag) => (
                  <span
                    key={tag}
                    className="rounded-full border border-[#8c9baa]/55 px-2.5 py-0.5 text-[12px] font-medium text-[#222222]"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            <div className="min-w-0 border-t border-[#8c9baa]/25 pt-3 lg:border-l lg:border-t-0 lg:pl-4 lg:pt-0">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[12px] font-semibold text-[#000000]">
                  Настроить после клонирования
                </p>
                <span className="fm-tnum rounded-full bg-[#fff3c4] px-2 py-0.5 text-[12px] font-semibold text-[#000000]">
                  {template.requiredParams.length}
                </span>
              </div>
              {template.requiredParams.length === 0 ? (
                <p className="mt-1.5 text-[12px] text-[#636f7b]">
                  Шаблон не требует обязательных внешних секретов или URL.
                </p>
              ) : (
                <ul className="mt-2 space-y-1.5">
                  {template.requiredParams.map((param) => (
                    <li
                      key={`${param.node}-${param.field}`}
                      className="text-[12px] leading-[1.55] text-[#636f7b]"
                    >
                      <span className="fm-mono mr-1.5 inline-block rounded-[6px] border border-[#8c9baa]/50 bg-[#f8fafc] px-1.5 py-0.5 text-[12px] font-medium text-[#0050ff]">
                        {param.node}.{param.field}
                      </span>
                      <span>— {param.hint}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export interface FlowmappTemplatesViewProps {
  templates: StarterTemplateRecord[];
  workflows: WorkflowRecord[];
  canEdit: boolean;
  onUseTemplate: (tpl: StarterTemplateRecord, openCanvas?: boolean, customName?: string) => void;
  onPublishTemplate: (input: {
    workflowId: string;
    name: string;
    description: string;
    problemSolved: string;
    tags: string[];
    category?: TemplateCategory;
  }) => Promise<StarterTemplateRecord | null> | StarterTemplateRecord | null;
  onNotice?: (message: string) => void;
}

export function FlowmappTemplatesView({
  templates,
  workflows,
  canEdit,
  onUseTemplate,
  onPublishTemplate,
  onNotice,
}: FlowmappTemplatesViewProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("ALL");
  const [triggerFilter, setTriggerFilter] = useState<"ALL" | TriggerKind>("ALL");
  const [categoryFilter, setCategoryFilter] = useState<"ALL" | TemplateCategory>("ALL");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>(templates[0]?.id ?? "");
  const [mobileView, setMobileView] = useState<"list" | "detail">("list");

  // Publish Workflow as Template modal state
  const [publishOpen, setPublishOpen] = useState(false);
  const [publishWfId, setPublishWfId] = useState<string>(workflows[0]?.id ?? "");
  const [publishName, setPublishName] = useState("");
  const [publishProblem, setPublishProblem] = useState("");
  const [publishDesc, setPublishDesc] = useState("");
  const [publishTags, setPublishTags] = useState("AppSec, Kotlin PSI");
  const [publishError, setPublishError] = useState<string | null>(null);
  const [publishing, setPublishing] = useState(false);

  const filterPopoverRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    if (!publishOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setPublishOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [publishOpen]);

  const filteredTemplates = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return templates.filter((tpl) => {
      if (sourceFilter === "BUILTIN" && !tpl.isBuiltin) return false;
      if (sourceFilter === "TEAM" && tpl.isBuiltin) return false;
      if (triggerFilter !== "ALL" && tpl.trigger !== triggerFilter) return false;
      if (categoryFilter !== "ALL" && tpl.category !== categoryFilter) return false;
      if (!q) return true;
      return (
        tpl.name.toLowerCase().includes(q) ||
        tpl.slug.toLowerCase().includes(q) ||
        tpl.problemSolved.toLowerCase().includes(q) ||
        tpl.description.toLowerCase().includes(q) ||
        tpl.tags.some((t) => t.toLowerCase().includes(q)) ||
        tpl.nodes.some((n) => n.pluginId.toLowerCase().includes(q) || n.label.toLowerCase().includes(q))
      );
    });
  }, [templates, searchQuery, sourceFilter, triggerFilter, categoryFilter]);

  const activeTemplate = useMemo(() => {
    const exact = filteredTemplates.find((item) => item.id === selectedTemplateId);
    return exact ?? filteredTemplates[0] ?? null;
  }, [filteredTemplates, selectedTemplateId]);

  const activeFiltersCount =
    (sourceFilter !== "ALL" ? 1 : 0) +
    (triggerFilter !== "ALL" ? 1 : 0) +
    (categoryFilter !== "ALL" ? 1 : 0);

  const resetFilters = () => {
    setSearchQuery("");
    setSourceFilter("ALL");
    setTriggerFilter("ALL");
    setCategoryFilter("ALL");
  };

  const openPublishModal = () => {
    const defaultWf = workflows[0];
    setPublishWfId(defaultWf?.id ?? "");
    setPublishName(defaultWf ? `${defaultWf.name} (шаблон)` : "");
    setPublishProblem(defaultWf?.highlights[0] ?? "Стандартизованная проверка безопасности команды");
    setPublishDesc(defaultWf?.description ?? "");
    setPublishTags(defaultWf ? `${defaultWf.trigger}, AppSec, Kotlin` : "AppSec, Kotlin");
    setPublishError(null);
    setPublishOpen(true);
  };

  const selectedPublishWf = useMemo(
    () => workflows.find((w) => w.id === publishWfId) ?? workflows[0] ?? null,
    [workflows, publishWfId],
  );

  const sanitizationPreviewItems = useMemo(() => {
    if (!selectedPublishWf) return [];
    const items: string[] = [
      "Все привязки secretBindings (токены ботов, HMAC, SMTP, MCP)",
    ];
    if (selectedPublishWf.nodes.some((n) => n.pluginId === "source.git")) {
      items.push("URL и ветка репозитория в source.git");
    }
    if (selectedPublishWf.nodes.some((n) => n.pluginId === "source.upload")) {
      items.push("Ссылка на загруженный ZIP-архив в source.upload");
    }
    if (
      selectedPublishWf.nodes.some(
        (n) =>
          n.pluginId === "notify.telegram" ||
          n.pluginId === "notify.webhook" ||
          n.pluginId === "notify.smtp",
      )
    ) {
      items.push("Адреса доставки: chatId, webhook URL и email-получатели");
    }
    if (selectedPublishWf.nodes.some((n) => n.pluginId === "mcp.tool")) {
      items.push("Привязка конкретного Outbound MCP Connection");
    }
    return items;
  }, [selectedPublishWf]);

  const handlePublishSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canEdit || !selectedPublishWf || publishing) return;
    if (!publishName.trim()) {
      setPublishError("Укажите название шаблона перед публикацией.");
      return;
    }
    const parsedTags = publishTags
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 6);

    setPublishing(true);
    try {
      const created = await onPublishTemplate({
        workflowId: selectedPublishWf.id,
        name: publishName.trim(),
        description: publishDesc.trim() || selectedPublishWf.description,
        problemSolved:
          publishProblem.trim() || "Повторно используемый граф проверок безопасности",
        tags: parsedTags,
      });

      if (created) {
        resetFilters();
        setSelectedTemplateId(created.id);
        setMobileView("detail");
        setPublishOpen(false);
      }
    } finally {
      setPublishing(false);
    }
  };

  const builtinCount = templates.filter((t) => t.isBuiltin).length;
  const teamCount = templates.length - builtinCount;

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden bg-[#ffffff] md:flex-row">
      {/* LEFT CATALOG RAIL */}
      <aside
        aria-label="Каталог шаблонов Workflow"
        className={`${
          mobileView === "detail" ? "hidden md:flex" : "flex"
        } min-h-0 w-full flex-1 flex-col border-[#8c9baa]/50 bg-[#ffffff] md:w-[356px] md:flex-none md:border-r lg:w-[392px]`}
      >
        {/* Rail Header */}
        <div className="flex shrink-0 items-center justify-between gap-2 border-b border-[#8c9baa]/45 px-3.5 py-3">
          <div className="flex min-w-0 items-center gap-2">
            <h1 className="text-[18px] font-bold leading-none tracking-[-0.03em] text-[#000000]">
              Шаблоны
            </h1>
            <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[12px] font-semibold leading-none text-[#222222]">
              {templates.length}
            </span>
          </div>

          {canEdit && workflows.length > 0 && (
            <button
              type="button"
              onClick={openPublishModal}
              className="fm-btn-ink fm-focus inline-flex min-h-[36px] shrink-0 cursor-pointer items-center gap-1.5 px-3.5 text-[12.5px] font-medium"
            >
              <Plus className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
              <span>Опубликовать</span>
            </button>
          )}
        </div>

        {/* Search + Filter Popover */}
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
                placeholder="Поиск по задаче, ноде или тегу..."
                aria-label="Поиск шаблонов"
                className="fm-focus min-h-[40px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] pl-8 pr-8 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[13px] [&::-webkit-search-cancel-button]:appearance-none"
              />
              {searchQuery.length > 0 && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  aria-label="Очистить поиск шаблонов"
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
                    ? `Фильтры шаблонов (${activeFiltersCount})`
                    : "Фильтры шаблонов"
                }
                title="Фильтры каталога шаблонов"
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
                  aria-label="Фильтры каталога шаблонов"
                  className="fm-float absolute right-0 top-[calc(100%+8px)] z-40 w-[min(330px,calc(100vw-2rem))] origin-top-right rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-4 md:left-0 md:right-auto md:origin-top-left"
                >
                  <div className="flex items-center justify-between gap-2 border-b border-[#8c9baa]/35 pb-2">
                    <span className="text-[13px] font-semibold text-[#000000]">Фильтры</span>
                    <div className="flex items-center gap-1.5">
                      {activeFiltersCount > 0 && (
                        <button
                          type="button"
                          onClick={resetFilters}
                          className="fm-focus cursor-pointer rounded-full px-2 py-0.5 text-[12px] font-medium text-[#0050ff] hover:underline"
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
                      <p className="mb-1.5 text-[12px] font-semibold text-[#222222]">Источник</p>
                      <div className="flex flex-wrap gap-1.5">
                        {SOURCE_FILTER_OPTIONS.map((item) => {
                          const countSuffix =
                            item.id === "BUILTIN"
                              ? ` (${builtinCount})`
                              : item.id === "TEAM"
                                ? ` (${teamCount})`
                                : "";
                          return (
                            <button
                              key={item.id}
                              type="button"
                              onClick={() => setSourceFilter(item.id)}
                              aria-pressed={sourceFilter === item.id}
                              className={`fm-focus fm-tnum min-h-[32px] cursor-pointer rounded-full px-2.5 text-[12px] font-medium transition-colors ${
                                sourceFilter === item.id
                                  ? "bg-[#000000] text-[#ffffff]"
                                  : "border border-[#8c9baa]/75 text-[#222222] hover:border-[#0080ff]"
                              }`}
                            >
                              {item.label}
                              {countSuffix}
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    <div>
                      <p className="mb-1.5 text-[12px] font-semibold text-[#222222]">Триггер</p>
                      <div className="flex flex-wrap gap-1.5">
                        {TRIGGER_FILTER_OPTIONS.map((item) => (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => setTriggerFilter(item.id)}
                            aria-pressed={triggerFilter === item.id}
                            className={`fm-focus inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 rounded-full px-2.5 text-[12px] font-medium transition-colors ${
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
                      <p className="mb-1.5 text-[12px] font-semibold text-[#222222]">Сценарий</p>
                      <div className="flex flex-wrap gap-1.5">
                        {CATEGORY_FILTER_OPTIONS.map((item) => (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => setCategoryFilter(item.id)}
                            aria-pressed={categoryFilter === item.id}
                            className={`fm-focus min-h-[32px] cursor-pointer rounded-full px-2.5 text-[12px] font-medium transition-colors ${
                              categoryFilter === item.id
                                ? "bg-[#0066e6] text-[#ffffff]"
                                : "border border-[#8c9baa]/75 text-[#222222] hover:border-[#0080ff]"
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

          {activeFiltersCount > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              {sourceFilter !== "ALL" && (
                <button
                  type="button"
                  onClick={() => setSourceFilter("ALL")}
                  className="fm-focus inline-flex min-h-[28px] cursor-pointer items-center gap-1 rounded-full bg-[#000000] px-2.5 text-[12px] font-medium text-[#ffffff]"
                >
                  <span>{sourceFilter === "BUILTIN" ? "Встроенные" : "Командные"}</span>
                  <X className="h-3 w-3 stroke-[2]" aria-hidden="true" />
                </button>
              )}
              {triggerFilter !== "ALL" && (
                <button
                  type="button"
                  onClick={() => setTriggerFilter("ALL")}
                  className="fm-focus inline-flex min-h-[28px] cursor-pointer items-center gap-1 rounded-full bg-[#000000] px-2.5 text-[12px] font-medium text-[#ffffff]"
                >
                  <span>{triggerFilter}</span>
                  <X className="h-3 w-3 stroke-[2]" aria-hidden="true" />
                </button>
              )}
              {categoryFilter !== "ALL" && (
                <button
                  type="button"
                  onClick={() => setCategoryFilter("ALL")}
                  className="fm-focus inline-flex min-h-[28px] cursor-pointer items-center gap-1 rounded-full bg-[#0066e6] px-2.5 text-[12px] font-medium text-[#ffffff]"
                >
                  <span>{CATEGORY_LABELS[categoryFilter]}</span>
                  <X className="h-3 w-3 stroke-[2]" aria-hidden="true" />
                </button>
              )}
              <button
                type="button"
                onClick={resetFilters}
                className="fm-focus cursor-pointer px-1.5 text-[12px] font-medium text-[#0050ff] hover:underline"
              >
                Сбросить
              </button>
            </div>
          )}
        </div>

        {/* Scrollable Vertical Template List */}
        <div className="fm-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain">
          {filteredTemplates.length === 0 ? (
            <div className="p-6 text-center">
              <p className="text-[14px] font-semibold text-[#000000]">Шаблоны не найдены</p>
              <p className="mt-1 text-[12.5px] text-[#636f7b]">
                Попробуйте изменить запрос или сбросить активные фильтры.
              </p>
              <button
                type="button"
                onClick={resetFilters}
                className="fm-btn-outline fm-focus mt-3 min-h-[36px] cursor-pointer px-4 text-[12.5px] font-medium"
              >
                Сбросить фильтры
              </button>
            </div>
          ) : (
            <ul className="divide-y divide-[#8c9baa]/35 border-b border-[#8c9baa]/35">
              {filteredTemplates.map((tpl) => {
                const isSelected = activeTemplate?.id === tpl.id;
                return (
                  <li key={tpl.id}>
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedTemplateId(tpl.id);
                        setMobileView("detail");
                      }}
                      aria-current={isSelected ? "true" : undefined}
                      className={`fm-focus relative flex w-full cursor-pointer flex-col gap-2 px-3.5 py-3.5 text-left transition-colors ${
                        isSelected ? "bg-[#c5e0fb]/30" : "bg-[#ffffff] hover:bg-[#f6faff]"
                      }`}
                    >
                      <div className="flex items-start gap-2.5">
                        <FlowmappPastelTriggerIcon trigger={tpl.trigger} />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-start justify-between gap-2">
                            <span
                              title={tpl.name}
                              className={`line-clamp-2 [overflow-wrap:anywhere] text-[13.5px] font-semibold leading-[1.3] tracking-[-0.015em] ${
                                isSelected ? "text-[#0050ff]" : "text-[#000000]"
                              }`}
                            >
                              {tpl.name}
                            </span>
                            {tpl.featured ? (
                              <span className="shrink-0 rounded-full bg-[#c5e0fb] px-2 py-0.5 text-[12px] font-semibold text-[#000000]">
                                Эталон
                              </span>
                            ) : !tpl.isBuiltin ? (
                              <span className="shrink-0 rounded-full bg-[#c8f0d8] px-2 py-0.5 text-[12px] font-semibold text-[#000000]">
                                Команда
                              </span>
                            ) : null}
                          </div>

                          <p className="mt-1 line-clamp-2 [overflow-wrap:anywhere] text-[12px] leading-[1.4] text-[#636f7b]">
                            {tpl.problemSolved}
                          </p>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 pl-[42px] text-[12px] text-[#636f7b]">
                        <div className="fm-tnum flex items-center gap-2">
                          <span className="rounded-full border border-[#8c9baa]/50 bg-[#ffffff] px-2 py-0.5 font-medium text-[#222222]">
                            {tpl.nodes.length} {pluralRu(tpl.nodes.length, "нода", "ноды", "нод")}
                          </span>
                          <span>{tpl.trigger}</span>
                        </div>
                        <span className="fm-tnum inline-flex items-center gap-1 text-[#636f7b]">
                          <Copy className="h-3 w-3 stroke-[1.7]" aria-hidden="true" />
                          {formatCount(tpl.cloneCount)}
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

      {/* RIGHT MAIN PREVIEW & CLONE WORKBENCH */}
      <section
        aria-label="Предпросмотр графа и параметров выбранного шаблона"
        className={`${
          mobileView === "list" ? "hidden md:flex" : "flex"
        } min-h-0 min-w-0 flex-1 flex-col bg-[#ffffff]`}
      >
        {/* Mobile Back Strip */}
        <div className="flex shrink-0 items-center justify-between gap-2 border-b border-[#8c9baa]/45 bg-[#ffffff] px-3 py-2 md:hidden">
          <button
            type="button"
            onClick={() => setMobileView("list")}
            className="fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 rounded-full px-2.5 text-[13px] font-semibold text-[#0050ff]"
          >
            <ArrowLeft className="h-4 w-4 stroke-[2]" aria-hidden="true" />
            <span>Все шаблоны</span>
          </button>
          <span className="fm-tnum text-[12px] text-[#636f7b]">
            {filteredTemplates.length} в каталоге
          </span>
        </div>

        {activeTemplate ? (
          <ReactFlowProvider>
            <TemplateCanvasPreviewInner
              template={activeTemplate}
              canEdit={canEdit}
              onClone={onUseTemplate}
              onNotice={onNotice}
            />
          </ReactFlowProvider>
        ) : (
          <div className="flex flex-1 flex-col items-center justify-center p-8 text-center">
            <span
              aria-hidden="true"
              className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-[#c5e0fb]/50 text-[#000000]"
            >
              <Layers className="h-5 w-5 stroke-[1.7]" />
            </span>
            <p className="mt-3 text-[15px] font-semibold text-[#000000]">
              Выберите шаблон для предпросмотра графа
            </p>
            <p className="mt-1 max-w-[42ch] text-[13px] text-[#636f7b]">
              Здесь отображается интерактивная схема DAG выбранного шаблона, очищенные параметры
              и быстрое клонирование в редактор.
            </p>
          </div>
        )}
      </section>

      {/* PUBLISH WORKFLOW AS TEMPLATE MODAL */}
      {publishOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="fm-publish-template-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/25 p-4"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setPublishOpen(false);
          }}
        >
          <div className="fm-float flex max-h-[88dvh] w-full max-w-[600px] flex-col overflow-hidden rounded-[24px] border border-[#8c9baa] bg-[#ffffff]">
            <div className="flex items-center justify-between gap-3 border-b border-[#8c9baa]/40 px-5 py-4">
              <h2
                id="fm-publish-template-title"
                className="text-[18px] font-bold tracking-[-0.025em] text-[#000000]"
              >
                Опубликовать Workflow как шаблон
              </h2>
              <button
                type="button"
                onClick={() => setPublishOpen(false)}
                aria-label="Закрыть окно публикации шаблона"
                className="fm-focus inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/70 text-[#222222] transition-colors hover:border-[#000000]"
              >
                <X className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
              </button>
            </div>

            <form
              onSubmit={handlePublishSubmit}
              className="fm-scroll flex-1 space-y-4 overflow-y-auto overscroll-contain p-5"
            >
              <div>
                <label
                  htmlFor="fm-pub-workflow"
                  className="block text-[13px] font-semibold text-[#000000]"
                >
                  Исходная доска Workflow
                </label>
                <select
                  id="fm-pub-workflow"
                  value={publishWfId}
                  onChange={(e) => {
                    const nextId = e.target.value;
                    setPublishWfId(nextId);
                    const found = workflows.find((w) => w.id === nextId);
                    if (found) {
                      setPublishName(`${found.name} (шаблон)`);
                      setPublishDesc(found.description);
                      setPublishProblem(
                        found.highlights[0] ?? "Стандартизованный сценарий проверки безопасности",
                      );
                    }
                  }}
                  className="fm-select fm-focus mt-1.5 min-h-[44px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 text-[16px] text-[#000000] sm:text-[14px]"
                >
                  {workflows.map((wf) => (
                    <option key={wf.id} value={wf.id}>
                      {wf.name} ({wf.nodes.length}{" "}
                      {pluralRu(wf.nodes.length, "нода", "ноды", "нод")})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label
                  htmlFor="fm-pub-name"
                  className="block text-[13px] font-semibold text-[#000000]"
                >
                  Название шаблона
                </label>
                <input
                  id="fm-pub-name"
                  type="text"
                  maxLength={120}
                  value={publishName}
                  onChange={(e) => {
                    setPublishName(e.target.value);
                    if (publishError) setPublishError(null);
                  }}
                  placeholder="Например, Spring Boot Pre-Merge Security Gate"
                  className="fm-focus mt-1.5 min-h-[44px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[14px]"
                />
                {publishError && (
                  <p className="mt-1 text-[12px] font-medium text-[#dc2626]">{publishError}</p>
                )}
              </div>

              <div>
                <label
                  htmlFor="fm-pub-problem"
                  className="block text-[13px] font-semibold text-[#000000]"
                >
                  Какую задачу решает
                </label>
                <input
                  id="fm-pub-problem"
                  type="text"
                  maxLength={180}
                  value={publishProblem}
                  onChange={(e) => setPublishProblem(e.target.value)}
                  placeholder="Коротко: зачем команде этот шаблон"
                  className="fm-focus mt-1.5 min-h-[44px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[14px]"
                />
              </div>

              <div>
                <label
                  htmlFor="fm-pub-desc"
                  className="block text-[13px] font-semibold text-[#000000]"
                >
                  Описание
                </label>
                <textarea
                  id="fm-pub-desc"
                  rows={2}
                  value={publishDesc}
                  onChange={(e) => setPublishDesc(e.target.value)}
                  className="fm-focus mt-1.5 w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] p-3 text-[16px] leading-[1.45] text-[#000000] sm:text-[13.5px]"
                />
              </div>

              <div>
                <label
                  htmlFor="fm-pub-tags"
                  className="block text-[13px] font-semibold text-[#000000]"
                >
                  Теги (через запятую)
                </label>
                <input
                  id="fm-pub-tags"
                  type="text"
                  value={publishTags}
                  onChange={(e) => setPublishTags(e.target.value)}
                  placeholder="SAST, Secrets, Policy Gate"
                  className="fm-focus mt-1.5 min-h-[44px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[14px]"
                />
              </div>

              {/* Automatic Sanitization Guarantee Box */}
              <div className="rounded-[16px] border border-[#8c9baa]/60 bg-[#c8f0d8]/30 p-3.5">
                <div className="flex items-center gap-2 text-[12.5px] font-semibold text-[#000000]">
                  <ShieldCheck className="h-4 w-4 shrink-0 stroke-[1.8]" aria-hidden="true" />
                  <span>Автоматическая очистка перед публикацией</span>
                </div>
                <ul className="mt-2 space-y-1 text-[12px] leading-[1.4] text-[#222222]">
                  {sanitizationPreviewItems.map((item) => (
                    <li key={item} className="flex items-start gap-2">
                      <Check
                        className="mt-0.5 h-3.5 w-3.5 shrink-0 stroke-[2] text-[#0f5132]"
                        aria-hidden="true"
                      />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
                <button
                  type="button"
                  onClick={() => setPublishOpen(false)}
                  className="fm-btn-outline fm-focus min-h-[42px] cursor-pointer px-4 text-[13px] font-medium"
                >
                  Отмена
                </button>
                <button
                  type="submit"
                  disabled={publishing}
                  className="fm-btn-signal fm-focus inline-flex min-h-[42px] cursor-pointer items-center gap-1.5 px-5 text-[13px] font-semibold disabled:cursor-not-allowed disabled:opacity-55"
                >
                  <Check className="h-4 w-4 stroke-[2]" aria-hidden="true" />
                  <span>{publishing ? "Публикация…" : "Опубликовать в библиотеку"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
