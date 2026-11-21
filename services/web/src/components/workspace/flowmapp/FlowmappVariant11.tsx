"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  ArrowUpRight,
  Check,
  FilePlus2,
  History,
  LayoutTemplate,
  Play,
  Plus,
  Search,
  SlidersHorizontal,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import {
  AI_TEXT_PRESETS,
  type PolicyVerdict,
  type TriggerKind,
} from "@/data/workflows-workspace-data";
import {
  useWorkflowsWorkspace,
  type AiWorkflowPreview,
} from "../useWorkflowsWorkspace";
import { FlowmappCanvas11 } from "./FlowmappCanvas11";
import { FlowmappRunHistoryView } from "./FlowmappRunHistoryView";
import { FlowmappTemplatesView } from "./FlowmappTemplatesView";
import {
  FlowmappEmptyState,
  FlowmappHeader,
  FlowmappNoticeBar,
  FlowmappPastelTriggerIcon,
  FlowmappPolicyPill,
  FlowmappRunStatusText,
  FlowmappSeverityPills,
} from "./FlowmappChrome";

type CreateModalTab = "blank" | "ai" | "template";

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

const QUICK_TRIGGERS: Array<{ id: TriggerKind; label: string; dot: string }> = [
  { id: "Manual", label: "Manual", dot: "#fff3c4" },
  { id: "Webhook", label: "Webhook", dot: "#c8f0d8" },
  { id: "Schedule", label: "Schedule", dot: "#ffe0c4" },
];

const GATE_FILTER_OPTIONS: Array<{
  id: "ALL" | PolicyVerdict;
  label: string;
}> = [
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

/**
 * Вариант 11 — Мастер-сборка на базе Flowmapp 5.
 * Изолированная копия для переноса лучших фишек из всех остальных вариантов (1–10).
 */
type HomeSection = "workflows" | "runs" | "templates";

function sectionFromLocation(): HomeSection {
  if (typeof window === "undefined") return "workflows";
  const section = new URLSearchParams(window.location.search).get("section");
  if (section === "runs" || section === "templates") return section;
  return "workflows";
}

export function FlowmappVariant11() {
  const ws = useWorkflowsWorkspace();
  const router = useRouter();
  const [activeSection, setActiveSection] = useState<HomeSection>("workflows");
  const [runWorkflowFilterId, setRunWorkflowFilterId] = useState<string | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createTab, setCreateTab] = useState<CreateModalTab>("blank");
  const [descTooltip, setDescTooltip] = useState<{
    text: string;
    x: number;
    y: number;
  } | null>(null);

  // Blank tab state
  const [newBoardName, setNewBoardName] = useState("");
  const [newBoardTrigger, setNewBoardTrigger] = useState<TriggerKind>("Manual");

  // AI tab state
  const [selectedPresetId, setSelectedPresetId] = useState(AI_TEXT_PRESETS[0]?.id ?? "");
  const [aiPrompt, setAiPrompt] = useState(AI_TEXT_PRESETS[0]?.prompt ?? "");
  const [aiCustomName, setAiCustomName] = useState("");
  const [aiPreview, setAiPreview] = useState<AiWorkflowPreview | null>(null);
  const [aiPreviewLoading, setAiPreviewLoading] = useState(false);
  const [aiPreviewError, setAiPreviewError] = useState<string | null>(null);
  const [aiSaving, setAiSaving] = useState(false);

  const filterPopoverRef = useRef<HTMLDivElement>(null);

  const selectSection = (section: HomeSection) => {
    setActiveSection(section);
    if (section === "workflows") {
      setRunWorkflowFilterId(null);
      router.replace("/", { scroll: false });
      return;
    }
    router.replace(`/?section=${section}`, { scroll: false });
  };

  useEffect(() => {
    setActiveSection(sectionFromLocation());
  }, []);

  useEffect(() => {
    if (!ws.historyFocus || ws.activeBoardId) return;
    selectSection("runs");
    // selectSection is recreated each render; the focus token is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ws.historyFocus, ws.activeBoardId]);

  const activeFiltersCount =
    (ws.triggerFilter !== "ALL" ? 1 : 0) + (ws.verdictFilter !== "ALL" ? 1 : 0);

  const openHistoryForWorkflow = (workflowId: string) => {
    setRunWorkflowFilterId(workflowId);
    setActiveSection("runs");
  };

  const activeAiPreset =
    AI_TEXT_PRESETS.find((item) => item.id === selectedPresetId) ?? AI_TEXT_PRESETS[0];

  const openCreateModal = (initialTab: CreateModalTab = "blank") => {
    setCreateTab(initialTab);
    setAiPreview(null);
    setAiPreviewError(null);
    setCreateModalOpen(true);
  };

  useEffect(() => {
    if (!filtersOpen) return;
    const onMouseDown = (event: MouseEvent) => {
      if (
        filterPopoverRef.current &&
        !filterPopoverRef.current.contains(event.target as Node)
      ) {
        setFiltersOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setFiltersOpen(false);
      }
    };
    window.addEventListener("mousedown", onMouseDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [filtersOpen]);

  useEffect(() => {
    if (!createModalOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setCreateModalOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [createModalOpen]);

  const handleCreateBlankSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!ws.canEdit) return;
    ws.createBlankWorkflow({
      name: newBoardName.trim() || undefined,
      trigger: newBoardTrigger,
      openCanvas: true,
    });
    setNewBoardName("");
    setCreateModalOpen(false);
  };

  const handleGenerateAiPreview = async (e?: FormEvent<HTMLFormElement>) => {
    e?.preventDefault();
    if (!ws.canEdit || aiPreviewLoading) return;
    setAiPreviewLoading(true);
    setAiPreviewError(null);
    try {
      const preview = await ws.previewAiWorkflow(aiPrompt);
      setAiPreview(preview);
      if (!aiCustomName.trim()) {
        setAiCustomName(preview.workflowName);
      }
    } catch (err) {
      setAiPreview(null);
      setAiPreviewError(
        err instanceof Error ? err.message : "Не удалось сгенерировать превью workflow",
      );
    } finally {
      setAiPreviewLoading(false);
    }
  };

  const handleConfirmSaveAiWorkflow = async () => {
    if (!ws.canEdit || !aiPreview || aiSaving) return;
    setAiSaving(true);
    setAiPreviewError(null);
    try {
      const created = await ws.saveGeneratedWorkflow(
        aiCustomName.trim() || aiPreview.workflowName,
        aiPreview.graph,
        aiPreview.description,
        true,
      );
      if (created) {
        setAiCustomName("");
        setAiPreview(null);
        setCreateModalOpen(false);
      }
    } catch (err) {
      setAiPreviewError(
        err instanceof Error ? err.message : "Не удалось сохранить сгенерированный workflow",
      );
    } finally {
      setAiSaving(false);
    }
  };

  if (ws.activeBoardWorkflow && ws.activeBoardGraph) {
    const boardRuns = ws.runHistory.filter(
      (r) => r.workflowId === ws.activeBoardWorkflow?.id,
    );
    return (
      <>
        <FlowmappCanvas11
          workflow={ws.activeBoardWorkflow}
          runs={boardRuns}
          initialNodes={ws.activeBoardGraph.nodes}
          initialEdges={ws.activeBoardGraph.edges}
          canEdit={ws.canEdit}
          availableSecrets={ws.availableSecrets}
          onBack={() => {
            ws.closeBoard();
            selectSection("workflows");
          }}
          onRename={ws.renameWorkflow}
          onSyncGraph={ws.updateBoardGraph}
          onRunCompleted={ws.recordCanvasRun}
          onNotice={ws.showNotice}
          onServerRun={() => {
            if (ws.activeBoardWorkflow) ws.triggerRun(ws.activeBoardWorkflow);
          }}
          onCancelRun={(runId) => void ws.cancelRun(runId)}
          onRerunFromNode={(runId, nodeId) => void ws.rerunFromNode(runId, nodeId)}
          serverRunning={Boolean(ws.activeBoardWorkflow && ws.runningMap[ws.activeBoardWorkflow.id])}
          nodeRunStatuses={ws.nodeRunStatuses}
          openHistoryAt={ws.historyFocus?.runId && ws.activeBoardWorkflow?.id && ws.runHistory.some((run) => run.id === ws.historyFocus?.runId && run.workflowId === ws.activeBoardWorkflow?.id) ? ws.historyFocus.at : 0}
        />
        <FlowmappNoticeBar
          notice={ws.notice}
          onUndo={ws.undoDelete}
          onDismiss={() => ws.setNotice(null)}
        />
      </>
    );
  }

  return (
    <div
      className={
        activeSection === "runs" || activeSection === "templates"
          ? "flex h-dvh flex-col overflow-hidden bg-[#ffffff] text-[#000000]"
          : "min-h-dvh bg-[#ffffff] text-[#000000]"
      }
    >
      <FlowmappHeader
        role={ws.role}
        onNavigateHint={ws.showNotice}
        activeSection={activeSection}
        onSelectSection={selectSection}
        runsCount={ws.runHistory.length}
        templatesCount={ws.templates.length}
      />

      {activeSection === "runs" ? (
        <FlowmappRunHistoryView
          runs={ws.runHistory}
          workflows={ws.workflows}
          boardsMap={ws.boardsMap}
          initialWorkflowFilterId={runWorkflowFilterId}
          canEdit={ws.canEdit}
          onOpenEditor={(wfId) => ws.openBoard(wfId)}
          onReplayRun={(wf) => ws.triggerRun(wf)}
          onCancelRun={(runId) => void ws.cancelRun(runId)}
          onRerunFromNode={(runId, nodeId) => void ws.rerunFromNode(runId, nodeId)}
          onNotice={ws.showNotice}
          focusRunId={ws.historyFocus?.runId ?? null}
        />
      ) : activeSection === "templates" ? (
        <FlowmappTemplatesView
          templates={ws.templates}
          workflows={ws.workflows}
          canEdit={ws.canEdit}
          onUseTemplate={(tpl, openCanvas = true, customName) => {
            ws.createFromTemplate(tpl, openCanvas, customName);
            if (!openCanvas) {
              setActiveSection("workflows");
            }
          }}
          onPublishTemplate={ws.publishTemplate}
          onNotice={ws.showNotice}
        />
      ) : (
        <main id="workflows-main" className="mx-auto max-w-[1200px] px-4 pb-24 pt-7 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#8c9baa]/45 pb-4">
          <h1 className="text-[28px] font-bold leading-[1.1] tracking-[-0.035em] text-[#000000]">
            Workflows
          </h1>

          {ws.canEdit && (
            <button
              type="button"
              onClick={() => openCreateModal("blank")}
              className="fm-btn-signal fm-focus inline-flex min-h-[44px] cursor-pointer items-center gap-1.5 px-5 text-[13px] font-semibold"
            >
              <Plus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
              Создать доску
            </button>
          )}
        </div>

        {ws.loading && ws.workflows.length === 0 ? (
          <p className="py-16 text-center text-[14px] text-[#636f7b]">Загружаем сценарии с сервера…</p>
        ) : ws.isEmptyWorkspace ? (
          <FlowmappEmptyState
            canEdit={ws.canEdit}
            templates={ws.templates}
            onUseTemplate={ws.createFromTemplate}
            onOpenAi={() => openCreateModal("ai")}
          />
        ) : (
          <>
            {/* Full-Width Search Bar + Filter Icon Button Immediately on the Right */}
            <div className="py-4">
              <div className="flex w-full items-center gap-2">
                <div className="relative min-w-0 flex-1">
                  <Search
                    className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 stroke-[1.6] text-[#636f7b]"
                    aria-hidden="true"
                  />
                  <input
                    type="search"
                    enterKeyHint="search"
                    value={ws.searchQuery}
                    onChange={(e) => ws.setSearchQuery(e.target.value)}
                    placeholder="Поиск по названию, источнику или триггеру..."
                    aria-label="Поиск Workflow"
                    className="fm-focus min-h-[44px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] pl-10 pr-10 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[14px] [&::-webkit-search-cancel-button]:appearance-none"
                  />
                  {ws.searchQuery.length > 0 && (
                    <button
                      type="button"
                      onClick={() => ws.setSearchQuery("")}
                      aria-label="Очистить поиск"
                      className="fm-focus absolute right-2 top-1/2 inline-flex h-8 w-8 -translate-y-1/2 cursor-pointer items-center justify-center rounded-full text-[#636f7b] transition-colors hover:bg-[#f6faff] hover:text-[#000000]"
                    >
                      <X className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                    </button>
                  )}
                </div>

                {/* Filter Popover Trigger (Right Edge of Full-Width Search Bar) */}
                <div ref={filterPopoverRef} className="relative shrink-0">
                  <button
                    type="button"
                    onClick={() => setFiltersOpen((prev) => !prev)}
                    aria-expanded={filtersOpen}
                    aria-haspopup="dialog"
                    aria-label={
                      activeFiltersCount > 0
                        ? `Фильтры (активно: ${activeFiltersCount})`
                        : "Открыть фильтры"
                    }
                    title="Фильтры по триггерам и Policy Gate"
                    className={`fm-focus relative inline-flex h-[44px] min-w-[44px] cursor-pointer items-center justify-center gap-1.5 rounded-full border px-3 text-[13px] font-medium transition-colors active:scale-[0.97] ${
                      filtersOpen || activeFiltersCount > 0
                        ? "border-[#0080ff] bg-[#000000] text-[#ffffff]"
                        : "border-[#8c9baa] bg-[#ffffff] text-[#222222] hover:border-[#0080ff] hover:bg-[#f6faff]"
                    }`}
                  >
                    <SlidersHorizontal className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
                    {activeFiltersCount > 0 && (
                      <span className="fm-tnum inline-flex h-5 min-w-[20px] items-center justify-center rounded-full bg-[#0080ff] px-1.5 text-[11px] font-semibold text-[#ffffff]">
                        {activeFiltersCount}
                      </span>
                    )}
                  </button>

                  {filtersOpen && (
                    <div
                      role="dialog"
                      aria-label="Фильтры списка Workflow"
                      className="fm-float absolute right-0 top-[calc(100%+8px)] z-30 w-[min(360px,calc(100vw-2rem))] rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-4"
                    >
                      <div className="flex items-center justify-between gap-2 border-b border-[#8c9baa]/35 pb-2.5">
                        <span className="text-[13px] font-semibold tracking-[-0.015em] text-[#000000]">
                          Фильтры
                        </span>
                        <div className="flex items-center gap-2">
                          {activeFiltersCount > 0 && (
                            <button
                              type="button"
                              onClick={() => {
                                ws.setTriggerFilter("ALL");
                                ws.setVerdictFilter("ALL");
                              }}
                              className="fm-focus cursor-pointer rounded-full px-2 py-1 text-[12px] font-medium text-[#0050ff] hover:underline"
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

                      <div className="mt-3 space-y-3.5">
                        <div>
                          <p className="mb-2 text-[12px] font-semibold text-[#222222]">Триггер</p>
                          <div
                            role="group"
                            aria-label="Фильтр по триггеру"
                            className="flex flex-wrap gap-1.5"
                          >
                            {TRIGGER_FILTER_OPTIONS.map((item) => {
                              const active = ws.triggerFilter === item.id;
                              return (
                                <button
                                  key={item.id}
                                  type="button"
                                  onClick={() => ws.setTriggerFilter(item.id)}
                                  aria-pressed={active}
                                  className={`fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12px] font-medium transition-colors active:scale-[0.98] ${
                                    active
                                      ? "bg-[#000000] text-[#ffffff]"
                                      : "border border-[#8c9baa]/75 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                                  }`}
                                >
                                  {item.dot && (
                                    <span
                                      aria-hidden="true"
                                      className="h-2 w-2 shrink-0 rounded-full border border-[#000000]/15"
                                      style={{ backgroundColor: item.dot }}
                                    />
                                  )}
                                  {item.label}
                                </button>
                              );
                            })}
                          </div>
                        </div>

                        <div>
                          <p className="mb-2 text-[12px] font-semibold text-[#222222]">
                            Policy Gate
                          </p>
                          <div
                            role="group"
                            aria-label="Фильтр по Policy Gate"
                            className="flex flex-wrap gap-1.5"
                          >
                            {GATE_FILTER_OPTIONS.map((item) => {
                              const active = ws.verdictFilter === item.id;
                              return (
                                <button
                                  key={item.id}
                                  type="button"
                                  onClick={() => ws.setVerdictFilter(item.id)}
                                  aria-pressed={active}
                                  className={`fm-focus fm-tnum inline-flex min-h-[34px] cursor-pointer items-center rounded-full px-3 text-[12px] font-semibold transition-colors active:scale-[0.98] ${
                                    active
                                      ? "bg-[#0066e6] text-[#ffffff]"
                                      : "border border-[#8c9baa]/75 bg-[#ffffff] text-[#636f7b] hover:border-[#0080ff] hover:text-[#000000]"
                                  }`}
                                >
                                  {item.label}
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {activeFiltersCount > 0 && (
                <div className="mt-2.5 flex flex-wrap items-center gap-2">
                  {ws.triggerFilter !== "ALL" && (
                    <button
                      type="button"
                      onClick={() => ws.setTriggerFilter("ALL")}
                      className="fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full bg-[#000000] px-3 text-[12px] font-medium text-[#ffffff] transition-opacity hover:opacity-85"
                    >
                      <span>Триггер: {ws.triggerFilter}</span>
                      <X className="h-3 w-3 stroke-[2]" aria-hidden="true" />
                    </button>
                  )}
                  {ws.verdictFilter !== "ALL" && (
                    <button
                      type="button"
                      onClick={() => ws.setVerdictFilter("ALL")}
                      className="fm-focus fm-tnum inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 rounded-full bg-[#0066e6] px-3 text-[12px] font-semibold text-[#ffffff] transition-opacity hover:opacity-85"
                    >
                      <span>Gate: {ws.verdictFilter}</span>
                      <X className="h-3 w-3 stroke-[2]" aria-hidden="true" />
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => {
                      ws.setTriggerFilter("ALL");
                      ws.setVerdictFilter("ALL");
                    }}
                    className="fm-focus cursor-pointer rounded-full px-2.5 py-1 text-[12px] font-medium text-[#0050ff] hover:underline"
                  >
                    Сбросить все
                  </button>
                </div>
              )}
            </div>

            {ws.filteredWorkflows.length === 0 ? (
              <div className="mt-2 rounded-[20px] border border-[#8c9baa] p-10 text-center">
                <p className="text-[15px] font-semibold text-[#000000]">Ничего не найдено</p>
                <p className="mt-1 text-[13px] text-[#636f7b]">
                  Попробуйте сбросить поисковый запрос или выбранные фильтры.
                </p>
                <button
                  type="button"
                  onClick={ws.resetFilters}
                  className="fm-btn-outline fm-focus mt-3 min-h-[38px] cursor-pointer px-4 text-[13px] font-medium"
                >
                  Сбросить фильтры
                </button>
              </div>
            ) : (
              <div className="overflow-hidden rounded-[20px] border border-[#8c9baa] bg-[#ffffff]">
                {/* Mobile / tablet stacked list */}
                <div className="divide-y divide-[#8c9baa]/30 lg:hidden">
                  {ws.filteredWorkflows.map((wf) => {
                    const runState = ws.runningMap[wf.id];
                    return (
                      <div
                        key={wf.id}
                        onClick={() => ws.openBoard(wf.id)}
                        className="cursor-pointer p-4 transition-colors active:bg-[#c5e0fb]/20"
                      >
                        <div className="flex min-w-0 items-start gap-3">
                          <FlowmappPastelTriggerIcon trigger={wf.trigger} />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-start justify-between gap-2">
                              <button
                                type="button"
                                title={wf.name}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  ws.openBoard(wf.id);
                                }}
                                className="fm-focus inline-flex min-w-0 cursor-pointer items-center gap-1 text-left text-[14px] font-semibold tracking-[-0.015em] text-[#000000]"
                              >
                                <span className="truncate">{wf.name}</span>
                                <ArrowUpRight
                                  className="h-3.5 w-3.5 shrink-0 stroke-[1.8] text-[#636f7b]"
                                  aria-hidden="true"
                                />
                              </button>
                            </div>
                            <p className="mt-1 line-clamp-2 text-[12.5px] leading-snug text-[#636f7b]">
                              {wf.description}
                            </p>
                            {runState && (
                              <div className="mt-2 flex items-center gap-2">
                                <div className="h-1.5 w-24 overflow-hidden rounded-full bg-[#c5e0fb]/65">
                                  <div
                                    className="h-full w-full origin-left rounded-full bg-[#0080ff] transition-transform duration-300"
                                    style={{ transform: `scaleX(${runState.progress / 100})` }}
                                  />
                                </div>
                                <span className="fm-tnum truncate text-[12px] font-semibold text-[#0066e6]">
                                  {runState.stage} · {runState.progress}%
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-[#8c9baa]/25 pt-3">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <FlowmappPolicyPill verdict={wf.policyGate} />
                            <FlowmappSeverityPills crit={wf.critCount} high={wf.highCount} />
                            <span className="fm-tnum text-[12px] text-[#636f7b]">
                              {wf.updatedAt}
                            </span>
                          </div>
                          {ws.canEdit && (
                            <div
                              className="flex items-center gap-1.5"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <button
                                type="button"
                                onClick={() => openHistoryForWorkflow(wf.id)}
                                aria-label={`История прогонов ${wf.name}`}
                                className="fm-focus inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] text-[#636f7b]"
                              >
                                <History className="h-4 w-4 stroke-[1.6]" aria-hidden="true" />
                              </button>
                              <button
                                type="button"
                                onClick={() => ws.triggerRun(wf)}
                                disabled={Boolean(runState)}
                                className="fm-btn-ink fm-focus inline-flex h-9 cursor-pointer items-center gap-1.5 px-3.5 text-[12.5px] font-medium disabled:opacity-50"
                              >
                                <Play className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                                Пуск
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Desktop table */}
                <div className="fm-scroll hidden overflow-x-auto lg:block">
                <table className="w-full table-fixed border-collapse text-left">
                  <colgroup>
                    <col className="w-auto" />
                    <col className="w-[84px]" />
                    <col className="w-[86px]" />
                    <col className="w-[116px]" />
                    <col className="w-[104px]" />
                    <col className="w-[156px]" />
                    <col className="w-[122px]" />
                    {ws.canEdit && <col className="w-[168px]" />}
                  </colgroup>
                  <thead>
                    <tr className="border-b border-[#8c9baa]/45 text-[12px] font-semibold text-[#636f7b]">
                      <th className="py-3 pl-4 pr-3 font-semibold">Workflow</th>
                      <th className="px-2.5 py-3 font-semibold">Trigger</th>
                      <th className="px-2.5 py-3 font-semibold">Граф</th>
                      <th className="px-2.5 py-3 font-semibold">Run</th>
                      <th className="px-2.5 py-3 font-semibold">Policy Gate</th>
                      <th className="px-2.5 py-3 font-semibold">CRIT / HIGH</th>
                      <th className="px-2.5 py-3 font-semibold">Обновлён</th>
                      {ws.canEdit && (
                        <th className="py-3 pl-2 pr-4 text-right font-semibold">Действия</th>
                      )}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#8c9baa]/30">
                    {ws.filteredWorkflows.map((wf) => {
                      const runState = ws.runningMap[wf.id];
                      return (
                        <tr
                          key={wf.id}
                          onClick={() => {
                            setDescTooltip(null);
                            ws.openBoard(wf.id);
                          }}
                          className="group cursor-pointer transition-colors hover:bg-[#c5e0fb]/20"
                        >
                          <td className="min-w-0 py-3 pl-4 pr-3 align-middle">
                            <div className="flex min-w-0 items-start gap-2.5">
                              <FlowmappPastelTriggerIcon trigger={wf.trigger} />
                              <div className="min-w-0 flex-1">
                                <button
                                  type="button"
                                  title={wf.name}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setDescTooltip(null);
                                    ws.openBoard(wf.id);
                                  }}
                                  className="fm-focus inline-flex max-w-full cursor-pointer items-center gap-1 text-left text-[13.5px] font-semibold tracking-[-0.015em] text-[#000000] transition-colors group-hover:text-[#0066e6]"
                                >
                                  <span className="truncate">{wf.name}</span>
                                  <ArrowUpRight
                                    className="h-3.5 w-3.5 shrink-0 stroke-[1.8] text-[#636f7b] transition-transform duration-150 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-[#0066e6]"
                                    aria-hidden="true"
                                  />
                                </button>
                                <p
                                  title={wf.description}
                                  onMouseEnter={(e) => {
                                    const rect = e.currentTarget.getBoundingClientRect();
                                    setDescTooltip({
                                      text: wf.description,
                                      x: rect.left,
                                      y: rect.bottom + 8,
                                    });
                                  }}
                                  onMouseLeave={() => setDescTooltip(null)}
                                  className="mt-0.5 block w-full overflow-hidden text-ellipsis whitespace-nowrap text-[12px] text-[#636f7b]"
                                >
                                  {wf.description}
                                </p>
                                {runState && (
                                  <div className="mt-2 flex items-center gap-2">
                                    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-[#c5e0fb]/65">
                                      <div
                                        className="h-full w-full origin-left rounded-full bg-[#0080ff] transition-transform duration-300"
                                        style={{ transform: `scaleX(${runState.progress / 100})` }}
                                      />
                                    </div>
                                    <span className="fm-tnum truncate text-[12px] font-semibold text-[#0066e6]">
                                      {runState.stage} · {runState.progress}%
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                          <td className="whitespace-nowrap px-2.5 py-3 align-middle text-[12.5px] font-medium text-[#222222]">
                            {wf.trigger}
                          </td>
                          <td className="fm-tnum whitespace-nowrap px-2.5 py-3 align-middle text-[12px] font-medium text-[#636f7b]">
                            <span className="rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[#222222]">
                              {wf.nodes.length}{" "}
                              {pluralRu(wf.nodes.length, "нода", "ноды", "нод")}
                            </span>
                          </td>
                          <td className="whitespace-nowrap px-2.5 py-3 align-middle">
                            <FlowmappRunStatusText status={wf.lastRunStatus} />
                          </td>
                          <td className="whitespace-nowrap px-2.5 py-3 align-middle">
                            <FlowmappPolicyPill verdict={wf.policyGate} />
                          </td>
                          <td className="whitespace-nowrap px-2.5 py-3 align-middle">
                            <FlowmappSeverityPills crit={wf.critCount} high={wf.highCount} />
                          </td>
                          <td className="fm-tnum whitespace-nowrap px-2.5 py-3 align-middle text-[12px] text-[#636f7b]">
                            {wf.updatedAt}
                          </td>
                          {ws.canEdit && (
                            <td
                              className="whitespace-nowrap py-3 pl-2 pr-4 text-right align-middle"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <div className="inline-flex items-center justify-end gap-1.5">
                                <button
                                  type="button"
                                  onClick={() => openHistoryForWorkflow(wf.id)}
                                  aria-label={`История прогонов ${wf.name}`}
                                  title="История прогонов"
                                  className="fm-focus inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] text-[#636f7b] transition-colors hover:border-[#0080ff] hover:text-[#0080ff]"
                                >
                                  <History className="h-3.5 w-3.5 stroke-[1.6]" aria-hidden="true" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => ws.triggerRun(wf)}
                                  disabled={Boolean(runState)}
                                  className="fm-btn-ink fm-focus inline-flex h-8 shrink-0 cursor-pointer items-center gap-1.5 px-3 text-[12px] font-medium disabled:opacity-50"
                                >
                                  <Play className="h-3 w-3 stroke-[1.8]" aria-hidden="true" />
                                  Пуск
                                </button>
                                <button
                                  type="button"
                                  onClick={() => ws.deleteWorkflow(wf)}
                                  aria-label={`Удалить ${wf.name}`}
                                  className="fm-focus inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] text-[#636f7b] hover:border-[#000000] hover:text-[#000000]"
                                >
                                  <Trash2 className="h-3.5 w-3.5 stroke-[1.6]" aria-hidden="true" />
                                </button>
                              </div>
                            </td>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                </div>
              </div>
            )}
          </>
        )}
      </main>
      )}

      {/* Unified Create New Board Modal: Пустая доска / Из текста (AI) / Из шаблона */}
      {createModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="v11-create-modal-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/25 p-4"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) {
              setCreateModalOpen(false);
            }
          }}
        >
          <div className="fm-float flex max-h-[88dvh] w-full max-w-[660px] flex-col overflow-hidden rounded-[24px] border border-[#8c9baa] bg-[#ffffff]">
            {/* Modal Header */}
            <div className="flex items-center justify-between gap-3 border-b border-[#8c9baa]/40 px-5 py-4">
              <h2
                id="v11-create-modal-title"
                className="text-[18px] font-bold tracking-[-0.025em] text-[#000000]"
              >
                Новая доска Workflow
              </h2>
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                aria-label="Закрыть окно создания доски"
                className="fm-focus inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/70 text-[#222222] transition-colors hover:border-[#000000]"
              >
                <X className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
              </button>
            </div>

            {/* Creation Method Tabs */}
            <div className="border-b border-[#8c9baa]/35 px-5 py-3">
              <div
                role="tablist"
                aria-label="Способ создания доски"
                className="flex flex-wrap items-center gap-2"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={createTab === "blank"}
                  onClick={() => setCreateTab("blank")}
                  className={`fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-full px-4 text-[13px] font-medium transition-colors active:scale-[0.98] ${
                    createTab === "blank"
                      ? "bg-[#000000] text-[#ffffff]"
                      : "border border-[#8c9baa]/75 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                  }`}
                >
                  <FilePlus2 className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                  Пустая доска
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={createTab === "ai"}
                  onClick={() => setCreateTab("ai")}
                  className={`fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-full px-4 text-[13px] font-medium transition-colors active:scale-[0.98] ${
                    createTab === "ai"
                      ? "bg-[#000000] text-[#ffffff]"
                      : "border border-[#8c9baa]/75 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                  }`}
                >
                  <Sparkles
                    className={`h-3.5 w-3.5 stroke-[1.7] ${
                      createTab === "ai" ? "text-[#c5e0fb]" : "text-[#0080ff]"
                    }`}
                    aria-hidden="true"
                  />
                  Из текста (AI)
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={createTab === "template"}
                  onClick={() => setCreateTab("template")}
                  className={`fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-full px-4 text-[13px] font-medium transition-colors active:scale-[0.98] ${
                    createTab === "template"
                      ? "bg-[#000000] text-[#ffffff]"
                      : "border border-[#8c9baa]/75 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                  }`}
                >
                  <LayoutTemplate className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                  Из шаблона
                </button>
              </div>
            </div>

            {/* Tab Panel Body */}
            <div className="fm-scroll flex-1 overflow-y-auto overscroll-contain p-5">
              {createTab === "blank" && (
                <form onSubmit={handleCreateBlankSubmit} className="space-y-4">
                  <div>
                    <label
                      htmlFor="v11-new-board-name"
                      className="block text-[13px] font-semibold text-[#000000]"
                    >
                      Название доски
                    </label>
                    <input
                      id="v11-new-board-name"
                      type="text"
                      maxLength={120}
                      enterKeyHint="done"
                      value={newBoardName}
                      onChange={(e) => setNewBoardName(e.target.value)}
                      placeholder="Например, Billing Kotlin PSI Audit"
                      className="fm-focus mt-1.5 min-h-[44px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[14px]"
                    />
                  </div>

                  <div>
                    <p className="text-[13px] font-semibold text-[#000000]">Стартовый триггер</p>
                    <div
                      role="group"
                      aria-label="Стартовый триггер новой доски"
                      className="mt-2 flex flex-wrap gap-2"
                    >
                      {QUICK_TRIGGERS.map((item) => {
                        const active = newBoardTrigger === item.id;
                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => setNewBoardTrigger(item.id)}
                            aria-pressed={active}
                            className={`fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-2 rounded-full px-4 text-[13px] font-medium transition-colors active:scale-[0.98] ${
                              active
                                ? "bg-[#000000] text-[#ffffff]"
                                : "border border-[#8c9baa]/75 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                            }`}
                          >
                            <span
                              aria-hidden="true"
                              className="h-2.5 w-2.5 shrink-0 rounded-full border border-[#000000]/15"
                              style={{ backgroundColor: item.dot }}
                            />
                            {item.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
                    <button
                      type="button"
                      onClick={() => setCreateModalOpen(false)}
                      className="fm-btn-outline fm-focus min-h-[42px] cursor-pointer px-4 text-[13px] font-medium"
                    >
                      Отмена
                    </button>
                    <button
                      type="submit"
                      className="fm-btn-signal fm-focus inline-flex min-h-[42px] cursor-pointer items-center gap-1.5 px-5 text-[13px] font-semibold"
                    >
                      <Plus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
                      Создать и открыть канвас
                    </button>
                  </div>
                </form>
              )}

              {createTab === "ai" && activeAiPreset && (
                <form onSubmit={(e) => void handleGenerateAiPreview(e)} className="space-y-4">
                  <div>
                    <p className="text-[12px] font-semibold text-[#636f7b]">Примеры запросов</p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {AI_TEXT_PRESETS.map((preset) => {
                        const active = preset.id === activeAiPreset.id;
                        return (
                          <button
                            key={preset.id}
                            type="button"
                            onClick={() => {
                              setSelectedPresetId(preset.id);
                              setAiPrompt(preset.prompt);
                              setAiPreview(null);
                              setAiPreviewError(null);
                            }}
                            className={`fm-focus min-h-[36px] cursor-pointer rounded-full px-3.5 text-[12px] font-medium transition-colors ${
                              active
                                ? "bg-[#000000] text-[#ffffff]"
                                : "border border-[#8c9baa]/75 bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                            }`}
                          >
                            {preset.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  <div>
                    <label
                      htmlFor="v11-ai-prompt"
                      className="block text-[13px] font-semibold text-[#000000]"
                    >
                      Описание workflow проверки
                    </label>
                    <textarea
                      id="v11-ai-prompt"
                      rows={3}
                      value={aiPrompt}
                      onChange={(e) => {
                        setAiPrompt(e.target.value);
                        if (aiPreview) setAiPreview(null);
                        if (aiPreviewError) setAiPreviewError(null);
                      }}
                      placeholder="Опишите триггер, источник кода, нужные анализаторы, порог Policy Gate и канал уведомлений..."
                      className="fm-focus mt-1.5 w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] p-3 text-[16px] leading-[1.45] text-[#000000] sm:text-[13.5px]"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="v11-ai-name"
                      className="block text-[13px] font-semibold text-[#000000]"
                    >
                      Название workflow (необязательно)
                    </label>
                    <input
                      id="v11-ai-name"
                      type="text"
                      maxLength={120}
                      value={aiCustomName}
                      onChange={(e) => setAiCustomName(e.target.value)}
                      placeholder={aiPreview?.workflowName || activeAiPreset.generatedName}
                      className="fm-focus mt-1.5 min-h-[42px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[14px]"
                    />
                  </div>

                  {aiPreviewError && (
                    <div className="rounded-[12px] border border-[#dc2626]/40 bg-[#ffd6e0]/40 px-3.5 py-2.5 text-[12.5px] font-medium text-[#842029]">
                      {aiPreviewError}
                    </div>
                  )}

                  {aiPreview ? (
                    <div className="rounded-[16px] border border-[#0080ff]/55 bg-[#f6faff] p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-[12.5px] font-semibold text-[#000000]">
                          Превью от сервера ({aiPreview.board.nodes.length}{" "}
                          {pluralRu(aiPreview.board.nodes.length, "узел", "узла", "узлов")})
                        </p>
                        {(aiPreview.modelId || aiPreview.providerMode) && (
                          <span className="fm-mono text-[11px] text-[#636f7b]">
                            {[aiPreview.modelId, aiPreview.providerMode].filter(Boolean).join(" · ")}
                          </span>
                        )}
                      </div>

                      {aiPreview.rationale && (
                        <p className="mt-1.5 [overflow-wrap:anywhere] text-[12px] leading-[1.45] text-[#222222]">
                          {aiPreview.rationale}
                        </p>
                      )}

                      <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                        {aiPreview.board.nodes.map((node, idx) => (
                          <span key={node.id} className="inline-flex items-center gap-1">
                            <span className="fm-mono rounded-full border border-[#8c9baa]/60 bg-[#ffffff] px-2.5 py-0.5 text-[11px] text-[#000000]">
                              {node.data.pluginId}
                            </span>
                            {idx < aiPreview.board.nodes.length - 1 && (
                              <ArrowRight
                                className="h-3 w-3 shrink-0 text-[#0080ff]"
                                aria-hidden="true"
                              />
                            )}
                          </span>
                        ))}
                      </div>

                      {aiPreview.missingFields.length > 0 && (
                        <div className="mt-3 border-t border-[#8c9baa]/30 pt-2.5">
                          <p className="text-[11.5px] font-semibold text-[#664d03]">
                            Нужно заполнить на канвасе (missingFields):
                          </p>
                          <ul className="mt-1 space-y-1 text-[12px] text-[#222222]">
                            {aiPreview.missingFields.map((mf, idx) => (
                              <li
                                key={`${mf.nodeId ?? "n"}-${mf.fieldPath ?? idx}`}
                                className="[overflow-wrap:anywhere]"
                              >
                                {(mf.nodeId || mf.fieldPath) && (
                                  <span className="fm-mono mr-1.5 text-[#0066e6]">
                                    {[mf.nodeId, mf.fieldPath].filter(Boolean).join(".")}:
                                  </span>
                                )}
                                {mf.message}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="rounded-[16px] border border-dashed border-[#8c9baa]/75 p-4 text-[12.5px] leading-[1.45] text-[#636f7b]">
                      Нажмите «Сгенерировать превью», чтобы сервер собрал DAG из вашего описания и
                      показал узлы, обоснование и незаполненные параметры. Сохранение выполняется
                      только после вашего подтверждения.
                    </div>
                  )}

                  <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
                    <button
                      type="button"
                      onClick={() => setCreateModalOpen(false)}
                      className="fm-btn-outline fm-focus min-h-[42px] cursor-pointer px-4 text-[13px] font-medium"
                    >
                      Отмена
                    </button>
                    <button
                      type="submit"
                      disabled={aiPreviewLoading || !aiPrompt.trim()}
                      className="fm-btn-ink fm-focus inline-flex min-h-[42px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Sparkles className="h-4 w-4 stroke-[1.8]" aria-hidden="true" />
                      <span>
                        {aiPreviewLoading
                          ? "Генерация превью…"
                          : aiPreview
                            ? "Перегенерировать превью"
                            : "Сгенерировать превью"}
                      </span>
                    </button>
                    {aiPreview && (
                      <button
                        type="button"
                        disabled={aiSaving}
                        onClick={() => void handleConfirmSaveAiWorkflow()}
                        className="fm-btn-signal fm-focus inline-flex min-h-[42px] cursor-pointer items-center gap-1.5 px-5 text-[13px] font-semibold disabled:cursor-not-allowed disabled:opacity-55"
                      >
                        <Check className="h-4 w-4 stroke-[2]" aria-hidden="true" />
                        <span>{aiSaving ? "Сохранение…" : "Создать workflow"}</span>
                      </button>
                    )}
                  </div>
                </form>
              )}

              {createTab === "template" && (
                <div className="space-y-3">
                  {ws.templates.map((tpl) => (
                    <article
                      key={tpl.id}
                      className="flex flex-col gap-3 rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4 transition-colors hover:border-[#0080ff] sm:flex-row sm:items-center sm:justify-between"
                    >
                      <div className="flex min-w-0 items-start gap-3">
                        <FlowmappPastelTriggerIcon trigger={tpl.trigger} />
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="text-[14px] font-semibold tracking-[-0.015em] text-[#000000]">
                              {tpl.name}
                            </h3>
                            <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[11px] font-medium text-[#636f7b]">
                              {tpl.nodes.length}{" "}
                              {pluralRu(tpl.nodes.length, "нода", "ноды", "нод")}
                            </span>
                          </div>
                          <p className="mt-1 text-[12.5px] leading-[1.45] text-[#636f7b]">
                            {tpl.description}
                          </p>
                          <div className="mt-2 flex flex-wrap gap-1">
                            {tpl.tags.map((tag) => (
                              <span
                                key={tag}
                                className="rounded-full bg-[#f6faff] px-2.5 py-0.5 text-[11px] font-medium text-[#222222]"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => {
                          ws.createFromTemplate(tpl, true);
                          setCreateModalOpen(false);
                        }}
                        className="fm-btn-ink fm-focus inline-flex min-h-[38px] shrink-0 cursor-pointer items-center justify-center gap-1.5 px-4 text-[12.5px] font-medium"
                      >
                        Использовать
                        <ArrowUpRight className="h-3.5 w-3.5 stroke-[1.8]" aria-hidden="true" />
                      </button>
                    </article>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {descTooltip && (
        <div
          role="tooltip"
          style={{
            left: Math.min(
              descTooltip.x,
              typeof window !== "undefined" ? Math.max(16, window.innerWidth - 360) : descTooltip.x,
            ),
            top:
              typeof window !== "undefined" && descTooltip.y + 110 > window.innerHeight
                ? descTooltip.y - 96
                : descTooltip.y,
          }}
          className="fm-float pointer-events-none fixed z-50 w-[min(340px,calc(100vw-2rem))] rounded-[14px] border border-[#8c9baa] bg-[#ffffff] px-3.5 py-2.5 text-[12.5px] leading-[1.45] text-[#222222]"
        >
          {descTooltip.text}
        </div>
      )}

      <FlowmappNoticeBar
        notice={ws.notice}
        onUndo={ws.undoDelete}
        onDismiss={() => ws.setNotice(null)}
      />
    </div>
  );
}
