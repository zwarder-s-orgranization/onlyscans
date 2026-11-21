"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createCanvasNodeFromTemplate,
  TEMPLATE_BY_PLUGIN_ID,
  type CanvasBoardEdge,
  type CanvasBoardNode,
} from "@/data/canvas-nodes-catalog";
import { canManageSecrets } from "@/data/settings-data";
import type {
  StarterTemplateRecord,
  TemplateCategory,
  TextToWorkflowPreset,
  TriggerKind,
  WorkflowRecord,
  WorkflowRunRecord,
} from "@/data/workflows-workspace-data";
import {
  ApiError,
  gql,
  QUERIES,
  subscribeRunEvents,
  type RunEventMessage,
} from "@/lib/api";
import {
  boardFromGraph,
  canvasStatus,
  graphFromBoard,
  runRecord,
  statusesFromRun,
  templateRecord,
  workflowRecord,
  type NodeRunPaint,
  type ServerGraph,
  type ServerRun,
  type ServerTemplate,
  type ServerWorkflow,
} from "@/lib/workflow-map";
import { useWorkspacePreview } from "./WorkspacePreviewContext";

export interface RunningProgress {
  progress: number;
  stage: string;
  runId?: string;
}

export interface FeedbackNotice {
  id: number;
  text: string;
  undoWorkflow?: WorkflowRecord;
}

export interface BoardGraphState {
  nodes: CanvasBoardNode[];
  edges: CanvasBoardEdge[];
}

export interface CreateBlankOptions {
  openCanvas?: boolean;
  name?: string;
  trigger?: TriggerKind;
  startEmpty?: boolean;
}

export interface AvailableSecretItem {
  id: string;
  secretRef: string;
  name: string;
  kind: string;
  maskedPreview?: string;
}

export interface AiMissingFieldItem {
  code?: string;
  severity?: string;
  message: string;
  nodeId?: string | null;
  fieldPath?: string | null;
}

export interface AiWorkflowPreview {
  workflowName: string;
  description: string;
  rationale: string;
  modelId: string;
  providerMode: string;
  graph: ServerGraph;
  board: BoardGraphState;
  missingFields: AiMissingFieldItem[];
}

const TERMINAL = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);
const DONE_NODE_STATUSES = new Set(["SUCCEEDED", "FAILED", "SKIPPED", "CANCELLED"]);
const DONE_CANVAS_STATUSES = new Set(["succeeded", "warning", "failed"]);

function runTimestamp(run: ServerRun): number {
  const raw = run.createdAt || run.startedAt || "";
  const parsed = raw ? Date.parse(raw) : 0;
  return Number.isFinite(parsed) ? parsed : 0;
}

function stageLabelFromRun(run: ServerRun): string {
  if (run.status === "QUEUED") return "В очереди";
  if (run.status === "SUCCEEDED") return "Завершён";
  if (run.status === "FAILED") return "Остановлен";
  if (run.status === "CANCELLED") return "Отменён";
  const activeNode = (run.nodeRuns ?? []).find((nr) => nr.status === "RUNNING");
  if (activeNode) {
    const label = TEMPLATE_BY_PLUGIN_ID[activeNode.pluginId]?.shortLabel ?? activeNode.pluginId;
    return `Узел: ${label}`;
  }
  return "Выполнение графа";
}

function progressFromRun(run: ServerRun, totalNodesEstimate: number): number {
  if (TERMINAL.has(run.status)) return 100;
  const nodeRuns = run.nodeRuns ?? [];
  const total = Math.max(totalNodesEstimate, nodeRuns.length, 1);
  const done = nodeRuns.filter((nr) => DONE_NODE_STATUSES.has(nr.status)).length;
  const running = nodeRuns.some((nr) => nr.status === "RUNNING") ? 0.35 : 0;
  const pct = Math.round(((done + running) / total) * 100);
  return Math.max(8, Math.min(95, pct));
}

function progressFromPaintMap(
  paintMap: Record<string, NodeRunPaint>,
  totalNodesEstimate: number,
): number {
  const entries = Object.values(paintMap);
  const total = Math.max(totalNodesEstimate, entries.length, 1);
  const done = entries.filter((item) => DONE_CANVAS_STATUSES.has(item.status)).length;
  const running = entries.some((item) => item.status === "running") ? 0.35 : 0;
  const pct = Math.round(((done + running) / total) * 100);
  return Math.max(8, Math.min(95, pct));
}

export function useWorkflowsWorkspace() {
  const { role, forceEmpty, setForceEmpty } = useWorkspacePreview();
  const canEdit = role === "owner" || role === "editor";

  const [workflows, setWorkflows] = useState<WorkflowRecord[]>([]);
  const [templates, setTemplates] = useState<StarterTemplateRecord[]>([]);
  const [runHistory, setRunHistory] = useState<WorkflowRunRecord[]>([]);
  const [boardsMap, setBoardsMap] = useState<Record<string, BoardGraphState>>({});
  const [availableSecrets, setAvailableSecrets] = useState<AvailableSecretItem[]>([]);
  const [activeBoardId, setActiveBoardId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [triggerFilter, setTriggerFilter] = useState<"ALL" | TriggerKind>("ALL");
  const [verdictFilter, setVerdictFilter] = useState<"ALL" | WorkflowRecord["policyGate"]>("ALL");
  const [selectedId, setSelectedId] = useState("");
  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [runningMap, setRunningMap] = useState<Record<string, RunningProgress>>({});
  const [historyFocus, setHistoryFocus] = useState<{ runId: string; at: number } | null>(null);
  const [nodeRunStatusesByWorkflow, setNodeRunStatusesByWorkflow] = useState<
    Record<string, Record<string, NodeRunPaint>>
  >({});
  const [notice, setNotice] = useState<FeedbackNotice | null>(null);
  const [loading, setLoading] = useState(true);

  const mountedRef = useRef(true);
  const activeBoardIdRef = useRef<string | null>(null);
  const timersRef = useRef<number[]>([]);
  const versionsRef = useRef<Record<string, number>>({});
  const namesRef = useRef<Record<string, { name: string; description: string }>>({});
  const boardsRef = useRef<Record<string, BoardGraphState>>({});
  const pendingBoardRef = useRef<Record<string, BoardGraphState>>({});
  const saveTimers = useRef<Record<string, number>>({});
  const saveQueueRef = useRef<Record<string, Promise<void>>>({});
  const runWatchersRef = useRef<Map<string, () => void>>(new Map());
  const deletedBoard = useRef<BoardGraphState | null>(null);
  const latestRuns = useRef<Record<string, ServerRun>>({});

  useEffect(() => {
    activeBoardIdRef.current = activeBoardId;
  }, [activeBoardId]);

  const showNotice = useCallback((text: string, undoWorkflow?: WorkflowRecord) => {
    if (!mountedRef.current) return;
    const id = Date.now();
    setNotice({ id, text, undoWorkflow });
    const timer = window.setTimeout(() => {
      if (mountedRef.current) {
        setNotice((prev) => (prev?.id === id ? null : prev));
      }
    }, 5200);
    timersRef.current.push(timer);
  }, []);

  const applyWorkspace = useCallback(
    (items: ServerWorkflow[], tpls: ServerTemplate[], runs: ServerRun[]) => {
      // Defensively sort runs descending by createdAt/startedAt so index 0 is always newest (H2)
      const sortedRuns = [...runs].sort((a, b) => runTimestamp(b) - runTimestamp(a));
      const latest = new Map<string, ServerRun>();
      const latestRecord: Record<string, ServerRun> = {};
      for (const run of sortedRuns) {
        if (!latest.has(run.workflowId)) {
          latest.set(run.workflowId, run);
          latestRecord[run.workflowId] = run;
        }
      }
      latestRuns.current = latestRecord;

      const boards: Record<string, BoardGraphState> = {};
      const records = items.map((wf) => {
        versionsRef.current[wf.id] = wf.version;
        namesRef.current[wf.id] = { name: wf.name, description: wf.description || "" };
        boards[wf.id] = boardFromGraph(wf.graph);
        return workflowRecord(wf, latest.get(wf.id));
      });

      const mergedBoards = { ...boards, ...pickDirty(boardsRef.current, saveTimers.current) };
      boardsRef.current = mergedBoards;

      setWorkflows(records);
      setBoardsMap(mergedBoards);
      setTemplates(tpls.map(templateRecord));
      setRunHistory(sortedRuns.map(runRecord));
      setNodeRunStatusesByWorkflow((prev) => {
        const next = { ...prev };
        for (const [wfId, run] of Object.entries(latestRecord)) {
          if (!runWatchersRef.current.has(wfId)) {
            next[wfId] = statusesFromRun(run);
          }
        }
        return next;
      });
      setSelectedId((current) => current || records[0]?.id || "");
    },
    [],
  );

  const reload = useCallback(async () => {
    const data = await gql<{
      workflows: { items: ServerWorkflow[] };
      templates: { items: ServerTemplate[] };
      runs: { items: ServerRun[] };
    }>(QUERIES.workspace);
    if (!mountedRef.current) return;
    applyWorkspace(data.workflows.items ?? [], data.templates.items ?? [], data.runs.items ?? []);
  }, [applyWorkspace]);

  const loadAvailableSecrets = useCallback(async () => {
    if (!canManageSecrets(role)) {
      setAvailableSecrets([]);
      return;
    }
    try {
      const data = await gql<{
        secrets: Array<{
          secretRef: string;
          name: string;
          kind: string;
          maskedPreview?: string;
        }>;
      }>(QUERIES.settingsSecrets);
      if (!mountedRef.current) return;
      const items: AvailableSecretItem[] = (data.secrets ?? []).map((item) => ({
        id: item.secretRef,
        secretRef: item.secretRef,
        name: item.name,
        kind: item.kind,
        maskedPreview: item.maskedPreview,
      }));
      setAvailableSecrets(items);
    } catch {
      if (mountedRef.current) {
        setAvailableSecrets([]);
      }
    }
  }, [role]);

  useEffect(() => {
    mountedRef.current = true;
    let cancelled = false;
    setLoading(true);
    reload()
      .catch((err: unknown) => {
        if (!cancelled) showNotice(err instanceof Error ? err.message : "Не удалось загрузить сценарии");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reload, showNotice]);

  useEffect(() => {
    void loadAvailableSecrets();
  }, [loadAvailableSecrets]);

  const persistBoard = useCallback(
    async (workflowId: string, board: BoardGraphState) => {
      const meta = namesRef.current[workflowId];
      if (!meta) return;
      const data = await gql<{ saveWorkflow: ServerWorkflow }>(QUERIES.save, {
        input: {
          id: workflowId,
          expectedVersion: versionsRef.current[workflowId],
          name: meta.name,
          description: meta.description,
          graph: graphFromBoard(board),
        },
      });
      versionsRef.current[workflowId] = data.saveWorkflow.version;
    },
    [],
  );

  const enqueuePersist = useCallback(
    (workflowId: string, board: BoardGraphState): Promise<void> => {
      const prev = saveQueueRef.current[workflowId] ?? Promise.resolve();
      const next = prev
        .catch(() => {
          // Keep the queue alive even if a previous save failed
        })
        .then(() => persistBoard(workflowId, board));
      saveQueueRef.current[workflowId] = next;
      return next;
    },
    [persistBoard],
  );

  const flushPendingSave = useCallback(
    (workflowId: string): Promise<void> => {
      const existingTimer = saveTimers.current[workflowId];
      if (existingTimer) {
        window.clearTimeout(existingTimer);
        delete saveTimers.current[workflowId];
      }
      const pendingBoard = pendingBoardRef.current[workflowId];
      if (pendingBoard) {
        delete pendingBoardRef.current[workflowId];
        return enqueuePersist(workflowId, pendingBoard);
      }
      return saveQueueRef.current[workflowId] ?? Promise.resolve();
    },
    [enqueuePersist],
  );

  useEffect(() => {
    const timers = timersRef.current;
    const pending = saveTimers.current;
    const watchers = runWatchersRef.current;
    return () => {
      mountedRef.current = false;
      timers.forEach((timer) => window.clearTimeout(timer));
      timers.length = 0;
      for (const wfId of Object.keys(pending)) {
        window.clearTimeout(pending[wfId]);
        delete pending[wfId];
        const board = pendingBoardRef.current[wfId];
        if (board) {
          delete pendingBoardRef.current[wfId];
          void enqueuePersist(wfId, board).catch(() => {});
        }
      }
      watchers.forEach((cleanup) => cleanup());
      watchers.clear();
    };
  }, [enqueuePersist]);

  const rememberWorkflow = useCallback((wf: ServerWorkflow) => {
    versionsRef.current[wf.id] = wf.version;
    namesRef.current[wf.id] = { name: wf.name, description: wf.description || "" };
    const board = boardFromGraph(wf.graph);
    boardsRef.current = { ...boardsRef.current, [wf.id]: board };
    const record = workflowRecord(wf);
    setWorkflows((prev) => [record, ...prev.filter((item) => item.id !== wf.id)]);
    setBoardsMap((prev) => ({ ...prev, [wf.id]: board }));
    setSelectedId(wf.id);
    return record;
  }, []);

  const visibleWorkflows = useMemo(() => (forceEmpty ? [] : workflows), [forceEmpty, workflows]);

  const filteredWorkflows = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return visibleWorkflows.filter((wf) => {
      if (triggerFilter !== "ALL" && wf.trigger !== triggerFilter) return false;
      if (verdictFilter !== "ALL" && wf.policyGate !== verdictFilter) return false;
      if (!q) return true;
      return (
        wf.name.toLowerCase().includes(q) ||
        wf.description.toLowerCase().includes(q) ||
        wf.trigger.toLowerCase().includes(q) ||
        wf.sourceLabel.toLowerCase().includes(q)
      );
    });
  }, [visibleWorkflows, searchQuery, triggerFilter, verdictFilter]);

  const selectedWorkflow = useMemo(() => {
    const inFiltered = filteredWorkflows.find((w) => w.id === selectedId);
    return inFiltered ?? filteredWorkflows[0] ?? visibleWorkflows[0] ?? null;
  }, [filteredWorkflows, visibleWorkflows, selectedId]);

  const activeBoardWorkflow = useMemo(() => {
    if (!activeBoardId) return null;
    return workflows.find((w) => w.id === activeBoardId) ?? null;
  }, [activeBoardId, workflows]);

  const activeBoardGraph = useMemo<BoardGraphState | null>(() => {
    if (!activeBoardId) return null;
    return boardsMap[activeBoardId] ?? null;
  }, [activeBoardId, boardsMap]);

  const nodeRunStatuses = useMemo<Record<string, NodeRunPaint>>(() => {
    if (!activeBoardId) return {};
    return nodeRunStatusesByWorkflow[activeBoardId] ?? {};
  }, [activeBoardId, nodeRunStatusesByWorkflow]);

  const openBoard = useCallback(
    (workflowId: string) => {
      const prevBoardId = activeBoardIdRef.current;
      if (prevBoardId && prevBoardId !== workflowId && canEdit) {
        void flushPendingSave(prevBoardId).catch((err: unknown) => {
          showNotice(err instanceof Error ? err.message : "Не удалось сохранить граф");
        });
      }
      setSelectedId(workflowId);
      setActiveBoardId(workflowId);
      if (!runWatchersRef.current.has(workflowId)) {
        const run = latestRuns.current[workflowId];
        setNodeRunStatusesByWorkflow((prev) => ({
          ...prev,
          [workflowId]: run ? statusesFromRun(run) : {},
        }));
      }
    },
    [canEdit, flushPendingSave, showNotice],
  );

  const closeBoard = useCallback(() => {
    const prevBoardId = activeBoardIdRef.current;
    if (prevBoardId && canEdit) {
      void flushPendingSave(prevBoardId).catch((err: unknown) => {
        showNotice(err instanceof Error ? err.message : "Не удалось сохранить граф");
      });
    }
    setActiveBoardId(null);
  }, [canEdit, flushPendingSave, showNotice]);

  const updateBoardGraph = useCallback(
    (workflowId: string, nodes: CanvasBoardNode[], edges: CanvasBoardEdge[]) => {
      if (!canEdit) return;
      const board = { nodes, edges };
      boardsRef.current = { ...boardsRef.current, [workflowId]: board };
      pendingBoardRef.current[workflowId] = board;
      setBoardsMap((prev) => ({ ...prev, [workflowId]: board }));
      setWorkflows((prev) =>
        prev.map((wf) => {
          if (wf.id !== workflowId) return wf;
          const firstTrigger = nodes.find((n) => n.data.family === "trigger");
          const nextTrigger: TriggerKind =
            firstTrigger?.data.pluginId === "trigger.webhook"
              ? "Webhook"
              : firstTrigger?.data.pluginId === "trigger.schedule"
                ? "Schedule"
                : "Manual";
          return {
            ...wf,
            trigger: nextTrigger,
            updatedAt: "Только что",
            nodes: nodes.map((n) => ({
              id: n.id,
              family: n.data.family,
              pluginId: n.data.pluginId,
              label: n.data.shortLabel || n.data.label,
            })),
          };
        }),
      );
      const existing = saveTimers.current[workflowId];
      if (existing) window.clearTimeout(existing);
      saveTimers.current[workflowId] = window.setTimeout(() => {
        delete saveTimers.current[workflowId];
        const latestPending = pendingBoardRef.current[workflowId] ?? board;
        delete pendingBoardRef.current[workflowId];
        enqueuePersist(workflowId, latestPending).catch((err: unknown) => {
          showNotice(err instanceof Error ? err.message : "Не удалось сохранить граф");
        });
      }, 700);
    },
    [canEdit, enqueuePersist, showNotice],
  );

  const renameWorkflow = useCallback(
    (workflowId: string, newName: string) => {
      if (!canEdit) return;
      const trimmed = newName.trim();
      if (!trimmed) return;
      const meta = namesRef.current[workflowId] ?? { name: trimmed, description: "" };
      namesRef.current[workflowId] = { ...meta, name: trimmed };
      setWorkflows((prev) =>
        prev.map((wf) => (wf.id === workflowId ? { ...wf, name: trimmed, updatedAt: "Только что" } : wf)),
      );
      const existingTimer = saveTimers.current[workflowId];
      if (existingTimer) {
        window.clearTimeout(existingTimer);
        delete saveTimers.current[workflowId];
      }
      const board = pendingBoardRef.current[workflowId] ?? boardsRef.current[workflowId];
      delete pendingBoardRef.current[workflowId];
      if (!board) return;
      enqueuePersist(workflowId, board).catch((err: unknown) => {
        showNotice(err instanceof Error ? err.message : "Не удалось переименовать");
      });
    },
    [canEdit, enqueuePersist, showNotice],
  );

  const recordCanvasRun = useCallback((_payload: unknown) => {
    // Прогон пишет сервер. Локальная анимация не является источником истории.
  }, []);

  const watchRunLifecycle = useCallback(
    (workflowId: string, runId: string, totalNodesEstimate: number) => {
      const prevCleanup = runWatchersRef.current.get(workflowId);
      if (prevCleanup) {
        prevCleanup();
        runWatchersRef.current.delete(workflowId);
      }

      let stopped = false;
      let wsConnected = false;
      let lastSeq = 0;
      let pollTimer: number | null = null;
      let pollAttempts = 0;
      let unsubWs: (() => void) | null = null;

      const cleanup = () => {
        if (stopped) return;
        stopped = true;
        if (pollTimer !== null) {
          window.clearTimeout(pollTimer);
          pollTimer = null;
        }
        if (unsubWs) {
          unsubWs();
          unsubWs = null;
        }
        if (runWatchersRef.current.get(workflowId) === cleanup) {
          runWatchersRef.current.delete(workflowId);
        }
      };
      runWatchersRef.current.set(workflowId, cleanup);

      const finishRun = async (finalRun?: ServerRun | null) => {
        cleanup();
        let resolved = finalRun ?? null;
        if (!resolved) {
          try {
            const data = await gql<{ run: ServerRun | null }>(QUERIES.run, { id: runId });
            resolved = data.run;
          } catch {
            // fallback to reload below
          }
        }
        if (!mountedRef.current) return;
        if (resolved) {
          latestRuns.current[workflowId] = resolved;
          setNodeRunStatusesByWorkflow((prev) => ({
            ...prev,
            [workflowId]: statusesFromRun(resolved!),
          }));
        }
        try {
          await reload();
        } catch {
          // ignore reload failure after finish
        }
        if (!mountedRef.current) return;
        setRunningMap((prev) => {
          const next = { ...prev };
          delete next[workflowId];
          return next;
        });
        const status = resolved?.status ?? "SUCCEEDED";
        const findings = (resolved?.findingsStats?.total ?? 0).toString();
        showNotice(
          status === "SUCCEEDED"
            ? `Прогон ${runId} завершён, находок: ${findings}`
            : status === "CANCELLED"
              ? `Прогон ${runId} отменён`
              : `Прогон ${runId}: ${status}${resolved?.errorMessage ? `. ${resolved.errorMessage}` : ""}`,
        );
        setHistoryFocus({ runId, at: Date.now() });
      };

      const schedulePoll = (delayMs: number) => {
        if (stopped || !mountedRef.current) return;
        if (pollTimer !== null) window.clearTimeout(pollTimer);
        pollTimer = window.setTimeout(async () => {
          if (stopped || !mountedRef.current) return;
          pollAttempts += 1;
          if (pollAttempts > 90) {
            await finishRun(null);
            return;
          }
          try {
            const data = await gql<{ run: ServerRun | null }>(QUERIES.run, { id: runId });
            if (stopped || !mountedRef.current) return;
            const current = data.run;
            if (current) {
              if (current.lastSeqId != null) {
                lastSeq = Math.max(lastSeq, Number(current.lastSeqId) || 0);
              }
              const paintMap = statusesFromRun(current);
              setNodeRunStatusesByWorkflow((prev) => ({ ...prev, [workflowId]: paintMap }));
              setRunHistory((prev) => {
                const mapped = runRecord(current);
                const exists = prev.some((item) => item.id === mapped.id);
                return exists
                  ? prev.map((item) => (item.id === mapped.id ? mapped : item))
                  : [mapped, ...prev];
              });
              setRunningMap((prev) => ({
                ...prev,
                [workflowId]: {
                  runId,
                  progress: progressFromRun(current, totalNodesEstimate),
                  stage: stageLabelFromRun(current),
                },
              }));
              if (TERMINAL.has(current.status)) {
                await finishRun(current);
                return;
              }
            }
          } catch {
            // keep polling on transient error
          }
          schedulePoll(wsConnected ? 4000 : 1400);
        }, delayMs);
      };

      const handleEvent = (ev: RunEventMessage) => {
        if (stopped || !mountedRef.current) return;
        const seqNum = Number(ev.seqId);
        if (Number.isFinite(seqNum) && seqNum > lastSeq) {
          lastSeq = seqNum;
        }
        if (ev.nodeId && ev.nodeStatus) {
          const mappedStatus = canvasStatus(ev.nodeStatus);
          setNodeRunStatusesByWorkflow((prev) => {
            const wfMap = { ...(prev[workflowId] ?? {}) };
            const existing = wfMap[ev.nodeId!];
            wfMap[ev.nodeId!] = {
              status: mappedStatus,
              durationMs: existing?.durationMs,
              findings: existing?.findings,
              activeOutputPorts: existing?.activeOutputPorts,
              redactedPreview: ev.redactedPreview ?? existing?.redactedPreview,
            };
            setRunningMap((rPrev) => ({
              ...rPrev,
              [workflowId]: {
                runId,
                progress: progressFromPaintMap(wfMap, totalNodesEstimate),
                stage:
                  ev.nodeStatus === "RUNNING"
                    ? `Узел: ${ev.nodeId}`
                    : ev.message || rPrev[workflowId]?.stage || "Выполнение графа",
              },
            }));
            return { ...prev, [workflowId]: wfMap };
          });
        } else if (ev.eventType === "GATE_EVALUATED" && ev.gateResult) {
          setRunningMap((prev) => ({
            ...prev,
            [workflowId]: {
              runId,
              progress: prev[workflowId]?.progress ?? 75,
              stage: `Policy Gate: ${ev.gateResult?.status}`,
            },
          }));
        } else if (ev.eventType === "AI_REPORT_READY") {
          setRunningMap((prev) => ({
            ...prev,
            [workflowId]: {
              runId,
              progress: Math.max(prev[workflowId]?.progress ?? 85, 88),
              stage: "AI-отчёт готов",
            },
          }));
        } else if (ev.eventType === "SBOM_READY") {
          setRunningMap((prev) => ({
            ...prev,
            [workflowId]: {
              runId,
              progress: Math.max(prev[workflowId]?.progress ?? 60, 65),
              stage: "SBOM сформирован",
            },
          }));
        }

        if (
          TERMINAL.has(ev.runStatus) ||
          ev.eventType === "RUN_COMPLETED" ||
          ev.eventType === "RUN_FAILED" ||
          ev.eventType === "RUN_CANCELLED"
        ) {
          void finishRun(null);
        }
      };

      unsubWs = subscribeRunEvents(runId, lastSeq, {
        onOpen: () => {
          wsConnected = true;
        },
        onEvent: handleEvent,
        onError: () => {
          wsConnected = false;
          schedulePoll(1000);
        },
        onComplete: () => {
          wsConnected = false;
          if (!stopped) {
            schedulePoll(600);
          }
        },
      });

      // Kick off an immediate safety poll so initial node states and fallback work even without WS
      schedulePoll(1200);
    },
    [reload, showNotice],
  );

  const triggerRun = useCallback(
    (wf: WorkflowRecord) => {
      if (!canEdit || runningMap[wf.id]) return;
      setRunningMap((prev) => ({
        ...prev,
        [wf.id]: { progress: 6, stage: "Сервер принимает прогон" },
      }));
      void (async () => {
        try {
          await flushPendingSave(wf.id);
          const started = await gql<{ startRun: { id: string; status: string } }>(QUERIES.startRun, {
            input: { workflowId: wf.id },
          });
          if (!mountedRef.current) return;
          const runId = started.startRun.id;
          setNodeRunStatusesByWorkflow((prev) => ({ ...prev, [wf.id]: {} }));
          setRunningMap((prev) => ({
            ...prev,
            [wf.id]: { runId, progress: 12, stage: "Запуск узлов DAG" },
          }));
          const totalNodes = boardsRef.current[wf.id]?.nodes.length ?? wf.nodes.length;
          watchRunLifecycle(wf.id, runId, totalNodes);
        } catch (err) {
          if (mountedRef.current) {
            showNotice(err instanceof ApiError ? err.message : "Не удалось запустить прогон");
            setRunningMap((prev) => {
              const next = { ...prev };
              delete next[wf.id];
              return next;
            });
          }
        }
      })();
    },
    [canEdit, flushPendingSave, runningMap, showNotice, watchRunLifecycle],
  );

  const cancelRun = useCallback(
    async (runId: string) => {
      if (!canEdit) return;
      try {
        await gql<{ cancelRun: { id: string; status: string } }>(QUERIES.cancelRun, {
          runId,
          reason: "Отменено пользователем из UI",
        });
        const target = runHistory.find((r) => r.id === runId);
        if (target) {
          const cleanup = runWatchersRef.current.get(target.workflowId);
          if (cleanup) {
            cleanup();
            runWatchersRef.current.delete(target.workflowId);
          }
          setRunningMap((prev) => {
            const next = { ...prev };
            delete next[target.workflowId];
            return next;
          });
        }
        await reload();
        showNotice(`Прогон ${runId} отменён`);
      } catch (err) {
        showNotice(err instanceof Error ? err.message : "Не удалось отменить прогон");
      }
    },
    [canEdit, reload, runHistory, showNotice],
  );

  const rerunFromNode = useCallback(
    async (runId: string, nodeId: string) => {
      if (!canEdit) return;
      try {
        const res = await gql<{
          rerunFromNode: { id: string; status: string; parentRunId?: string; rerunFromNodeId?: string };
        }>(QUERIES.rerunFromNode, {
          input: { sourceRunId: runId, nodeId },
        });
        const newRunId = res.rerunFromNode.id;
        const sourceRun = runHistory.find((r) => r.id === runId);
        const wfId = sourceRun?.workflowId ?? activeBoardIdRef.current ?? "";
        if (wfId) {
          const totalNodes = boardsRef.current[wfId]?.nodes.length ?? sourceRun?.nodesCount ?? 1;
          setRunningMap((prev) => ({
            ...prev,
            [wfId]: { runId: newRunId, progress: 15, stage: `Повтор с узла ${nodeId}` },
          }));
          watchRunLifecycle(wfId, newRunId, totalNodes);
        } else {
          await reload();
        }
        showNotice(`Запущен повторный прогон ${newRunId} с узла ${nodeId}`);
      } catch (err) {
        showNotice(err instanceof Error ? err.message : "Не удалось перезапустить с выбранного узла");
      }
    },
    [canEdit, reload, runHistory, showNotice, watchRunLifecycle],
  );

  const deleteWorkflow = useCallback(
    (workflowOrId: WorkflowRecord | string) => {
      if (!canEdit) return;
      const workflowId = typeof workflowOrId === "string" ? workflowOrId : workflowOrId.id;
      const target = workflows.find((wf) => wf.id === workflowId);
      deletedBoard.current = boardsRef.current[workflowId] ?? null;
      const existingTimer = saveTimers.current[workflowId];
      if (existingTimer) {
        window.clearTimeout(existingTimer);
        delete saveTimers.current[workflowId];
      }
      delete pendingBoardRef.current[workflowId];
      setWorkflows((prev) => prev.filter((wf) => wf.id !== workflowId));
      if (activeBoardId === workflowId) setActiveBoardId(null);
      void gql(QUERIES.deleteWorkflow, { id: workflowId })
        .then(() => {
          if (target) showNotice(`Workflow «${target.name}» удалён на сервере`, target);
        })
        .catch((err: unknown) => {
          showNotice(err instanceof Error ? err.message : "Не удалось удалить workflow");
          void reload();
        });
    },
    [activeBoardId, canEdit, reload, showNotice, workflows],
  );

  const undoDelete = useCallback(() => {
    const restored = notice?.undoWorkflow;
    const board = deletedBoard.current;
    if (!restored || !board) return;
    setNotice(null);
    void gql<{ saveWorkflow: ServerWorkflow }>(QUERIES.save, {
      input: {
        name: restored.name,
        description: restored.description,
        graph: graphFromBoard(board),
      },
    })
      .then((data) => {
        rememberWorkflow(data.saveWorkflow);
        showNotice(`Workflow «${restored.name}» восстановлен`);
      })
      .catch((err: unknown) => {
        showNotice(err instanceof Error ? err.message : "Не удалось восстановить workflow");
      });
  }, [notice, rememberWorkflow, showNotice]);

  const createBlankWorkflow = useCallback(
    (options?: CreateBlankOptions | unknown) => {
      if (!canEdit) return;
      const opts: CreateBlankOptions =
        options && typeof options === "object" && !("nativeEvent" in options)
          ? (options as CreateBlankOptions)
          : {};
      const triggerKind: TriggerKind = opts.trigger ?? "Manual";
      const pluginId =
        triggerKind === "Webhook"
          ? "trigger.webhook"
          : triggerKind === "Schedule"
            ? "trigger.schedule"
            : "trigger.manual";
      const tpl = TEMPLATE_BY_PLUGIN_ID[pluginId];
      const starter = opts.startEmpty || !tpl ? [] : [createCanvasNodeFromTemplate(tpl, { x: 120, y: 160 })];
      const board: BoardGraphState = { nodes: starter, edges: [] };
      const name = opts.name?.trim() || "Новый workflow";
      void gql<{ saveWorkflow: ServerWorkflow }>(QUERIES.save, {
        input: {
          name,
          description: "Соберите граф проверки и запустите его на сервере.",
          graph: graphFromBoard(board),
        },
      })
        .then((data) => {
          if (forceEmpty) setForceEmpty(false);
          rememberWorkflow(data.saveWorkflow);
          if (opts.openCanvas ?? true) setActiveBoardId(data.saveWorkflow.id);
          showNotice(`Workflow «${data.saveWorkflow.name}» создан на сервере`);
        })
        .catch((err: unknown) => {
          showNotice(err instanceof Error ? err.message : "Не удалось создать workflow");
        });
    },
    [canEdit, forceEmpty, rememberWorkflow, setForceEmpty, showNotice],
  );

  const createFromTemplate = useCallback(
    (tpl: StarterTemplateRecord, openCanvas = true, customName?: string) => {
      if (!canEdit) return;
      const name = customName?.trim() || tpl.name;
      void gql<{ cloneTemplate: ServerWorkflow }>(QUERIES.clone, {
        input: { templateId: tpl.id, newWorkflowName: name },
      })
        .then((data) => {
          if (forceEmpty) setForceEmpty(false);
          rememberWorkflow(data.cloneTemplate);
          if (openCanvas) setActiveBoardId(data.cloneTemplate.id);
          setTemplates((prev) =>
            prev.map((item) => (item.id === tpl.id ? { ...item, cloneCount: item.cloneCount + 1 } : item)),
          );
          showNotice(`Шаблон «${name}» склонирован в ваш workflow`);
        })
        .catch((err: unknown) => {
          showNotice(err instanceof Error ? err.message : "Не удалось клонировать шаблон");
        });
    },
    [canEdit, forceEmpty, rememberWorkflow, setForceEmpty, showNotice],
  );

  const publishTemplate = useCallback(
    async (input: {
      workflowId: string;
      name: string;
      description: string;
      problemSolved: string;
      tags: string[];
      category?: TemplateCategory;
    }): Promise<StarterTemplateRecord | null> => {
      if (!canEdit) return null;
      const source = workflows.find((wf) => wf.id === input.workflowId);
      if (!source) return null;

      // Flush any unsaved graph edits before publishing
      await flushPendingSave(input.workflowId).catch(() => {});

      const optimisticId = `pending-${Date.now()}`;
      const optimistic: StarterTemplateRecord = {
        ...templateRecord({
          id: optimisticId,
          slug: "pending",
          name: input.name,
          description: input.description,
          problemSolved: input.problemSolved,
          tags: input.tags,
          isBuiltin: false,
          authorSubject: "",
          cloneCount: 0,
          sanitizedGraph: graphFromBoard(boardsRef.current[source.id] ?? { nodes: [], edges: [] }),
        }),
        category: input.category ?? "benchmark",
      };
      setTemplates((prev) => [optimistic, ...prev]);

      // Strictly pick only fields declared by GraphQL PublishTemplateInput (M1)
      const gqlInput = {
        workflowId: input.workflowId,
        name: input.name,
        description: input.description,
        problemSolved: input.problemSolved,
        tags: input.tags,
      };

      try {
        const data = await gql<{ publishTemplate: ServerTemplate }>(QUERIES.publish, {
          input: gqlInput,
        });
        const saved = templateRecord(data.publishTemplate);
        if (mountedRef.current) {
          setTemplates((prev) => [saved, ...prev.filter((item) => item.id !== optimisticId)]);
          showNotice(`Шаблон «${saved.name}» опубликован`);
        }
        return saved;
      } catch (err: unknown) {
        if (mountedRef.current) {
          setTemplates((prev) => prev.filter((item) => item.id !== optimisticId));
          showNotice(err instanceof Error ? err.message : "Не удалось опубликовать шаблон");
        }
        return null;
      }
    },
    [canEdit, flushPendingSave, showNotice, workflows],
  );

  const previewAiWorkflow = useCallback(
    async (prompt: string): Promise<AiWorkflowPreview> => {
      if (!canEdit) {
        throw new ApiError("Режим просмотра (viewer): генерация workflow недоступна");
      }
      const trimmed = prompt.trim();
      if (!trimmed) {
        throw new ApiError("Введите описание сценария проверки");
      }
      const data = await gql<{
        generateWorkflowFromText: {
          suggestedName: string;
          suggestedDescription: string;
          rationale: string;
          modelId: string;
          providerMode: string;
          graph: ServerGraph;
          missingFields: AiMissingFieldItem[];
        };
      }>(QUERIES.generate, { input: { prompt: trimmed, locale: "ru" } });

      const draft = data.generateWorkflowFromText;
      return {
        workflowName: draft.suggestedName || "Новый workflow (AI)",
        description: draft.suggestedDescription || trimmed,
        rationale: draft.rationale || "",
        modelId: draft.modelId || "",
        providerMode: draft.providerMode || "",
        graph: draft.graph,
        board: boardFromGraph(draft.graph),
        missingFields: draft.missingFields ?? [],
      };
    },
    [canEdit],
  );

  const saveGeneratedWorkflow = useCallback(
    async (
      name: string,
      graph: ServerGraph,
      promptOrDescription?: string,
      openCanvas = true,
    ): Promise<WorkflowRecord | null> => {
      if (!canEdit) return null;
      const trimmedName = name.trim() || "Новый workflow (AI)";
      const saved = await gql<{ saveWorkflow: ServerWorkflow }>(QUERIES.save, {
        input: {
          name: trimmedName,
          description: promptOrDescription?.trim() || "Собран из текстового описания (AI).",
          graph,
        },
      });
      if (!mountedRef.current) return null;
      if (forceEmpty) setForceEmpty(false);
      const record = rememberWorkflow(saved.saveWorkflow);
      if (openCanvas) setActiveBoardId(saved.saveWorkflow.id);
      showNotice(`Workflow «${saved.saveWorkflow.name}» создан на сервере`);
      return record;
    },
    [canEdit, forceEmpty, rememberWorkflow, setForceEmpty, showNotice],
  );

  const createFromAiPreset = useCallback(
    (preset: TextToWorkflowPreset, customName?: string, openCanvas = true, customPrompt?: string) => {
      if (!canEdit) return;
      const promptToUse = customPrompt?.trim() || preset.prompt;
      void previewAiWorkflow(promptToUse)
        .then(async (preview) => {
          await saveGeneratedWorkflow(
            customName?.trim() || preview.workflowName || preset.generatedName,
            preview.graph,
            preview.description || preset.generatedDescription,
            openCanvas,
          );
        })
        .catch((err: unknown) => {
          showNotice(err instanceof Error ? err.message : "Не удалось собрать workflow");
        });
    },
    [canEdit, previewAiWorkflow, saveGeneratedWorkflow, showNotice],
  );

  const resetFilters = useCallback(() => {
    setSearchQuery("");
    setTriggerFilter("ALL");
    setVerdictFilter("ALL");
  }, []);

  const hasActiveFilters =
    searchQuery.trim().length > 0 || triggerFilter !== "ALL" || verdictFilter !== "ALL";

  return {
    role,
    canEdit,
    loading,
    workflows: visibleWorkflows,
    filteredWorkflows,
    selectedWorkflow,
    selectedId: selectedWorkflow?.id ?? "",
    setSelectedId,
    boardsMap,
    availableSecrets,
    activeBoardId,
    activeBoardWorkflow,
    activeBoardGraph,
    openBoard,
    closeBoard,
    updateBoardGraph,
    renameWorkflow,
    searchQuery,
    setSearchQuery,
    triggerFilter,
    setTriggerFilter,
    verdictFilter,
    setVerdictFilter,
    hasActiveFilters,
    resetFilters,
    isEmptyWorkspace: visibleWorkflows.length === 0,
    runHistory,
    historyFocus,
    recordCanvasRun,
    runningMap,
    nodeRunStatuses,
    nodeRunStatusesByWorkflow,
    triggerRun,
    cancelRun,
    rerunFromNode,
    deleteWorkflow,
    undoDelete,
    createBlankWorkflow,
    templates,
    createFromTemplate,
    publishTemplate,
    previewAiWorkflow,
    saveGeneratedWorkflow,
    createFromAiPreset,
    aiModalOpen,
    setAiModalOpen,
    notice,
    setNotice,
    showNotice,
  };
}

function pickDirty(
  prev: Record<string, BoardGraphState>,
  pending: Record<string, number>,
): Record<string, BoardGraphState> {
  const dirty: Record<string, BoardGraphState> = {};
  for (const id of Object.keys(pending)) {
    if (prev[id]) dirty[id] = prev[id];
  }
  return dirty;
}
