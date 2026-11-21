"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import {
  addEdge,
  useEdgesState,
  useNodesState,
  useReactFlow,
  useUpdateNodeInternals,
  type Connection,
  type Edge,
  type Node,
} from "@xyflow/react";
import {
  autoLayoutBoard,
  CANVAS_NODE_CATALOG,
  createCanvasNodeFromTemplate,
  DND_NODE_MIME,
  getSwitchOutputPorts,
  resolveNodeRunOutcome,
  TEMPLATE_BY_PLUGIN_ID,
  type CanvasBoardEdge,
  type CanvasBoardNode,
  type CanvasBoardNodeData,
  type CanvasNodeTemplate,
} from "@/data/canvas-nodes-catalog";
import type { NodeRunPaint } from "@/lib/workflow-map";
import type {
  NodeFamily,
  PolicyVerdict,
  WorkflowRunStep,
} from "@/data/workflows-workspace-data";

export type FlowCanvasNode = Node<CanvasBoardNodeData, "secflowNode">;

export interface CanvasRunCompletedPayload {
  workflowId: string;
  wavesCount: number;
  totalDurationMs: number;
  steps: WorkflowRunStep[];
}

interface UseCanvasBoardControllerParams {
  boardId: string;
  initialNodes: CanvasBoardNode[];
  initialEdges: CanvasBoardEdge[];
  canEdit: boolean;
  policyGate?: PolicyVerdict;
  edgeType?: "smoothstep" | "bezier" | "default" | "step";
  edgeColor?: string;
  activeEdgeColor?: string;
  onSyncGraph: (boardId: string, nodes: CanvasBoardNode[], edges: CanvasBoardEdge[]) => void;
  onRunCompleted?: (payload: CanvasRunCompletedPayload) => void;
  onNotice?: (message: string) => void;
  nodeRunStatuses?: Record<string, NodeRunPaint>;
}

function toFlowNodes(items: CanvasBoardNode[]): FlowCanvasNode[] {
  return items.map((n) => ({
    id: n.id,
    type: "secflowNode",
    position: n.position,
    data: { ...n.data },
  }));
}

function toFlowEdges(
  items: CanvasBoardEdge[],
  edgeType: "smoothstep" | "bezier" | "default" | "step",
  edgeColor: string,
): Edge[] {
  return items.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    sourceHandle: e.sourceHandle ?? undefined,
    targetHandle: e.targetHandle ?? undefined,
    label: e.label,
    type: edgeType,
    interactionWidth: 24,
    style: { stroke: edgeColor, strokeWidth: 1.75 },
  }));
}

function fromFlowNodes(items: FlowCanvasNode[]): CanvasBoardNode[] {
  return items.map((n) => ({
    id: n.id,
    type: "secflowNode",
    position: n.position,
    data: { ...n.data },
  }));
}

function fromFlowEdges(items: Edge[]): CanvasBoardEdge[] {
  return items.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    sourceHandle: e.sourceHandle,
    targetHandle: e.targetHandle,
    label: typeof e.label === "string" ? e.label : undefined,
  }));
}

export function useCanvasBoardController({
  boardId,
  initialNodes,
  initialEdges,
  canEdit,
  policyGate = "PASS",
  edgeType = "smoothstep",
  edgeColor = "#8c9baa",
  activeEdgeColor = "#0080ff",
  onSyncGraph,
  onRunCompleted,
  onNotice,
  nodeRunStatuses,
}: UseCanvasBoardControllerParams) {
  const { screenToFlowPosition, fitView } = useReactFlow();
  const updateNodeInternals = useUpdateNodeInternals();

  const [nodes, setNodes, onNodesChange] = useNodesState<FlowCanvasNode>(
    toFlowNodes(initialNodes),
  );
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(
    toFlowEdges(initialEdges, edgeType, edgeColor),
  );

  useEffect(() => {
    if (!nodeRunStatuses) return;
    setNodes((prev) =>
      prev.map((node) => {
        const paint = nodeRunStatuses[node.id];
        if (!paint) return node;
        if (
          node.data.runStatus === paint.status &&
          node.data.durationMs === (paint.durationMs ?? node.data.durationMs) &&
          node.data.findingsEmitted === paint.findings
        ) {
          return node;
        }
        return {
          ...node,
          data: {
            ...node.data,
            runStatus: paint.status,
            durationMs: paint.durationMs ?? node.data.durationMs,
            findingsEmitted: paint.findings ?? 0,
          },
        };
      }),
    );
  }, [nodeRunStatuses, setNodes]);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(
    initialNodes[0]?.id ?? null,
  );
  const [categoryFilter, setCategoryFilter] = useState<"ALL" | NodeFamily>("ALL");
  const [paletteQuery, setPaletteQuery] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [runLog, setRunLog] = useState<string[]>([]);
  const [undoDepth, setUndoDepth] = useState(0);

  const timersRef = useRef<number[]>([]);
  const prevBoardIdRef = useRef<string>(boardId);
  const historyRef = useRef<Array<{ nodes: FlowCanvasNode[]; edges: Edge[] }>>([]);

  const cloneSnapshot = useCallback(
    (snapNodes: FlowCanvasNode[], snapEdges: Edge[]) => ({
      nodes: snapNodes.map((n) => ({
        ...n,
        position: { ...n.position },
        data: {
          ...n.data,
          outputs: [...n.data.outputs],
          requiredSecretKeys: n.data.requiredSecretKeys ? [...n.data.requiredSecretKeys] : [],
          optionalSecretKeys: n.data.optionalSecretKeys ? [...n.data.optionalSecretKeys] : [],
          secretBindings: n.data.secretBindings
            ? n.data.secretBindings.map((binding) => ({ ...binding }))
            : [],
          config: { ...n.data.config },
          sampleOutput: { ...n.data.sampleOutput },
        },
      })),
      edges: snapEdges.map((e) => ({ ...e })),
    }),
    [],
  );

  const pushHistory = useCallback(
    (snapNodes: FlowCanvasNode[], snapEdges: Edge[]) => {
      const stack = historyRef.current;
      stack.push(cloneSnapshot(snapNodes, snapEdges));
      if (stack.length > 40) {
        stack.shift();
      }
      setUndoDepth(stack.length);
    },
    [cloneSnapshot],
  );

  const clearTimers = useCallback(() => {
    for (const t of timersRef.current) {
      window.clearTimeout(t);
    }
    timersRef.current = [];
  }, []);

  useEffect(() => {
    return () => clearTimers();
  }, [clearTimers]);

  // Reset local graph when switching to a different boardId
  useEffect(() => {
    if (prevBoardIdRef.current !== boardId) {
      prevBoardIdRef.current = boardId;
      clearTimers();
      historyRef.current = [];
      setUndoDepth(0);
      setIsRunning(false);
      setRunLog([]);
      setNodes(toFlowNodes(initialNodes));
      setEdges(toFlowEdges(initialEdges, edgeType, edgeColor));
      setSelectedNodeId(initialNodes[0]?.id ?? null);
      window.requestAnimationFrame(() => {
        void fitView({ padding: 0.22, maxZoom: 1.05, duration: 200 });
      });
    }
  }, [boardId, initialNodes, initialEdges, edgeType, edgeColor, clearTimers, setNodes, setEdges, fitView]);

  const syncToParent = useCallback(
    (nextNodes: FlowCanvasNode[], nextEdges: Edge[]) => {
      onSyncGraph(boardId, fromFlowNodes(nextNodes), fromFlowEdges(nextEdges));
    },
    [boardId, onSyncGraph],
  );

  const filteredCatalog = useMemo(() => {
    const q = paletteQuery.trim().toLowerCase();
    return CANVAS_NODE_CATALOG.filter((tpl) => {
      if (categoryFilter !== "ALL" && tpl.family !== categoryFilter) {
        return false;
      }
      if (!q) return true;
      return (
        tpl.label.toLowerCase().includes(q) ||
        tpl.shortLabel.toLowerCase().includes(q) ||
        tpl.purposeTag.toLowerCase().includes(q) ||
        tpl.description.toLowerCase().includes(q) ||
        tpl.pluginId.toLowerCase().includes(q)
      );
    });
  }, [categoryFilter, paletteQuery]);

  const categoryCounts = useMemo(() => {
    const counts: Record<"ALL" | NodeFamily, number> = {
      ALL: CANVAS_NODE_CATALOG.length,
      trigger: 0,
      source: 0,
      analyzer: 0,
      logic: 0,
      ai: 0,
      action: 0,
    };
    for (const tpl of CANVAS_NODE_CATALOG) {
      counts[tpl.family] += 1;
    }
    return counts;
  }, []);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId],
  );

  const onDragStartNode = useCallback(
    (event: DragEvent<HTMLElement>, pluginId: string) => {
      if (!canEdit) return;
      event.dataTransfer.setData(DND_NODE_MIME, pluginId);
      event.dataTransfer.setData("text/plain", pluginId);
      event.dataTransfer.effectAllowed = "move";
    },
    [canEdit],
  );

  const onDragOverCanvas = useCallback(
    (event: DragEvent<HTMLElement>) => {
      if (!canEdit) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
      if (!isDragOver) {
        setIsDragOver(true);
      }
    },
    [canEdit, isDragOver],
  );

  const onDragLeaveCanvas = useCallback(() => {
    setIsDragOver(false);
  }, []);

  const addTemplateNode = useCallback(
    (tpl: CanvasNodeTemplate, explicitPosition?: { x: number; y: number }) => {
      if (!canEdit) {
        onNotice?.("Режим viewer: редактирование графа отключено");
        return;
      }
      let nextPos = explicitPosition;
      if (!nextPos) {
        const last = nodes[nodes.length - 1];
        nextPos = last
          ? { x: last.position.x + 270, y: last.position.y + ((nodes.length % 2) * 56 - 28) }
          : { x: 100, y: 180 };
      }
      const created = createCanvasNodeFromTemplate(tpl, nextPos);
      const flowNode: FlowCanvasNode = {
        id: created.id,
        type: "secflowNode",
        position: created.position,
        data: created.data,
      };
      pushHistory(nodes, edges);
      const nextNodes = [...nodes, flowNode];
      let nextEdges = edges;

      // Smart n8n-style auto-connect if user clicked to add and there's a selected/previous node with output
      if (!explicitPosition) {
        const anchor = selectedNode ?? nodes[nodes.length - 1];
        if (anchor && tpl.inputs > 0 && anchor.data.outputs.length > 0) {
          const autoEdge: Edge = {
            id: `e-${anchor.id}-${flowNode.id}`,
            source: anchor.id,
            target: flowNode.id,
            sourceHandle: anchor.data.outputs[0],
            targetHandle: "in",
            type: edgeType,
            style: { stroke: edgeColor, strokeWidth: 1.75 },
          };
          nextEdges = [...edges, autoEdge];
          setEdges(nextEdges);
        }
      }

      setNodes(nextNodes);
      setSelectedNodeId(flowNode.id);
      syncToParent(nextNodes, nextEdges);
      onNotice?.(`Добавлена нода «${tpl.label}»`);
    },
    [canEdit, nodes, edges, selectedNode, edgeType, edgeColor, setNodes, setEdges, syncToParent, pushHistory, onNotice],
  );

  const onDropCanvas = useCallback(
    (event: DragEvent<HTMLElement>) => {
      event.preventDefault();
      setIsDragOver(false);
      if (!canEdit) return;

      const pluginId =
        event.dataTransfer.getData(DND_NODE_MIME) || event.dataTransfer.getData("text/plain");
      const tpl = TEMPLATE_BY_PLUGIN_ID[pluginId];
      if (!tpl) return;

      const flowPosition = screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      addTemplateNode(tpl, {
        x: Math.round(flowPosition.x - 110),
        y: Math.round(flowPosition.y - 36),
      });
    },
    [canEdit, screenToFlowPosition, addTemplateNode],
  );

  const onConnect = useCallback(
    (connection: Connection) => {
      if (!canEdit) return;
      pushHistory(nodes, edges);
      setEdges((prev) => {
        const next = addEdge(
          {
            ...connection,
            type: edgeType,
            style: { stroke: edgeColor, strokeWidth: 1.75 },
          },
          prev,
        );
        syncToParent(nodes, next);
        return next;
      });
    },
    [canEdit, edgeType, edgeColor, nodes, edges, setEdges, syncToParent, pushHistory],
  );

  const deleteNodesByIds = useCallback(
    (nodeIds: string[]) => {
      if (!canEdit || nodeIds.length === 0) return;
      const toRemove = new Set(nodeIds);
      const existingCount = nodes.filter((n) => toRemove.has(n.id)).length;
      if (existingCount === 0) return;

      pushHistory(nodes, edges);
      const nextNodes = nodes.filter((n) => !toRemove.has(n.id));
      const nextEdges = edges.filter(
        (e) => !toRemove.has(e.source) && !toRemove.has(e.target),
      );
      setNodes(nextNodes);
      setEdges(nextEdges);
      setSelectedNodeId((prev) =>
        prev && toRemove.has(prev) ? (nextNodes[0]?.id ?? null) : prev,
      );
      syncToParent(nextNodes, nextEdges);
      onNotice?.(
        existingCount === 1
          ? "Нода удалена · Ctrl+Z для возврата"
          : `Удалено нод: ${existingCount} · Ctrl+Z для возврата`,
      );
    },
    [canEdit, nodes, edges, setNodes, setEdges, syncToParent, pushHistory, onNotice],
  );

  const selectOnlyNode = useCallback(
    (nodeId: string) => {
      setSelectedNodeId(nodeId);
      setNodes((prev) => prev.map((node) => ({ ...node, selected: node.id === nodeId })));
      setEdges((prev) => prev.map((edge) => (edge.selected ? { ...edge, selected: false } : edge)));
    },
    [setEdges, setNodes],
  );

  const selectOnlyEdge = useCallback(
    (edgeId: string) => {
      setSelectedNodeId(null);
      setNodes((prev) => prev.map((node) => (node.selected ? { ...node, selected: false } : node)));
      setEdges((prev) => prev.map((edge) => ({ ...edge, selected: edge.id === edgeId })));
    },
    [setEdges, setNodes],
  );

  const clearSelection = useCallback(() => {
    setSelectedNodeId(null);
    setNodes((prev) => prev.map((node) => (node.selected ? { ...node, selected: false } : node)));
    setEdges((prev) => prev.map((edge) => (edge.selected ? { ...edge, selected: false } : edge)));
  }, [setEdges, setNodes]);

  const deleteEdgesByIds = useCallback(
    (edgeIds: string[]) => {
      if (!canEdit || edgeIds.length === 0) return;
      const toRemove = new Set(edgeIds);
      const existingCount = edges.filter((e) => toRemove.has(e.id)).length;
      if (existingCount === 0) return;

      pushHistory(nodes, edges);
      const nextEdges = edges.filter((e) => !toRemove.has(e.id));
      setEdges(nextEdges);
      syncToParent(nodes, nextEdges);
      onNotice?.("Связь удалена · Ctrl+Z для возврата");
    },
    [canEdit, nodes, edges, setEdges, syncToParent, pushHistory, onNotice],
  );

  const deleteNodeById = useCallback(
    (nodeId: string) => {
      deleteNodesByIds([nodeId]);
    },
    [deleteNodesByIds],
  );

  const undo = useCallback(() => {
    if (!canEdit) return;
    const prev = historyRef.current.pop();
    setUndoDepth(historyRef.current.length);
    if (!prev) return;
    setNodes(prev.nodes);
    setEdges(prev.edges);
    setSelectedNodeId((curr) => {
      if (curr && prev.nodes.some((n) => n.id === curr)) return curr;
      return prev.nodes[prev.nodes.length - 1]?.id ?? null;
    });
    syncToParent(prev.nodes, prev.edges);
    onNotice?.("Действие отменено (Ctrl+Z)");
  }, [canEdit, setNodes, setEdges, syncToParent, onNotice]);

  const updateNodeLabel = useCallback(
    (nodeId: string, label: string) => {
      if (!canEdit) return;
      const nextNodes = nodes.map((n) =>
        n.id === nodeId ? { ...n, data: { ...n.data, label } } : n,
      );
      setNodes(nextNodes);
      syncToParent(nextNodes, edges);
    },
    [canEdit, nodes, edges, setNodes, syncToParent],
  );

  const updateNodeConfig = useCallback(
    (nodeId: string, key: string, value: string) => {
      if (!canEdit) return;
      let portsChanged = false;
      const nextNodes = nodes.map((n) => {
        if (n.id !== nodeId) return n;
        const nextConfig = { ...n.data.config, [key]: value };
        if (n.data.pluginId === "logic.switch" && key === "mode") {
          portsChanged = true;
          return {
            ...n,
            data: {
              ...n.data,
              outputs: getSwitchOutputPorts(value),
              config: nextConfig,
            },
          };
        }
        return { ...n, data: { ...n.data, config: nextConfig } };
      });
      setNodes(nextNodes);
      if (portsChanged) {
        window.requestAnimationFrame(() => updateNodeInternals(nodeId));
      }
      syncToParent(nextNodes, edges);
    },
    [canEdit, nodes, edges, setNodes, syncToParent, updateNodeInternals],
  );

  const updateNodeSecretBinding = useCallback(
    (nodeId: string, paramKey: string, secretRef: string) => {
      if (!canEdit) return;
      const trimmedRef = secretRef.trim();
      const nextNodes = nodes.map((n) => {
        if (n.id !== nodeId) return n;
        const rest = (n.data.secretBindings ?? []).filter(
          (binding) => binding.paramKey !== paramKey,
        );
        const nextBindings = trimmedRef
          ? [...rest, { paramKey, secretRef: trimmedRef }]
          : rest;
        return {
          ...n,
          data: {
            ...n.data,
            secretBindings: nextBindings,
          },
        };
      });
      setNodes(nextNodes);
      syncToParent(nextNodes, edges);
    },
    [canEdit, nodes, edges, setNodes, syncToParent],
  );

  const handleAutoLayout = useCallback(
    (options?: { fit?: boolean } | unknown) => {
      const shouldFit =
        options &&
        typeof options === "object" &&
        "fit" in options &&
        typeof (options as { fit?: unknown }).fit === "boolean"
          ? Boolean((options as { fit?: boolean }).fit)
          : true;
      if (canEdit) {
        pushHistory(nodes, edges);
      }
      const laidOut = autoLayoutBoard(fromFlowNodes(nodes), fromFlowEdges(edges));
      const nextFlowNodes = toFlowNodes(laidOut);
      setNodes(nextFlowNodes);
      if (canEdit) {
        syncToParent(nextFlowNodes, edges);
      }
      if (shouldFit) {
        window.requestAnimationFrame(() => {
          void fitView({ padding: 0.2, maxZoom: 1.05, duration: 240 });
        });
      }
      onNotice?.("Граф выровнен по слоям DAG");
    },
    [canEdit, nodes, edges, setNodes, syncToParent, pushHistory, fitView, onNotice],
  );

  const handleClearCanvas = useCallback(() => {
    if (!canEdit || nodes.length === 0) return;
    clearTimers();
    pushHistory(nodes, edges);
    setIsRunning(false);
    setNodes([]);
    setEdges([]);
    setSelectedNodeId(null);
    syncToParent([], []);
    onNotice?.("Холст очищен · Ctrl+Z для возврата");
  }, [canEdit, nodes, edges, clearTimers, pushHistory, setNodes, setEdges, syncToParent, onNotice]);

  const handleFitView = useCallback(() => {
    void fitView({ padding: 0.2, maxZoom: 1.1, duration: 220 });
  }, [fitView]);

  const runCanvasSimulation = useCallback(() => {
    if (nodes.length === 0 || isRunning) return;
    clearTimers();
    setIsRunning(true);
    setRunLog(["Старт детерминированного прогона графа (DAG)..."]);

    // Build topological parallel waves from actual graph edges (Kahn's algorithm by layers)
    const nodeById = new Map<string, FlowCanvasNode>();
    const inDegree = new Map<string, number>();
    const adj = new Map<string, Set<string>>();

    for (const n of nodes) {
      nodeById.set(n.id, n);
      inDegree.set(n.id, 0);
      adj.set(n.id, new Set());
    }

    for (const e of edges) {
      if (nodeById.has(e.source) && nodeById.has(e.target) && e.source !== e.target) {
        const targets = adj.get(e.source)!;
        if (!targets.has(e.target)) {
          targets.add(e.target);
          inDegree.set(e.target, (inDegree.get(e.target) ?? 0) + 1);
        }
      }
    }

    const waves: FlowCanvasNode[][] = [];
    const scheduled = new Set<string>();
    let frontier = nodes
      .filter((n) => (inDegree.get(n.id) ?? 0) === 0)
      .sort((a, b) => a.position.y - b.position.y);

    while (frontier.length > 0) {
      waves.push(frontier);
      const nextFrontier: FlowCanvasNode[] = [];
      for (const curr of frontier) {
        scheduled.add(curr.id);
        for (const tgtId of adj.get(curr.id) ?? []) {
          const rem = (inDegree.get(tgtId) ?? 1) - 1;
          inDegree.set(tgtId, rem);
          if (rem === 0) {
            const tgtNode = nodeById.get(tgtId);
            if (tgtNode) nextFrontier.push(tgtNode);
          }
        }
      }
      frontier = nextFrontier.sort((a, b) => a.position.y - b.position.y);
    }

    // Fallback for any cyclic nodes so every node still runs
    const unscheduled = nodes
      .filter((n) => !scheduled.has(n.id))
      .sort((a, b) => a.position.x - b.position.x || a.position.y - b.position.y);
    if (unscheduled.length > 0) {
      waves.push(unscheduled);
    }

    setNodes((prev) =>
      prev.map((n) => ({ ...n, data: { ...n.data, runStatus: "idle" } })),
    );
    setEdges((prev) =>
      prev.map((e) => ({
        ...e,
        animated: false,
        style: { stroke: edgeColor, strokeWidth: 1.75 },
      })),
    );

    let offset = 120;
    waves.forEach((wave) => {
      const waveIds = new Set(wave.map((n) => n.id));
      const waveStart = offset;

      const startTimer = window.setTimeout(() => {
        setNodes((prev) =>
          prev.map((n) =>
            waveIds.has(n.id) ? { ...n, data: { ...n.data, runStatus: "running" } } : n,
          ),
        );
        setEdges((prev) =>
          prev.map((e) =>
            waveIds.has(e.target)
              ? { ...e, animated: true, style: { stroke: activeEdgeColor, strokeWidth: 2.25 } }
              : e,
          ),
        );
        if (wave.length === 1) {
          setSelectedNodeId(wave[0].id);
          setRunLog((prev) => [...prev, `→ ${wave[0].data.label} (${wave[0].data.runtime})`]);
        } else {
          setRunLog((prev) => [
            ...prev,
            `⇉ Параллельно (${wave.length}): ${wave.map((n) => n.data.shortLabel).join(", ")}`,
          ]);
        }
      }, waveStart);
      timersRef.current.push(startTimer);

      // Inside a parallel wave, each branch finishes proportionally to its durationMs
      const maxRealDuration = Math.max(...wave.map((n) => n.data.durationMs), 1);
      let waveEnd = waveStart;

      wave.forEach((node) => {
        const visualDuration =
          wave.length === 1
            ? 700
            : Math.round(640 + (node.data.durationMs / maxRealDuration) * 440);
        const nodeEnd = waveStart + visualDuration;
        if (nodeEnd > waveEnd) waveEnd = nodeEnd;

        const doneTimer = window.setTimeout(() => {
          const outcome = resolveNodeRunOutcome(node.data.pluginId, policyGate);
          setNodes((prev) =>
            prev.map((n) =>
              n.id === node.id ? { ...n, data: { ...n.data, runStatus: outcome.canvasStatus } } : n,
            ),
          );
          setEdges((prev) =>
            prev.map((e) =>
              e.target === node.id
                ? { ...e, animated: false, style: { stroke: activeEdgeColor, strokeWidth: 2 } }
                : e,
            ),
          );
        }, nodeEnd);
        timersRef.current.push(doneTimer);
      });

      offset = waveEnd + 90;
    });

    const finishTimer = window.setTimeout(() => {
      setIsRunning(false);
      setRunLog((prev) => [
        ...prev,
        `✓ Прогон завершён · волн: ${waves.length}, нод: ${nodes.length}`,
      ]);
      const finalNodes = nodes.map((n) => ({
        ...n,
        data: {
          ...n.data,
          runStatus: resolveNodeRunOutcome(n.data.pluginId, policyGate).canvasStatus,
        },
      }));
      syncToParent(finalNodes, edges);
      const executedSteps: WorkflowRunStep[] = waves.flatMap((wave, waveIdx) =>
        wave.map((n) => {
          const outcome = resolveNodeRunOutcome(n.data.pluginId, policyGate);
          return {
            id: `${n.id}-w${waveIdx}`,
            nodeId: n.id,
            nodeLabel: n.data.label,
            pluginId: n.data.pluginId,
            family: n.data.family,
            status: outcome.stepStatus,
            durationMs: n.data.durationMs,
            summary:
              wave.length > 1
                ? `Волна ${waveIdx + 1} (параллельно · ${wave.length}) · ${n.data.purposeTag}`
                : `Волна ${waveIdx + 1} · ${n.data.purposeTag}`,
          };
        }),
      );
      const totalDurationMs = waves.reduce(
        (sum, wave) => sum + Math.max(...wave.map((n) => n.data.durationMs), 0),
        0,
      );
      onRunCompleted?.({
        workflowId: boardId,
        wavesCount: waves.length,
        totalDurationMs,
        steps: executedSteps,
      });
      onNotice?.(`Прогон доски завершён (${nodes.length} нод, ${waves.length} волн)`);
    }, offset + 80);
    timersRef.current.push(finishTimer);
  }, [boardId, nodes, edges, isRunning, policyGate, clearTimers, setNodes, setEdges, syncToParent, edgeColor, activeEdgeColor, onRunCompleted, onNotice]);

  return {
    nodes,
    edges,
    onNodesChange,
    onEdgesChange,
    onConnect,
    selectedNode,
    selectedNodeId,
    setSelectedNodeId,
    categoryFilter,
    setCategoryFilter,
    paletteQuery,
    setPaletteQuery,
    filteredCatalog,
    categoryCounts,
    isDragOver,
    isRunning,
    runLog,
    onDragStartNode,
    onDragOverCanvas,
    onDragLeaveCanvas,
    onDropCanvas,
    addTemplateNode,
    deleteNodeById,
    deleteNodesByIds,
    deleteEdgesByIds,
    selectOnlyNode,
    selectOnlyEdge,
    clearSelection,
    undo,
    canUndo: undoDepth > 0,
    updateNodeLabel,
    updateNodeConfig,
    updateNodeSecretBinding,
    handleAutoLayout,
    handleClearCanvas,
    handleFitView,
    runCanvasSimulation,
    syncToParent,
  };
}
