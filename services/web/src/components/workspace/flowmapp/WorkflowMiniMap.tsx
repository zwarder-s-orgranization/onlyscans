"use client";

import { useCallback } from "react";
import {
  MiniMap,
  Panel,
  useReactFlow,
  useViewport,
  useViewportStore,
  type Node,
} from "@xyflow/react";
import { LocateFixed } from "lucide-react";
import type { CanvasBoardNodeData } from "@/data/canvas-nodes-catalog";
import type { FlowCanvasNode } from "../useCanvasBoardController";

const MINIMAP_WIDTH = 200;
const MINIMAP_HEIGHT = 134;

const INITIAL_FIT_OPTIONS = {
  padding: 0.22,
  maxZoom: 1.05,
} as const;

function getMotionDuration(ms: number): number {
  if (typeof window === "undefined") return 0;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : ms;
}

function getMiniMapNodeColor(node: Node): string {
  if (node.selected) return "#0040cc";

  const data = node.data as Partial<CanvasBoardNodeData> | undefined;
  switch (data?.runStatus) {
    case "failed":
      return "#dc2626";
    case "warning":
      return "#d97706";
    case "succeeded":
      return "#16a34a";
    case "running":
      return "#0080ff";
    default:
      break;
  }

  switch (data?.family) {
    case "trigger":
      return "#0050ff";
    case "source":
      return "#0284c7";
    case "analyzer":
      return "#0070f3";
    case "logic":
      return "#334155";
    case "ai":
      return "#0f766e";
    case "action":
      return "#1d4ed8";
    default:
      return "#0070f3";
  }
}

function getMiniMapNodeStrokeColor(node: Node): string {
  if (node.selected) return "#000000";

  const data = node.data as Partial<CanvasBoardNodeData> | undefined;
  switch (data?.runStatus) {
    case "failed":
      return "#7f1d1d";
    case "warning":
      return "#78350f";
    case "succeeded":
      return "#14532d";
    default:
      return "#002b6b";
  }
}

interface WorkflowMiniMapProps {
  hasNodes: boolean;
}

export function WorkflowMiniMap({ hasNodes }: WorkflowMiniMapProps) {
  const { fitView, setCenter, getZoom, getNodes, getNodesBounds } =
    useReactFlow<FlowCanvasNode>();
  const viewport = useViewport();
  const canvasWidth = useViewportStore((s) => s.width);
  const canvasHeight = useViewportStore((s) => s.height);

  const isOffscreen = (() => {
    if (!hasNodes || canvasWidth <= 0 || canvasHeight <= 0 || viewport.zoom <= 0) {
      return false;
    }
    const nodes = getNodes();
    if (nodes.length === 0) return false;
    const bounds = getNodesBounds(nodes);
    const viewLeft = -viewport.x / viewport.zoom;
    const viewTop = -viewport.y / viewport.zoom;
    const viewRight = viewLeft + canvasWidth / viewport.zoom;
    const viewBottom = viewTop + canvasHeight / viewport.zoom;

    const intersects =
      bounds.x + bounds.width > viewLeft + 24 &&
      bounds.x < viewRight - 24 &&
      bounds.y + bounds.height > viewTop + 24 &&
      bounds.y < viewBottom - 24;

    return !intersects;
  })();

  const handleResetView = useCallback(() => {
    void fitView({
      ...INITIAL_FIT_OPTIONS,
      duration: getMotionDuration(320),
    });
  }, [fitView]);

  const handleMiniMapClick = useCallback(
    (_event: React.MouseEvent, position: { x: number; y: number }) => {
      const targetZoom = Math.min(Math.max(getZoom(), 0.7), 1.15);
      void setCenter(position.x, position.y, {
        zoom: targetZoom,
        duration: getMotionDuration(260),
      });
    },
    [getZoom, setCenter],
  );

  const handleMiniMapNodeClick = useCallback(
    (event: React.MouseEvent, node: Node) => {
      event.stopPropagation();
      const width = node.measured?.width ?? 220;
      const height = node.measured?.height ?? 80;
      const targetZoom = Math.min(Math.max(getZoom(), 0.85), 1.05);
      void setCenter(node.position.x + width / 2, node.position.y + height / 2, {
        zoom: targetZoom,
        duration: getMotionDuration(260),
      });
    },
    [getZoom, setCenter],
  );

  return (
    <Panel
      position="bottom-right"
      className="fm-minimap-shell !m-3 hidden md:block"
    >
      <div
        className={`fm-float overflow-hidden rounded-[16px] border bg-[#ffffff] transition-colors ${
          isOffscreen
            ? "border-[#0080ff] shadow-[0_6px_22px_rgba(0,102,230,0.18)]"
            : "border-[#8c9baa]/75"
        }`}
        onDoubleClick={handleResetView}
      >
        <div className="flex items-center justify-between gap-2 border-b border-[#8c9baa]/35 bg-[#ffffff] px-2.5 py-1.5">
          <span
            className={`min-w-0 truncate text-[11px] font-semibold tracking-[-0.01em] ${
              isOffscreen ? "text-[#0050ff]" : "text-[#636f7b]"
            }`}
          >
            {isOffscreen ? "Схема вне экрана" : "Карта схемы"}
          </span>
          <button
            type="button"
            onClick={handleResetView}
            disabled={!hasNodes}
            title="Вернуться к начальному положению схемы (или двойной клик по карте)"
            aria-label="Вернуться к начальному положению схемы"
            className={`fm-focus inline-flex min-h-[26px] shrink-0 cursor-pointer items-center gap-1 rounded-full px-2.5 text-[11px] font-semibold transition-colors active:scale-[0.97] disabled:cursor-not-allowed disabled:opacity-40 ${
              isOffscreen
                ? "bg-[#0066e6] text-[#ffffff] hover:bg-[#0050ff]"
                : "border border-[#8c9baa]/60 bg-[#ffffff] text-[#222222] hover:border-[#0080ff] hover:bg-[#f6faff] hover:text-[#0050ff]"
            }`}
          >
            <LocateFixed className="h-3.5 w-3.5 stroke-[2]" aria-hidden="true" />
            <span>{isOffscreen ? "Вернуться" : "В начало"}</span>
          </button>
        </div>

        <MiniMap
          pannable
          zoomable
          nodeColor={getMiniMapNodeColor}
          nodeStrokeColor={getMiniMapNodeStrokeColor}
          nodeStrokeWidth={3}
          nodeBorderRadius={6}
          bgColor="#f8fbff"
          maskColor="rgba(15, 23, 42, 0.14)"
          maskStrokeColor="#0066e6"
          maskStrokeWidth={2}
          onClick={handleMiniMapClick}
          onNodeClick={handleMiniMapNodeClick}
          ariaLabel="Миникарта графа workflow — клик перемещает камеру, двойной клик возвращает в начало"
          className="!static !m-0 !block !rounded-none !border-0 !bg-transparent !shadow-none"
          style={{ width: MINIMAP_WIDTH, height: MINIMAP_HEIGHT }}
        />
      </div>
    </Panel>
  );
}
