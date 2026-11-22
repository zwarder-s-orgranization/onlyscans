import type { ThemeMode } from "./renderer";

const THEME_BG: Record<ThemeMode, string> = {
  light: "#ffffff",
  dark: "#0a0d14",
};

let preloadPromise: Promise<typeof import("modern-screenshot").domToCanvas> | null = null;

function loadDomToCanvas(): Promise<typeof import("modern-screenshot").domToCanvas> {
  if (!preloadPromise) {
    preloadPromise = import("modern-screenshot").then((mod) => mod.domToCanvas);
  }
  return preloadPromise;
}

/** Eagerly loads modern-screenshot on idle so the first theme click never stalls on dynamic import. */
export function preloadCapture(): void {
  void loadDomToCanvas();
}

export function renderScale(): number {
  const isCoarse = window.matchMedia("(pointer: coarse)").matches;
  const cap = isCoarse ? 1 : 1.25;
  return Math.min(window.devicePixelRatio || 1, cap);
}

export interface ViewportSnapshot {
  canvas: HTMLCanvasElement;
  cssW: number;
  cssH: number;
}

/**
 * Captures the currently visible viewport using modern-screenshot (SVG foreignObject),
 * which natively supports Tailwind CSS v4 color functions (oklch/color-mix), React Flow
 * SVGs, and custom fonts without crashing or blocking layout.
 */
export async function captureViewport(
  currentTheme: ThemeMode,
  scale: number,
  maxTextureSize: number,
): Promise<ViewportSnapshot> {
  const width = document.documentElement.clientWidth || window.innerWidth;
  const height = document.documentElement.clientHeight || window.innerHeight;
  const safeScale = Math.min(scale, maxTextureSize / Math.max(1, width), maxTextureSize / Math.max(1, height));

  const domToCanvas = await loadDomToCanvas();

  const sx = window.scrollX;
  const sy = window.scrollY;

  const fullCanvas = await domToCanvas(document.body, {
    scale: safeScale,
    width,
    height,
    backgroundColor: THEME_BG[currentTheme],
    features: {
      restoreScrollPosition: false,
    },
    filter: (node) => {
      if (!(node instanceof Element)) return true;
      if (node.hasAttribute("data-ink-overlay")) return false;
      return true;
    },
    onCloneNode: (cloned) => {
      if (!(cloned instanceof HTMLElement)) return;
      // Offset cloned body by current scroll so the captured rectangle matches the viewport.
      if (cloned.tagName === "BODY") {
        cloned.style.width = `${width}px`;
        if (sx !== 0 || sy !== 0) {
          cloned.style.transform = `translate(${-sx}px, ${-sy}px)`;
          cloned.style.transformOrigin = "0 0";
        }
      } else if (sy !== 0 && cloned.tagName === "HEADER") {
        // Keep sticky top headers locked to viewport y=0 so their bottom border never jumps.
        cloned.style.transform = `translateY(${sy}px)`;
      }
    },
  });

  return { canvas: fullCanvas, cssW: width, cssH: height };
}
