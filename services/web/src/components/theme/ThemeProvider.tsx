"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { captureViewport, preloadCapture, renderScale } from "@/lib/ink-theme/capture";
import { INK_PARAMS, InkRenderer, type ThemeMode } from "@/lib/ink-theme/renderer";

export interface InkOrigin {
  x: number;
  y: number;
}

interface ThemeContextValue {
  theme: ThemeMode;
  isTransitioning: boolean;
  toggleTheme: (origin?: InkOrigin) => void;
}

const STORAGE_KEY = "secflow-theme";
const SPREAD = { growth: 0.7, cleanupFrom: 0.45, cleanupReach: 0.4, cleanupPow: 2 };
const CSS_FADE_MS = 380;

const ThemeContext = createContext<ThemeContextValue | null>(null);

function farthestCorner(x: number, y: number): number {
  const w = document.documentElement.clientWidth || window.innerWidth;
  const h = document.documentElement.clientHeight || window.innerHeight;
  return (
    Math.max(
      Math.hypot(x, y),
      Math.hypot(w - x, y),
      Math.hypot(x, h - y),
      Math.hypot(w - x, h - y),
    ) + 4
  );
}

function easePower3Out(t: number): number {
  const inv = 1 - Math.min(1, Math.max(0, t));
  return 1 - inv * inv * inv;
}

function applyDomTheme(next: ThemeMode): void {
  const root = document.documentElement;
  root.dataset.theme = next;
  root.style.colorScheme = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Ignore storage failures in restricted contexts.
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<ThemeMode>("light");
  const [isTransitioning, setIsTransitioning] = useState(false);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rendererRef = useRef<InkRenderer | null>(null);
  const rafRef = useRef<number | null>(null);
  const fadeTimerRef = useRef<number | null>(null);
  const capturingRef = useRef(false);
  const themeRef = useRef<ThemeMode>("light");

  useEffect(() => {
    const attr = document.documentElement.dataset.theme;
    const saved = (() => {
      try {
        return window.localStorage.getItem(STORAGE_KEY);
      } catch {
        return null;
      }
    })();
    const initial: ThemeMode =
      attr === "dark" || saved === "dark" ? "dark" : "light";
    themeRef.current = initial;
    setTheme(initial);
    applyDomTheme(initial);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const renderer = InkRenderer.create(canvas);
    rendererRef.current = renderer;
    if (!renderer) return;

    renderer.resize(renderScale());

    // Preload modern-screenshot on idle so the first click has zero dynamic-import stall.
    const preloadTimer = window.setTimeout(() => {
      preloadCapture();
    }, 300);

    const unwatch = renderer.watchContext(
      () => {
        if (rafRef.current !== null) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = null;
        }
        canvas.classList.remove("is-active");
        setIsTransitioning(false);
      },
      () => {
        renderer.resize(renderScale());
      },
    );

    const onResize = () => {
      renderer.resize(renderScale());
    };
    window.addEventListener("resize", onResize);

    return () => {
      window.clearTimeout(preloadTimer);
      window.removeEventListener("resize", onResize);
      unwatch();
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      if (fadeTimerRef.current !== null) window.clearTimeout(fadeTimerRef.current);
      renderer.dispose();
      rendererRef.current = null;
    };
  }, []);

  const crossFade = useCallback((next: ThemeMode, reduced: boolean) => {
    const root = document.documentElement;
    if (!reduced) {
      root.classList.add("theme-fade");
      if (fadeTimerRef.current !== null) window.clearTimeout(fadeTimerRef.current);
      fadeTimerRef.current = window.setTimeout(() => {
        root.classList.remove("theme-fade");
      }, CSS_FADE_MS + 40);
    }
    themeRef.current = next;
    applyDomTheme(next);
    setTheme(next);
  }, []);

  const toggleTheme = useCallback(
    (origin?: InkOrigin) => {
      if (capturingRef.current) return;

      const current = themeRef.current;
      const next: ThemeMode = current === "dark" ? "light" : "dark";
      const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      const renderer = rendererRef.current;
      const canvas = canvasRef.current;

      if (reduced || !renderer || renderer.isLost || !canvas) {
        crossFade(next, reduced);
        return;
      }

      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
        canvas.classList.remove("is-active");
        renderer.clear();
      }

      const cx = origin?.x ?? (document.documentElement.clientWidth || window.innerWidth) - 56;
      const cy = origin?.y ?? 26;
      const maxDist = farthestCorner(cx, cy);
      const seed = {
        x: Math.random() * 64 - 32,
        y: Math.random() * 64 - 32,
        angle: Math.random() * Math.PI * 2,
      };

      capturingRef.current = true;
      setIsTransitioning(true);

      const scale = renderScale();
      void captureViewport(current, scale, renderer.maxTextureSize)
        .then((snap) => {
          capturingRef.current = false;
          if (!rendererRef.current || rendererRef.current.isLost) {
            crossFade(next, false);
            setIsTransitioning(false);
            return;
          }

          renderer.syncToSnapshot(snap.canvas, snap.cssW, snap.cssH);
          renderer.uploadFrom(snap.canvas);

          // Draw frame 0 (100% old theme) before flipping the live DOM underneath.
          renderer.draw({
            to: next,
            center: { x: cx, y: cy },
            radius: 0,
            cleanup: 0,
            time: 0,
            seed,
          });
          canvas.classList.add("is-active");

          // Flip live DOM underneath the opaque snapshot.
          themeRef.current = next;
          applyDomTheme(next);
          setTheme(next);

          const durationMs = INK_PARAMS.duration * 1000;
          let start: number | null = null;

          const step = (now: number) => {
            if (start === null) {
              // Anchor clock on the first post-paint frame so DOM recalc never eats frame 0.
              start = now;
            }
            const elapsedMs = now - start;
            const linear = Math.min(1, elapsedMs / durationMs);
            const progress = easePower3Out(linear);
            const ramp = Math.max(
              0,
              (linear - SPREAD.cleanupFrom) / (1 - SPREAD.cleanupFrom),
            );
            const cleanup =
              ramp ** SPREAD.cleanupPow * maxDist * SPREAD.cleanupReach +
              Math.max(0, (linear - 0.96) / 0.04) * maxDist;

            renderer.draw({
              to: next,
              center: { x: cx, y: cy },
              radius: progress * maxDist * SPREAD.growth,
              cleanup,
              time: elapsedMs / 1000,
              seed,
            });

            if (linear < 1) {
              rafRef.current = requestAnimationFrame(step);
            } else {
              rafRef.current = null;
              canvas.classList.remove("is-active");
              renderer.clear();
              setIsTransitioning(false);
            }
          };

          // Wait one animation frame for the browser to commit the new theme underneath.
          rafRef.current = requestAnimationFrame(() => {
            rafRef.current = requestAnimationFrame(step);
          });
        })
        .catch((err) => {
          console.error("[ink-theme] snapshot failed, using CSS fallback:", err);
          capturingRef.current = false;
          canvas.classList.remove("is-active");
          setIsTransitioning(false);
          crossFade(next, false);
        });
    },
    [crossFade],
  );

  const value = useMemo(
    () => ({ theme, isTransitioning, toggleTheme }),
    [theme, isTransitioning, toggleTheme],
  );

  return (
    <ThemeContext.Provider value={value}>
      {children}
      <canvas
        ref={canvasRef}
        data-ink-overlay="true"
        aria-hidden="true"
        className="ink-overlay-canvas"
      />
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used inside ThemeProvider");
  }
  return ctx;
}
