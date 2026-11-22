"use client";

import type { MouseEvent } from "react";
import { useTheme } from "./ThemeProvider";

export function InkThemeToggle({ className = "h-9 w-9" }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";

  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    const isKeyboard = event.clientX === 0 && event.clientY === 0;
    const x = isKeyboard ? rect.left + rect.width / 2 : event.clientX;
    const y = isKeyboard ? rect.top + rect.height / 2 : event.clientY;
    toggleTheme({ x, y });
  };

  return (
    <button
      type="button"
      data-ink-live="true"
      onClick={handleClick}
      aria-pressed={isDark}
      aria-label={isDark ? "Включить светлую тему" : "Включить тёмную тему"}
      title={isDark ? "Светлая тема" : "Тёмная тема"}
      className={`fm-focus ink-theme-toggle relative inline-flex shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] bg-[#ffffff] text-[#000000] transition-[border-color,color,transform] duration-200 hover:border-[#0080ff] hover:text-[#0080ff] active:scale-95 ${className}`}
    >
      <svg
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        className={`transition-transform duration-500 [transition-timing-function:var(--ease-out-expo)] ${
          isDark ? "-rotate-25" : "rotate-0"
        }`}
      >
        {/* Sun body */}
        <circle
          cx="12"
          cy="12"
          r="4.2"
          className={`origin-center transition-[transform,opacity] duration-500 [transition-timing-function:var(--ease-out-expo)] ${
            isDark ? "scale-0 opacity-0" : "scale-100 opacity-100"
          }`}
        />
        {/* Sun rays */}
        <g
          className={`origin-center transition-[transform,opacity] duration-500 [transition-timing-function:var(--ease-out-expo)] ${
            isDark ? "-rotate-45 scale-50 opacity-0" : "rotate-0 scale-100 opacity-100"
          }`}
        >
          <line x1="12" y1="2.5" x2="12" y2="5" />
          <line x1="12" y1="19" x2="12" y2="21.5" />
          <line x1="4.9" y1="4.9" x2="6.7" y2="6.7" />
          <line x1="17.3" y1="17.3" x2="19.1" y2="19.1" />
          <line x1="2.5" y1="12" x2="5" y2="12" />
          <line x1="19" y1="12" x2="21.5" y2="12" />
          <line x1="4.9" y1="19.1" x2="6.7" y2="17.3" />
          <line x1="17.3" y1="6.7" x2="19.1" y2="4.9" />
        </g>
        {/* Moon crescent */}
        <path
          d="M20.2 13.4A8.2 8.2 0 1 1 10.6 3.8a6.8 6.8 0 0 0 9.6 9.6z"
          className={`origin-center transition-[transform,opacity] duration-500 [transition-timing-function:var(--ease-out-expo)] ${
            isDark ? "scale-100 opacity-100" : "rotate-45 scale-50 opacity-0"
          }`}
        />
      </svg>
    </button>
  );
}
