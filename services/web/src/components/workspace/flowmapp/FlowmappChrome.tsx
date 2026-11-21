"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Clock,
  GitBranch,
  LogOut,
  Play,
  Plus,
  RotateCcw,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  User,
  Webhook,
  X,
} from "lucide-react";
import {
  AI_TEXT_PRESETS,
  ROLE_LABELS,
  RUN_STATUS_LABELS,
  type PolicyVerdict,
  type RunStatus,
  type StarterTemplateRecord,
  type TextToWorkflowPreset,
  type TriggerKind,
  type UserRole,
} from "@/data/workflows-workspace-data";
import { clearSession } from "@/lib/session";
import { useWorkspacePreview } from "../WorkspacePreviewContext";
import type { FeedbackNotice } from "../useWorkflowsWorkspace";

export function FlowmappLogoMark() {
  return (
    <span
      aria-hidden="true"
      className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] bg-[#000000] text-[#ffffff]"
    >
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="4.5" cy="4.5" r="2" stroke="#ffffff" strokeWidth="1.5" />
        <circle cx="11.5" cy="11.5" r="2" stroke="#0080ff" strokeWidth="1.5" />
        <path d="M6.5 4.5H10C10.8 4.5 11.5 5.2 11.5 6V9.5" stroke="#ffffff" strokeWidth="1.5" />
      </svg>
    </span>
  );
}

export function FlowmappHeader({
  role,
  onNavigateHint,
  activeSection = "workflows",
  onSelectSection,
  runsCount,
  templatesCount,
}: {
  role: UserRole;
  onNavigateHint: (msg: string) => void;
  activeSection?: "workflows" | "runs" | "templates" | "settings";
  onSelectSection?: (section: "workflows" | "runs" | "templates") => void;
  runsCount?: number;
  templatesCount?: number;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { email, setRole, setEmail } = useWorkspacePreview();
  const user = ROLE_LABELS[role];
  const displayEmail = email || user.email;
  const displayName = email || user.name;
  const initials = displayName
    .split(" ")
    .map((p) => p[0])
    .join("")
    .slice(0, 2);

  useEffect(() => {
    if (!menuOpen) return;
    const onPointerDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("mousedown", onPointerDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [menuOpen]);

  return (
    <header className="sticky top-0 z-30 h-[52px] border-b border-[#8c9baa]/45 bg-[#ffffff]">
      <div className="mx-auto flex h-full max-w-[1200px] items-center justify-between gap-2 px-3 sm:gap-4 sm:px-6">
        <div className="flex min-w-0 items-center gap-3 sm:gap-8">
          {onSelectSection ? (
            <button
              type="button"
              onClick={() => onSelectSection("workflows")}
              className="fm-focus inline-flex shrink-0 cursor-pointer items-center gap-2 rounded-[6px] py-1 text-[14px] font-bold tracking-[-0.03em] text-[#000000] sm:text-[15px]"
            >
              <FlowmappLogoMark />
              <span className="hidden min-[400px]:inline">SecFlow</span>
            </button>
          ) : (
            <Link
              href="/"
              className="fm-focus inline-flex shrink-0 items-center gap-2 rounded-[6px] py-1 text-[14px] font-bold tracking-[-0.03em] text-[#000000] sm:text-[15px]"
            >
              <FlowmappLogoMark />
              <span className="hidden min-[400px]:inline">SecFlow</span>
            </Link>
          )}

          <nav aria-label="Основная навигация" className="flex items-center gap-3 sm:gap-7">
            {onSelectSection ? (
              <button
                type="button"
                onClick={() => onSelectSection("workflows")}
                aria-current={activeSection === "workflows" ? "page" : undefined}
                className={`fm-focus relative inline-flex h-[52px] shrink-0 cursor-pointer items-center whitespace-nowrap text-[13px] tracking-[-0.015em] transition-colors sm:text-[14px] ${
                  activeSection === "workflows"
                    ? "font-semibold text-[#000000] after:absolute after:inset-x-0 after:bottom-0 after:h-[2px] after:rounded-full after:bg-[#0080ff]"
                    : "font-medium text-[#636f7b] hover:text-[#0050ff]"
                }`}
              >
                Workflows
              </button>
            ) : (
              <Link
                href="/"
                aria-current={activeSection === "workflows" ? "page" : undefined}
                className="fm-focus relative inline-flex h-[52px] shrink-0 items-center whitespace-nowrap text-[13px] font-medium tracking-[-0.015em] text-[#636f7b] transition-colors hover:text-[#0050ff] sm:text-[14px]"
              >
                Workflows
              </Link>
            )}
            {onSelectSection ? (
              <button
                type="button"
                onClick={() => onSelectSection("runs")}
                aria-current={activeSection === "runs" ? "page" : undefined}
                className={`fm-focus relative inline-flex h-[52px] shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap text-[13px] tracking-[-0.015em] transition-colors sm:text-[14px] ${
                  activeSection === "runs"
                    ? "font-semibold text-[#000000] after:absolute after:inset-x-0 after:bottom-0 after:h-[2px] after:rounded-full after:bg-[#0080ff]"
                    : "font-medium text-[#636f7b] hover:text-[#0050ff]"
                }`}
              >
                <span>Запуски</span>
                {typeof runsCount === "number" && (
                  <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-1.5 py-0.5 text-[12px] font-semibold leading-none text-[#222222]">
                    {runsCount}
                  </span>
                )}
              </button>
            ) : (
              <Link
                href="/?section=runs"
                className="fm-focus relative inline-flex h-[52px] shrink-0 items-center gap-1.5 whitespace-nowrap text-[13px] font-medium tracking-[-0.015em] text-[#636f7b] transition-colors hover:text-[#0050ff] sm:text-[14px]"
              >
                <span>Запуски</span>
                {typeof runsCount === "number" && (
                  <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-1.5 py-0.5 text-[12px] font-semibold leading-none text-[#222222]">
                    {runsCount}
                  </span>
                )}
              </Link>
            )}
            {onSelectSection ? (
              <button
                type="button"
                onClick={() => onSelectSection("templates")}
                aria-current={activeSection === "templates" ? "page" : undefined}
                className={`fm-focus relative inline-flex h-[52px] shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap text-[13px] tracking-[-0.015em] transition-colors sm:text-[14px] ${
                  activeSection === "templates"
                    ? "font-semibold text-[#000000] after:absolute after:inset-x-0 after:bottom-0 after:h-[2px] after:rounded-full after:bg-[#0080ff]"
                    : "font-medium text-[#636f7b] hover:text-[#0050ff]"
                }`}
              >
                <span>Шаблоны</span>
                {typeof templatesCount === "number" && (
                  <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-1.5 py-0.5 text-[12px] font-semibold leading-none text-[#222222]">
                    {templatesCount}
                  </span>
                )}
              </button>
            ) : (
              <Link
                href="/?section=templates"
                aria-current={activeSection === "templates" ? "page" : undefined}
                className="fm-focus relative inline-flex h-[52px] shrink-0 items-center gap-1.5 whitespace-nowrap text-[13px] font-medium tracking-[-0.015em] text-[#636f7b] transition-colors hover:text-[#0050ff] sm:text-[14px]"
              >
                <span>Шаблоны</span>
                {typeof templatesCount === "number" && (
                  <span className="fm-tnum rounded-full border border-[#8c9baa]/55 px-1.5 py-0.5 text-[12px] font-semibold leading-none text-[#222222]">
                    {templatesCount}
                  </span>
                )}
              </Link>
            )}
          </nav>
        </div>

        <div className="relative" ref={menuRef}>
          <button
            type="button"
            onClick={() => setMenuOpen((v) => !v)}
            aria-label={`Меню пользователя (${displayName})`}
            aria-expanded={menuOpen}
            aria-haspopup="menu"
            className="fm-focus inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] bg-[#ffffff] text-[12px] font-semibold text-[#000000] transition-colors hover:border-[#0080ff] hover:text-[#0080ff]"
          >
            {initials}
          </button>

          {menuOpen && (
            <div
              role="menu"
              aria-label="Меню профиля"
              className="fm-float fixed right-4 top-[58px] z-40 w-[220px] rounded-[20px] border border-[#8c9baa]/60 p-2 sm:absolute sm:right-0 sm:top-[44px]"
            >
              <div className="border-b border-[#8c9baa]/35 px-3 py-2.5">
                <p className="truncate text-[13px] font-semibold text-[#000000]">{displayName}</p>
                <p className="fm-tnum mt-0.5 truncate text-[12px] text-[#636f7b]">
                  {user.short} · {displayEmail}
                </p>
              </div>
              <div className="mt-1 flex flex-col gap-0.5">
                <Link
                  href="/settings?tab=profile"
                  role="menuitem"
                  onClick={() => setMenuOpen(false)}
                  className="fm-focus flex min-h-[40px] w-full cursor-pointer items-center gap-2.5 rounded-full px-3 text-left text-[14px] font-medium text-[#222222] transition-colors hover:bg-[#c5e0fb]/35 hover:text-[#000000]"
                >
                  <User className="h-4 w-4 stroke-[1.5]" aria-hidden="true" />
                  Профиль
                </Link>
                <Link
                  href="/settings"
                  role="menuitem"
                  onClick={() => setMenuOpen(false)}
                  className="fm-focus flex min-h-[40px] w-full cursor-pointer items-center gap-2.5 rounded-full px-3 text-left text-[14px] font-medium text-[#222222] transition-colors hover:bg-[#c5e0fb]/35 hover:text-[#000000]"
                >
                  <Settings className="h-4 w-4 stroke-[1.5]" aria-hidden="true" />
                  Настройки
                </Link>
                <div className="my-1 border-t border-[#8c9baa]/35" />
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setMenuOpen(false);
                    clearSession();
                    setEmail("");
                    setRole("viewer");
                    onNavigateHint("Сессия завершена");
                  }}
                  className="fm-focus flex min-h-[40px] w-full cursor-pointer items-center gap-2.5 rounded-full px-3 text-left text-[14px] font-medium text-[#636f7b] transition-colors hover:bg-[#ffd6e0]/45 hover:text-[#000000]"
                >
                  <LogOut className="h-4 w-4 stroke-[1.5]" aria-hidden="true" />
                  Выйти
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

export function FlowmappWavyCreateButton({
  onClick,
  label = "Создать",
}: {
  onClick: () => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="fm-btn-signal fm-focus group relative inline-flex min-h-[44px] cursor-pointer items-center gap-2 pl-5 pr-6 text-[14px] font-semibold tracking-[-0.015em]"
    >
      <Plus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
      <span>{label}</span>
      <svg
        width="18"
        height="10"
        viewBox="0 0 18 10"
        fill="none"
        aria-hidden="true"
        className="ml-0.5 transition-transform duration-150 group-hover:translate-x-0.5"
      >
        <path
          d="M1 5C3.2 1.8 5.8 8.2 8.5 5C11.2 1.8 13.8 8.2 17 5"
          stroke="#ffffff"
          strokeWidth="1.6"
          strokeLinecap="round"
        />
      </svg>
    </button>
  );
}

export function FlowmappPastelTriggerIcon({ trigger }: { trigger: TriggerKind }) {
  const config =
    trigger === "Manual"
      ? { bg: "#fff3c4", Icon: Play }
      : trigger === "Webhook" || trigger === "CI API"
        ? { bg: "#c8f0d8", Icon: Webhook }
        : trigger === "Rerun"
          ? { bg: "#c5e0fb", Icon: RotateCcw }
          : { bg: "#ffe0c4", Icon: Clock };
  const Icon = config.Icon;
  return (
    <span
      aria-hidden="true"
      className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full"
      style={{ backgroundColor: config.bg }}
    >
      <Icon className="h-3.5 w-3.5 stroke-[1.6] text-[#000000]" />
    </span>
  );
}

export function FlowmappStepTriggerBadge({ trigger }: { trigger: TriggerKind }) {
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-[#8c9baa] bg-[#ffffff] px-3 py-1 text-[12px] leading-none">
      <span className="font-semibold uppercase tracking-[0.03em] text-[#000000]">TRIGGER</span>
      <span className="text-[#8c9baa]" aria-hidden="true">
        •
      </span>
      <span className="font-medium text-[#636f7b]">{trigger}</span>
    </span>
  );
}

export function FlowmappPolicyPill({ verdict }: { verdict: PolicyVerdict }) {
  if (verdict === "FAIL") {
    return (
      <span className="fm-tnum inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full bg-[#ffd6e0] px-3 py-1 text-[12px] font-semibold text-[#000000]">
        <ShieldAlert className="h-3.5 w-3.5 shrink-0 stroke-[1.6]" aria-hidden="true" />
        FAIL
      </span>
    );
  }
  if (verdict === "WARN") {
    return (
      <span className="fm-tnum inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full bg-[#fff3c4] px-3 py-1 text-[12px] font-semibold text-[#000000]">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0 stroke-[1.6]" aria-hidden="true" />
        WARN
      </span>
    );
  }
  if (verdict === "NONE") {
    return (
      <span className="fm-tnum inline-flex shrink-0 items-center whitespace-nowrap rounded-full border border-[#8c9baa]/70 px-3 py-1 text-[12px] font-medium text-[#636f7b]">
        нет gate
      </span>
    );
  }
  return (
    <span className="fm-tnum inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full bg-[#c8f0d8] px-3 py-1 text-[12px] font-semibold text-[#000000]">
      <ShieldCheck className="h-3.5 w-3.5 shrink-0 stroke-[1.6]" aria-hidden="true" />
      PASS
    </span>
  );
}

export function FlowmappRunStatusText({ status }: { status: RunStatus }) {
  const isRunning = status === "RUNNING";
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap text-[13px] font-medium text-[#636f7b]">
      <span
        aria-hidden="true"
        className={`h-2 w-2 shrink-0 rounded-full ${
          isRunning
            ? "bg-[#0080ff] animate-pulse"
            : status === "FAILED"
              ? "bg-[#dc2626]"
              : status === "SUCCEEDED"
                ? "bg-[#16a34a]"
                : status === "QUEUED" || status === "NONE"
                  ? "border border-[#8c9baa] bg-transparent"
                  : "bg-[#8c9baa]"
        }`}
      />
      <span>{RUN_STATUS_LABELS[status]}</span>
    </span>
  );
}

export function FlowmappSeverityPills({ crit, high }: { crit: number; high: number }) {
  return (
    <div className="fm-tnum inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap text-[12px] font-medium">
      <span
        className={`rounded-full px-2.5 py-0.5 ${
          crit > 0
            ? "bg-[#000000] text-[#ffffff]"
            : "border border-[#8c9baa]/60 bg-[#ffffff] text-[#636f7b]"
        }`}
      >
        {crit} CRIT
      </span>
      <span
        className={`rounded-full px-2.5 py-0.5 ${
          high > 0
            ? "bg-[#c5e0fb]/75 text-[#000000]"
            : "border border-[#8c9baa]/60 bg-[#ffffff] text-[#636f7b]"
        }`}
      >
        {high} HIGH
      </span>
    </div>
  );
}

export function FlowmappEmptyState({
  canEdit,
  templates = [],
  onUseTemplate,
  onOpenAi,
}: {
  canEdit: boolean;
  templates?: StarterTemplateRecord[];
  onUseTemplate: (tpl: StarterTemplateRecord) => void;
  onOpenAi: () => void;
}) {
  const displayTemplates = templates.slice(0, 4);

  return (
    <section
      aria-label="Пустое рабочее пространство"
      className="mx-auto max-w-[960px] py-10 sm:py-16"
    >
      <div className="text-center">
        <h2 className="text-[32px] font-bold leading-[1.06] tracking-[-0.04em] text-[#000000] sm:text-[44px]">
          Соберите первый Workflow безопасности
        </h2>
        <p className="mx-auto mt-3.5 max-w-[56ch] text-[16px] leading-[1.5] text-[#636f7b]">
          Начните с готового шаблона (включая аудит учебного проекта Repair Desk) или опишите
          сценарий словами — SecFlow соберёт граф для проверки.
        </p>

        {canEdit && (
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <button
              type="button"
              onClick={onOpenAi}
              className="fm-btn-signal fm-focus inline-flex min-h-[44px] cursor-pointer items-center gap-2 px-6 text-[14px] font-semibold"
            >
              <Sparkles className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
              Из текста (AI)
            </button>
          </div>
        )}
      </div>

      {displayTemplates.length > 0 ? (
        <div className="mt-10 grid gap-5 sm:grid-cols-2">
          {displayTemplates.map((tpl) => (
            <article
              key={tpl.id}
              className="flex flex-col justify-between rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-6"
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <FlowmappPastelTriggerIcon trigger={tpl.trigger} />
                    <FlowmappStepTriggerBadge trigger={tpl.trigger} />
                  </div>
                  {tpl.featured && (
                    <span className="rounded-full bg-[#c5e0fb] px-3 py-1 text-[11px] font-semibold text-[#000000]">
                      Repair Desk
                    </span>
                  )}
                </div>

                <h3 className="mt-4 text-[18px] font-semibold leading-[1.3] tracking-[-0.02em] text-[#000000]">
                  {tpl.name}
                </h3>
                <p className="mt-2 text-[14px] leading-[1.5] text-[#636f7b]">{tpl.description}</p>
              </div>

              <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-[#8c9baa]/35 pt-4">
                <div className="flex flex-wrap gap-1.5">
                  {tpl.tags.slice(0, 3).map((tag) => (
                    <span
                      key={tag}
                      className="rounded-full border border-[#8c9baa]/60 px-2.5 py-0.5 text-[11px] font-medium text-[#636f7b]"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
                {canEdit && (
                  <button
                    type="button"
                    onClick={() => onUseTemplate(tpl)}
                    className="fm-btn-ink fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-medium"
                  >
                    Использовать
                    <ArrowRight className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                  </button>
                )}
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="mt-10 rounded-[20px] border border-[#8c9baa]/60 bg-[#ffffff] p-6 text-center text-[14px] text-[#636f7b]">
          Шаблоны с сервера появятся здесь после загрузки каталога. Вы можете создать пустую доску
          или собрать workflow из текста.
        </div>
      )}
    </section>
  );
}

export function FlowmappAiModal({
  open,
  onClose,
  onSave,
}: {
  open: boolean;
  onClose: () => void;
  onSave: (preset: TextToWorkflowPreset, customName?: string) => void;
}) {
  const [selectedPresetId, setSelectedPresetId] = useState(AI_TEXT_PRESETS[0].id);
  const [promptText, setPromptText] = useState(AI_TEXT_PRESETS[0].prompt);
  const [workflowName, setWorkflowName] = useState(AI_TEXT_PRESETS[0].generatedName);

  const preset = AI_TEXT_PRESETS.find((p) => p.id === selectedPresetId) ?? AI_TEXT_PRESETS[0];

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const handleSelectPreset = (p: TextToWorkflowPreset) => {
    setSelectedPresetId(p.id);
    setPromptText(p.prompt);
    setWorkflowName(p.generatedName);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="fm-ai-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/25 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="fm-float max-h-[90dvh] w-full max-w-[740px] overflow-y-auto overscroll-contain rounded-[24px] border border-[#8c9baa] bg-[#ffffff] p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-[#ffd6e0] px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.04em] text-[#000000]">
              AI GENERATOR · TEXT → WORKFLOW
            </span>
            <h2
              id="fm-ai-modal-title"
              className="mt-3 text-[26px] font-bold leading-[1.15] tracking-[-0.03em] text-[#000000]"
            >
              Собрать Workflow из текста
            </h2>
            <p className="mt-1.5 text-[14px] leading-[1.45] text-[#636f7b]">
              Предпросмотр DAG с авто-раскладкой и подсветкой незаполненных параметров. Запуск
              доступен только после явного сохранения.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Закрыть окно генерации Workflow"
            className="fm-focus inline-flex h-10 w-10 shrink-0 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa] text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0080ff]"
          >
            <X className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
          </button>
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          {AI_TEXT_PRESETS.map((p) => {
            const active = p.id === selectedPresetId;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => handleSelectPreset(p)}
                className={`fm-focus min-h-[36px] cursor-pointer rounded-full px-3.5 text-[13px] font-medium transition-colors ${
                  active
                    ? "bg-[#000000] text-[#ffffff]"
                    : "border border-[#8c9baa] bg-[#ffffff] text-[#222222] hover:border-[#0080ff]"
                }`}
              >
                {p.label}
              </button>
            );
          })}
        </div>

        <div className="mt-4">
          <label
            htmlFor="fm-ai-prompt"
            className="block text-[13px] font-semibold text-[#000000]"
          >
            Сценарий проверки
          </label>
          <textarea
            id="fm-ai-prompt"
            rows={3}
            value={promptText}
            onChange={(e) => setPromptText(e.target.value)}
            className="fm-focus mt-2 w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 py-2.5 text-[15px] leading-[1.5] text-[#000000] placeholder:text-[#636f7b]"
          />
        </div>

        <div className="mt-5 rounded-[20px] border border-[#8c9baa] bg-[#ffffff] p-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="inline-flex items-center gap-2 text-[13px] font-semibold text-[#000000]">
              <GitBranch className="h-4 w-4 stroke-[1.7] text-[#0080ff]" aria-hidden="true" />
              Схема графа ({preset.nodes.length} нод)
            </span>
            <FlowmappStepTriggerBadge trigger={preset.trigger} />
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-y-2.5">
            {preset.nodes.map((node, index) => (
              <div key={node.id} className="flex items-center">
                <span className="fm-mono rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 py-1.5 text-[12px] text-[#000000]">
                  {node.label}
                </span>
                {index < preset.nodes.length - 1 && (
                  <svg
                    width="22"
                    height="12"
                    viewBox="0 0 22 12"
                    fill="none"
                    aria-hidden="true"
                    className="shrink-0"
                  >
                    <path
                      d="M1 6H19M15 2L19.5 6L15 10"
                      stroke="#0080ff"
                      strokeWidth="1.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </div>
            ))}
          </div>

          {preset.missingFields.length > 0 && (
            <div className="mt-4 rounded-[12px] border border-[#8c9baa]/60 bg-[#fff3c4]/55 p-4">
              <p className="text-[13px] font-semibold text-[#000000]">
                Требуется заполнить перед запуском (missingFields)
              </p>
              <ul className="mt-2 space-y-1.5">
                {preset.missingFields.map((mf) => (
                  <li
                    key={`${mf.node}-${mf.field}`}
                    className="flex flex-wrap items-baseline gap-2 text-[13px] text-[#222222]"
                  >
                    <span className="fm-mono text-[12px] font-medium text-[#000000]">
                      {mf.node}.{mf.field}
                    </span>
                    <span className="text-[#636f7b]">— {mf.hint}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="mt-4">
            <label htmlFor="fm-ai-name" className="block text-[13px] font-semibold text-[#000000]">
              Название нового Workflow
            </label>
            <input
              id="fm-ai-name"
              type="text"
              value={workflowName}
              onChange={(e) => setWorkflowName(e.target.value)}
              className="fm-focus mt-1.5 min-h-[44px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3.5 text-[15px] text-[#000000]"
            />
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="fm-btn-outline fm-focus min-h-[44px] cursor-pointer px-5 text-[14px] font-medium"
          >
            Отмена
          </button>
          <button
            type="button"
            onClick={() => onSave(preset, workflowName)}
            className="fm-btn-signal fm-focus inline-flex min-h-[44px] cursor-pointer items-center gap-2 px-6 text-[14px] font-semibold"
          >
            <Check className="h-4 w-4 stroke-[2]" aria-hidden="true" />
            Сохранить Workflow
          </button>
        </div>
      </div>
    </div>
  );
}

export function FlowmappNoticeBar({
  notice,
  onUndo,
  onDismiss,
}: {
  notice: FeedbackNotice | null;
  onUndo: () => void;
  onDismiss: () => void;
}) {
  if (!notice) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      className="fm-float fixed bottom-4 left-4 z-40 flex max-w-[min(460px,calc(100vw-2rem))] items-center gap-3 rounded-full border border-[#8c9baa] bg-[#ffffff] py-2.5 pl-5 pr-3 text-[13px] font-medium text-[#000000]"
      style={{ marginBottom: "env(safe-area-inset-bottom, 0px)" }}
    >
      <span className="h-2 w-2 shrink-0 rounded-full bg-[#0080ff]" aria-hidden="true" />
      <span className="min-w-0 flex-1">{notice.text}</span>
      {notice.undoWorkflow && (
        <button
          type="button"
          onClick={onUndo}
          className="fm-btn-ink fm-focus inline-flex min-h-[32px] shrink-0 cursor-pointer items-center gap-1 px-3 text-[12px] font-medium"
        >
          <RotateCcw className="h-3 w-3 stroke-[1.7]" aria-hidden="true" />
          Вернуть
        </button>
      )}
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Скрыть уведомление"
        className="fm-focus inline-flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-full text-[#636f7b] hover:text-[#000000]"
      >
        <X className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
      </button>
    </div>
  );
}
