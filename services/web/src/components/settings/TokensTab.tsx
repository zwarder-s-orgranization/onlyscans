"use client";

import { useMemo, useState, type FormEvent } from "react";
import { Ban, Check, Copy, KeyRound, Lock, Plus, X } from "lucide-react";
import type { UserRole } from "@/data/workflows-workspace-data";
import {
  ALL_TOKEN_SCOPES,
  canManageOwnerOnly,
  type ScopedTokenRecord,
  type TokenScope,
} from "@/data/settings-data";

interface TokensTabProps {
  role: UserRole;
  tokens: ScopedTokenRecord[];
  workflows: Array<{ id: string; name: string }>;
  onCreateToken: (payload: {
    name: string;
    scopes: TokenScope[];
    workflowScope: string;
    expiresInDays: number | null;
  }) => string | Promise<string>;
  onRevokeToken: (id: string) => void;
  onSwitchToProfile: () => void;
  onNotice: (message: string) => void;
}

const EXPIRY_OPTIONS: Array<{ label: string; days: number | null }> = [
  { label: "7 дней", days: 7 },
  { label: "30 дней", days: 30 },
  { label: "90 дней", days: 90 },
  { label: "Бессрочно", days: null },
];

export function TokensTab({
  role,
  tokens,
  workflows,
  onCreateToken,
  onRevokeToken,
  onSwitchToProfile,
  onNotice,
}: TokensTabProps) {
  const allowed = canManageOwnerOnly(role);
  const [creatingOpen, setCreatingOpen] = useState(false);
  const [nameInput, setNameInput] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<TokenScope[]>(["ci:startRun", "ci:readRun"]);
  const [workflowScope, setWorkflowScope] = useState<string>("");
  const [expiryDays, setExpiryDays] = useState<number | null>(90);
  const [formError, setFormError] = useState<string | null>(null);

  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const workflowNameById = useMemo(
    () => new Map(workflows.map((wf) => [wf.id, wf.name])),
    [workflows],
  );

  const formatWorkflowScope = (scopeId: string): string => {
    if (!scopeId) return "Все workflow";
    return workflowNameById.get(scopeId) ?? scopeId;
  };

  const toggleScope = (scope: TokenScope) => {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((item) => item !== scope) : [...prev, scope],
    );
  };

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    void submitToken();
  };

  const submitToken = async () => {
    const cleanName = nameInput.trim();
    if (cleanName.length < 3) {
      setFormError("Укажите понятное название токена (от 3 символов).");
      return;
    }
    if (selectedScopes.length === 0) {
      setFormError("Выберите хотя бы один scope доступа.");
      return;
    }
    const rawToken = await Promise.resolve(
      onCreateToken({
        name: cleanName,
        scopes: selectedScopes,
        workflowScope,
        expiresInDays: expiryDays,
      }),
    );
    if (!rawToken) {
      setFormError("Сервер не вернул значение токена.");
      return;
    }
    setRevealedToken(rawToken);
    setCopied(false);
    setNameInput("");
    setWorkflowScope("");
    setFormError(null);
    setCreatingOpen(false);
  };

  const handleCopyToken = async () => {
    if (!revealedToken) return;
    try {
      await navigator.clipboard.writeText(revealedToken);
      setCopied(true);
      onNotice("Токен скопирован в буфер обмена");
    } catch {
      onNotice("Не удалось скопировать автоматически — выделите строку вручную");
    }
  };

  if (!allowed) {
    return (
      <div className="space-y-6">
        <div className="border-b border-[#8c9baa]/45 pb-5">
          <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
            Токены доступа (Scoped Tokens)
          </h1>
          <p className="mt-1 text-[14px] text-[#636f7b]">
            Ограниченные токены для CI/CD-пайплайнов и внешних MCP-клиентов.
          </p>
        </div>

        <div className="rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] p-6">
          <div className="flex items-start gap-3">
            <Lock className="mt-0.5 h-5 w-5 shrink-0 text-[#636f7b]" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-[15px] font-semibold text-[#000000]">
                Управление Scoped Tokens доступно только роли owner
              </p>
              <p className="mt-1 text-[13.5px] text-[#636f7b]">
                По матрице RBAC (<span className="fm-mono">Query.scopedTokens</span>,{" "}
                <span className="fm-mono">createScopedToken</span>,{" "}
                <span className="fm-mono">revokeScopedToken</span>) выпуск и отзыв токенов
                выполняет только <span className="fm-mono font-semibold text-[#222222]">owner</span>.
                Текущая роль: <span className="fm-mono font-semibold text-[#222222]">{role}</span>.
              </p>
              <button
                type="button"
                onClick={onSwitchToProfile}
                className="fm-btn-outline fm-focus mt-4 inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-medium"
              >
                Переключить роль в профиле
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const activeCount = tokens.filter((t) => t.status === "ACTIVE").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#8c9baa]/45 pb-5">
        <div className="min-w-0">
          <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
            Настройки: Токены
          </h1>
          <p className="mt-1 text-[14px] text-[#636f7b]">
            Выпуск и отзыв Scoped Tokens (<span className="fm-mono">ci:*</span>,{" "}
            <span className="fm-mono">mcp:*</span>) с минимальными правами на workflow.
          </p>
        </div>

        <button
          type="button"
          onClick={() => {
            setCreatingOpen((v) => !v);
            setFormError(null);
          }}
          className="fm-btn-ink fm-focus inline-flex min-h-[40px] shrink-0 cursor-pointer items-center gap-1.5 px-4 text-[13.5px] font-semibold"
        >
          {creatingOpen ? (
            <>
              <X className="h-4 w-4 stroke-[2]" aria-hidden="true" />
              Закрыть
            </>
          ) : (
            <>
              <Plus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
              Выпустить токен
            </>
          )}
        </button>
      </div>

      {/* One-time token reveal banner */}
      {revealedToken && (
        <div
          role="status"
          className="rounded-[16px] border border-[#0080ff] bg-[#f6faff] p-4"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <p className="text-[14px] font-semibold text-[#000000]">
                Скопируйте токен сейчас — повторно он показан не будет
              </p>
              <code className="fm-mono mt-2 block break-all rounded-[10px] border border-[#8c9baa]/60 bg-[#ffffff] px-3 py-2 text-[13px] font-semibold text-[#000000]">
                {revealedToken}
              </code>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyToken}
                className="fm-btn-signal fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
              >
                {copied ? (
                  <>
                    <Check className="h-4 w-4" aria-hidden="true" />
                    Скопировано
                  </>
                ) : (
                  <>
                    <Copy className="h-4 w-4" aria-hidden="true" />
                    Скопировать
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => setRevealedToken(null)}
                aria-label="Скрыть токен"
                className="fm-btn-outline fm-focus inline-flex h-[38px] w-[38px] cursor-pointer items-center justify-center"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          </div>
        </div>
      )}

      {creatingOpen && (
        <form
          onSubmit={handleSubmit}
          className="rounded-[16px] border border-[#0080ff]/55 bg-[#f6faff]/65 p-5"
        >
          <h2 className="text-[15px] font-semibold text-[#000000]">Новый Scoped Token</h2>

          <div className="mt-3 grid gap-3 sm:grid-cols-3">
            <div>
              <label htmlFor="tok-name" className="block text-[12px] font-medium text-[#636f7b]">
                Название токена
              </label>
              <input
                id="tok-name"
                type="text"
                placeholder="GitHub Actions — Main Gate"
                value={nameInput}
                onChange={(e) => setNameInput(e.target.value)}
                className="fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              />
            </div>

            <div>
              <label htmlFor="tok-wf" className="block text-[12px] font-medium text-[#636f7b]">
                Область workflow
              </label>
              <select
                id="tok-wf"
                value={workflowScope}
                onChange={(e) => setWorkflowScope(e.target.value)}
                className="fm-focus fm-select mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              >
                <option value="">Все workflow</option>
                {workflows.map((wf) => (
                  <option key={wf.id} value={wf.id}>
                    {wf.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="tok-exp" className="block text-[12px] font-medium text-[#636f7b]">
                Срок действия
              </label>
              <select
                id="tok-exp"
                value={expiryDays === null ? "never" : String(expiryDays)}
                onChange={(e) =>
                  setExpiryDays(e.target.value === "never" ? null : Number(e.target.value))
                }
                className="fm-focus fm-select mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              >
                {EXPIRY_OPTIONS.map((opt) => (
                  <option key={opt.label} value={opt.days === null ? "never" : String(opt.days)}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <fieldset className="mt-4">
            <legend className="text-[12px] font-medium text-[#636f7b]">
              Разрешённые скоупы
            </legend>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              {ALL_TOKEN_SCOPES.map((item) => {
                const checked = selectedScopes.includes(item.scope);
                return (
                  <label
                    key={item.scope}
                    className={`flex cursor-pointer items-start gap-2.5 rounded-[12px] border px-3 py-2.5 transition-colors ${
                      checked
                        ? "border-[#0080ff] bg-[#ffffff]"
                        : "border-[#8c9baa]/50 bg-[#ffffff]/70 hover:border-[#8c9baa]"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleScope(item.scope)}
                      className="mt-0.5 h-4 w-4 accent-[#0080ff]"
                    />
                    <span className="min-w-0">
                      <span className="fm-mono block text-[12.5px] font-semibold text-[#000000]">
                        {item.scope}
                      </span>
                      <span className="block text-[12px] text-[#636f7b]">{item.description}</span>
                    </span>
                  </label>
                );
              })}
            </div>
          </fieldset>

          {formError && (
            <p role="alert" className="mt-2.5 text-[13px] font-medium text-[#b42318]">
              {formError}
            </p>
          )}

          <div className="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-[#8c9baa]/35 pt-3.5">
            <button
              type="button"
              onClick={() => setCreatingOpen(false)}
              className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-medium"
            >
              Отмена
            </button>
            <button
              type="submit"
              className="fm-btn-signal fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
            >
              <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
              Сгенерировать токен
            </button>
          </div>
        </form>
      )}

      <div className="flex items-center justify-between text-[12.5px] text-[#636f7b]">
        <span className="fm-tnum">
          Активных токенов: <strong className="text-[#000000]">{activeCount}</strong> из{" "}
          {tokens.length}
        </span>
      </div>

      <div className="overflow-hidden rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff]">
        {tokens.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-[14px] font-semibold text-[#000000]">Токенов пока нет</p>
            <p className="mt-1 text-[13px] text-[#636f7b]">
              Выпустите Scoped Token для запуска SecFlow из GitLab CI, GitHub Actions или IDE.
            </p>
          </div>
        ) : (
          <>
            <div className="divide-y divide-[#8c9baa]/35 sm:hidden">
              {tokens.map((tok) => {
                const revoked = tok.status === "REVOKED";
                const scopeLabel = formatWorkflowScope(tok.workflowScope);
                return (
                  <div
                    key={tok.id}
                    className={`p-4 ${revoked ? "bg-[#f8fafc]/60 text-[#636f7b]" : ""}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p
                          title={tok.name}
                          className={`truncate text-[14px] font-semibold ${
                            revoked ? "text-[#636f7b] line-through" : "text-[#000000]"
                          }`}
                        >
                          {tok.name}
                        </p>
                        <p className="fm-mono mt-0.5 text-[12px] text-[#636f7b]">{tok.prefix}</p>
                      </div>
                      <span
                        className={`shrink-0 rounded-full px-2.5 py-0.5 text-[12px] font-semibold ${
                          revoked
                            ? "bg-[#ffd6e0]/70 text-[#842029]"
                            : "bg-[#c8f0d8]/75 text-[#0f5132]"
                        }`}
                      >
                        {revoked ? "Отозван" : "Активен"}
                      </span>
                    </div>

                    <div className="mt-2.5 flex flex-wrap gap-1.5">
                      {tok.scopes.map((sc) => (
                        <span
                          key={sc}
                          className="fm-mono rounded-full border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 py-0.5 text-[12px] text-[#222222]"
                        >
                          {sc}
                        </span>
                      ))}
                    </div>

                    <p className="mt-2 text-[12.5px] text-[#222222]">{scopeLabel}</p>

                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-[#8c9baa]/25 pt-2.5">
                      <span className="fm-tnum text-[12px] text-[#636f7b]">
                        до {tok.expiresAt} · {tok.lastUsedAt}
                      </span>
                      {!revoked && (
                        <button
                          type="button"
                          onClick={() => onRevokeToken(tok.id)}
                          className="fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-full border border-[#8c9baa]/60 px-3 text-[12.5px] font-medium text-[#636f7b]"
                        >
                          <Ban className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                          Отозвать
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="hidden overflow-x-auto sm:block">
              <table className="w-full min-w-[680px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-[#8c9baa]/45 bg-[#f8fafc] text-[12px] font-semibold text-[#636f7b]">
                    <th className="px-4 py-3">Токен</th>
                    <th className="px-4 py-3">Скоупы</th>
                    <th className="px-4 py-3">Workflow</th>
                    <th className="px-4 py-3">Истекает / Статус</th>
                    <th className="px-4 py-3 text-right">Действия</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#8c9baa]/35 text-[13px]">
                  {tokens.map((tok) => {
                    const revoked = tok.status === "REVOKED";
                    const scopeLabel = formatWorkflowScope(tok.workflowScope);
                    return (
                      <tr
                        key={tok.id}
                        className={`transition-colors ${
                          revoked ? "bg-[#f8fafc]/60 text-[#636f7b]" : "hover:bg-[#f6faff]/65"
                        }`}
                      >
                        <td className="px-4 py-3.5">
                          <p
                            title={tok.name}
                            className={`max-w-[200px] truncate font-semibold ${
                              revoked ? "text-[#636f7b] line-through" : "text-[#000000]"
                            }`}
                          >
                            {tok.name}
                          </p>
                          <p className="fm-mono mt-0.5 text-[12px] text-[#636f7b]">{tok.prefix}</p>
                        </td>
                        <td className="px-4 py-3.5">
                          <div className="flex flex-wrap gap-1">
                            {tok.scopes.map((sc) => (
                              <span
                                key={sc}
                                className="fm-mono rounded-full border border-[#8c9baa]/55 bg-[#ffffff] px-2 py-0.5 text-[12px] text-[#222222]"
                              >
                                {sc}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td
                          title={scopeLabel}
                          className="max-w-[180px] truncate px-4 py-3.5 text-[#222222]"
                        >
                          {scopeLabel}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3.5">
                          <span
                            className={`inline-flex rounded-full px-2 py-0.5 text-[12px] font-semibold ${
                              revoked
                                ? "bg-[#ffd6e0]/70 text-[#842029]"
                                : "bg-[#c8f0d8]/75 text-[#0f5132]"
                            }`}
                          >
                            {revoked ? "Отозван" : "Активен"}
                          </span>
                          <p className="fm-tnum mt-1 text-[12px] text-[#636f7b]">
                            до {tok.expiresAt} · {tok.lastUsedAt}
                          </p>
                        </td>
                        <td className="whitespace-nowrap px-4 py-3.5 text-right">
                          {revoked ? (
                            <span className="text-[12px] text-[#636f7b]">Недействителен</span>
                          ) : (
                            <button
                              type="button"
                              onClick={() => onRevokeToken(tok.id)}
                              className="fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12.5px] font-medium text-[#636f7b] transition-colors hover:bg-[#ffd6e0]/50 hover:text-[#842029]"
                            >
                              <Ban className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                              Отозвать
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
