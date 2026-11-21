"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { CheckCircle2, Cpu, Loader2, ShieldCheck, Sparkles } from "lucide-react";
import type { UserRole } from "@/data/workflows-workspace-data";
import {
  canManageSecrets,
  type AiAuditLogRecord,
  type AiProviderConfig,
  type AiProviderMode,
  type SecretRecord,
} from "@/data/settings-data";

interface AiProviderTabProps {
  role: UserRole;
  config: AiProviderConfig;
  secrets: SecretRecord[];
  auditLogs: AiAuditLogRecord[];
  onSaveConfig: (next: AiProviderConfig) => void;
  onTestConnection: (candidate: AiProviderConfig) => Promise<void>;
}

const MODE_OPTIONS: Array<{ id: AiProviderMode; label: string; hint: string }> = [
  {
    id: "openai-compatible",
    label: "OpenAI-compatible API",
    hint: "Корпоративный шлюз или внешний провайдер",
  },
  {
    id: "local-ollama",
    label: "Локальный Ollama / vLLM",
    hint: "Запуск внутри контура без выхода во внешнюю сеть",
  },
  {
    id: "deterministic-only",
    label: "Deterministic-only (без LLM)",
    hint: "Шаблонные объяснения, анализаторы работают штатно",
  },
];

export function AiProviderTab({
  role,
  config,
  secrets,
  auditLogs,
  onSaveConfig,
  onTestConnection,
}: AiProviderTabProps) {
  const canEdit = canManageSecrets(role);
  const [draft, setDraft] = useState<AiProviderConfig>(config);
  const [testing, setTesting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    setDraft(config);
  }, [config]);

  const totalStrippedHallucinatedCve = useMemo(
    () => auditLogs.reduce((sum, log) => sum + (Number(log.hallucinatedCve) || 0), 0),
    [auditLogs],
  );

  const isDeterministic = draft.mode === "deterministic-only";

  const handleSave = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canEdit) return;
    if (!isDeterministic && !draft.endpointUrl.trim().startsWith("http")) {
      setFormError("Укажите корректный URL эндпоинта (http:// или https://).");
      return;
    }
    if (!isDeterministic && draft.model.trim().length < 2) {
      setFormError("Укажите идентификатор модели LLM.");
      return;
    }
    setFormError(null);
    onSaveConfig({
      ...draft,
      endpointUrl: draft.endpointUrl.trim(),
      model: draft.model.trim(),
      status: isDeterministic ? "DISABLED" : draft.status === "DISABLED" ? "HEALTHY" : draft.status,
    });
  };

  const handleTest = async () => {
    if (testing) return;
    setFormError(null);
    setTesting(true);
    try {
      await onTestConnection(draft);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-3 border-b border-[#8c9baa]/45 pb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
            Настройки: AI-провайдер
          </h1>
          <p className="mt-1 max-w-[62ch] text-[14px] text-[#636f7b]">
            Контур <span className="fm-mono">ai-service</span> используется только для объяснений{" "}
            <span className="fm-mono">ai.explain</span> и генерации графов — поиск уязвимостей
            остаётся строго детерминированным.
          </p>
        </div>

        <span
          className={`fm-tnum inline-flex shrink-0 items-center gap-1.5 self-start whitespace-nowrap rounded-full px-3 py-1.5 text-[12px] font-semibold ${
            config.status === "HEALTHY"
              ? "bg-[#c8f0d8]/75 text-[#0f5132]"
              : config.status === "DISABLED"
                ? "bg-[#e9ecef] text-[#495057]"
                : "bg-[#fff3c4] text-[#664d03]"
          }`}
        >
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
          {config.status === "HEALTHY"
            ? config.lastLatencyMs > 0
              ? `Подключён · ${config.lastLatencyMs} мс`
              : "Подключён"
            : config.status === "DISABLED"
              ? "Deterministic fallback"
              : "Требуется проверка"}
        </span>
      </div>

      {/* Config form (flat surface — no nested cards) */}
      <form onSubmit={handleSave} className="space-y-5 border-b border-[#8c9baa]/45 pb-7">
        <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-[#000000]">
          Параметры подключения
        </h2>

        <fieldset disabled={!canEdit}>
          <legend className="text-[12px] font-medium text-[#636f7b]">Режим работы LLM</legend>
          <div className="mt-2 grid gap-2.5 sm:grid-cols-3">
            {MODE_OPTIONS.map((opt) => {
              const active = draft.mode === opt.id;
              return (
                <label
                  key={opt.id}
                  className={`flex cursor-pointer flex-col rounded-[12px] border p-3.5 transition-colors ${
                    active
                      ? "border-[#0080ff] bg-[#f6faff]"
                      : "border-[#8c9baa]/50 bg-[#ffffff] hover:border-[#8c9baa]"
                  } ${!canEdit ? "cursor-not-allowed opacity-70" : ""}`}
                >
                  <span className="flex items-center gap-2">
                    <input
                      type="radio"
                      name="ai-mode"
                      checked={active}
                      onChange={() => setDraft((prev) => ({ ...prev, mode: opt.id }))}
                      className="h-4 w-4 accent-[#0080ff]"
                    />
                    <span className="text-[13px] font-semibold text-[#000000]">{opt.label}</span>
                  </span>
                  <span className="mt-1 pl-6 text-[12px] text-[#636f7b]">{opt.hint}</span>
                </label>
              );
            })}
          </div>
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="ai-endpoint" className="block text-[12px] font-medium text-[#636f7b]">
              Endpoint URL
            </label>
            <input
              id="ai-endpoint"
              type="url"
              disabled={!canEdit || isDeterministic}
              value={draft.endpointUrl}
              onChange={(e) => setDraft((prev) => ({ ...prev, endpointUrl: e.target.value }))}
              className="fm-focus fm-mono mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] disabled:bg-[#f8fafc] disabled:text-[#636f7b] sm:text-[13.5px]"
            />
          </div>

          <div>
            <label htmlFor="ai-model" className="block text-[12px] font-medium text-[#636f7b]">
              Модель
            </label>
            <input
              id="ai-model"
              type="text"
              disabled={!canEdit || isDeterministic}
              value={draft.model}
              onChange={(e) => setDraft((prev) => ({ ...prev, model: e.target.value }))}
              className="fm-focus fm-mono mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] disabled:bg-[#f8fafc] disabled:text-[#636f7b] sm:text-[13.5px]"
            />
          </div>

          <div>
            <label htmlFor="ai-secret" className="block text-[12px] font-medium text-[#636f7b]">
              Секрет (secret_ref)
            </label>
            <select
              id="ai-secret"
              disabled={!canEdit || isDeterministic}
              value={draft.secretRef}
              onChange={(e) => setDraft((prev) => ({ ...prev, secretRef: e.target.value }))}
              className="fm-focus fm-mono fm-select mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] disabled:bg-[#f8fafc] disabled:text-[#636f7b] sm:text-[13.5px]"
            >
              <option value="">Без ключа (локальный инстанс)</option>
              {secrets.map((sec) => (
                <option key={sec.id} value={sec.id}>
                  {sec.name} ({sec.maskedValue})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="ai-timeout" className="block text-[12px] font-medium text-[#636f7b]">
              Таймаут запроса (сек)
            </label>
            <input
              id="ai-timeout"
              type="number"
              min={5}
              max={120}
              disabled={!canEdit || isDeterministic}
              value={draft.timeoutSec}
              onChange={(e) =>
                setDraft((prev) => ({
                  ...prev,
                  timeoutSec: Math.max(5, Math.min(120, Number(e.target.value) || 25)),
                }))
              }
              className="fm-focus fm-tnum mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] disabled:bg-[#f8fafc] disabled:text-[#636f7b] sm:text-[13.5px]"
            />
          </div>
        </div>

        {/* Toggles */}
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex items-start justify-between gap-3 rounded-[12px] border border-dashed border-[#8c9baa]/70 bg-[#f8fafc] p-3.5">
            <div className="min-w-0">
              <p className="flex items-center gap-1.5 text-[13.5px] font-semibold text-[#000000]">
                <ShieldCheck className="h-4 w-4 text-[#0080ff]" aria-hidden="true" />
                Жёсткий Grounding (обязательно)
              </p>
              <p className="mt-0.5 text-[12px] text-[#636f7b]">
                Верификация каждого findingId и запрет выдуманных CVE.
              </p>
            </div>
            <input
              type="checkbox"
              aria-label="Жёсткий Grounding"
              checked={draft.strictGrounding}
              disabled
              className="mt-0.5 h-4 w-4 accent-[#0080ff]"
            />
          </div>

          <label className="flex cursor-pointer items-start justify-between gap-3 rounded-[12px] border border-[#8c9baa]/55 bg-[#ffffff] p-3.5">
            <span className="min-w-0">
              <span className="flex items-center gap-1.5 text-[13.5px] font-semibold text-[#000000]">
                <Sparkles className="h-4 w-4 text-[#0080ff]" aria-hidden="true" />
                Text-to-Workflow (GenerateWorkflow)
              </span>
              <span className="mt-0.5 block text-[12px] text-[#636f7b]">
                Разрешить сборку черновика графа из текстового описания.
              </span>
            </span>
            <input
              type="checkbox"
              disabled={!canEdit || isDeterministic}
              checked={draft.allowTextToWorkflow && !isDeterministic}
              onChange={(e) =>
                setDraft((prev) => ({ ...prev, allowTextToWorkflow: e.target.checked }))
              }
              className="mt-0.5 h-4 w-4 accent-[#0080ff]"
            />
          </label>
        </div>

        {formError && (
          <p role="alert" className="text-[13px] font-medium text-[#b42318]">
            {formError}
          </p>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <p className="fm-tnum text-[12px] text-[#636f7b]">
            Последняя проверка: {config.lastCheckedAt}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={testing || isDeterministic}
              onClick={handleTest}
              className="fm-btn-outline fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-medium disabled:cursor-not-allowed disabled:opacity-55"
            >
              {testing ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  Проверка…
                </>
              ) : (
                <>
                  <Cpu className="h-4 w-4 stroke-[1.6]" aria-hidden="true" />
                  Тест соединения
                </>
              )}
            </button>

            <button
              type="submit"
              disabled={!canEdit}
              className="fm-btn-ink fm-focus inline-flex min-h-[40px] cursor-pointer items-center px-5 text-[13px] font-semibold disabled:cursor-not-allowed disabled:opacity-50"
            >
              Сохранить
            </button>
          </div>
        </div>
      </form>

      {/* AI Audit Logs */}
      <section aria-labelledby="ai-audit-heading">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2
            id="ai-audit-heading"
            className="text-[16px] font-semibold tracking-[-0.02em] text-[#000000]"
          >
            Журнал AI Audit (<span className="fm-mono text-[14px]">aiAuditLogs</span>)
          </h2>
          <span className="fm-tnum text-[12.5px] text-[#636f7b]">
            Отфильтровано выдуманных CVE:{" "}
            <strong
              className={
                totalStrippedHallucinatedCve === 0 ? "text-[#0f5132]" : "text-[#664d03]"
              }
            >
              {totalStrippedHallucinatedCve}
            </strong>
          </span>
        </div>

        <div className="mt-3 overflow-x-auto rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff]">
          <table className="w-full min-w-[640px] border-collapse text-left">
            <thead>
              <tr className="border-b border-[#8c9baa]/45 bg-[#f8fafc] text-[12px] font-semibold text-[#636f7b]">
                <th className="px-4 py-3">Время</th>
                <th className="px-4 py-3">Операция / Run</th>
                <th className="px-4 py-3">Модель</th>
                <th className="px-4 py-3">Grounding</th>
                <th className="px-4 py-3 text-right">Задержка</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#8c9baa]/35 text-[13px]">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-[#636f7b]">
                    Записей AI Audit пока нет.
                  </td>
                </tr>
              ) : (
                auditLogs.map((log) => (
                  <tr key={log.id} className="transition-colors hover:bg-[#f6faff]/65">
                    <td className="fm-tnum whitespace-nowrap px-4 py-3 text-[#636f7b]">
                      {log.timestamp}
                    </td>
                    <td className="px-4 py-3">
                      <span className="fm-mono font-semibold text-[#000000]">{log.operation}</span>
                      <span className="fm-mono ml-2 text-[12px] text-[#636f7b]">{log.runId}</span>
                    </td>
                    <td className="fm-mono whitespace-nowrap px-4 py-3 text-[#222222]">
                      {log.model}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex whitespace-nowrap rounded-full px-2.5 py-0.5 text-[12px] font-semibold ${
                          log.status === "OK"
                            ? "bg-[#c8f0d8]/75 text-[#0f5132]"
                            : "bg-[#fff3c4]/85 text-[#664d03]"
                        }`}
                      >
                        {log.findingsGrounded} · {log.hallucinatedCve} CVE-галлюцинаций
                      </span>
                    </td>
                    <td className="fm-tnum whitespace-nowrap px-4 py-3 text-right text-[#222222]">
                      {log.latencyMs} мс
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
