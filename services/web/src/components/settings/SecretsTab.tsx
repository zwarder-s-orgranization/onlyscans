"use client";

import { useMemo, useState, type FormEvent } from "react";
import { Lock, Plus, Search, ShieldAlert, Trash2, X } from "lucide-react";
import type { UserRole } from "@/data/workflows-workspace-data";
import {
  SECRET_BINDING_OPTIONS,
  canManageSecrets,
  type SecretBindingScope,
  type SecretRecord,
} from "@/data/settings-data";

interface SecretsTabProps {
  role: UserRole;
  secrets: SecretRecord[];
  onCreateSecret: (payload: {
    name: string;
    value: string;
    binding: SecretBindingScope;
  }) => void;
  onDeleteSecret: (id: string) => void;
  onSwitchToProfile: () => void;
}

export function SecretsTab({
  role,
  secrets,
  onCreateSecret,
  onDeleteSecret,
  onSwitchToProfile,
}: SecretsTabProps) {
  const allowed = canManageSecrets(role);
  const [query, setQuery] = useState("");
  const [addingOpen, setAddingOpen] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const [nameInput, setNameInput] = useState("");
  const [valueInput, setValueInput] = useState("");
  const [bindingInput, setBindingInput] = useState<SecretBindingScope>("source.git");
  const [formError, setFormError] = useState<string | null>(null);

  const filteredSecrets = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return secrets;
    return secrets.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.binding.toLowerCase().includes(q) ||
        s.createdBy.toLowerCase().includes(q),
    );
  }, [secrets, query]);

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const normalizedName = nameInput.trim().toUpperCase().replace(/[^A-Z0-9_]/g, "_");
    if (normalizedName.length < 3) {
      setFormError("Укажите имя ключа (минимум 3 символа, например GIT_TOKEN).");
      return;
    }
    if (secrets.some((s) => s.name === normalizedName)) {
      setFormError(`Секрет ${normalizedName} уже существует. Удалите старый или выберите другое имя.`);
      return;
    }
    if (valueInput.trim().length < 4) {
      setFormError("Введите значение секрета (минимум 4 символа).");
      return;
    }
    onCreateSecret({
      name: normalizedName,
      value: valueInput.trim(),
      binding: bindingInput,
    });
    setNameInput("");
    setValueInput("");
    setFormError(null);
    setAddingOpen(false);
  };

  if (!allowed) {
    return (
      <div className="space-y-6">
        <div className="border-b border-[#8c9baa]/45 pb-5">
          <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
            Секреты
          </h1>
          <p className="mt-1 text-[14px] text-[#636f7b]">
            Хранилище токенов и ключей с политикой least-privilege.
          </p>
        </div>

        <div className="rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] p-6">
          <div className="flex items-start gap-3">
            <Lock className="mt-0.5 h-5 w-5 shrink-0 text-[#636f7b]" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-[15px] font-semibold text-[#000000]">
                Недостаточно прав для просмотра секретов
              </p>
              <p className="mt-1 text-[13.5px] text-[#636f7b]">
                По матрице RBAC (<span className="fm-mono">Query.secrets</span>) доступ к
                метаданным и управлению секретами разрешён только ролям{" "}
                <span className="fm-mono font-semibold text-[#222222]">editor</span> и{" "}
                <span className="fm-mono font-semibold text-[#222222]">owner</span>. Сейчас
                активна роль <span className="fm-mono font-semibold text-[#222222]">{role}</span>.
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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#8c9baa]/45 pb-5">
        <div className="min-w-0">
          <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
            Настройки: Секреты
          </h1>
          <p className="mt-1 text-[14px] text-[#636f7b]">
            Ключи для Git, LLM, уведомлений и MCP. Plaintext никогда не возвращается в UI, логи и
            отчёты.
          </p>
        </div>

        <button
          type="button"
          onClick={() => {
            setAddingOpen((v) => !v);
            setFormError(null);
          }}
          className="fm-btn-ink fm-focus inline-flex min-h-[40px] shrink-0 cursor-pointer items-center gap-1.5 px-4 text-[13.5px] font-semibold"
        >
          {addingOpen ? (
            <>
              <X className="h-4 w-4 stroke-[2]" aria-hidden="true" />
              Закрыть
            </>
          ) : (
            <>
              <Plus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
              Добавить секрет
            </>
          )}
        </button>
      </div>

      {addingOpen && (
        <form
          onSubmit={handleSubmit}
          className="rounded-[16px] border border-[#0080ff]/55 bg-[#f6faff]/65 p-5"
        >
          <h2 className="text-[15px] font-semibold text-[#000000]">Новый секрет</h2>
          <div className="mt-3 grid gap-3 sm:grid-cols-3">
            <div>
              <label htmlFor="sec-name" className="block text-[12px] font-medium text-[#636f7b]">
                Имя ключа (UPPER_SNAKE_CASE)
              </label>
              <input
                id="sec-name"
                type="text"
                placeholder="GITLAB_PAT"
                value={nameInput}
                onChange={(e) => setNameInput(e.target.value)}
                className="fm-focus fm-mono mt-1.5 w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              />
            </div>

            <div>
              <label htmlFor="sec-value" className="block text-[12px] font-medium text-[#636f7b]">
                Значение (скрывается после сохранения)
              </label>
              <input
                id="sec-value"
                type="password"
                autoComplete="off"
                placeholder="glpat-••••••••"
                value={valueInput}
                onChange={(e) => setValueInput(e.target.value)}
                className="fm-focus fm-mono mt-1.5 w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              />
            </div>

            <div>
              <label htmlFor="sec-binding" className="block text-[12px] font-medium text-[#636f7b]">
                Привязка (plugin_id)
              </label>
              <select
                id="sec-binding"
                value={bindingInput}
                onChange={(e) => setBindingInput(e.target.value as SecretBindingScope)}
                className="fm-focus fm-select mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              >
                {SECRET_BINDING_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {formError && (
            <p role="alert" className="mt-2.5 text-[13px] font-medium text-[#b42318]">
              {formError}
            </p>
          )}

          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-[#8c9baa]/35 pt-3.5">
            <p className="text-[12px] text-[#636f7b]">
              Анализаторы (<span className="fm-mono">scan.*</span>,{" "}
              <span className="fm-mono">sbom.*</span>) не получают доступ к секретам.
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setAddingOpen(false)}
                className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-medium"
              >
                Отмена
              </button>
              <button
                type="submit"
                className="fm-btn-signal fm-focus inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-semibold"
              >
                Сохранить секрет
              </button>
            </div>
          </div>
        </form>
      )}

      {/* Search bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative w-full sm:max-w-[340px]">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 stroke-[1.7] text-[#636f7b]"
            aria-hidden="true"
          />
          <input
            type="search"
            aria-label="Поиск секретов"
            placeholder="Поиск по названию секрета..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="fm-focus w-full rounded-full border border-[#8c9baa]/70 bg-[#ffffff] py-2 pl-9 pr-3 text-[16px] text-[#000000] placeholder:text-[#636f7b] sm:text-[13.5px]"
          />
        </div>
        <p className="fm-tnum text-[12.5px] text-[#636f7b]">
          Всего секретов: <span className="font-semibold text-[#000000]">{secrets.length}</span>
        </p>
      </div>

      {/* Table (Desktop) + Stacked List (Mobile) */}
      <div className="overflow-hidden rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff]">
        {filteredSecrets.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-[14px] font-semibold text-[#000000]">Секреты не найдены</p>
            <p className="mt-1 text-[13px] text-[#636f7b]">
              {query.trim()
                ? "Попробуйте изменить поисковый запрос."
                : "Добавьте первый ключ для Git, AI-провайдера или уведомлений."}
            </p>
          </div>
        ) : (
          <>
            <div className="divide-y divide-[#8c9baa]/35 sm:hidden">
              {filteredSecrets.map((sec) => {
                const confirming = confirmDeleteId === sec.id;
                return (
                  <div key={sec.id} className="p-4">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p
                          title={sec.name}
                          className="fm-mono truncate text-[13.5px] font-semibold text-[#000000]"
                        >
                          {sec.name}
                        </p>
                        <p className="fm-mono mt-1 text-[13px] text-[#222222]">{sec.maskedValue}</p>
                        <p className="fm-tnum mt-1 text-[12px] text-[#636f7b]">
                          Обновлён: {sec.updatedAt}
                        </p>
                      </div>
                      <div className="shrink-0">
                        {confirming ? (
                          <div className="flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => {
                                onDeleteSecret(sec.id);
                                setConfirmDeleteId(null);
                              }}
                              className="fm-focus min-h-[34px] cursor-pointer rounded-full bg-[#b42318] px-3 text-[12px] font-semibold text-[#ffffff]"
                            >
                              Да
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDeleteId(null)}
                              className="fm-btn-outline fm-focus min-h-[34px] cursor-pointer px-2.5 text-[12px] font-medium"
                            >
                              Нет
                            </button>
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={() => setConfirmDeleteId(sec.id)}
                            aria-label={`Удалить секрет ${sec.name}`}
                            className="fm-focus inline-flex min-h-[36px] cursor-pointer items-center gap-1.5 rounded-full border border-[#8c9baa]/60 px-3 text-[12.5px] font-medium text-[#636f7b]"
                          >
                            <Trash2 className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                            Удалить
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="hidden overflow-x-auto sm:block">
              <table className="w-full min-w-[480px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-[#8c9baa]/45 bg-[#f8fafc] text-[12px] font-semibold text-[#636f7b]">
                    <th className="px-4 py-3">Название</th>
                    <th className="px-4 py-3">Значение (masked)</th>
                    <th className="px-4 py-3">Обновлён</th>
                    <th className="px-4 py-3 text-right">Действия</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#8c9baa]/35 text-[13.5px]">
                  {filteredSecrets.map((sec) => {
                    const confirming = confirmDeleteId === sec.id;
                    return (
                      <tr key={sec.id} className="transition-colors hover:bg-[#f6faff]/65">
                        <td
                          title={sec.name}
                          className="fm-mono max-w-[200px] truncate px-4 py-3.5 font-semibold text-[#000000]"
                        >
                          {sec.name}
                        </td>
                        <td className="fm-mono whitespace-nowrap px-4 py-3.5 text-[#222222]">
                          {sec.maskedValue}
                        </td>
                        <td className="fm-tnum whitespace-nowrap px-4 py-3.5 text-[12.5px] text-[#636f7b]">
                          {sec.updatedAt}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3.5 text-right">
                          {confirming ? (
                            <div className="inline-flex items-center gap-1.5">
                              <button
                                type="button"
                                onClick={() => {
                                  onDeleteSecret(sec.id);
                                  setConfirmDeleteId(null);
                                }}
                                className="fm-focus min-h-[32px] cursor-pointer rounded-full bg-[#b42318] px-3 text-[12px] font-semibold text-[#ffffff] transition-colors hover:bg-[#912018]"
                              >
                                Подтвердить
                              </button>
                              <button
                                type="button"
                                onClick={() => setConfirmDeleteId(null)}
                                className="fm-btn-outline fm-focus min-h-[32px] cursor-pointer px-2.5 text-[12px] font-medium"
                              >
                                Отмена
                              </button>
                            </div>
                          ) : (
                            <button
                              type="button"
                              onClick={() => setConfirmDeleteId(sec.id)}
                              aria-label={`Удалить секрет ${sec.name}`}
                              className="fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-full px-3 text-[12.5px] font-medium text-[#636f7b] transition-colors hover:bg-[#ffd6e0]/50 hover:text-[#842029]"
                            >
                              <Trash2 className="h-3.5 w-3.5 stroke-[1.7]" aria-hidden="true" />
                              Удалить
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

      {/* Least-privilege invariant footer */}
      <div className="flex items-start gap-2.5 rounded-[14px] border border-[#8c9baa]/45 bg-[#f8fafc] px-4 py-3 text-[12.5px] text-[#636f7b]">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-[#0080ff]" aria-hidden="true" />
        <p>
          <span className="font-semibold text-[#222222]">Least-Privilege (SecretService):</span>{" "}
          plaintext разрешается только по подписанному{" "}
          <span className="fm-mono">task_lease_token</span> для узлов{" "}
          <span className="fm-mono">source.git</span>, <span className="fm-mono">ai.explain</span>,{" "}
          <span className="fm-mono">notify.*</span> и <span className="fm-mono">mcp.tool</span>.
        </p>
      </div>
    </div>
  );
}
