"use client";

import { useMemo, useState, type FormEvent } from "react";
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  CircleDashed,
  Loader2,
  Plug,
  Plus,
  RefreshCw,
  Trash2,
  Wrench,
  X,
} from "lucide-react";
import type { UserRole } from "@/data/workflows-workspace-data";
import {
  canManageOwnerOnly,
  type McpConnectionRecord,
  type SecretRecord,
} from "@/data/settings-data";

interface McpServersTabProps {
  role: UserRole;
  connections: McpConnectionRecord[];
  secrets: SecretRecord[];
  onRegisterConnection: (payload: {
    name: string;
    transport: "Streamable HTTP" | "SSE";
    endpointUrl: string;
    authSecretRef: string;
  }) => void;
  onTestConnection: (id: string) => Promise<void>;
  onExpandTools?: (connectionId: string) => Promise<void>;
  onDeleteConnection: (id: string) => void;
}

export function McpServersTab({
  role,
  connections,
  secrets,
  onRegisterConnection,
  onTestConnection,
  onExpandTools,
  onDeleteConnection,
}: McpServersTabProps) {
  const canManage = canManageOwnerOnly(role);
  const [addingOpen, setAddingOpen] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [loadingToolsId, setLoadingToolsId] = useState<string | null>(null);

  const [nameInput, setNameInput] = useState("");
  const [transportInput, setTransportInput] = useState<"Streamable HTTP" | "SSE">(
    "Streamable HTTP",
  );
  const [urlInput, setUrlInput] = useState("");
  const [secretRefInput, setSecretRefInput] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const secretNameById = useMemo(
    () => new Map(secrets.map((sec) => [sec.id, sec.name])),
    [secrets],
  );

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canManage) return;
    const cleanName = nameInput.trim();
    const cleanUrl = urlInput.trim();
    if (cleanName.length < 3) {
      setFormError("Укажите название MCP-подключения (минимум 3 символа).");
      return;
    }
    if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
      setFormError("Укажите URL подключения (http:// или https://).");
      return;
    }
    onRegisterConnection({
      name: cleanName,
      transport: transportInput,
      endpointUrl: cleanUrl,
      authSecretRef: secretRefInput,
    });
    setNameInput("");
    setUrlInput("");
    setSecretRefInput("");
    setFormError(null);
    setAddingOpen(false);
  };

  const handleRunTest = async (id: string) => {
    if (!canManage || testingId) return;
    setTestingId(id);
    try {
      await onTestConnection(id);
    } finally {
      setTestingId(null);
    }
  };

  const handleToggleExpand = (conn: McpConnectionRecord) => {
    const nextExpanded = expandedId === conn.id ? null : conn.id;
    setExpandedId(nextExpanded);
    if (nextExpanded && onExpandTools && conn.tools.length === 0) {
      setLoadingToolsId(conn.id);
      void Promise.resolve(onExpandTools(conn.id)).finally(() => {
        setLoadingToolsId((curr) => (curr === conn.id ? null : curr));
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 border-b border-[#8c9baa]/45 pb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
            Настройки: MCP-подключения
          </h1>
          <p className="mt-1 max-w-[62ch] text-[14px] text-[#636f7b]">
            Внешние Outbound MCP-подключения для узла <span className="fm-mono">mcp.tool</span> и
            автообнаружение <span className="fm-mono">tools/list</span> через{" "}
            <span className="fm-mono">mcp-bridge</span>.
          </p>
        </div>

        {canManage ? (
          <button
            type="button"
            onClick={() => {
              setAddingOpen((v) => !v);
              setFormError(null);
            }}
            className="fm-btn-ink fm-focus inline-flex min-h-[40px] shrink-0 cursor-pointer items-center gap-1.5 self-start whitespace-nowrap px-4 text-[13.5px] font-semibold"
          >
            {addingOpen ? (
              <>
                <X className="h-4 w-4 stroke-[2]" aria-hidden="true" />
                Закрыть
              </>
            ) : (
              <>
                <Plus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
                Подключить MCP
              </>
            )}
          </button>
        ) : (
          <span className="rounded-full border border-[#8c9baa]/55 bg-[#f8fafc] px-3 py-1.5 text-[12px] font-medium text-[#636f7b]">
            Режим чтения (изменение доступно owner)
          </span>
        )}
      </div>

      {addingOpen && canManage && (
        <form
          onSubmit={handleSubmit}
          className="rounded-[16px] border border-[#0080ff]/55 bg-[#f6faff]/65 p-5"
        >
          <h2 className="text-[15px] font-semibold text-[#000000]">Новое MCP-подключение</h2>

          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="mcp-name" className="block text-[12px] font-medium text-[#636f7b]">
                Название подключения
              </label>
              <input
                id="mcp-name"
                type="text"
                placeholder="jira-security-mcp"
                value={nameInput}
                onChange={(e) => setNameInput(e.target.value)}
                className="fm-focus fm-mono mt-1.5 w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              />
            </div>

            <div>
              <label
                htmlFor="mcp-transport"
                className="block text-[12px] font-medium text-[#636f7b]"
              >
                Транспорт
              </label>
              <select
                id="mcp-transport"
                value={transportInput}
                onChange={(e) =>
                  setTransportInput(e.target.value as "Streamable HTTP" | "SSE")
                }
                className="fm-focus fm-select mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              >
                <option value="Streamable HTTP">Streamable HTTP</option>
                <option value="SSE">SSE</option>
              </select>
            </div>

            <div>
              <label htmlFor="mcp-url" className="block text-[12px] font-medium text-[#636f7b]">
                Endpoint URL
              </label>
              <input
                id="mcp-url"
                type="url"
                placeholder="https://mcp.internal.local/mcp"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="fm-focus fm-mono mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              />
            </div>

            <div>
              <label htmlFor="mcp-secret" className="block text-[12px] font-medium text-[#636f7b]">
                Авторизация (auth_secret_ref)
              </label>
              <select
                id="mcp-secret"
                value={secretRefInput}
                onChange={(e) => setSecretRefInput(e.target.value)}
                className="fm-focus fm-mono fm-select mt-1.5 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 py-2 text-[16px] text-[#000000] sm:text-[13.5px]"
              >
                <option value="">Без авторизации</option>
                {secrets.map((sec) => (
                  <option key={sec.id} value={sec.id}>
                    {sec.name} ({sec.maskedValue})
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

          <div className="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-[#8c9baa]/35 pt-3.5">
            <button
              type="button"
              onClick={() => setAddingOpen(false)}
              className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center px-4 text-[13px] font-medium"
            >
              Отмена
            </button>
            <button
              type="submit"
              className="fm-btn-signal fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
            >
              <Plug className="h-3.5 w-3.5" aria-hidden="true" />
              Зарегистрировать
            </button>
          </div>
        </form>
      )}

      {/* Connections list */}
      {connections.length === 0 ? (
        <div className="rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] px-6 py-10 text-center">
          <p className="text-[14px] font-semibold text-[#000000]">
            Нет зарегистрированных MCP-подключений
          </p>
          <p className="mt-1 text-[13px] text-[#636f7b]">
            Зарегистрируйте внешнее MCP-подключение, чтобы вызывать его инструменты из узла{" "}
            <span className="fm-mono">mcp.tool</span>.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {connections.map((conn) => {
            const expanded = expandedId === conn.id;
            const isTesting = testingId === conn.id;
            const isLoadingTools = loadingToolsId === conn.id;
            const secretLabel = conn.authSecretRef
              ? secretNameById.get(conn.authSecretRef) ?? conn.authSecretRef
              : "не требуется";

            return (
              <div
                key={conn.id}
                className="overflow-hidden rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff]"
              >
                <div className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="fm-mono text-[14.5px] font-semibold text-[#000000]">
                        {conn.name}
                      </span>
                      <span className="rounded-full border border-[#8c9baa]/55 px-2 py-0.5 text-[12px] font-medium text-[#222222]">
                        {conn.transport}
                      </span>
                      <span
                        className={`fm-tnum inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[12px] font-semibold ${
                          conn.status === "CONNECTED"
                            ? "bg-[#c8f0d8]/75 text-[#0f5132]"
                            : conn.status === "UNTESTED"
                              ? "bg-[#e9ecef] text-[#495057]"
                              : "bg-[#ffd6e0]/75 text-[#842029]"
                        }`}
                      >
                        {conn.status === "CONNECTED" ? (
                          <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                        ) : conn.status === "UNTESTED" ? (
                          <CircleDashed className="h-3 w-3" aria-hidden="true" />
                        ) : (
                          <AlertCircle className="h-3 w-3" aria-hidden="true" />
                        )}
                        {conn.status === "CONNECTED"
                          ? `OK · ${conn.latencyMs} мс`
                          : conn.status === "UNTESTED"
                            ? "Не проверялось"
                            : "Ошибка"}
                      </span>
                    </div>

                    <p className="fm-mono mt-1.5 break-all text-[12.5px] text-[#636f7b]">
                      {conn.endpointUrl}
                    </p>
                    <p className="mt-1 text-[12px] text-[#636f7b]">
                      Секрет:{" "}
                      <span className="fm-mono font-medium text-[#222222]">{secretLabel}</span> ·
                      Проверка: {conn.lastTestedAt}
                    </p>
                  </div>

                  <div className="flex shrink-0 flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleToggleExpand(conn)}
                      aria-expanded={expanded}
                      className="fm-btn-outline fm-focus inline-flex min-h-[36px] cursor-pointer items-center gap-1.5 px-3 text-[12.5px] font-medium"
                    >
                      <Wrench className="h-3.5 w-3.5 stroke-[1.6]" aria-hidden="true" />
                      Tools ({conn.tools.length})
                      {expanded ? (
                        <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                    </button>

                    {canManage && (
                      <>
                        <button
                          type="button"
                          disabled={isTesting}
                          onClick={() => handleRunTest(conn.id)}
                          className="fm-btn-outline fm-focus inline-flex min-h-[36px] cursor-pointer items-center gap-1.5 px-3 text-[12.5px] font-medium disabled:opacity-55"
                        >
                          {isTesting ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                          ) : (
                            <RefreshCw className="h-3.5 w-3.5 stroke-[1.6]" aria-hidden="true" />
                          )}
                          Тест
                        </button>

                        <button
                          type="button"
                          onClick={() => onDeleteConnection(conn.id)}
                          aria-label={`Удалить MCP-подключение ${conn.name}`}
                          className="fm-focus inline-flex h-[36px] w-[36px] cursor-pointer items-center justify-center rounded-full text-[#636f7b] transition-colors hover:bg-[#ffd6e0]/50 hover:text-[#842029]"
                        >
                          <Trash2 className="h-4 w-4 stroke-[1.7]" aria-hidden="true" />
                        </button>
                      </>
                    )}
                  </div>
                </div>

                {expanded && (
                  <div className="border-t border-[#8c9baa]/35 bg-[#f8fafc] px-4 py-3.5">
                    <p className="text-[12px] font-semibold text-[#636f7b]">
                      Обнаруженные инструменты (<span className="fm-mono">tools/list</span>)
                    </p>
                    {isLoadingTools ? (
                      <p className="mt-2 flex items-center gap-2 text-[12.5px] text-[#636f7b]">
                        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                        Загружаем список инструментов…
                      </p>
                    ) : conn.tools.length === 0 ? (
                      <p className="mt-2 text-[12.5px] text-[#636f7b]">
                        Инструменты не загружены. Нажмите «Тест», чтобы проверить подключение и
                        обновить список.
                      </p>
                    ) : (
                      <div className="mt-2 divide-y divide-[#8c9baa]/30">
                        {conn.tools.map((tool) => (
                          <div key={tool.name} className="py-2.5 first:pt-1 last:pb-0">
                            <div className="flex flex-wrap items-baseline justify-between gap-2">
                              <span className="fm-mono text-[13px] font-semibold text-[#000000]">
                                {tool.name}
                              </span>
                              <span className="fm-mono text-[12px] text-[#636f7b]">
                                {tool.inputHint}
                              </span>
                            </div>
                            <p className="mt-0.5 text-[12.5px] text-[#222222]">
                              {tool.description}
                            </p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
