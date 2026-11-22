"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, Loader2, RefreshCw } from "lucide-react";
import { fetchAiProviderModels, type AiModelOption } from "@/lib/api";

interface AiModelPickerProps {
  id: string;
  value: string;
  onChange: (model: string) => void;
  baseUrl: string;
  secretRef?: string;
  mode?: "openai-compatible" | "local-ollama" | "deterministic-only";
  disabled?: boolean;
  compact?: boolean;
  placeholder?: string;
  externalModels?: AiModelOption[];
  onModelsLoaded?: (models: AiModelOption[], normalizedUrl: string) => void;
  onSuggestedBaseUrl?: (url: string) => void;
}

function isValidHttpUrl(raw: string): boolean {
  const trimmed = raw.trim();
  if (!/^https?:\/\/[^/\s]+/i.test(trimmed)) return false;
  try {
    const parsed = new URL(trimmed);
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.hostname.length > 0;
  } catch {
    return false;
  }
}

export function AiModelPicker({
  id,
  value,
  onChange,
  baseUrl,
  secretRef = "",
  mode = "openai-compatible",
  disabled = false,
  compact = false,
  placeholder = "Выберите модель из списка или введите ID",
  externalModels,
  onModelsLoaded,
  onSuggestedBaseUrl,
}: AiModelPickerProps) {
  const [models, setModels] = useState<AiModelOption[]>(externalModels ?? []);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [suggestedUrl, setSuggestedUrl] = useState<string | null>(null);

  const rootRef = useRef<HTMLDivElement | null>(null);
  const reqIdRef = useRef(0);
  const lastFetchedKeyRef = useRef("");

  useEffect(() => {
    if (externalModels && externalModels.length > 0) {
      setModels(externalModels);
      setFetchError(null);
    }
  }, [externalModels]);

  const loadModels = useCallback(
    async (force = false) => {
      const trimmedUrl = baseUrl.trim();
      if (mode === "deterministic-only" || !isValidHttpUrl(trimmedUrl)) {
        setModels([]);
        setFetchError(null);
        setSuggestedUrl(null);
        lastFetchedKeyRef.current = "";
        return;
      }
      const key = `${mode}|${trimmedUrl}|${secretRef}`;
      if (!force && key === lastFetchedKeyRef.current) {
        return;
      }
      lastFetchedKeyRef.current = key;
      const reqId = ++reqIdRef.current;
      setLoading(true);
      setFetchError(null);
      setSuggestedUrl(null);
      try {
        const res = await fetchAiProviderModels({
          baseUrl: trimmedUrl,
          secretRef: secretRef || undefined,
          mode,
        });
        if (reqId !== reqIdRef.current) return;
        setModels(res.models ?? []);
        if (res.suggestedBaseUrl) {
          setSuggestedUrl(res.suggestedBaseUrl);
        }
        if (res.ok) {
          setFetchError(null);
          onModelsLoaded?.(res.models ?? [], res.normalizedBaseUrl);
        } else {
          const hint =
            res.statusCode === 401 && !secretRef
              ? "HTTP 401: выберите секрет с API-ключом, чтобы загрузить список моделей."
              : res.error || "Не удалось загрузить список моделей.";
          setFetchError(hint);
        }
      } catch (err: unknown) {
        if (reqId !== reqIdRef.current) return;
        setModels([]);
        setFetchError(err instanceof Error ? err.message : "Ошибка загрузки списка моделей");
      } finally {
        if (reqId === reqIdRef.current) {
          setLoading(false);
        }
      }
    },
    [baseUrl, secretRef, mode, onModelsLoaded],
  );

  // Debounced auto-fetch whenever baseUrl / secretRef / mode changes.
  useEffect(() => {
    if (disabled || mode === "deterministic-only") {
      return;
    }
    if (!isValidHttpUrl(baseUrl)) {
      setModels([]);
      setFetchError(null);
      setSuggestedUrl(null);
      lastFetchedKeyRef.current = "";
      return;
    }
    const timer = window.setTimeout(() => {
      void loadModels(false);
    }, 450);
    return () => window.clearTimeout(timer);
  }, [baseUrl, secretRef, mode, disabled, loadModels]);

  // Close popover on outside click.
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
        setQuery("");
      }
    };
    window.addEventListener("pointerdown", onPointerDown);
    return () => window.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return models;
    return models.filter(
      (m) =>
        m.id.toLowerCase().includes(q) ||
        (m.name && m.name.toLowerCase().includes(q)) ||
        (m.ownedBy && m.ownedBy.toLowerCase().includes(q)),
    );
  }, [models, query]);

  const inputHeightClass = compact ? "min-h-[38px] rounded-[12px] sm:text-[12px]" : "min-h-[42px] rounded-[10px] sm:text-[13.5px]";

  return (
    <div ref={rootRef} className="relative">
      <div className="flex items-center gap-1.5">
        <div className="relative min-w-0 flex-1">
          <input
            id={id}
            type="text"
            role="combobox"
            aria-expanded={open}
            aria-controls={`${id}-listbox`}
            aria-autocomplete="list"
            autoCapitalize="none"
            autoCorrect="off"
            autoComplete="off"
            disabled={disabled}
            placeholder={placeholder}
            value={value}
            onFocus={() => {
              if (!disabled && models.length > 0) {
                setOpen(true);
              }
            }}
            onChange={(e) => {
              const next = e.target.value;
              onChange(next);
              setQuery(next);
              if (models.length > 0) {
                setOpen(true);
              }
            }}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                setOpen(false);
                setQuery("");
              } else if (e.key === "ArrowDown" && models.length > 0) {
                setOpen(true);
              }
            }}
            className={`fm-focus fm-mono w-full border border-[#8c9baa] bg-[#ffffff] py-2 pl-3 pr-9 text-[16px] text-[#000000] disabled:bg-[#f8fafc] disabled:text-[#636f7b] ${inputHeightClass}`}
          />

          <button
            type="button"
            disabled={disabled || models.length === 0}
            aria-label="Открыть список моделей"
            onClick={() => {
              setQuery("");
              setOpen((prev) => !prev);
            }}
            className="fm-focus absolute right-1.5 top-1/2 inline-flex h-7 w-7 -translate-y-1/2 cursor-pointer items-center justify-center rounded-[8px] text-[#636f7b] transition-colors hover:bg-[#f1f5f9] hover:text-[#000000] disabled:cursor-default disabled:opacity-40"
          >
            {loading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[#0080ff]" aria-hidden="true" />
            ) : (
              <ChevronDown
                className={`h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`}
                aria-hidden="true"
              />
            )}
          </button>
        </div>

        <button
          type="button"
          disabled={disabled || loading || !isValidHttpUrl(baseUrl)}
          onClick={() => {
            void loadModels(true).then(() => setOpen(true));
          }}
          title="Загрузить список доступных моделей с эндпоинта"
          aria-label="Обновить список моделей"
          className={`fm-focus inline-flex shrink-0 cursor-pointer items-center justify-center border border-[#8c9baa] bg-[#ffffff] text-[#222222] transition-colors hover:border-[#0080ff] hover:text-[#0050ff] disabled:cursor-not-allowed disabled:opacity-45 ${
            compact ? "h-[38px] w-[38px] rounded-[12px]" : "h-[42px] w-[42px] rounded-[10px]"
          }`}
        >
          <RefreshCw className={`h-4 w-4 stroke-[1.7] ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
        </button>
      </div>

      {/* Dropdown listbox */}
      {open && models.length > 0 && !disabled && (
        <div
          id={`${id}-listbox`}
          role="listbox"
          aria-label="Доступные модели LLM"
          className="absolute left-0 right-0 z-40 mt-1.5 overflow-hidden rounded-[12px] border border-[#8c9baa]/80 bg-[#ffffff] shadow-[0_12px_28px_-8px_rgba(15,23,42,0.18)]"
        >
          <div className="flex items-center justify-between gap-2 border-b border-[#8c9baa]/35 bg-[#f8fafc] px-3 py-1.5 text-[11px] text-[#636f7b]">
            <span className="fm-tnum">
              Доступно моделей: <strong className="text-[#000000]">{filtered.length}</strong>
              {filtered.length !== models.length ? ` из ${models.length}` : ""}
            </span>
            {query.trim() !== "" && (
              <button
                type="button"
                onClick={() => setQuery("")}
                className="cursor-pointer font-medium text-[#0050ff] hover:underline"
              >
                Показать все
              </button>
            )}
          </div>
          <ul className="max-h-[240px] overflow-y-auto py-1">
            {filtered.length === 0 ? (
              <li className="px-3 py-2.5 text-[12px] text-[#636f7b]">
                Совпадений нет — можно оставить введённый ID вручную.
              </li>
            ) : (
              filtered.map((m) => {
                const selected = m.id === value.trim();
                return (
                  <li key={m.id} role="option" aria-selected={selected}>
                    <button
                      type="button"
                      onClick={() => {
                        onChange(m.id);
                        setQuery("");
                        setOpen(false);
                      }}
                      className={`flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left transition-colors ${
                        selected
                          ? "bg-[#f0f7ff] text-[#0050ff]"
                          : "text-[#000000] hover:bg-[#f8fafc]"
                      }`}
                    >
                      <span className="min-w-0 flex-1">
                        <span className="fm-mono block truncate text-[12.5px] font-medium">
                          {m.id}
                        </span>
                        {(m.name || m.ownedBy || m.contextLength) && (
                          <span className="mt-0.5 block truncate text-[11px] text-[#636f7b]">
                            {[
                              m.name,
                              m.ownedBy,
                              m.contextLength ? `${Math.round(m.contextLength / 1000)}k ctx` : "",
                            ]
                              .filter(Boolean)
                              .join(" · ")}
                          </span>
                        )}
                      </span>
                      {selected && (
                        <Check className="h-3.5 w-3.5 shrink-0 text-[#0080ff]" aria-hidden="true" />
                      )}
                    </button>
                  </li>
                );
              })
            )}
          </ul>
        </div>
      )}

      {/* Status / count / error / suggested baseUrl hint */}
      {!disabled && mode !== "deterministic-only" && (
        <div className="mt-1.5 space-y-1">
          {loading && (
            <p className="text-[11.5px] text-[#636f7b]">Загрузка списка моделей с эндпоинта…</p>
          )}
          {!loading && models.length > 0 && !fetchError && (
            <p className="fm-tnum text-[11.5px] text-[#0f5132]">
              Загружено моделей: <strong>{models.length}</strong>. Нажмите на поле или стрелку для выбора.
            </p>
          )}
          {!loading && fetchError && (
            <p className="[overflow-wrap:anywhere] text-[11.5px] text-[#842029]">{fetchError}</p>
          )}
          {suggestedUrl && onSuggestedBaseUrl && (
            <div className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-[#664d03]">
              <span>Рабочий путь найден по адресу:</span>
              <button
                type="button"
                onClick={() => {
                  onSuggestedBaseUrl(suggestedUrl);
                  setSuggestedUrl(null);
                }}
                className="fm-mono cursor-pointer rounded-full border border-[#e5c158] bg-[#fff3c4]/70 px-2 py-0.5 text-[11px] font-semibold text-[#664d03] hover:bg-[#fff3c4]"
              >
                {suggestedUrl}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
