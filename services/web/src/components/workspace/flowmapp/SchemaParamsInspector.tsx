"use client";

import { useEffect, useState } from "react";
import { Code2, KeyRound, Plus, SlidersHorizontal, X } from "lucide-react";
import type { SecretBindingRef } from "@/data/canvas-nodes-catalog";
import type { JsonSchemaObject, JsonSchemaProperty } from "@/data/plugins-data";
import type { SecretRecord } from "@/data/settings-data";

interface SchemaParamsInspectorProps {
  nodeId: string;
  config: Record<string, string>;
  secretBindings?: SecretBindingRef[];
  paramsJsonSchema?: JsonSchemaObject;
  requiredSecretKeys?: string[];
  secrets: SecretRecord[];
  hideSecretBindings?: boolean;
  canEdit: boolean;
  onUpdateConfig: (key: string, value: string) => void;
  onReplaceConfig: (next: Record<string, string>) => void;
  onUpdateSecretBinding: (paramKey: string, secretRef: string) => void;
}

function parseArrayValue(raw: string | undefined, prop: JsonSchemaProperty): string[] {
  const source = raw ?? (Array.isArray(prop.default) ? JSON.stringify(prop.default) : "[]");
  try {
    const parsed = JSON.parse(source);
    if (Array.isArray(parsed)) {
      return parsed.map((v) => String(v));
    }
  } catch {
    if (source.trim()) {
      return source
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }
  return [];
}

function parseBoolValue(raw: string | undefined, prop: JsonSchemaProperty): boolean {
  if (raw !== undefined) {
    return raw === "true" || raw === "1";
  }
  return Boolean(prop.default);
}

function serializeTypedConfig(
  config: Record<string, string>,
  schema?: JsonSchemaObject,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const props = schema?.properties ?? {};
  for (const [k, raw] of Object.entries(config)) {
    const prop = props[k];
    if (!prop) {
      out[k] = raw;
      continue;
    }
    if (prop.type === "boolean") {
      out[k] = raw === "true";
    } else if (prop.type === "integer" || prop.type === "number") {
      const n = Number(raw);
      out[k] = raw.trim() === "" || Number.isNaN(n) ? raw : n;
    } else if (prop.type === "array") {
      out[k] = parseArrayValue(raw, prop);
    } else {
      out[k] = raw;
    }
  }
  return out;
}

export function SchemaParamsInspector({
  nodeId,
  config,
  secretBindings = [],
  paramsJsonSchema,
  requiredSecretKeys = [],
  secrets,
  hideSecretBindings = false,
  canEdit,
  onUpdateConfig,
  onReplaceConfig,
  onUpdateSecretBinding,
}: SchemaParamsInspectorProps) {
  const [mode, setMode] = useState<"form" | "json">("form");
  const [rawJsonDraft, setRawJsonDraft] = useState("");
  const [rawJsonError, setRawJsonError] = useState<string | null>(null);
  const [arrayDrafts, setArrayDrafts] = useState<Record<string, string>>({});

  useEffect(() => {
    setMode("form");
    setRawJsonError(null);
    setArrayDrafts({});
  }, [nodeId]);

  const schemaProps = paramsJsonSchema?.properties ?? {};
  const schemaKeys = Object.keys(schemaProps);
  const requiredSet = new Set(paramsJsonSchema?.required ?? []);
  const hasSchema = schemaKeys.length > 0;
  const fallbackEntries = Object.entries(config);

  const openRawJson = () => {
    setRawJsonDraft(JSON.stringify(serializeTypedConfig(config, paramsJsonSchema), null, 2));
    setRawJsonError(null);
    setMode("json");
  };

  const applyRawJson = () => {
    if (!canEdit) return;
    try {
      const parsed = JSON.parse(rawJsonDraft);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        setRawJsonError("Параметры должны быть JSON-объектом { ... }.");
        return;
      }
      const next: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        next[k] = typeof v === "string" ? v : JSON.stringify(v);
      }
      onReplaceConfig(next);
      setRawJsonError(null);
      setMode("form");
    } catch (err) {
      setRawJsonError(
        err instanceof Error ? `Невалидный JSON: ${err.message}` : "Невалидный JSON",
      );
    }
  };

  const addArrayItem = (key: string, prop: JsonSchemaProperty) => {
    if (!canEdit) return;
    const item = (arrayDrafts[key] ?? "").trim();
    if (!item) return;
    const curr = parseArrayValue(config[key], prop);
    if (!curr.includes(item)) {
      onUpdateConfig(key, JSON.stringify([...curr, item]));
    }
    setArrayDrafts((prev) => ({ ...prev, [key]: "" }));
  };

  const removeArrayItem = (key: string, prop: JsonSchemaProperty, idx: number) => {
    if (!canEdit) return;
    const curr = parseArrayValue(config[key], prop);
    onUpdateConfig(
      key,
      JSON.stringify(curr.filter((_, i) => i !== idx)),
    );
  };

  return (
    <div className="space-y-4">
      {/* Secret Reference Bindings for requiredSecretKeys */}
      {!hideSecretBindings && requiredSecretKeys.length > 0 && (
        <div className="rounded-[20px] border border-[#d97706]/50 bg-[#fffdf5] p-4">
          <div className="flex items-center gap-1.5">
            <KeyRound className="h-3.5 w-3.5 text-[#d97706]" aria-hidden="true" />
            <h3 className="text-[13px] font-semibold text-[#000000]">
              Секреты (Secret Reference)
            </h3>
          </div>
          <p className="mt-1 text-[11.5px] text-[#636f7b]">
            Учётные данные привязываются по ссылке <span className="fm-mono">secret_ref</span> и
            никогда не попадают в параметры графа.
          </p>
          <div className="mt-3 space-y-3">
            {requiredSecretKeys.map((secretKey) => {
              const bound =
                secretBindings.find((b) => b.paramKey === secretKey)?.secretRef ?? "";
              const selectId = `fm11-sec-${nodeId}-${secretKey}`;
              return (
                <div key={secretKey}>
                  <label
                    htmlFor={selectId}
                    className="fm-mono flex items-center gap-1 text-[11.5px] font-semibold text-[#222222]"
                  >
                    <span>{secretKey}</span>
                    <span className="text-[#dc2626]" aria-hidden="true">
                      *
                    </span>
                  </label>
                  <select
                    id={selectId}
                    value={bound}
                    disabled={!canEdit}
                    onChange={(e) => onUpdateSecretBinding(secretKey, e.target.value)}
                    className="fm-focus fm-mono fm-select mt-1 min-h-[38px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] disabled:bg-[#f8fafc] sm:text-[12px]"
                  >
                    <option value="">— Выберите Secret Reference —</option>
                    {secrets.map((sec) => (
                      <option key={sec.id} value={sec.id}>
                        {sec.name} ({sec.maskedValue})
                      </option>
                    ))}
                  </select>
                  {!bound && (
                    <p className="mt-1 text-[11px] font-medium text-[#b42318]">
                      Обязательный секрет не привязан
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Main Params Card with Form / Raw JSON switcher */}
      <div className="rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            <h3 className="whitespace-nowrap text-[13px] font-semibold text-[#000000]">
              Параметры узла
            </h3>
            {hasSchema && (
              <span className="inline-flex shrink-0 items-center whitespace-nowrap rounded-full border border-[#0080ff]/35 bg-[#f6faff] px-2 py-0.5 text-[10px] font-semibold leading-none text-[#004a99]">
                JSON Schema
              </span>
            )}
          </div>
          <div
            role="tablist"
            aria-label="Режим редактирования параметров"
            className="inline-flex shrink-0 items-center rounded-full border border-[#8c9baa]/60 bg-[#ffffff] p-0.5"
          >
            <button
              type="button"
              role="tab"
              aria-selected={mode === "form"}
              onClick={() => setMode("form")}
              className={`fm-focus inline-flex min-h-[26px] shrink-0 cursor-pointer items-center gap-1 whitespace-nowrap rounded-full px-2.5 text-[11px] font-semibold ${
                mode === "form"
                  ? "bg-[#000000] text-[#ffffff]"
                  : "text-[#636f7b] hover:text-[#000000]"
              }`}
            >
              <SlidersHorizontal className="h-3 w-3 shrink-0" aria-hidden="true" />
              Форма
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === "json"}
              onClick={openRawJson}
              className={`fm-focus inline-flex min-h-[26px] shrink-0 cursor-pointer items-center gap-1 whitespace-nowrap rounded-full px-2.5 text-[11px] font-semibold ${
                mode === "json"
                  ? "bg-[#000000] text-[#ffffff]"
                  : "text-[#636f7b] hover:text-[#000000]"
              }`}
            >
              <Code2 className="h-3 w-3 shrink-0" aria-hidden="true" />
              Raw JSON
            </button>
          </div>
        </div>

        {mode === "json" ? (
          <div className="mt-3 space-y-2.5">
            <textarea
              aria-label="Raw JSON параметров узла"
              rows={8}
              value={rawJsonDraft}
              readOnly={!canEdit}
              onChange={(e) => {
                setRawJsonDraft(e.target.value);
                setRawJsonError(null);
              }}
              className="fm-focus fm-mono fm-scroll overscroll-contain w-full rounded-[12px] border border-[#8c9baa] bg-[#f8fafc] p-3 text-[16px] leading-[1.45] text-[#000000] sm:text-[12px]"
            />
            {rawJsonError && (
              <p role="alert" className="text-[11.5px] font-medium text-[#b42318]">
                {rawJsonError}
              </p>
            )}
            {canEdit && (
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setMode("form")}
                  className="fm-btn-outline fm-focus min-h-[34px] cursor-pointer px-3 text-[12px] font-medium"
                >
                  Отмена
                </button>
                <button
                  type="button"
                  onClick={applyRawJson}
                  className="fm-btn-ink fm-focus min-h-[34px] cursor-pointer px-3 text-[12px] font-semibold"
                >
                  Применить JSON
                </button>
              </div>
            )}
          </div>
        ) : hasSchema ? (
          <div className="mt-3 space-y-3.5">
            {schemaKeys.map((key) => {
              const prop = schemaProps[key];
              const isRequired = requiredSet.has(key);
              const inputId = `fm11-schema-${nodeId}-${key}`;
              const currentVal =
                config[key] !== undefined
                  ? config[key]
                  : prop.default !== undefined && prop.default !== null
                    ? typeof prop.default === "string"
                      ? prop.default
                      : JSON.stringify(prop.default)
                    : "";

              if (prop.type === "boolean") {
                const checked = parseBoolValue(config[key], prop);
                return (
                  <div
                    key={key}
                    className="rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc]/60 px-3 py-2.5"
                  >
                    <label
                      htmlFor={inputId}
                      className="flex cursor-pointer items-center justify-between gap-2"
                    >
                      <span className="fm-mono truncate text-[12px] font-semibold text-[#000000]">
                        {key}
                        {isRequired && <span className="ml-0.5 text-[#dc2626]">*</span>}
                      </span>
                      <input
                        id={inputId}
                        type="checkbox"
                        checked={checked}
                        disabled={!canEdit}
                        onChange={(e) => onUpdateConfig(key, String(e.target.checked))}
                        className="h-4 w-4 accent-[#0080ff]"
                      />
                    </label>
                    {prop.description && (
                      <p className="mt-1 text-[11px] leading-[1.35] text-[#636f7b]">
                        {prop.description}
                      </p>
                    )}
                  </div>
                );
              }

              if (prop.enum && prop.enum.length > 0) {
                return (
                  <div key={key}>
                    <label
                      htmlFor={inputId}
                      className="fm-mono block truncate text-[11.5px] font-semibold text-[#222222]"
                    >
                      {key}
                      {isRequired && <span className="ml-0.5 text-[#dc2626]">*</span>}
                    </label>
                    {prop.description && (
                      <p className="mt-0.5 text-[11px] text-[#636f7b]">{prop.description}</p>
                    )}
                    <select
                      id={inputId}
                      value={currentVal}
                      disabled={!canEdit}
                      onChange={(e) => onUpdateConfig(key, e.target.value)}
                      className="fm-focus fm-mono fm-select mt-1 min-h-[38px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] disabled:bg-[#f8fafc] sm:text-[12px]"
                    >
                      {prop.enum.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  </div>
                );
              }

              if (prop.type === "array") {
                const items = parseArrayValue(config[key], prop);
                const draft = arrayDrafts[key] ?? "";
                return (
                  <div key={key}>
                    <label
                      htmlFor={inputId}
                      className="fm-mono block truncate text-[11.5px] font-semibold text-[#222222]"
                    >
                      {key}
                      {isRequired && <span className="ml-0.5 text-[#dc2626]">*</span>}
                    </label>
                    {prop.description && (
                      <p className="mt-0.5 text-[11px] text-[#636f7b]">{prop.description}</p>
                    )}
                    {items.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {items.map((tag, idx) => (
                          <span
                            key={`${tag}-${idx}`}
                            className="fm-mono inline-flex items-center gap-1 rounded-full border border-[#8c9baa]/55 bg-[#f8fafc] px-2.5 py-0.5 text-[11px] text-[#000000]"
                          >
                            <span className="max-w-[160px] truncate">{tag}</span>
                            {canEdit && (
                              <button
                                type="button"
                                onClick={() => removeArrayItem(key, prop, idx)}
                                aria-label={`Удалить ${tag}`}
                                className="cursor-pointer text-[#636f7b] hover:text-[#dc2626]"
                              >
                                <X className="h-3 w-3" aria-hidden="true" />
                              </button>
                            )}
                          </span>
                        ))}
                      </div>
                    )}
                    {canEdit && (
                      <div className="mt-1.5 flex items-center gap-1.5">
                        <input
                          id={inputId}
                          type="text"
                          value={draft}
                          placeholder="Добавить значение…"
                          onChange={(e) =>
                            setArrayDrafts((prev) => ({ ...prev, [key]: e.target.value }))
                          }
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              addArrayItem(key, prop);
                            }
                          }}
                          className="fm-focus fm-mono min-h-[36px] min-w-0 flex-1 rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-2.5 text-[16px] text-[#000000] sm:text-[12px]"
                        />
                        <button
                          type="button"
                          onClick={() => addArrayItem(key, prop)}
                          aria-label={`Добавить элемент в ${key}`}
                          className="fm-btn-outline fm-focus inline-flex h-[36px] w-[36px] shrink-0 cursor-pointer items-center justify-center"
                        >
                          <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    )}
                  </div>
                );
              }

              const isNumeric = prop.type === "number" || prop.type === "integer";
              const missingReq = isRequired && currentVal.trim() === "";
              return (
                <div key={key}>
                  <label
                    htmlFor={inputId}
                    className="fm-mono block truncate text-[11.5px] font-semibold text-[#222222]"
                  >
                    {key}
                    {isRequired && <span className="ml-0.5 text-[#dc2626]">*</span>}
                  </label>
                  {prop.description && (
                    <p className="mt-0.5 text-[11px] text-[#636f7b]">{prop.description}</p>
                  )}
                  <input
                    id={inputId}
                    type={isNumeric ? "number" : "text"}
                    min={isNumeric ? prop.minimum : undefined}
                    max={isNumeric ? prop.maximum : undefined}
                    step={prop.type === "integer" ? 1 : "any"}
                    value={currentVal}
                    readOnly={!canEdit}
                    placeholder={
                      prop.default !== undefined ? `По умолчанию: ${String(prop.default)}` : ""
                    }
                    onChange={(e) => onUpdateConfig(key, e.target.value)}
                    className={`fm-focus fm-mono mt-1 min-h-[38px] w-full rounded-[12px] border bg-[#ffffff] px-3 text-[16px] text-[#000000] read-only:bg-[#f8fafc] read-only:text-[#636f7b] sm:text-[12px] ${
                      missingReq ? "border-[#dc2626]" : "border-[#8c9baa]"
                    }`}
                  />
                  {missingReq && (
                    <p className="mt-1 text-[11px] font-medium text-[#b42318]">
                      Обязательное поле
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        ) : fallbackEntries.length === 0 ? (
          <p className="mt-2 text-[12px] text-[#636f7b]">
            У этой ноды нет дополнительных параметров.
          </p>
        ) : (
          <div className="mt-3 space-y-3">
            {fallbackEntries.map(([key, value]) => {
              const inputId = `fm11-cfg-${nodeId}-${key}`;
              return (
                <div key={key}>
                  <label
                    htmlFor={inputId}
                    className="fm-mono block truncate text-[11px] font-medium text-[#636f7b]"
                  >
                    {key}
                  </label>
                  <input
                    id={inputId}
                    type="text"
                    autoCapitalize="none"
                    autoCorrect="off"
                    enterKeyHint="done"
                    value={value}
                    readOnly={!canEdit}
                    onChange={(e) => onUpdateConfig(key, e.target.value)}
                    className="fm-focus fm-mono mt-1 min-h-[38px] w-full rounded-[12px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] read-only:bg-[#f8fafc] read-only:text-[#636f7b] sm:text-[12px]"
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
