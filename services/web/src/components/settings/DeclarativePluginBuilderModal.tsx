"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Code2,
  Download,
  FileCode2,
  Globe,
  KeyRound,
  Loader2,
  Play,
  Plus,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { NodeCategoryIcon } from "@/components/workspace/NodeCategoryIcon";
import { SchemaParamsInspector } from "@/components/workspace/flowmapp/SchemaParamsInspector";
import {
  CATEGORY_BY_ID,
  type CanvasNodeTemplate,
} from "@/data/canvas-nodes-catalog";
import {
  emptySpecForCategory,
  prefixForCategory,
  slugifyName,
  specToCanvasTemplate,
  specToJsonSchema,
  type DeclarativeAnalyzerRule,
  type DeclarativeBlueprintRecord,
  type DeclarativeCategory,
  type DeclarativeLogicRoute,
  type DeclarativeParamField,
  type DeclarativeParamType,
  type DeclarativePluginSpec,
  type TestDeclarativePluginInput,
  type TestDeclarativePluginResult,
  type VirtualFileFixture,
} from "@/data/declarative-plugin-data";
import type {
  InstallPluginFormInput,
  PluginInstallationRecord,
  UpdatePluginInstallationFormInput,
} from "@/data/plugins-data";
import type { SecretRecord } from "@/data/settings-data";
import type { UserRole } from "@/data/workflows-workspace-data";

export interface DeclarativePluginSavedResult {
  mode: "canvas-draft" | "draft" | "pending" | "active" | "updated";
  spec: DeclarativePluginSpec;
  installation?: PluginInstallationRecord;
  template: CanvasNodeTemplate;
}

interface DeclarativePluginBuilderModalProps {
  open: boolean;
  role: UserRole;
  launchSource: "settings" | "palette" | "canvas";
  initialSpec?: DeclarativePluginSpec | null;
  editingInstallation?: PluginInstallationRecord | null;
  blueprints: DeclarativeBlueprintRecord[];
  secrets: SecretRecord[];
  onClose: () => void;
  onInstallPlugin: (input: InstallPluginFormInput) => Promise<{
    installation: PluginInstallationRecord;
    plaintextPluginToken: string | null;
  }>;
  onUpdateInstallation: (input: UpdatePluginInstallationFormInput) => Promise<{
    installation: PluginInstallationRecord;
    plaintextPluginToken: string | null;
  }>;
  onTestPlugin: (input: TestDeclarativePluginInput) => Promise<TestDeclarativePluginResult>;
  onCompleted: (result: DeclarativePluginSavedResult) => void;
  onNotice: (text: string) => void;
}

type BuilderStep = 1 | 2 | 3 | 4;

const STEP_META: Array<{ id: BuilderStep; label: string }> = [
  { id: 1, label: "1. Основы" },
  { id: 2, label: "2. Параметры" },
  { id: 3, label: "3. Логика" },
  { id: 4, label: "4. Тест" },
];

const DEFAULT_TEST_FILES: VirtualFileFixture[] = [
  {
    path: "src/main/resources/application.yml",
    content: 'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n',
  },
];

const ENVELOPE_PRESETS: Record<string, Record<string, unknown>> = {
  clean: { runId: "test_run", findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }, vars: {} },
  critical: {
    runId: "test_run",
    findings: [
      { id: "f1", category: "SECRET", severity: "CRITICAL", description: "Hardcoded API key" },
      { id: "f2", category: "SAST", severity: "HIGH", description: "SQL injection sink" },
    ],
    stats: { total: 2, critical: 1, high: 1, medium: 0, low: 0 },
    vars: {},
  },
  medium: {
    runId: "test_run",
    findings: [{ id: "f1", category: "SCA", severity: "MEDIUM", description: "Outdated library" }],
    stats: { total: 1, critical: 0, high: 0, medium: 1, low: 0 },
    vars: {},
  },
};

export function DeclarativePluginBuilderModal({
  open,
  role,
  launchSource,
  initialSpec,
  editingInstallation,
  blueprints,
  secrets,
  onClose,
  onInstallPlugin,
  onUpdateInstallation,
  onTestPlugin,
  onCompleted,
  onNotice,
}: DeclarativePluginBuilderModalProps) {
  const isOwner = role === "owner";
  const isEditing = Boolean(editingInstallation);

  const [step, setStep] = useState<BuilderStep>(1);
  const [spec, setSpec] = useState<DeclarativePluginSpec>(() =>
    initialSpec ? structuredClone(initialSpec) : emptySpecForCategory("ANALYZER"),
  );
  const [slugTouched, setSlugTouched] = useState(Boolean(initialSpec || editingInstallation));
  const [showSchemaJson, setShowSchemaJson] = useState(false);

  // Preview Inspector state
  const [previewConfig, setPreviewConfig] = useState<Record<string, string>>({});
  const [previewSecretBindings, setPreviewSecretBindings] = useState<
    Array<{ paramKey: string; secretRef: string }>
  >([]);

  // Test Bench state
  const [testFiles, setTestFiles] = useState<VirtualFileFixture[]>(DEFAULT_TEST_FILES);
  const [testEnvelopeText, setTestEnvelopeText] = useState<string>(() =>
    JSON.stringify(ENVELOPE_PRESETS.critical, null, 2),
  );
  const [testResult, setTestResult] = useState<TestDeclarativePluginResult | null>(null);
  const [testing, setTesting] = useState(false);

  // Action/form submission state
  const [saving, setSaving] = useState(false);
  const [errorText, setErrorText] = useState<string | null>(null);
  const fileImportRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const base = initialSpec
      ? structuredClone(initialSpec)
      : editingInstallation?.pendingDeclarativeSpec
        ? structuredClone(editingInstallation.pendingDeclarativeSpec as unknown as DeclarativePluginSpec)
        : editingInstallation?.declarativeSpec
          ? structuredClone(editingInstallation.declarativeSpec as unknown as DeclarativePluginSpec)
          : emptySpecForCategory("ANALYZER");
    setSpec(base);
    setSlugTouched(Boolean(initialSpec || editingInstallation));
    setStep(1);
    setTestResult(null);
    setErrorText(null);
    setPreviewConfig(specToCanvasTemplate(base, editingInstallation?.id).defaultConfig);
    setPreviewSecretBindings([]);
  }, [open, initialSpec, editingInstallation]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  const previewSchema = useMemo(() => specToJsonSchema(spec), [spec]);
  const previewTemplate = useMemo(
    () => specToCanvasTemplate(spec, editingInstallation?.id),
    [spec, editingInstallation?.id],
  );
  const previewCategoryMeta = CATEGORY_BY_ID[previewTemplate.family];

  if (!open) return null;

  const handleCategoryChange = (nextCat: DeclarativeCategory) => {
    if (isEditing) return;
    const fresh = emptySpecForCategory(nextCat);
    setSpec({
      ...fresh,
      displayName: spec.displayName || fresh.displayName,
      description: spec.description || fresh.description,
      pluginId: `${prefixForCategory(nextCat)}${slugifyName(spec.displayName || fresh.displayName)}`,
    });
    setTestResult(null);
    setErrorText(null);
  };

  const handleApplyBlueprint = (bp: DeclarativeBlueprintRecord) => {
    const cloned = structuredClone(bp.spec);
    if (isEditing && editingInstallation?.pluginIds[0]) {
      cloned.pluginId = editingInstallation.pluginIds[0];
    }
    setSpec(cloned);
    setSlugTouched(true);
    setPreviewConfig(specToCanvasTemplate(cloned, editingInstallation?.id).defaultConfig);
    setTestResult(null);
    setErrorText(null);
    onNotice(`Загружена заготовка «${bp.name}»`);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(spec, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${spec.pluginId || "declarative-plugin"}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onNotice("Спецификация экспортирована в JSON (без секретов)");
  };

  const handleImportFile = async (file: File | null) => {
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as DeclarativePluginSpec;
      if (!parsed || typeof parsed !== "object" || !parsed.category || !parsed.pluginId) {
        throw new Error("JSON не похож на спецификацию Declarative Plugin");
      }
      if (isEditing && editingInstallation?.pluginIds[0]) {
        parsed.pluginId = editingInstallation.pluginIds[0];
      }
      setSpec(parsed);
      setSlugTouched(true);
      setPreviewConfig(specToCanvasTemplate(parsed, editingInstallation?.id).defaultConfig);
      setErrorText(null);
      onNotice(`Импортирована спецификация «${parsed.displayName || parsed.pluginId}»`);
    } catch (err) {
      setErrorText(err instanceof Error ? err.message : "Ошибка импорта JSON");
    }
  };

  const handleRunTestBench = async () => {
    if (testing) return;
    setTesting(true);
    setErrorText(null);
    try {
      let parsedEnvelope: Record<string, unknown> | undefined;
      if (spec.category === "LOGIC" || spec.category === "ACTION") {
        parsedEnvelope = JSON.parse(testEnvelopeText) as Record<string, unknown>;
      }
      const typedParams: Record<string, unknown> = {};
      for (const [k, raw] of Object.entries(previewConfig)) {
        const field = spec.params?.find((p) => p.key === k);
        if (field?.type === "boolean") typedParams[k] = raw === "true";
        else if (field?.type === "integer" || field?.type === "number") typedParams[k] = Number(raw);
        else typedParams[k] = raw;
      }
      const res = await onTestPlugin({
        declarativeSpec: spec,
        params: typedParams,
        files: spec.category === "ANALYZER" ? testFiles : undefined,
        envelope: parsedEnvelope,
      });
      setTestResult(res);
    } catch (err) {
      setErrorText(err instanceof Error ? err.message : "Ошибка запуска Test Bench");
    } finally {
      setTesting(false);
    }
  };

  const handlePlaceUnsavedOnCanvas = () => {
    setErrorText(null);
    onCompleted({
      mode: "canvas-draft",
      spec,
      template: previewTemplate,
    });
    onClose();
  };

  const handlePersist = async (target: "draft" | "pending" | "active") => {
    if (saving) return;
    setSaving(true);
    setErrorText(null);
    try {
      const payloadSpec = spec as unknown as Record<string, unknown>;
      if (editingInstallation) {
        const res = await onUpdateInstallation({
          installationId: editingInstallation.id,
          declarativeSpec: payloadSpec,
          submitForApproval: target === "pending",
          approveImmediately: target === "active" && isOwner,
        });
        onCompleted({
          mode: target === "active" ? "active" : "updated",
          spec,
          installation: res.installation,
          template: specToCanvasTemplate(spec, res.installation.id),
        });
        onClose();
        return;
      }

      const res = await onInstallPlugin({
        name: spec.displayName.trim() || spec.pluginId,
        sourceMode: "DECLARATIVE",
        sandboxProfile: spec.category === "ACTION" ? "EGRESS_EXTERNAL" : "INTERNAL_ONLY",
        egressAllowlist: spec.category === "ACTION" ? spec.egressAllowlist ?? [] : [],
        desiredReplicas: 1,
        autoApprove: target === "active" && isOwner,
        saveAsDraft: target === "draft",
        declarativeSpec: payloadSpec,
      });
      onCompleted({
        mode: target,
        spec,
        installation: res.installation,
        template: specToCanvasTemplate(spec, res.installation.id),
      });
      onClose();
    } catch (err) {
      setErrorText(err instanceof Error ? err.message : "Не удалось сохранить Declarative Plugin");
    } finally {
      setSaving(false);
    }
  };

  // Parameter schema helpers
  const updateParam = (idx: number, patch: Partial<DeclarativeParamField>) => {
    setSpec((prev) => {
      const list = [...(prev.params ?? [])];
      list[idx] = { ...list[idx], ...patch };
      return { ...prev, params: list };
    });
  };
  const addParam = () => {
    setSpec((prev) => ({
      ...prev,
      params: [
        ...(prev.params ?? []),
        { key: `param${(prev.params?.length ?? 0) + 1}`, type: "string", description: "", default: "" },
      ],
    }));
  };
  const removeParam = (idx: number) => {
    setSpec((prev) => ({
      ...prev,
      params: (prev.params ?? []).filter((_, i) => i !== idx),
    }));
  };

  // Analyzer rule helpers
  const rules = spec.analyzer?.rules ?? [];
  const updateRule = (idx: number, patch: Partial<DeclarativeAnalyzerRule>) => {
    setSpec((prev) => {
      const next = [...(prev.analyzer?.rules ?? [])];
      next[idx] = { ...next[idx], ...patch };
      return { ...prev, analyzer: { rules: next } };
    });
  };
  const addRule = () => {
    if (rules.length >= 50) return;
    setSpec((prev) => ({
      ...prev,
      analyzer: {
        rules: [
          ...(prev.analyzer?.rules ?? []),
          {
            ruleId: `RULE-${String(rules.length + 1).padStart(3, "0")}`,
            category: "SAST",
            severity: "HIGH",
            title: "Новое правило проверки",
            includeGlobs: ["**/*.kt", "**/*.yml"],
            matcherType: "regex",
            pattern: "TODO_PATTERN",
            excludePatterns: [],
          },
        ],
      },
    }));
  };

  // Logic helpers
  const outputPorts = spec.outputPorts ?? [{ id: "OK", label: "OK" }];
  const logicRoutes = spec.logic?.routes ?? [];
  const updateLogicRoute = (idx: number, patch: Partial<DeclarativeLogicRoute>) => {
    setSpec((prev) => {
      const logic = prev.logic ?? { routes: [], fallbackPort: outputPorts[0]?.id || "OK" };
      const nextRoutes = [...logic.routes];
      nextRoutes[idx] = { ...nextRoutes[idx], ...patch };
      return { ...prev, logic: { ...logic, routes: nextRoutes } };
    });
  };

  const sandboxBadge = spec.category === "ACTION" ? "EGRESS_EXTERNAL" : "INTERNAL_ONLY";

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Редактор новой ноды"
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/50 p-2 sm:p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="flex h-[min(780px,90dvh)] w-full max-w-[1140px] flex-col overflow-hidden rounded-[20px] border border-[#8c9baa]/55 bg-[#ffffff] shadow-2xl">
        {/* Top Modal Bar */}
        <div className="flex items-center justify-between gap-3 border-b border-[#8c9baa]/30 px-6 py-3.5">
          <div className="flex min-w-0 items-center gap-2.5">
            <h2 className="truncate text-[16px] font-semibold tracking-[-0.02em] text-[#000000]">
              {isEditing
                ? `Редактирование «${editingInstallation?.name}»`
                : "Новая нода"}
            </h2>
            <span className="fm-mono hidden shrink-0 rounded-full border border-[#8c9baa]/40 px-2 py-0.5 text-[10.5px] font-medium text-[#636f7b] sm:inline-flex">
              {sandboxBadge}
            </span>
          </div>

          <div className="flex shrink-0 items-center gap-1.5">
            <input
              ref={fileImportRef}
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(e) => {
                void handleImportFile(e.target.files?.[0] ?? null);
                e.target.value = "";
              }}
            />
            <button
              type="button"
              onClick={() => fileImportRef.current?.click()}
              title="Импорт JSON"
              aria-label="Импорт JSON"
              className="fm-focus inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-full px-2.5 text-[12px] font-medium text-[#636f7b] transition-colors hover:bg-[#f8fafc] hover:text-[#000000]"
            >
              <Upload className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Импорт</span>
            </button>
            <button
              type="button"
              onClick={handleExportJson}
              title="Экспорт JSON"
              aria-label="Экспорт JSON"
              className="fm-focus inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-full px-2.5 text-[12px] font-medium text-[#636f7b] transition-colors hover:bg-[#f8fafc] hover:text-[#000000]"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Экспорт</span>
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Закрыть конструктор"
              className="fm-focus ml-1 inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-full text-[#636f7b] transition-colors hover:bg-[#f8fafc] hover:text-[#000000]"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Clean Underline Step Tabs */}
        <div className="flex items-center gap-6 overflow-x-auto border-b border-[#8c9baa]/30 px-6">
          {STEP_META.map((item) => {
            const active = step === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setStep(item.id)}
                className={`fm-focus relative inline-flex h-[42px] shrink-0 cursor-pointer items-center whitespace-nowrap text-[13px] transition-colors ${
                  active
                    ? "font-semibold text-[#000000] after:absolute after:inset-x-0 after:bottom-0 after:h-[2px] after:rounded-full after:bg-[#0080ff]"
                    : "font-medium text-[#636f7b] hover:text-[#000000]"
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </div>

        {/* Main Split Body: Left Editor + Right Live Preview */}
        <div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[minmax(0,1fr)_368px]">
          {/* Left Scrollable Step Body */}
          <div className="fm-scroll min-h-0 space-y-5 overflow-y-auto overscroll-contain p-6">
            {errorText && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-[12px] border border-[#dc2626]/45 bg-[#ffd6e0]/45 px-3.5 py-2.5 text-[12.5px] text-[#842029]"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <span className="break-words">{errorText}</span>
              </div>
            )}

            {/* STEP 1: Basics & Ports */}
            {step === 1 && (
              <div className="space-y-5">
                {!isEditing && blueprints.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[12px] font-medium text-[#636f7b]">Заготовка:</span>
                    {blueprints.map((bp) => (
                      <button
                        key={bp.id}
                        type="button"
                        onClick={() => handleApplyBlueprint(bp)}
                        title={bp.description}
                        className="fm-btn-outline fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1.5 px-3 text-[12px] font-medium"
                      >
                        <span>{bp.name}</span>
                        <span className="fm-mono text-[10px] text-[#636f7b]">
                          {bp.spec.category}
                        </span>
                      </button>
                    ))}
                  </div>
                )}

                <div>
                  <label className="block text-[12px] font-medium text-[#636f7b]">Категория</label>
                  <div className="mt-1.5 inline-grid w-full grid-cols-3 rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc] p-1">
                    {(["ANALYZER", "LOGIC", "ACTION"] as DeclarativeCategory[]).map((cat) => {
                      const active = spec.category === cat;
                      return (
                        <button
                          key={cat}
                          type="button"
                          disabled={isEditing}
                          onClick={() => handleCategoryChange(cat)}
                          className={`fm-focus min-h-[34px] cursor-pointer rounded-[9px] px-3 text-[12.5px] font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
                            active
                              ? "bg-[#000000] text-[#ffffff]"
                              : "text-[#636f7b] hover:text-[#000000]"
                          }`}
                        >
                          {cat}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <label className="block text-[12px] font-medium text-[#636f7b]">
                      Название
                    </label>
                    <input
                      type="text"
                      value={spec.displayName}
                      onChange={(e) => {
                        const nextName = e.target.value;
                        setSpec((prev) => ({
                          ...prev,
                          displayName: nextName,
                          pluginId:
                            !slugTouched && !isEditing
                              ? `${prefixForCategory(prev.category)}${slugifyName(nextName)}`
                              : prev.pluginId,
                        }));
                      }}
                      placeholder="Например, Spring Config Guard"
                      className="fm-focus mt-1.5 min-h-[38px] w-full rounded-[10px] border border-[#8c9baa]/55 px-3 text-[16px] text-[#000000] sm:text-[13px]"
                    />
                  </div>
                  <div>
                    <label className="block text-[12px] font-medium text-[#636f7b]">
                      ID плагина
                    </label>
                    <input
                      type="text"
                      disabled={isEditing}
                      value={spec.pluginId}
                      onChange={(e) => {
                        setSlugTouched(true);
                        setSpec((prev) => ({ ...prev, pluginId: e.target.value.toLowerCase() }));
                      }}
                      placeholder={`${prefixForCategory(spec.category)}my-rule`}
                      className="fm-mono fm-focus mt-1.5 min-h-[38px] w-full rounded-[10px] border border-[#8c9baa]/55 px-3 text-[16px] text-[#000000] disabled:opacity-60 sm:text-[13px]"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[12px] font-medium text-[#636f7b]">Описание</label>
                  <textarea
                    rows={2}
                    value={spec.description ?? ""}
                    onChange={(e) => setSpec((prev) => ({ ...prev, description: e.target.value }))}
                    placeholder="Краткое назначение ноды"
                    className="fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa]/55 px-3 py-2 text-[16px] text-[#000000] sm:text-[13px]"
                  />
                </div>

                {spec.category === "LOGIC" && (
                  <div className="border-t border-[#8c9baa]/25 pt-4">
                    <div className="flex items-center justify-between">
                      <span className="text-[12.5px] font-semibold text-[#000000]">
                        Выходные порты ({outputPorts.length}/8)
                      </span>
                      <button
                        type="button"
                        disabled={outputPorts.length >= 8}
                        onClick={() =>
                          setSpec((prev) => {
                            const nextId = `PORT_${(prev.outputPorts?.length ?? 0) + 1}`;
                            return {
                              ...prev,
                              outputPorts: [
                                ...(prev.outputPorts ?? []),
                                { id: nextId, label: nextId },
                              ],
                            };
                          })
                        }
                        className="fm-btn-outline fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1 px-2.5 text-[11.5px] font-medium disabled:opacity-40"
                      >
                        <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                        Порт
                      </button>
                    </div>
                    <div className="mt-2.5 space-y-2">
                      {outputPorts.map((port, idx) => (
                        <div key={idx} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={port.id}
                            onChange={(e) => {
                              const idVal = e.target.value.trim();
                              setSpec((prev) => {
                                const list = [...(prev.outputPorts ?? [])];
                                list[idx] = { ...list[idx], id: idVal, label: idVal };
                                return { ...prev, outputPorts: list };
                              });
                            }}
                            placeholder="BLOCK"
                            className="fm-mono fm-focus min-h-[36px] flex-1 rounded-[10px] border border-[#8c9baa]/55 px-2.5 text-[12.5px]"
                          />
                          <button
                            type="button"
                            disabled={outputPorts.length <= 1}
                            onClick={() =>
                              setSpec((prev) => ({
                                ...prev,
                                outputPorts: (prev.outputPorts ?? []).filter((_, i) => i !== idx),
                              }))
                            }
                            aria-label="Удалить порт"
                            className="fm-focus inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-full text-[#636f7b] hover:text-[#dc2626] disabled:opacity-30"
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* STEP 2: Parameters Schema + Action Secrets/Allowlist */}
            {step === 2 && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-[13.5px] font-semibold text-[#000000]">
                    Параметры формы ({(spec.params ?? []).length})
                  </h3>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setShowSchemaJson((v) => !v)}
                      className="fm-btn-outline fm-focus inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 px-3 text-[12px] font-medium"
                    >
                      <Code2 className="h-3.5 w-3.5" aria-hidden="true" />
                      {showSchemaJson ? "Скрыть схему" : "JSON Schema"}
                    </button>
                    <button
                      type="button"
                      onClick={addParam}
                      className="fm-btn-signal fm-focus inline-flex min-h-[32px] cursor-pointer items-center gap-1 px-3 text-[12px] font-semibold"
                    >
                      <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                      Поле
                    </button>
                  </div>
                </div>

                {(spec.params ?? []).length === 0 ? (
                  <p className="rounded-[12px] border border-dashed border-[#8c9baa]/45 px-4 py-6 text-center text-[12.5px] text-[#636f7b]">
                    Параметров пока нет. Добавьте поля, которые будут отображаться в инспекторе ноды.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {(spec.params ?? []).map((param, idx) => (
                      <div
                        key={idx}
                        className="space-y-2 rounded-[12px] border border-[#8c9baa]/35 bg-[#f8fafc]/50 p-3"
                      >
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_126px_1fr_auto]">
                          <input
                            type="text"
                            value={param.key}
                            onChange={(e) => updateParam(idx, { key: e.target.value })}
                            placeholder="ключ (severity)"
                            className="fm-mono fm-focus min-h-[36px] rounded-[9px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 text-[12.5px]"
                          />
                          <select
                            value={param.type}
                            onChange={(e) => {
                              const t = e.target.value as DeclarativeParamType;
                              updateParam(idx, {
                                type: t,
                                enum: t === "enum" ? param.enum ?? ["LOW", "MEDIUM", "HIGH", "CRITICAL"] : undefined,
                                default: t === "boolean" ? false : t === "integer" || t === "number" ? 0 : t === "array" ? [] : "",
                              });
                            }}
                            className="fm-focus min-h-[36px] rounded-[9px] border border-[#8c9baa]/55 bg-[#ffffff] px-2 text-[12.5px]"
                          >
                            <option value="string">string</option>
                            <option value="enum">enum</option>
                            <option value="integer">integer</option>
                            <option value="number">number</option>
                            <option value="boolean">boolean</option>
                            <option value="array">array</option>
                          </select>
                          <input
                            type="text"
                            value={
                              param.default === undefined
                                ? ""
                                : typeof param.default === "string"
                                  ? param.default
                                  : JSON.stringify(param.default)
                            }
                            onChange={(e) => {
                              const raw = e.target.value;
                              let val: unknown = raw;
                              if (param.type === "boolean") val = raw === "true";
                              else if (param.type === "integer" || param.type === "number") val = Number(raw) || 0;
                              updateParam(idx, { default: val });
                            }}
                            placeholder="по умолчанию"
                            className="fm-focus min-h-[36px] rounded-[9px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 text-[12.5px]"
                          />
                          <button
                            type="button"
                            onClick={() => removeParam(idx)}
                            aria-label="Удалить параметр"
                            className="fm-focus inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-full text-[#636f7b] hover:text-[#dc2626]"
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        </div>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_auto]">
                          <input
                            type="text"
                            value={param.description ?? ""}
                            onChange={(e) => updateParam(idx, { description: e.target.value })}
                            placeholder="Подпись поля"
                            className="fm-focus min-h-[34px] rounded-[9px] border border-[#8c9baa]/45 bg-[#ffffff] px-2.5 text-[12px]"
                          />
                          <label className="inline-flex cursor-pointer items-center gap-1.5 px-1 text-[12px] text-[#636f7b]">
                            <input
                              type="checkbox"
                              checked={Boolean(param.required)}
                              onChange={(e) => updateParam(idx, { required: e.target.checked })}
                            />
                            Обязательное
                          </label>
                        </div>
                        {param.type === "enum" && (
                          <input
                            type="text"
                            value={(param.enum ?? []).join(", ")}
                            onChange={(e) =>
                              updateParam(idx, {
                                enum: e.target.value
                                  .split(",")
                                  .map((s) => s.trim())
                                  .filter(Boolean),
                              })
                            }
                            placeholder="Варианты через запятую: LOW, MEDIUM, HIGH, CRITICAL"
                            className="fm-mono fm-focus min-h-[34px] w-full rounded-[9px] border border-[#8c9baa]/45 bg-[#ffffff] px-2.5 text-[12px]"
                          />
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {spec.category === "ACTION" && (
                  <div className="grid grid-cols-1 gap-4 border-t border-[#8c9baa]/25 pt-4 sm:grid-cols-2">
                    <div>
                      <label className="flex items-center gap-1.5 text-[12px] font-medium text-[#636f7b]">
                        <Globe className="h-3.5 w-3.5" aria-hidden="true" />
                        Разрешённые хосты
                      </label>
                      <textarea
                        rows={3}
                        value={(spec.egressAllowlist ?? []).join("\n")}
                        onChange={(e) =>
                          setSpec((prev) => ({
                            ...prev,
                            egressAllowlist: e.target.value
                              .split(/[\n,]+/)
                              .map((s) => s.trim())
                              .filter(Boolean),
                          }))
                        }
                        placeholder="tracker.example.com"
                        className="fm-mono fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 py-1.5 text-[12px]"
                      />
                    </div>
                    <div>
                      <label className="flex items-center gap-1.5 text-[12px] font-medium text-[#636f7b]">
                        <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                        Ключи секретов (опционально)
                      </label>
                      <textarea
                        rows={3}
                        value={(spec.requiredSecretKeys ?? []).join("\n")}
                        onChange={(e) =>
                          setSpec((prev) => ({
                            ...prev,
                            requiredSecretKeys: e.target.value
                              .split(/[\n,]+/)
                              .map((s) => s.trim())
                              .filter(Boolean),
                          }))
                        }
                        placeholder="apiToken"
                        className="fm-mono fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 py-1.5 text-[12px]"
                      />
                    </div>
                  </div>
                )}

                {showSchemaJson && (
                  <pre className="fm-mono fm-code-block max-h-[200px] overflow-auto rounded-[12px] p-3 text-[11.5px]">
                    {JSON.stringify(previewSchema, null, 2)}
                  </pre>
                )}
              </div>
            )}

            {/* STEP 3: Category Logic Builder */}
            {step === 3 && spec.category === "ANALYZER" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-[13.5px] font-semibold text-[#000000]">
                    Правила анализа ({rules.length}/50)
                  </h3>
                  <button
                    type="button"
                    onClick={addRule}
                    disabled={rules.length >= 50}
                    className="fm-btn-signal fm-focus inline-flex min-h-[32px] cursor-pointer items-center gap-1 px-3 text-[12px] font-semibold"
                  >
                    <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                    Правило
                  </button>
                </div>

                {rules.map((rule, idx) => (
                  <div
                    key={idx}
                    className="space-y-2.5 rounded-[12px] border border-[#8c9baa]/35 bg-[#f8fafc]/50 p-3.5"
                  >
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-[130px_104px_126px_1fr_auto]">
                      <input
                        type="text"
                        value={rule.ruleId}
                        onChange={(e) => updateRule(idx, { ruleId: e.target.value })}
                        placeholder="RULE-001"
                        className="fm-mono fm-focus min-h-[36px] rounded-[9px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 text-[12px]"
                      />
                      <select
                        value={rule.category}
                        onChange={(e) =>
                          updateRule(idx, { category: e.target.value as "SECRET" | "SAST" | "SCA" })
                        }
                        className="fm-focus min-h-[36px] rounded-[9px] border border-[#8c9baa]/55 bg-[#ffffff] px-2 text-[12px]"
                      >
                        <option value="SAST">SAST</option>
                        <option value="SECRET">SECRET</option>
                        <option value="SCA">SCA</option>
                      </select>
                      <input
                        type="text"
                        value={rule.severity}
                        onChange={(e) => updateRule(idx, { severity: e.target.value })}
                        placeholder="HIGH"
                        className="fm-mono fm-focus min-h-[36px] rounded-[9px] border border-[#8c9baa]/55 bg-[#ffffff] px-2 text-[12px]"
                      />
                      <input
                        type="text"
                        value={rule.title}
                        onChange={(e) => updateRule(idx, { title: e.target.value })}
                        placeholder="Заголовок находки"
                        className="fm-focus min-h-[36px] rounded-[9px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 text-[12.5px]"
                      />
                      <button
                        type="button"
                        disabled={rules.length <= 1}
                        onClick={() =>
                          setSpec((prev) => ({
                            ...prev,
                            analyzer: {
                              rules: (prev.analyzer?.rules ?? []).filter((_, i) => i !== idx),
                            },
                          }))
                        }
                        aria-label="Удалить правило"
                        className="fm-focus inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-full text-[#636f7b] hover:text-[#dc2626] disabled:opacity-30"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>

                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      <select
                        value={rule.matcherType}
                        onChange={(e) =>
                          updateRule(idx, {
                            matcherType: e.target.value as DeclarativeAnalyzerRule["matcherType"],
                            presenceMode: e.target.value === "file_presence" ? "absent" : undefined,
                          })
                        }
                        className="fm-focus min-h-[36px] rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-2.5 text-[12.5px]"
                      >
                        <option value="regex">regex (RE2)</option>
                        <option value="config_key">config_key (YAML/properties/JSON)</option>
                        <option value="file_presence">file_presence (exists/absent)</option>
                      </select>
                      <input
                        type="text"
                        value={(rule.excludePatterns ?? []).join(", ")}
                        onChange={(e) =>
                          updateRule(idx, {
                            excludePatterns: e.target.value
                              .split(",")
                              .map((s) => s.trim())
                              .filter(Boolean),
                          })
                        }
                        placeholder="excludePatterns (Control-исключения)"
                        className="fm-mono fm-focus min-h-[36px] rounded-[10px] border border-[#8c9baa] px-2.5 text-[12px]"
                      />
                      <input
                        type="text"
                        value={(rule.includeGlobs ?? []).join(", ")}
                        onChange={(e) =>
                          updateRule(idx, {
                            includeGlobs: e.target.value
                              .split(",")
                              .map((s) => s.trim())
                              .filter(Boolean),
                          })
                        }
                        placeholder="includeGlobs: **/*.kt, **/*.yml"
                        className="fm-mono fm-focus min-h-[36px] rounded-[10px] border border-[#8c9baa] px-2.5 text-[12px]"
                      />
                      <input
                        type="text"
                        value={(rule.excludeGlobs ?? []).join(", ")}
                        onChange={(e) =>
                          updateRule(idx, {
                            excludeGlobs: e.target.value
                              .split(",")
                              .map((s) => s.trim())
                              .filter(Boolean),
                          })
                        }
                        placeholder="excludeGlobs: **/test/**, **/*.md"
                        className="fm-mono fm-focus min-h-[36px] rounded-[10px] border border-[#8c9baa] px-2.5 text-[12px]"
                      />
                    </div>

                    {rule.matcherType === "regex" && (
                      <input
                        type="text"
                        value={rule.pattern ?? ""}
                        onChange={(e) => updateRule(idx, { pattern: e.target.value })}
                        placeholder="RE2 паттерн (≤ 512 символов)"
                        className="fm-mono fm-focus min-h-[36px] w-full rounded-[10px] border border-[#8c9baa] px-2.5 text-[12.5px]"
                      />
                    )}
                    {rule.matcherType === "config_key" && (
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                        <input
                          type="text"
                          value={rule.configKey ?? ""}
                          onChange={(e) => updateRule(idx, { configKey: e.target.value })}
                          placeholder="Ключ: management.endpoints.web.exposure.include"
                          className="fm-mono fm-focus min-h-[36px] rounded-[10px] border border-[#8c9baa] px-2.5 text-[12px]"
                        />
                        <input
                          type="text"
                          value={rule.configValuePattern ?? ""}
                          onChange={(e) => updateRule(idx, { configValuePattern: e.target.value })}
                          placeholder="RE2 значения (например ^\\*$)"
                          className="fm-mono fm-focus min-h-[36px] rounded-[10px] border border-[#8c9baa] px-2.5 text-[12px]"
                        />
                      </div>
                    )}
                    {rule.matcherType === "file_presence" && (
                      <select
                        value={rule.presenceMode ?? "absent"}
                        onChange={(e) =>
                          updateRule(idx, { presenceMode: e.target.value as "exists" | "absent" })
                        }
                        className="fm-focus min-h-[36px] rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-2.5 text-[12.5px]"
                      >
                        <option value="absent">Сработать, если файл отсутствует (absent)</option>
                        <option value="exists">Сработать, если файл присутствует (exists)</option>
                      </select>
                    )}

                    <input
                      type="text"
                      value={rule.remediation ?? ""}
                      onChange={(e) => updateRule(idx, { remediation: e.target.value })}
                      placeholder="Рекомендация по исправлению (remediation)"
                      className="fm-focus min-h-[34px] w-full rounded-[10px] border border-[#8c9baa]/70 px-2.5 text-[12px]"
                    />
                  </div>
                ))}
              </div>
            )}

            {step === 3 && spec.category === "LOGIC" && (
              <div className="space-y-5">
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <h3 className="text-[13.5px] font-semibold text-[#000000]">
                      Вычисляемые метрики
                    </h3>
                    <button
                      type="button"
                      onClick={() =>
                        setSpec((prev) => ({
                          ...prev,
                          logic: {
                            ...(prev.logic ?? { routes: [], fallbackPort: outputPorts[0]?.id || "OK" }),
                            computedVars: [
                              ...(prev.logic?.computedVars ?? []),
                              {
                                name: "riskScore",
                                kind: "weighted_score",
                                criticalWeight: 10,
                                highWeight: 5,
                                mediumWeight: 2,
                                lowWeight: 1,
                              },
                            ],
                          },
                        }))
                      }
                      className="fm-btn-outline fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1 px-2.5 text-[11.5px]"
                    >
                      <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                      Метрика
                    </button>
                  </div>
                  {(spec.logic?.computedVars ?? []).map((cv, idx) => (
                    <div
                      key={idx}
                      className="grid grid-cols-2 gap-2 rounded-[12px] border border-[#8c9baa]/35 bg-[#f8fafc]/50 p-2.5 sm:grid-cols-6"
                    >
                      <input
                        type="text"
                        value={cv.name}
                        onChange={(e) =>
                          setSpec((prev) => {
                            const list = [...(prev.logic?.computedVars ?? [])];
                            list[idx] = { ...list[idx], name: e.target.value };
                            return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                          })
                        }
                        placeholder="riskScore"
                        className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                      />
                      <select
                        value={cv.kind}
                        onChange={(e) =>
                          setSpec((prev) => {
                            const list = [...(prev.logic?.computedVars ?? [])];
                            list[idx] = {
                              ...list[idx],
                              kind: e.target.value as "weighted_score" | "finding_count" | "template",
                            };
                            return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                          })
                        }
                        className="fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] bg-[#ffffff] px-1.5 text-[12px]"
                      >
                        <option value="weighted_score">weighted_score</option>
                        <option value="finding_count">finding_count</option>
                        <option value="template">template</option>
                      </select>
                      {cv.kind === "weighted_score" ? (
                        <>
                          <input
                            type="number"
                            value={cv.criticalWeight ?? 10}
                            onChange={(e) =>
                              setSpec((prev) => {
                                const list = [...(prev.logic?.computedVars ?? [])];
                                list[idx] = { ...list[idx], criticalWeight: Number(e.target.value) };
                                return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                              })
                            }
                            title="Вес CRITICAL"
                            className="fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                          />
                          <input
                            type="number"
                            value={cv.highWeight ?? 5}
                            onChange={(e) =>
                              setSpec((prev) => {
                                const list = [...(prev.logic?.computedVars ?? [])];
                                list[idx] = { ...list[idx], highWeight: Number(e.target.value) };
                                return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                              })
                            }
                            title="Вес HIGH"
                            className="fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                          />
                          <input
                            type="number"
                            value={cv.mediumWeight ?? 2}
                            onChange={(e) =>
                              setSpec((prev) => {
                                const list = [...(prev.logic?.computedVars ?? [])];
                                list[idx] = { ...list[idx], mediumWeight: Number(e.target.value) };
                                return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                              })
                            }
                            title="Вес MEDIUM"
                            className="fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                          />
                        </>
                      ) : cv.kind === "finding_count" ? (
                        <>
                          <input
                            type="text"
                            value={cv.filterCategory ?? ""}
                            onChange={(e) =>
                              setSpec((prev) => {
                                const list = [...(prev.logic?.computedVars ?? [])];
                                list[idx] = { ...list[idx], filterCategory: e.target.value };
                                return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                              })
                            }
                            placeholder="Категория (SAST/SECRET/SCA)"
                            className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                          />
                          <input
                            type="text"
                            value={cv.filterSeverity ?? ""}
                            onChange={(e) =>
                              setSpec((prev) => {
                                const list = [...(prev.logic?.computedVars ?? [])];
                                list[idx] = { ...list[idx], filterSeverity: e.target.value };
                                return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                              })
                            }
                            placeholder="Severity (CRITICAL/HIGH)"
                            className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                          />
                          <input
                            type="text"
                            value={cv.filterRuleId ?? ""}
                            onChange={(e) =>
                              setSpec((prev) => {
                                const list = [...(prev.logic?.computedVars ?? [])];
                                list[idx] = { ...list[idx], filterRuleId: e.target.value };
                                return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                              })
                            }
                            placeholder="ruleId (опц.)"
                            className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                          />
                        </>
                      ) : (
                        <input
                          type="text"
                          value={cv.template ?? ""}
                          onChange={(e) =>
                            setSpec((prev) => {
                              const list = [...(prev.logic?.computedVars ?? [])];
                              list[idx] = { ...list[idx], template: e.target.value };
                              return { ...prev, logic: { ...prev.logic!, computedVars: list } };
                            })
                          }
                          placeholder="Шаблон: risk={{ vars.riskScore }}"
                          className="fm-mono fm-focus col-span-3 min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                        />
                      )}
                      <button
                        type="button"
                        onClick={() =>
                          setSpec((prev) => ({
                            ...prev,
                            logic: {
                              ...prev.logic!,
                              computedVars: (prev.logic?.computedVars ?? []).filter((_, i) => i !== idx),
                            },
                          }))
                        }
                        aria-label="Удалить метрику"
                        className="fm-focus inline-flex h-[34px] cursor-pointer items-center justify-center rounded-[8px] border border-[#8c9baa]/60 text-[#636f7b] hover:border-[#dc2626] hover:text-[#dc2626]"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  ))}
                </div>

                <div className="space-y-3 border-t border-[#8c9baa]/25 pt-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-[13.5px] font-semibold text-[#000000]">
                      Маршруты ({logicRoutes.length}/30)
                    </h3>
                    <button
                      type="button"
                      onClick={() =>
                        setSpec((prev) => ({
                          ...prev,
                          logic: {
                            ...(prev.logic ?? { routes: [], fallbackPort: outputPorts[0]?.id || "OK" }),
                            routes: [
                              ...(prev.logic?.routes ?? []),
                              {
                                name: `Маршрут ${logicRoutes.length + 1}`,
                                matchMode: "ALL",
                                outputPort: outputPorts[0]?.id || "OK",
                                gate: "",
                                conditions: [{ field: "stats.total", operator: "gte", value: "1" }],
                              },
                            ],
                          },
                        }))
                      }
                      className="fm-btn-signal fm-focus inline-flex min-h-[30px] cursor-pointer items-center gap-1 px-2.5 text-[11.5px] font-semibold"
                    >
                      <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                      Маршрут
                    </button>
                  </div>

                  {logicRoutes.map((route, idx) => {
                    const conds =
                      route.conditions.length > 0
                        ? route.conditions
                        : [{ field: "stats.total", operator: "gte" as const, value: "1" }];
                    return (
                      <div key={idx} className="space-y-2 rounded-[12px] border border-[#8c9baa]/35 bg-[#f8fafc]/50 p-3">
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_88px_110px_100px_auto]">
                          <input
                            type="text"
                            value={route.name ?? ""}
                            onChange={(e) => updateLogicRoute(idx, { name: e.target.value })}
                            placeholder="Название маршрута"
                            className="fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2.5 text-[12px]"
                          />
                          <select
                            value={route.matchMode ?? "ALL"}
                            onChange={(e) =>
                              updateLogicRoute(idx, { matchMode: e.target.value as "ALL" | "ANY" })
                            }
                            title="Режим совпадения условий"
                            className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] bg-[#ffffff] px-2 text-[12px]"
                          >
                            <option value="ALL">ALL</option>
                            <option value="ANY">ANY</option>
                          </select>
                          <select
                            value={route.outputPort}
                            onChange={(e) => updateLogicRoute(idx, { outputPort: e.target.value })}
                            className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] bg-[#ffffff] px-2 text-[12px]"
                          >
                            {outputPorts.map((p) => (
                              <option key={p.id} value={p.id}>
                                → {p.id}
                              </option>
                            ))}
                          </select>
                          <select
                            value={route.gate ?? ""}
                            onChange={(e) =>
                              updateLogicRoute(idx, {
                                gate: e.target.value as "" | "PASS" | "WARN" | "FAIL",
                              })
                            }
                            className="fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] bg-[#ffffff] px-2 text-[12px]"
                          >
                            <option value="">Gate: —</option>
                            <option value="PASS">PASS</option>
                            <option value="WARN">WARN</option>
                            <option value="FAIL">FAIL</option>
                          </select>
                          <button
                            type="button"
                            onClick={() =>
                              setSpec((prev) => ({
                                ...prev,
                                logic: {
                                  ...prev.logic!,
                                  routes: (prev.logic?.routes ?? []).filter((_, i) => i !== idx),
                                },
                              }))
                            }
                            aria-label="Удалить маршрут"
                            className="fm-focus inline-flex h-[34px] w-[34px] cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/60 text-[#636f7b] hover:border-[#dc2626] hover:text-[#dc2626]"
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        </div>
                        <div className="space-y-1.5">
                          {conds.map((cond, cIdx) => (
                            <div key={cIdx} className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_130px_1fr_auto]">
                              <input
                                type="text"
                                value={cond.field}
                                onChange={(e) =>
                                  updateLogicRoute(idx, {
                                    conditions: conds.map((c, j) =>
                                      j === cIdx ? { ...c, field: e.target.value } : c,
                                    ),
                                  })
                                }
                                placeholder="vars.riskScore / stats.critical"
                                className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                              />
                              <select
                                value={cond.operator}
                                onChange={(e) =>
                                  updateLogicRoute(idx, {
                                    conditions: conds.map((c, j) =>
                                      j === cIdx
                                        ? {
                                            ...c,
                                            operator: e.target.value as DeclarativeLogicRoute["conditions"][0]["operator"],
                                          }
                                        : c,
                                    ),
                                  })
                                }
                                className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] bg-[#ffffff] px-2 text-[12px]"
                              >
                                <option value="gte">&gt;= (gte)</option>
                                <option value="gt">&gt; (gt)</option>
                                <option value="lte">&lt;= (lte)</option>
                                <option value="lt">&lt; (lt)</option>
                                <option value="eq">== (eq)</option>
                                <option value="neq">!= (neq)</option>
                                <option value="contains">contains</option>
                                <option value="matches">matches (RE2)</option>
                              </select>
                              <input
                                type="text"
                                value={cond.value}
                                onChange={(e) =>
                                  updateLogicRoute(idx, {
                                    conditions: conds.map((c, j) =>
                                      j === cIdx ? { ...c, value: e.target.value } : c,
                                    ),
                                  })
                                }
                                placeholder="{{ params.blockThreshold }}"
                                className="fm-mono fm-focus min-h-[34px] rounded-[8px] border border-[#8c9baa] px-2 text-[12px]"
                              />
                              <button
                                type="button"
                                disabled={conds.length <= 1}
                                onClick={() =>
                                  updateLogicRoute(idx, {
                                    conditions: conds.filter((_, j) => j !== cIdx),
                                  })
                                }
                                aria-label="Удалить условие"
                                className="fm-focus inline-flex h-[34px] w-[34px] cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/50 text-[#636f7b] hover:border-[#dc2626] hover:text-[#dc2626] disabled:opacity-35"
                              >
                                <X className="h-3.5 w-3.5" aria-hidden="true" />
                              </button>
                            </div>
                          ))}
                        </div>
                        <div className="flex flex-wrap items-center gap-2 pt-0.5">
                          <button
                            type="button"
                            onClick={() =>
                              updateLogicRoute(idx, {
                                conditions: [
                                  ...conds,
                                  { field: "stats.high", operator: "gte", value: "1" },
                                ],
                              })
                            }
                            className="fm-btn-outline fm-focus inline-flex min-h-[28px] cursor-pointer items-center gap-1 px-2 text-[11px]"
                          >
                            <Plus className="h-3 w-3" aria-hidden="true" />
                            Условие
                          </button>
                          <input
                            type="text"
                            value={Object.entries(route.setVars ?? {})
                              .map(([k, v]) => `${k}=${v}`)
                              .join(", ")}
                            onChange={(e) => {
                              const nextVars: Record<string, string> = {};
                              for (const part of e.target.value.split(",")) {
                                const [k, ...rest] = part.split("=");
                                if (k?.trim() && rest.join("=").trim()) {
                                  nextVars[k.trim()] = rest.join("=").trim();
                                }
                              }
                              updateLogicRoute(idx, {
                                setVars: Object.keys(nextVars).length > 0 ? nextVars : undefined,
                              });
                            }}
                            placeholder="setVars: decision=BLOCK, owner=appsec"
                            className="fm-mono fm-focus min-h-[28px] min-w-[180px] flex-1 rounded-[8px] border border-[#8c9baa]/70 px-2 text-[11.5px]"
                          />
                          <select
                            value={route.filterFindings?.minSeverity ?? ""}
                            onChange={(e) =>
                              updateLogicRoute(idx, {
                                filterFindings: e.target.value
                                  ? { ...route.filterFindings, minSeverity: e.target.value }
                                  : undefined,
                              })
                            }
                            title="Фильтрация Envelope.findings для этой ветки"
                            className="fm-mono fm-focus min-h-[28px] rounded-[8px] border border-[#8c9baa]/70 bg-[#ffffff] px-2 text-[11.5px]"
                          >
                            <option value="">Фильтр findings: все</option>
                            <option value="CRITICAL">≥ CRITICAL</option>
                            <option value="HIGH">≥ HIGH</option>
                            <option value="MEDIUM">≥ MEDIUM</option>
                            <option value="LOW">≥ LOW</option>
                          </select>
                        </div>
                      </div>
                    );
                  })}

                  <div className="grid grid-cols-1 gap-2 border-t border-[#8c9baa]/35 pt-2.5 sm:grid-cols-2">
                    <div>
                      <label className="block text-[11.5px] font-semibold text-[#222222]">
                        Fallback-порт (обязательный)
                      </label>
                      <select
                        value={spec.logic?.fallbackPort ?? outputPorts[0]?.id ?? "OK"}
                        onChange={(e) =>
                          setSpec((prev) => ({
                            ...prev,
                            logic: {
                              ...(prev.logic ?? { routes: [], fallbackPort: e.target.value }),
                              fallbackPort: e.target.value,
                            },
                          }))
                        }
                        className="fm-mono fm-focus mt-1 min-h-[36px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-2.5 text-[12.5px]"
                      >
                        {outputPorts.map((p) => (
                          <option key={p.id} value={p.id}>
                            {p.id}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11.5px] font-semibold text-[#222222]">
                        Fallback Gate
                      </label>
                      <select
                        value={spec.logic?.fallbackGate ?? "PASS"}
                        onChange={(e) =>
                          setSpec((prev) => ({
                            ...prev,
                            logic: {
                              ...(prev.logic ?? { routes: [], fallbackPort: outputPorts[0]?.id || "OK" }),
                              fallbackGate: e.target.value as "" | "PASS" | "WARN" | "FAIL",
                            },
                          }))
                        }
                        className="fm-focus mt-1 min-h-[36px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-2.5 text-[12.5px]"
                      >
                        <option value="">—</option>
                        <option value="PASS">PASS</option>
                        <option value="WARN">WARN</option>
                        <option value="FAIL">FAIL</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {step === 3 && spec.category === "ACTION" && (
              <div className="space-y-3">
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-[120px_1fr_110px]">
                  <select
                    value={spec.action?.method ?? "POST"}
                    onChange={(e) =>
                      setSpec((prev) => ({
                        ...prev,
                        action: {
                          ...(prev.action ?? { method: "POST", url: "https://hooks.example.com" }),
                          method: e.target.value as "POST" | "PUT" | "PATCH" | "GET",
                        },
                      }))
                    }
                    className="fm-mono fm-focus min-h-[38px] rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-2.5 text-[12.5px]"
                  >
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="PATCH">PATCH</option>
                    <option value="GET">GET</option>
                  </select>
                  <input
                    type="text"
                    value={spec.action?.url ?? ""}
                    onChange={(e) =>
                      setSpec((prev) => ({
                        ...prev,
                        action: { ...(prev.action ?? { method: "POST", url: "" }), url: e.target.value },
                      }))
                    }
                    placeholder="https://tracker.example.com/api/v1/issues"
                    className="fm-mono fm-focus min-h-[38px] rounded-[10px] border border-[#8c9baa] px-3 text-[12.5px]"
                  />
                  <input
                    type="number"
                    min={1}
                    max={30}
                    value={spec.action?.timeoutSeconds ?? 10}
                    onChange={(e) =>
                      setSpec((prev) => ({
                        ...prev,
                        action: {
                          ...(prev.action ?? { method: "POST", url: "" }),
                          timeoutSeconds: Math.min(30, Math.max(1, Number(e.target.value) || 10)),
                        },
                      }))
                    }
                    title="Таймаут (сек, макс. 30)"
                    className="fm-focus min-h-[38px] rounded-[10px] border border-[#8c9baa] px-2.5 text-[12.5px]"
                  />
                </div>

                <div>
                  <label className="block text-[12px] font-medium text-[#636f7b]">
                    Заголовки (JSON)
                  </label>
                  <textarea
                    rows={3}
                    value={JSON.stringify(spec.action?.headers ?? {}, null, 2)}
                    onChange={(e) => {
                      try {
                        const parsed = JSON.parse(e.target.value) as Record<string, string>;
                        setSpec((prev) => ({
                          ...prev,
                          action: { ...(prev.action ?? { method: "POST", url: "" }), headers: parsed },
                        }));
                      } catch {
                        // Allow intermediate typing
                      }
                    }}
                    className="fm-mono fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa]/55 px-3 py-2 text-[12px]"
                  />
                </div>

                <div>
                  <label className="block text-[12px] font-medium text-[#636f7b]">
                    Тело запроса
                  </label>
                  <textarea
                    rows={4}
                    value={spec.action?.bodyTemplate ?? ""}
                    onChange={(e) =>
                      setSpec((prev) => ({
                        ...prev,
                        action: { ...(prev.action ?? { method: "POST", url: "" }), bodyTemplate: e.target.value },
                      }))
                    }
                    className="fm-mono fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa]/55 px-3 py-2 text-[12px]"
                  />
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label className="block text-[12px] font-medium text-[#636f7b]">
                      Ожидаемые HTTP-статусы
                    </label>
                    <input
                      type="text"
                      value={(spec.action?.expectedStatuses ?? [200, 201, 202]).join(", ")}
                      onChange={(e) => {
                        const statuses = e.target.value
                          .split(",")
                          .map((s) => Number.parseInt(s.trim(), 10))
                          .filter((n) => Number.isFinite(n) && n >= 100 && n <= 599);
                        setSpec((prev) => ({
                          ...prev,
                          action: {
                            ...(prev.action ?? { method: "POST", url: "" }),
                            expectedStatuses: statuses.length > 0 ? statuses : [200],
                          },
                        }));
                      }}
                      placeholder="200, 201, 202"
                      className="fm-mono fm-focus mt-1.5 min-h-[38px] w-full rounded-[10px] border border-[#8c9baa]/55 px-3 text-[12px]"
                    />
                  </div>
                  <div>
                    <label className="block text-[12px] font-medium text-[#636f7b]">
                      Переменные из ответа (имя=путь)
                    </label>
                    <textarea
                      rows={2}
                      value={Object.entries(spec.action?.extractVars ?? {})
                        .map(([k, v]) => `${k}=${v}`)
                        .join("\n")}
                      onChange={(e) => {
                        const next: Record<string, string> = {};
                        for (const line of e.target.value.split("\n")) {
                          const [k, ...rest] = line.split("=");
                          if (k?.trim() && rest.join("=").trim()) {
                            next[k.trim()] = rest.join("=").trim();
                          }
                        }
                        setSpec((prev) => ({
                          ...prev,
                          action: { ...(prev.action ?? { method: "POST", url: "" }), extractVars: next },
                        }));
                      }}
                      placeholder="ticketKey=issue.key"
                      className="fm-mono fm-focus mt-1.5 w-full rounded-[10px] border border-[#8c9baa]/55 px-3 py-2 text-[12px]"
                    />
                  </div>
                </div>
              </div>
            )}

            {/* STEP 4: Test Bench & Publish Summary */}
            {step === 4 && (
              <div className="space-y-5">
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-[#16a34a]" aria-hidden="true" />
                      <h3 className="text-[13.5px] font-semibold text-[#000000]">
                        {spec.category === "ACTION" ? "Проверка запроса (dry-run)" : "Тестовый прогон"}
                      </h3>
                    </div>
                    <button
                      type="button"
                      disabled={testing}
                      onClick={() => void handleRunTestBench()}
                      className="fm-btn-signal fm-focus inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 px-3.5 text-[12.5px] font-semibold disabled:opacity-50"
                    >
                      {testing ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                      ) : (
                        <Play className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                      Запустить тест
                    </button>
                  </div>

                  {spec.category === "ANALYZER" ? (
                    <div className="space-y-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[12px] font-medium text-[#636f7b]">
                          Файлы фикстуры ({testFiles.length}/5)
                        </span>
                        <button
                          type="button"
                          disabled={testFiles.length >= 5}
                          onClick={() =>
                            setTestFiles((prev) => [
                              ...prev,
                              {
                                path: `src/main/kotlin/Sample${prev.length + 1}.kt`,
                                content: "// Пример кода или конфига\n",
                              },
                            ])
                          }
                          className="fm-btn-outline fm-focus inline-flex min-h-[28px] cursor-pointer items-center gap-1 px-2.5 text-[11.5px] disabled:opacity-45"
                        >
                          <Plus className="h-3 w-3" aria-hidden="true" />
                          Файл
                        </button>
                      </div>
                      {testFiles.map((tf, idx) => (
                        <div key={idx} className="space-y-2 rounded-[12px] border border-[#8c9baa]/35 bg-[#f8fafc]/50 p-3">
                          <div className="flex items-center gap-2">
                            <FileCode2 className="h-3.5 w-3.5 shrink-0 text-[#636f7b]" aria-hidden="true" />
                            <input
                              type="text"
                              value={tf.path}
                              onChange={(e) =>
                                setTestFiles((prev) =>
                                  prev.map((item, i) => (i === idx ? { ...item, path: e.target.value } : item)),
                                )
                              }
                              className="fm-mono fm-focus min-h-[32px] min-w-0 flex-1 rounded-[8px] border border-[#8c9baa]/55 bg-[#ffffff] px-2.5 text-[12px]"
                            />
                            {testFiles.length > 1 && (
                              <button
                                type="button"
                                onClick={() =>
                                  setTestFiles((prev) => prev.filter((_, i) => i !== idx))
                                }
                                aria-label="Удалить виртуальный файл"
                                className="fm-focus inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-full text-[#636f7b] hover:text-[#dc2626]"
                              >
                                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                              </button>
                            )}
                          </div>
                          <textarea
                            rows={4}
                            value={tf.content}
                            onChange={(e) =>
                              setTestFiles((prev) =>
                                prev.map((item, i) => (i === idx ? { ...item, content: e.target.value } : item)),
                              )
                            }
                            className="fm-mono fm-focus fm-code-block w-full rounded-[9px] px-3 py-2 text-[12px]"
                          />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-2.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="mr-1 text-[12px] font-medium text-[#636f7b]">Пресет:</span>
                        {Object.entries(ENVELOPE_PRESETS).map(([presetKey, presetObj]) => (
                          <button
                            key={presetKey}
                            type="button"
                            onClick={() => setTestEnvelopeText(JSON.stringify(presetObj, null, 2))}
                            className="fm-btn-outline fm-focus min-h-[28px] cursor-pointer px-3 text-[11.5px] font-medium"
                          >
                            {presetKey}
                          </button>
                        ))}
                      </div>
                      <textarea
                        rows={6}
                        value={testEnvelopeText}
                        onChange={(e) => setTestEnvelopeText(e.target.value)}
                        className="fm-mono fm-focus fm-code-block w-full rounded-[12px] px-3 py-2.5 text-[12px] leading-[1.5]"
                      />
                    </div>
                  )}

                  {testResult && (
                    <div
                      className={`overflow-hidden rounded-[12px] border text-[12px] ${
                        testResult.ok
                          ? "border-[#16a34a]/40 bg-[#c8f0d8]/35"
                          : "border-[#dc2626]/45 bg-[#ffd6e0]/40"
                      }`}
                    >
                      <div
                        className={`flex items-center justify-between gap-2 px-3.5 py-2.5 font-semibold ${
                          testResult.ok ? "text-[#0f5132]" : "text-[#842029]"
                        }`}
                      >
                        <span className="min-w-0 break-words">{testResult.summary}</span>
                        <span className="fm-mono shrink-0 text-[11px] opacity-85">
                          {testResult.durationMs} ms
                        </span>
                      </div>
                      {(testResult.validationErrors.length > 0 ||
                        testResult.findings.length > 0 ||
                        Boolean(testResult.envelopePatch) ||
                        Boolean(testResult.dryRunHttp)) && (
                        <div className="space-y-2 px-3 pb-3">
                          {testResult.validationErrors.length > 0 && (
                            <ul className="list-disc space-y-0.5 pl-4 text-[#842029]">
                              {testResult.validationErrors.map((ve, i) => (
                                <li key={i}>{ve}</li>
                              ))}
                            </ul>
                          )}
                          {testResult.findings.length > 0 && (
                            <div className="space-y-1.5">
                              {testResult.findings.map((f, i) => (
                                <div
                                  key={i}
                                  className="fm-mono fm-code-block rounded-[9px] px-3 py-2 text-[11.5px] leading-[1.45]"
                                >
                                  [{f.severity}] {f.findingClass} · {f.path}:{f.line ?? 1} —{" "}
                                  {f.maskedSnippet || f.description}
                                </div>
                              ))}
                            </div>
                          )}
                          {testResult.envelopePatch && (
                            <pre className="fm-mono fm-code-block fm-scroll max-h-[220px] overflow-auto rounded-[9px] p-3 text-[11.5px] leading-[1.5]">
                              {JSON.stringify(testResult.envelopePatch, null, 2)}
                            </pre>
                          )}
                          {testResult.dryRunHttp && (
                            <pre className="fm-mono fm-code-block fm-scroll max-h-[220px] overflow-auto rounded-[9px] p-3 text-[11.5px] leading-[1.5]">
                              {JSON.stringify(testResult.dryRunHttp, null, 2)}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-[#8c9baa]/25 pt-3.5 text-[11.5px] text-[#636f7b]">
                  <span>
                    Песочница: <span className="fm-mono font-semibold text-[#222222]">{sandboxBadge}</span>
                  </span>
                  <span>
                    Хосты:{" "}
                    <span className="fm-mono text-[#222222]">
                      {spec.category === "ACTION"
                        ? (spec.egressAllowlist ?? []).join(", ") || "не заданы"
                        : "нет"}
                    </span>
                  </span>
                  <span>
                    Секреты:{" "}
                    <span className="fm-mono text-[#222222]">
                      {spec.category === "ACTION"
                        ? (spec.requiredSecretKeys ?? []).join(", ") || "нет"
                        : "нет"}
                    </span>
                  </span>
                </div>
                {isEditing && editingInstallation?.status === "ACTIVE" && !isOwner && (
                  <p className="text-[12px] font-medium text-[#7c4a03]">
                    Изменение создаст pending-ревизию: текущие Workflow продолжат работать до одобрения OWNER.
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Right Persistent Live Preview Panel (flat surface, zero nested boxes) */}
          <aside className="fm-scroll hidden min-h-0 flex-col gap-5 overflow-y-auto overscroll-contain border-l border-[#8c9baa]/30 bg-[#f8fafc] p-5 lg:flex">
            <div className="space-y-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[#636f7b]">
                Предпросмотр ноды
              </p>
              <div className="rounded-[16px] border border-[#8c9baa]/50 bg-[#ffffff] p-3.5">
                <div className="flex items-start gap-2.5">
                  <span
                    className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
                    style={{ backgroundColor: previewCategoryMeta.flowmappPastel }}
                  >
                    <NodeCategoryIcon
                      iconKey={previewTemplate.iconKey}
                      className="h-4 w-4 stroke-[1.7] text-[#000000]"
                    />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[13.5px] font-semibold text-[#000000]">
                      {spec.displayName || "Без названия"}
                    </p>
                    <p className="fm-mono mt-0.5 truncate text-[11.5px] text-[#636f7b]">
                      {spec.pluginId}
                    </p>
                  </div>
                </div>
                {previewTemplate.outputs.length > 0 && (
                  <div className="mt-2.5 flex flex-wrap gap-1.5">
                    {previewTemplate.outputs.map((port) => (
                      <span
                        key={port}
                        className="fm-mono rounded-full border border-[#8c9baa]/45 bg-[#f8fafc] px-2 py-0.5 text-[10.5px] text-[#222222]"
                      >
                        {port}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[#636f7b]">
                Инспектор параметров
              </p>
              <SchemaParamsInspector
                nodeId={`preview_${spec.pluginId}`}
                config={previewConfig}
                secretBindings={previewSecretBindings}
                paramsJsonSchema={previewSchema}
                requiredSecretKeys={spec.category === "ACTION" ? spec.requiredSecretKeys ?? [] : []}
                secrets={secrets}
                canEdit
                onUpdateConfig={(k, v) => setPreviewConfig((prev) => ({ ...prev, [k]: v }))}
                onReplaceConfig={(next) => setPreviewConfig(next)}
                onUpdateSecretBinding={(paramKey, secretRef) => {
                  setPreviewSecretBindings((prev) => {
                    const rest = prev.filter((b) => b.paramKey !== paramKey);
                    return secretRef ? [...rest, { paramKey, secretRef }] : rest;
                  });
                }}
              />
            </div>
          </aside>
        </div>

        {/* Footer Navigation & Publish Actions */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#8c9baa]/30 bg-[#ffffff] px-6 py-3">
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={step === 1}
              onClick={() => setStep((s) => Math.max(1, s - 1) as BuilderStep)}
              className="fm-btn-outline fm-focus min-h-[36px] cursor-pointer px-3.5 text-[12.5px] font-medium disabled:opacity-40"
            >
              Назад
            </button>
            {step < 4 && (
              <button
                type="button"
                onClick={() => setStep((s) => Math.min(4, s + 1) as BuilderStep)}
                className="fm-btn-outline fm-focus min-h-[36px] cursor-pointer px-3.5 text-[12.5px] font-semibold"
              >
                Далее
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {launchSource === "canvas" && !isEditing && (
              <button
                type="button"
                disabled={saving}
                onClick={handlePlaceUnsavedOnCanvas}
                className="fm-btn-outline fm-focus min-h-[36px] cursor-pointer px-3.5 text-[12.5px] font-medium"
              >
                На холст
              </button>
            )}
            <button
              type="button"
              disabled={saving}
              onClick={() => void handlePersist("draft")}
              className="fm-btn-outline fm-focus min-h-[36px] cursor-pointer px-3.5 text-[12.5px] font-medium disabled:opacity-50"
            >
              Черновик
            </button>
            {!isOwner && (
              <button
                type="button"
                disabled={saving}
                onClick={() => void handlePersist("pending")}
                className="fm-btn-signal fm-focus inline-flex min-h-[36px] cursor-pointer items-center gap-1.5 px-4 text-[12.5px] font-semibold disabled:opacity-50"
              >
                {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
                На одобрение
              </button>
            )}
            {isOwner && (
              <button
                type="button"
                disabled={saving}
                onClick={() => void handlePersist("active")}
                className="fm-btn-signal fm-focus inline-flex min-h-[36px] cursor-pointer items-center gap-1.5 px-4 text-[12.5px] font-semibold disabled:opacity-50"
              >
                {saving ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                ) : (
                  <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                )}
                Сохранить и активировать
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
