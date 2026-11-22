"use client";

import { useEffect, useState, type FormEvent } from "react";
import {
  AlertTriangle,
  Blocks,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  KeyRound,
  Loader2,
  PackagePlus,
  Pencil,
  Power,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import type {
  DeclarativeBlueprintRecord,
  DeclarativePluginSpec,
  TestDeclarativePluginInput,
  TestDeclarativePluginResult,
} from "@/data/declarative-plugin-data";
import type {
  GqlSandboxProfile,
  InstallPluginFormInput,
  LivePluginRecord,
  PluginInstallationRecord,
  PluginInstallationStatus,
  PluginManifestRecord,
  PluginPresetRecord,
  PluginSourceMode,
  UpdatePluginInstallationFormInput,
} from "@/data/plugins-data";
import { canManageOwnerOnly, type SecretRecord } from "@/data/settings-data";
import type { UserRole } from "@/data/workflows-workspace-data";
import { DeclarativePluginBuilderModal } from "./DeclarativePluginBuilderModal";

interface PluginsTabProps {
  role: UserRole;
  backendConnected: boolean;
  presets: PluginPresetRecord[];
  installations: PluginInstallationRecord[];
  livePlugins: LivePluginRecord[];
  declarativeBlueprints: DeclarativeBlueprintRecord[];
  secrets: SecretRecord[];
  onInstallPlugin: (input: InstallPluginFormInput) => Promise<{
    installation: PluginInstallationRecord;
    plaintextPluginToken: string | null;
  }>;
  onApproveInstallation: (installationId: string) => Promise<PluginInstallationRecord>;
  onUpdateInstallation: (input: UpdatePluginInstallationFormInput) => Promise<{
    installation: PluginInstallationRecord;
    plaintextPluginToken: string | null;
  }>;
  onSetEnabled: (
    installationId: string,
    enabled: boolean,
    reason?: string,
  ) => Promise<PluginInstallationRecord>;
  onDeleteInstallation: (installationId: string, reason?: string) => Promise<boolean>;
  onTestDeclarativePlugin: (
    input: TestDeclarativePluginInput,
  ) => Promise<TestDeclarativePluginResult>;
  onRefresh: () => Promise<void>;
  onNotice: (text: string) => void;
}

const STATUS_BADGE: Record<
  PluginInstallationStatus,
  { label: string; cls: string }
> = {
  DRAFT: {
    label: "DRAFT",
    cls: "border-[#636f7b]/55 bg-[#f1f5f9] text-[#334155]",
  },
  PROVISIONING: {
    label: "PROVISIONING",
    cls: "border-[#0080ff]/55 bg-[#c5e0fb]/45 text-[#004a99]",
  },
  PENDING_APPROVAL: {
    label: "PENDING_APPROVAL",
    cls: "border-[#d97706]/55 bg-[#fff3c4] text-[#7c4a03]",
  },
  ACTIVE: {
    label: "ACTIVE",
    cls: "border-[#16a34a]/50 bg-[#c8f0d8]/75 text-[#0f5132]",
  },
  DISABLED: {
    label: "DISABLED",
    cls: "border-[#8c9baa]/60 bg-[#f1f5f9] text-[#475569]",
  },
  ERROR: {
    label: "ERROR",
    cls: "border-[#dc2626]/55 bg-[#ffd6e0]/75 text-[#842029]",
  },
  DELETING: {
    label: "DELETING",
    cls: "border-[#8c9baa]/60 bg-[#f8fafc] text-[#636f7b]",
  },
};

const SOURCE_MODE_LABEL: Record<PluginSourceMode, string> = {
  PRESET: "Пресет (K8s)",
  OCI_IMAGE: "OCI-образ (K8s)",
  EXTERNAL_PULL: "External Pull",
  DECLARATIVE: "Конструктор (Declarative)",
};

export function PluginsTab({
  role,
  backendConnected,
  presets,
  installations,
  livePlugins,
  declarativeBlueprints,
  secrets,
  onInstallPlugin,
  onApproveInstallation,
  onUpdateInstallation,
  onSetEnabled,
  onDeleteInstallation,
  onTestDeclarativePlugin,
  onRefresh,
  onNotice,
}: PluginsTabProps) {
  const canManage = canManageOwnerOnly(role);
  const canAuthorDeclarative = role === "owner" || role === "editor";
  const [builderOpen, setBuilderOpen] = useState(false);
  const [builderEditTarget, setBuilderEditTarget] = useState<PluginInstallationRecord | null>(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [modalTab, setModalTab] = useState<"presets" | "custom">("presets");
  const [autoApprovePreset, setAutoApprovePreset] = useState(false);

  // Custom OCI / EXTERNAL_PULL form state
  const [customName, setCustomName] = useState("");
  const [customSourceMode, setCustomSourceMode] = useState<"OCI_IMAGE" | "EXTERNAL_PULL">(
    "OCI_IMAGE",
  );
  const [customImageRef, setCustomImageRef] = useState("ghcr.io/secflow/");
  const [customProfile, setCustomProfile] = useState<GqlSandboxProfile>("INTERNAL_ONLY");
  const [customEgress, setCustomEgress] = useState("");
  const [customCpuReq, setCustomCpuReq] = useState("100m");
  const [customCpuLim, setCustomCpuLim] = useState("500m");
  const [customMemReq, setCustomMemReq] = useState("64Mi");
  const [customMemLim, setCustomMemLim] = useState("256Mi");
  const [customReplicas, setCustomReplicas] = useState("1");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // One-time token reveal after EXTERNAL_PULL install or rotation
  const [revealedToken, setRevealedToken] = useState<{
    installationName: string;
    token: string;
  } | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);

  // Expanded manifest preview & modals
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [approveTarget, setApproveTarget] = useState<PluginInstallationRecord | null>(null);
  const [editTarget, setEditTarget] = useState<PluginInstallationRecord | null>(null);
  const [editImageRef, setEditImageRef] = useState("");
  const [editReplicas, setEditReplicas] = useState("1");
  const [editEgress, setEditEgress] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<PluginInstallationRecord | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    if (!modalOpen && !approveTarget && !editTarget && !deleteTarget) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (deleteTarget) setDeleteTarget(null);
      else if (editTarget) setEditTarget(null);
      else if (approveTarget) setApproveTarget(null);
      else if (modalOpen) setModalOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [modalOpen, approveTarget, editTarget, deleteTarget]);

  const handleCopyToken = () => {
    if (!revealedToken) return;
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(revealedToken.token);
    }
    setCopiedToken(true);
    onNotice("Токен скопирован в буфер обмена");
    window.setTimeout(() => setCopiedToken(false), 1800);
  };

  const handleInstallPreset = async (preset: PluginPresetRecord) => {
    if (!canManage || submitting) return;
    setSubmitting(true);
    setFormError(null);
    try {
      const existingNames = new Set(installations.map((i) => i.name.toLowerCase()));
      let name = preset.id;
      let suffix = 2;
      while (existingNames.has(name.toLowerCase())) {
        name = `${preset.id}-${suffix}`;
        suffix += 1;
      }
      const res = await onInstallPlugin({
        name,
        sourceMode: "PRESET",
        presetId: preset.id,
        imageRef: preset.imageRef,
        sandboxProfile: preset.sandboxProfile,
        egressAllowlist: preset.defaultEgressAllowlist,
        resourceLimits: preset.defaultResourceLimits,
        desiredReplicas: 1,
        autoApprove: preset.autoApproveSupported && autoApprovePreset,
      });
      setModalOpen(false);
      setExpandedId(res.installation.id);
      onNotice(
        `Установка «${preset.name}» запущена (${res.installation.status})`,
      );
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Не удалось подключить пресет");
    } finally {
      setSubmitting(false);
    }
  };

  const handleInstallCustom = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canManage || submitting) return;
    const cleanName = customName.trim();
    const cleanImg = customImageRef.trim();
    if (cleanName.length < 2) {
      setFormError("Укажите имя установки (минимум 2 символа).");
      return;
    }
    if (customSourceMode === "OCI_IMAGE" && (!cleanImg || !cleanImg.includes("/"))) {
      setFormError("Укажите корректный OCI-образ с реестром (например ghcr.io/secflow/plugin:1.0.0).");
      return;
    }
    const egressList =
      customProfile === "EGRESS_EXTERNAL"
        ? customEgress
            .split(/[\n,]+/)
            .map((s) => s.trim())
            .filter(Boolean)
        : [];
    const replicas = Math.max(1, Math.min(5, Number.parseInt(customReplicas, 10) || 1));

    setSubmitting(true);
    setFormError(null);
    try {
      const res = await onInstallPlugin({
        name: cleanName,
        sourceMode: customSourceMode,
        imageRef: customSourceMode === "OCI_IMAGE" ? cleanImg : "",
        sandboxProfile: customProfile,
        egressAllowlist: egressList,
        resourceLimits: {
          cpuRequest: customCpuReq.trim() || "100m",
          cpuLimit: customCpuLim.trim() || "500m",
          memoryRequest: customMemReq.trim() || "64Mi",
          memoryLimit: customMemLim.trim() || "256Mi",
          minReplicas: 1,
          maxReplicas: Math.max(2, replicas),
        },
        desiredReplicas: replicas,
        autoApprove: false,
      });
      if (res.plaintextPluginToken) {
        setRevealedToken({
          installationName: res.installation.name,
          token: res.plaintextPluginToken,
        });
      }
      setCustomName("");
      setCustomEgress("");
      setModalOpen(false);
      setExpandedId(res.installation.id);
      onNotice(`Установка «${res.installation.name}» создана`);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Ошибка создания установки");
    } finally {
      setSubmitting(false);
    }
  };

  const handleConfirmApprove = async () => {
    if (!approveTarget || !canManage) return;
    setBusyId(approveTarget.id);
    try {
      await onApproveInstallation(approveTarget.id);
      onNotice(`Плагин «${approveTarget.name}» одобрен и активирован`);
      setApproveTarget(null);
    } catch (err) {
      onNotice(err instanceof Error ? err.message : "Ошибка одобрения");
    } finally {
      setBusyId(null);
    }
  };

  const handleToggleEnabled = async (inst: PluginInstallationRecord) => {
    if (!canManage || busyId) return;
    const nextEnabled = inst.status !== "ACTIVE";
    setBusyId(inst.id);
    try {
      await onSetEnabled(
        inst.id,
        nextEnabled,
        nextEnabled ? "Включён из Настроек" : "Отключён из Настроек",
      );
      onNotice(
        nextEnabled
          ? `Плагин «${inst.name}» включён`
          : `Плагин «${inst.name}» отключён (DrainRequest отправлен)`,
      );
    } catch (err) {
      onNotice(err instanceof Error ? err.message : "Ошибка переключения статуса");
    } finally {
      setBusyId(null);
    }
  };

  const openEditModal = (inst: PluginInstallationRecord) => {
    setEditTarget(inst);
    setEditImageRef(inst.imageRef);
    setEditReplicas(String(inst.desiredReplicas || 1));
    setEditEgress(inst.egressAllowlist.join(", "));
  };

  const handleSaveUpdate = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!editTarget || !canManage) return;
    setBusyId(editTarget.id);
    try {
      const egressList =
        editTarget.sandboxProfile === "EGRESS_EXTERNAL"
          ? editEgress
              .split(/[\n,]+/)
              .map((s) => s.trim())
              .filter(Boolean)
          : undefined;
      const res = await onUpdateInstallation({
        installationId: editTarget.id,
        imageRef: editImageRef.trim() || undefined,
        desiredReplicas: Math.max(1, Math.min(5, Number.parseInt(editReplicas, 10) || 1)),
        egressAllowlist: egressList,
      });
      if (res.plaintextPluginToken) {
        setRevealedToken({
          installationName: res.installation.name,
          token: res.plaintextPluginToken,
        });
      }
      onNotice(`Установка «${editTarget.name}» обновлена`);
      setEditTarget(null);
    } catch (err) {
      onNotice(err instanceof Error ? err.message : "Ошибка обновления установки");
    } finally {
      setBusyId(null);
    }
  };

  const handleConfirmDelete = async () => {
    if (!deleteTarget || !canManage) return;
    setBusyId(deleteTarget.id);
    try {
      await onDeleteInstallation(deleteTarget.id, "Удалён администратором OWNER");
      onNotice(`Установка «${deleteTarget.name}» удалена`);
      setDeleteTarget(null);
    } catch (err) {
      onNotice(err instanceof Error ? err.message : "Ошибка удаления установки");
    } finally {
      setBusyId(null);
    }
  };

  const handleManualRefresh = async () => {
    if (refreshing) return;
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  };

  const getPluginsForInstallation = (instId: string): LivePluginRecord[] =>
    livePlugins.filter((p) => p.installationId === instId);

  const renderManifestPreview = (manifests: PluginManifestRecord[]) => {
    if (manifests.length === 0) {
      return (
        <p className="text-[12px] text-[#636f7b]">
          Манифест ещё не получен — ожидается подключение воркера по{" "}
          <span className="fm-mono">WorkerService.Connect</span>.
        </p>
      );
    }
    return (
      <div className="space-y-3">
        {manifests.map((m) => (
          <div
            key={m.pluginId}
            className="rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc] p-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="text-[13px] font-semibold text-[#000000]">
                  {m.displayName}{" "}
                  <span className="fm-mono text-[11.5px] font-normal text-[#636f7b]">
                    ({m.pluginId} · v{m.version})
                  </span>
                </p>
                <p className="mt-0.5 text-[12px] text-[#636f7b]">{m.description}</p>
              </div>
              <span className="fm-mono rounded-full border border-[#8c9baa]/50 bg-[#ffffff] px-2 py-0.5 text-[11px] font-semibold text-[#222222]">
                {m.category}
              </span>
            </div>

            <div className="mt-2.5 flex flex-wrap gap-2 text-[11.5px]">
              <span className="text-[#636f7b]">Выходные порты:</span>
              {(m.outputPorts.length > 0
                ? m.outputPorts
                : [{ id: "default", label: "default" }]
              ).map((port) => (
                <span
                  key={port.id}
                  className="fm-mono rounded-full border border-[#8c9baa]/55 bg-[#ffffff] px-2 py-0.5 text-[11px] font-semibold text-[#000000]"
                >
                  {port.id}
                </span>
              ))}
              {m.requiredSecretKeys.length > 0 && (
                <>
                  <span className="ml-2 text-[#636f7b]">Требуемые секреты:</span>
                  {m.requiredSecretKeys.map((sk) => (
                    <span
                      key={sk}
                      className="fm-mono rounded-full border border-[#d97706]/55 bg-[#fff3c4] px-2 py-0.5 text-[11px] font-semibold text-[#7c4a03]"
                    >
                      {sk}
                    </span>
                  ))}
                </>
              )}
            </div>

            <pre className="fm-mono fm-scroll mt-2.5 max-h-[180px] overflow-auto rounded-[10px] border border-[#8c9baa]/40 bg-[#ffffff] p-2.5 text-[11px] leading-[1.45] text-[#222222]">
              {JSON.stringify(m.paramsJsonSchema, null, 2)}
            </pre>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 border-b border-[#8c9baa]/45 pb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-[22px] font-bold tracking-[-0.03em] text-[#000000]">
              Настройки: Плагины
            </h1>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${
                backendConnected
                  ? "border-[#16a34a]/45 bg-[#c8f0d8]/70 text-[#0f5132]"
                  : "border-[#0080ff]/45 bg-[#c5e0fb]/45 text-[#004a99]"
              }`}
            >
              <span
                aria-hidden="true"
                className={`h-1.5 w-1.5 rounded-full ${
                  backendConnected ? "bg-[#16a34a]" : "bg-[#0080ff]"
                }`}
              />
              {backendConnected ? "Live GraphQL" : "Preview Sandbox"}
            </span>
          </div>
          <p className="mt-1 max-w-[66ch] text-[14px] text-[#636f7b]">
            Центр управления внешними <span className="font-medium text-[#222222]">Plugin Installation</span>{" "}
            в песочнице <span className="fm-mono">secflow-sandbox</span>. После одобрения манифеста
            ноды мгновенно появляются в палитре редактора Workflow без перезапуска ядра.
          </p>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2 self-start">
          <button
            type="button"
            onClick={() => void handleManualRefresh()}
            disabled={refreshing}
            aria-label="Обновить список плагинов"
            className="fm-btn-outline fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 px-3 text-[13px] font-medium"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            Обновить
          </button>

          {canAuthorDeclarative && (
            <button
              type="button"
              onClick={() => {
                setBuilderEditTarget(null);
                setBuilderOpen(true);
              }}
              className="fm-btn-signal fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 whitespace-nowrap px-4 text-[13.5px] font-semibold"
            >
              <Sparkles className="h-4 w-4 stroke-[2]" aria-hidden="true" />
              Конструктор плагина
            </button>
          )}

          {canManage ? (
            <button
              type="button"
              onClick={() => {
                setModalTab("presets");
                setFormError(null);
                setModalOpen(true);
              }}
              className="fm-btn-ink fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 whitespace-nowrap px-4 text-[13.5px] font-semibold"
            >
              <PackagePlus className="h-4 w-4 stroke-[2]" aria-hidden="true" />
              Подключить плагин
            </button>
          ) : (
            <span className="rounded-full border border-[#8c9baa]/55 bg-[#f8fafc] px-3 py-1.5 text-[12px] font-medium text-[#636f7b]">
              {canAuthorDeclarative
                ? "Editor: конструктор и черновики (одобрение — owner)"
                : "Режим чтения (управление доступно owner)"}
            </span>
          )}
        </div>
      </div>

      {/* One-time plaintext PLUGIN_TOKEN reveal banner (EXTERNAL_PULL) */}
      {revealedToken && (
        <div
          role="status"
          className="rounded-[16px] border border-[#0080ff]/60 bg-[#f6faff] p-4"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <p className="inline-flex items-center gap-1.5 text-[13.5px] font-semibold text-[#000000]">
                <KeyRound className="h-4 w-4 text-[#0080ff]" aria-hidden="true" />
                Одноразовый PLUGIN_TOKEN для «{revealedToken.installationName}»
              </p>
              <p className="mt-1 text-[12.5px] text-[#636f7b]">
                Сохраните токен сейчас и передайте его воркеру через переменную окружения{" "}
                <span className="fm-mono">PLUGIN_TOKEN</span>. В базе хранится только SHA-256 хеш.
              </p>
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <code className="fm-mono max-w-full break-all rounded-[10px] border border-[#8c9baa]/55 bg-[#ffffff] px-3 py-1.5 text-[12px] text-[#000000]">
                  {revealedToken.token}
                </code>
                <button
                  type="button"
                  onClick={handleCopyToken}
                  className="fm-btn-outline fm-focus inline-flex min-h-[36px] cursor-pointer items-center gap-1.5 px-3 text-[12px] font-semibold"
                >
                  {copiedToken ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-[#16a34a]" aria-hidden="true" />
                      Скопировано
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      Копировать
                    </>
                  )}
                </button>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setRevealedToken(null)}
              aria-label="Скрыть токен"
              className="fm-focus inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/60 text-[#636f7b] hover:border-[#000000] hover:text-[#000000]"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      )}

      {/* Installations List */}
      {installations.length === 0 ? (
        <div className="rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] px-6 py-10 text-center">
          <span
            aria-hidden="true"
            className="mx-auto inline-flex h-11 w-11 items-center justify-center rounded-full bg-[#c5e0fb]/55 text-[#000000]"
          >
            <Blocks className="h-5 w-5 stroke-[1.7]" />
          </span>
          <p className="mt-3 text-[15px] font-semibold text-[#000000]">
            Внешние плагины ещё не подключены
          </p>
          <p className="mx-auto mt-1 max-w-[54ch] text-[13px] text-[#636f7b]">
            Подключите готовый пресет (<span className="fm-mono">Spring Config Hardening</span>,{" "}
            <span className="fm-mono">Risk Router</span>) в один клик или укажите собственный
            OCI-образ из доверенного реестра.
          </p>
          {(canAuthorDeclarative || canManage) && (
            <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
              {canAuthorDeclarative && (
                <button
                  type="button"
                  onClick={() => {
                    setBuilderEditTarget(null);
                    setBuilderOpen(true);
                  }}
                  className="fm-btn-signal fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
                >
                  <Sparkles className="h-4 w-4" aria-hidden="true" />
                  Создать в конструкторе
                </button>
              )}
              {canManage && (
                <button
                  type="button"
                  onClick={() => {
                    setModalTab("presets");
                    setFormError(null);
                    setModalOpen(true);
                  }}
                  className="fm-btn-ink fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
                >
                  <PackagePlus className="h-4 w-4" aria-hidden="true" />
                  Подключить первый плагин
                </button>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-3.5">
          {installations.map((inst) => {
            const badge = STATUS_BADGE[inst.status] ?? STATUS_BADGE.PROVISIONING;
            const expanded = expandedId === inst.id;
            const instPlugins = getPluginsForInstallation(inst.id);
            const activeWorkers = instPlugins.reduce((sum, p) => sum + p.activeWorkers, 0);
            const queueDepth = instPlugins.reduce((sum, p) => sum + p.queueDepth, 0);
            const allManifests =
              inst.pendingManifests.length > 0 ? inst.pendingManifests : inst.manifests;
            const isBusy = busyId === inst.id;
            const isDeclarative = inst.sourceMode === "DECLARATIVE";
            const hasPendingRevision =
              isDeclarative &&
              inst.status === "ACTIVE" &&
              Boolean(inst.pendingDeclarativeSpec);
            const canApproveNow =
              inst.status === "PENDING_APPROVAL" ||
              (isDeclarative && inst.status === "DRAFT") ||
              hasPendingRevision;

            return (
              <section
                key={inst.id}
                className="rounded-[16px] border border-[#8c9baa]/55 bg-[#ffffff] p-4 sm:p-5"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="break-words text-[15px] font-semibold text-[#000000]">
                        {inst.name}
                      </h2>
                      <span
                        className={`fm-mono inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${badge.cls}`}
                      >
                        {inst.status === "PROVISIONING" && (
                          <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
                        )}
                        {badge.label}
                      </span>
                      {isDeclarative && inst.pluginVersion && (
                        <span className="fm-mono rounded-full border border-[#0080ff]/40 bg-[#f6faff] px-2 py-0.5 text-[11px] font-semibold text-[#004a99]">
                          v{inst.pluginVersion}
                        </span>
                      )}
                      {hasPendingRevision && (
                        <span className="fm-mono rounded-full border border-[#d97706]/55 bg-[#fff3c4] px-2 py-0.5 text-[11px] font-semibold text-[#7c4a03]">
                          PENDING REVISION
                        </span>
                      )}
                      <span
                        className={`fm-mono inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                          inst.sandboxProfile === "EGRESS_EXTERNAL"
                            ? "border-[#d97706]/50 bg-[#fff3c4]/70 text-[#7c4a03]"
                            : "border-[#8c9baa]/55 bg-[#f8fafc] text-[#222222]"
                        }`}
                      >
                        {inst.sandboxProfile === "EGRESS_EXTERNAL" ? (
                          <ShieldAlert className="h-3 w-3" aria-hidden="true" />
                        ) : (
                          <ShieldCheck className="h-3 w-3 text-[#16a34a]" aria-hidden="true" />
                        )}
                        {inst.sandboxProfile}
                      </span>
                      <span className="rounded-full border border-[#8c9baa]/45 bg-[#ffffff] px-2 py-0.5 text-[11px] text-[#636f7b]">
                        {SOURCE_MODE_LABEL[inst.sourceMode]}
                      </span>
                    </div>

                    <p className="fm-mono mt-1.5 break-all text-[12px] text-[#636f7b]">
                      {isDeclarative
                        ? inst.sandboxProfile === "EGRESS_EXTERNAL"
                          ? "plugin-runtime-action (secflow-sandbox · EGRESS_EXTERNAL · hot-reload <1s)"
                          : "plugin-runtime-internal (secflow-sandbox · INTERNAL_ONLY · 0 egress)"
                        : inst.imageRef || "external-pull (подключается воркером по PLUGIN_TOKEN)"}
                    </p>

                    {/* Diagnostics & runtime metrics */}
                    <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[12px] text-[#222222]">
                      <span className="fm-tnum">
                        Поды:{" "}
                        <strong>
                          {inst.runtimeDiagnostics.readyReplicas}/
                          {inst.runtimeDiagnostics.desiredReplicas || inst.desiredReplicas}
                        </strong>{" "}
                        <span className="text-[#636f7b]">
                          ({inst.runtimeDiagnostics.phase || "Pending"})
                        </span>
                      </span>
                      <span className="fm-tnum">
                        Active workers: <strong>{activeWorkers}</strong>
                      </span>
                      <span className="fm-tnum">
                        Queue depth: <strong>{queueDepth}</strong>
                      </span>
                      <span className="fm-mono text-[11.5px] text-[#636f7b]">
                        CPU {inst.resourceLimits.cpuRequest}/{inst.resourceLimits.cpuLimit} · RAM{" "}
                        {inst.resourceLimits.memoryRequest}/{inst.resourceLimits.memoryLimit}
                      </span>
                    </div>

                    {/* Exported plugin_ids */}
                    {inst.pluginIds.length > 0 && (
                      <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                        <span className="text-[11.5px] text-[#636f7b]">Ноды Workflow:</span>
                        {inst.pluginIds.map((pid) => (
                          <span
                            key={pid}
                            className="fm-mono rounded-[8px] border border-[#0080ff]/35 bg-[#f6faff] px-2 py-0.5 text-[11.5px] font-medium text-[#004a99]"
                          >
                            {pid}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Egress allowlist */}
                    {inst.egressAllowlist.length > 0 && (
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        <span className="text-[11.5px] text-[#636f7b]">Egress allowlist:</span>
                        {inst.egressAllowlist.map((host) => (
                          <span
                            key={host}
                            className="fm-mono rounded-[8px] border border-[#d97706]/40 bg-[#fff3c4]/55 px-2 py-0.5 text-[11px] text-[#7c4a03]"
                          >
                            {host}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Pod error / escalation alert */}
                    {(inst.runtimeDiagnostics.lastError || inst.statusReason) && (
                      <p
                        className={`mt-2.5 rounded-[10px] border px-3 py-1.5 text-[12px] ${
                          inst.runtimeDiagnostics.lastError || inst.status === "ERROR"
                            ? "border-[#dc2626]/45 bg-[#ffd6e0]/45 text-[#842029]"
                            : inst.privilegeEscalation || canApproveNow
                              ? "border-[#d97706]/45 bg-[#fff3c4]/60 text-[#7c4a03]"
                              : "border-[#8c9baa]/35 bg-[#f8fafc] text-[#636f7b]"
                        }`}
                      >
                        {inst.runtimeDiagnostics.lastError || inst.statusReason}
                      </p>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex shrink-0 flex-wrap items-center gap-2">
                    {canManage && canApproveNow && (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => setApproveTarget(inst)}
                        className="fm-btn-signal fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-3.5 text-[12.5px] font-semibold"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                        {hasPendingRevision ? "Одобрить pending" : "Одобрить и включить"}
                      </button>
                    )}

                    {canManage &&
                      (inst.status === "ACTIVE" || inst.status === "DISABLED") && (
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => void handleToggleEnabled(inst)}
                          className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-3 text-[12.5px] font-medium"
                        >
                          <Power className="h-3.5 w-3.5" aria-hidden="true" />
                          {inst.status === "ACTIVE" ? "Отключить" : "Включить"}
                        </button>
                      )}

                    {isDeclarative && canAuthorDeclarative && inst.status !== "DELETING" && (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => {
                          setBuilderEditTarget(inst);
                          setBuilderOpen(true);
                        }}
                        className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-3 text-[12.5px] font-medium"
                      >
                        <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                        Редактировать
                      </button>
                    )}

                    {!isDeclarative && canManage && inst.status !== "DELETING" && (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => openEditModal(inst)}
                        className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 px-3 text-[12.5px] font-medium"
                      >
                        <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                        Обновить образ
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => setExpandedId(expanded ? null : inst.id)}
                      aria-expanded={expanded}
                      className="fm-btn-outline fm-focus inline-flex min-h-[38px] cursor-pointer items-center gap-1 px-3 text-[12.5px] font-medium"
                    >
                      Манифест
                      {expanded ? (
                        <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                    </button>

                    {canManage && (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => setDeleteTarget(inst)}
                        aria-label={`Удалить установку ${inst.name}`}
                        className="fm-focus inline-flex min-h-[38px] min-w-[38px] cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/70 bg-[#ffffff] text-[#636f7b] transition-colors hover:border-[#dc2626] hover:bg-[#ffd6e0]/45 hover:text-[#842029]"
                      >
                        <Trash2 className="h-4 w-4" aria-hidden="true" />
                      </button>
                    )}
                  </div>
                </div>

                {expanded && (
                  <div className="mt-4 border-t border-[#8c9baa]/35 pt-4">
                    <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-[12px] text-[#636f7b]">
                      <span className="font-semibold text-[#000000]">
                        Plugin Manifest ({allManifests.length})
                      </span>
                      {inst.approvedBy && (
                        <span>
                          Одобрил: <strong className="text-[#222222]">{inst.approvedBy}</strong>
                        </span>
                      )}
                    </div>
                    {renderManifestPreview(allManifests)}
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}

      {/* Modal 1: Install Plugin (Presets / Custom OCI) */}
      {modalOpen && canManage && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="install-plugin-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/40 p-4"
        >
          <div className="fm-scroll max-h-[90dvh] w-full max-w-[680px] overflow-y-auto overscroll-contain rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-5 sm:p-6">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2
                  id="install-plugin-title"
                  className="text-[18px] font-bold tracking-[-0.02em] text-[#000000]"
                >
                  Подключить плагин
                </h2>
                <p className="mt-0.5 text-[13px] text-[#636f7b]">
                  Выберите проверенный пресет или разверните собственный OCI-образ в{" "}
                  <span className="fm-mono">secflow-sandbox</span>.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                aria-label="Закрыть окно"
                className="fm-focus inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-full border border-[#8c9baa]/65 text-[#222222] hover:border-[#000000]"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>

            {/* 2-tab pill switcher */}
            <div
              role="tablist"
              aria-label="Способ подключения плагина"
              className="mt-4 grid grid-cols-2 rounded-full border border-[#8c9baa]/70 bg-[#ffffff] p-1"
            >
              <button
                type="button"
                role="tab"
                aria-selected={modalTab === "presets"}
                onClick={() => {
                  setModalTab("presets");
                  setFormError(null);
                }}
                className={`fm-focus min-h-[38px] cursor-pointer rounded-full px-3 text-[13px] font-semibold transition-colors ${
                  modalTab === "presets"
                    ? "bg-[#000000] text-[#ffffff]"
                    : "text-[#636f7b] hover:text-[#000000]"
                }`}
              >
                Пресеты (1 клик)
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={modalTab === "custom"}
                onClick={() => {
                  setModalTab("custom");
                  setFormError(null);
                }}
                className={`fm-focus min-h-[38px] cursor-pointer rounded-full px-3 text-[13px] font-semibold transition-colors ${
                  modalTab === "custom"
                    ? "bg-[#000000] text-[#ffffff]"
                    : "text-[#636f7b] hover:text-[#000000]"
                }`}
              >
                Свой OCI-образ
              </button>
            </div>

            {formError && (
              <p
                role="alert"
                className="mt-3 rounded-[10px] border border-[#dc2626]/45 bg-[#ffd6e0]/45 px-3 py-2 text-[12.5px] font-medium text-[#842029]"
              >
                {formError}
              </p>
            )}

            {modalTab === "presets" ? (
              <div className="mt-4 space-y-3">
                <label className="flex cursor-pointer items-center gap-2.5 rounded-[12px] border border-[#8c9baa]/45 bg-[#f8fafc] px-3 py-2 text-[12.5px] text-[#222222]">
                  <input
                    type="checkbox"
                    checked={autoApprovePreset}
                    onChange={(e) => setAutoApprovePreset(e.target.checked)}
                    className="h-4 w-4 accent-[#0080ff]"
                  />
                  <span>
                    Автоодобрять доверенные пресеты <span className="fm-mono">INTERNAL_ONLY</span>{" "}
                    сразу после подключения воркера
                  </span>
                </label>

                {presets.map((preset) => (
                  <div
                    key={preset.id}
                    className="rounded-[14px] border border-[#8c9baa]/55 bg-[#ffffff] p-4"
                  >
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="text-[14px] font-semibold text-[#000000]">
                            {preset.name}
                          </h3>
                          <span className="fm-mono rounded-full border border-[#8c9baa]/50 bg-[#f8fafc] px-2 py-0.5 text-[11px] font-semibold text-[#222222]">
                            {preset.category}
                          </span>
                          <span className="fm-mono rounded-full border border-[#8c9baa]/50 px-2 py-0.5 text-[11px] text-[#636f7b]">
                            {preset.sandboxProfile}
                          </span>
                        </div>
                        <p className="mt-1 text-[12.5px] text-[#636f7b]">{preset.description}</p>
                        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
                          <span className="text-[#636f7b]">Порты:</span>
                          {preset.outputPorts.map((port) => (
                            <span
                              key={port.id}
                              className="fm-mono rounded-full border border-[#8c9baa]/55 bg-[#ffffff] px-2 py-0.5 font-semibold text-[#000000]"
                            >
                              {port.id}
                            </span>
                          ))}
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={submitting}
                        onClick={() => void handleInstallPreset(preset)}
                        className="fm-btn-signal fm-focus inline-flex min-h-[40px] shrink-0 cursor-pointer items-center justify-center gap-1.5 px-4 text-[13px] font-semibold"
                      >
                        {submitting ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                        ) : (
                          <PackagePlus className="h-3.5 w-3.5" aria-hidden="true" />
                        )}
                        Установить
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <form onSubmit={(e) => void handleInstallCustom(e)} className="mt-4 space-y-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label
                      htmlFor="plg-name"
                      className="block text-[12px] font-medium text-[#636f7b]"
                    >
                      Имя установки
                    </label>
                    <input
                      id="plg-name"
                      type="text"
                      required
                      maxLength={120}
                      placeholder="custom-spring-audit"
                      value={customName}
                      onChange={(e) => setCustomName(e.target.value)}
                      className="fm-focus fm-mono mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] sm:text-[13.5px]"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="plg-mode"
                      className="block text-[12px] font-medium text-[#636f7b]"
                    >
                      Режим запуска
                    </label>
                    <select
                      id="plg-mode"
                      value={customSourceMode}
                      onChange={(e) =>
                        setCustomSourceMode(e.target.value as "OCI_IMAGE" | "EXTERNAL_PULL")
                      }
                      className="fm-focus fm-select mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] sm:text-[13.5px]"
                    >
                      <option value="OCI_IMAGE">K8s автодеплой (OCI-образ)</option>
                      <option value="EXTERNAL_PULL">EXTERNAL_PULL (выдать токен)</option>
                    </select>
                  </div>
                </div>

                {customSourceMode === "OCI_IMAGE" && (
                  <div>
                    <label
                      htmlFor="plg-image"
                      className="block text-[12px] font-medium text-[#636f7b]"
                    >
                      OCI-образ (allowlist реестров, SemVer тег без :latest)
                    </label>
                    <input
                      id="plg-image"
                      type="text"
                      placeholder="ghcr.io/secflow/my-plugin:1.0.0"
                      value={customImageRef}
                      onChange={(e) => setCustomImageRef(e.target.value)}
                      className="fm-focus fm-mono mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] sm:text-[13.5px]"
                    />
                  </div>
                )}

                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label
                      htmlFor="plg-profile"
                      className="block text-[12px] font-medium text-[#636f7b]"
                    >
                      Профиль изоляции (ADR-0010)
                    </label>
                    <select
                      id="plg-profile"
                      value={customProfile}
                      onChange={(e) =>
                        setCustomProfile(e.target.value as GqlSandboxProfile)
                      }
                      className="fm-focus fm-select mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] sm:text-[13.5px]"
                    >
                      <option value="INTERNAL_ONLY">
                        INTERNAL_ONLY (ANALYZER / LOGIC / AI_REPORT, 0 egress)
                      </option>
                      <option value="EGRESS_EXTERNAL">
                        EGRESS_EXTERNAL (только ACTION, без secflow-sources)
                      </option>
                    </select>
                  </div>

                  <div>
                    <label
                      htmlFor="plg-replicas"
                      className="block text-[12px] font-medium text-[#636f7b]"
                    >
                      Желаемые реплики (1–5)
                    </label>
                    <input
                      id="plg-replicas"
                      type="number"
                      min={1}
                      max={5}
                      value={customReplicas}
                      onChange={(e) => setCustomReplicas(e.target.value)}
                      className="fm-focus fm-tnum mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] sm:text-[13.5px]"
                    />
                  </div>
                </div>

                {customProfile === "EGRESS_EXTERNAL" && (
                  <div>
                    <label
                      htmlFor="plg-egress"
                      className="block text-[12px] font-medium text-[#636f7b]"
                    >
                      Egress Allowlist (хосты или публичные CIDR через запятую; SSRF блокируется)
                    </label>
                    <input
                      id="plg-egress"
                      type="text"
                      placeholder="hooks.slack.com:443, jira.company.com:443"
                      value={customEgress}
                      onChange={(e) => setCustomEgress(e.target.value)}
                      className="fm-focus fm-mono mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] bg-[#ffffff] px-3 text-[16px] text-[#000000] sm:text-[13.5px]"
                    />
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div>
                    <label htmlFor="plg-cpureq" className="block text-[11.5px] text-[#636f7b]">
                      CPU request
                    </label>
                    <input
                      id="plg-cpureq"
                      type="text"
                      value={customCpuReq}
                      onChange={(e) => setCustomCpuReq(e.target.value)}
                      className="fm-focus fm-mono mt-1 min-h-[38px] w-full rounded-[10px] border border-[#8c9baa] px-2.5 text-[16px] sm:text-[12.5px]"
                    />
                  </div>
                  <div>
                    <label htmlFor="plg-cpulim" className="block text-[11.5px] text-[#636f7b]">
                      CPU limit
                    </label>
                    <input
                      id="plg-cpulim"
                      type="text"
                      value={customCpuLim}
                      onChange={(e) => setCustomCpuLim(e.target.value)}
                      className="fm-focus fm-mono mt-1 min-h-[38px] w-full rounded-[10px] border border-[#8c9baa] px-2.5 text-[16px] sm:text-[12.5px]"
                    />
                  </div>
                  <div>
                    <label htmlFor="plg-memreq" className="block text-[11.5px] text-[#636f7b]">
                      RAM request
                    </label>
                    <input
                      id="plg-memreq"
                      type="text"
                      value={customMemReq}
                      onChange={(e) => setCustomMemReq(e.target.value)}
                      className="fm-focus fm-mono mt-1 min-h-[38px] w-full rounded-[10px] border border-[#8c9baa] px-2.5 text-[16px] sm:text-[12.5px]"
                    />
                  </div>
                  <div>
                    <label htmlFor="plg-memlim" className="block text-[11.5px] text-[#636f7b]">
                      RAM limit
                    </label>
                    <input
                      id="plg-memlim"
                      type="text"
                      value={customMemLim}
                      onChange={(e) => setCustomMemLim(e.target.value)}
                      className="fm-focus fm-mono mt-1 min-h-[38px] w-full rounded-[10px] border border-[#8c9baa] px-2.5 text-[16px] sm:text-[12.5px]"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
                  <button
                    type="button"
                    onClick={() => setModalOpen(false)}
                    className="fm-btn-outline fm-focus min-h-[40px] cursor-pointer px-4 text-[13px] font-medium"
                  >
                    Отмена
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="fm-btn-signal fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
                  >
                    {submitting && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                    Создать установку
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* Modal 2: Approve Installation with Manifest Preview & Privilege Escalation Warning */}
      {approveTarget && canManage && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="approve-plugin-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/40 p-4"
        >
          <div className="fm-scroll max-h-[88dvh] w-full max-w-[620px] overflow-y-auto overscroll-contain rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-5 sm:p-6">
            <h2
              id="approve-plugin-title"
              className="text-[17px] font-bold text-[#000000]"
            >
              Одобрить Plugin Manifest: {approveTarget.name}
            </h2>

            {(approveTarget.privilegeEscalation ||
              Boolean(approveTarget.approvedManifestDigest) ||
              (approveTarget.statusReason?.toLowerCase().includes("escalat") ?? false) ||
              approveTarget.sandboxProfile === "EGRESS_EXTERNAL") && (
              <div className="mt-3 flex items-start gap-2.5 rounded-[12px] border border-[#d97706]/55 bg-[#fff3c4]/75 p-3 text-[12.5px] text-[#7c4a03]">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <div>
                  <p className="font-semibold">
                    {approveTarget.privilegeEscalation ||
                    Boolean(approveTarget.approvedManifestDigest) ||
                    (approveTarget.statusReason?.toLowerCase().includes("escalat") ?? false)
                      ? "Обнаружена эскалация привилегий манифеста"
                      : "Внешний egress (EGRESS_EXTERNAL)"}
                  </p>
                  <p className="mt-0.5">
                    Проверьте список разрешённых egress-хостов и запрашиваемых{" "}
                    <span className="fm-mono">requiredSecretKeys</span> перед активацией.
                  </p>
                </div>
              </div>
            )}

            <div className="mt-4">
              {renderManifestPreview(
                approveTarget.pendingManifests.length > 0
                  ? approveTarget.pendingManifests
                  : approveTarget.manifests,
              )}
            </div>

            <div className="mt-5 flex flex-wrap justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
              <button
                type="button"
                onClick={() => setApproveTarget(null)}
                className="fm-btn-outline fm-focus min-h-[40px] cursor-pointer px-4 text-[13px] font-medium"
              >
                Отмена
              </button>
              <button
                type="button"
                disabled={busyId === approveTarget.id}
                onClick={() => void handleConfirmApprove()}
                className="fm-btn-signal fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 px-4 text-[13px] font-semibold"
              >
                <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                Одобрить и включить
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 3: Update Image / Replicas / Egress */}
      {editTarget && canManage && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="edit-plugin-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/40 p-4"
        >
          <form
            onSubmit={(e) => void handleSaveUpdate(e)}
            className="w-full max-w-[520px] rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-5 sm:p-6"
          >
            <h2 id="edit-plugin-title" className="text-[17px] font-bold text-[#000000]">
              Обновить установку: {editTarget.name}
            </h2>

            <div className="mt-4 space-y-3">
              {editTarget.sourceMode !== "EXTERNAL_PULL" && (
                <div>
                  <label
                    htmlFor="edit-image-ref"
                    className="block text-[12px] font-medium text-[#636f7b]"
                  >
                    OCI-образ
                  </label>
                  <input
                    id="edit-image-ref"
                    type="text"
                    value={editImageRef}
                    onChange={(e) => setEditImageRef(e.target.value)}
                    className="fm-focus fm-mono mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] px-3 text-[16px] sm:text-[13px]"
                  />
                </div>
              )}

              <div>
                <label
                  htmlFor="edit-replicas"
                  className="block text-[12px] font-medium text-[#636f7b]"
                >
                  Реплики (1–5)
                </label>
                <input
                  id="edit-replicas"
                  type="number"
                  min={1}
                  max={5}
                  value={editReplicas}
                  onChange={(e) => setEditReplicas(e.target.value)}
                  className="fm-focus fm-tnum mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] px-3 text-[16px] sm:text-[13px]"
                />
              </div>

              {editTarget.sandboxProfile === "EGRESS_EXTERNAL" && (
                <div>
                  <label
                    htmlFor="edit-egress"
                    className="block text-[12px] font-medium text-[#636f7b]"
                  >
                    Egress Allowlist (расширение вернёт установку в PENDING_APPROVAL)
                  </label>
                  <input
                    id="edit-egress"
                    type="text"
                    value={editEgress}
                    onChange={(e) => setEditEgress(e.target.value)}
                    className="fm-focus fm-mono mt-1 min-h-[42px] w-full rounded-[10px] border border-[#8c9baa] px-3 text-[16px] sm:text-[13px]"
                  />
                </div>
              )}
            </div>

            <div className="mt-5 flex flex-wrap justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
              <button
                type="button"
                onClick={() => setEditTarget(null)}
                className="fm-btn-outline fm-focus min-h-[40px] cursor-pointer px-4 text-[13px] font-medium"
              >
                Отмена
              </button>
              <button
                type="submit"
                disabled={busyId === editTarget.id}
                className="fm-btn-ink fm-focus min-h-[40px] cursor-pointer px-4 text-[13px] font-semibold"
              >
                Сохранить изменения
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Modal 4: Confirm Delete */}
      {deleteTarget && canManage && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-plugin-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#000000]/40 p-4"
        >
          <div className="w-full max-w-[460px] rounded-[20px] border border-[#8c9baa]/75 bg-[#ffffff] p-5 sm:p-6">
            <h2 id="delete-plugin-title" className="text-[17px] font-bold text-[#000000]">
              Удалить «{deleteTarget.name}»?
            </h2>
            <p className="mt-2 text-[13px] text-[#636f7b]">
              Активным подам будет отправлен <span className="fm-mono">DrainRequest</span>, а все
              ресурсы установки в <span className="fm-mono">secflow-sandbox</span> будут удалены.
              Узлы в сохранённых Workflow останутся на холсте с индикацией{" "}
              <span className="fm-mono">PLUGIN_UNREGISTERED</span>.
            </p>
            <div className="mt-5 flex flex-wrap justify-end gap-2 border-t border-[#8c9baa]/35 pt-4">
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                className="fm-btn-outline fm-focus min-h-[40px] cursor-pointer px-4 text-[13px] font-medium"
              >
                Отмена
              </button>
              <button
                type="button"
                disabled={busyId === deleteTarget.id}
                onClick={() => void handleConfirmDelete()}
                className="fm-focus inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 rounded-full bg-[#dc2626] px-4 text-[13px] font-semibold text-[#ffffff] hover:bg-[#b91c1c]"
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                Удалить установку
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 5: Declarative Plugin Builder */}
      {canAuthorDeclarative && (
        <DeclarativePluginBuilderModal
          open={builderOpen}
          role={role}
          launchSource="settings"
          initialSpec={
            (builderEditTarget?.pendingDeclarativeSpec ??
              builderEditTarget?.declarativeSpec ??
              null) as DeclarativePluginSpec | null
          }
          editingInstallation={builderEditTarget}
          blueprints={declarativeBlueprints}
          secrets={secrets}
          onClose={() => {
            setBuilderOpen(false);
            setBuilderEditTarget(null);
          }}
          onInstallPlugin={onInstallPlugin}
          onUpdateInstallation={onUpdateInstallation}
          onTestPlugin={onTestDeclarativePlugin}
          onCompleted={(result) => {
            setBuilderOpen(false);
            setBuilderEditTarget(null);
            if (result.installation) {
              setExpandedId(result.installation.id);
            }
          }}
          onNotice={onNotice}
        />
      )}
    </div>
  );
}
