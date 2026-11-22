"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  canonicalizeParamsObject,
  DECLARATIVE_STARTER_BLUEPRINTS,
  sha256HexClient,
  specToJsonSchema,
  stripSecretsFromParams,
  type DeclarativeBlueprintRecord,
  type DeclarativePluginSpec,
  type SavedNodeRecord,
  type TestDeclarativePluginInput,
  type TestDeclarativePluginResult,
} from "@/data/declarative-plugin-data";
import {
  BUILTIN_PLUGIN_PRESETS,
  DEFAULT_RESOURCE_LIMITS,
  JIRA_NOTIFIER_MANIFEST,
  RISK_ROUTER_MANIFEST,
  SPRING_CONFIG_MANIFEST,
  type InstallPluginFormInput,
  type LivePluginRecord,
  type PluginInstallationRecord,
  type PluginManifestRecord,
  type PluginPresetRecord,
  type UpdatePluginInstallationFormInput,
} from "@/data/plugins-data";
import { INITIAL_SECRETS, type SecretRecord } from "@/data/settings-data";
import { ROLE_LABELS, type UserRole } from "@/data/workflows-workspace-data";
import { authToken } from "@/lib/session";
import {
  approvePluginInstallationMutation,
  deletePluginInstallationMutation,
  deleteSavedNodeMutation,
  fetchDeclarativeBlueprints,
  fetchPluginControlPlane,
  fetchSavedNodes,
  installPluginMutation,
  saveNodeMutation,
  setPluginInstallationEnabledMutation,
  subscribePluginInstallationEvents,
  subscribePluginRegistryEvents,
  testDeclarativePluginMutation,
  updatePluginInstallationMutation,
  updateSavedNodeMutation,
} from "@/lib/plugins-graphql";

export interface RegistryEventBanner {
  id: number;
  message: string;
}

interface WorkspacePreviewContextValue {
  role: UserRole;
  setRole: (role: UserRole) => void;
  email: string;
  setEmail: (email: string) => void;
  forceEmpty: boolean;
  setForceEmpty: (value: boolean) => void;
  secrets: SecretRecord[];
  setSecrets: React.Dispatch<React.SetStateAction<SecretRecord[]>>;
  backendConnected: boolean;
  pluginPresets: PluginPresetRecord[];
  pluginInstallations: PluginInstallationRecord[];
  livePlugins: LivePluginRecord[];
  declarativeBlueprints: DeclarativeBlueprintRecord[];
  savedNodes: SavedNodeRecord[];
  lastRegistryEvent: RegistryEventBanner | null;
  installPlugin: (input: InstallPluginFormInput) => Promise<{
    installation: PluginInstallationRecord;
    plaintextPluginToken: string | null;
  }>;
  approvePluginInstallation: (installationId: string) => Promise<PluginInstallationRecord>;
  updatePluginInstallation: (input: UpdatePluginInstallationFormInput) => Promise<{
    installation: PluginInstallationRecord;
    plaintextPluginToken: string | null;
  }>;
  setPluginInstallationEnabled: (
    installationId: string,
    enabled: boolean,
    reason?: string,
  ) => Promise<PluginInstallationRecord>;
  deletePluginInstallation: (installationId: string, reason?: string) => Promise<boolean>;
  testDeclarativePlugin: (
    input: TestDeclarativePluginInput,
  ) => Promise<TestDeclarativePluginResult>;
  saveNode: (input: {
    name: string;
    description?: string;
    pluginId: string;
    params: Record<string, unknown>;
  }) => Promise<SavedNodeRecord>;
  updateSavedNode: (input: {
    id: string;
    name?: string;
    description?: string;
    params?: Record<string, unknown>;
  }) => Promise<SavedNodeRecord>;
  deleteSavedNode: (id: string) => Promise<boolean>;
  refreshPluginControlPlane: () => Promise<void>;
}

const WorkspacePreviewContext = createContext<WorkspacePreviewContextValue>({
  role: "owner",
  setRole: () => {},
  email: "",
  setEmail: () => {},
  forceEmpty: false,
  setForceEmpty: () => {},
  secrets: INITIAL_SECRETS,
  setSecrets: () => {},
  backendConnected: false,
  pluginPresets: BUILTIN_PLUGIN_PRESETS,
  pluginInstallations: [],
  livePlugins: [],
  declarativeBlueprints: DECLARATIVE_STARTER_BLUEPRINTS,
  savedNodes: [],
  lastRegistryEvent: null,
  installPlugin: async () => {
    throw new Error("WorkspacePreviewProvider not mounted");
  },
  approvePluginInstallation: async () => {
    throw new Error("WorkspacePreviewProvider not mounted");
  },
  updatePluginInstallation: async () => {
    throw new Error("WorkspacePreviewProvider not mounted");
  },
  setPluginInstallationEnabled: async () => {
    throw new Error("WorkspacePreviewProvider not mounted");
  },
  deletePluginInstallation: async () => false,
  testDeclarativePlugin: async () => ({
    ok: false,
    validationErrors: ["Provider not mounted"],
    findings: [],
    activeOutputPorts: [],
    durationMs: 0,
    summary: "Provider not mounted",
  }),
  saveNode: async () => {
    throw new Error("WorkspacePreviewProvider not mounted");
  },
  updateSavedNode: async () => {
    throw new Error("WorkspacePreviewProvider not mounted");
  },
  deleteSavedNode: async () => false,
  refreshPluginControlPlane: async () => {},
});

function randomHex(len: number): string {
  const chars = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < len; i += 1) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function buildCustomPreviewManifest(input: InstallPluginFormInput): PluginManifestRecord {
  const slug = input.name
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-|-$/g, "") || "custom-plugin";
  const isEgress = input.sandboxProfile === "EGRESS_EXTERNAL";
  return {
    pluginId: isEgress ? `action.${slug}` : `scan.${slug}`,
    version: "1.0.0",
    displayName: input.name,
    description: `Внешний контейнерный плагин ${input.imageRef || slug} (${input.sandboxProfile || "INTERNAL_ONLY"}).`,
    category: isEgress ? "ACTION" : "ANALYZER",
    capabilities: isEgress ? ["action", "notify"] : ["analyzer"],
    paramsJsonSchema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      additionalProperties: false,
      required: isEgress ? ["endpointPath"] : [],
      properties: isEgress
        ? {
            endpointPath: {
              type: "string",
              default: "/api/v1/alerts",
              description: "Путь на разрешённом egress-хосте.",
            },
            notifyOnWarn: {
              type: "boolean",
              default: true,
              description: "Отправлять уведомления при статусе WARN.",
            },
          }
        : {
            strictMode: {
              type: "boolean",
              default: true,
              description: "Включить строгий набор детерминированных проверок.",
            },
            severity: {
              type: "string",
              enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
              default: "HIGH",
              description: "Уровень критичности находок.",
            },
          },
    },
    inputPorts: [{ id: "default", label: "Вход" }],
    outputPorts: [{ id: "default", label: "Выход" }],
    runtimeLanguage: "go",
    sandboxProfile: input.sandboxProfile || "INTERNAL_ONLY",
    isExternal: true,
    requiredSecretKeys: isEgress ? ["apiToken"] : [],
    maxConcurrency: 2,
  };
}

function presetManifestsFor(presetId?: string | null): PluginManifestRecord[] {
  switch (presetId) {
    case "spring-config-hardening":
      return [SPRING_CONFIG_MANIFEST];
    case "risk-router":
      return [RISK_ROUTER_MANIFEST];
    case "jira-security-notifier":
      return [JIRA_NOTIFIER_MANIFEST];
    default:
      return [];
  }
}

function manifestsToLivePlugins(
  installationId: string,
  manifests: PluginManifestRecord[],
  enabled: boolean,
  approvalPending: boolean,
  workers: number,
): LivePluginRecord[] {
  const now = new Date().toISOString();
  return manifests.map((m) => ({
    pluginId: m.pluginId,
    version: m.version,
    displayName: m.displayName,
    description: m.description,
    category: m.category,
    capabilities: m.capabilities,
    paramsJsonSchema: m.paramsJsonSchema,
    inputPorts: m.inputPorts,
    outputPorts: m.outputPorts,
    runtimeLanguage: m.runtimeLanguage,
    sandboxProfile: m.sandboxProfile,
    isExternal: true,
    requiredSecretKeys: m.requiredSecretKeys,
    status: workers > 0 && enabled ? "ONLINE" : "OFFLINE",
    activeWorkers: enabled ? workers : 0,
    queueDepth: 0,
    installationId,
    enabled,
    approvalPending,
    registeredAt: now,
    lastSeenAt: now,
  }));
}

export function WorkspacePreviewProvider({ children }: { children: ReactNode }) {
  const [role, setRole] = useState<UserRole>("owner");
  const [email, setEmail] = useState("");
  const [forceEmpty, setForceEmpty] = useState(false);
  const [secrets, setSecrets] = useState<SecretRecord[]>(INITIAL_SECRETS);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [backendConnected, setBackendConnected] = useState(false);
  const [pluginPresets, setPluginPresets] =
    useState<PluginPresetRecord[]>(BUILTIN_PLUGIN_PRESETS);
  const [pluginInstallations, setPluginInstallations] = useState<
    PluginInstallationRecord[]
  >([]);
  const [livePlugins, setLivePlugins] = useState<LivePluginRecord[]>([]);
  const [declarativeBlueprints, setDeclarativeBlueprints] = useState<
    DeclarativeBlueprintRecord[]
  >(DECLARATIVE_STARTER_BLUEPRINTS);
  const [savedNodes, setSavedNodes] = useState<SavedNodeRecord[]>([]);
  const [lastRegistryEvent, setLastRegistryEvent] =
    useState<RegistryEventBanner | null>(null);

  const timersRef = useRef<number[]>([]);

  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      timers.forEach((t) => window.clearTimeout(t));
    };
  }, []);

  useEffect(() => {
    const syncAuth = () => {
      setSessionToken(authToken());
    };
    syncAuth();
    window.addEventListener("secflow-auth", syncAuth);
    window.addEventListener("storage", syncAuth);
    return () => {
      window.removeEventListener("secflow-auth", syncAuth);
      window.removeEventListener("storage", syncAuth);
    };
  }, []);

  const emitRegistryBanner = useCallback((message: string) => {
    setLastRegistryEvent({ id: Date.now() + Math.random(), message });
  }, []);

  const refreshPluginControlPlane = useCallback(async () => {
    if (!authToken()) {
      setBackendConnected(false);
      return;
    }
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetchPluginControlPlane(controller.signal);
      setBackendConnected(true);
      setPluginInstallations(res.installations);
      if (res.presets.length > 0) {
        // Enrich backend presets with preview sample manifests when available
        setPluginPresets(
          res.presets.map((p) => ({
            ...p,
            sampleManifests: presetManifestsFor(p.id),
          })),
        );
      }
      setLivePlugins(res.plugins.filter((p) => p.isExternal));
      const [bps, snList] = await Promise.all([
        fetchDeclarativeBlueprints(controller.signal).catch(() => []),
        fetchSavedNodes(controller.signal).catch(() => []),
      ]);
      if (bps.length > 0) setDeclarativeBlueprints(bps);
      setSavedNodes(snList);
    } catch {
      setBackendConnected(false);
    } finally {
      window.clearTimeout(timeoutId);
    }
  }, []);

  // Re-sync GraphQL control plane + WebSocket subscriptions whenever the auth session changes.
  useEffect(() => {
    if (!sessionToken) {
      setBackendConnected(false);
      setPluginInstallations([]);
      setLivePlugins([]);
      setSavedNodes([]);
      return;
    }

    void refreshPluginControlPlane();

    const unsubRegistry = subscribePluginRegistryEvents((ev) => {
      setBackendConnected(true);
      if (!ev.plugin.isExternal) return;
      setLivePlugins((prev) => {
        const idx = prev.findIndex((p) => p.pluginId === ev.plugin.pluginId);
        if (idx === -1) return [...prev, ev.plugin];
        const next = [...prev];
        next[idx] = ev.plugin;
        return next;
      });
      if (ev.plugin.enabled && ev.eventType !== "OFFLINE") {
        emitRegistryBanner(
          `Подключён Sandbox-плагин «${ev.plugin.displayName}» (${ev.plugin.pluginId})`,
        );
      }
    });

    const unsubInst = subscribePluginInstallationEvents((ev) => {
      setBackendConnected(true);
      setPluginInstallations((prev) => {
        if (ev.eventType === "DELETED") {
          return prev.filter((item) => item.id !== ev.installation.id);
        }
        const idx = prev.findIndex((item) => item.id === ev.installation.id);
        if (idx === -1) return [ev.installation, ...prev];
        const next = [...prev];
        next[idx] = ev.installation;
        return next;
      });
    });

    return () => {
      unsubRegistry();
      unsubInst();
    };
  }, [sessionToken, refreshPluginControlPlane, emitRegistryBanner]);

  const upsertPreviewPlugins = useCallback(
    (
      instId: string,
      manifests: PluginManifestRecord[],
      enabled: boolean,
      approvalPending: boolean,
      workers: number,
    ) => {
      const nextEntries = manifestsToLivePlugins(
        instId,
        manifests,
        enabled,
        approvalPending,
        workers,
      );
      setLivePlugins((prev) => {
        const filtered = prev.filter((p) => p.installationId !== instId);
        return [...filtered, ...nextEntries];
      });
    },
    [],
  );

  const syncLivePluginsFromInstallation = useCallback(
    (inst: PluginInstallationRecord) => {
      if (inst.status === "ACTIVE" && inst.manifests.length > 0) {
        upsertPreviewPlugins(
          inst.id,
          inst.manifests,
          true,
          false,
          Math.max(1, inst.desiredReplicas || 1),
        );
      } else if (inst.status === "DISABLED" && inst.manifests.length > 0) {
        upsertPreviewPlugins(inst.id, inst.manifests, false, false, 0);
      }
    },
    [upsertPreviewPlugins],
  );

  const installPlugin = useCallback(
    async (input: InstallPluginFormInput) => {
      if (backendConnected || Boolean(authToken())) {
        const res = await installPluginMutation(input);
        setBackendConnected(true);
        setPluginInstallations((prev) => {
          const rest = prev.filter((item) => item.id !== res.installation.id);
          return [res.installation, ...rest];
        });
        syncLivePluginsFromInstallation(res.installation);
        await refreshPluginControlPlane();
        return {
          installation: res.installation,
          plaintextPluginToken: res.plaintextPluginToken ?? null,
        };
      }

      // Autonomous preview-fallback state machine: DECLARATIVE / PROVISIONING -> PENDING_APPROVAL / ACTIVE
      const now = new Date().toISOString();
      if (input.sourceMode === "DECLARATIVE" && input.declarativeSpec) {
        const spec = input.declarativeSpec as unknown as DeclarativePluginSpec;
        const manifest: PluginManifestRecord = {
          pluginId: spec.pluginId,
          version: spec.version || "1.0.0",
          displayName: spec.displayName || spec.pluginId,
          description: spec.description || "",
          category: spec.category,
          capabilities: [spec.category.toLowerCase(), "declarative"],
          paramsJsonSchema: specToJsonSchema(spec),
          inputPorts: [{ id: "default", label: "default" }],
          outputPorts:
            spec.category === "LOGIC" && spec.outputPorts && spec.outputPorts.length > 0
              ? spec.outputPorts
              : [{ id: "default", label: "default" }],
          runtimeLanguage: "declarative",
          sandboxProfile: spec.category === "ACTION" ? "EGRESS_EXTERNAL" : "INTERNAL_ONLY",
          isExternal: true,
          requiredSecretKeys: spec.category === "ACTION" ? spec.requiredSecretKeys ?? [] : [],
        };
        const dup = pluginInstallations.find((existing) =>
          existing.pluginIds.some((p) => p.toLowerCase() === spec.pluginId.toLowerCase()),
        );
        if (dup) {
          throw new Error(`DUPLICATE_PLUGIN_ID: плагин ${spec.pluginId} уже существует (${dup.name})`);
        }
        const id = `plginst_${randomHex(8)}`;
        const isActive = Boolean(input.autoApprove && role === "owner" && !input.saveAsDraft);
        const rec: PluginInstallationRecord = {
          id,
          name: input.name.trim() || spec.displayName,
          sourceMode: "DECLARATIVE",
          presetId: null,
          imageRef: "",
          sandboxProfile: manifest.sandboxProfile,
          egressAllowlist: spec.egressAllowlist ?? [],
          resourceLimits: DEFAULT_RESOURCE_LIMITS,
          desiredReplicas: 1,
          status: isActive ? "ACTIVE" : input.saveAsDraft ? "DRAFT" : "PENDING_APPROVAL",
          statusReason: isActive ? "" : input.saveAsDraft ? "Сохранён как черновик" : "Ожидает одобрения OWNER",
          autoApprove: Boolean(input.autoApprove),
          approvedManifestDigest: isActive ? `sha256:${randomHex(16)}` : null,
          manifests: isActive ? [manifest] : [],
          pendingManifests: isActive ? [] : [manifest],
          pluginIds: [manifest.pluginId],
          runtimeDiagnostics: {
            phase: isActive ? "Running" : "Pending",
            desiredReplicas: 1,
            readyReplicas: isActive ? 1 : 0,
            message: isActive ? "Hot-reloaded in declarative runtime pool" : "Awaiting approval",
            lastError: "",
            updatedAt: now,
          },
          createdBy: ROLE_LABELS[role].name,
          approvedBy: isActive ? ROLE_LABELS[role].name : null,
          createdAt: now,
          updatedAt: now,
          approvedAt: isActive ? now : null,
          declarativeSpec: isActive ? input.declarativeSpec : null,
          pendingDeclarativeSpec: isActive ? null : input.declarativeSpec,
          pluginVersion: spec.version || "1.0.0",
        };
        setPluginInstallations((prev) => [rec, ...prev]);
        if (isActive) {
          upsertPreviewPlugins(id, [manifest], true, false, 1);
          emitRegistryBanner(`Активирован Declarative Plugin «${manifest.displayName}» (${manifest.pluginId})`);
        }
        return { installation: rec, plaintextPluginToken: null };
      }

      const preset = input.presetId
        ? pluginPresets.find((p) => p.id === input.presetId)
        : undefined;
      const manifests =
        preset?.sampleManifests && preset.sampleManifests.length > 0
          ? preset.sampleManifests
          : presetManifestsFor(input.presetId).length > 0
            ? presetManifestsFor(input.presetId)
            : [buildCustomPreviewManifest(input)];
      const id = `plginst_${randomHex(8)}`;
      const replicas = Math.max(1, input.desiredReplicas ?? 1);
      const profile =
        input.sandboxProfile ?? preset?.sandboxProfile ?? "INTERNAL_ONLY";
      const imageRef = input.imageRef || preset?.imageRef || "external-pull";
      const canAutoApprove = Boolean(
        input.sourceMode === "PRESET" &&
          preset?.autoApproveSupported &&
          input.autoApprove &&
          profile === preset.sandboxProfile,
      );

      const initial: PluginInstallationRecord = {
        id,
        name: input.name.trim(),
        sourceMode: input.sourceMode,
        presetId: input.presetId ?? null,
        imageRef,
        sandboxProfile: profile,
        egressAllowlist:
          input.egressAllowlist ?? preset?.defaultEgressAllowlist ?? [],
        resourceLimits: {
          ...DEFAULT_RESOURCE_LIMITS,
          ...(preset?.defaultResourceLimits ?? {}),
          ...(input.resourceLimits ?? {}),
        },
        desiredReplicas: replicas,
        status: "PROVISIONING",
        statusReason:
          input.sourceMode === "EXTERNAL_PULL"
            ? "Ожидание подключения внешнего Pull-воркера по PLUGIN_TOKEN"
            : "Создание Deployment, Secret и NetworkPolicy в secflow-sandbox",
        autoApprove: Boolean(input.autoApprove),
        approvedManifestDigest: null,
        manifests: [],
        pendingManifests: manifests,
        pluginIds: manifests.map((m) => m.pluginId),
        runtimeDiagnostics: {
          phase: "Provisioning",
          desiredReplicas: replicas,
          readyReplicas: 0,
          message:
            input.sourceMode === "EXTERNAL_PULL"
              ? "Ожидание gRPC-рукопожатия WorkerService.Connect"
              : "Подготовка пода в namespace secflow-sandbox…",
          lastError: "",
          updatedAt: now,
        },
        createdBy: ROLE_LABELS[role].name,
        approvedBy: null,
        createdAt: now,
        updatedAt: now,
        approvedAt: null,
      };

      setPluginInstallations((prev) => [initial, ...prev]);

      const plaintextPluginToken =
        input.sourceMode === "EXTERNAL_PULL" ? `sf_plg_${randomHex(32)}` : null;

      // Simulate realistic PROVISIONING -> PENDING_APPROVAL (or ACTIVE if trusted preset autoApprove)
      const timer = window.setTimeout(() => {
        const ts = new Date().toISOString();
        const nextStatus = canAutoApprove ? "ACTIVE" : "PENDING_APPROVAL";
        setPluginInstallations((prev) =>
          prev.map((item) => {
            if (item.id !== id || item.status !== "PROVISIONING") return item;
            return {
              ...item,
              status: nextStatus,
              statusReason: canAutoApprove
                ? "Автоодобрено для доверенного пресета"
                : "Манифест получен, ожидается одобрение OWNER",
              approvedManifestDigest: canAutoApprove
                ? `sha256:${randomHex(16)}`
                : null,
              manifests: canAutoApprove ? manifests : [],
              pendingManifests: canAutoApprove ? [] : manifests,
              approvedBy: canAutoApprove ? ROLE_LABELS[role].name : null,
              approvedAt: canAutoApprove ? ts : null,
              updatedAt: ts,
              runtimeDiagnostics: {
                phase: "Running",
                desiredReplicas: replicas,
                readyReplicas: replicas,
                message: `${replicas}/${replicas} sandbox replicas ready`,
                lastError: "",
                updatedAt: ts,
              },
            };
          }),
        );
        if (canAutoApprove) {
          upsertPreviewPlugins(id, manifests, true, false, replicas);
          emitRegistryBanner(
            `Плагин «${initial.name}» активен: ноды ${manifests.map((m) => m.pluginId).join(", ")} добавлены в палитру`,
          );
        }
      }, 650);
      timersRef.current.push(timer);

      return { installation: initial, plaintextPluginToken };
    },
    [
      backendConnected,
      pluginInstallations,
      pluginPresets,
      role,
      refreshPluginControlPlane,
      syncLivePluginsFromInstallation,
      upsertPreviewPlugins,
      emitRegistryBanner,
    ],
  );

  const approvePluginInstallation = useCallback(
    async (installationId: string) => {
      if (backendConnected || Boolean(authToken())) {
        const updated = await approvePluginInstallationMutation(installationId);
        setBackendConnected(true);
        setPluginInstallations((prev) =>
          prev.map((item) => (item.id === installationId ? updated : item)),
        );
        syncLivePluginsFromInstallation(updated);
        await refreshPluginControlPlane();
        return updated;
      }

      const now = new Date().toISOString();
      let approvedRecord: PluginInstallationRecord | null = null;
      setPluginInstallations((prev) =>
        prev.map((item) => {
          if (item.id !== installationId) return item;
          const activeManifests =
            item.pendingManifests.length > 0
              ? item.pendingManifests
              : item.manifests;
          approvedRecord = {
            ...item,
            status: "ACTIVE",
            statusReason: "Одобрено OWNER",
            approvedManifestDigest: `sha256:${randomHex(16)}`,
            manifests: activeManifests,
            pendingManifests: [],
            declarativeSpec: item.pendingDeclarativeSpec ?? item.declarativeSpec ?? null,
            pendingDeclarativeSpec: null,
            pluginIds: activeManifests.map((m) => m.pluginId),
            approvedBy: ROLE_LABELS[role].name,
            approvedAt: now,
            updatedAt: now,
            privilegeEscalation: false,
            runtimeDiagnostics: {
              ...item.runtimeDiagnostics,
              phase: "Running",
              readyReplicas: item.desiredReplicas,
              message: `${item.desiredReplicas}/${item.desiredReplicas} sandbox replicas ready`,
              lastError: "",
              updatedAt: now,
            },
          };
          upsertPreviewPlugins(
            item.id,
            activeManifests,
            true,
            false,
            item.desiredReplicas,
          );
          emitRegistryBanner(
            `Одобрен плагин «${item.name}»: ноды ${activeManifests.map((m) => m.pluginId).join(", ")} доступны в палитре Workflow`,
          );
          return approvedRecord;
        }),
      );
      if (!approvedRecord) {
        throw new Error("Plugin Installation not found");
      }
      return approvedRecord;
    },
    [
      backendConnected,
      role,
      refreshPluginControlPlane,
      syncLivePluginsFromInstallation,
      upsertPreviewPlugins,
      emitRegistryBanner,
    ],
  );

  const updatePluginInstallation = useCallback(
    async (input: UpdatePluginInstallationFormInput) => {
      if (backendConnected || Boolean(authToken())) {
        const res = await updatePluginInstallationMutation(input);
        setBackendConnected(true);
        setPluginInstallations((prev) =>
          prev.map((item) =>
            item.id === res.installation.id ? res.installation : item,
          ),
        );
        syncLivePluginsFromInstallation(res.installation);
        await refreshPluginControlPlane();
        return {
          installation: res.installation,
          plaintextPluginToken: res.plaintextPluginToken ?? null,
        };
      }

      const now = new Date().toISOString();
      let updatedRec: PluginInstallationRecord | null = null;
      let rotatedToken: string | null = null;
      setPluginInstallations((prev) =>
        prev.map((item) => {
          if (item.id !== input.installationId) return item;
          const nextProfile = input.sandboxProfile ?? item.sandboxProfile;
          const nextEgress = input.egressAllowlist ?? item.egressAllowlist;
          const escalated =
            (item.sandboxProfile === "INTERNAL_ONLY" &&
              nextProfile === "EGRESS_EXTERNAL") ||
            nextEgress.some((host) => !item.egressAllowlist.includes(host));

          const activeManifests =
            item.manifests.length > 0 ? item.manifests : item.pendingManifests;
          if (input.rotateToken && item.sourceMode === "EXTERNAL_PULL") {
            rotatedToken = `sf_plg_${randomHex(32)}`;
          }

          if (item.sourceMode === "DECLARATIVE" && input.declarativeSpec) {
            const spec = input.declarativeSpec as unknown as DeclarativePluginSpec;
            const curParts = (item.pluginVersion || "1.0.0").split(".").map((n) => Number.parseInt(n, 10) || 0);
            const nextVer = `${curParts[0] || 1}.${curParts[1] || 0}.${(curParts[2] || 0) + 1}`;
            const nextSpec: DeclarativePluginSpec = { ...spec, version: nextVer };
            const manifest: PluginManifestRecord = {
              pluginId: nextSpec.pluginId,
              version: nextVer,
              displayName: nextSpec.displayName || nextSpec.pluginId,
              description: nextSpec.description || "",
              category: nextSpec.category,
              capabilities: ["declarative"],
              paramsJsonSchema: specToJsonSchema(nextSpec),
              inputPorts: [{ id: "default", label: "default" }],
              outputPorts:
                nextSpec.category === "LOGIC" && nextSpec.outputPorts && nextSpec.outputPorts.length > 0
                  ? nextSpec.outputPorts
                  : [{ id: "default", label: "default" }],
              runtimeLanguage: "declarative",
              sandboxProfile: nextSpec.category === "ACTION" ? "EGRESS_EXTERNAL" : "INTERNAL_ONLY",
              isExternal: true,
              requiredSecretKeys: nextSpec.category === "ACTION" ? nextSpec.requiredSecretKeys ?? [] : [],
            };
            const immediateActivate = Boolean(role === "owner" && input.approveImmediately);
            if (immediateActivate) {
              updatedRec = {
                ...item,
                name: nextSpec.displayName || item.name,
                sandboxProfile: manifest.sandboxProfile,
                egressAllowlist: nextSpec.egressAllowlist ?? [],
                status: "ACTIVE",
                statusReason: "Обновлено и активировано OWNER",
                approvedManifestDigest: `sha256:${randomHex(16)}`,
                manifests: [manifest],
                pendingManifests: [],
                pluginIds: [manifest.pluginId],
                declarativeSpec: nextSpec as unknown as Record<string, unknown>,
                pendingDeclarativeSpec: null,
                pluginVersion: nextVer,
                privilegeEscalation: false,
                approvedBy: ROLE_LABELS[role].name,
                approvedAt: now,
                updatedAt: now,
              };
              upsertPreviewPlugins(item.id, [manifest], true, false, 1);
            } else if (item.status === "ACTIVE") {
              // Non-destructive pending staging revision while current ACTIVE version stays live.
              updatedRec = {
                ...item,
                statusReason: `Pending ревизия v${nextVer} ожидает одобрения OWNER (текущая версия активна)`,
                pendingManifests: [manifest],
                pendingDeclarativeSpec: nextSpec as unknown as Record<string, unknown>,
                pluginVersion: nextVer,
                privilegeEscalation: escalated,
                updatedAt: now,
              };
            } else {
              const submit = Boolean(input.submitForApproval);
              updatedRec = {
                ...item,
                name: nextSpec.displayName || item.name,
                sandboxProfile: manifest.sandboxProfile,
                egressAllowlist: nextSpec.egressAllowlist ?? [],
                status: submit ? "PENDING_APPROVAL" : "DRAFT",
                statusReason: submit
                  ? `Ревизия v${nextVer} отправлена на одобрение OWNER`
                  : `Черновик v${nextVer} обновлён`,
                pendingManifests: [manifest],
                pendingDeclarativeSpec: nextSpec as unknown as Record<string, unknown>,
                pluginVersion: nextVer,
                privilegeEscalation: escalated,
                updatedAt: now,
              };
            }
            return updatedRec;
          }

          updatedRec = {
            ...item,
            imageRef: input.imageRef?.trim() || item.imageRef,
            sandboxProfile: nextProfile,
            egressAllowlist: nextEgress,
            desiredReplicas: input.desiredReplicas ?? item.desiredReplicas,
            resourceLimits: {
              ...item.resourceLimits,
              ...(input.resourceLimits ?? {}),
            },
            status: escalated ? "PENDING_APPROVAL" : item.status,
            statusReason: escalated
              ? "Эскалация привилегий (профиль/egress): требуется повторное одобрение OWNER"
              : "Конфигурация обновлена",
            manifests: escalated ? [] : item.manifests,
            pendingManifests: escalated ? activeManifests : item.pendingManifests,
            privilegeEscalation: escalated,
            updatedAt: now,
          };

          if (escalated) {
            upsertPreviewPlugins(item.id, activeManifests, false, true, 0);
          }
          return updatedRec;
        }),
      );
      if (!updatedRec) {
        throw new Error("Plugin Installation not found");
      }
      return { installation: updatedRec, plaintextPluginToken: rotatedToken };
    },
    [backendConnected, role, refreshPluginControlPlane, syncLivePluginsFromInstallation, upsertPreviewPlugins],
  );

  const setPluginInstallationEnabled = useCallback(
    async (installationId: string, enabled: boolean, reason?: string) => {
      if (backendConnected || Boolean(authToken())) {
        const updated = await setPluginInstallationEnabledMutation(
          installationId,
          enabled,
          reason,
        );
        setBackendConnected(true);
        setPluginInstallations((prev) =>
          prev.map((item) => (item.id === installationId ? updated : item)),
        );
        syncLivePluginsFromInstallation(updated);
        await refreshPluginControlPlane();
        return updated;
      }

      const now = new Date().toISOString();
      let updatedRec: PluginInstallationRecord | null = null;
      setPluginInstallations((prev) =>
        prev.map((item) => {
          if (item.id !== installationId) return item;
          const nextStatus = enabled ? "ACTIVE" : "DISABLED";
          const manifests =
            item.manifests.length > 0 ? item.manifests : item.pendingManifests;
          updatedRec = {
            ...item,
            status: nextStatus,
            statusReason:
              reason ||
              (enabled
                ? "Включён администратором OWNER"
                : "Отключён (DrainRequest → replicas: 0)"),
            updatedAt: now,
            runtimeDiagnostics: {
              ...item.runtimeDiagnostics,
              phase: enabled ? "Running" : "ScaledToZero",
              desiredReplicas: enabled ? item.desiredReplicas : 0,
              readyReplicas: enabled ? item.desiredReplicas : 0,
              message: enabled
                ? `${item.desiredReplicas}/${item.desiredReplicas} sandbox replicas ready`
                : "Deployment scaled to 0 replicas",
              updatedAt: now,
            },
          };
          upsertPreviewPlugins(
            item.id,
            manifests,
            enabled,
            false,
            enabled ? item.desiredReplicas : 0,
          );
          return updatedRec;
        }),
      );
      if (!updatedRec) {
        throw new Error("Plugin Installation not found");
      }
      return updatedRec;
    },
    [backendConnected, refreshPluginControlPlane, syncLivePluginsFromInstallation, upsertPreviewPlugins],
  );

  const deletePluginInstallation = useCallback(
    async (installationId: string, reason?: string) => {
      if (backendConnected || Boolean(authToken())) {
        const deleted = await deletePluginInstallationMutation(
          installationId,
          reason,
        );
        setBackendConnected(true);
        if (deleted) {
          setPluginInstallations((prev) =>
            prev.filter((item) => item.id !== installationId),
          );
          setLivePlugins((prev) =>
            prev.filter((p) => p.installationId !== installationId),
          );
        }
        return deleted;
      }

      setPluginInstallations((prev) =>
        prev.filter((item) => item.id !== installationId),
      );
      setLivePlugins((prev) =>
        prev.filter((p) => p.installationId !== installationId),
      );
      return true;
    },
    [backendConnected],
  );

  const testDeclarativePlugin = useCallback(
    async (input: TestDeclarativePluginInput): Promise<TestDeclarativePluginResult> => {
      if (backendConnected || Boolean(authToken())) {
        const res = await testDeclarativePluginMutation(input);
        setBackendConnected(true);
        return res;
      }
      const spec = input.declarativeSpec;
      if (spec.category === "ACTION") {
        const allowlist = spec.egressAllowlist ?? [];
        const rawUrl = spec.action?.url || "";
        let allowed = false;
        let reason = "";
        try {
          const u = new URL(rawUrl);
          allowed = allowlist.some(
            (h) => h.toLowerCase() === u.host.toLowerCase() || h.toLowerCase() === u.hostname.toLowerCase(),
          );
          if (!allowed) reason = `Хост ${u.host} отсутствует в egressAllowlist`;
        } catch {
          reason = "Некорректный URL";
        }
        return {
          ok: allowed,
          validationErrors: allowed ? [] : [reason],
          findings: [],
          activeOutputPorts: ["default"],
          dryRunHttp: {
            method: spec.action?.method || "POST",
            url: rawUrl,
            headers: Object.fromEntries(
              Object.entries(spec.action?.headers ?? {}).map(([k, v]) => [
                k,
                v.replace(/\{\{\s*secrets\.[^}]+\}\}/g, "***"),
              ]),
            ),
            body: spec.action?.bodyTemplate ?? "",
            allowed,
            policyReason: reason || undefined,
          },
          durationMs: 4,
          summary: allowed
            ? `Offline dry-run готов: ${spec.action?.method || "POST"} ${rawUrl}`
            : `Заблокировано egress-политикой: ${reason}`,
        };
      }
      if (spec.category === "LOGIC") {
        const port = spec.logic?.routes?.[0]?.outputPort || spec.logic?.fallbackPort || "default";
        return {
          ok: true,
          validationErrors: [],
          findings: [],
          activeOutputPorts: [port],
          envelopePatch: { vars: { previewMode: "true" }, gate: { status: spec.logic?.routes?.[0]?.gate || "PASS" } },
          durationMs: 3,
          summary: `Preview маршрутизация → порт ${port}`,
        };
      }
      return {
        ok: true,
        validationErrors: [],
        findings: [],
        activeOutputPorts: ["default"],
        durationMs: 3,
        summary: `Preview проверка завершена (${input.files?.length ?? 0} файл.)`,
      };
    },
    [backendConnected],
  );

  const saveNode = useCallback(
    async (input: {
      name: string;
      description?: string;
      pluginId: string;
      params: Record<string, unknown>;
    }): Promise<SavedNodeRecord> => {
      if (backendConnected || Boolean(authToken())) {
        const created = await saveNodeMutation(input);
        setBackendConnected(true);
        setSavedNodes((prev) => [created, ...prev.filter((s) => s.id !== created.id)]);
        return created;
      }
      const clean = stripSecretsFromParams(input.params);
      const hash = await sha256HexClient(canonicalizeParamsObject(clean));
      const dup = savedNodes.find(
        (s) => s.pluginId.toLowerCase() === input.pluginId.toLowerCase() && s.canonicalParamsHash === hash,
      );
      if (dup) {
        throw new Error(`DUPLICATE_SAVED_NODE: конфигурация уже сохранена как «${dup.name}»`);
      }
      const now = new Date().toISOString();
      const rec: SavedNodeRecord = {
        id: `snode_${randomHex(8)}`,
        name: input.name.trim(),
        description: input.description?.trim() ?? "",
        pluginId: input.pluginId,
        params: clean,
        canonicalParamsHash: hash,
        createdBy: ROLE_LABELS[role].name,
        createdAt: now,
        updatedAt: now,
      };
      setSavedNodes((prev) => [rec, ...prev]);
      return rec;
    },
    [backendConnected, role, savedNodes],
  );

  const updateSavedNode = useCallback(
    async (input: {
      id: string;
      name?: string;
      description?: string;
      params?: Record<string, unknown>;
    }): Promise<SavedNodeRecord> => {
      if (backendConnected || Boolean(authToken())) {
        const updated = await updateSavedNodeMutation(input);
        setBackendConnected(true);
        setSavedNodes((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
        return updated;
      }
      const cur = savedNodes.find((s) => s.id === input.id);
      if (!cur) throw new Error("Saved Node not found");
      const clean = input.params ? stripSecretsFromParams(input.params) : cur.params;
      const hash = await sha256HexClient(canonicalizeParamsObject(clean));
      const dup = savedNodes.find(
        (s) => s.id !== cur.id && s.pluginId.toLowerCase() === cur.pluginId.toLowerCase() && s.canonicalParamsHash === hash,
      );
      if (dup) {
        throw new Error(`DUPLICATE_SAVED_NODE: идентичная конфигурация уже есть («${dup.name}»)`);
      }
      const updated: SavedNodeRecord = {
        ...cur,
        name: input.name?.trim() || cur.name,
        description: input.description !== undefined ? input.description.trim() : cur.description,
        params: clean,
        canonicalParamsHash: hash,
        updatedAt: new Date().toISOString(),
      };
      setSavedNodes((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
      return updated;
    },
    [backendConnected, savedNodes],
  );

  const deleteSavedNode = useCallback(
    async (id: string): Promise<boolean> => {
      if (backendConnected || Boolean(authToken())) {
        const ok = await deleteSavedNodeMutation(id);
        setBackendConnected(true);
        if (ok) setSavedNodes((prev) => prev.filter((s) => s.id !== id));
        return ok;
      }
      setSavedNodes((prev) => prev.filter((s) => s.id !== id));
      return true;
    },
    [backendConnected],
  );

  return (
    <WorkspacePreviewContext.Provider
      value={{
        role,
        setRole,
        email,
        setEmail,
        forceEmpty,
        setForceEmpty,
        secrets,
        setSecrets,
        backendConnected,
        pluginPresets,
        pluginInstallations,
        livePlugins,
        declarativeBlueprints,
        savedNodes,
        lastRegistryEvent,
        installPlugin,
        approvePluginInstallation,
        updatePluginInstallation,
        setPluginInstallationEnabled,
        deletePluginInstallation,
        testDeclarativePlugin,
        saveNode,
        updateSavedNode,
        deleteSavedNode,
        refreshPluginControlPlane,
      }}
    >
      {children}
    </WorkspacePreviewContext.Provider>
  );
}

export function useWorkspacePreview() {
  return useContext(WorkspacePreviewContext);
}
