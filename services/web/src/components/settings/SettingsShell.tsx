"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Blocks,
  KeyRound,
  Lock,
  Plug,
  Shield,
  Sparkles,
  User,
} from "lucide-react";
import {
  ApiError,
  getAiProviderConfig,
  gql,
  QUERIES,
  saveAiProviderConfig,
  testAiProviderConnection,
  type AiModelsProbeResponse,
} from "@/lib/api";
import { clearSession } from "@/lib/session";
import {
  INITIAL_AI_CONFIG,
  SETTINGS_TABS,
  canManageOwnerOnly,
  canManageSecrets,
  normalizeSettingsTab,
  type AiAuditLogRecord,
  type AiProviderConfig,
  type McpConnectionRecord,
  type McpToolInfo,
  type ScopedTokenRecord,
  type SecretBindingScope,
  type SecretRecord,
  type SettingsTabId,
  type TokenScope,
} from "@/data/settings-data";
import { useWorkspacePreview } from "@/components/workspace/WorkspacePreviewContext";
import {
  FlowmappHeader,
  FlowmappNoticeBar,
} from "@/components/workspace/flowmapp/FlowmappChrome";
import type { FeedbackNotice } from "@/components/workspace/useWorkflowsWorkspace";
import { ProfileTab } from "./ProfileTab";
import { SecretsTab } from "./SecretsTab";
import { TokensTab } from "./TokensTab";
import { AiProviderTab } from "./AiProviderTab";
import { McpServersTab } from "./McpServersTab";
import { PluginsTab } from "./PluginsTab";

function TabIcon({ id, active }: { id: SettingsTabId; active: boolean }) {
  const cls = `h-4 w-4 shrink-0 stroke-[1.7] ${active ? "text-[#0080ff]" : "text-[#636f7b]"}`;
  switch (id) {
    case "profile":
      return <User className={cls} aria-hidden="true" />;
    case "secrets":
      return <KeyRound className={cls} aria-hidden="true" />;
    case "tokens":
      return <Shield className={cls} aria-hidden="true" />;
    case "ai":
      return <Sparkles className={cls} aria-hidden="true" />;
    case "mcp":
      return <Plug className={cls} aria-hidden="true" />;
    case "plugins":
      return <Blocks className={cls} aria-hidden="true" />;
  }
}

const KIND_BY_BINDING: Record<SecretBindingScope, string> = {
  "source.git": "GIT_TOKEN",
  "ai.explain": "LLM_API_KEY",
  "notify.telegram": "TELEGRAM_BOT_TOKEN",
  "notify.webhook": "WEBHOOK_HMAC_SECRET",
  "notify.smtp": "SMTP_PASSWORD",
  "notify.commit_status": "GIT_TOKEN",
  "trigger.webhook": "GIT_WEBHOOK_SECRET",
  "mcp.tool": "MCP_AUTH_HEADER",
  generic: "GENERIC",
};

const BINDING_BY_KIND: Record<string, SecretBindingScope> = {
  GIT_TOKEN: "source.git",
  LLM_API_KEY: "ai.explain",
  TELEGRAM_BOT_TOKEN: "notify.telegram",
  WEBHOOK_HMAC_SECRET: "notify.webhook",
  SMTP_PASSWORD: "notify.smtp",
  GIT_WEBHOOK_SECRET: "trigger.webhook",
  MCP_AUTH_HEADER: "mcp.tool",
  GENERIC: "generic",
};

function kindFromBinding(binding: SecretBindingScope): string {
  return KIND_BY_BINDING[binding] ?? "GENERIC";
}

function bindingFromKind(kind: string): SecretBindingScope {
  return BINDING_BY_KIND[kind] ?? "generic";
}

function isTokenScope(scope: string): scope is TokenScope {
  return (
    scope === "ci:startRun" ||
    scope === "ci:readRun" ||
    scope === "mcp:read" ||
    scope === "mcp:run" ||
    scope === "mcp:write"
  );
}

function formatInputHint(inputSchema: unknown): string {
  if (inputSchema && typeof inputSchema === "object") {
    const props = (inputSchema as { properties?: Record<string, unknown> }).properties;
    if (props && typeof props === "object") {
      const keys = Object.keys(props);
      if (keys.length > 0) return `{ ${keys.join(", ")} }`;
    }
  }
  return "{}";
}

interface SettingsBaseResponse {
  aiProviderStatus: {
    providerMode: string;
    modelId: string;
    endpointHost: string;
    healthy: boolean;
  };
  aiAuditLogs: {
    items: Array<{
      id: string;
      runId?: string | null;
      operation: string;
      modelId: string;
      quality: string;
      strippedHallucinatedAdvisories: number;
      latencyMs: number | string;
      createdAt: string;
    }>;
  };
  mcpConnections: Array<{
    id: string;
    enabled: boolean;
    config: { name: string; endpointUrl: string; authSecretRef?: string | null };
  }>;
  runs: { totalCount: number | string };
  workflows: { items: Array<{ id: string; name: string }> };
}

interface SettingsSecretsResponse {
  secrets: Array<{
    secretRef: string;
    name: string;
    kind: string;
    maskedPreview: string;
    updatedAt?: string;
    createdBy?: string;
  }>;
}

interface SettingsTokensResponse {
  scopedTokens: Array<{
    tokenId: string;
    name: string;
    tokenPrefix: string;
    scopes: string[];
    workflowId?: string | null;
    expiresAt?: string | null;
    lastUsedAt?: string | null;
    revokedAt?: string | null;
  }>;
}

export function SettingsShell() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const activeTab = normalizeSettingsTab(searchParams.get("tab"));

  const {
    role,
    setRole,
    backendConnected,
    pluginPresets,
    pluginInstallations,
    livePlugins,
    declarativeBlueprints,
    installPlugin,
    approvePluginInstallation,
    updatePluginInstallation,
    setPluginInstallationEnabled,
    deletePluginInstallation,
    refreshPluginControlPlane,
    testDeclarativePlugin,
  } = useWorkspacePreview();
  const [secrets, setSecrets] = useState<SecretRecord[]>([]);
  const [tokens, setTokens] = useState<ScopedTokenRecord[]>([]);
  const [workflows, setWorkflows] = useState<Array<{ id: string; name: string }>>([]);
  const [aiConfig, setAiConfig] = useState<AiProviderConfig>({
    ...INITIAL_AI_CONFIG,
    endpointUrl: "",
    model: "",
    secretRef: "",
    lastLatencyMs: 0,
    lastCheckedAt: "—",
  });
  const [aiAuditLogs, setAiAuditLogs] = useState<AiAuditLogRecord[]>([]);
  const [mcpConnections, setMcpConnections] = useState<McpConnectionRecord[]>([]);
  const [runsCount, setRunsCount] = useState(0);

  const [notice, setNotice] = useState<FeedbackNotice | null>(null);
  const timersRef = useRef<number[]>([]);
  const activeMobileTabRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    activeMobileTabRef.current?.scrollIntoView({
      behavior: "instant",
      inline: "center",
      block: "nearest",
    });
  }, [activeTab]);

  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      timers.forEach((t) => window.clearTimeout(t));
    };
  }, []);

  const showNotice = useCallback((text: string) => {
    const id = Date.now();
    setNotice({ id, text });
    const timer = window.setTimeout(() => {
      setNotice((prev) => (prev?.id === id ? null : prev));
    }, 4500);
    timersRef.current.push(timer);
  }, []);

  const loadSettings = useCallback(async () => {
    const allowSecrets = canManageSecrets(role);
    const allowTokens = canManageOwnerOnly(role);

    const [baseData, secretsData, tokensData, providerCfg] = await Promise.all([
      gql<SettingsBaseResponse>(QUERIES.settingsBase),
      allowSecrets ? gql<SettingsSecretsResponse>(QUERIES.settingsSecrets) : Promise.resolve(null),
      allowTokens ? gql<SettingsTokensResponse>(QUERIES.settingsTokens) : Promise.resolve(null),
      getAiProviderConfig().catch(() => null),
    ]);

    if (secretsData) {
      setSecrets(
        secretsData.secrets.map((item) => ({
          id: item.secretRef,
          name: item.name,
          maskedValue: item.maskedPreview,
          binding: bindingFromKind(item.kind),
          updatedAt: item.updatedAt ? new Date(item.updatedAt).toLocaleString("ru-RU") : "—",
          createdBy: item.createdBy || "—",
        })),
      );
    } else {
      setSecrets([]);
    }

    if (tokensData) {
      setTokens(
        tokensData.scopedTokens.map((item) => ({
          id: item.tokenId,
          name: item.name,
          prefix: item.tokenPrefix,
          scopes: item.scopes.filter(isTokenScope),
          workflowScope: item.workflowId || "",
          expiresAt: item.expiresAt ? item.expiresAt.slice(0, 10) : "Бессрочно",
          lastUsedAt: item.lastUsedAt
            ? new Date(item.lastUsedAt).toLocaleString("ru-RU")
            : "Ещё не использовался",
          status: item.revokedAt ? "REVOKED" : "ACTIVE",
        })),
      );
    } else {
      setTokens([]);
    }

    setWorkflows(baseData.workflows?.items ?? []);

    if (providerCfg) {
      setAiConfig({
        mode: providerCfg.mode,
        endpointUrl: providerCfg.endpointUrl,
        model: providerCfg.model,
        secretRef: providerCfg.secretRef,
        timeoutSec: providerCfg.timeoutSec || 60,
        strictGrounding: true,
        allowTextToWorkflow: providerCfg.allowTextToWorkflow,
        status: providerCfg.status,
        lastLatencyMs: providerCfg.lastLatencyMs || 0,
        lastCheckedAt:
          providerCfg.lastCheckedAt && providerCfg.lastCheckedAt !== "—"
            ? new Date(providerCfg.lastCheckedAt).toLocaleString("ru-RU")
            : "—",
      });
    } else {
      setAiConfig((prev) => ({
        ...prev,
        mode:
          baseData.aiProviderStatus.providerMode === "OLLAMA"
            ? "local-ollama"
            : baseData.aiProviderStatus.providerMode === "CLOUD"
              ? "openai-compatible"
              : "deterministic-only",
        endpointUrl:
          baseData.aiProviderStatus.endpointHost === "local"
            ? ""
            : baseData.aiProviderStatus.endpointHost,
        model: baseData.aiProviderStatus.modelId,
        status:
          baseData.aiProviderStatus.providerMode === "TEMPLATE_FALLBACK"
            ? "DISABLED"
            : baseData.aiProviderStatus.healthy
              ? "HEALTHY"
              : "DEGRADED",
        lastCheckedAt: "С сервера",
      }));
    }

    setAiAuditLogs(
      baseData.aiAuditLogs.items.map((item) => ({
        id: item.id,
        timestamp: new Date(item.createdAt).toLocaleString("ru-RU"),
        operation: item.operation === "GENERATE_WORKFLOW" ? "GenerateWorkflow" : "ai.explain",
        runId: item.runId || "—",
        model: item.modelId,
        findingsGrounded: item.quality,
        hallucinatedCve: item.strippedHallucinatedAdvisories,
        latencyMs: Number(item.latencyMs || 0),
        status: item.quality === "VERIFIED" ? "OK" : "FALLBACK",
      })),
    );

    setMcpConnections((prev) => {
      const prevById = new Map(prev.map((conn) => [conn.id, conn]));
      return baseData.mcpConnections.map((item) => {
        const existing = prevById.get(item.id);
        return {
          id: item.id,
          name: item.config.name,
          transport: "Streamable HTTP",
          endpointUrl: item.config.endpointUrl,
          authSecretRef: item.config.authSecretRef || "",
          status: !item.enabled ? "ERROR" : existing?.status ?? "UNTESTED",
          lastTestedAt: existing?.lastTestedAt ?? "—",
          latencyMs: existing?.latencyMs ?? 0,
          tools: existing?.tools ?? [],
        };
      });
    });

    setRunsCount(Number(baseData.runs.totalCount || 0));
  }, [role]);

  useEffect(() => {
    void loadSettings().catch((err: unknown) => {
      showNotice(err instanceof Error ? err.message : "Не удалось загрузить настройки");
    });
  }, [loadSettings, showNotice]);

  const selectTab = useCallback(
    (tabId: SettingsTabId) => {
      router.replace(`/settings?tab=${tabId}`, { scroll: false });
    },
    [router],
  );

  // Handlers for Secrets
  const handleCreateSecret = useCallback(
    (payload: { name: string; value: string; binding: SecretBindingScope }) => {
      void gql(QUERIES.createSecret, {
        input: {
          name: payload.name,
          kind: kindFromBinding(payload.binding),
          plaintextValue: payload.value,
        },
      })
        .then(() => loadSettings())
        .then(() => showNotice(`Секрет ${payload.name} сохранён на сервере`))
        .catch((err: unknown) =>
          showNotice(err instanceof ApiError ? err.message : "Не удалось сохранить секрет"),
        );
    },
    [loadSettings, showNotice],
  );

  const handleDeleteSecret = useCallback(
    (id: string) => {
      const target = secrets.find((item) => item.id === id);
      void gql(QUERIES.deleteSecret, { secretRef: id })
        .then(() => loadSettings())
        .then(() => showNotice(`Секрет ${target?.name ?? id} удалён`))
        .catch((err: unknown) =>
          showNotice(err instanceof Error ? err.message : "Не удалось удалить секрет"),
        );
    },
    [loadSettings, secrets, showNotice],
  );

  // Handlers for Scoped Tokens
  const handleCreateToken = useCallback(
    async (payload: {
      name: string;
      scopes: TokenScope[];
      workflowScope: string;
      expiresInDays: number | null;
    }) => {
      const expiresAt =
        payload.expiresInDays === null
          ? undefined
          : new Date(Date.now() + payload.expiresInDays * 24 * 60 * 60 * 1000).toISOString();
      try {
        const data = await gql<{ createScopedToken: { plaintextToken: string } }>(
          QUERIES.createToken,
          {
            input: {
              name: payload.name,
              scopes: payload.scopes,
              workflowId: payload.workflowScope ? payload.workflowScope : undefined,
              expiresAt,
            },
          },
        );
        await loadSettings();
        showNotice(`Токен «${payload.name}» выпущен. Сохраните его: он больше не будет показан.`);
        return data.createScopedToken.plaintextToken;
      } catch (err) {
        showNotice(err instanceof ApiError ? err.message : "Не удалось выпустить токен");
        return "";
      }
    },
    [loadSettings, showNotice],
  );

  const handleRevokeToken = useCallback(
    (id: string) => {
      const target = tokens.find((tok) => tok.id === id);
      void gql(QUERIES.revokeToken, { tokenId: id })
        .then(() => loadSettings())
        .then(() => showNotice(`Токен «${target?.name ?? id}» отозван`))
        .catch((err: unknown) =>
          showNotice(err instanceof Error ? err.message : "Не удалось отозвать токен"),
        );
    },
    [loadSettings, showNotice, tokens],
  );

  // Handlers for AI Provider
  const handleSaveAiConfig = useCallback(
    async (next: AiProviderConfig) => {
      const saved = await saveAiProviderConfig({
        mode: next.mode,
        endpointUrl: next.endpointUrl,
        model: next.model,
        secretRef: next.secretRef,
        timeoutSec: next.timeoutSec,
        allowTextToWorkflow: next.allowTextToWorkflow,
      });
      setAiConfig({
        mode: saved.mode,
        endpointUrl: saved.endpointUrl,
        model: saved.model,
        secretRef: saved.secretRef,
        timeoutSec: saved.timeoutSec,
        strictGrounding: true,
        allowTextToWorkflow: saved.allowTextToWorkflow,
        status: saved.status,
        lastLatencyMs: saved.lastLatencyMs || 0,
        lastCheckedAt: new Date(saved.lastCheckedAt || Date.now()).toLocaleString("ru-RU"),
      });
      if (saved.errorMessage) {
        showNotice(`Настройки сохранены, но проверка эндпоинта вернула ошибку: ${saved.errorMessage}`);
      } else {
        showNotice("Настройки AI-провайдера сохранены на сервере");
      }
    },
    [showNotice],
  );

  const handleTestAiConnection = useCallback(
    async (candidate: AiProviderConfig): Promise<AiModelsProbeResponse | null> => {
      try {
        const res = await testAiProviderConnection({
          mode: candidate.mode,
          endpointUrl: candidate.endpointUrl,
          model: candidate.model,
          secretRef: candidate.secretRef,
        });
        if (res.ok) {
          showNotice(`Подключение подтверждено (${res.latencyMs} мс, моделей: ${res.models.length})`);
        } else {
          showNotice(res.error || "AI-провайдер не ответил");
        }
        return res;
      } catch (err: unknown) {
        showNotice(err instanceof Error ? err.message : "Ошибка проверки соединения");
        return null;
      }
    },
    [showNotice],
  );

  // Handlers for MCP Connections
  const handleRegisterMcp = useCallback(
    (payload: {
      name: string;
      transport: "Streamable HTTP" | "SSE";
      endpointUrl: string;
      authSecretRef: string;
    }) => {
      void gql(QUERIES.registerMcp, {
        input: {
          config: {
            name: payload.name,
            endpointUrl: payload.endpointUrl,
            authSecretRef: payload.authSecretRef || null,
            authHeaderName: "Authorization",
          },
        },
      })
        .then(() => loadSettings())
        .then(() => showNotice(`MCP-подключение ${payload.name} зарегистрировано`))
        .catch((err: unknown) =>
          showNotice(err instanceof Error ? err.message : "Не удалось зарегистрировать MCP"),
        );
    },
    [loadSettings, showNotice],
  );

  const handleLoadMcpTools = useCallback(
    async (connectionId: string) => {
      try {
        const res = await gql<{
          mcpConnectionTools: {
            tools: Array<{ name: string; description: string; inputSchema?: unknown }>;
          };
        }>(QUERIES.mcpTools, { id: connectionId, forceRefresh: false });
        const mapped: McpToolInfo[] = res.mcpConnectionTools.tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputHint: formatInputHint(tool.inputSchema),
        }));
        setMcpConnections((prev) =>
          prev.map((conn) => (conn.id === connectionId ? { ...conn, tools: mapped } : conn)),
        );
      } catch (err) {
        showNotice(err instanceof Error ? err.message : "Не удалось загрузить список tools");
      }
    },
    [showNotice],
  );

  const handleTestMcp = useCallback(
    async (id: string) => {
      const started = Date.now();
      try {
        const test = await gql<{
          testMcpConnection: {
            ok: boolean;
            errorMessage?: string | null;
            availableToolCount: number;
          };
        }>(QUERIES.testMcp, { id });
        const latency = Date.now() - started;

        if (!test.testMcpConnection.ok) {
          setMcpConnections((prev) =>
            prev.map((conn) =>
              conn.id === id
                ? {
                    ...conn,
                    status: "ERROR",
                    lastTestedAt: "Только что",
                    latencyMs: latency,
                  }
                : conn,
            ),
          );
          showNotice(test.testMcpConnection.errorMessage || "MCP-подключение не ответило");
          return;
        }

        let mappedTools: McpToolInfo[] = [];
        try {
          const tools = await gql<{
            mcpConnectionTools: {
              tools: Array<{ name: string; description: string; inputSchema?: unknown }>;
            };
          }>(QUERIES.mcpTools, { id, forceRefresh: true });
          mappedTools = tools.mcpConnectionTools.tools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            inputHint: formatInputHint(tool.inputSchema),
          }));
        } catch {
          // keep empty tools if tools/list fails separately
        }

        setMcpConnections((prev) =>
          prev.map((conn) =>
            conn.id === id
              ? {
                  ...conn,
                  status: "CONNECTED",
                  lastTestedAt: "Только что",
                  latencyMs: latency,
                  tools: mappedTools,
                }
              : conn,
          ),
        );
        showNotice(
          `MCP-подключение отвечает, доступно инструментов: ${test.testMcpConnection.availableToolCount}`,
        );
      } catch (err) {
        setMcpConnections((prev) =>
          prev.map((conn) =>
            conn.id === id
              ? { ...conn, status: "ERROR", lastTestedAt: "Только что" }
              : conn,
          ),
        );
        showNotice(err instanceof Error ? err.message : "Проверка MCP-подключения не удалась");
      }
    },
    [showNotice],
  );

  const handleDeleteMcp = useCallback(
    (id: string) => {
      const found = mcpConnections.find((item) => item.id === id);
      void gql(QUERIES.deleteMcp, { id })
        .then(() => loadSettings())
        .then(() => showNotice(`MCP-подключение ${found?.name ?? id} удалено`))
        .catch((err: unknown) =>
          showNotice(err instanceof Error ? err.message : "Не удалось удалить MCP"),
        );
    },
    [loadSettings, mcpConnections, showNotice],
  );

  const handleLogout = useCallback(() => {
    clearSession();
    showNotice("Сессия завершена");
  }, [showNotice]);

  const getTabMetaBadge = (id: SettingsTabId): string | null => {
    switch (id) {
      case "secrets":
        return canManageSecrets(role) ? String(secrets.length) : null;
      case "tokens":
        return canManageOwnerOnly(role)
          ? String(tokens.filter((t) => t.status === "ACTIVE").length)
          : null;
      case "mcp":
        return String(mcpConnections.length);
      case "plugins":
        return String(pluginInstallations.filter((p) => p.status === "ACTIVE").length);
      default:
        return null;
    }
  };

  const isTabRestricted = (id: SettingsTabId): boolean => {
    if (id === "secrets") return !canManageSecrets(role);
    if (id === "tokens") return !canManageOwnerOnly(role);
    return false;
  };

  return (
    <div className="flex min-h-dvh flex-col bg-[#ffffff] text-[#000000]">
      <FlowmappHeader
        role={role}
        activeSection="settings"
        runsCount={runsCount}
        templatesCount={0}
        onNavigateHint={showNotice}
      />

      {/* Mobile horizontal tab bar */}
      <div className="border-b border-[#8c9baa]/45 bg-[#ffffff] md:hidden">
        <nav
          aria-label="Разделы настроек"
          className="fm-scroll flex items-center gap-1.5 overflow-x-auto overscroll-x-contain px-3 py-2"
        >
          {SETTINGS_TABS.map((tab) => {
            const active = activeTab === tab.id;
            const badge = getTabMetaBadge(tab.id);
            return (
              <button
                key={tab.id}
                ref={active ? activeMobileTabRef : undefined}
                type="button"
                onClick={() => selectTab(tab.id)}
                aria-current={active ? "page" : undefined}
                className={`fm-focus inline-flex min-h-[44px] shrink-0 cursor-pointer select-none items-center gap-1.5 rounded-full px-3.5 text-[13px] transition-colors ${
                  active
                    ? "bg-[#c5e0fb]/45 font-semibold text-[#000000]"
                    : "font-medium text-[#636f7b] hover:bg-[#f6faff] hover:text-[#000000]"
                }`}
              >
                <TabIcon id={tab.id} active={active} />
                <span>{tab.shortLabel}</span>
                {tab.id === "plugins" && badge !== null && (
                  <span className="fm-tnum rounded-full border border-[#8c9baa]/50 bg-[#ffffff] px-1.5 py-0.5 text-[11px] font-semibold leading-none text-[#636f7b]">
                    {badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Main 2-column layout matching wireframe: Sidebar + Content */}
      <div className="mx-auto flex w-full max-w-[1200px] flex-1">
        {/* Desktop left sidebar */}
        <aside
          aria-label="Навигация настроек"
          className="hidden w-[260px] shrink-0 border-r border-[#8c9baa]/45 bg-[#ffffff] py-5 pr-3 pl-4 md:block lg:pl-6"
        >
          <nav className="sticky top-[72px] flex flex-col gap-1">
            {SETTINGS_TABS.map((tab) => {
              const active = activeTab === tab.id;
              const badge = getTabMetaBadge(tab.id);
              const restricted = isTabRestricted(tab.id);
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => selectTab(tab.id)}
                  aria-current={active ? "page" : undefined}
                  className={`fm-focus flex min-h-[42px] w-full cursor-pointer items-center justify-between gap-2 rounded-[12px] px-3 text-left text-[14px] transition-colors ${
                    active
                      ? "bg-[#c5e0fb]/40 font-semibold text-[#000000]"
                      : "font-medium text-[#222222] hover:bg-[#f6faff] hover:text-[#000000]"
                  }`}
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    <TabIcon id={tab.id} active={active} />
                    <span className="truncate">{tab.label}</span>
                  </span>

                  {restricted ? (
                    <Lock className="h-3.5 w-3.5 shrink-0 text-[#8c9baa]" aria-hidden="true" />
                  ) : (
                    badge !== null && (
                      <span className="fm-tnum rounded-full border border-[#8c9baa]/50 bg-[#ffffff] px-1.5 py-0.5 text-[12px] font-semibold leading-none text-[#636f7b]">
                        {badge}
                      </span>
                    )
                  )}
                </button>
              );
            })}
          </nav>
        </aside>

        {/* Active tab content */}
        <main className="min-w-0 flex-1 px-4 py-6 sm:px-6 md:px-8 md:py-7">
          {activeTab === "profile" && (
            <ProfileTab
              role={role}
              onChangeRole={setRole}
              onNotice={showNotice}
              onLogout={handleLogout}
            />
          )}

          {activeTab === "secrets" && (
            <SecretsTab
              role={role}
              secrets={secrets}
              onCreateSecret={handleCreateSecret}
              onDeleteSecret={handleDeleteSecret}
              onSwitchToProfile={() => selectTab("profile")}
            />
          )}

          {activeTab === "tokens" && (
            <TokensTab
              role={role}
              tokens={tokens}
              workflows={workflows}
              onCreateToken={handleCreateToken}
              onRevokeToken={handleRevokeToken}
              onSwitchToProfile={() => selectTab("profile")}
              onNotice={showNotice}
            />
          )}

          {activeTab === "ai" && (
            <AiProviderTab
              role={role}
              config={aiConfig}
              secrets={secrets}
              auditLogs={aiAuditLogs}
              onSaveConfig={handleSaveAiConfig}
              onTestConnection={handleTestAiConnection}
            />
          )}

          {activeTab === "mcp" && (
            <McpServersTab
              role={role}
              connections={mcpConnections}
              secrets={secrets}
              onRegisterConnection={handleRegisterMcp}
              onTestConnection={handleTestMcp}
              onExpandTools={handleLoadMcpTools}
              onDeleteConnection={handleDeleteMcp}
            />
          )}

          {activeTab === "plugins" && (
            <PluginsTab
              role={role}
              backendConnected={backendConnected}
              presets={pluginPresets}
              installations={pluginInstallations}
              livePlugins={livePlugins}
              declarativeBlueprints={declarativeBlueprints}
              secrets={secrets}
              onInstallPlugin={installPlugin}
              onApproveInstallation={approvePluginInstallation}
              onUpdateInstallation={updatePluginInstallation}
              onSetEnabled={setPluginInstallationEnabled}
              onDeleteInstallation={deletePluginInstallation}
              onTestDeclarativePlugin={testDeclarativePlugin}
              onRefresh={refreshPluginControlPlane}
              onNotice={showNotice}
            />
          )}
        </main>
      </div>

      {notice && (
        <FlowmappNoticeBar
          notice={notice}
          onUndo={() => setNotice(null)}
          onDismiss={() => setNotice(null)}
        />
      )}
    </div>
  );
}
