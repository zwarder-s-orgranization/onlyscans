import type {
  DeclarativeBlueprintRecord,
  SavedNodeRecord,
  TestDeclarativePluginInput,
  TestDeclarativePluginResult,
} from "@/data/declarative-plugin-data";
import type {
  InstallPluginFormInput,
  LivePluginRecord,
  PluginInstallationRecord,
  PluginPresetRecord,
  UpdatePluginInstallationFormInput,
} from "@/data/plugins-data";
import { apiBase } from "./api";
import { authToken } from "./session";

const GRAPHQL_HTTP_URL =
  process.env.NEXT_PUBLIC_GRAPHQL_URL?.trim() || `${apiBase()}/graphql`;

function graphqlWsUrl(): string {
  if (typeof window === "undefined") return "";
  if (GRAPHQL_HTTP_URL.startsWith("https://")) {
    return "wss://" + GRAPHQL_HTTP_URL.slice("https://".length);
  }
  if (GRAPHQL_HTTP_URL.startsWith("http://")) {
    return "ws://" + GRAPHQL_HTTP_URL.slice("http://".length);
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${GRAPHQL_HTTP_URL}`;
}

function getAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return (
      authToken() ||
      window.localStorage.getItem("secflow_access_token") ||
      window.sessionStorage.getItem("secflow_access_token") ||
      null
    );
  } catch {
    return null;
  }
}

interface GraphQLResponse<T> {
  data?: T;
  errors?: Array<{ message: string; extensions?: { code?: string } }>;
}

export async function graphqlRequest<T>(
  query: string,
  variables?: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const token = getAuthToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(GRAPHQL_HTTP_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables }),
    signal,
  });

  if (!res.ok) {
    throw new Error(`GraphQL HTTP ${res.status}`);
  }

  const body = (await res.json()) as GraphQLResponse<T>;
  if (body.errors && body.errors.length > 0) {
    const first = body.errors[0];
    const code = first.extensions?.code ? `[${first.extensions.code}] ` : "";
    throw new Error(`${code}${first.message}`);
  }
  if (!body.data) {
    throw new Error("Empty GraphQL response");
  }
  return body.data;
}

const MANIFEST_FIELDS = `
  pluginId
  version
  displayName
  description
  category
  capabilities
  paramsJsonSchema
  inputPorts { id label description }
  outputPorts { id label description }
  runtimeLanguage
  sandboxProfile
  isExternal
  requiredSecretKeys
  maxConcurrency
`;

const INSTALLATION_FIELDS = `
  id
  name
  sourceMode
  presetId
  imageRef
  sandboxProfile
  egressAllowlist
  resourceLimits {
    cpuRequest
    cpuLimit
    memoryRequest
    memoryLimit
    minReplicas
    maxReplicas
  }
  desiredReplicas
  status
  statusReason
  autoApprove
  approvedManifestDigest
  pluginIds
  manifests { ${MANIFEST_FIELDS} }
  pendingManifests { ${MANIFEST_FIELDS} }
  runtimeDiagnostics {
    phase
    desiredReplicas
    readyReplicas
    message
    lastError
    updatedAt
  }
  createdBy
  approvedBy
  createdAt
  updatedAt
  approvedAt
  declarativeSpec
  pendingDeclarativeSpec
  pluginVersion
`;

const PLUGIN_FIELDS = `
  pluginId
  version
  displayName
  description
  category
  capabilities
  paramsJsonSchema
  inputPorts { id label description }
  outputPorts { id label description }
  runtimeLanguage
  sandboxProfile
  isExternal
  requiredSecretKeys
  status
  activeWorkers
  queueDepth
  installationId
  enabled
  approvalPending
  registeredAt
  lastSeenAt
`;

export async function fetchPluginControlPlane(signal?: AbortSignal): Promise<{
  installations: PluginInstallationRecord[];
  presets: PluginPresetRecord[];
  plugins: LivePluginRecord[];
}> {
  const data = await graphqlRequest<{
    pluginInstallations: PluginInstallationRecord[];
    pluginPresets: PluginPresetRecord[];
    plugins: LivePluginRecord[];
  }>(
    `query PluginControlPlane {
      pluginInstallations { ${INSTALLATION_FIELDS} }
      pluginPresets {
        id
        name
        description
        imageRef
        category
        sandboxProfile
        pluginIds
        outputPorts { id label description }
        requiredSecretKeys
        defaultEgressAllowlist
        defaultResourceLimits {
          cpuRequest cpuLimit memoryRequest memoryLimit minReplicas maxReplicas
        }
        autoApproveSupported
      }
      plugins(includeOffline: true, includeDisabled: true) { ${PLUGIN_FIELDS} }
    }`,
    undefined,
    signal,
  );
  return {
    installations: data.pluginInstallations ?? [],
    presets: data.pluginPresets ?? [],
    plugins: data.plugins ?? [],
  };
}

export async function installPluginMutation(input: InstallPluginFormInput): Promise<{
  installation: PluginInstallationRecord;
  plaintextPluginToken?: string | null;
}> {
  const data = await graphqlRequest<{
    installPlugin: {
      installation: PluginInstallationRecord;
      plaintextPluginToken?: string | null;
    };
  }>(
    `mutation InstallPlugin($input: InstallPluginInput!) {
      installPlugin(input: $input) {
        installation { ${INSTALLATION_FIELDS} }
        plaintextPluginToken
      }
    }`,
    { input },
  );
  return data.installPlugin;
}

export async function approvePluginInstallationMutation(
  installationId: string,
  expectedManifestDigest?: string,
): Promise<PluginInstallationRecord> {
  const data = await graphqlRequest<{
    approvePluginInstallation: PluginInstallationRecord;
  }>(
    `mutation ApprovePlugin($input: ApprovePluginInstallationInput!) {
      approvePluginInstallation(input: $input) { ${INSTALLATION_FIELDS} }
    }`,
    { input: { installationId, expectedManifestDigest } },
  );
  return data.approvePluginInstallation;
}

export async function updatePluginInstallationMutation(
  input: UpdatePluginInstallationFormInput,
): Promise<{
  installation: PluginInstallationRecord;
  plaintextPluginToken?: string | null;
}> {
  const data = await graphqlRequest<{
    updatePluginInstallation: {
      installation: PluginInstallationRecord;
      plaintextPluginToken?: string | null;
    };
  }>(
    `mutation UpdatePlugin($input: UpdatePluginInstallationInput!) {
      updatePluginInstallation(input: $input) {
        installation { ${INSTALLATION_FIELDS} }
        plaintextPluginToken
      }
    }`,
    { input },
  );
  return data.updatePluginInstallation;
}

export async function setPluginInstallationEnabledMutation(
  installationId: string,
  enabled: boolean,
  reason?: string,
): Promise<PluginInstallationRecord> {
  const data = await graphqlRequest<{
    setPluginInstallationEnabled: PluginInstallationRecord;
  }>(
    `mutation SetPluginEnabled($input: SetPluginInstallationEnabledInput!) {
      setPluginInstallationEnabled(input: $input) { ${INSTALLATION_FIELDS} }
    }`,
    { input: { installationId, enabled, reason } },
  );
  return data.setPluginInstallationEnabled;
}

export async function deletePluginInstallationMutation(
  id: string,
  reason?: string,
): Promise<boolean> {
  const data = await graphqlRequest<{ deletePluginInstallation: boolean }>(
    `mutation DeletePlugin($id: ID!, $reason: String) {
      deletePluginInstallation(id: $id, reason: $reason)
    }`,
    { id, reason },
  );
  return Boolean(data.deletePluginInstallation);
}

const SAVED_NODE_FIELDS = `
  id
  name
  description
  pluginId
  params
  canonicalParamsHash
  createdBy
  createdAt
  updatedAt
`;

export async function fetchDeclarativeBlueprints(
  signal?: AbortSignal,
): Promise<DeclarativeBlueprintRecord[]> {
  const data = await graphqlRequest<{
    declarativePluginBlueprints: DeclarativeBlueprintRecord[];
  }>(
    `query DeclarativeBlueprints {
      declarativePluginBlueprints { id name description spec }
    }`,
    undefined,
    signal,
  );
  return data.declarativePluginBlueprints ?? [];
}

export async function testDeclarativePluginMutation(
  input: TestDeclarativePluginInput,
): Promise<TestDeclarativePluginResult> {
  const data = await graphqlRequest<{
    testDeclarativePlugin: TestDeclarativePluginResult;
  }>(
    `mutation TestDeclarativePlugin($input: TestDeclarativePluginInput!) {
      testDeclarativePlugin(input: $input) {
        ok
        validationErrors
        findings {
          findingId
          findingClass
          category
          severity
          path
          line
          description
          maskedSnippet
        }
        activeOutputPorts
        envelopePatch
        dryRunHttp
        durationMs
        summary
      }
    }`,
    { input },
  );
  return data.testDeclarativePlugin;
}

export async function fetchSavedNodes(signal?: AbortSignal): Promise<SavedNodeRecord[]> {
  const data = await graphqlRequest<{ savedNodes: SavedNodeRecord[] }>(
    `query ListSavedNodes {
      savedNodes { ${SAVED_NODE_FIELDS} }
    }`,
    undefined,
    signal,
  );
  return data.savedNodes ?? [];
}

export async function saveNodeMutation(input: {
  name: string;
  description?: string;
  pluginId: string;
  params: Record<string, unknown>;
}): Promise<SavedNodeRecord> {
  const data = await graphqlRequest<{ saveNode: SavedNodeRecord }>(
    `mutation SaveNode($input: SaveNodeInput!) {
      saveNode(input: $input) { ${SAVED_NODE_FIELDS} }
    }`,
    { input },
  );
  return data.saveNode;
}

export async function updateSavedNodeMutation(input: {
  id: string;
  name?: string;
  description?: string;
  params?: Record<string, unknown>;
}): Promise<SavedNodeRecord> {
  const data = await graphqlRequest<{ updateSavedNode: SavedNodeRecord }>(
    `mutation UpdateSavedNode($input: UpdateSavedNodeInput!) {
      updateSavedNode(input: $input) { ${SAVED_NODE_FIELDS} }
    }`,
    { input },
  );
  return data.updateSavedNode;
}

export async function deleteSavedNodeMutation(id: string): Promise<boolean> {
  const data = await graphqlRequest<{ deleteSavedNode: boolean }>(
    `mutation DeleteSavedNode($id: ID!) {
      deleteSavedNode(id: $id)
    }`,
    { id },
  );
  return Boolean(data.deleteSavedNode);
}

/**
 * Lightweight graphql-transport-ws subscriber for pluginRegistryEvents and pluginInstallationEvents.
 * Fails silently when backend WebSocket is unavailable (preview mode takes over seamlessly).
 */
export function subscribeGraphQL<T>(
  query: string,
  variables: Record<string, unknown> | undefined,
  onData: (payload: T) => void,
): () => void {
  if (typeof window === "undefined" || typeof WebSocket === "undefined") {
    return () => {};
  }
  const url = graphqlWsUrl();
  if (!url) return () => {};

  let closed = false;
  let ws: WebSocket | null = null;
  const subId = `sub-${Math.random().toString(36).slice(2, 10)}`;

  try {
    ws = new WebSocket(url, "graphql-transport-ws");
  } catch {
    return () => {};
  }

  ws.onopen = () => {
    if (closed || !ws) return;
    const token = getAuthToken();
    ws.send(
      JSON.stringify({
        type: "connection_init",
        payload: token ? { Authorization: `Bearer ${token}` } : {},
      }),
    );
  };

  ws.onmessage = (event) => {
    if (closed || !ws) return;
    try {
      const msg = JSON.parse(String(event.data)) as {
        type?: string;
        payload?: { data?: T };
      };
      if (msg.type === "connection_ack") {
        ws.send(
          JSON.stringify({
            id: subId,
            type: "subscribe",
            payload: { query, variables },
          }),
        );
      } else if (msg.type === "next" && msg.payload?.data) {
        onData(msg.payload.data);
      }
    } catch {
      // ignore malformed frames
    }
  };

  ws.onerror = () => {
    // quiet fallback when backend is offline
  };

  return () => {
    closed = true;
    try {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ id: subId, type: "complete" }));
      }
      ws?.close();
    } catch {
      // ignore close errors
    }
  };
}

export function subscribePluginRegistryEvents(
  onEvent: (ev: { eventType: string; plugin: LivePluginRecord; occurredAt: string }) => void,
): () => void {
  return subscribeGraphQL<{
    pluginRegistryEvents: {
      eventType: string;
      plugin: LivePluginRecord;
      occurredAt: string;
    };
  }>(
    `subscription { pluginRegistryEvents { eventType occurredAt plugin { ${PLUGIN_FIELDS} } } }`,
    undefined,
    (data) => {
      if (data.pluginRegistryEvents) {
        onEvent(data.pluginRegistryEvents);
      }
    },
  );
}

export function subscribePluginInstallationEvents(
  onEvent: (ev: {
    eventType: string;
    installation: PluginInstallationRecord;
    occurredAt: string;
  }) => void,
): () => void {
  return subscribeGraphQL<{
    pluginInstallationEvents: {
      eventType: string;
      installation: PluginInstallationRecord;
      occurredAt: string;
    };
  }>(
    `subscription { pluginInstallationEvents { eventType occurredAt installation { ${INSTALLATION_FIELDS} } } }`,
    undefined,
    (data) => {
      if (data.pluginInstallationEvents) {
        onEvent(data.pluginInstallationEvents);
      }
    },
  );
}
