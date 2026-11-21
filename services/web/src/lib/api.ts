import { authToken, clearSession } from "./session";

export interface GraphQLErrorItem {
  message?: string;
  extensions?: {
    code?: string;
    [key: string]: unknown;
  };
}

export class ApiError extends Error {
  code?: string;
  codes: string[];
  status?: number;

  constructor(message: string, opts?: { code?: string; codes?: string[]; status?: number }) {
    super(message);
    this.name = "ApiError";
    this.code = opts?.code;
    this.codes = opts?.codes ?? (opts?.code ? [opts.code] : []);
    this.status = opts?.status;
  }
}

export function apiBase(): string {
  return (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080").replace(/\/$/, "");
}

export function generateTraceparent(): string {
  const randomHex = (byteCount: number): string => {
    const bytes = new Uint8Array(byteCount);
    if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
      crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < byteCount; i += 1) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    if (bytes.every((b) => b === 0)) {
      bytes[byteCount - 1] = 1;
    }
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  };
  return `00-${randomHex(16)}-${randomHex(8)}-01`;
}

function authHeaders(opts?: { auth?: boolean; json?: boolean }): Record<string, string> {
  const headers: Record<string, string> = {
    traceparent: generateTraceparent(),
  };
  if (opts?.json) {
    headers["content-type"] = "application/json";
  }
  if (opts?.auth !== false) {
    const token = authToken();
    if (token) headers.authorization = `Bearer ${token}`;
  }
  return headers;
}

export async function gql<T>(
  query: string,
  variables?: Record<string, unknown>,
  opts?: { auth?: boolean },
): Promise<T> {
  const res = await fetch(`${apiBase()}/graphql`, {
    method: "POST",
    headers: authHeaders({ auth: opts?.auth, json: true }),
    body: JSON.stringify({ query, variables }),
  });

  if (res.status === 401 && opts?.auth !== false) {
    clearSession();
  }

  let body: { data?: T; errors?: GraphQLErrorItem[] };
  try {
    body = (await res.json()) as { data?: T; errors?: GraphQLErrorItem[] };
  } catch {
    throw new ApiError(`Сервер ответил ${res.status}`, {
      code: res.status === 401 ? "UNAUTHENTICATED" : undefined,
      status: res.status,
    });
  }

  if (body.errors?.length) {
    const codes = body.errors
      .map((item) => item.extensions?.code)
      .filter((code): code is string => typeof code === "string" && code.length > 0);
    const message = [...new Set(body.errors.map((item) => item.message || "ошибка"))].join("; ");
    const unauthenticated =
      res.status === 401 || body.errors.some((e) => e.extensions?.code === "UNAUTHENTICATED");
    if (unauthenticated && opts?.auth !== false) {
      clearSession();
    }
    throw new ApiError(message, {
      code: codes[0] ?? (unauthenticated ? "UNAUTHENTICATED" : undefined),
      codes,
      status: res.status,
    });
  }

  if (!res.ok) {
    throw new ApiError(`Сервер ответил ${res.status}`, {
      code: res.status === 401 ? "UNAUTHENTICATED" : undefined,
      status: res.status,
    });
  }
  if (!body.data) {
    throw new ApiError("Пустой ответ GraphQL", { status: res.status });
  }
  return body.data;
}

async function parseHttpError(res: Response): Promise<ApiError> {
  if (res.status === 401) {
    clearSession();
  }
  let message = `Сервер ответил ${res.status}`;
  let code: string | undefined = res.status === 401 ? "UNAUTHENTICATED" : undefined;
  try {
    const body = (await res.json()) as { code?: string; message?: string; detail?: string };
    if (body.message) message = body.message;
    else if (body.detail) message = body.detail;
    if (body.code) code = body.code;
  } catch {
    // non-JSON response
  }
  return new ApiError(message, { code, status: res.status });
}

export interface UploadSourceResult {
  sourceId: string;
  sha256: string;
  repoName: string;
  sizeBytes: number;
  fileCount: number;
  deduplicatedHit: boolean;
  bucket?: string;
  key?: string;
  ingestedAt?: string;
}

export async function uploadSource(file: File, repoName?: string): Promise<UploadSourceResult> {
  const form = new FormData();
  form.append("file", file);
  if (repoName && repoName.trim()) {
    form.append("repoName", repoName.trim());
  }
  const res = await fetch(`${apiBase()}/upload`, {
    method: "POST",
    headers: authHeaders({ auth: true, json: false }),
    body: form,
  });
  if (!res.ok) {
    throw await parseHttpError(res);
  }
  return (await res.json()) as UploadSourceResult;
}

export interface UploadCatalogResult {
  id: string;
  name: string;
  sha256: string;
  snapshotDate: string;
  advisoryCount: number;
  isDefault: boolean;
  ecosystem?: string;
  versionFormat?: string;
  s3Key?: string;
}

export async function uploadCatalog(
  file: File,
  name: string,
  snapshotDate?: string,
  setAsDefault?: boolean,
): Promise<UploadCatalogResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("name", name.trim());
  if (snapshotDate && snapshotDate.trim()) {
    form.append("snapshotDate", snapshotDate.trim());
  }
  if (typeof setAsDefault === "boolean") {
    form.append("setAsDefault", String(setAsDefault));
  }
  const res = await fetch(`${apiBase()}/catalogs/upload`, {
    method: "POST",
    headers: authHeaders({ auth: true, json: false }),
    body: form,
  });
  if (!res.ok) {
    throw await parseHttpError(res);
  }
  return (await res.json()) as UploadCatalogResult;
}

function filenameFromDisposition(header: string | null, fallback: string): string {
  if (!header) return fallback;
  const utf8Match = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1].trim());
    } catch {
      return utf8Match[1].trim();
    }
  }
  const plainMatch = /filename="?([^";]+)"?/i.exec(header);
  if (plainMatch?.[1]) {
    return plainMatch[1].trim();
  }
  return fallback;
}

export async function downloadArtifact(
  pathOrUrl: string,
  fallbackFilename: string,
): Promise<void> {
  const url = /^https?:\/\//i.test(pathOrUrl)
    ? pathOrUrl
    : `${apiBase()}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`;
  const res = await fetch(url, {
    method: "GET",
    headers: authHeaders({ auth: true, json: false }),
  });
  if (!res.ok) {
    throw await parseHttpError(res);
  }
  const blob = await res.blob();
  const filename = filenameFromDisposition(res.headers.get("content-disposition"), fallbackFilename);
  const objectUrl = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  }
}

export interface RunEventMessage {
  seqId: number | string;
  runId: string;
  eventType:
    | "RUN_STARTED"
    | "NODE_STATUS_CHANGED"
    | "EDGE_TRAVERSED"
    | "FINDINGS_UPDATED"
    | "SBOM_READY"
    | "AI_REPORT_READY"
    | "GATE_EVALUATED"
    | "RUN_COMPLETED"
    | "RUN_FAILED"
    | "RUN_CANCELLED";
  runStatus: "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "CANCELLED";
  nodeId?: string | null;
  nodeRunId?: string | null;
  nodeStatus?: "PENDING" | "RUNNING" | "SUCCEEDED" | "FAILED" | "SKIPPED" | "CANCELLED" | null;
  edgeId?: string | null;
  sourceHandle?: string | null;
  stats?: {
    total: number;
    newCount: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    secretCount: number;
    sastCount: number;
    scaCount: number;
    maxSeverity?: string | null;
  } | null;
  gateResult?: {
    status: "PASS" | "WARN" | "FAIL";
    reason: string;
    nodeId: string;
  } | null;
  redactedPreview?: unknown;
  message?: string | null;
  createdAt: string;
}

export interface RunEventCallbacks {
  onEvent: (event: RunEventMessage) => void;
  onError?: (error: Error) => void;
  onComplete?: () => void;
  onOpen?: () => void;
}

export function subscribeRunEvents(
  runId: string,
  afterSeq: number,
  callbacks: RunEventCallbacks,
): () => void {
  if (typeof window === "undefined" || typeof WebSocket === "undefined") {
    return () => {};
  }
  const wsUrl = `${apiBase().replace(/^http(s?):\/\//i, "ws$1://")}/graphql`;
  const subId = `run-${runId}-${Date.now().toString(36)}`;
  let closed = false;
  let completed = false;
  let ws: WebSocket;

  try {
    ws = new WebSocket(wsUrl, "graphql-transport-ws");
  } catch (err) {
    callbacks.onError?.(err instanceof Error ? err : new ApiError("WebSocket недоступен"));
    return () => {};
  }

  ws.addEventListener("open", () => {
    if (closed) return;
    const token = authToken();
    const payload: Record<string, string> = {
      traceparent: generateTraceparent(),
    };
    if (token) {
      payload.Authorization = `Bearer ${token}`;
    }
    ws.send(JSON.stringify({ type: "connection_init", payload }));
  });

  ws.addEventListener("message", (event) => {
    if (closed) return;
    let msg: {
      id?: string;
      type?: string;
      payload?: {
        data?: { runEvents?: RunEventMessage };
        errors?: GraphQLErrorItem[];
      } | GraphQLErrorItem[];
    };
    try {
      msg = JSON.parse(String(event.data)) as typeof msg;
    } catch {
      return;
    }

    switch (msg.type) {
      case "connection_ack": {
        callbacks.onOpen?.();
        ws.send(
          JSON.stringify({
            id: subId,
            type: "subscribe",
            payload: {
              query: QUERIES.runEventsSubscription,
              variables: { runId, afterSeq },
            },
          }),
        );
        break;
      }
      case "ping": {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "pong" }));
        }
        break;
      }
      case "next": {
        const body = !Array.isArray(msg.payload) ? msg.payload : undefined;
        if (body?.errors?.length) {
          const codes = body.errors
            .map((e) => e.extensions?.code)
            .filter((c): c is string => typeof c === "string");
          const unauth = codes.includes("UNAUTHENTICATED");
          if (unauth) clearSession();
          const text = body.errors.map((e) => e.message || "ошибка подписки").join("; ");
          callbacks.onError?.(new ApiError(text, { code: codes[0], codes }));
          return;
        }
        const ev = body?.data?.runEvents;
        if (ev) {
          callbacks.onEvent(ev);
        }
        break;
      }
      case "error": {
        const errs = Array.isArray(msg.payload) ? msg.payload : msg.payload?.errors ?? [];
        const codes = errs
          .map((e) => e.extensions?.code)
          .filter((c): c is string => typeof c === "string");
        if (codes.includes("UNAUTHENTICATED")) clearSession();
        const text = errs.map((e) => e.message || "ошибка подписки").join("; ") || "Ошибка подписки WebSocket";
        callbacks.onError?.(new ApiError(text, { code: codes[0], codes }));
        break;
      }
      case "complete": {
        completed = true;
        callbacks.onComplete?.();
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          ws.close(1000, "complete");
        }
        break;
      }
    }
  });

  ws.addEventListener("error", () => {
    if (closed || completed) return;
    callbacks.onError?.(new ApiError("Потеряно WebSocket-соединение"));
  });

  ws.addEventListener("close", (ev) => {
    if (closed || completed) return;
    if (ev.code !== 1000) {
      callbacks.onError?.(new ApiError(`WebSocket закрыт (${ev.code})`));
    } else {
      callbacks.onComplete?.();
    }
  });

  return () => {
    if (closed) return;
    closed = true;
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ id: subId, type: "complete" }));
      }
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close(1000, "unsubscribe");
      }
    } catch {
      // ignore close races
    }
  };
}

const GRAPH = `
  schemaVersion
  nodes { id pluginId label position { x y } params secretBindings { paramKey secretRef } }
  edges { id sourceNodeId sourceHandle targetNodeId targetHandle }
`;

const RUN_FIELDS = `
  id workflowId workflowVersion workflowName status createdAt startedAt finishedAt errorMessage
  parentRunId rerunFromNodeId traceId lastSeqId
  submissionDownloadUrl markdownReportDownloadUrl htmlReportDownloadUrl
  trigger { type repoUrl branch commitSha prNumber gitProvider triggeredBy triggeredAt }
  gateResult { status reason nodeId }
  findingsStats { total newCount critical high medium low secretCount sastCount scaCount maxSeverity }
  sourceRef { sourceId sha256 repoName repoUrl gitRef commitSha sizeBytes fileCount }
  sbom { digest specVersion componentCount vulnerabilityCount downloadUrl generatedAt }
  aiReport {
    quality releaseDecision executiveSummary modelId providerMode privacyMode
    strippedHallucinatedAdvisories cached promptHash tokensIn tokensOut latencyMs createdAt
    groups { title maxSeverity findingIds summary }
    items {
      findingId priorityRank plainLanguageRisk businessImpact remediationSteps referencedAdvisories
      finding { category path line endLine findingClass group artifact version advisoryId severity }
    }
  }
  nodeRuns {
    nodeRunId nodeId pluginId status attempt workerId
    activeOutputPorts redactedPreview findingsEmitted errorMessage durationMs startedAt finishedAt
  }
`;

const SETTINGS_BASE = `query {
  aiProviderStatus { providerMode modelId endpointHost closedLoop defaultPrivacyMode healthy }
  aiAuditLogs(limit: 20) { items { id runId nodeRunId operation modelId providerMode privacyMode quality strippedHallucinatedAdvisories cacheHit latencyMs createdAt } }
  mcpConnections { id enabled config { name description endpointUrl authSecretRef authHeaderName allowedTools deniedTools } }
  runs(limit: 1) { totalCount }
  workflows(limit: 50) { items { id name } }
}`;

export const QUERIES = {
  me: `query {
    me { subject email role scopes scopedWorkflowId authMode }
  }`,
  login: `mutation($input: LoginInput!) {
    login(input: $input) { accessToken tokenType expiresAt actor { subject email role authMode } }
  }`,
  workspace: `query {
    workflows(limit: 50) { items { id name description version updatedAt webhookPath cronExpression graph { ${GRAPH} } } }
    templates(limit: 50) { items { id slug name description problemSolved tags isBuiltin authorSubject cloneCount createdAt updatedAt sanitizedGraph { ${GRAPH} } } }
    runs(limit: 50) { items { ${RUN_FIELDS} } }
  }`,
  run: `query($id: ID!) {
    run(id: $id) { ${RUN_FIELDS} }
  }`,
  findings: `query($runId: ID!, $category: FindingCategory, $minSeverity: Severity, $limit: Int = 100, $cursor: String) {
    findings(runId: $runId, category: $category, minSeverity: $minSeverity, limit: $limit, cursor: $cursor) {
      items {
        findingId fingerprint sourceNodeId pluginId category path findingClass line endLine
        group artifact version advisoryId severity description remediation maskedSnippet isNewVsBaseline
      }
      stats { total newCount critical high medium low secretCount sastCount scaCount maxSeverity }
      nextCursor hasMore totalCount
    }
  }`,
  nodeRunPayload: `query($runId: ID!, $nodeId: ID!, $sourceHandle: String) {
    nodeRunPayload(runId: $runId, nodeId: $nodeId, sourceHandle: $sourceHandle) {
      runId nodeId pluginId status inputEnvelope outputEnvelope activeOutputPorts
      portOutputs { sourceHandle outputEnvelope }
    }
  }`,
  readableReport: `query($runId: ID!, $format: ReportFormat = MARKDOWN) {
    readableReport(runId: $runId, format: $format) {
      format content findingCount downloadUrl
    }
  }`,
  validateWorkflow: `query($graph: WorkflowGraphInput!) {
    validateWorkflow(graph: $graph) {
      valid
      issues { code severity message nodeId edgeId fieldPath }
    }
  }`,
  catalogs: `query {
    catalogs { id name ecosystem versionFormat s3Key sha256 snapshotDate advisoryCount isDefault uploadedBy createdAt }
  }`,
  plugins: `query($category: PluginCategory, $includeOffline: Boolean = false) {
    plugins(category: $category, includeOffline: $includeOffline) {
      pluginId version displayName description category capabilities paramsJsonSchema
      inputPorts { id label description }
      outputPorts { id label description }
      runtimeLanguage sandboxProfile isExternal requiredSecretKeys status activeWorkers queueDepth
    }
  }`,
  save: `mutation($input: SaveWorkflowInput!) {
    saveWorkflow(input: $input) { id name description version updatedAt graph { ${GRAPH} } }
  }`,
  deleteWorkflow: `mutation($id: ID!) { deleteWorkflow(id: $id) }`,
  startRun: `mutation($input: StartRunInput!) { startRun(input: $input) { id status } }`,
  cancelRun: `mutation($runId: ID!, $reason: String) {
    cancelRun(runId: $runId, reason: $reason) { id status errorMessage finishedAt }
  }`,
  rerunFromNode: `mutation($input: RerunFromNodeInput!) {
    rerunFromNode(input: $input) { id status parentRunId rerunFromNodeId }
  }`,
  generateCiConfig: `mutation($input: GenerateCiConfigInput!) {
    generateCiConfig(input: $input) { provider filename yamlContent requiredCiSecrets }
  }`,
  clone: `mutation($input: CloneTemplateInput!) {
    cloneTemplate(input: $input) { id name description version updatedAt graph { ${GRAPH} } }
  }`,
  publish: `mutation($input: PublishTemplateInput!) {
    publishTemplate(input: $input) { id slug name description problemSolved tags isBuiltin authorSubject cloneCount createdAt updatedAt sanitizedGraph { ${GRAPH} } }
  }`,
  generate: `mutation($input: GenerateWorkflowFromTextInput!) {
    generateWorkflowFromText(input: $input) {
      suggestedName suggestedDescription rationale modelId providerMode
      graph { ${GRAPH} }
      missingFields { code severity message nodeId fieldPath }
    }
  }`,
  settings: SETTINGS_BASE,
  settingsBase: SETTINGS_BASE,
  settingsSecrets: `query {
    secrets { secretRef name kind maskedPreview backend updatedAt createdBy }
  }`,
  settingsTokens: `query {
    scopedTokens { tokenId name tokenPrefix scopes workflowId expiresAt lastUsedAt revokedAt createdAt }
  }`,
  createSecret: `mutation($input: CreateSecretInput!) {
    createSecret(input: $input) { secretRef name kind maskedPreview backend updatedAt createdBy }
  }`,
  deleteSecret: `mutation($secretRef: ID!) { deleteSecret(secretRef: $secretRef) }`,
  createToken: `mutation($input: CreateScopedTokenInput!) {
    createScopedToken(input: $input) { plaintextToken metadata { tokenId name tokenPrefix scopes workflowId expiresAt lastUsedAt revokedAt createdAt } }
  }`,
  revokeToken: `mutation($tokenId: ID!) { revokeScopedToken(tokenId: $tokenId) }`,
  registerMcp: `mutation($input: RegisterMCPConnectionInput!) {
    registerMcpConnection(input: $input) { id enabled config { name description endpointUrl authSecretRef authHeaderName } }
  }`,
  testMcp: `mutation($id: ID!) { testMcpConnection(id: $id) { ok serverName serverVersion availableToolCount blockedToolCount errorMessage } }`,
  mcpTools: `query($id: ID!, $forceRefresh: Boolean = false) {
    mcpConnectionTools(connectionId: $id, forceRefresh: $forceRefresh) {
      connectionId blockedToolCount fetchedAt
      tools { name description inputSchema }
    }
  }`,
  deleteMcp: `mutation($id: ID!) { deleteMcpConnection(id: $id) }`,
  runEventsSubscription: `subscription($runId: ID!, $afterSeq: BigInt = 0) {
    runEvents(runId: $runId, afterSeq: $afterSeq) {
      seqId runId eventType runStatus nodeId nodeRunId nodeStatus edgeId sourceHandle
      stats { total newCount critical high medium low secretCount sastCount scaCount maxSeverity }
      gateResult { status reason nodeId }
      redactedPreview message createdAt
    }
  }`,
};
