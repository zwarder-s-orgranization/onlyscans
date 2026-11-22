# OnlyScans

Платформа визуальной автоматизации проверок безопасности кода и зависимостей (**AI Security Workflow**): конструктор DAG-пайплайнов, собственные детерминированные анализаторы (Kotlin PSI SAST/Secrets, Go SCA, CycloneDX SBOM), grounded AI-объяснения находок, изоляция плагинов в Kubernetes и сквозная наблюдаемость.

---

## Возможности

- **Визуальный редактор workflow** — собственный drag-and-drop конструктор (`Next.js 16` + `@xyflow/react`) с шаблонами, сохранёнными нодами (Saved Nodes), генерацией пайплайна из текста (Text-to-Workflow), выражениями `{{ ... }}` и перезапуском с любого узла (`Re-run from Node`).
- **Детерминированный анализ без сторонних сканеров** — поиск уязвимостей и секретов выполняется только собственными анализаторами без обёрток вокруг Semgrep, Gitleaks, Trivy и чужих rulesets:
  - `worker-kotlin` — SAST и поиск секретов на базе Kotlin PSI;
  - `worker-sca` — анализ зависимостей и сопоставление с базой уязвимостей;
  - `sbom-service` — генерация Product SBOM (CycloneDX).
- **Grounded AI (`explain-only`)** — LLM не ищет уязвимости, а объясняет и предлагает исправления строго по уже найденным `findingId` с валидацией JSON-схемы; поддерживаются OpenAI-совместимый Cloud API, локальный Ollama и `template_fallback`.
- **Единый Pull-протокол gRPC без брокеров очередей** — оркестратор раздаёт задачи подключённым воркерам по gRPC (`WorkerService`) и в Kubernetes умеет сам масштабировать пулы воркеров `0 → N → 0` через Kubernetes API (или через KEDA).
- **Декларативные и внешние плагины** — управление установками через `plugin-provisioner` и два изолированных sandbox-пула (`plugin-runtime-internal` без доступа в интернет и `plugin-runtime-action` для внешних действий).
- **Dual MCP и CI/CD** — входящий MCP-сервер (`/mcp`) и исходящие allowlisted вызовы (`mcp-bridge`), переиспользуемые интеграции для GitHub Actions и GitLab CI, webhook-триггеры и отправка Commit Status.
- **Наблюдаемость из коробки** — сквозная корреляция по `trace_id`: Prometheus (RED-метрики + Exemplars) ↔ Tempo (OTLP-трейсы) ↔ Loki (JSON-логи) в преднастроенной Grafana.

---

## Архитектура и сервисы

| Компонент | Путь | Стек | Порты / роль |
|---|---|---|---|
| **Web UI** | [`services/web`](./services/web) | Next.js 16, React 19, Tailwind CSS 4, `@xyflow/react` | `:3000` — визуальный редактор, история запусков, настройки, шаблоны |
| **Edge Gateway** | [`services/edge-gateway`](./services/edge-gateway) | Go 1.27, GraphQL (`gqlgen`), HTTP/WS, MCP | `:8080` — единая точка входа (GraphQL API + subscriptions, upload/export, webhooks, `/mcp`) |
| **Orchestrator** | [`services/orchestrator`](./services/orchestrator) | Go 1.27, gRPC, PostgreSQL | `:50051` (gRPC), `:8081` (HTTP/metrics) — исполнение DAG, очередь, секреты, пул воркеров, K8s autoscaler |
| **Source Ingester** | [`services/source-ingester`](./services/source-ingester) | Go 1.27, gRPC | `:50052` (gRPC), `:8082` (HTTP) — загрузка Git/архивов по allowlist в Garage S3 |
| **Worker Kotlin** | [`services/worker-kotlin`](./services/worker-kotlin) | Go 1.27 + Kotlin PSI (`Gradle`, JDK 21) | Pull-воркер: `scan.sast.kotlin`, `scan.secrets` (`internal-only`, без доступа в интернет) |
| **Worker SCA** | [`services/worker-sca`](./services/worker-sca) | Go 1.27 | Pull-воркер: `scan.sca` (`internal-only`) |
| **SBOM Service** | [`services/sbom-service`](./services/sbom-service) | Go 1.27 | Pull-воркер: `sbom.generate` (`internal-only`) |
| **AI Service** | [`services/ai-service`](./services/ai-service) | Go 1.27 | `:50053` (gRPC), `:8086` (HTTP) — `ai.explain`, генерация workflow, аудит вызовов |
| **Notify Service** | [`services/notify-service`](./services/notify-service) | Go 1.27 | `:50054` (gRPC), `:8087` (HTTP) — Telegram, Webhook, SMTP, Commit Status |
| **MCP Bridge** | [`services/mcp-bridge`](./services/mcp-bridge) | Go 1.27 | `:8088` — исходящие вызовы внешних MCP-инструментов (`mcp.tool`) |
| **Plugin Provisioner & Runtimes** | [`services/plugin-provisioner`](./services/plugin-provisioner), [`plugin-runtime-internal`](./services/plugin-runtime-internal), [`plugin-runtime-action`](./services/plugin-runtime-action) | Go 1.27 | `:8089`, `:8090`, `:8091` — деплой пользовательских плагинов и исполнение декларативных нод в `secflow-sandbox` |
| **Garage Init** | [`services/garage-init`](./services/garage-init) | Go 1.27 | Инициализация Garage S3 (`2.5.0`), создание бакетов и сидирование каталога уязвимостей |
| **Демо-плагины** | [`services/demo-spring-config`](./services/demo-spring-config), [`services/demo-risk-router`](./services/demo-risk-router) | Go 1.27 | Примеры внешних hot-plug воркеров |

Инфраструктурный слой: **PostgreSQL 17**, **Redis 8**, **Garage S3 2.5**, опционально **Ollama**, **Mailpit** и стек **Prometheus / Loki / Promtail / OTel Collector / Tempo / Grafana**.

---

## Структура репозитория

```text
.
├── .github/workflows/       # GitHub Actions: CI, сборка 14 образов в GHCR, lint & OCI-релиз Helm-чарта
├── ci-integrations/         # Переиспользуемые GitHub Composite Action и GitLab CI/CD Component
├── deploy/
│   ├── angie/               # Конфигурация reverse proxy Angie с ACME TLS
│   ├── argocd/              # AppProject и Application-манифесты для GitOps (Argo CD)
│   ├── charts/onlyscans/    # Helm-чарт (values-k3s, values-local-k8s, values-prod)
│   ├── compose/             # Docker Compose для локальной разработки и observability
│   └── k8s/                 # Kustomize base, observability и overlays (k3s / k8s)
├── docs/deployment/         # Документация по Kubernetes, observability и GitOps
├── packages/
│   ├── contracts/           # OpenAPI, JSON Schemas, спецификация MCP
│   ├── graphql/             # GraphQL-схема Edge Gateway
│   └── proto/               # Protobuf-контракты (buf) и сгенерированный Go-код
├── scripts/                 # Скрипты сборки и деплоя в k3s / k8s / kind (bash и PowerShell)
├── services/                # Исходный код фронтенда (web) и всех бэкенд-сервисов
└── tests/data/repos/        # Учебный тестовый корпус и каталог уязвимостей
```

---

## Быстрый старт (Docker Compose)

Требования: **Docker** и **Docker Compose v2**.

### 1. Базовый запуск платформы

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build
```

После старта доступны:
- **Web UI**: `http://localhost:3000`
- **Edge Gateway (GraphQL / HTTP / MCP)**: `http://localhost:8080`

Остановить стек:

```bash
docker compose -f deploy/compose/docker-compose.yml down
```

### 2. Опциональные профили Compose

Профили можно комбинировать через `--profile`:

| Профиль | Что поднимает | Порты |
|---|---|---|
| `observability` | OTel Collector, Prometheus, Tempo, Loki, Grafana | Grafana `:3001`, Prometheus `:9090`, Tempo `:3200`, Loki `:3100` |
| `local-llm` | Ollama для локальных моделей в `ai-service` | `:11434` |
| `dev-tools` | Mailpit для перехвата SMTP-уведомлений | Web UI `:8025`, SMTP `:1025` |
| `external-plugin` | Демо-плагины `demo-spring-config` и `demo-risk-router` | Подключаются к `orchestrator:50051` |

Пример запуска с observability и локальным SMTP:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 \
  docker compose -f deploy/compose/docker-compose.yml \
  --profile observability --profile dev-tools up -d --build
```

### Основные переменные окружения (Compose)

- `REPO_ALLOWLIST` — список разрешённых HTTPS-репозиториев для сканирования (по умолчанию `github.com/TBagirov/training`).
- `AI_PROVIDER` — провайдер AI (`template_fallback`, `ollama`, `openai`); при использовании внешнего LLM задаются `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`.
- `CORS_ALLOW_ORIGINS` — разрешённые origin для браузера (по умолчанию `http://localhost:3000,http://127.0.0.1:3000`).

---

## Развёртывание в Kubernetes (k3s / k8s / kind)

Платформа поддерживает два способа деплоя — **Helm** и **Kustomize** — с разделением по namespace (`secflow-app`, `secflow-workers`, `secflow-sandbox`, `secflow-system`, `secflow-observability`), `PodSecurity: restricted` и `NetworkPolicy` (у воркеров-анализаторов нулевой доступ в интернет).

### Автоматический скрипт (сборка образов + деплой)

Linux / macOS:

```bash
./scripts/k8s-deploy.sh --target k3s --method helm
# или без Helm (Kustomize):
./scripts/k8s-deploy.sh --target k3s --method kustomize
```

Windows (PowerShell):

```powershell
.\scripts\k8s-deploy.ps1 -Target k8s -Method helm
# или с публикацией в registry:
.\scripts\k8s-deploy.ps1 -Target k3s -Method helm -Registry ghcr.io/zwarder-s-orgranization/onlyscans -Tag 1.0.0 -Push
```

### Ручной деплой через Helm

```bash
# k3s (Traefik, on-demand воркеры):
helm upgrade --install onlyscans deploy/charts/onlyscans \
  -f deploy/charts/onlyscans/values-k3s.yaml \
  --set global.imageRegistry=ghcr.io/zwarder-s-orgranization/onlyscans \
  --set global.imageTag=latest \
  --set observability.enabled=true

# Production k8s (HPA, PDB, TLS, KEDA):
helm upgrade --install onlyscans deploy/charts/onlyscans \
  -f deploy/charts/onlyscans/values-prod.yaml \
  --set workerScaling.mode=keda \
  --set observability.enabled=true
```

### Ручной деплой через Kustomize

```bash
kubectl apply -k deploy/k8s/overlays/k3s
# Дополнительно стек наблюдаемости:
kubectl apply -k deploy/k8s/observability
```

### GitOps (Argo CD) и Angie

- Манифесты `AppProject` и `Application` (отслеживание OCI Helm-чарта из GHCR): [`deploy/argocd/`](./deploy/argocd/)
- Конфигурация reverse proxy Angie с ACME TLS для UI, Grafana и Argo CD: [`deploy/angie/onlyscans.conf`](./deploy/angie/onlyscans.conf)

Подробные инструкции:
- [`docs/deployment/kubernetes.md`](./docs/deployment/kubernetes.md) — архитектура кластера, динамический скейлинг воркеров `0 → N → 0`, KEDA, k3s/k8s/kind.
- [`docs/deployment/observability-and-gitops.md`](./docs/deployment/observability-and-gitops.md) — Prometheus/Loki/Tempo/Grafana, корреляция по `trace_id`, Argo CD и Angie.

---

## CI/CD и интеграции

### GitHub Actions в этом репозитории

- [`.github/workflows/images-and-ci.yml`](./.github/workflows/images-and-ci.yml) — `go vet`, `go test -race ./...`, проверка запрещённых зависимостей в `go.mod`, сборка `services/web` (`npm ci && npm run build`), сборка и публикация 14 Docker-образов в `ghcr.io/<owner>/onlyscans/<service>`.
- [`.github/workflows/helm-release.yml`](./.github/workflows/helm-release.yml) — `helm lint` по всем пресетам, валидация манифестов Helm/Kustomize через `kubeconform`, проверка JSON дашборда и YAML Argo CD, публикация OCI Helm-чарта в `oci://ghcr.io/<owner>/charts/onlyscans`.

### Подключение сканирования в сторонние репозитории

Готовые интеграции без сторонних зависимостей (требуются только `curl` и POSIX `sh`):
- **GitHub Actions (Composite Action)**: [`ci-integrations/github/action.yml`](./ci-integrations/github/action.yml) и пример [`example.yml`](./ci-integrations/github/example.yml).
- **GitLab CI/CD Component**: [`ci-integrations/gitlab/templates/secflow.yml`](./ci-integrations/gitlab/templates/secflow.yml) и пример [`example.gitlab-ci.yml`](./ci-integrations/gitlab/example.gitlab-ci.yml).

Описание входных параметров, артефактов (`run.json`, `submission.json`, `report.md`, `sbom.cdx.json`) и переменных для self-hosted раннеров — в [`ci-integrations/README.md`](./ci-integrations/README.md).

---

## Локальная разработка и проверки

Требования: **Go 1.27+**, **Node.js 24 LTS**, опционально **JDK 21 + Gradle 8.12** (для `worker-kotlin/psi`) и **golangci-lint**.

### Бэкенд (Go)

```bash
cd services
go vet ./...
go test ./...
# В Linux/macOS или при включённом CGO:
go test -race ./...
```

Конфигурация линтера находится в [`.golangci.yml`](./.golangci.yml):

```bash
cd services
golangci-lint run ./...
```

### Фронтенд (Next.js)

```bash
cd services/web
npm ci
npm run typecheck
npm run build
# Запуск dev-сервера на http://localhost:3000:
NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev
```

### Контракты

- Protobuf: [`packages/proto`](./packages/proto) (`buf.yaml`, `buf.gen.yaml`)
- GraphQL-схема: [`packages/graphql/schema.graphqls`](./packages/graphql/schema.graphqls)
- OpenAPI и JSON-схемы: [`packages/contracts`](./packages/contracts)
