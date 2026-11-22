# Развёртывание OnlyScans в Kubernetes (k8s и k3s) и динамическое масштабирование воркеров

OnlyScans поддерживает полноценное развёртывание в **Kubernetes (k8s)** и **k3s** двумя способами:
1. **Helm Chart**: `deploy/charts/onlyscans/` (с пресетами `values-k3s.yaml`, `values-local-k8s.yaml`, `values-prod.yaml`)
2. **Чистый Kustomize (без Helm)**: `deploy/k8s/overlays/k3s` и `deploy/k8s/overlays/k8s` (`kubectl apply -k`)

---

## 1. Архитектура кластера и изоляция по Namespace

| Namespace | Компоненты | Сетевая политика и PSS |
|---|---|---|
| `secflow-app` | `web` (`:3000`), `edge-gateway` (`:8080`), `orchestrator` (gRPC `:50051`, HTTP `:8081`), `source-ingester` (`:50052`), `plugin-provisioner` (`:8089`), `Ingress` | Внешний Ingress только на `web` и `edge-gateway`; `orchestrator` имеет узкий namespace-scoped `Role` только на `secflow-workers` |
| `secflow-workers` | **On-demand pull-воркеры** (`worker-kotlin`, `worker-sca`, `sbom-service`) + **dual-role воркеры** (`ai-service`, `notify-service`, `mcp-bridge`) | `PodSecurity: restricted` + `default-deny-all` `NetworkPolicy`. Анализаторы с лейблом `secflow.io/egress-tier: internal-only` имеют **0 доступа в интернет** (только CoreDNS, `orchestrator:50051`, `garage:3900`) |
| `secflow-sandbox` | Внешние hot-plug плагины, управляемые `plugin-provisioner` из UI | `PodSecurity: restricted` + `default-deny-all` + per-installation `NetworkPolicy` |
| `secflow-system` | `postgres` (`17.12`), `redis` (`8.10.3`), `garage` (`2.5.0`), Job `garage-init` (+ опционально `ollama`, `mailpit`) | Только внутренний трафик из кластера |
| `secflow-observability` | Опционально: `otel-collector`, `prometheus`, `tempo`, `grafana` | Внутренний сбор метрик и трейсов |

### Инициализация Garage S3 (`garage-init`)

`garage-init` запускается как Kubernetes `Job` в `secflow-system`:
1. Назначает layout кластера Garage и создаёт 4 бакета (`secflow-sources`, `secflow-artifacts`, `secflow-sbom`, `secflow-catalogs`).
2. Сидирует базу уязвимостей `secflow-catalogs/default.json`.
3. Автоматически синхронизирует S3-креды в Kubernetes Secret `secflow-garage-creds` в namespaces `secflow-app` и `secflow-workers` (переиспользуя существующий Secret при повторных запусках).

---

## 2. Динамическое создание воркеров через Kubernetes API и разделение задач

Оркестратор (`services/orchestrator/k8s_workers.go`, `queue.go`, `store_plugins.go`) умеет **самостоятельно создавать, масштабировать и останавливать воркеры** через Kubernetes API (`k8s.io/client-go`) без внешних операторов (работает из коробки и на k3s, и на k8s).

### Как работает поток выполнения и разделение задач

1. **Параллельная выборка задач из очереди (`queue.go`)**:
   - Оркестратор исполняет готовые узлы DAG и параллельные запуски одновременно (до `ORCHESTRATOR_MAX_CONCURRENT_TASKS`, по умолчанию `32`).
   - Например, после `source.git` ветки `scan.sast.kotlin`, `scan.secrets`, `scan.sca`, `sbom.generate` запускаются параллельно, а при 5 одновременных запусках все их задачи конкурируют за пул воркеров.
2. **Создание Deployment по требованию (`0 → N`)**:
   - При поступлении задачи для плагина (например, `scan.sast.kotlin` или `scan.sca`) оркестратор вычисляет суммарный спрос `demand` по всем плагинам пула (очередь + активные задачи) и формулу:
     `desired = clamp(ceil(demand / tasksPerWorker), minReplicas, maxReplicas)`
   - Если `Deployment` в `secflow-workers` ещё не существует — оркестратор **создаёт hardened Deployment через Kubernetes API** (`runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `automountServiceAccountToken: false`, `WORKER_INSTANCE_ID` из Downward API `metadata.name`, лейбл `secflow.io/egress-tier: internal-only`).
   - Если `Deployment` уже существует с меньшим числом реплик — оркестратор патчит `.spec.replicas` вверх.
3. **Ожидание подключения и least-loaded балансировка (`store_plugins.go`)**:
   - Пока новый под стартует и открывает Pull gRPC стрим (`WorkerService.Connect`), задача ожидает уведомления на per-plugin канале (до `WORKER_PROVISION_TIMEOUT_SECONDS`, по умолчанию `90s`).
   - Как только реплики подключились, оркестратор распределяет задачи методом **least-loaded + round-robin** (`inFlight < maxConcurrency`), разделяя нагрузку равномерно по всем подам (например, `scan.sast.kotlin` на `worker-kotlin-pod-1`, `scan.secrets` на `worker-kotlin-pod-2`).
4. **Плавный scale-down (вплоть до `0` реплик)**:
   - Фоновый reconciler раз в `WORKER_RECONCILE_INTERVAL_SECONDS` (`10s`) проверяет спрос (под PostgreSQL advisory lock при 2+ репликах оркестратора).
   - После простоя дольше `cooldownSeconds` (`WORKER_IDLE_TTL_SECONDS`, по умолчанию `120s`) оркестратор отправляет свободным воркерам `DrainRequest` по gRPC и снижает `replicas` до `minReplicas` (`0` для `worker-kotlin`, `worker-sca`, `sbom-service`; `1` для `ai-service`, `notify-service`, `mcp-bridge`).

### Пулы воркеров по умолчанию

| Pool / Deployment | Плагины | `minReplicas` | `maxReplicas` | `tasksPerWorker` | Egress Tier |
|---|---|---|---|---|---|
| `worker-kotlin` | `scan.sast.kotlin`, `scan.secrets` | `0` | `5` | `1` | `internal-only` (0 интернет) |
| `worker-sca` | `scan.sca` | `0` | `5` | `2` | `internal-only` (0 интернет) |
| `sbom-service` | `sbom.generate` | `0` | `5` | `2` | `internal-only` (0 интернет) |
| `ai-service` | `ai.explain` | `1` | `4` | `2` | `egress-external` |
| `notify-service` | `notify.telegram`, `notify.webhook`, `notify.smtp` | `1` | `4` | `4` | `egress-external` |
| `mcp-bridge` | `mcp.tool` | `1` | `4` | `4` | `egress-external` |

Настройка пулов доступна через ConfigMap `secflow-worker-pools` (`WORKER_POOLS_CONFIG=/etc/secflow/worker-pools.json`) или переменные окружения `WORKER_SCALER_DRIVER=k8s`, `WORKERS_NAMESPACE`, `WORKER_IMAGE_REGISTRY`, `WORKER_IMAGE_TAG`, `WORKER_MAX_REPLICAS`, `WORKER_IDLE_TTL_SECONDS`.

### Альтернативный режим: KEDA

Если в кластере установлен оператор KEDA и Prometheus (`observability.enabled=true`), можно переключить масштабирование на KEDA:
```bash
helm upgrade --install onlyscans deploy/charts/onlyscans \
  -f deploy/charts/onlyscans/values-prod.yaml \
  --set workerScaling.mode=keda \
  --set observability.enabled=true
```

---

## 3. Быстрый старт на k3s (Linux)

### Вариант A: Автоматический скрипт (сборка образов + импорт в k3s + деплой)
```bash
./scripts/k8s-deploy.sh --target k3s --method helm
# Или без Helm (только kubectl):
./scripts/k8s-deploy.sh --target k3s --method kustomize
```

### Вариант B: Ручной деплой на k3s (с уже опубликованными образами)
```bash
# Через Helm (Traefik + local-path + on-demand воркеры):
helm upgrade --install onlyscans deploy/charts/onlyscans \
  -f deploy/charts/onlyscans/values-k3s.yaml \
  --set global.imageRegistry=ghcr.io/zwarder-s-orgranization/onlyscans \
  --set global.imageTag=latest

# Или через Kustomize:
kubectl apply -k deploy/k8s/overlays/k3s
```

Добавьте в `/etc/hosts` (или DNS):
```text
127.0.0.1 onlyscans.local
```

---

## 4. Развёртывание на стандартном Kubernetes (k8s / kind / Docker Desktop)

### Через Helm
```bash
# Локальный k8s (kind / minikube / Docker Desktop):
helm upgrade --install onlyscans deploy/charts/onlyscans \
  -f deploy/charts/onlyscans/values-local-k8s.yaml

# Production k8s (2+ реплики, HPA, PDB, TLS Ingress, Observability):
helm upgrade --install onlyscans deploy/charts/onlyscans \
  -f deploy/charts/onlyscans/values-prod.yaml \
  --set ingress.host=onlyscans.company.internal \
  --set global.publicUrl=https://onlyscans.company.internal \
  --set auth.jwtSecret="<strong-random-32+>" \
  --set auth.serviceToken="<strong-random-token>" \
  --set postgres.password="<strong-pg-password>"
```

### Через Kustomize
```bash
kubectl apply -k deploy/k8s/overlays/k8s
```

### На Windows (PowerShell)
```powershell
.\scripts\k8s-deploy.ps1 -Target k8s -Method kustomize
```

---

## 5. Проверка работы динамического создания и масштабирования воркеров

1. До первого запуска сканирования в `secflow-workers` работают только базовые сервисы (`ai-service`, `notify-service`, `mcp-bridge`), а `worker-kotlin`, `worker-sca`, `sbom-service` отсутствуют (или `0/0`):
   ```bash
   kubectl -n secflow-workers get deployments,pods
   ```
2. Запустите 1 или несколько параллельных workflow-сканов через UI или GraphQL.
3. Наблюдайте, как оркестратор создаёт и масштабирует воркеры в реальном времени:
   ```bash
   kubectl -n secflow-workers get deployments,pods -w
   kubectl -n secflow-app logs -l app=orchestrator -f | grep -E "worker deployment|scaled worker"
   ```
4. Проверьте Prometheus-метрики масштабирования на `orchestrator:8081/metrics`:
   - `orchestrator_queue_depth{plugin_id}`
   - `orchestrator_active_workers{plugin_id}`
   - `orchestrator_worker_pool_desired_replicas{pool}`
   - `orchestrator_worker_scale_events_total{pool,direction}`
5. Через `WORKER_IDLE_TTL_SECONDS` (`90s` на k3s / `120s` по умолчанию) после завершения сканов `worker-kotlin`, `worker-sca` и `sbom-service` автоматически масштабируются обратно до `0` реплик.
