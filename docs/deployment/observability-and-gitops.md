# Инфраструктура OnlyScans: Observability (Loki / Prometheus / Tempo / Grafana), Argo CD, GitHub Actions и Angie

Руководство по запуску стека наблюдаемости (сбор логов, метрик, трейсов, постоянное хранение на PVC и готовый дашборд Grafana), GitOps-доставке через **Argo CD**, автоматической сборке Helm-чартов в **GitHub Actions** и проксированию через **Angie** с автоматическим ACME TLS.

---

## 1. Стек Observability (`secflow-observability`)

Все компоненты хранят данные на постоянных `PersistentVolumeClaim` (`StatefulSet`) и связаны сквозной корреляцией по `trace_id`:

| Компонент | Версия | Роль | Хранение |
|---|---|---|---|
| **Prometheus** | `v3.2.1` | Сбор метрик `/metrics` со всех сервисов SecFlow + Pod SD + **Exemplars** (`trace_id`) | PVC `5Gi`, retention `15d` |
| **Loki** | `3.4.2` | Индексация и хранение структурированных JSON-логов (`TSDB v13`, compactor) | PVC `5Gi`, retention `168h` |
| **Promtail** | `3.4.2` | `DaemonSet` на каждой ноде: собирает CRI-логи подов из `secflow-app`, `secflow-workers`, `secflow-sandbox`, `secflow-system`, парсит `level`, `service`, `trace_id` | `/var/log/pods` (RO) |
| **OTel Collector** | `0.120.0` | Приём W3C OTLP-трейсов (`:4317` gRPC, `:4318` HTTP) → батчинг → Tempo | Stateless |
| **Tempo** | `2.7.2` | Хранение распределённых трейсов | PVC `5Gi`, retention `168h` |
| **Grafana** | `11.5.2` | Преднастроенные Datasources (`Prometheus ↔ Tempo ↔ Loki`) + дашборд **`OnlyScans Platform Overview`** | PVC `2Gi` |

### Что уже настроено в Grafana из коробки

- **Корреляция Prometheus → Tempo**: клик по Exemplar на графиках p95 HTTP/gRPC задержки открывает точный трейс в Tempo.
- **Корреляция Tempo → Loki**: из любого span в Tempo кнопка `Logs for this span` открывает отфильтрованные по `trace_id` JSON-логи в Loki.
- **Корреляция Loki → Tempo**: в каждой строке JSON-лога поле `"trace_id":"..."` автоматически превращается в ссылку в Tempo.
- **Дашборд `OnlyScans Platform Overview`** ([secflow-overview.json](file:///e:/projects/hack/hz_chto_viydet/deploy/charts/onlyscans/files/dashboards/secflow-overview.json)):
  - KPI: Edge HTTP RPS, HTTP 5xx %, Workflow Runs Completed, Queued/In-Flight Tasks, Active Workers, K8s Desired Worker Replicas.
  - Автоскейлинг воркеров и очередь: `orchestrator_queue_depth{plugin_id}`, `orchestrator_active_workers` vs `orchestrator_worker_pool_desired_replicas{pool}`, события масштабирования `orchestrator_worker_scale_events_total{pool,direction}`, p95 длительности нод `orchestrator_node_duration_seconds`.
  - RED-метрики Edge HTTP (`secflow_http_requests_total`, `secflow_http_request_duration_seconds`) и внутреннего gRPC (`rpc_server_requests_total`, `rpc_server_duration_seconds`) с Exemplars.
  - Живой поток WARN/ERROR и структурированных JSON-логов из Loki с фильтром по сервису (`$service`).

### Запуск Observability на k3s / k8s

#### Вариант A: Через Kustomize (если SecFlow уже развёрнут без Helm)
```bash
sudo kubectl apply -k deploy/k8s/observability

# Включите отправку OTLP-трейсов со всех сервисов SecFlow в OTel Collector:
OTEL_URL="http://otel-collector.secflow-observability.svc.cluster.local:4318"
for d in orchestrator edge-gateway source-ingester plugin-provisioner; do
  sudo kubectl -n secflow-app set env "deploy/${d}" "OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_URL}"
done
for d in ai-service notify-service mcp-bridge; do
  sudo kubectl -n secflow-workers set env "deploy/${d}" "OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_URL}"
done

# Проверка:
sudo kubectl -n secflow-observability get pods,pvc
```

#### Вариант B: Через Helm Chart (всё единым релизом)
```bash
helm upgrade --install onlyscans deploy/charts/onlyscans \
  -f deploy/charts/onlyscans/values-k3s.yaml \
  --set observability.enabled=true \
  --set ingress.enabled=false \
  --set web.service.type=NodePort --set web.service.nodePort=30300 \
  --set edgeGateway.service.type=NodePort --set edgeGateway.service.nodePort=30808 \
  --set observability.grafana.service.type=NodePort --set observability.grafana.service.nodePort=30301
```

#### Открыть доступ к Grafana (например, на NodePort `30301` для Angie/браузера)
```bash
sudo kubectl -n secflow-observability patch svc grafana \
  -p '{"spec":{"type":"NodePort","ports":[{"name":"http","port":3000,"targetPort":3000,"nodePort":30301}]}}'
```
*(Дефолтный логин: `admin` / `secflow-grafana-change-me` — обязательно смените пароль в продакшене через Secret `grafana-admin` или `observability.grafana.adminPassword`.)*

---

## 2. GitHub Actions: автосборка Helm-чартов и образов для Argo CD

Добавлены два workflow:

1. **[`.github/workflows/helm-release.yml`](file:///e:/projects/hack/hz_chto_viydet/.github/workflows/helm-release.yml)**:
   - На каждый PR/push проверяет `helm lint` по всем пресетам (`values.yaml`, `values-k3s.yaml`, `values-local-k8s.yaml`, `values-prod.yaml`, KEDA + Observability), валидирует все отрендеренные манифесты Helm и Kustomize через `kubeconform`, проверяет JSON дашборда и YAML Argo CD.
   - На push в `main`, тег (`v*` / `chart-v*`) или ручной `workflow_dispatch`:
     - Вычисляет semver-версию чарта (`0.1.<run_number>` на `main` или точную версию из тега `vX.Y.Z`).
     - Упаковывает `deploy/charts/onlyscans` и публикует OCI Helm-чарт в **GitHub Container Registry**:
       ```text
       oci://ghcr.io/zwarder-s-orgranization/charts/onlyscans:<version>
       ```
2. **[`.github/workflows/images-and-ci.yml`](file:///e:/projects/hack/hz_chto_viydet/.github/workflows/images-and-ci.yml)**:
   - Запускает `go vet`, `go test -race ./...`, проверку deny-list сканеров и сборку Next.js.
   - Собирает и пушит все 14 Docker-образов OnlyScans в `ghcr.io/zwarder-s-orgranization/onlyscans/<service>:<tag>` (`latest`, `sha-...`, semver).

---

## 3. Argo CD GitOps (`deploy/argocd/`)

### Установка Argo CD в k3s
```bash
sudo kubectl create namespace argocd
sudo kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
sudo kubectl -n argocd rollout status deployment/argocd-server --timeout=180s

# Узнать начальный пароль admin:
sudo kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d; echo

# Включить insecure-режим argocd-server (TLS терминирует Angie) и открыть NodePort 30480:
sudo kubectl -n argocd patch configmap argocd-cmd-params-cm --type merge -p '{"data":{"server.insecure":"true"}}'
sudo kubectl -n argocd rollout restart deployment/argocd-server
sudo kubectl -n argocd patch svc argocd-server \
  -p '{"spec":{"type":"NodePort","ports":[{"name":"http","port":80,"targetPort":8080,"nodePort":30480},{"name":"https","port":443,"targetPort":8080}]}}'
```

Готовый шаблон конфигурации Angie (автоматический ACME TLS для OnlyScans, Grafana и Argo CD): [`deploy/angie/onlyscans.conf`](file:///e:/projects/hack/hz_chto_viydet/deploy/angie/onlyscans.conf).

### Подключение OnlyScans к Argo CD

1. Примените проект `AppProject` (ограничивает допустимые репозитории и namespaces):
   ```bash
   sudo kubectl apply -f deploy/argocd/project.yaml
   ```
2. *(Если пакеты в GHCR приватные)* создайте Secret по шаблону [oci-repository-secret.example.yaml](file:///e:/projects/hack/hz_chto_viydet/deploy/argocd/oci-repository-secret.example.yaml) с GitHub PAT (`read:packages`) и примените в namespace `argocd`.
3. Подключите нужное `Application`:
   - **Через OCI Helm-чарт из GitHub Actions (рекомендуется для k3s)**:
     ```bash
     sudo kubectl apply -f deploy/argocd/application-k3s-oci.yaml
     ```
     Argo CD отслеживает диапазон `targetRevision: "0.1.*"` в `ghcr.io/zwarder-s-orgranization/charts/onlyscans` + значения `values-k3s.yaml` из Git (включая декларативные NodePort `30300`/`30808`/`30301`) и автоматически обновляет кластер при каждом новом релизе чарта!
   - **Для продакшен-кластера k8s**:
     ```bash
     sudo kubectl apply -f deploy/argocd/application-prod-oci.yaml
     ```
   - **Напрямую из Git-ветки `main` (без OCI-реестра)**:
     ```bash
     sudo kubectl apply -f deploy/argocd/application-git.yaml
     ```

> **Важно про автоскейлинг воркеров:** во всех манифестах Argo CD (`deploy/argocd/application-*.yaml`) включён `ignoreDifferences` на `/spec/replicas` для `Deployment` в `secflow-workers` и флаг `RespectIgnoreDifferences=true`. Благодаря этому `selfHeal: true` в Argo CD не конфликтует с динамическим K8s API скейлером оркестратора.
