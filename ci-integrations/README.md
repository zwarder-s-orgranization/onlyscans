# SecFlow CI Integrations (GitHub Action & GitLab CI/CD Component)

Переиспользуемые интеграции для максимально простого вызова SecFlow workflow с локальных раннеров (Docker / self-hosted / Kubernetes). Работают без сторонних экшенов и зависимостей — нужны только `curl` и POSIX `sh`.

## Структура

```text
ci-integrations/
├── github/
│   ├── action.yml              # GitHub Composite Action (вызывается через uses:)
│   └── example.yml             # Пример вызова из .github/workflows/
└── gitlab/
    ├── templates/
    │   └── secflow.yml         # GitLab CI/CD Component (аналог uses:, подключается через include:)
    └── example.gitlab-ci.yml   # Пример вызова из .gitlab-ci.yml
```

## 1. GitHub Actions (`uses:`)

Подключается как Composite Action через `uses:` ([`github/action.yml`](github/action.yml)):

```yaml
- name: SecFlow Scan
  id: secflow
  uses: zwarder-s-orgranization/hz_chto_viydet/ci-integrations/github@main
  with:
    workflow-id: ${{ vars.SECFLOW_WORKFLOW_ID }}
    token: ${{ secrets.SECFLOW_TOKEN }}
    # по умолчанию: http://edge-gateway:8080
    secflow-url: http://edge-gateway:8080
```

**Возвращаемые `outputs`:** `run-id`, `status`, `gate-status`, `result-dir`, `submission-file`, `report-file`, `sbom-file`. Если workflow сформировал `report.md`, он также автоматически попадает в `Job Summary` (`GITHUB_STEP_SUMMARY`).

## 2. GitLab CI (`include: component:` / `include: project:`)

В GitLab аналог GitHub Action (`uses:`) — это **CI/CD Component** ([`gitlab/templates/secflow.yml`](gitlab/templates/secflow.yml) с блоком `spec: inputs:`). Подключается через `include:` в `.gitlab-ci.yml`:

```yaml
include:
  # Через CI/CD Component (GitLab 16+)
  - component: $CI_SERVER_FQDN/<group>/secflow-ci/secflow@main
    inputs:
      workflow_id: wf_your_workflow_id
      secflow_url: http://edge-gateway:8080
```

Либо напрямую из репозитория без публикации в CI/CD Catalog:

```yaml
include:
  - project: '<group>/<repo>'
    file: '/ci-integrations/gitlab/templates/secflow.yml'
    inputs:
      workflow_id: wf_your_workflow_id
      secflow_url: http://edge-gateway:8080
```

Секрет `SECFLOW_TOKEN` (или `SECFLOW_EMAIL` + `SECFLOW_PASSWORD` для локального `AUTH_MODE=local`) задаётся в **Settings → CI/CD → Variables** (с флагом Masked).

**Возвращаемые результаты:**
- Артефакты джобы (`secflow-result/`): `run.json`, `submission.json`, `report.md`, `sbom.cdx.json` (те, которые реально сформировал workflow).
- Переменные для следующих джоб через `artifacts:reports:dotenv`: `SECFLOW_RUN_ID`, `SECFLOW_STATUS`, `SECFLOW_GATE_STATUS`, `SECFLOW_RESULT_DIR`, `SECFLOW_SUBMISSION_FILE`, `SECFLOW_REPORT_FILE`, `SECFLOW_SBOM_FILE`.

## Примечания для локальных раннеров

- **Домен сервиса:** по умолчанию используется `http://edge-gateway:8080` (имя сервиса в `deploy/compose/docker-compose.yml` и Kubernetes). Если раннер работает на хосте, укажите `http://localhost:8080` или `http://host.docker.internal:8080`.
- **Allowlist:** `orchestrator` и `source-ingester` принимают только HTTPS URL из `REPO_ALLOWLIST` (по умолчанию `github.com/TBagirov/training`). Для своих учебных репозиториев добавьте их в `REPO_ALLOWLIST` (например `github.com/TBagirov/training,github.com/my-org/*`).
