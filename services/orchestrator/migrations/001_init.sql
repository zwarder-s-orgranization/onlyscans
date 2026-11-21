-- +goose Up
CREATE TABLE IF NOT EXISTS workflows (
    id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    version int NOT NULL DEFAULT 1,
    graph_json jsonb NOT NULL,
    owner_subject text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workflow_templates (
    id text PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    problem_solved text NOT NULL DEFAULT '',
    graph_json jsonb NOT NULL,
    is_builtin boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS runs (
    id text PRIMARY KEY,
    workflow_id text NOT NULL,
    status text NOT NULL,
    parent_run_id text,
    rerun_from_node_id text,
    trace_id text NOT NULL DEFAULT '',
    findings_json jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS node_tasks (
    node_run_id text PRIMARY KEY,
    run_id text NOT NULL,
    node_id text NOT NULL,
    plugin_id text NOT NULL,
    status text NOT NULL,
    lease_until timestamptz
);

CREATE TABLE IF NOT EXISTS run_events (
    seq_id bigserial PRIMARY KEY,
    run_id text NOT NULL,
    event_type text NOT NULL,
    payload_json jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS secrets (
    secret_ref text PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    email text PRIMARY KEY,
    password_hash text NOT NULL,
    role text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scoped_tokens (
    token_id text PRIMARY KEY,
    name text NOT NULL,
    token_prefix text NOT NULL,
    scopes text[] NOT NULL,
    workflow_id text,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plugins (
    plugin_id text PRIMARY KEY,
    manifest_json jsonb NOT NULL,
    status text NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS catalogs (
    id text PRIMARY KEY,
    name text NOT NULL,
    sha256 text NOT NULL,
    bucket text NOT NULL DEFAULT 'secflow-catalogs',
    s3_key text NOT NULL,
    snapshot_date text NOT NULL DEFAULT '',
    advisory_count int NOT NULL DEFAULT 0,
    is_default boolean NOT NULL DEFAULT false,
    uploaded_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mcp_connections (
    id text PRIMARY KEY,
    config_json jsonb NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE scoped_tokens ADD COLUMN IF NOT EXISTS token_hash bytea;
ALTER TABLE scoped_tokens ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE catalogs ADD COLUMN IF NOT EXISTS bucket text NOT NULL DEFAULT 'secflow-catalogs';
ALTER TABLE catalogs ADD COLUMN IF NOT EXISTS snapshot_date text NOT NULL DEFAULT '';
ALTER TABLE catalogs ADD COLUMN IF NOT EXISTS advisory_count int NOT NULL DEFAULT 0;
ALTER TABLE catalogs ADD COLUMN IF NOT EXISTS uploaded_by text NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS sbom_json jsonb NOT NULL DEFAULT '{}';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS idempotency_key text;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS workflow_version int NOT NULL DEFAULT 1;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS trigger_json jsonb NOT NULL DEFAULT '{}';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS source_ref_json jsonb NOT NULL DEFAULT '{}';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS gate_result_json jsonb NOT NULL DEFAULT '{}';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS error_message text NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS started_at timestamptz;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS finished_at timestamptz;
ALTER TABLE node_tasks ADD COLUMN IF NOT EXISTS payload_json jsonb NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS ai_audit_logs (
    id text PRIMARY KEY,
    run_id text,
    node_run_id text NOT NULL DEFAULT '',
    operation text NOT NULL,
    model_id text NOT NULL,
    provider_mode text NOT NULL DEFAULT 'AI_PROVIDER_MODE_TEMPLATE_FALLBACK',
    privacy_mode text NOT NULL DEFAULT 'PRIVACY_MODE_METADATA_ONLY',
    prompt_hash text NOT NULL,
    tokens_in int NOT NULL DEFAULT 0,
    tokens_out int NOT NULL DEFAULT 0,
    latency_ms bigint NOT NULL DEFAULT 0,
    quality text NOT NULL,
    stripped_hallucinated_advisories int NOT NULL DEFAULT 0,
    cache_hit boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS node_run_id text NOT NULL DEFAULT '';
ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS provider_mode text NOT NULL DEFAULT 'AI_PROVIDER_MODE_TEMPLATE_FALLBACK';
ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS privacy_mode text NOT NULL DEFAULT 'PRIVACY_MODE_METADATA_ONLY';
ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS tokens_in int NOT NULL DEFAULT 0;
ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS tokens_out int NOT NULL DEFAULT 0;
ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS latency_ms bigint NOT NULL DEFAULT 0;
ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS stripped_hallucinated_advisories int NOT NULL DEFAULT 0;
ALTER TABLE ai_audit_logs ADD COLUMN IF NOT EXISTS cache_hit boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_node_tasks_status_lease ON node_tasks (status, lease_until);
CREATE INDEX IF NOT EXISTS idx_node_tasks_run_id ON node_tasks (run_id);
CREATE INDEX IF NOT EXISTS idx_run_events_run_seq ON run_events (run_id, seq_id);
CREATE INDEX IF NOT EXISTS idx_runs_workflow_id ON runs (workflow_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_idempotency_key ON runs (idempotency_key) WHERE idempotency_key IS NOT NULL AND idempotency_key <> '';
CREATE INDEX IF NOT EXISTS idx_ai_audit_logs_run_id ON ai_audit_logs (run_id);

-- +goose Down
DROP TABLE IF EXISTS ai_audit_logs, mcp_connections, catalogs, plugins, scoped_tokens, users, secrets, run_events, node_tasks, runs, workflow_templates, workflows;
