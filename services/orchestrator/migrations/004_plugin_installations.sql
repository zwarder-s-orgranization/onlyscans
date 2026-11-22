-- +goose Up
CREATE TABLE IF NOT EXISTS plugin_installations (
    id text PRIMARY KEY,
    name text NOT NULL UNIQUE,
    source_mode text NOT NULL CHECK (source_mode IN ('PRESET', 'OCI_IMAGE', 'EXTERNAL_PULL')),
    preset_id text NOT NULL DEFAULT '',
    image_ref text NOT NULL DEFAULT '',
    sandbox_profile text NOT NULL CHECK (sandbox_profile IN ('INTERNAL_ONLY', 'EGRESS_EXTERNAL')),
    egress_allowlist text[] NOT NULL DEFAULT '{}',
    resource_limits jsonb NOT NULL DEFAULT '{}'::jsonb,
    desired_replicas int NOT NULL DEFAULT 1 CHECK (desired_replicas >= 0),
    status text NOT NULL CHECK (status IN ('PROVISIONING', 'PENDING_APPROVAL', 'ACTIVE', 'DISABLED', 'ERROR', 'DELETING')),
    auto_approve boolean NOT NULL DEFAULT false,
    token_hash bytea,
    token_prefix text NOT NULL DEFAULT '',
    approved_manifest_digest text NOT NULL DEFAULT '',
    approved_manifests_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    pending_manifests_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    runtime_diagnostics jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_error text NOT NULL DEFAULT '',
    status_reason text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    approved_by text NOT NULL DEFAULT '',
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE plugins ADD COLUMN IF NOT EXISTS installation_id text REFERENCES plugin_installations(id) ON DELETE SET NULL;
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true;
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS approval_state text NOT NULL DEFAULT 'APPROVED' CHECK (approval_state IN ('APPROVED', 'PENDING_APPROVAL', 'REJECTED'));
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS active_workers int NOT NULL DEFAULT 0;
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS registered_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_plugin_installations_status ON plugin_installations (status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_plugin_installations_token_hash ON plugin_installations (token_hash) WHERE token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_plugins_installation_id ON plugins (installation_id) WHERE installation_id IS NOT NULL;

CREATE OR REPLACE FUNCTION secflow_notify_plugin_installation() RETURNS trigger AS $$
DECLARE
    origin text := COALESCE(NULLIF(current_setting('secflow.notify_origin', true), ''), 'pg_trigger');
    ev_type text := COALESCE(NULLIF(current_setting('secflow.event_type', true), ''), TG_OP);
    inst_id text;
    inst_status text;
    should_notify_provision bool := false;
BEGIN
    IF TG_OP = 'DELETE' THEN
        inst_id := OLD.id;
        inst_status := 'DELETED';
        should_notify_provision := true;
    ELSIF TG_OP = 'INSERT' THEN
        inst_id := NEW.id;
        inst_status := NEW.status;
        should_notify_provision := true;
    ELSE
        inst_id := NEW.id;
        inst_status := NEW.status;
        should_notify_provision := (
            NEW.status IS DISTINCT FROM OLD.status OR
            NEW.source_mode IS DISTINCT FROM OLD.source_mode OR
            NEW.image_ref IS DISTINCT FROM OLD.image_ref OR
            NEW.sandbox_profile IS DISTINCT FROM OLD.sandbox_profile OR
            NEW.egress_allowlist IS DISTINCT FROM OLD.egress_allowlist OR
            NEW.resource_limits IS DISTINCT FROM OLD.resource_limits OR
            NEW.desired_replicas IS DISTINCT FROM OLD.desired_replicas OR
            NEW.token_hash IS DISTINCT FROM OLD.token_hash
        );
    END IF;

    PERFORM pg_notify(
        'plugin_events',
        json_build_object(
            'origin', origin,
            'entity', 'installation',
            'eventType', ev_type,
            'installationId', inst_id,
            'status', inst_status
        )::text
    );
    IF should_notify_provision THEN
        PERFORM pg_notify(
            'plugin_provision_jobs',
            json_build_object(
                'installationId', inst_id,
                'status', inst_status,
                'op', TG_OP
            )::text
        );
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_plugin_installations_notify ON plugin_installations;
CREATE TRIGGER trg_plugin_installations_notify
AFTER INSERT OR UPDATE OR DELETE ON plugin_installations
FOR EACH ROW EXECUTE FUNCTION secflow_notify_plugin_installation();

CREATE OR REPLACE FUNCTION secflow_notify_plugin_row() RETURNS trigger AS $$
DECLARE
    origin text := COALESCE(NULLIF(current_setting('secflow.notify_origin', true), ''), 'pg_trigger');
    ev_type text := COALESCE(NULLIF(current_setting('secflow.event_type', true), ''), TG_OP);
    pid text;
    inst_id text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        pid := OLD.plugin_id;
        IF OLD.installation_id IS NOT NULL THEN
            inst_id := OLD.installation_id;
        ELSE
            inst_id := '';
        END IF;
    ELSE
        pid := NEW.plugin_id;
        IF NEW.installation_id IS NOT NULL THEN
            inst_id := NEW.installation_id;
        ELSE
            inst_id := '';
        END IF;
    END IF;

    PERFORM pg_notify(
        'plugin_events',
        json_build_object(
            'origin', origin,
            'entity', 'plugin',
            'eventType', ev_type,
            'pluginId', pid,
            'installationId', inst_id
        )::text
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_plugins_notify ON plugins;
CREATE TRIGGER trg_plugins_notify
AFTER INSERT OR UPDATE OR DELETE ON plugins
FOR EACH ROW EXECUTE FUNCTION secflow_notify_plugin_row();

-- +goose Down
DROP TRIGGER IF EXISTS trg_plugins_notify ON plugins;
DROP FUNCTION IF EXISTS secflow_notify_plugin_row();
DROP TRIGGER IF EXISTS trg_plugin_installations_notify ON plugin_installations;
DROP FUNCTION IF EXISTS secflow_notify_plugin_installation();
DROP INDEX IF EXISTS idx_plugins_installation_id;
DROP INDEX IF EXISTS idx_plugin_installations_token_hash;
DROP INDEX IF EXISTS idx_plugin_installations_status;
ALTER TABLE plugins DROP COLUMN IF EXISTS updated_at;
ALTER TABLE plugins DROP COLUMN IF EXISTS registered_at;
ALTER TABLE plugins DROP COLUMN IF EXISTS active_workers;
ALTER TABLE plugins DROP COLUMN IF EXISTS approval_state;
ALTER TABLE plugins DROP COLUMN IF EXISTS enabled;
ALTER TABLE plugins DROP COLUMN IF EXISTS installation_id;
DROP TABLE IF EXISTS plugin_installations;
