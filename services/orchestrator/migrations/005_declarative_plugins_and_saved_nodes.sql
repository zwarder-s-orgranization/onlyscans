-- +goose Up
ALTER TABLE plugin_installations DROP CONSTRAINT IF EXISTS plugin_installations_source_mode_check;
ALTER TABLE plugin_installations ADD CONSTRAINT plugin_installations_source_mode_check
    CHECK (source_mode IN ('PRESET', 'OCI_IMAGE', 'EXTERNAL_PULL', 'DECLARATIVE'));

ALTER TABLE plugin_installations DROP CONSTRAINT IF EXISTS plugin_installations_status_check;
ALTER TABLE plugin_installations ADD CONSTRAINT plugin_installations_status_check
    CHECK (status IN ('DRAFT', 'PROVISIONING', 'PENDING_APPROVAL', 'ACTIVE', 'DISABLED', 'ERROR', 'DELETING'));

ALTER TABLE plugin_installations ADD COLUMN IF NOT EXISTS declarative_spec_json jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE plugin_installations ADD COLUMN IF NOT EXISTS pending_declarative_spec_json jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE plugin_installations ADD COLUMN IF NOT EXISTS plugin_version text NOT NULL DEFAULT '1.0.0';
ALTER TABLE plugin_installations ADD COLUMN IF NOT EXISTS declarative_plugin_id text;

CREATE UNIQUE INDEX IF NOT EXISTS idx_plugin_installations_declarative_plugin_id
    ON plugin_installations (lower(declarative_plugin_id))
    WHERE declarative_plugin_id IS NOT NULL AND declarative_plugin_id <> '';

CREATE TABLE IF NOT EXISTS saved_nodes (
    id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    plugin_id text NOT NULL,
    params_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    canonical_params_hash text NOT NULL,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (plugin_id, canonical_params_hash)
);

CREATE INDEX IF NOT EXISTS idx_saved_nodes_plugin_id ON saved_nodes (plugin_id);

-- +goose Down
DROP INDEX IF EXISTS idx_saved_nodes_plugin_id;
DROP TABLE IF EXISTS saved_nodes;
DROP INDEX IF EXISTS idx_plugin_installations_declarative_plugin_id;
ALTER TABLE plugin_installations DROP COLUMN IF EXISTS declarative_plugin_id;
ALTER TABLE plugin_installations DROP COLUMN IF EXISTS plugin_version;
ALTER TABLE plugin_installations DROP COLUMN IF EXISTS pending_declarative_spec_json;
ALTER TABLE plugin_installations DROP COLUMN IF EXISTS declarative_spec_json;
ALTER TABLE plugin_installations DROP CONSTRAINT IF EXISTS plugin_installations_status_check;
ALTER TABLE plugin_installations ADD CONSTRAINT plugin_installations_status_check
    CHECK (status IN ('PROVISIONING', 'PENDING_APPROVAL', 'ACTIVE', 'DISABLED', 'ERROR', 'DELETING'));
ALTER TABLE plugin_installations DROP CONSTRAINT IF EXISTS plugin_installations_source_mode_check;
ALTER TABLE plugin_installations ADD CONSTRAINT plugin_installations_source_mode_check
    CHECK (source_mode IN ('PRESET', 'OCI_IMAGE', 'EXTERNAL_PULL'));
