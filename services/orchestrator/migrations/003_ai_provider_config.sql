-- +goose Up
CREATE TABLE IF NOT EXISTS ai_provider_settings (
    id text PRIMARY KEY DEFAULT 'default',
    mode text NOT NULL DEFAULT 'template_fallback',
    base_url text NOT NULL DEFAULT '',
    model text NOT NULL DEFAULT '',
    secret_ref text NOT NULL DEFAULT '',
    timeout_sec int NOT NULL DEFAULT 60,
    allow_text_to_workflow boolean NOT NULL DEFAULT true,
    updated_by text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS ai_provider_settings;
