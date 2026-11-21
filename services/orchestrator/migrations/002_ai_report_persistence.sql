-- +goose Up
ALTER TABLE runs ADD COLUMN IF NOT EXISTS ai_report_json jsonb NOT NULL DEFAULT '{}';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS node_runs_json jsonb NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE runs DROP COLUMN IF EXISTS node_runs_json;
ALTER TABLE runs DROP COLUMN IF EXISTS ai_report_json;
