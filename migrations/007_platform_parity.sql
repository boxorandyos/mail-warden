ALTER TABLE cluster_nodes ADD COLUMN IF NOT EXISTS maintenance_token TEXT;

CREATE TABLE IF NOT EXISTS platform_environments (
  id TEXT PRIMARY KEY,
  organization_id BIGINT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS platform_service_accounts (
  id TEXT PRIMARY KEY,
  organization_id BIGINT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  environment_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS platform_jobs (
  id TEXT PRIMARY KEY,
  organization_id BIGINT NOT NULL,
  type TEXT NOT NULL,
  status TEXT NOT NULL,
  actor TEXT NOT NULL,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS platform_runbooks (
  id TEXT PRIMARY KEY,
  organization_id BIGINT NOT NULL,
  environment_id TEXT,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS platform_alert_rules (
  id TEXT PRIMARY KEY,
  organization_id BIGINT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  threshold INT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  environment_id TEXT
);

CREATE TABLE IF NOT EXISTS platform_policies (
  id TEXT PRIMARY KEY,
  organization_id BIGINT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  threshold INT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  environment_id TEXT
);

CREATE TABLE IF NOT EXISTS platform_snapshots (
  id TEXT PRIMARY KEY,
  organization_id BIGINT NOT NULL,
  actor TEXT NOT NULL,
  body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
