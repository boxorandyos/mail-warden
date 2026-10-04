CREATE TABLE IF NOT EXISTS authentication_results (
  id BIGSERIAL PRIMARY KEY,
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  spf TEXT NOT NULL DEFAULT 'none',
  dkim TEXT NOT NULL DEFAULT 'none',
  dmarc TEXT NOT NULL DEFAULT 'none',
  arc TEXT NOT NULL DEFAULT 'none',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS url_observations (
  id BIGSERIAL PRIMARY KEY,
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  malicious BOOLEAN NOT NULL DEFAULT FALSE,
  confidence TEXT NOT NULL DEFAULT 'unknown',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attachment_observations (
  id BIGSERIAL PRIMARY KEY,
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  suspicious BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_results_message_id ON authentication_results (message_id);
CREATE INDEX IF NOT EXISTS idx_url_obs_message_id ON url_observations (message_id);
CREATE INDEX IF NOT EXISTS idx_url_obs_domain ON url_observations (domain);
CREATE INDEX IF NOT EXISTS idx_attachment_obs_message_id ON attachment_observations (message_id);
