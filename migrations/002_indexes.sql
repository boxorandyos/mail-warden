CREATE INDEX IF NOT EXISTS idx_messages_observed_at ON messages (observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_direction ON messages (direction);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages (sender);
CREATE INDEX IF NOT EXISTS idx_message_events_event_time ON message_events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_reputation_events_observed_at ON reputation_events (observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_relationships_last_seen ON relationships (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_messages_status ON quarantine_messages (status, created_at DESC);
