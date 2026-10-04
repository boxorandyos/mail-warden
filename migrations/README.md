# Database Migrations

Initial schema targets:

- organizations, users, domains
- mailboxes, aliases
- messages, message_events
- reputation_entities, reputation_events
- relationships
- quarantine_messages
- authentication_results
- url_observations, attachment_observations

Current files:

- `001_initial_schema.sql`
- `002_indexes.sql`
- `003_identity_and_audit.sql`
- `004_policy_identity_ops.sql`
- `005_message_observations.sql`
