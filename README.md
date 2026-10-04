# Mail Warden

Open-source email security gateway for on-premises Exchange environments.

Mail Warden is designed to mirror the **operational philosophy** of Nginx Warden, but for SMTP:

- Nginx Warden protects web infrastructure by understanding HTTP behavior.
- Mail Warden protects mail infrastructure by understanding SMTP behavior, identity, reputation, and relationships.

## Project Status

- Phase: Concept / architecture baseline
- Primary target: On-premises Microsoft Exchange
- Deployment model: DMZ SMTP security gateway
- Traffic: Inbound and outbound
- Core content engine: Rspamd
- SMTP foundation: Postfix

## Core Design Principles

1. Evidence over assumptions
2. Bounded trust (no single positive signal can dominate)
3. Historical context matters
4. Current high-confidence risk can override trust
5. Explainable policy decisions

## MVP Scope (Bootstrap)

- SMTP ingress/egress architecture and policy contracts
- Normalized decision object
- Bounded-trust scoring engine with hard security gates
- Reputation and relationship model stubs
- Event model and telemetry contracts
- Exchange/AD/Entra integration design documents
- Deployment skeleton (Docker/systemd/VM docs)

## Repository Structure

```text
mail-warden/
├── cmd/
│   ├── mailwarden/
│   ├── policy-worker/
│   └── migrations/
├── internal/
│   ├── smtp/
│   ├── policy/
│   ├── reputation/
│   ├── identity/
│   ├── relationship/
│   ├── quarantine/
│   ├── rspamd/
│   ├── exchange/
│   ├── ldap/
│   ├── entra/
│   ├── database/
│   ├── events/
│   ├── scoring/
│   └── telemetry/
├── web/
│   ├── admin/
│   └── quarantine/
├── migrations/
├── configs/
├── deployments/
│   ├── docker/
│   ├── systemd/
│   └── vm/
├── docs/
└── tests/
```

## Build and Test

```bash
cd mail-warden
go test ./...
go run ./cmd/mailwarden \
  -config ./configs/mailwarden.example.yaml \
  -policy-config ./configs/policy.example.yaml
```

## Current API Baseline

- `GET /healthz`
- `GET /api/v1/info`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/logout-all`
- `GET /api/v1/auth/sessions`
- `POST /api/v1/policy/evaluate`
- `GET /api/v1/policy/current`
- `GET /api/v1/policy/versions`
- `POST /api/v1/policy/versions`
- `POST /api/v1/policy/rollback?id=<version-id>`
- `GET /api/v1/config/snapshots`
- `POST /api/v1/config/snapshots`
- `GET /api/v1/identity/providers`
- `POST /api/v1/identity/providers`
- `DELETE /api/v1/identity/providers/{id}`
- `GET /api/v1/quarantine/messages`
- `POST /api/v1/quarantine/messages`
- `GET /api/v1/quarantine/messages/{id}`
- `POST /api/v1/quarantine/messages/{id}/release`
- `GET /api/v1/messages`
- `GET /api/v1/events`
- `GET /api/v1/metrics`
- `POST /api/v1/cluster/heartbeat`
- `GET /api/v1/cluster/nodes`

## SMTP Integration Baseline

- Built-in Postfix policy delegation server (TCP `:10031` by default)
- Policy decision mapping:
  - `accept` -> `dunno`
  - `quarantine` -> `hold`
  - `reject` -> `reject`
  - `throttle`/`temporary_failure` -> `defer_if_permit`

## Persistence and Workers

- PostgreSQL-backed migrations runner (`cmd/migrations`)
- PostgreSQL-backed quarantine repository (with in-memory fallback)
- Redis-backed outbound behavior counters
- Redis-backed recipient enumeration detector
- Background policy worker with reputation decay, stale-node marking, and session cleanup
- Policy version and config snapshot persistence with rollback support

## Identity and LDAP

- Local auth with bootstrap admin account support
- LDAP authentication compatible with AD-style search + bind
- OIDC/Entra-compatible authorization code flow endpoints
- Group-to-role mapping and LDAP filter escaping
- JWT access/refresh token issuance
- Refresh rotation, session list/logout/logout-all lifecycle
- Bearer-protected RBAC APIs (viewer/moderator/admin tiers)
- Optional Vault-backed secret ingestion

## Message observations

- Authentication results persisted per message (SPF/DKIM/DMARC/ARC)
- URL observations with domain extraction and malicious-confidence flags
- Attachment observations with suspicious-extension heuristics
- Optional attachment sandbox escalation path
- Outbound DLP heuristic scoring for sensitive data indicators

## Backup and Restore

```bash
POSTGRES_DSN="postgres://..." ./scripts/backup.sh ./backups
POSTGRES_DSN="postgres://..." ./scripts/restore.sh ./backups/<file>.sql.gz
```

## Integration test scaffold

```bash
go test -tags=integration ./tests/integration -v
go test ./tests/regression -v
```

## Load testing scaffold

```bash
# Requires k6 installed and a valid bearer token
MAILWARDEN_BASE_URL=http://localhost:8080 \
MAILWARDEN_BEARER_TOKEN=<token> \
k6 run tests/load/k6_policy_eval.js
```

## Production readiness status

See `docs/PRODUCTION_READINESS.md` for the deployment checklist and remaining gates.

Operational guides:

- `docs/OPERATIONS.md`
- `docs/UPGRADE_STRATEGY.md`
- `docs/SECURITY_REVIEW.md`
- `deployments/vm/EXCHANGE_HARDENING.md`
- `docs/ATTACHMENT_SANDBOX.md`
- `docs/SIEM_SENTINEL.md`

Evidence collection helper:

```bash
./scripts/collect-readiness-evidence.sh
```

Local stack end-to-end validation:

```bash
./tests/integration/run-local-stack-e2e.sh
```

## Immediate Next Steps

1. Add full OIDC/Entra provider flow and SSO login redirect endpoints.
2. Expand message ingest pipeline with attachment/url observation persistence.
3. Add policy-class based authorization (finance/executive/mailbox profiles).
4. Add comprehensive OpenAPI coverage for all endpoints.
5. Add end-to-end integration tests across Postfix, Redis, Rspamd, and PostgreSQL.
