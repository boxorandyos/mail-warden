# Mail Warden API (Current)

## Authentication

- `POST /api/v1/auth/login`
- `GET /api/v1/auth/oidc/start`
- `GET /api/v1/auth/oidc/callback`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/logout-all`
- `GET /api/v1/auth/sessions`

## Policy and configuration

- `POST /api/v1/policy/evaluate`
- `GET /api/v1/policy/current`
- `GET /api/v1/policy/versions`
- `POST /api/v1/policy/versions`
- `POST /api/v1/policy/rollback?id=<version-id>`
- `GET /api/v1/config/snapshots`
- `POST /api/v1/config/snapshots`

## Identity providers

- `GET /api/v1/identity/providers`
- `POST /api/v1/identity/providers`
- `DELETE /api/v1/identity/providers/{id}`

## Message and quarantine operations

- `GET /api/v1/messages`
- `GET /api/v1/events`
- `GET /api/v1/quarantine/messages`
- `POST /api/v1/quarantine/messages`
- `GET /api/v1/quarantine/messages/{id}`
- `POST /api/v1/quarantine/messages/{id}/release`

## Cluster operations

- `POST /api/v1/cluster/heartbeat`
- `GET /api/v1/cluster/nodes`

## Maintenance

Admin:

- `POST /api/v1/maintenance/product` rebuilds this node from git when `MAIL_ALLOW_HOST_UPDATE=1`
- `POST /api/v1/maintenance/packages` upgrades installed `postfix`, `rspamd`, `redis-server`, `ca-certificates`, and `openssl`
- `POST /api/v1/maintenance/slaves` with `{ "kind": "product" | "packages" }` asks every heartbeat node whose role is standby, secondary, slave, backup, or replica to run the same action

A primary sends `X-Maintenance-Key` from `MAIL_MAINTENANCE_KEY`. The standby accepts that header on `POST /api/v1/maintenance/apply`. `MAIL_NODE_ROLE` is `primary` on the node allowed to trigger slaves. A registered node's `maintenance_token` is sent instead of the shared key when it is set. `WARDEN_ALLOW_HOST_UPDATE=1` runs the host script even when `MAIL_ALLOW_HOST_UPDATE` is unset.

## Platform

- `GET/POST /api/v1/platform/environments`
- `GET/POST /api/v1/platform/service-accounts` and `DELETE /api/v1/platform/service-accounts/{id}` (`mw_` token returned once)
- `GET /api/v1/platform/jobs`
- `GET/POST /api/v1/platform/runbooks`
- `GET /api/v1/platform/alert-rules` and `POST /api/v1/platform/alert-rules/{id}` with `{enabled}`
- `GET /api/v1/platform/policies` and `GET /api/v1/platform/policies/violations`
- `GET/POST /api/v1/platform/snapshots` and `POST /api/v1/platform/snapshots/{id}/apply`
- `GET /api/v1/platform/metrics`
- `GET /api/v1/platform/audit/export?format=csv`
- `GET /api/v1/platform/logs`
- `POST /api/v1/platform/sync` and `POST /api/v1/platform/sync/apply` (`X-Maintenance-Key`)

`GET /metrics` appends `warden_up`, `warden_nodes`, `warden_alert_rules`, and `warden_jobs`.

## Metrics

- `GET /metrics` (Prometheus text format)
- `GET /api/v1/metrics` (JSON snapshot, authenticated)
