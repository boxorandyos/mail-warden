# Mail Warden

Control plane and SMTP policy service for **on-premises mail**: **Postfix** policy decisions, **Rspamd**, **quarantine**, **identity**, and **operations**—delivered as an **HTTP API** (Go) and an **admin UI** (React).

**Repository:** [github.com/boxorandyos/mail-warden](https://github.com/boxorandyos/mail-warden)

There is no one-command installer comparable to Nginx Warden’s `scripts/deploy.sh`. Production is either the Docker Compose profile or a host layout that matches the systemd units.

---

## What it does

- Decide SMTP policy for Postfix (`accept`, `quarantine`, `reject`, `throttle`) and map those decisions onto Postfix actions.
- Score content with Rspamd, persist message observations (SPF/DKIM/DMARC/ARC, URLs, attachments), and hold or release quarantine.
- Sign operators in with a local bootstrap admin, LDAP, or OIDC, with refresh sessions and optional TOTP.
- Record cluster nodes, fleet alert rules, environments, and `mw_` service accounts.

The **supported production target** is **Linux** in a DMZ in front of Exchange. Postfix, Rspamd, Redis, and PostgreSQL run beside the API. The admin UI is a **browser app**. Firewall and Exchange connector notes are in [deployments/vm/README.md](deployments/vm/README.md).

---

## Quick reference

| Action | Command / location |
|--------|-------------------|
| **Local stack (Docker)** | `docker compose -f deployments/docker/docker-compose.yml up -d` |
| **Production images** | Build `deployments/docker/Dockerfile.mailwarden` and `Dockerfile.policy-worker`, then `docker compose -f deployments/docker/docker-compose.prod.yml up -d` |
| **Host layout** | Binaries under `/opt/mail-warden`, units in [deployments/systemd/](deployments/systemd/) |
| **Upgrade (CLI)** | `sudo bash scripts/update.sh` (git pull, rebuild `bin/mailwarden`, restart `mailwarden` when that unit is installed) |
| **API config** | `configs/mailwarden.example.yaml` and `configs/policy.example.yaml` |
| **Process env** | `/etc/mail-warden/mail-warden.env` when using the systemd units |

---

## Ports

Defaults come from `configs/mailwarden.example.yaml` and the Compose files.

| Port | Service |
|------|---------|
| **8080** | HTTP API (`service.listen`) |
| **10031** | Postfix policy socket (`smtp.policy_listen`) |
| **5173** | Admin UI (Vite dev server; proxies `/api` to `127.0.0.1:8080`) |
| **25 / 465 / 587** | SMTP on the Postfix host you configure; not listeners of the Go process |
| **15433** | PostgreSQL published by the **development** Compose file (container `5432`) |
| **16379** | Redis published by the development Compose file |
| **11334** | Rspamd published by the development Compose file |

Health: `GET http://<host>:8080/healthz` and `GET http://<host>:8080/readyz`.

The development Compose file also publishes ClamAV on **3310**. The production Compose file does not publish Postgres, Redis, or Rspamd on the host.

---

## Production install

**Requirements:** Docker (for the Compose profile) or a Linux host with Go to build the binaries, plus PostgreSQL, Redis, and Rspamd reachable at the addresses in the config. Copy `configs/mailwarden.example.yaml` before production use. The example file points `stores.postgres_dsn` and `stores.redis_addr` at Docker DNS names (`postgres`, `redis`) and ships placeholder auth secrets.

### Docker

```bash
git clone https://github.com/boxorandyos/mail-warden.git
cd mail-warden
docker build -f deployments/docker/Dockerfile.mailwarden -t mailwarden:latest .
docker build -f deployments/docker/Dockerfile.policy-worker -t mailwarden-worker:latest .
export POSTGRES_PASSWORD='strong-password'
export POSTGRES_IMAGE=postgres:18
export REDIS_IMAGE=redis:8.2
export RSPAMD_IMAGE=rspamd/rspamd:4.2
docker compose -f deployments/docker/docker-compose.prod.yml up -d
```

Those three image variables are the current long-term lines for a new volume. Leave them unset when a volume from an older major already exists. `docker compose up` then keeps Postgres 17, Redis 7, and Rspamd 3.10. Fleet → Maintenance copies Postgres and Redis forward and can install Go 1.27. Image builds default to `golang:1.27`.

Set `MAILWARDEN_ACCESS_SECRET`, `MAILWARDEN_REFRESH_SECRET`, and `MAILWARDEN_BOOTSTRAP_ADMIN_PASSWORD` for production. Set `MAILWARDEN_OIDC_CLIENT_SECRET` or `MAILWARDEN_LDAP_BIND_PASSWORD` only when those directories are enabled. Details: [deployments/docker/README.md](deployments/docker/README.md).

### systemd host

The units expect this layout. Nothing in the repo creates the user, the directory, or the env file for you.

- User and group `mailwarden`
- Working directory `/opt/mail-warden`
- Binaries `/opt/mail-warden/bin/mailwarden` and `/opt/mail-warden/bin/policy-worker`
- Config `/opt/mail-warden/configs/mailwarden.yaml` and `policy.yaml`
- Environment file `/etc/mail-warden/mail-warden.env` (the worker unit reads `POSTGRES_DSN` from it)

```bash
go build -o /opt/mail-warden/bin/mailwarden ./cmd/mailwarden
go build -o /opt/mail-warden/bin/policy-worker ./cmd/policy-worker
sudo cp deployments/systemd/mailwarden.service deployments/systemd/policy-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mailwarden policy-worker
```

Apply schema changes with `go run ./cmd/migrations -dsn "$POSTGRES_DSN" -dir ./migrations` before the first start, and again on upgrade. The development Compose file runs that command for you. The production Compose file does not.

Postfix `main.cf` / `master.cf` baselines are in [deployments/postfix/](deployments/postfix/).

### Configuration highlights

- **Listen and SMTP policy:** `service.listen` (`:8080`) and `smtp.policy_listen` (`:10031`).
- **Auth secrets and bootstrap admin:** `auth` in the YAML. Replace `change-me-access-secret`, `change-me-refresh-secret`, and `change-this-password`.
- **LDAP and OIDC:** `ldap` and `auth.oidc`. Both default to disabled in the example file.
- **Postgres, Redis, Rspamd:** `stores` and `rspamd.endpoint`.
- **Host updates from the API:** unset, the API records the planned command. `MAIL_ALLOW_HOST_UPDATE=1` runs it. `WARDEN_ALLOW_HOST_UPDATE=1` runs it even when the mail flag is unset; `WARDEN_ALLOW_HOST_UPDATE=0` plans it even when the mail flag is on.
- **Slave maintenance:** `MAIL_NODE_ROLE=primary` on the node allowed to trigger standbys. Standbys accept `POST /api/v1/maintenance/apply` when `X-Maintenance-Key` matches `MAIL_MAINTENANCE_KEY`.

---

## Upgrading

Back up Postgres first (`scripts/backup.sh`). The rolling sequence is in [docs/UPGRADE_STRATEGY.md](docs/UPGRADE_STRATEGY.md).

```bash
cd /path/to/mail-warden
sudo bash scripts/update.sh
```

`update.sh` fast-forwards `main`, rebuilds `bin/mailwarden`, and restarts the `mailwarden` unit when that unit is installed. It does not rebuild `policy-worker` and it does not run migrations. Run `cmd/migrations` and restart `policy-worker` yourself when a release adds either. It also does not move PostgreSQL, Redis, Rspamd, or Go to a new major. A new Compose install sets the image variables in the production section. Fleet → Maintenance starts the copy on a server that is still on the older line: [docs/RUNTIME_UPGRADES.md](docs/RUNTIME_UPGRADES.md).

`scripts/update-packages.sh` (root) upgrades installed packages from a fixed list: `postfix`, `postfix-pcre`, `rspamd`, `redis-server`, `ca-certificates`, `openssl`. Packages that are not installed are skipped.

`GET /metrics` is Prometheus text. `/platform` in the admin UI covers environments, `mw_` service accounts, and fleet alert rules. Jobs, runbooks, snapshots, audit export, and platform sync are on the API; see [docs/API.md](docs/API.md).

---

## Development

The development Compose file builds nothing. It runs the API, worker, and migrations with `go run` inside `golang:1.26`, plus Postgres 17, Redis 7, Rspamd, and ClamAV. Published passwords in that file are `mailwarden` / `mailwarden`.

```bash
docker compose -f deployments/docker/docker-compose.yml up -d
```

API: `http://localhost:8080`. Admin UI, from a second terminal:

```bash
cd web/admin
npm install
npm run dev    # http://localhost:5173
```

Without Docker, point a copied config at a Postgres and Redis you already have, then:

```bash
go test ./...
go run ./cmd/mailwarden \
  -config ./configs/mailwarden.example.yaml \
  -policy-config ./configs/policy.example.yaml
```

Integration and load scaffolds:

```bash
go test -tags=integration ./tests/integration -v
./tests/integration/run-local-stack-e2e.sh
```

---

## Operations

### systemd

```bash
sudo systemctl {start|stop|restart|status} mailwarden
sudo systemctl {start|stop|restart|status} policy-worker
```

### Backup

```bash
POSTGRES_DSN="postgres://..." ./scripts/backup.sh ./backups
POSTGRES_DSN="postgres://..." ./scripts/restore.sh ./backups/<file>.sql.gz
```

### Logs

```bash
sudo journalctl -u mailwarden -f
sudo journalctl -u policy-worker -f
docker compose -f deployments/docker/docker-compose.prod.yml logs -f mailwarden
```

Host update scripts append to `/var/log/mail-warden-update.log` unless `MAIL_WARDEN_UPDATE_LOG` is set. The API tails that allowlisted path.

Policy decisions on the socket: `accept` → `dunno`, `quarantine` → `hold`, `reject` → `reject`, `throttle` / `temporary_failure` → `defer_if_permit`.

---

## Troubleshooting (short)

| Issue | What to check |
|-------|----------------|
| **API not listening** | `service.listen` in the YAML; `ss -tlnp` for `:8080`. |
| **Postfix defers everything** | Policy socket `:10031`, Postfix `check_policy_service`, and `/readyz`. |
| **Login fails on a fresh database** | Bootstrap admin in `auth`, and that migrations have been applied. |
| **Compose API cannot reach Postgres** | Development config uses hostname `postgres`. A host-built binary needs a DSN that resolves from the host (`localhost:15433` when the development Compose ports are published). |
| **Update script did not restart** | `mailwarden.service` must be installed. Otherwise the script only rebuilds `bin/mailwarden`. |
| **Package or product update planned only** | `MAIL_ALLOW_HOST_UPDATE` or `WARDEN_ALLOW_HOST_UPDATE`. |

---

## Documentation in this repo

| Resource | Path |
|----------|------|
| HTTP API | [docs/API.md](docs/API.md) |
| OpenAPI | [docs/openapi.yaml](docs/openapi.yaml) |
| Operations and SLOs | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Upgrades | [docs/UPGRADE_STRATEGY.md](docs/UPGRADE_STRATEGY.md) |
| Postgres, Redis, and Go majors | [docs/RUNTIME_UPGRADES.md](docs/RUNTIME_UPGRADES.md) |
| Production checklist | [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Exchange hardening | [deployments/vm/EXCHANGE_HARDENING.md](deployments/vm/EXCHANGE_HARDENING.md) |
| Docker | [deployments/docker/README.md](deployments/docker/README.md) |
| Admin UI | [web/admin/README.md](web/admin/README.md) |

Readiness evidence: `./scripts/collect-readiness-evidence.sh`.

---

## Tech stack (summary)

| Layer | Stack |
|-------|--------|
| **UI** | React, TypeScript, Vite, Tailwind |
| **API** | Go, PostgreSQL, Redis, JWT access and refresh |
| **Mail path** | Postfix policy delegation, Rspamd |

---

## Contributing

1. Branch from `main`.
2. Keep changes focused.
3. Run `go test ./...` for packages you touch.
4. Open a pull request with a clear description.

Commit messages use conventional prefixes (`feat:`, `fix:`, `docs:`, …).

---

## Security

Report vulnerabilities privately to the maintainers. Do not open public issues for unfixed exploits. The threat model and review notes are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).
