# Runtime upgrades

`scripts/update.sh` rebuilds the Mail Warden binary. It does not move PostgreSQL, Redis, or the Go toolchain on a server that already has them. A new Compose install exports `POSTGRES_IMAGE=postgres:18`, `REDIS_IMAGE=redis:8.2`, and `RSPAMD_IMAGE=rspamd/rspamd:4.2`. Without those variables the Compose file still starts Postgres 17, Redis 7, and Rspamd 3.10, so an existing volume is not rewritten. Fleet → Maintenance runs the copy. The buttons stay planned until `MAIL_ALLOW_HOST_UPDATE=1`.

New image builds use Go 1.27. `go.mod` still says 1.26.0, which that toolchain compiles.

PostgreSQL 17 and Redis 7 are still supported release lines. Go 1.26 is the version in `go.mod`. Move a server before the line you are on stops receiving fixes. PostgreSQL 19 is a beta and is not a target here.

## PostgreSQL

`postgres:17` data cannot start on Postgres 18. The upgrade script dumps the live database, starts Postgres 18 beside it, and restores into a new volume. The live container stays up. Compose is not edited.

```bash
sudo UPGRADE_POSTGRES_CONFIRM=1 bash scripts/upgrade-postgres.sh 18
```

The copy listens on `127.0.0.1:55432`. If more than one Compose Postgres is running, set `MAIL_POSTGRES_CONTAINER` to the live name. Switch only after a mail-flow check against the copy, and only during a window where you can point the API back at the original container.

`scripts/backup.sh` remains the dump you take before an application upgrade. The major-version script writes a custom-format dump under `.upgrade/`.

## Redis

Outbound counters and recipient tracking live in Redis. A new major gets its own volume. The live Redis keeps serving.

```bash
sudo UPGRADE_REDIS_CONFIRM=1 bash scripts/upgrade-redis.sh 8
```

The copy listens on `127.0.0.1:16380`. An empty Redis is safe for delivery: counters start again. Point `stores.redis_addr` at the copy when you are ready, and point it back to roll back.

## Rspamd

The shipped Compose file pins `rspamd/rspamd:3.10` and does not mount a data volume. Try a newer tag as a second container and point `rspamd.endpoint` at it. Change the Compose image tag only after that check. Pulling the existing tag does not move you off 3.10.

## Go

Host installs build with whatever `go` is on `PATH`. Test a toolchain in Docker before replacing `/usr/local/go`:

```bash
bash scripts/try-go.sh 1.27
sudo UPGRADE_GO_CONFIRM=1 bash scripts/upgrade-go.sh 1.27.0
PATH=/usr/local/go/bin:$PATH go test ./...
PATH=/usr/local/go/bin:$PATH bash scripts/update.sh
```

`try-go.sh` does not retag `mailwarden:latest`. The previous toolchain is left at `/usr/local/go.previous`. Image builds default to `golang:1.26`. Pass `--build-arg GO_IMAGE=golang:1.27` to try another image. The development Compose file reads `MAILWARDEN_GO_IMAGE` and otherwise stays on `golang:1.26`.

`go.mod` still says `go 1.26.0`. Raising that line belongs in a release that has passed `try-go.sh`, not on a running server by itself.

## ClamAV

`clamav/clamav:latest` already floats. Pin a version tag if a pull should not change the scanner.

## pnpm

The admin UI is a separate Node app under `web/admin` and uses npm. The API does not use pnpm.
