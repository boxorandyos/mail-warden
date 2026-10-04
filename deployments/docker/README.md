# Mail Warden Docker deployment

## Development stack

```bash
docker compose -f deployments/docker/docker-compose.yml up -d
```

## Production images

Build API image:

```bash
docker build -f deployments/docker/Dockerfile.mailwarden -t mailwarden:latest .
```

Build worker image:

```bash
docker build -f deployments/docker/Dockerfile.policy-worker -t mailwarden-worker:latest .
```

## Production compose

```bash
export POSTGRES_PASSWORD='strong-password'
docker compose -f deployments/docker/docker-compose.prod.yml up -d
```

## Required environment overrides

Set these for production-grade secrets:

- `MAILWARDEN_ACCESS_SECRET`
- `MAILWARDEN_REFRESH_SECRET`
- `MAILWARDEN_BOOTSTRAP_ADMIN_PASSWORD`
- `MAILWARDEN_OIDC_CLIENT_SECRET` (when OIDC is enabled)
- `MAILWARDEN_LDAP_BIND_PASSWORD` (when LDAP bind account is used)
