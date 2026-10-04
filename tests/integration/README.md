# Integration test scaffolding

These tests are intentionally opt-in and designed for environments where
PostgreSQL, Redis, Rspamd, and the Mail Warden API are all reachable.

## Run

```bash
go test -tags=integration ./tests/integration -v
```

Required environment variables:

- `MAILWARDEN_BASE_URL` (e.g. `http://localhost:8080`)
- `MAILWARDEN_BEARER_TOKEN` (viewer/moderator/admin token)
- Optional: `POSTFIX_POLICY_ADDR` (default `127.0.0.1:10031`)
- Optional: `MAILWARDEN_RUN_LOAD_TESTS=true` to run k6 load test in staging suite
- Optional: `MAILWARDEN_RUN_QUEUE_STRESS=true` to run SMTP queue stress in staging suite

Admin workflow coverage (`admin_workflows_test.go`) requires an admin token and a reachable policy/provider repository backend.
