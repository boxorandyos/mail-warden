# Production Readiness Checklist

This checklist tracks deployability for Mail Warden in a production Exchange + DMZ environment.

## Implemented

- Core policy API and Postfix policy socket
- PostgreSQL/Redis integrations
- Quarantine subsystem
- Local + LDAP auth, JWT sessions, RBAC
- OIDC login foundation endpoints
- Policy versioning, rollback, and config snapshots
- Cluster heartbeat foundation
- Prometheus-style metrics endpoint
- Docker production images and compose baseline
- systemd unit templates
- Hardened Postfix + Rspamd baseline profiles with validation guides
- HA failover drill and DR restore drill scripts
- Integration/regression/load test scaffolding for staging validation
- Security audit script and external review checklist artifact
- Runtime safety guards for non-bootstrap mode (fails fast on placeholder secrets/missing critical config)
- API hardening pass (request body limits, strict JSON decoding, safer 5xx responses, server read/write/idle timeouts)
- Auth abuse protection baseline (in-memory auth endpoint rate limiting)
- Monitoring baseline artifacts (Prometheus alert rules + Grafana dashboard templates)
- Operator go/no-go evaluator script (`scripts/release/go-no-go.sh`)

## Still required before declaring production-ready

1. Security hardening completion
   - Secrets manager integration (Vault client support added; production secret backend onboarding still required)
   - End-to-end TLS enforcement profile and certificate rotation strategy
   - Attachment sandbox process isolation policy (sandbox API hook added; production sandbox platform validation pending)
   - External security review / penetration test

2. Reliability and HA completion
   - Active/passive failover orchestration and tested runbook (automation scripts added; staged proof run still required)
   - Zero-downtime migration strategy
   - Disaster recovery validation with backup restore drills (drill script added; staged proof run still required)

3. Email transport completeness
   - Full Postfix + Rspamd production topology configs committed and tested in staging (configs added; staged validation pending)
   - Mail queue management and backpressure controls under load (stress scripts added; staged execution pending)
   - Exchange connector hardening verification runbook (added; staged signoff pending)

4. Testing depth
   - Full integration tests against real Postfix/Rspamd/Redis/PostgreSQL environment (local + workflow scaffolds added; staged secrets + first passing run pending)
   - Load tests (inbound/outbound spikes) (scaffolds added; staged execution pending)
   - Regression tests for quarantine release and policy rollback workflows (baseline regressions added; endpoint-level coverage expansion still pending)

5. Operational readiness
   - Production dashboards/alerts and SLO thresholds (alert rules/dashboard templates added; monitoring stack wiring and threshold tuning still required)
   - Incident response playbooks (baseline added; rehearsal still required)
   - Upgrade strategy and compatibility matrix (strategy added; release matrix population pending)

## Current Status

**Not yet production-ready** until all items above are completed and validated in a staging environment that mirrors production.
