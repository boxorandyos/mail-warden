# Security hardening and external review plan

## Internal hardening controls implemented

- RBAC-gated admin APIs
- JWT access/refresh lifecycle with revocation
- LDAP/OIDC auth provider support
- Secret injection from env or mounted secret files (`*_FILE`)
- Structured audit-event persistence
- Quarantine and policy rollback auditing hooks

## Required external security review before production go-live

1. Infrastructure penetration test focused on DMZ ingress and management plane isolation.
2. SMTP abuse simulation campaign (enumeration, spoofing, high-volume bursts, malware payloads).
3. Authentication review (LDAP/OIDC misconfiguration and privilege escalation paths).
4. Data protection review (quarantine retention and sensitive metadata exposure).
5. Dependency and image vulnerability scan on final release images.

## Suggested evidence package

- Results from `scripts/security/run-security-audit.sh`
- Latest staging integration + load test outputs
- DR drill logs and restore verification report
- Failover drill runbook output and timestamps
