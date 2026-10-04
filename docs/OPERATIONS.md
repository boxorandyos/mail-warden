# Operations Playbook

## Suggested SLOs

- API availability (`/readyz`): 99.9%
- SMTP policy socket availability (`:10031`): 99.95%
- Quarantine release API success rate: >99.5%
- Policy evaluate p95 latency: <750ms (staging target)

## Alert baselines

- `mailwarden_messages_rejected` sudden spike
- `mailwarden_directory_enumeration_detections` sustained spike
- `mailwarden_messages_quarantined` abnormal surge
- `mailwarden_smtp_connections` collapse or saturation
- API readiness failures for >2 minutes

Reference artifacts:
- `deployments/monitoring/prometheus-alert-rules.yml`
- `deployments/monitoring/grafana-dashboard-mailwarden.json`

## Incident response flow

1. Triage
   - confirm alert scope and blast radius
   - check `/readyz`, `/metrics`, queue depth
2. Containment
   - switch to fallback policy profile if required
   - isolate abusive senders/IPs
3. Recovery
   - restore dependent service health (DB/Redis/Rspamd/Postfix)
   - verify inbound/outbound path integrity
4. Post-incident
   - add audit note
   - update detection and runbooks

## Release go/no-go

- Collect evidence first:
  - `./scripts/collect-readiness-evidence.sh`
- Evaluate evidence bundle:
  - `./scripts/release/go-no-go.sh ./artifacts/readiness-<timestamp>`
- The evaluator reports `GO`, `CONDITIONAL`, or `NO-GO` based on test/security/staging evidence files.
