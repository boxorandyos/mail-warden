# Monitoring and Alerting Baseline

This directory provides starter monitoring artifacts for Mail Warden production rollout.

## Contents

- `prometheus-alert-rules.yml`: Prometheus alert rules aligned to the operations SLO/alert baseline.
- `grafana-dashboard-mailwarden.json`: importable Grafana dashboard for core service and policy metrics.

## Recommended wiring

1. Scrape `/metrics` from every Mail Warden API node.
2. Set `job="mailwarden-api"` on the scrape target or adjust expressions in the rule file.
3. Import the dashboard JSON into Grafana and bind it to your Prometheus datasource.
4. Route alerts to SOC/on-call notification channels and tune thresholds against baseline traffic.

## Validation

- Trigger synthetic traffic with:
  - `k6 run tests/load/k6_policy_eval.js`
  - `./tests/load/postfix_queue_stress.sh`
- Verify alerts in a staging environment before production enablement.
