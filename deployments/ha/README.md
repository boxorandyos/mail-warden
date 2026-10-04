# High availability and failover validation

This guide defines the active/passive validation workflow for Mail Warden.

## Topology target

- `mailwarden-a` (active)
- `mailwarden-b` (standby)
- shared PostgreSQL + Redis
- fronted by firewall/LB or dual MX preference

## Failover tests

1. Stop active Mail Warden API + Postfix services.
2. Promote standby node.
3. Verify:
   - policy socket response (`10031`)
   - API readiness (`/readyz`)
   - SMTP acceptance from test client
   - queue drain resumes

## Success criteria

- RTO under operator-defined objective.
- No message loss in synthetic test campaign.
- No policy drift after failover (policy version IDs match).
