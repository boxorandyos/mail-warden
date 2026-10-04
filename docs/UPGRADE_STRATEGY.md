# Upgrade Strategy

## Principles

- Preserve mail flow availability.
- Ensure schema compatibility before runtime cutover.
- Keep rollback path immediate and rehearsed.

## Rolling upgrade sequence (active/passive)

1. Backup database (`scripts/backup.sh`).
2. Deploy new binaries to standby.
3. Run migrations (`cmd/migrations`) against shared DB.
4. Validate standby readiness and smoke tests.
5. Fail over to standby.
6. Upgrade old active node (now passive).
7. Run failback drill if needed.

## Rollback

- If application behavior regresses:
  - rollback binary/container image
  - rollback policy with `/api/v1/policy/rollback`
  - restore DB from latest backup only when strictly required

## Compatibility matrix maintenance

- Record API and migration compatibility per release.
- Document minimum/maximum supported schema version per binary.
