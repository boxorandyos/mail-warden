# Disaster recovery drills

DR drills validate that backups and restore procedures recover service correctly.

## Drill cycle

1. Take backup via `scripts/backup.sh`.
2. Restore into isolated staging DB using `scripts/restore.sh`.
3. Start Mail Warden against restored DB.
4. Validate:
   - admin login
   - policy versions and snapshots
   - quarantine access/release
   - message/event listing

## Acceptance criteria

- Recovery point objective (RPO) is met.
- Recovery time objective (RTO) is met.
- No schema mismatches after restore.
