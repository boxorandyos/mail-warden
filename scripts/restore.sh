#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <backup.sql.gz>"
  exit 1
fi

BACKUP_FILE="$1"
POSTGRES_DSN="${POSTGRES_DSN:-}"

if [[ ! -f "${BACKUP_FILE}" ]]; then
  echo "Backup file not found: ${BACKUP_FILE}"
  exit 1
fi
if [[ -z "${POSTGRES_DSN}" ]]; then
  echo "POSTGRES_DSN must be set"
  exit 1
fi

echo "Restoring ${BACKUP_FILE}"
gunzip -c "${BACKUP_FILE}" | psql "${POSTGRES_DSN}"
echo "Restore complete"
