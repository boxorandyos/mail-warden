#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-./backups}"
POSTGRES_DSN="${POSTGRES_DSN:-}"

if [[ -z "${POSTGRES_DSN}" ]]; then
  echo "POSTGRES_DSN must be set"
  exit 1
fi

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${OUT_DIR}/mailwarden-${STAMP}.sql.gz"

echo "Creating backup: ${OUT_FILE}"
pg_dump "${POSTGRES_DSN}" | gzip -9 > "${OUT_FILE}"
echo "Backup complete"
