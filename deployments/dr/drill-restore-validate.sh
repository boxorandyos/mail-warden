#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <backup.sql.gz>"
  exit 1
fi

BACKUP_FILE="$1"
RESTORE_DSN="${RESTORE_DSN:-}"
API_BASE="${API_BASE:-http://localhost:8080}"
TOKEN="${TOKEN:-}"

if [[ -z "${RESTORE_DSN}" ]]; then
  echo "RESTORE_DSN must be set"
  exit 1
fi

echo "[1/4] Restoring backup into drill database..."
POSTGRES_DSN="${RESTORE_DSN}" ./scripts/restore.sh "${BACKUP_FILE}"

echo "[2/4] Waiting for API readiness..."
for i in {1..30}; do
  if curl -fsS "${API_BASE}/readyz" >/dev/null; then
    break
  fi
  sleep 2
done

echo "[3/4] Checking API health..."
curl -fsS "${API_BASE}/healthz" >/dev/null
curl -fsS "${API_BASE}/readyz" >/dev/null

if [[ -n "${TOKEN}" ]]; then
  echo "[4/4] Checking authenticated endpoints..."
  curl -fsS -H "Authorization: Bearer ${TOKEN}" "${API_BASE}/api/v1/messages" >/dev/null
  curl -fsS -H "Authorization: Bearer ${TOKEN}" "${API_BASE}/api/v1/events" >/dev/null
fi

echo "DR restore drill completed."
