#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deployments/docker/docker-compose.yml"
BASE_URL="${MAILWARDEN_BASE_URL:-http://localhost:8080}"
ADMIN_USER="${MAILWARDEN_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${MAILWARDEN_ADMIN_PASSWORD:-change-this-password}"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/5] Starting local stack..."
docker compose -f "${COMPOSE_FILE}" up -d

echo "[2/5] Waiting for readiness..."
for i in {1..90}; do
  if curl -fsS "${BASE_URL}/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS "${BASE_URL}/readyz" >/dev/null

echo "[3/5] Login..."
LOGIN_JSON="$(curl -fsS -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASSWORD}\"}")"
TOKEN="$(python3 - <<'PY' "${LOGIN_JSON}"
import json,sys
print(json.loads(sys.argv[1])["tokens"]["access_token"])
PY
)"
if [[ -z "${TOKEN}" ]]; then
  echo "Unable to obtain access token."
  exit 1
fi

echo "[4/5] Evaluating policy..."
curl -fsS -X POST "${BASE_URL}/api/v1/policy/evaluate" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"direction":"inbound","message":{"envelope":{"from":"sender@example.net","recipients":["user@company.com"]},"authentication":{"spf":"pass","dkim":"pass","dmarc":"pass","arc":"none"},"identity":{"sender_reputation":2,"domain_reputation":2},"relationship":{"known_correspondent":false,"interaction_count":0},"behavior":{"sending_velocity_level":"normal","recipient_diversity":0.1,"enumeration_likely":false},"content":{"rspamd_score":1.2,"malicious_url":false,"malware_confirmed":false}}}' >/dev/null

echo "[5/5] Verifying key protected endpoints..."
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/api/v1/messages" >/dev/null
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/api/v1/events" >/dev/null
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/api/v1/metrics" >/dev/null

echo "Local stack e2e validation completed."
