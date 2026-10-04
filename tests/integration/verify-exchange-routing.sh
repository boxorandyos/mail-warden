#!/usr/bin/env bash
set -euo pipefail

API_BASE="${MAILWARDEN_BASE_URL:-http://localhost:8080}"
TOKEN="${MAILWARDEN_BEARER_TOKEN:-}"

if [[ -z "${TOKEN}" ]]; then
  echo "MAILWARDEN_BEARER_TOKEN is required"
  exit 1
fi

echo "[1/3] API readiness check"
curl -fsS "${API_BASE}/readyz" >/dev/null

echo "[2/3] Fetching recent outbound messages"
OUTBOUND_JSON="$(curl -fsS -H "Authorization: Bearer ${TOKEN}" "${API_BASE}/api/v1/messages?direction=outbound")"
if [[ "${OUTBOUND_JSON}" == "[]" ]]; then
  echo "No outbound messages found; generate test traffic first."
  exit 1
fi

echo "[3/3] Fetching recent inbound messages"
INBOUND_JSON="$(curl -fsS -H "Authorization: Bearer ${TOKEN}" "${API_BASE}/api/v1/messages?direction=inbound")"
if [[ "${INBOUND_JSON}" == "[]" ]]; then
  echo "No inbound messages found; generate test traffic first."
  exit 1
fi

echo "Exchange routing validation checks passed (message records exist for both directions)."
