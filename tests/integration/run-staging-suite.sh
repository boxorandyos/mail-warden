#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${MAILWARDEN_BASE_URL:-http://localhost:8080}"
TOKEN="${MAILWARDEN_BEARER_TOKEN:-}"
RUN_LOAD="${MAILWARDEN_RUN_LOAD_TESTS:-false}"
RUN_QUEUE_STRESS="${MAILWARDEN_RUN_QUEUE_STRESS:-false}"

if [[ -z "${TOKEN}" ]]; then
  echo "MAILWARDEN_BEARER_TOKEN is required"
  exit 1
fi

echo "[1/6] Running integration-tag tests..."
go test -tags=integration ./tests/integration -v

echo "[2/6] Running regression tests..."
go test ./tests/regression -v

echo "[3/6] Smoke probing protected endpoints..."
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/api/v1/messages" >/dev/null
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/api/v1/events" >/dev/null
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/api/v1/metrics" >/dev/null

echo "[4/6] Verifying message path evidence..."
./tests/integration/verify-exchange-routing.sh

echo "[5/6] Policy evaluate load test (optional)..."
if [[ "${RUN_LOAD}" == "true" ]]; then
  k6 run \
    -e MAILWARDEN_BASE_URL="${BASE_URL}" \
    -e MAILWARDEN_BEARER_TOKEN="${TOKEN}" \
    tests/load/k6_policy_eval.js
else
  echo "skipped (set MAILWARDEN_RUN_LOAD_TESTS=true to enable)"
fi

echo "[6/6] SMTP queue stress test (optional)..."
if [[ "${RUN_QUEUE_STRESS}" == "true" ]]; then
  ./tests/load/postfix_queue_stress.sh
else
  echo "skipped (set MAILWARDEN_RUN_QUEUE_STRESS=true to enable)"
fi

echo "Staging suite completed."
