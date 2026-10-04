#!/usr/bin/env bash
set -euo pipefail

ACTIVE_HOST="${ACTIVE_HOST:-mailwarden-a.local}"
STANDBY_HOST="${STANDBY_HOST:-mailwarden-b.local}"
API_PORT="${API_PORT:-8080}"
POLICY_PORT="${POLICY_PORT:-10031}"

echo "=== Mail Warden failover drill ==="
echo "Active: ${ACTIVE_HOST}"
echo "Standby: ${STANDBY_HOST}"

echo "[1/5] Checking active readiness..."
curl -fsS "http://${ACTIVE_HOST}:${API_PORT}/readyz" >/dev/null

echo "[2/5] Checking standby readiness..."
curl -fsS "http://${STANDBY_HOST}:${API_PORT}/readyz" >/dev/null

echo "[3/5] Verifying policy service on standby..."
if ! timeout 3 bash -c "cat < /dev/null > /dev/tcp/${STANDBY_HOST}/${POLICY_PORT}" 2>/dev/null; then
  echo "Standby policy port not reachable: ${STANDBY_HOST}:${POLICY_PORT}"
  exit 1
fi

echo "[4/5] Trigger failover manually (operator step)."
echo "    - stop active services"
echo "    - promote standby"
echo "Press enter when completed..."
read -r _

echo "[5/5] Post-failover readiness check..."
curl -fsS "http://${STANDBY_HOST}:${API_PORT}/readyz" >/dev/null
echo "Failover drill checks completed successfully."
