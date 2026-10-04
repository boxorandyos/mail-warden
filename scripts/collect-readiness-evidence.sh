#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-./artifacts/readiness-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "${OUT_DIR}"

echo "[1/6] backend tests"
go test ./... | tee "${OUT_DIR}/go-test.txt"

echo "[2/6] regression tests"
go test ./tests/regression -v | tee "${OUT_DIR}/regression-test.txt"

echo "[3/6] security audit"
./scripts/security/run-security-audit.sh | tee "${OUT_DIR}/security-audit.txt"

if [[ -n "${MAILWARDEN_BASE_URL:-}" && -n "${MAILWARDEN_BEARER_TOKEN:-}" ]]; then
  echo "[4/6] staging suite"
  ./tests/integration/run-staging-suite.sh | tee "${OUT_DIR}/staging-suite.txt"
  echo "[5/6] exchange routing validation"
  ./tests/integration/verify-exchange-routing.sh | tee "${OUT_DIR}/exchange-routing.txt"
else
  echo "[4/6] staging suite skipped (MAILWARDEN_BASE_URL/TOKEN not set)" | tee "${OUT_DIR}/staging-suite.txt"
  echo "[5/6] exchange routing skipped" | tee "${OUT_DIR}/exchange-routing.txt"
fi

echo "[6/6] readiness checklist snapshot"
cp docs/PRODUCTION_READINESS.md "${OUT_DIR}/PRODUCTION_READINESS.md"

echo "Evidence collected in ${OUT_DIR}"
