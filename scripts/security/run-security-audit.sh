#!/usr/bin/env bash
set -euo pipefail

echo "== Mail Warden security audit =="

echo "[1/4] go vet"
go vet ./...

echo "[2/4] go test"
go test ./...

if command -v govulncheck >/dev/null 2>&1; then
  echo "[3/4] govulncheck"
  govulncheck ./...
else
  echo "[3/4] govulncheck not installed (skip)"
fi

if command -v gosec >/dev/null 2>&1; then
  echo "[4/4] gosec"
  gosec ./...
else
  echo "[4/4] gosec not installed (skip)"
fi

echo "Security audit completed."
