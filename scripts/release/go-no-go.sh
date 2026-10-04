#!/usr/bin/env bash
set -euo pipefail

pick_latest_evidence_dir() {
  local latest
  latest="$(ls -1dt ./artifacts/readiness-* 2>/dev/null | head -n 1 || true)"
  if [[ -z "${latest}" ]]; then
    echo "No readiness artifact directory found. Pass a path explicitly." >&2
    return 1
  fi
  echo "${latest}"
}

EVIDENCE_DIR="${1:-}"
if [[ -z "${EVIDENCE_DIR}" ]]; then
  EVIDENCE_DIR="$(pick_latest_evidence_dir)"
fi
if [[ ! -d "${EVIDENCE_DIR}" ]]; then
  echo "Evidence directory not found: ${EVIDENCE_DIR}" >&2
  exit 1
fi

pass_count=0
warn_count=0
fail_count=0

report() {
  local status="$1"
  local label="$2"
  local detail="$3"
  printf "%-5s %-30s %s\n" "${status}" "${label}" "${detail}"
}

check_test_output() {
  local file="$1"
  local label="$2"
  if [[ ! -f "${file}" ]]; then
    report "FAIL" "${label}" "missing file"
    fail_count=$((fail_count + 1))
    return
  fi
  if rg -q "FAIL|panic:" "${file}"; then
    report "FAIL" "${label}" "failures detected"
    fail_count=$((fail_count + 1))
    return
  fi
  report "PASS" "${label}" "no failures detected"
  pass_count=$((pass_count + 1))
}

check_test_output "${EVIDENCE_DIR}/go-test.txt" "Go test suite"
check_test_output "${EVIDENCE_DIR}/regression-test.txt" "Regression suite"

if [[ -f "${EVIDENCE_DIR}/security-audit.txt" ]]; then
  if rg -qi "critical|high.*[1-9]|\\bfail\\b" "${EVIDENCE_DIR}/security-audit.txt"; then
    report "FAIL" "Security audit" "high-severity findings detected"
    fail_count=$((fail_count + 1))
  else
    report "PASS" "Security audit" "no high-severity findings detected"
    pass_count=$((pass_count + 1))
  fi
else
  report "WARN" "Security audit" "missing file"
  warn_count=$((warn_count + 1))
fi

for staged_file in "${EVIDENCE_DIR}/staging-suite.txt" "${EVIDENCE_DIR}/exchange-routing.txt"; do
  label="$(basename "${staged_file}")"
  if [[ ! -f "${staged_file}" ]]; then
    report "WARN" "${label}" "missing file"
    warn_count=$((warn_count + 1))
    continue
  fi
  if rg -qi "skipped" "${staged_file}"; then
    report "WARN" "${label}" "not executed in this evidence set"
    warn_count=$((warn_count + 1))
    continue
  fi
  if rg -qi "FAIL|error" "${staged_file}"; then
    report "FAIL" "${label}" "failures detected"
    fail_count=$((fail_count + 1))
    continue
  fi
  report "PASS" "${label}" "executed without obvious failures"
  pass_count=$((pass_count + 1))
done

echo
echo "Summary: PASS=${pass_count} WARN=${warn_count} FAIL=${fail_count}"
if (( fail_count > 0 )); then
  echo "GO/NO-GO: NO-GO"
  exit 2
fi
if (( warn_count > 0 )); then
  echo "GO/NO-GO: CONDITIONAL (warnings must be acknowledged)"
  exit 0
fi
echo "GO/NO-GO: GO"
