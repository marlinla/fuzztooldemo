#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIDENT_DIR="${ROOT_DIR}/trident-tests"
RESULTS_DIR="${TRIDENT_DIR}/results"

MODE="${DEMO_FUZZ_MODE:-demo}"
ITERATIONS="${DEMO_FUZZ_ITERATIONS:-40}"
FLOW_CALLS="${DEMO_FUZZ_FLOW_CALLS:-10}"
ROLL_DENOM="${DEMO_VULN_ROLL_DENOM:-2}"
TRACE_PATHS="${DEMO_TRACE_PATHS:-1}"
WRITE_JSON="${DEMO_WRITE_FINDINGS_JSON:-1}"
BUILD_SBF="${DEMO_BUILD_SBF:-1}"

if ! command -v trident >/dev/null 2>&1; then
  echo "Missing 'trident' CLI in PATH."
  exit 1
fi

mkdir -p "${RESULTS_DIR}"

echo "=== Trident 3-minute path demo ==="
echo "mode=${MODE} iterations=${ITERATIONS} flow_calls=${FLOW_CALLS} vuln_roll_denom=${ROLL_DENOM} trace_paths=${TRACE_PATHS}"
echo "artifacts=${RESULTS_DIR}"
echo

if [[ "${BUILD_SBF}" == "1" || "${BUILD_SBF}" == "true" || "${BUILD_SBF}" == "yes" ]]; then
  echo "Rebuilding SBF artifact for reproducible runtime parity..."
  cargo build-sbf --manifest-path "${ROOT_DIR}/programs/fuzztooldemo/Cargo.toml" --sbf-out-dir "${ROOT_DIR}/sbf-artifacts"
  echo
fi

printf "%-10s | %-10s | %-10s\n" "TARGET" "RESULT" "EXIT_CODE"
printf "%-10s-+-%-10s-+-%-10s\n" "----------" "----------" "----------"

run_target() {
  local target="$1"
  local marker="$2"
  local logfile
  logfile="$(mktemp)"

  set +e
  (
    cd "${TRIDENT_DIR}"
    DEMO_FUZZ_MODE="${MODE}" \
    DEMO_FUZZ_ITERATIONS="${ITERATIONS}" \
    DEMO_FUZZ_FLOW_CALLS="${FLOW_CALLS}" \
    DEMO_VULN_ROLL_DENOM="${ROLL_DENOM}" \
    DEMO_TRACE_PATHS="${TRACE_PATHS}" \
    DEMO_WRITE_FINDINGS_JSON="${WRITE_JSON}" \
    trident fuzz run "${target}"
  ) >"${logfile}" 2>&1
  local status=$?
  set -e

  local result="NO_FINDING"
  if grep -q "${marker} finding:" "${logfile}"; then
    result="FOUND"
  fi

  printf "%-10s | %-10s | %-10s\n" "${target}" "${result}" "${status}"
  grep -E "${marker} finding:|\\[TRACE\\]\\[${target}\\]" "${logfile}" | sed -n '1,3p' || true
  echo
  rm -f "${logfile}"
}

run_target "fuzz_msc" "MSC"
run_target "fuzz_acpi" "ACPI"

echo "Done. Use JSONL artifacts in ${RESULTS_DIR} for replay evidence."
