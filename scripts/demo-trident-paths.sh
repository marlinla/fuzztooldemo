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
  local artifact_file="${RESULTS_DIR}/${target}.jsonl"
  local artifact_lines_before=0
  local artifact_lines_after=0
  local artifact_is_new=0

  if [[ -f "${artifact_file}" ]]; then
    artifact_lines_before="$(wc -l < "${artifact_file}")"
  fi

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

  local trace_line
  trace_line="$(grep -E "\\[TRACE\\]\\[${target}\\].*attempt_vulnerable=true" "${logfile}" | sed -n '1,1p' || true)"
  if [[ -z "${trace_line}" ]]; then
    trace_line="$(grep -E "\\[TRACE\\]\\[${target}\\]" "${logfile}" | sed -n '1,1p' || true)"
  fi

  local trace_facts
  trace_facts="$(printf "%s" "${trace_line}" | sed -E 's/^.*\] //' | sed 's/, / | /g')"

  local finding_line
  finding_line="$(grep -E "${marker} finding:" "${logfile}" | sed -n '1,1p' || true)"

  echo "Story:"
  if [[ -n "${trace_facts}" ]]; then
    echo "  Path sampled  : ${trace_facts}"
  else
    echo "  Path sampled  : <no trace emitted>"
  fi
  if [[ -n "${finding_line}" ]]; then
    echo "  Predicate hit : ${finding_line}"
  else
    echo "  Predicate hit : <none>"
  fi

  local artifact_line=""
  if [[ -f "${artifact_file}" ]]; then
    artifact_lines_after="$(wc -l < "${artifact_file}")"
    if (( artifact_lines_after > 0 )); then
      artifact_line="$(sed -n "${artifact_lines_after}p" "${artifact_file}")"
    fi
    if (( artifact_lines_after > artifact_lines_before )); then
      artifact_is_new=1
    fi
  fi

  if [[ "${result}" == "NO_FINDING" ]]; then
    echo "  Evidence      : <none in this run>"
  elif [[ -n "${artifact_line}" && "${artifact_is_new}" -eq 1 ]]; then
    if command -v python3 >/dev/null 2>&1; then
      ARTIFACT_LINE="${artifact_line}" python3 - <<'PY'
import json
import os

line = os.environ.get("ARTIFACT_LINE", "").strip()
if not line:
    raise SystemExit(0)

def shorten(value: str) -> str:
    if len(value) <= 18:
        return value
    return f"{value[:8]}...{value[-6:]}"

obj = json.loads(line)
fields = obj.get("fields", {})
interesting = []
for key in ("attempt_vulnerable", "authority_should_sign", "uses_attacker_program", "amount", "payload_len", "callee_program"):
    if key in fields:
        val = str(fields[key])
        if key == "callee_program":
            val = shorten(val)
        interesting.append(f"{key}={val}")

summary = " | ".join(interesting) if interesting else "no structured fields"
print(f"  Evidence      : finding=\"{obj.get('finding', '')}\" ({summary})")
PY
    else
      echo "  Evidence      : ${artifact_line}"
    fi
  elif [[ -n "${artifact_line}" ]]; then
    echo "  Evidence      : <latest entry is from a previous run>"
  else
    echo "  Evidence      : <none available>"
  fi

  echo
  rm -f "${logfile}"
}

run_target "fuzz_msc" "MSC"
run_target "fuzz_acpi" "ACPI"

echo "Done. Use JSONL artifacts in ${RESULTS_DIR} for replay evidence."
