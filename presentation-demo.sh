#!/usr/bin/env bash
# presentation-demo.sh
# Run all Trident demo fuzz targets with clean separators and stable paths.
#
# Tunables (exported for Trident → fuzz binaries; see trident-tests/src/lib.rs):
#   DEMO_VULN_ROLL_DENOM   Probability of attempting the vulnerable path is 1/N (default 10 → ~10%).
#   DEMO_FUZZ_ITERATIONS   Overrides Trident fuzz(iterations, _) when set (non-empty).
#   DEMO_FUZZ_FLOW_CALLS   Overrides Trident fuzz(_, flow_calls) when set (non-empty).
#   Effective tries per target ≈ ITERATIONS * FLOW_CALLS — large products with modest
#   DEMO_VULN_ROLL_DENOM make "mixed" outcomes unlikely (see README).
#
# Examples:
#   ./presentation-demo.sh --vuln-denom 20
#   DEMO_FUZZ_ITERATIONS=800 DEMO_FUZZ_FLOW_CALLS=40 ./presentation-demo.sh

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: presentation-demo.sh [options]

Options:
  --vuln-denom N        DEMO_VULN_ROLL_DENOM: vulnerable-path attempt rate 1/N (default 10).
  --fuzz-iterations N   DEMO_FUZZ_ITERATIONS: Trident iteration count (optional).
  --flow-calls N        DEMO_FUZZ_FLOW_CALLS: flow calls per iteration (optional).
  -h, --help            Show this help.

Environment variables with the same names override defaults; CLI flags set them for this run.
EOF
}

# Resolve repo root from script location (works even if launched elsewhere).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vuln-denom)
      DEMO_VULN_ROLL_DENOM="${2:?missing value for --vuln-denom}"
      shift 2
      ;;
    --fuzz-iterations)
      DEMO_FUZZ_ITERATIONS="${2:?missing value for --fuzz-iterations}"
      shift 2
      ;;
    --flow-calls)
      DEMO_FUZZ_FLOW_CALLS="${2:?missing value for --flow-calls}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# If script is placed outside repo root, let user override:
if [[ ! -f "${REPO_ROOT}/Cargo.toml" || ! -d "${REPO_ROOT}/trident-tests" ]]; then
  echo "Could not auto-detect repo root from script location."
  echo "Set REPO_ROOT manually in this script."
  exit 1
fi

export_demo_env() {
  export DEMO_VULN_ROLL_DENOM="${DEMO_VULN_ROLL_DENOM:-10}"
  if [[ -n "${DEMO_FUZZ_ITERATIONS:-}" ]]; then
    export DEMO_FUZZ_ITERATIONS
  fi
  if [[ -n "${DEMO_FUZZ_FLOW_CALLS:-}" ]]; then
    export DEMO_FUZZ_FLOW_CALLS
  fi
}

print_sep() {
  printf '\n%s\n' "============================================================"
}

has_finding_marker() {
  local file="$1"
  local line lower_line
  while IFS= read -r line; do
    lower_line="${line,,}"
    if [[ "${lower_line}" == *"finding:"* ]]; then
      return 0
    fi
  done < "${file}"
  return 1
}

run_target() {
  local target="$1"
  print_sep
  echo "Running: ${target}"
  print_sep

  local output_file
  output_file="$(mktemp)"

  # Fuzz targets may return either 0 or non-zero on finding depending on harness behavior.
  set +e
  trident fuzz run "${target}" 2>&1 | tee "${output_file}"
  local code=$?
  set -e

  local verdict
  if has_finding_marker "${output_file}"; then
    verdict="FOUND"
  elif [[ "${code}" -eq 0 ]]; then
    verdict="NO_FINDING"
  else
    verdict="ERROR"
  fi

  rm -f "${output_file}"

  echo
  printf "[RESULT] %-10s | %-10s | exit %s\n" "${target}" "${verdict}" "${code}"

  RESULTS+=("${target}|${verdict}|${code}")
}

export_demo_env

echo "Repo root: ${REPO_ROOT}"
echo "Demo fuzz: DEMO_VULN_ROLL_DENOM=${DEMO_VULN_ROLL_DENOM} (vulnerable-path attempt rate 1/${DEMO_VULN_ROLL_DENOM})"
if [[ -n "${DEMO_FUZZ_ITERATIONS:-}" ]]; then
  echo "  DEMO_FUZZ_ITERATIONS=${DEMO_FUZZ_ITERATIONS}"
fi
if [[ -n "${DEMO_FUZZ_FLOW_CALLS:-}" ]]; then
  echo "  DEMO_FUZZ_FLOW_CALLS=${DEMO_FUZZ_FLOW_CALLS}"
fi
if [[ -n "${DEMO_FUZZ_ITERATIONS:-}" && -n "${DEMO_FUZZ_FLOW_CALLS:-}" ]]; then
  echo "  (approx flow executions per target: $((DEMO_FUZZ_ITERATIONS * DEMO_FUZZ_FLOW_CALLS)))"
fi
print_sep
echo "Step 1/2: Build SBF artifact"
print_sep

(
  cd "${REPO_ROOT}" || exit 1
  cargo build-sbf \
    --manifest-path "programs/fuzztooldemo/Cargo.toml" \
    --sbf-out-dir "./sbf-artifacts"
) || {
  echo "Build failed. Stopping."
  exit 1
}

print_sep
echo "Step 2/2: Run fuzz targets one-by-one"
print_sep

declare -a RESULTS
cd "${REPO_ROOT}/trident-tests" || exit 1
run_target "fuzz_msc"
run_target "fuzz_moc"
run_target "fuzz_acpi"
run_target "fuzz_mkc"
run_target "fuzz_ib"

print_sep
echo "Summary"
print_sep
printf "%-10s | %-10s | %-8s\n" "TARGET" "STATUS" "EXIT"
printf "%-10s-+-%-10s-+-%-8s\n" "----------" "----------" "--------"
for entry in "${RESULTS[@]}"; do
  IFS='|' read -r target verdict code <<< "${entry}"
  printf "%-10s | %-10s | %-8s\n" "${target}" "${verdict}" "${code}"
done
print_sep
echo "Done."