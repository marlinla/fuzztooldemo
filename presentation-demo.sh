#!/usr/bin/env bash
# presentation-demo.sh
# Run all Trident demo fuzz targets with clean separators and stable paths.

set -euo pipefail

# Resolve repo root from script location (works even if launched elsewhere).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"

# If script is placed outside repo root, let user override:
if [[ ! -f "${REPO_ROOT}/Cargo.toml" || ! -d "${REPO_ROOT}/trident-tests" ]]; then
  echo "Could not auto-detect repo root from script location."
  echo "Set REPO_ROOT manually in this script."
  exit 1
fi

print_sep() {
  printf '\n%s\n' "============================================================"
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
  if rg -q "finding:" "${output_file}"; then
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

echo "Repo root: ${REPO_ROOT}"
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