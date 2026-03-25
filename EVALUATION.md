# Evaluation Template

Status: Runnable

Use this checklist when adding a new primitive or updating existing fuzz targets.

## Baseline Targets

- `fuzz_msc`
  - Mode: `demo`
  - Command: `trident fuzz run fuzz_msc`
  - Finding marker: `MSC finding:`
  - Artifact file: `trident-tests/results/fuzz_msc.jsonl`
  - Reproducible (Y/N): `Y`
  - Notes: Finding marker emitted and JSONL artifact updated in latest run.

- `fuzz_moc`
  - Mode: `demo`
  - Command: `trident fuzz run fuzz_moc`
  - Finding marker: `MOC finding:`
  - Artifact file: `trident-tests/results/fuzz_moc.jsonl`
  - Reproducible (Y/N): `Y`
  - Notes: Reproducible after rebuilding SBF artifact to match current source.

- `fuzz_acpi`
  - Mode: `demo`
  - Command: `trident fuzz run fuzz_acpi`
  - Finding marker: `ACPI finding:`
  - Artifact file: `trident-tests/results/fuzz_acpi.jsonl`
  - Reproducible (Y/N): `Y`
  - Notes: Finding marker emitted and JSONL artifact updated in latest run.

- `fuzz_mkc`
  - Mode: `demo`
  - Command: `trident fuzz run fuzz_mkc`
  - Finding marker: `MKC finding:`
  - Artifact file: `trident-tests/results/fuzz_mkc.jsonl`
  - Reproducible (Y/N): `Y`
  - Notes: Finding marker emitted (multiple hits observed) and JSONL artifact updated.

- `fuzz_ib`
  - Mode: `demo`
  - Command: `trident fuzz run fuzz_ib`
  - Finding marker: `IB finding:`
  - Artifact file: `trident-tests/results/fuzz_ib.jsonl`
  - Reproducible (Y/N): `Y`
  - Notes: Finding marker emitted (multiple hits observed) and JSONL artifact updated.

## Extension Target

- `escrow_mini`
  - Mode: `demo`
  - Command: `N/A (scaffold-only; not wired into Trident manifest/build path)`
  - Finding marker: `N/A`
  - Artifact file: `N/A`
  - Reproducible (Y/N): `N`
  - Notes: Integration deferred until baseline case-study lock is complete.

## Timing Metrics

- Time-to-first-finding (per target): `Sub-second to ~2s in current demo mode runs (guided path sampling).`
- Total run time (demo profile): `~8.4s for ./scripts/demo-trident-paths.sh with SBF rebuild enabled.`
- Number of flow dimensions traced: `18 total across baseline targets (3+3+4+4+4).`

## Quality Metrics

- False-positive notes: `Demo mode intentionally schedules vulnerable attempts; use paper mode for less-guided exploration behavior.`
- Failure modes observed: `Stale SBF artifact can desynchronize source vs runtime binary and suppress expected findings (observed on MOC).`
- Follow-up fixes: `scripts/demo-trident-paths.sh now rebuilds SBF by default before running demo targets.`
