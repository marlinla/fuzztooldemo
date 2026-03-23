# Trident Solana Fuzz Demo

This repository is a demo project for the Trident Solana fuzzing framework.
The demo is designed for a short presentation (<= 4 minutes) and is aligned
with the five vulnerability classes listed in Section 3.1 of:

- [Fuzz on the Beach: Fuzzing Solana Smart Contracts](https://arxiv.org/abs/2309.03006)

## Demo Goals

- Show how Trident can execute fuzz targets against an Anchor program.
- Map fuzz targets to Solana vulnerability classes.
- Demonstrate one working end-to-end finding path (Missing Signer Check).
- Keep the workflow simple and reproducible for classroom/demo use.

## Vulnerability Mapping

- `fuzz_msc` -> Missing Signer Check (implemented end-to-end)
- `fuzz_moc` -> Missing Owner Check (scaffold)
- `fuzz_acpi` -> Arbitrary CPI (scaffold)
- `fuzz_mkc` -> Missing Key Check (scaffold)
- `fuzz_ib` -> Integer Bugs (scaffold)

The target program is in:

- `programs/fuzztooldemo/src/lib.rs`

The Trident fuzz targets are in:

- `trident-tests/`

## Current Working Demo Target

The simplest confidence target is `fuzz_msc`, which exercises a minimal
missing-signer vulnerability:

- Program instruction: `msc_minimal`
- Behavior: mutates writable account data without requiring the authority
  account to be a signer.
- Fuzz finding signal: the run prints
  `MSC finding: non-signer authority call succeeded (seeded run should reject this).`

## Project Structure (Demo-Relevant)

- `programs/fuzztooldemo/src/lib.rs` - vulnerable demo instructions
- `trident-tests/fuzz_msc/test_fuzz.rs` - working MSC fuzz target
- `trident-tests/fuzz_moc/test_fuzz.rs` - MOC scaffold
- `trident-tests/fuzz_acpi/test_fuzz.rs` - ACPI scaffold
- `trident-tests/fuzz_mkc/test_fuzz.rs` - MKC scaffold
- `trident-tests/fuzz_ib/test_fuzz.rs` - IB scaffold
- `trident-tests/Trident.toml` - Trident program configuration
- `DEMO_SCRIPT.md` - timed talk track for the presentation

## Setup

Assumes Rust/Anchor/Trident are installed and available in `PATH`.

1. Build SBF artifact used by Trident:

```bash
cargo build-sbf --manifest-path "programs/fuzztooldemo/Cargo.toml" --sbf-out-dir "./sbf-artifacts"
```

1. Run the working MSC target:

```bash
cd trident-tests
trident fuzz run fuzz_msc
```

## Expected Output (MSC)

You should see a line similar to:

```text
MSC finding: non-signer authority call succeeded (seeded run should reject this).
```

This indicates the vulnerable path is reachable.

## 4-Minute Demo Flow

Use the detailed script in:

- `DEMO_SCRIPT.md`

Suggested high-level flow:

1. Explain the five vulnerability classes.
1. Run `fuzz_msc` as the end-to-end confidence demo.
1. Briefly point at the other four scaffold targets.
1. Close with next step: fill scaffold flows and add replayable seeds.

## Troubleshooting

- If you see `InstructionFallbackNotFound`, Trident is likely loading an old
  program binary.
- Ensure `trident-tests/Trident.toml` points to:
  `../sbf-artifacts/fuzztooldemo.so`
- Rebuild with:

```bash
cargo build-sbf --manifest-path "programs/fuzztooldemo/Cargo.toml" --sbf-out-dir "./sbf-artifacts"
```

## References

- Trident docs: [https://ackee.xyz/trident/docs/latest/](https://ackee.xyz/trident/docs/latest/)
- Vulnerability taxonomy paper: [https://arxiv.org/abs/2309.03006](https://arxiv.org/abs/2309.03006)
