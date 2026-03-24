# Trident Solana Fuzz Demo

This repository is a demo project for the Trident Solana fuzzing framework.
The active case study is a vulnerable **single-owner vault with plugin payout**
and it maps to the five vulnerability classes in Section 3.1 of:

- [Fuzz on the Beach: Fuzzing Solana Smart Contracts](https://arxiv.org/abs/2309.03006)

## Demo Goals

- Show how Trident can execute fuzz targets against an Anchor program.
- Map fuzz targets to all five Solana vulnerability classes.
- Demonstrate end-to-end findings for each class.
- Keep the workflow simple and reproducible for classroom/demo use.

## Vulnerability Mapping

- `fuzz_msc` -> Missing Signer Check (`msc_update_withdraw_limit`)
- `fuzz_moc` -> Missing Owner Check (`moc_update_policy_secret`)
- `fuzz_acpi` -> Arbitrary CPI (`acpi_plugin_payout`)
- `fuzz_mkc` -> Missing Key Check (`mkc_clock_gate`)
- `fuzz_ib` -> Integer Bugs (`ib_internal_transfer`)

The target program is in:

- `programs/fuzztooldemo/src/lib.rs`

The Trident fuzz targets are in:

- `trident-tests/`

## Project Structure (Demo-Relevant)

- `programs/fuzztooldemo/src/lib.rs` - vulnerable demo instructions
- `trident-tests/fuzz_msc/test_fuzz.rs` - MSC harness
- `trident-tests/fuzz_moc/test_fuzz.rs` - MOC harness
- `trident-tests/fuzz_acpi/test_fuzz.rs` - ACPI harness
- `trident-tests/fuzz_mkc/test_fuzz.rs` - MKC harness
- `trident-tests/fuzz_ib/test_fuzz.rs` - IB harness
- `trident-tests/Trident.toml` - Trident program configuration
- `DEMO_SCRIPT.md` - timed talk track for the presentation

## Setup

Assumes Rust/Anchor/Trident are installed and available in `PATH`.

1. Build SBF artifact used by Trident:

```bash
cargo build-sbf --manifest-path "programs/fuzztooldemo/Cargo.toml" --sbf-out-dir "./sbf-artifacts"
```

1. Run all vulnerability targets:

```bash
cd trident-tests
trident fuzz run fuzz_msc
trident fuzz run fuzz_moc
trident fuzz run fuzz_acpi
trident fuzz run fuzz_mkc
trident fuzz run fuzz_ib
```

## Expected Output

```text
MSC finding: ...
MOC finding: ...
ACPI finding: ...
MKC finding: ...
IB finding: ...
```

Each line indicates a vulnerable path was reached.

## 4-Minute Demo Flow

Use the detailed script in:

- `DEMO_SCRIPT.md`

Suggested high-level flow:

1. Explain the five vulnerability classes.
1. Run each of the five fuzz targets.
1. Map each finding string to the corresponding vulnerability class.
1. Show how AI-generated hypotheses can drive harness changes.

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
