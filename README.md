# Trident Solana Fuzz Demo (Vulnerable Vault)

This repository demonstrates Solana vulnerability testing with a vulnerable
**single-owner vault with plugin payout**.

It covers the five classes from Section 3.1 of
[Fuzz on the Beach: Fuzzing Solana Smart Contracts](https://arxiv.org/abs/2309.03006):

- Missing Signer Check (MSC)
- Missing Owner Check (MOC)
- Arbitrary CPI (ACPI)
- Missing Key Check (MKC)
- Integer Bugs (IB)

## Current Scope

- Runtime-faithful exploit discovery with **Trident fuzzing**
- Human-readable happy-path and exploit checks with **Rust integration tests**
- Presentation runner script with clear per-target status summary

## Codebase Map

- `programs/fuzztooldemo/src/lib.rs` - vulnerable vault program
- `trident-tests/fuzz_msc/test_fuzz.rs` - MSC exploit harness
- `trident-tests/fuzz_moc/test_fuzz.rs` - MOC exploit harness
- `trident-tests/fuzz_acpi/test_fuzz.rs` - ACPI exploit harness
- `trident-tests/fuzz_mkc/test_fuzz.rs` - MKC exploit harness
- `trident-tests/fuzz_ib/test_fuzz.rs` - IB exploit harness
- `programs/fuzztooldemo/tests/vault_security.rs` - Rust honest + exploit suite
- `presentation-demo.sh` - end-to-end presentation script
- `trident-tests/Trident.toml` - Trident program binary mapping

## Vulnerability Mapping

- `fuzz_msc` -> `msc_update_withdraw_limit`
- `fuzz_moc` -> `moc_update_policy_secret`
- `fuzz_acpi` -> `acpi_plugin_payout`
- `fuzz_mkc` -> `mkc_clock_gate`
- `fuzz_ib` -> `ib_internal_transfer`

## Quick Start

## Setup Requirements

If your environment is fresh, install the required tooling first.

### 1) Rust toolchain

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
rustup default stable
```

### 2) Solana CLI

```bash
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
```

Verify:

```bash
solana --version
```

### 3) Anchor CLI (recommended via AVM)

```bash
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install latest
avm use latest
```

Verify:

```bash
anchor --version
```

### 4) Trident CLI

```bash
cargo install trident-cli --locked
```

Verify:

```bash
trident --version
```

### 5) Optional helper tools

```bash
cargo install ripgrep --locked
```

## Quick Start

### 1) Build SBF artifact

```bash
cargo build-sbf --manifest-path "programs/fuzztooldemo/Cargo.toml" --sbf-out-dir "./sbf-artifacts"
```

### 2) Run presentation flow (recommended)

```bash
./presentation-demo.sh
```

Expected summary status:

```text
fuzz_msc  | FOUND
fuzz_moc  | FOUND
fuzz_acpi | FOUND
fuzz_mkc  | FOUND
fuzz_ib   | FOUND
```

### 3) Run Trident targets manually

```bash
cd trident-tests
trident fuzz run fuzz_msc
trident fuzz run fuzz_moc
trident fuzz run fuzz_acpi
trident fuzz run fuzz_mkc
trident fuzz run fuzz_ib
```

Expected finding markers:

```text
MSC finding: ...
MOC finding: ...
ACPI finding: ...
MKC finding: ...
IB finding: ...
```

## Rust Security Tests

Run the Rust integration suite:

```bash
cargo test -p fuzztooldemo --test vault_security
```

For human-readable step logs:

```bash
RUST_LOG=error cargo test -p fuzztooldemo --test vault_security -- --nocapture --test-threads=1
```

The suite includes:

- `honest_flow_passes`
- `msc_attack_reaches_vulnerability`
- `moc_attack_reaches_vulnerability`
- `acpi_attack_reaches_vulnerability`
- `mkc_attack_reaches_vulnerability`
- `ib_attack_reaches_vulnerability`

## ACPI Runtime Note

`acpi_plugin_payout` performs CPI. In host-native test runtimes, CPI cannot execute
like on-chain SBF execution. The program therefore returns
`CpiUnavailableOffChain` on non-Solana targets.

Use Trident (`fuzz_acpi`) as the runtime-faithful ACPI evidence path.

## Troubleshooting

- If Trident reports missing instructions, rebuild SBF and rerun.
- Ensure `trident-tests/Trident.toml` points to `../sbf-artifacts/fuzztooldemo.so`.
- If output is noisy in Rust tests, use `--test-threads=1`.

## References

- Trident docs: [https://ackee.xyz/trident/docs/latest/](https://ackee.xyz/trident/docs/latest/)
- Vulnerability taxonomy paper: [https://arxiv.org/abs/2309.03006](https://arxiv.org/abs/2309.03006)


