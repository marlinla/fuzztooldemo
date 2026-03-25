# Trident Solana Fuzz Demo (Vulnerable Vault)

Status: Runnable

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
- Focused 3-minute Trident pathing demo runner
- Case-study package for AI-extendable primitive development (`CASE_STUDY.md`, `AI_WORKFLOW.md`, `EVALUATION.md`)

## Project Direction

This repository now has two goals:

1. **Baseline vulnerability case study:** demonstrate Trident fuzz pathing on the five key Solana classes from Section 3.1.
2. **Transferability with AI:** show that the same workflow can scaffold and evolve new smart-contract primitives.

To reduce ambiguity, treat assets as either **Runnable** (in active build/demo path) or **Scaffold** (template for next integration).

### Status Snapshot

- `Runnable`
  - Baseline vulnerable program: `programs/fuzztooldemo/src/lib.rs`
  - Five Trident targets: `trident-tests/fuzz_{msc,moc,acpi,mkc,ib}/test_fuzz.rs`
  - Live path demo runner: `scripts/demo-trident-paths.sh`
  - Case-study docs: `CASE_STUDY.md`, `AI_WORKFLOW.md`, `EVALUATION.md`
- `Scaffold`
  - Extension primitive templates under `primitives/escrow_mini/` (not yet wired into workspace build or Trident manifest)

## Codebase Map

- `programs/fuzztooldemo/src/lib.rs` - vulnerable vault program
- `trident-tests/fuzz_msc/test_fuzz.rs` - MSC exploit harness
- `trident-tests/fuzz_moc/test_fuzz.rs` - MOC exploit harness
- `trident-tests/fuzz_acpi/test_fuzz.rs` - ACPI exploit harness
- `trident-tests/fuzz_mkc/test_fuzz.rs` - MKC exploit harness
- `trident-tests/fuzz_ib/test_fuzz.rs` - IB exploit harness
- `programs/fuzztooldemo/tests/vault_security.rs` - Rust honest + exploit suite
- `scripts/demo-trident-paths.sh` - 3-minute Trident pathing showcase (`MSC` + `ACPI`)
- `trident-tests/Trident.toml` - Trident program binary mapping
- `CASE_STUDY.md` - end-to-end case-study framing and success criteria
- `AI_WORKFLOW.md` - repeatable AI-driven primitive extension workflow
- `EVALUATION.md` - evidence capture checklist for baseline and extension runs
- `primitives/` - scaffold-only templates for next primitive integrations

## Vulnerability Mapping

- `fuzz_msc` -> `msc_update_withdraw_limit`
- `fuzz_moc` -> `moc_update_policy_secret`
- `fuzz_acpi` -> `acpi_plugin_payout`
- `fuzz_mkc` -> `mkc_clock_gate`
- `fuzz_ib` -> `ib_lamport_transfer`

## Paper Mapping (Section 3.1)

The table below documents how each demo target maps to the paper's vulnerability
definitions and where we intentionally simplify behavior for presentation.

- **MSC:** `msc_update_withdraw_limit` intentionally checks key equality but omits signer validation.
- **MOC:** `moc_update_policy_secret` reads attacker-controlled account data, compares embedded pubkey data to a writable treasury account key, and mutates that treasury without owner verification.
- **ACPI:** `acpi_plugin_payout` invokes caller-selected program id without validating it against the trusted id; CPI includes writable treasury account to reflect realistic impact.
- **MKC:** `mkc_clock_gate` calls a slot-loading helper without first validating `clock_like.key() == trusted_clock_key`.
- **IB:** `ib_lamport_transfer` uses wrapping arithmetic when writing account lamports, matching the paper's lamports-focused integer bug model.

## Harness Notes (Discovery vs Demo Control)

Fuzz harnesses support two modes:

- `DEMO_FUZZ_MODE=demo` (default): probabilistic vulnerable-path guidance using `DEMO_VULN_ROLL_DENOM`.
- `DEMO_FUZZ_MODE=paper`: minimizes external path scheduling and samples exploit shapes directly.

Use `demo` for reproducible classroom walkthroughs, and `paper` when you want behavior
closer to unguided oracle discovery.

## Start Here (By Goal)

- **Run baseline evidence quickly**
  - `cargo test -p fuzztooldemo --test vault_security`
  - `cd trident-tests && cargo check -p fuzz_tests --bins`
- **Show Trident pathing in 3 minutes**
  - `./scripts/demo-trident-paths.sh`
- **Run full five-class evidence manually**
  - `cd trident-tests && trident fuzz run fuzz_msc && trident fuzz run fuzz_moc && trident fuzz run fuzz_acpi && trident fuzz run fuzz_mkc && trident fuzz run fuzz_ib`
- **Extend to a new primitive with AI**
  - Read `AI_WORKFLOW.md`, then execute acceptance and metrics in `EVALUATION.md`

## Expected Vulnerable vs Hardened Outcomes

Current repository state is intentionally vulnerable. For each class, the expected
result is:

- Vulnerable instruction + exploit input: finding should be reachable.
- Hardened instruction (not yet implemented in this repo): finding should not be reachable.

When adding hardened variants, keep both checks:

- **Positive check:** exploit reaches finding in vulnerable variant.
- **Negative check:** same exploit path fails in hardened variant.

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

### 2) Run focused Trident path demo (recommended)

```bash
./scripts/demo-trident-paths.sh
```

Optional tuning:

- `DEMO_VULN_ROLL_DENOM` — vulnerable-path attempt rate `1/N`.
- `DEMO_FUZZ_ITERATIONS` — Trident `fuzz` iteration count (overrides each target’s default when set).
- `DEMO_FUZZ_FLOW_CALLS` — flow calls per iteration (Trident second parameter).
- `DEMO_FUZZ_MODE` — `demo` (guided, default) or `paper` (less guided).
- `DEMO_BUILD_SBF` — `1` (default) rebuilds `sbf-artifacts/fuzztooldemo.so` before demo run.
- `DEMO_TRACE_PATHS` — `1` prints per-flow path mutations as `[TRACE][target] ...`.
- `DEMO_WRITE_FINDINGS_JSON` — `1` writes finding artifacts to `trident-tests/results/*.jsonl`.

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

### 4) Three-minute Trident path demo details

This runner focuses on two high-signal targets (`MSC`, `ACPI`) and prints path traces
so you can explain how Trident-generated paths trigger findings.

```bash
./scripts/demo-trident-paths.sh
```

What it shows:

- Path exploration lines: `[TRACE][fuzz_*] key=value,...`
- Finding predicate line: `MSC finding: ...` / `ACPI finding: ...`
- Replay artifacts: JSONL records in `trident-tests/results/`

Example artifact entry:

```json
{"ts_ms":1711320000000,"target":"fuzz_msc","mode":"demo","finding":"non-signer authority updated withdraw_limit","fields":{"attempt_vulnerable":"true","authority_should_sign":"false","new_limit":"999"}}
```

## How Trident Paths Are Modeled Here

Each harness follows the same Trident structure:

1. `#[init]` seeds accounts/state for the target vulnerability class.
2. `#[flow]` mutates path dimensions (signer bits, owners, callee programs, keys, amounts).
3. Trident executes the generated instruction transaction.
4. Harness predicates label exploitable paths and emit finding markers.

This follows the Trident workflow of manually guided fuzzing with custom assertions and
runtime observation; see the official docs for API/macros and advanced customization:
[https://ackee.xyz/trident/docs/latest/](https://ackee.xyz/trident/docs/latest/).

## Further Development Roadmap

Use this order to keep scope disciplined while moving toward a complete case study:

1. **Stabilize baseline evidence** (no new vulnerability mechanics)
   - Keep `scripts/demo-trident-paths.sh` reliable for live use.
   - Keep `trident-tests/results/*.jsonl` reproducible with trace + finding output.
2. **Integrate first extension primitive (`escrow_mini`)**
   - Move scaffold into a real Anchor program under `programs/`.
   - Add artifact mapping to `trident-tests/Trident.toml`.
   - Add a real `fuzz_escrow_mini` target and one exploit predicate.
3. **Evaluate and compare**
   - Fill the extension row in `EVALUATION.md`.
   - Record time-to-first-finding and replayability notes.
4. **Only then broaden**
   - Add additional primitives or hardened variants.
   - Avoid parallel large refactors while proving transferability.

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
