# Case Study: Trident Fuzz Pathing for Solana Vulnerabilities

Status: Runnable

## Objective

Demonstrate that this repository is both:

1. A reproducible benchmark for five key Solana vulnerability classes from Section 3.1.
2. A transferable workflow that AI can reuse to develop and fuzz-test new smart contract primitives.

## Research Questions

- Can Trident fuzz flows reach exploit-relevant paths for all five target classes?
- Can findings be replayed and explained from path telemetry and artifacts?
- Can the same path-modeling approach be reused for a new primitive with limited edits?

## Scope

### Baseline (implemented)

- Program under test: `programs/fuzztooldemo/src/lib.rs`
- Five Trident targets:
  - `fuzz_msc`
  - `fuzz_moc`
  - `fuzz_acpi`
  - `fuzz_mkc`
  - `fuzz_ib`
- Path telemetry and finding artifacts:
  - `DEMO_TRACE_PATHS=1`
  - `DEMO_WRITE_FINDINGS_JSON=1`
  - `trident-tests/results/*.jsonl`

### Extension (scaffolded in this patch)

- Primitive scaffold: `primitives/escrow_mini/`
- AI workflow playbook: `AI_WORKFLOW.md`
- Evaluation template: `EVALUATION.md`

## Method

1. Model vulnerability-relevant control dimensions in `#[flow]` (signer bits, owners, keys, CPI target, arithmetic bounds).
2. Execute generated transactions via Trident.
3. Encode exploit predicates in harness logic.
4. Emit trace lines and JSON artifacts when predicates trigger.
5. Replay and report findings.

## Commands

### Baseline quick evidence

```bash
cargo test -p fuzztooldemo --test vault_security
cd trident-tests && cargo check -p fuzz_tests --bins
```

### Live path demo (3-minute profile)

```bash
./scripts/demo-trident-paths.sh
```

### Full five-target run

```bash
cd trident-tests
trident fuzz run fuzz_msc
trident fuzz run fuzz_moc
trident fuzz run fuzz_acpi
trident fuzz run fuzz_mkc
trident fuzz run fuzz_ib
```

## Success Criteria

- Five vulnerability targets run and can emit class-specific finding markers.
- At least two live targets (`MSC`, `ACPI`) reliably show:
  - trace line
  - finding line
  - JSON artifact
- A new primitive can be scaffolded by AI using `AI_WORKFLOW.md` and evaluated using `EVALUATION.md`.

## Known Limitations

- `demo` mode uses guided vulnerable-path scheduling for presentation reliability.
- `paper` mode is less guided but still not identical to binary-only oracle internals from the paper runtime.
- Current primitive extension is scaffold-only; implementation is tracked as next work.

## Deliverables Map

- Baseline implementation and docs: `README.md`
- Live script: `scripts/demo-trident-paths.sh`
- AI transfer workflow: `AI_WORKFLOW.md`
- Evaluation rubric: `EVALUATION.md`
- Next primitive scaffold: `primitives/escrow_mini/`
