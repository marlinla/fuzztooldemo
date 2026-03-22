# Trident Solana Fuzz Demo (4 Minutes)

This demo maps directly to the five vulnerabilities in Section 3.1 of
*Fuzz on the Beach: Fuzzing Solana Smart Contracts*.

Targets in this repository:

- `fuzz_msc` -> Missing Signer Check (MSC)
- `fuzz_moc` -> Missing Owner Check (MOC)
- `fuzz_acpi` -> Arbitrary CPI (ACPI)
- `fuzz_mkc` -> Missing Key Check (MKC)
- `fuzz_ib` -> Integer Bugs (IB)

## 0:00 - 0:25 Context

Say:
"We use Trident to fuzz a purposely vulnerable Anchor program. Each target maps to one
key Solana vulnerability class from section 3.1 of the paper."

## 0:25 - 0:45 Show Scaffold

Show these files:

- `programs/fuzztooldemo/src/lib.rs`
- `trident-tests/fuzz_msc/test_fuzz.rs`
- `trident-tests/fuzz_moc/test_fuzz.rs`
- `trident-tests/fuzz_acpi/test_fuzz.rs`
- `trident-tests/fuzz_mkc/test_fuzz.rs`
- `trident-tests/fuzz_ib/test_fuzz.rs`

## 0:45 - 3:20 Five Micro-Runs

Run each target briefly and call out the expected bug category:

```bash
trident fuzz run fuzz_msc
trident fuzz run fuzz_moc
trident fuzz run fuzz_acpi
trident fuzz run fuzz_mkc
trident fuzz run fuzz_ib
```

Narration template (10-15s each):

1. "This target exercises [vuln class]."
2. "The fuzzer mutates account metadata, account identity, CPI destination, or arithmetic."
3. "A hit here means business logic was reachable with attacker-controlled inputs."

## 3:20 - 3:45 Reproducibility

Replay one finding from a seed:

```bash
trident fuzz debug fuzz_mkc <SEED>
```

Say:
"Trident reproduces the exact path from a single seed, which makes triage and patching practical."

## 3:45 - 4:00 Close

Say:
"This structure scales: add instructions, encode invariants, then keep fuzzing in CI."

## Notes

- The fuzz targets currently provide scaffolding with TODOs for target-specific account setup
  and instruction crafting.
- The vulnerable instruction endpoints already exist in
  `programs/fuzztooldemo/src/lib.rs`.
- Use Trident docs for filling account generation and flow internals:
  [https://ackee.xyz/trident/docs/latest/](https://ackee.xyz/trident/docs/latest/)
