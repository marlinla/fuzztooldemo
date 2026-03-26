# AI Exploration — Fuzzing Rust & Solana Smart Contracts

**EECS 4313 · Winter 2026**
**Team:** Mark Farid (218994368) · Marlin Lachance (213885025) · Dilpreet Bansi (218803213)

---

## Overview

This directory contains the **Section 3: AI Exploration** deliverables for our project on
fuzzing Solana smart contracts with the Trident framework. We used AI (Claude) to:

1. **Fix the vulnerable vault program** so all 5 fuzz targets report `NO_FINDING`
2. **Implement three additional Solana program design patterns** (Escrow, AMM, NFT Minting)
3. **Generate Trident fuzz test harnesses** for each new program

---

## Directory Structure

```
ai-exploration/
├── AI_EXPLORATION_README.md           ← This file
│
├── vault-fixed/                       ← Fixed vault program
│   └── programs/fuzztooldemo/src/
│       └── lib.rs                     ← All 5 vulnerabilities patched
│
├── escrow/                            ← Escrow design pattern
│   ├── programs/escrow/src/
│   │   └── lib.rs                     ← Escrow program (init, exchange, cancel)
│   └── trident-tests/
│       ├── fuzz_escrow_exchange/
│       │   └── test_fuzz.rs           ← Exchange flow + double-exchange detection
│       └── fuzz_escrow_cancel/
│           └── test_fuzz.rs           ← Unauthorized cancel detection
│
├── amm/                               ← Constant-product AMM design pattern
│   ├── programs/amm/src/
│   │   └── lib.rs                     ← AMM program (init, add/remove liquidity, swap)
│   └── trident-tests/
│       ├── fuzz_amm_swap/
│       │   └── test_fuzz.rs           ← k-invariant violation detection
│       └── fuzz_amm_liquidity/
│           └── test_fuzz.rs           ← Value extraction via add/remove cycles
│
└── nft-mint/                          ← NFT Minting design pattern
    ├── programs/nft-mint/src/
    │   └── lib.rs                     ← NFT program (create, mint, transfer, burn)
    └── trident-tests/
        ├── fuzz_nft_transfer/
        │   └── test_fuzz.rs           ← Unauthorized transfer + burned NFT detection
        └── fuzz_nft_supply/
            └── test_fuzz.rs           ← Supply cap overflow detection
```

---

## Part 1: Fixing the Vault Program

The original vault program (`programs/fuzztooldemo/src/lib.rs`) contained five intentional
vulnerabilities from the "Fuzz on the Beach" taxonomy. Here is exactly what AI identified
and how each was fixed:

### Fix 1 — MSC (Missing Signer Check)
- **Vulnerable code:** `authority: UncheckedAccount<'info>` with only `require_keys_eq!`
- **Problem:** Checked key equality but never verified the authority actually *signed* the tx
- **Fix:** Changed to `authority: Signer<'info>` in the `MscUpdateWithdrawLimit` struct
- **Effect:** Anchor now rejects unsigned authority accounts at deserialization

### Fix 2 — MOC (Missing Owner Check)
- **Vulnerable code:** Read `policy_account.try_borrow_data()` and trusted `data[0] == 1` plus vault key reference, but never verified who owns the policy account
- **Problem:** Any account with the right byte pattern was accepted, regardless of who owns it — an attacker could craft a matching account
- **Fix:** Added `require_keys_eq!(*ctx.accounts.policy_account.owner, crate::id())`
- **Effect:** Only accounts owned by this program pass validation

### Fix 3 — ACPI (Arbitrary CPI)
- **Vulnerable code:** `invoke(&ix, ...)` with `plugin_program` unchecked
- **Problem:** Could CPI into any program (attacker-controlled code execution)
- **Fix:** Added `require_keys_eq!(plugin_program.key(), vault_state.trusted_plugin_program)`
- **Effect:** Only the trusted plugin program can be invoked

### Fix 4 — MKC (Missing Key Check)
- **Vulnerable code:** Read slot bytes from `clock_like` without pubkey validation
- **Problem:** Attacker could pass a spoofed account with fake slot data
- **Fix:** Added `require_keys_eq!(clock_like.key(), vault_state.trusted_clock_key)`
- **Effect:** Only the expected clock account is accepted

### Fix 5 — IB (Integer Bug)
- **Vulnerable code:** `wrapping_sub` / `wrapping_add` in `ib_lamport_transfer` for lamport moves
- **Problem:** Silent underflow/overflow of lamport balances (e.g., 5 - 10 wraps to u64::MAX - 4)
- **Fix:** Changed to `checked_sub` / `checked_add` with custom error variants
- **Effect:** Arithmetic violations return `ArithmeticUnderflow` / `ArithmeticOverflow`

**Expected demo result after fix:** All 5 fuzz targets should report `NO_FINDING`.

---

## Part 2: Additional Solana Design Patterns

### Escrow Program
A two-party atomic swap: Party A deposits token_a and requests token_b. Party B completes
the exchange by providing token_b and receiving token_a. The escrow enforces:
- Only the initializer can cancel
- Checked arithmetic on all balance mutations
- Active/inactive state prevents double-exchange

### AMM (Automated Market Maker) Program
A constant-product (x·y=k) liquidity pool supporting:
- Pool initialization with initial reserves
- Proportional liquidity add/remove with LP share tracking
- Token swaps with configurable fee (basis points) and slippage protection
- Post-swap invariant assertion (k must never decrease)

### NFT Minting Program
A collection-based NFT system supporting:
- Collection creation with max supply and mint price
- Sequential token ID minting with supply cap enforcement
- Owner-only transfer with burned-NFT rejection
- Burn with supply decrement

---

## Part 3: Trident Fuzz Test Harnesses

Each fuzz harness follows the same pattern as the original vault fuzz targets:

| Fuzz Target | Program | What It Tests | Finding Marker |
|---|---|---|---|
| `fuzz_escrow_exchange` | Escrow | Exchange correctness, double-exchange | `ESCROW finding:` |
| `fuzz_escrow_cancel` | Escrow | Unauthorized cancel (MSC) | `ESCROW-CANCEL finding:` |
| `fuzz_amm_swap` | AMM | k-invariant conservation | `AMM-SWAP finding:` |
| `fuzz_amm_liquidity` | AMM | Value extraction via add/remove | `AMM-LIQUIDITY finding:` |
| `fuzz_nft_transfer` | NFT | Unauthorized transfer, burned NFT | `NFT-TRANSFER finding:` |
| `fuzz_nft_supply` | NFT | Supply cap overflow, boundary mint | `NFT-SUPPLY finding:` |

All harnesses use exit code 99 and `"finding:"` markers compatible with the existing
`scripts/demo-trident-paths.sh` detection logic.

---

## How AI Was Used

1. **Vulnerability analysis:** AI read the vulnerable lib.rs and each fuzz harness,
   identified the exact vulnerability class and root cause for each of the 5 bugs.

2. **Automated fixing:** AI generated the patched lib.rs with precise fixes, each
   annotated with before/after comments explaining the security improvement.

3. **Design pattern implementation:** AI generated complete Anchor programs for
   Escrow, AMM, and NFT Minting following Solana best practices (Signer types,
   checked arithmetic, owner validation, PDA patterns).

4. **Fuzz harness generation:** AI generated Trident fuzz tests that follow the
   exact same architecture as the existing vault harnesses (FuzzTestMethods,
   flow_executor, set_anchor_account helper, env_u64 config, exit-99 finding).

5. **Cross-pattern security:** AI ensured each new program avoids all 5 vulnerability
   classes from the vault taxonomy, making them resistant to the same attack patterns.
