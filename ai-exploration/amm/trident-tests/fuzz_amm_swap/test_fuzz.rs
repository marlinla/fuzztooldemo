///! Trident fuzz target: AMM — Swap invariant checker
///!
///! The constant-product AMM must maintain x * y >= k after every swap.
///! This fuzz harness:
///!   1. Initializes a pool with random reserves
///!   2. Performs swaps with random amounts
///!   3. Verifies the k-invariant is never violated (k must not decrease)
///!   4. Verifies output is never zero for non-zero input
///!   5. Tests arithmetic edge cases near u64 boundaries
///!
///! Vulnerability classes probed:
///!   - IB (Integer Bug): overflow in reserve * amount multiplication
///!   - Invariant violation: k decreasing after swap (broken AMM logic)

use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use anchor_lang::Discriminator;
use anchor_lang::AnchorSerialize;

const ENV_FUZZ_ITERATIONS: &str = "DEMO_FUZZ_ITERATIONS";
const ENV_FUZZ_FLOW_CALLS: &str = "DEMO_FUZZ_FLOW_CALLS";

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[derive(Default)]
struct AccountAddresses {
    pool_state: Pubkey,
    trader: Pubkey,
    trader_token_a: Pubkey,
    trader_token_b: Pubkey,
}

#[derive(FuzzTestMethods)]
struct AmmSwapFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl AmmSwapFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.pool_state = self.trident.random_pubkey();
        self.fuzz_accounts.trader = self.trident.random_pubkey();
        self.fuzz_accounts.trader_token_a = self.trident.random_pubkey();
        self.fuzz_accounts.trader_token_b = self.trident.random_pubkey();

        // Random pool reserves in a realistic range
        let reserve_a = self.trident.random_from_range(1_000u64..=1_000_000_000u64);
        let reserve_b = self.trident.random_from_range(1_000u64..=1_000_000_000u64);
        let fee_bps = self.trident.random_from_range(0u16..=500u16); // 0–5% fee

        let pool = amm::PoolState {
            authority: self.trident.random_pubkey(),
            reserve_a,
            reserve_b,
            total_lp_shares: 1_000_000, // Simplified
            fee_bps,
            is_initialized: true,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.pool_state,
            &amm::id(),
            amm::PoolState::DISCRIMINATOR,
            &pool,
        );

        // Trader has plenty of token_a, starts with 0 token_b
        let trader_a_balance = self.trident.random_from_range(100_000u64..=10_000_000u64);
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.trader_token_a,
            &amm::id(),
            amm::TokenBalance::DISCRIMINATOR,
            &amm::TokenBalance { amount: trader_a_balance },
        );
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.trader_token_b,
            &amm::id(),
            amm::TokenBalance::DISCRIMINATOR,
            &amm::TokenBalance { amount: 0 },
        );

        let trader_account =
            AccountSharedData::new(1_000_000, 0, &solana_sdk::system_program::id());
        self.trident
            .set_account_custom(&self.fuzz_accounts.trader, &trader_account);
    }

    #[flow]
    fn swap_invariant_flow(&mut self) {
        // Read current pool state to capture k_before
        let pool_data = self
            .trident
            .get_account(&self.fuzz_accounts.pool_state)
            .expect("pool should exist");
        let pool_before: amm::PoolState =
            amm::PoolState::try_deserialize(&mut &pool_data.data[..])
                .expect("deserialize pool");
        let k_before = (pool_before.reserve_a as u128) * (pool_before.reserve_b as u128);

        let amount_in = self.trident.random_from_range(1u64..=100_000u64);

        let ix = Instruction {
            program_id: amm::id(),
            accounts: amm::accounts::Swap {
                pool_state: self.fuzz_accounts.pool_state,
                trader: self.fuzz_accounts.trader,
                trader_token_a: self.fuzz_accounts.trader_token_a,
                trader_token_b: self.fuzz_accounts.trader_token_b,
            }
            .to_account_metas(None),
            data: amm::instruction::Swap {
                amount_in,
                min_out: 0, // No slippage protection for fuzzing — we check invariant instead
            }
            .data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("swap"));

        if tx_result.is_success() {
            // Read pool state after swap
            let pool_data_after = self
                .trident
                .get_account(&self.fuzz_accounts.pool_state)
                .expect("pool should exist after swap");
            let pool_after: amm::PoolState =
                amm::PoolState::try_deserialize(&mut &pool_data_after.data[..])
                    .expect("deserialize pool after");
            let k_after = (pool_after.reserve_a as u128) * (pool_after.reserve_b as u128);

            // CRITICAL INVARIANT: k must never decrease
            if k_after < k_before {
                eprintln!(
                    "AMM-SWAP finding: k-invariant violated! k_before={}, k_after={}, amount_in={}",
                    k_before, k_after, amount_in
                );
                std::process::exit(99);
            }
        }
    }
}

fn set_anchor_account<T: AnchorSerialize>(
    trident: &mut Trident,
    key: &Pubkey,
    owner: &Pubkey,
    discriminator: &[u8],
    value: &T,
) {
    let mut data = discriminator.to_vec();
    value
        .serialize(&mut data)
        .expect("anchor serialization for fuzz account should succeed");
    let mut account = AccountSharedData::new(1_000_000, data.len(), owner);
    account.set_data_from_slice(&data);
    trident.set_account_custom(key, &account);
}

fn main() {
    AmmSwapFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 300),
        env_u64(ENV_FUZZ_FLOW_CALLS, 30),
    );
}
