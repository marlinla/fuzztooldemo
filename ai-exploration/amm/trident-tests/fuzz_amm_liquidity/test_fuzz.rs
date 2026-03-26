///! Trident fuzz target: AMM — Liquidity add/remove conservation
///!
///! Tests that adding and removing liquidity conserves total token value:
///!   1. Add liquidity → reserves increase, LP shares minted
///!   2. Remove liquidity → reserves decrease, LP shares burned
///!   3. After full removal, provider should get back approximately what they put in
///!
///! Vulnerability classes probed:
///!   - IB: overflow in share calculations (especially with large reserves)
///!   - Value extraction: remove more tokens than deposited (rounding exploits)

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
    provider: Pubkey,
    provider_token_a: Pubkey,
    provider_token_b: Pubkey,
    provider_lp: Pubkey,
}

#[derive(FuzzTestMethods)]
struct AmmLiquidityFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl AmmLiquidityFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.pool_state = self.trident.random_pubkey();
        self.fuzz_accounts.provider = self.trident.random_pubkey();
        self.fuzz_accounts.provider_token_a = self.trident.random_pubkey();
        self.fuzz_accounts.provider_token_b = self.trident.random_pubkey();
        self.fuzz_accounts.provider_lp = self.trident.random_pubkey();

        let reserve_a = self.trident.random_from_range(10_000u64..=100_000_000u64);
        let reserve_b = self.trident.random_from_range(10_000u64..=100_000_000u64);
        let total_lp = self.trident.random_from_range(1_000u64..=10_000_000u64);

        let pool = amm::PoolState {
            authority: self.trident.random_pubkey(),
            reserve_a,
            reserve_b,
            total_lp_shares: total_lp,
            fee_bps: 30, // 0.3%
            is_initialized: true,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.pool_state,
            &amm::id(),
            amm::PoolState::DISCRIMINATOR,
            &pool,
        );

        // Provider has tokens to add
        let provider_a = self.trident.random_from_range(1_000u64..=10_000_000u64);
        let provider_b = self.trident.random_from_range(1_000u64..=10_000_000u64);
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.provider_token_a,
            &amm::id(),
            amm::TokenBalance::DISCRIMINATOR,
            &amm::TokenBalance { amount: provider_a },
        );
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.provider_token_b,
            &amm::id(),
            amm::TokenBalance::DISCRIMINATOR,
            &amm::TokenBalance { amount: provider_b },
        );
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.provider_lp,
            &amm::id(),
            amm::TokenBalance::DISCRIMINATOR,
            &amm::TokenBalance { amount: 0 },
        );

        let provider_account =
            AccountSharedData::new(1_000_000, 0, &solana_sdk::system_program::id());
        self.trident
            .set_account_custom(&self.fuzz_accounts.provider, &provider_account);
    }

    #[flow]
    fn add_then_remove_flow(&mut self) {
        let amount_a = self.trident.random_from_range(1u64..=100_000u64);
        let amount_b = self.trident.random_from_range(1u64..=100_000u64);

        // Record total value before
        let pool_before = self
            .trident
            .get_account(&self.fuzz_accounts.pool_state)
            .expect("pool");
        let pool_state_before: amm::PoolState =
            amm::PoolState::try_deserialize(&mut &pool_before.data[..]).expect("deser");
        let total_a_before = pool_state_before.reserve_a;
        let total_b_before = pool_state_before.reserve_b;

        // Add liquidity
        let add_ix = Instruction {
            program_id: amm::id(),
            accounts: amm::accounts::AddLiquidity {
                pool_state: self.fuzz_accounts.pool_state,
                provider: self.fuzz_accounts.provider,
                provider_token_a: self.fuzz_accounts.provider_token_a,
                provider_token_b: self.fuzz_accounts.provider_token_b,
                provider_lp: self.fuzz_accounts.provider_lp,
            }
            .to_account_metas(None),
            data: amm::instruction::AddLiquidity { amount_a, amount_b }.data(),
        };

        let add_result = self
            .trident
            .process_transaction(&[add_ix], Some("add_liquidity"));

        if add_result.is_success() {
            // Check LP shares were minted
            let lp_data = self
                .trident
                .get_account(&self.fuzz_accounts.provider_lp)
                .expect("lp");
            let lp_balance: amm::TokenBalance =
                amm::TokenBalance::try_deserialize(&mut &lp_data.data[..]).expect("deser");

            if lp_balance.amount == 0 {
                eprintln!("AMM-LIQUIDITY finding: add_liquidity succeeded but no LP shares minted.");
                std::process::exit(99);
            }

            // Now remove the shares we just got
            let remove_ix = Instruction {
                program_id: amm::id(),
                accounts: amm::accounts::RemoveLiquidity {
                    pool_state: self.fuzz_accounts.pool_state,
                    provider: self.fuzz_accounts.provider,
                    provider_token_a: self.fuzz_accounts.provider_token_a,
                    provider_token_b: self.fuzz_accounts.provider_token_b,
                    provider_lp: self.fuzz_accounts.provider_lp,
                }
                .to_account_metas(None),
                data: amm::instruction::RemoveLiquidity {
                    lp_shares: lp_balance.amount,
                }
                .data(),
            };

            let remove_result = self
                .trident
                .process_transaction(&[remove_ix], Some("remove_liquidity"));

            if remove_result.is_success() {
                // After remove, pool reserves should not have grown beyond what was added
                let pool_after = self
                    .trident
                    .get_account(&self.fuzz_accounts.pool_state)
                    .expect("pool");
                let pool_state_after: amm::PoolState =
                    amm::PoolState::try_deserialize(&mut &pool_after.data[..]).expect("deser");

                // Reserves should be back near original (within rounding)
                // If reserves dropped below original, value was extracted
                if pool_state_after.reserve_a + 1 < total_a_before
                    || pool_state_after.reserve_b + 1 < total_b_before
                {
                    eprintln!(
                        "AMM-LIQUIDITY finding: value extraction detected. \
                         reserve_a: {} -> {}, reserve_b: {} -> {}",
                        total_a_before, pool_state_after.reserve_a,
                        total_b_before, pool_state_after.reserve_b,
                    );
                    std::process::exit(99);
                }
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
    AmmLiquidityFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 200),
        env_u64(ENV_FUZZ_FLOW_CALLS, 20),
    );
}
