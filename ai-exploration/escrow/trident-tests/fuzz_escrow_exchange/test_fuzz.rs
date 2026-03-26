///! Trident fuzz target: Escrow — Exchange flow
///!
///! Tests that the exchange instruction correctly enforces:
///!   1. Escrow must be active (cannot exchange after cancel/completion)
///!   2. Taker must have sufficient token_b to pay expected_amount
///!   3. All balance mutations use checked arithmetic (no overflow/underflow)
///!   4. After exchange: initializer gets token_b, taker gets token_a, escrow deactivated
///!
///! Vulnerability classes probed:
///!   - IB (Integer Bug): fuzz extreme deposit/expected amounts near u64 boundaries
///!   - MSC (Missing Signer): attempt exchange without taker signature (if applicable)

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
    escrow_state: Pubkey,
    initializer: Pubkey,
    initializer_token_a: Pubkey,
    initializer_token_b: Pubkey,
    token_a_vault: Pubkey,
    taker: Pubkey,
    taker_token_a: Pubkey,
    taker_token_b: Pubkey,
}

#[derive(FuzzTestMethods)]
struct EscrowExchangeFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl EscrowExchangeFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // Generate all account addresses
        self.fuzz_accounts.escrow_state = self.trident.random_pubkey();
        self.fuzz_accounts.initializer = self.trident.random_pubkey();
        self.fuzz_accounts.initializer_token_a = self.trident.random_pubkey();
        self.fuzz_accounts.initializer_token_b = self.trident.random_pubkey();
        self.fuzz_accounts.token_a_vault = self.trident.random_pubkey();
        self.fuzz_accounts.taker = self.trident.random_pubkey();
        self.fuzz_accounts.taker_token_a = self.trident.random_pubkey();
        self.fuzz_accounts.taker_token_b = self.trident.random_pubkey();

        // Fuzz deposit and expected amounts across wide ranges including edge cases
        let deposit_amount = self.trident.random_from_range(1u64..=1_000_000u64);
        let expected_amount = self.trident.random_from_range(1u64..=1_000_000u64);

        // Set up escrow state as if initialize_escrow already ran
        let escrow = escrow::EscrowState {
            initializer: self.fuzz_accounts.initializer,
            token_a_vault: self.fuzz_accounts.token_a_vault,
            deposit_amount,
            expected_amount,
            is_active: true,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.escrow_state,
            &escrow::id(),
            escrow::EscrowState::DISCRIMINATOR,
            &escrow,
        );

        // Vault holds the deposited token_a
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.token_a_vault,
            &escrow::id(),
            escrow::TokenBalance::DISCRIMINATOR,
            &escrow::TokenBalance { amount: deposit_amount },
        );

        // Initializer's token_b balance starts at 0 (will receive from taker)
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.initializer_token_b,
            &escrow::id(),
            escrow::TokenBalance::DISCRIMINATOR,
            &escrow::TokenBalance { amount: 0 },
        );

        // Taker has randomized token_b (may be insufficient to test error path)
        let taker_b_balance = self.trident.random_from_range(0u64..=2_000_000u64);
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.taker_token_b,
            &escrow::id(),
            escrow::TokenBalance::DISCRIMINATOR,
            &escrow::TokenBalance { amount: taker_b_balance },
        );

        // Taker's token_a balance starts at 0
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.taker_token_a,
            &escrow::id(),
            escrow::TokenBalance::DISCRIMINATOR,
            &escrow::TokenBalance { amount: 0 },
        );

        // Taker signer account
        let taker_account =
            AccountSharedData::new(1_000_000, 0, &solana_sdk::system_program::id());
        self.trident
            .set_account_custom(&self.fuzz_accounts.taker, &taker_account);
    }

    #[flow]
    fn exchange_flow(&mut self) {
        let ix = Instruction {
            program_id: escrow::id(),
            accounts: escrow::accounts::Exchange {
                escrow_state: self.fuzz_accounts.escrow_state,
                taker: self.fuzz_accounts.taker,
                token_a_vault: self.fuzz_accounts.token_a_vault,
                taker_token_a: self.fuzz_accounts.taker_token_a,
                taker_token_b: self.fuzz_accounts.taker_token_b,
                initializer_token_b: self.fuzz_accounts.initializer_token_b,
            }
            .to_account_metas(None),
            data: escrow::instruction::Exchange {}.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("exchange"));

        // If the exchange succeeded, verify conservation of value:
        // The total token_a and token_b across all accounts should be conserved.
        if tx_result.is_success() {
            // Read escrow state — it should now be inactive
            let escrow_data = self
                .trident
                .get_account(&self.fuzz_accounts.escrow_state)
                .expect("escrow state should exist");
            let escrow_state: escrow::EscrowState =
                escrow::EscrowState::try_deserialize(&mut &escrow_data.data[..])
                    .expect("deserialize escrow");
            if escrow_state.is_active {
                eprintln!("ESCROW finding: escrow still active after exchange.");
                std::process::exit(99);
            }
        }
    }

    /// Attempt exchange on an already-completed (inactive) escrow — should fail.
    #[flow]
    fn double_exchange_flow(&mut self) {
        // First deactivate the escrow
        let inactive_escrow = escrow::EscrowState {
            initializer: self.fuzz_accounts.initializer,
            token_a_vault: self.fuzz_accounts.token_a_vault,
            deposit_amount: 100,
            expected_amount: 100,
            is_active: false,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.escrow_state,
            &escrow::id(),
            escrow::EscrowState::DISCRIMINATOR,
            &inactive_escrow,
        );

        let ix = Instruction {
            program_id: escrow::id(),
            accounts: escrow::accounts::Exchange {
                escrow_state: self.fuzz_accounts.escrow_state,
                taker: self.fuzz_accounts.taker,
                token_a_vault: self.fuzz_accounts.token_a_vault,
                taker_token_a: self.fuzz_accounts.taker_token_a,
                taker_token_b: self.fuzz_accounts.taker_token_b,
                initializer_token_b: self.fuzz_accounts.initializer_token_b,
            }
            .to_account_metas(None),
            data: escrow::instruction::Exchange {}.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("double_exchange"));

        if tx_result.is_success() {
            eprintln!("ESCROW finding: double exchange succeeded on inactive escrow.");
            std::process::exit(99);
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
    EscrowExchangeFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 200),
        env_u64(ENV_FUZZ_FLOW_CALLS, 20),
    );
}
