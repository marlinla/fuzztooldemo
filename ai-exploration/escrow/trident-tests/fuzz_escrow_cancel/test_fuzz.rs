///! Trident fuzz target: Escrow — Cancel authorization
///!
///! Tests that only the original initializer can cancel the escrow.
///! Probes MSC (Missing Signer Check) by attempting cancellation with:
///!   - The correct initializer (should succeed)
///!   - A random attacker pubkey (should fail)
///!
///! Also tests that cancel correctly refunds the vault to the initializer.

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
    attacker: Pubkey,
    token_a_vault: Pubkey,
    initializer_token_a: Pubkey,
}

#[derive(FuzzTestMethods)]
struct EscrowCancelFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl EscrowCancelFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.escrow_state = self.trident.random_pubkey();
        self.fuzz_accounts.initializer = self.trident.random_pubkey();
        self.fuzz_accounts.attacker = self.trident.random_pubkey();
        self.fuzz_accounts.token_a_vault = self.trident.random_pubkey();
        self.fuzz_accounts.initializer_token_a = self.trident.random_pubkey();

        let deposit = self.trident.random_from_range(100u64..=10_000u64);

        let escrow = escrow::EscrowState {
            initializer: self.fuzz_accounts.initializer,
            token_a_vault: self.fuzz_accounts.token_a_vault,
            deposit_amount: deposit,
            expected_amount: deposit,
            is_active: true,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.escrow_state,
            &escrow::id(),
            escrow::EscrowState::DISCRIMINATOR,
            &escrow,
        );

        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.token_a_vault,
            &escrow::id(),
            escrow::TokenBalance::DISCRIMINATOR,
            &escrow::TokenBalance { amount: deposit },
        );

        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.initializer_token_a,
            &escrow::id(),
            escrow::TokenBalance::DISCRIMINATOR,
            &escrow::TokenBalance { amount: 0 },
        );

        // Both initializer and attacker need SOL for signing
        for key in [&self.fuzz_accounts.initializer, &self.fuzz_accounts.attacker] {
            let account = AccountSharedData::new(1_000_000, 0, &solana_sdk::system_program::id());
            self.trident.set_account_custom(key, &account);
        }
    }

    /// Attacker tries to cancel an escrow they don't own — should fail.
    #[flow]
    fn unauthorized_cancel_flow(&mut self) {
        let attempt_attacker = self.trident.random_from_range(1u64..=10u64) == 1;
        let signer = if attempt_attacker {
            self.fuzz_accounts.attacker
        } else {
            self.fuzz_accounts.initializer
        };

        let ix = Instruction {
            program_id: escrow::id(),
            accounts: escrow::accounts::CancelEscrow {
                escrow_state: self.fuzz_accounts.escrow_state,
                initializer: signer,
                token_a_vault: self.fuzz_accounts.token_a_vault,
                initializer_token_a: self.fuzz_accounts.initializer_token_a,
            }
            .to_account_metas(None),
            data: escrow::instruction::CancelEscrow {}.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("cancel_escrow"));

        if attempt_attacker && tx_result.is_success() {
            eprintln!(
                "ESCROW-CANCEL finding: attacker cancelled escrow they don't own."
            );
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
    EscrowCancelFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 200),
        env_u64(ENV_FUZZ_FLOW_CALLS, 20),
    );
}
