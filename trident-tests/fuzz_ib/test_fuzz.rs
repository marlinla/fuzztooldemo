use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use anchor_lang::Discriminator;
use anchor_lang::AnchorSerialize;

#[derive(Default)]
struct AccountAddresses {
    vault_state: Pubkey,
    from_vault: Pubkey,
    to_vault: Pubkey,
}

#[derive(FuzzTestMethods)]
struct IbFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl IbFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.vault_state = self.trident.random_pubkey();
        self.fuzz_accounts.from_vault = self.trident.random_pubkey();
        self.fuzz_accounts.to_vault = self.trident.random_pubkey();

        let state = fuzztooldemo::VaultState {
            authority: self.trident.random_pubkey(),
            trusted_plugin_program: self.trident.random_pubkey(),
            trusted_clock_key: self.trident.random_pubkey(),
            withdraw_limit: 100,
            secret: 0,
            payout_count: 0,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.vault_state,
            &fuzztooldemo::id(),
            fuzztooldemo::VaultState::DISCRIMINATOR,
            &state,
        );

        let from_vault = fuzztooldemo::VaultBalance {
            amount: self.trident.random_from_range(0u64..=100u64),
        };
        let to_vault = fuzztooldemo::VaultBalance {
            amount: self
                .trident
                .random_from_range((u64::MAX - 100u64)..=u64::MAX),
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.from_vault,
            &fuzztooldemo::id(),
            fuzztooldemo::VaultBalance::DISCRIMINATOR,
            &from_vault,
        );
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.to_vault,
            &fuzztooldemo::id(),
            fuzztooldemo::VaultBalance::DISCRIMINATOR,
            &to_vault,
        );
    }

    #[flow]
    fn integer_bug_flow(&mut self) {
        let from_initial = self.trident.random_from_range(0u64..=100u64);
        let to_initial = self
            .trident
            .random_from_range((u64::MAX - 100u64)..=u64::MAX);
        let amount = self.trident.random_from_range(0u64..=u64::MAX);

        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.from_vault,
            &fuzztooldemo::id(),
            fuzztooldemo::VaultBalance::DISCRIMINATOR,
            &fuzztooldemo::VaultBalance {
                amount: from_initial,
            },
        );
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.to_vault,
            &fuzztooldemo::id(),
            fuzztooldemo::VaultBalance::DISCRIMINATOR,
            &fuzztooldemo::VaultBalance { amount: to_initial },
        );

        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::IbInternalTransfer {
                vault_state: self.fuzz_accounts.vault_state,
                from_vault: self.fuzz_accounts.from_vault,
                to_vault: self.fuzz_accounts.to_vault,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::IbInternalTransfer { amount }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("ib_internal_transfer"));
        let underflow_path = amount > from_initial;
        let overflow_path = to_initial.checked_add(amount).is_none();

        if tx_result.is_success() && (underflow_path || overflow_path) {
            eprintln!(
                "IB finding: wrapping internal vault transfer accepted (from={}, to={}, amount={}).",
                from_initial, to_initial, amount
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
    IbFuzz::fuzz(400, 50);
}
