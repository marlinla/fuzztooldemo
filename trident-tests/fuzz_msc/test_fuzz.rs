use fuzz_tests::{
    env_u64, guided_demo_mode, record_finding, trace_path, vuln_roll_denom,
    ENV_FUZZ_FLOW_CALLS, ENV_FUZZ_ITERATIONS,
};
use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use anchor_lang::Discriminator;
use anchor_lang::AnchorSerialize;

#[derive(Default)]
struct AccountAddresses {
    vault_state: Pubkey,
    authority: Pubkey,
}

#[derive(FuzzTestMethods)]
struct MscFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl MscFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.vault_state = self.trident.random_pubkey();
        self.fuzz_accounts.authority = self.trident.random_pubkey();

        let state = fuzztooldemo::VaultState {
            authority: self.fuzz_accounts.authority,
            trusted_plugin_program: solana_sdk::system_program::id(),
            trusted_clock_key: solana_sdk::sysvar::clock::id(),
            withdraw_limit: 10,
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

        let authority_account =
            AccountSharedData::new(1_000_000, 0, &solana_sdk::system_program::id());
        self.trident
            .set_account_custom(&self.fuzz_accounts.authority, &authority_account);
    }

    #[flow]
    fn missing_signer_check_flow(&mut self) {
        let attempt_vulnerable = if guided_demo_mode() {
            // Demo mode: usually safe paths, with scheduled vulnerable attempts.
            self.trident.random_from_range(1u64..=vuln_roll_denom()) == 1
        } else {
            // Paper mode: no external scheduling; signer status is sampled directly.
            self.trident.random_from_range(0u8..=1u8) == 1
        };
        let should_sign_authority = !attempt_vulnerable;
        let new_limit = self.trident.random_from_range(11u64..=u64::MAX);
        trace_path(
            "fuzz_msc",
            &[
                ("attempt_vulnerable", attempt_vulnerable.to_string()),
                ("authority_should_sign", should_sign_authority.to_string()),
                ("new_limit", new_limit.to_string()),
            ],
        );

        let mut account_metas = fuzztooldemo::accounts::MscUpdateWithdrawLimit {
            vault_state: self.fuzz_accounts.vault_state,
            authority: self.fuzz_accounts.authority,
        }
        .to_account_metas(None);

        // Mutate signer metadata to emulate unauthorized caller.
        account_metas[1].is_signer = should_sign_authority;

        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: account_metas,
            data: fuzztooldemo::instruction::MscUpdateWithdrawLimit { new_limit }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("msc_update_withdraw_limit"));

        if !should_sign_authority && tx_result.is_success() {
            record_finding(
                "fuzz_msc",
                "non-signer authority updated withdraw_limit",
                &[
                    ("attempt_vulnerable", attempt_vulnerable.to_string()),
                    ("authority_should_sign", should_sign_authority.to_string()),
                    ("new_limit", new_limit.to_string()),
                ],
            );
            eprintln!(
                "MSC finding: non-signer authority updated withdraw_limit."
            );
            std::process::exit(99);
        }
    }
}

fn main() {
    MscFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 100),
        env_u64(ENV_FUZZ_FLOW_CALLS, 10),
    );
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
