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
    treasury_vault: Pubkey,
    policy_account: Pubkey,
}

#[derive(FuzzTestMethods)]
struct MocFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl MocFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.vault_state = self.trident.random_pubkey();
        self.fuzz_accounts.treasury_vault = self.trident.random_pubkey();
        self.fuzz_accounts.policy_account = self.trident.random_pubkey();

        let state = fuzztooldemo::VaultState {
            authority: self.trident.random_pubkey(),
            trusted_plugin_program: self.trident.random_pubkey(),
            trusted_clock_key: solana_sdk::sysvar::clock::id(),
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
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.treasury_vault,
            &fuzztooldemo::id(),
            fuzztooldemo::VaultBalance::DISCRIMINATOR,
            &fuzztooldemo::VaultBalance { amount: 1_000_000 },
        );
    }

    #[flow]
    fn missing_owner_check_flow(&mut self) {
        let attempt_vulnerable = if guided_demo_mode() {
            // Demo mode: vulnerable owner/key-reference shape sampled on schedule.
            self.trident.random_from_range(1u64..=vuln_roll_denom()) == 1
        } else {
            // Paper mode: owner/key-reference decisions are sampled directly.
            self.trident.random_from_range(0u8..=1u8) == 1
        };
        let attacker_owned = attempt_vulnerable;
        let policy_owner = if attacker_owned {
            self.trident.random_pubkey()
        } else {
            fuzztooldemo::id()
        };

        let mut policy_data = vec![0u8; 33];
        policy_data[0] = 1;
        let referenced_vault_key = if attempt_vulnerable {
            self.fuzz_accounts.treasury_vault
        } else {
            self.trident.random_pubkey()
        };
        trace_path(
            "fuzz_moc",
            &[
                ("attempt_vulnerable", attempt_vulnerable.to_string()),
                ("attacker_owned_policy", attacker_owned.to_string()),
                ("references_treasury", (referenced_vault_key == self.fuzz_accounts.treasury_vault).to_string()),
            ],
        );
        policy_data[1..33].copy_from_slice(referenced_vault_key.as_ref());
        let mut policy_account = AccountSharedData::new(1_000_000, policy_data.len(), &policy_owner);
        policy_account.set_data_from_slice(&policy_data);
        self.trident
            .set_account_custom(&self.fuzz_accounts.policy_account, &policy_account);

        let new_secret = self.trident.random_from_range(0u64..=u64::MAX);
        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MocUpdatePolicySecret {
                vault_state: self.fuzz_accounts.vault_state,
                treasury_vault: self.fuzz_accounts.treasury_vault,
                policy_account: self.fuzz_accounts.policy_account,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MocUpdatePolicySecret { new_secret }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("moc_update_policy_secret"));
        if attacker_owned && referenced_vault_key == self.fuzz_accounts.treasury_vault && tx_result.is_success() {
            record_finding(
                "fuzz_moc",
                "attacker-owned policy data authorized treasury mutation",
                &[
                    ("attempt_vulnerable", attempt_vulnerable.to_string()),
                    ("attacker_owned_policy", attacker_owned.to_string()),
                    ("references_treasury", "true".to_string()),
                    ("new_secret", new_secret.to_string()),
                ],
            );
            eprintln!(
                "MOC finding: attacker-owned policy account data authorized treasury mutation."
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
    MocFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 400),
        env_u64(ENV_FUZZ_FLOW_CALLS, 50),
    );
}
