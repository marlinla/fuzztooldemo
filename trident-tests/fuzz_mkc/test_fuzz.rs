use fuzz_tests::{env_u64, vuln_roll_denom, ENV_FUZZ_FLOW_CALLS, ENV_FUZZ_ITERATIONS};
use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use anchor_lang::Discriminator;
use anchor_lang::AnchorSerialize;

#[derive(Default)]
struct AccountAddresses {
    vault_state: Pubkey,
    spoofed_clock_like: Pubkey,
}

#[derive(FuzzTestMethods)]
struct MkcFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl MkcFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.vault_state = self.trident.random_pubkey();
        self.fuzz_accounts.spoofed_clock_like = self.trident.random_pubkey();

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

        // Spoofed account carries attacker-chosen slot bytes.
        let mut raw_clock_data = vec![0u8; 8];
        raw_clock_data.copy_from_slice(&u64::MAX.to_le_bytes());
        let mut spoofed_clock =
            AccountSharedData::new(1_000_000, raw_clock_data.len(), &solana_sdk::system_program::id());
        spoofed_clock.set_data_from_slice(&raw_clock_data);
        self.trident
            .set_account_custom(&self.fuzz_accounts.spoofed_clock_like, &spoofed_clock);
    }

    #[flow]
    fn missing_key_check_flow(&mut self) {
        let min_slot = self.trident.random_from_range(1u64..=u64::MAX / 2);
        let provided_slot = self
            .trident
            .random_from_range(min_slot..=u64::MAX);

        // ~10% of iterations use a spoofed clock-like account (vulnerable path). The rest use the real
        // Clock sysvar with valid slot data — success is expected and is not an MKC finding.
        let attempt_vulnerable =
            self.trident.random_from_range(1u64..=vuln_roll_denom()) == 1;
        let clock_like = if attempt_vulnerable {
            self.fuzz_accounts.spoofed_clock_like
        } else {
            solana_sdk::sysvar::clock::id()
        };

        let mut clock_data = vec![0u8; 8];
        clock_data.copy_from_slice(&provided_slot.to_le_bytes());
        let clock_owner = if attempt_vulnerable {
            &solana_sdk::system_program::id()
        } else {
            &solana_sdk::sysvar::id()
        };
        let mut clock_account = AccountSharedData::new(1_000_000, clock_data.len(), clock_owner);
        clock_account.set_data_from_slice(&clock_data);
        self.trident.set_account_custom(&clock_like, &clock_account);

        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MkcClockGate {
                vault_state: self.fuzz_accounts.vault_state,
                clock_like,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MkcClockGate { min_slot }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("mkc_clock_gate"));
        if attempt_vulnerable && tx_result.is_success() {
            eprintln!(
                "MKC finding: spoofed non-sysvar clock accepted for vault gate (slot={}, min_slot={}).",
                provided_slot, min_slot
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
    MkcFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 400),
        env_u64(ENV_FUZZ_FLOW_CALLS, 50),
    );
}
