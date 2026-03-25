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
    from_wallet: Pubkey,
    to_wallet: Pubkey,
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
        self.fuzz_accounts.from_wallet = self.trident.random_pubkey();
        self.fuzz_accounts.to_wallet = self.trident.random_pubkey();

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

        let from_wallet = AccountSharedData::new(
            self.trident.random_from_range(2_000_000u64..=3_000_000u64),
            0,
            &fuzztooldemo::id(),
        );
        let to_wallet = AccountSharedData::new(
            self.trident.random_from_range(2_000_000u64..=3_000_000u64),
            0,
            &fuzztooldemo::id(),
        );
        self.trident
            .set_account_custom(&self.fuzz_accounts.from_wallet, &from_wallet);
        self.trident
            .set_account_custom(&self.fuzz_accounts.to_wallet, &to_wallet);
    }

    #[flow]
    fn integer_bug_flow(&mut self) {
        let attempt_vulnerable = if guided_demo_mode() {
            // Demo mode: schedule wraparound-friendly input shapes.
            self.trident.random_from_range(1u64..=vuln_roll_denom()) == 1
        } else {
            // Paper mode: sample shape directly, without scheduled vulnerability attempts.
            self.trident.random_from_range(0u8..=1u8) == 1
        };
        let (from_initial, to_initial, amount) = if attempt_vulnerable {
            let delta_to_max = self.trident.random_from_range(0u64..=5u64);
            let to_initial = u64::MAX - delta_to_max;
            let amount = self
                .trident
                .random_from_range((delta_to_max + 1)..=(delta_to_max + 100));
            let from_initial = self
                .trident
                .random_from_range((amount + 2_000_000)..=(amount + 3_000_000));
            (from_initial, to_initial, amount)
        } else {
            let from_initial = self.trident.random_from_range(2_000_000u64..=3_000_000u64);
            let to_initial = self.trident.random_from_range(2_000_000u64..=3_000_000u64);
            let amount = self.trident.random_from_range(0u64..=from_initial);
            (from_initial, to_initial, amount)
        };
        trace_path(
            "fuzz_ib",
            &[
                ("attempt_vulnerable", attempt_vulnerable.to_string()),
                ("from_initial", from_initial.to_string()),
                ("to_initial", to_initial.to_string()),
                ("amount", amount.to_string()),
            ],
        );

        let from_wallet = AccountSharedData::new(from_initial, 0, &fuzztooldemo::id());
        let to_wallet = AccountSharedData::new(to_initial, 0, &fuzztooldemo::id());
        self.trident
            .set_account_custom(&self.fuzz_accounts.from_wallet, &from_wallet);
        self.trident
            .set_account_custom(&self.fuzz_accounts.to_wallet, &to_wallet);

        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::IbLamportTransfer {
                vault_state: self.fuzz_accounts.vault_state,
                from_wallet: self.fuzz_accounts.from_wallet,
                to_wallet: self.fuzz_accounts.to_wallet,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::IbLamportTransfer { amount }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("ib_lamport_transfer"));
        let overflow_path = to_initial.checked_add(amount).is_none();
        let program_success_log = format!("Program {} success", fuzztooldemo::id());
        let reached_buggy_write = tx_result.logs().contains(&program_success_log);

        if attempt_vulnerable && overflow_path && reached_buggy_write {
            record_finding(
                "fuzz_ib",
                "wrapping lamport transfer path reached",
                &[
                    ("attempt_vulnerable", attempt_vulnerable.to_string()),
                    ("overflow_path", overflow_path.to_string()),
                    ("from_initial", from_initial.to_string()),
                    ("to_initial", to_initial.to_string()),
                    ("amount", amount.to_string()),
                ],
            );
            eprintln!(
                "IB finding: wrapping lamport transfer path reached (from={}, to={}, amount={}).",
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
    IbFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 400),
        env_u64(ENV_FUZZ_FLOW_CALLS, 50),
    );
}
