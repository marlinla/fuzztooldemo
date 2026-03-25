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
    trusted_program: Pubkey,
    attacker_program: Pubkey,
}

#[derive(FuzzTestMethods)]
struct AcpiFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl AcpiFuzz {
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
        self.fuzz_accounts.trusted_program = solana_sdk::system_program::id();
        self.fuzz_accounts.attacker_program = solana_sdk::stake::program::id();

        let state = fuzztooldemo::VaultState {
            authority: self.trident.random_pubkey(),
            trusted_plugin_program: self.fuzz_accounts.trusted_program,
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

        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.treasury_vault,
            &fuzztooldemo::id(),
            fuzztooldemo::VaultBalance::DISCRIMINATOR,
            &fuzztooldemo::VaultBalance { amount: 1_000_000 },
        );
    }

    #[flow]
    fn arbitrary_cpi_flow(&mut self) {
        let attempt_vulnerable = if guided_demo_mode() {
            self.trident.random_from_range(1u64..=vuln_roll_denom()) == 1
        } else {
            self.trident.random_from_range(0u8..=1u8) == 1
        };
        let use_attacker_program = attempt_vulnerable;
        let callee_program = if use_attacker_program {
            self.fuzz_accounts.attacker_program
        } else {
            self.fuzz_accounts.trusted_program
        };
        let payload = vec![0u8; self.trident.random_from_range(0usize..=8usize)];
        let payload_len = payload.len();
        let amount = self.trident.random_from_range(1u64..=5_000u64);
        trace_path(
            "fuzz_acpi",
            &[
                ("attempt_vulnerable", attempt_vulnerable.to_string()),
                ("uses_attacker_program", use_attacker_program.to_string()),
                ("amount", amount.to_string()),
                ("payload_len", payload_len.to_string()),
            ],
        );

        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::AcpiPluginPayout {
                vault_state: self.fuzz_accounts.vault_state,
                treasury_vault: self.fuzz_accounts.treasury_vault,
                plugin_program: callee_program,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::AcpiPluginPayout { amount, payload }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("acpi_plugin_payout"));
        let logs = tx_result.logs();
        let cpi_reached = logs.contains("invoke [2]") && logs.contains(&callee_program.to_string());

        // Finding criterion: untrusted callee was reached by CPI at all.
        if use_attacker_program && cpi_reached {
            record_finding(
                "fuzz_acpi",
                "plugin payout invoked untrusted program",
                &[
                    ("attempt_vulnerable", attempt_vulnerable.to_string()),
                    ("uses_attacker_program", use_attacker_program.to_string()),
                    ("callee_program", callee_program.to_string()),
                    ("amount", amount.to_string()),
                    ("payload_len", payload_len.to_string()),
                ],
            );
            eprintln!(
                "ACPI finding: plugin payout invoked untrusted program {}.",
                callee_program
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
    AcpiFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 400),
        env_u64(ENV_FUZZ_FLOW_CALLS, 50),
    );
}
