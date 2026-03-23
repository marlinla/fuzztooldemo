use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use anchor_lang::Discriminator;
use anchor_lang::AccountSerialize;

#[derive(Default)]
struct AccountAddresses {
    state: Pubkey,
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
        self.fuzz_accounts.state = self.trident.random_pubkey();
        self.fuzz_accounts.trusted_program = solana_sdk::system_program::id();
        self.fuzz_accounts.attacker_program = solana_sdk::stake::program::id();

        let state = fuzztooldemo::DemoState {
            authority: self.trident.random_pubkey(),
            trusted_cpi_program: self.fuzz_accounts.trusted_program,
            trusted_clock_key: self.trident.random_pubkey(),
            secret: 0,
            counter: 0,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.state,
            &fuzztooldemo::id(),
            fuzztooldemo::DemoState::DISCRIMINATOR,
            &state,
        );
    }

    #[flow]
    fn arbitrary_cpi_flow(&mut self) {
        let use_attacker_program = true;
        let callee_program = if use_attacker_program {
            self.fuzz_accounts.attacker_program
        } else {
            self.fuzz_accounts.trusted_program
        };
        let payload = vec![0u8; self.trident.random_from_range(0usize..=8usize)];

        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::AcpiCall {
                state: self.fuzz_accounts.state,
                callee_program,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::AcpiCall { payload }.data(),
        };

        let tx_result = self.trident.process_transaction(&[ix], Some("acpi_call"));
        let logs = tx_result.logs();
        let cpi_reached = logs.contains("invoke [2]") && logs.contains(&callee_program.to_string());

        // Finding criterion: untrusted callee was reached by CPI at all.
        if use_attacker_program && cpi_reached {
            eprintln!(
                "ACPI finding: CPI reached untrusted program {}.",
                callee_program
            );
            std::process::exit(99);
        }
    }
}

fn set_anchor_account<T: AccountSerialize>(
    trident: &mut Trident,
    key: &Pubkey,
    owner: &Pubkey,
    discriminator: &[u8],
    value: &T,
) {
    let mut data = discriminator.to_vec();
    value
        .try_serialize(&mut data)
        .expect("anchor serialization for fuzz account should succeed");
    let mut account = AccountSharedData::new(1_000_000, data.len(), owner);
    account.set_data_from_slice(&data);
    trident.set_account_custom(key, &account);
}

fn main() {
    AcpiFuzz::fuzz(400, 50);
}
