//! Scaffold only: copy into trident-tests as a new fuzz binary before compiling.

use fuzz_tests::{
    env_u64, guided_demo_mode, record_finding, trace_path, vuln_roll_denom,
    ENV_FUZZ_FLOW_CALLS, ENV_FUZZ_ITERATIONS,
};
use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;

#[derive(Default)]
struct AccountAddresses {
    escrow_state: Pubkey,
    authority: Pubkey,
}

#[derive(FuzzTestMethods)]
struct EscrowMiniFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl EscrowMiniFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // TODO: seed escrow state account and authority account.
        self.fuzz_accounts.escrow_state = self.trident.random_pubkey();
        self.fuzz_accounts.authority = self.trident.random_pubkey();
    }

    #[flow]
    fn release_path_flow(&mut self) {
        let attempt_vulnerable = if guided_demo_mode() {
            self.trident.random_from_range(1u64..=vuln_roll_denom()) == 1
        } else {
            self.trident.random_from_range(0u8..=1u8) == 1
        };
        let should_sign_authority = !attempt_vulnerable;
        let amount = self.trident.random_from_range(1u64..=100u64);

        trace_path(
            "fuzz_escrow_mini",
            &[
                ("attempt_vulnerable", attempt_vulnerable.to_string()),
                ("authority_should_sign", should_sign_authority.to_string()),
                ("amount", amount.to_string()),
            ],
        );

        // TODO: replace with real accounts/instruction after integration.
        let ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: Vec::<u8>::new(),
        };
        let tx_result = self.trident.process_transaction(&[ix], Some("release_unchecked"));

        if !should_sign_authority && tx_result.is_success() {
            record_finding(
                "fuzz_escrow_mini",
                "non-signer authority released escrow funds",
                &[
                    ("attempt_vulnerable", attempt_vulnerable.to_string()),
                    ("authority_should_sign", should_sign_authority.to_string()),
                    ("amount", amount.to_string()),
                ],
            );
            eprintln!("ESCROW finding: non-signer authority released escrow funds.");
            std::process::exit(99);
        }
    }
}

fn main() {
    EscrowMiniFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 200),
        env_u64(ENV_FUZZ_FLOW_CALLS, 25),
    );
}
