use trident_fuzz::fuzzing::*;
use anchor_lang::ToAccountMetas;
use anchor_lang::InstructionData;

#[derive(Default)]
struct AccountAddresses {
    target: Pubkey,
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
        self.fuzz_accounts.target = self.trident.random_pubkey();
        self.fuzz_accounts.authority = self.trident.random_pubkey();

        let target_data = vec![0u8; 8];
        let mut target_account =
            AccountSharedData::new(1_000_000, target_data.len(), &fuzztooldemo::id());
        target_account.set_data_from_slice(&target_data);
        self.trident
            .set_account_custom(&self.fuzz_accounts.target, &target_account);

        let authority_account =
            AccountSharedData::new(1_000_000, 0, &solana_sdk::system_program::id());
        self.trident
            .set_account_custom(&self.fuzz_accounts.authority, &authority_account);
    }

    #[flow]
    fn missing_signer_check_flow(&mut self) {
        let should_sign_authority = false;
        let marker = self.trident.random_from_range(1u8..=u8::MAX);

        let mut account_metas = fuzztooldemo::accounts::MscMinimal {
            target: self.fuzz_accounts.target,
            authority: self.fuzz_accounts.authority,
        }
        .to_account_metas(None);

        // Mutate signer metadata to emulate unauthorized caller.
        account_metas[1].is_signer = should_sign_authority;

        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: account_metas,
            data: fuzztooldemo::instruction::MscMinimal { marker }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("msc_minimal"));

        if !should_sign_authority && tx_result.is_success() {
            eprintln!(
                "MSC finding: non-signer authority call succeeded (seeded run should reject this)."
            );
            std::process::exit(99);
        }
    }
}

fn main() {
    MscFuzz::fuzz(100, 10);
}
