use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use anchor_lang::Discriminator;
use anchor_lang::AccountSerialize;

#[derive(Default)]
struct AccountAddresses {
    state: Pubkey,
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
        self.fuzz_accounts.state = self.trident.random_pubkey();
        self.fuzz_accounts.policy_account = self.trident.random_pubkey();

        let state = fuzztooldemo::DemoState {
            authority: self.trident.random_pubkey(),
            trusted_cpi_program: self.trident.random_pubkey(),
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
    fn missing_owner_check_flow(&mut self) {
        let attacker_owned = true;
        let policy_owner = if attacker_owned {
            self.trident.random_pubkey()
        } else {
            fuzztooldemo::id()
        };

        let mut policy_data = vec![0u8; 8];
        policy_data[0] = 1;
        policy_data[1..8].copy_from_slice(
            &self
                .trident
                .random_from_range(0u64..=u64::MAX)
                .to_le_bytes()[..7],
        );
        let mut policy_account = AccountSharedData::new(1_000_000, policy_data.len(), &policy_owner);
        policy_account.set_data_from_slice(&policy_data);
        self.trident
            .set_account_custom(&self.fuzz_accounts.policy_account, &policy_account);

        let new_secret = self.trident.random_from_range(0u64..=u64::MAX);
        let ix = Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MocSetSecret {
                state: self.fuzz_accounts.state,
                policy_account: self.fuzz_accounts.policy_account,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MocSetSecret { new_secret }.data(),
        };

        let tx_result = self.trident.process_transaction(&[ix], Some("moc_set_secret"));
        if attacker_owned && tx_result.is_success() {
            eprintln!(
                "MOC finding: attacker-owned policy account accepted for state update."
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
    MocFuzz::fuzz(400, 50);
}
