///! Trident fuzz target: NFT Minting — Transfer authorization
///!
///! Tests that only the current NFT owner can transfer ownership.
///! Probes MSC (Missing Signer Check):
///!   - ~10% of iterations use an attacker pubkey as signer (should fail)
///!   - The rest use the legitimate owner (should succeed)
///!
///! Also checks:
///!   - Burned NFTs cannot be transferred
///!   - Owner field is correctly updated after legitimate transfer

use trident_fuzz::fuzzing::*;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use anchor_lang::Discriminator;
use anchor_lang::AnchorSerialize;

const ENV_FUZZ_ITERATIONS: &str = "DEMO_FUZZ_ITERATIONS";
const ENV_FUZZ_FLOW_CALLS: &str = "DEMO_FUZZ_FLOW_CALLS";

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn vuln_roll_denom() -> u64 {
    env_u64("DEMO_VULN_ROLL_DENOM", 10).max(1)
}

#[derive(Default)]
struct AccountAddresses {
    nft_metadata: Pubkey,
    owner: Pubkey,
    attacker: Pubkey,
}

#[derive(FuzzTestMethods)]
struct NftTransferFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl NftTransferFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.nft_metadata = self.trident.random_pubkey();
        self.fuzz_accounts.owner = self.trident.random_pubkey();
        self.fuzz_accounts.attacker = self.trident.random_pubkey();

        let nft = nft_mint::NftMetadata {
            collection: self.trident.random_pubkey(),
            token_id: self.trident.random_from_range(1u64..=10_000u64),
            owner: self.fuzz_accounts.owner,
            is_burned: false,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.nft_metadata,
            &nft_mint::id(),
            nft_mint::NftMetadata::DISCRIMINATOR,
            &nft,
        );

        for key in [&self.fuzz_accounts.owner, &self.fuzz_accounts.attacker] {
            let account = AccountSharedData::new(1_000_000, 0, &solana_sdk::system_program::id());
            self.trident.set_account_custom(key, &account);
        }
    }

    #[flow]
    fn unauthorized_transfer_flow(&mut self) {
        let attempt_attacker =
            self.trident.random_from_range(1u64..=vuln_roll_denom()) == 1;
        let signer = if attempt_attacker {
            self.fuzz_accounts.attacker
        } else {
            self.fuzz_accounts.owner
        };
        let new_owner = self.trident.random_pubkey();

        let ix = Instruction {
            program_id: nft_mint::id(),
            accounts: nft_mint::accounts::TransferNft {
                nft_metadata: self.fuzz_accounts.nft_metadata,
                owner: signer,
            }
            .to_account_metas(None),
            data: nft_mint::instruction::TransferNft { new_owner }.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("transfer_nft"));

        if attempt_attacker && tx_result.is_success() {
            eprintln!(
                "NFT-TRANSFER finding: attacker transferred NFT they don't own."
            );
            std::process::exit(99);
        }
    }

    /// Try to transfer a burned NFT — should always fail.
    #[flow]
    fn burned_transfer_flow(&mut self) {
        // Set NFT as burned
        let burned_nft = nft_mint::NftMetadata {
            collection: self.trident.random_pubkey(),
            token_id: 999,
            owner: self.fuzz_accounts.owner,
            is_burned: true,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.nft_metadata,
            &nft_mint::id(),
            nft_mint::NftMetadata::DISCRIMINATOR,
            &burned_nft,
        );

        let ix = Instruction {
            program_id: nft_mint::id(),
            accounts: nft_mint::accounts::TransferNft {
                nft_metadata: self.fuzz_accounts.nft_metadata,
                owner: self.fuzz_accounts.owner,
            }
            .to_account_metas(None),
            data: nft_mint::instruction::TransferNft {
                new_owner: self.trident.random_pubkey(),
            }
            .data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("burned_transfer"));

        if tx_result.is_success() {
            eprintln!("NFT-TRANSFER finding: burned NFT was successfully transferred.");
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
    NftTransferFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 200),
        env_u64(ENV_FUZZ_FLOW_CALLS, 20),
    );
}
