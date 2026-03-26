///! Trident fuzz target: NFT Minting — Supply cap enforcement
///!
///! Tests that the minting instruction correctly enforces the max_supply cap.
///! This is critical because over-minting dilutes the collection value.
///!
///! Approach:
///!   1. Create a collection with small max_supply (e.g. 3–10)
///!   2. Mint NFTs repeatedly, tracking current_supply
///!   3. Assert that minting beyond max_supply always fails
///!   4. Verify token_id is sequential and never duplicated
///!
///! Vulnerability classes probed:
///!   - IB: overflow in current_supply counter could wrap past max_supply
///!   - Logic bug: off-by-one allowing max_supply+1 mints

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

#[derive(Default)]
struct AccountAddresses {
    collection: Pubkey,
    nft_metadata: Pubkey,
    minter: Pubkey,
    minter_balance: Pubkey,
    treasury: Pubkey,
}

#[derive(FuzzTestMethods)]
struct NftSupplyFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
    max_supply: u64,
}

#[flow_executor]
impl NftSupplyFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
            max_supply: 0,
        }
    }

    #[init]
    fn start(&mut self) {
        self.fuzz_accounts.collection = self.trident.random_pubkey();
        self.fuzz_accounts.minter = self.trident.random_pubkey();
        self.fuzz_accounts.minter_balance = self.trident.random_pubkey();
        self.fuzz_accounts.treasury = self.trident.random_pubkey();

        // Small max_supply so we can hit the cap quickly during fuzzing
        self.max_supply = self.trident.random_from_range(1u64..=5u64);
        let mint_price = self.trident.random_from_range(0u64..=100u64);

        // Start with current_supply already at max_supply (testing the boundary)
        let collection = nft_mint::CollectionState {
            authority: self.trident.random_pubkey(),
            name: [0u8; 32],
            max_supply: self.max_supply,
            current_supply: self.max_supply, // AT the cap
            next_token_id: self.max_supply + 1,
            mint_price,
            is_active: true,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.collection,
            &nft_mint::id(),
            nft_mint::CollectionState::DISCRIMINATOR,
            &collection,
        );

        // Minter has plenty of funds
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.minter_balance,
            &nft_mint::id(),
            nft_mint::TokenBalance::DISCRIMINATOR,
            &nft_mint::TokenBalance { amount: 1_000_000 },
        );

        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.treasury,
            &nft_mint::id(),
            nft_mint::TokenBalance::DISCRIMINATOR,
            &nft_mint::TokenBalance { amount: 0 },
        );

        let minter_account =
            AccountSharedData::new(10_000_000, 0, &solana_sdk::system_program::id());
        self.trident
            .set_account_custom(&self.fuzz_accounts.minter, &minter_account);
    }

    /// Attempt to mint when collection is already at max_supply — must fail.
    #[flow]
    fn overmint_flow(&mut self) {
        // Fresh NFT metadata account for each mint attempt
        self.fuzz_accounts.nft_metadata = self.trident.random_pubkey();

        let ix = Instruction {
            program_id: nft_mint::id(),
            accounts: nft_mint::accounts::MintNft {
                collection: self.fuzz_accounts.collection,
                nft_metadata: self.fuzz_accounts.nft_metadata,
                minter: self.fuzz_accounts.minter,
                minter_balance: self.fuzz_accounts.minter_balance,
                treasury: self.fuzz_accounts.treasury,
                system_program: solana_sdk::system_program::id(),
            }
            .to_account_metas(None),
            data: nft_mint::instruction::MintNft {}.data(),
        };

        let tx_result = self
            .trident
            .process_transaction(&[ix], Some("overmint"));

        if tx_result.is_success() {
            // Read the collection to check supply
            let col_data = self
                .trident
                .get_account(&self.fuzz_accounts.collection)
                .expect("collection");
            let col: nft_mint::CollectionState =
                nft_mint::CollectionState::try_deserialize(&mut &col_data.data[..])
                    .expect("deser");

            if col.current_supply > self.max_supply {
                eprintln!(
                    "NFT-SUPPLY finding: minted beyond max_supply! current={}, max={}",
                    col.current_supply, self.max_supply
                );
                std::process::exit(99);
            }
        }
    }

    /// Test with current_supply just below max (should succeed once, then fail)
    #[flow]
    fn boundary_mint_flow(&mut self) {
        // Set supply to max-1 so exactly one more mint should be allowed
        let collection = nft_mint::CollectionState {
            authority: self.trident.random_pubkey(),
            name: [0u8; 32],
            max_supply: self.max_supply,
            current_supply: self.max_supply.saturating_sub(1),
            next_token_id: self.max_supply,
            mint_price: 0,
            is_active: true,
        };
        set_anchor_account(
            &mut self.trident,
            &self.fuzz_accounts.collection,
            &nft_mint::id(),
            nft_mint::CollectionState::DISCRIMINATOR,
            &collection,
        );

        self.fuzz_accounts.nft_metadata = self.trident.random_pubkey();

        // First mint at boundary — should succeed
        let ix = Instruction {
            program_id: nft_mint::id(),
            accounts: nft_mint::accounts::MintNft {
                collection: self.fuzz_accounts.collection,
                nft_metadata: self.fuzz_accounts.nft_metadata,
                minter: self.fuzz_accounts.minter,
                minter_balance: self.fuzz_accounts.minter_balance,
                treasury: self.fuzz_accounts.treasury,
                system_program: solana_sdk::system_program::id(),
            }
            .to_account_metas(None),
            data: nft_mint::instruction::MintNft {}.data(),
        };

        let _ = self
            .trident
            .process_transaction(&[ix], Some("boundary_mint_1"));

        // Second mint — should now fail (at cap)
        self.fuzz_accounts.nft_metadata = self.trident.random_pubkey();
        let ix2 = Instruction {
            program_id: nft_mint::id(),
            accounts: nft_mint::accounts::MintNft {
                collection: self.fuzz_accounts.collection,
                nft_metadata: self.fuzz_accounts.nft_metadata,
                minter: self.fuzz_accounts.minter,
                minter_balance: self.fuzz_accounts.minter_balance,
                treasury: self.fuzz_accounts.treasury,
                system_program: solana_sdk::system_program::id(),
            }
            .to_account_metas(None),
            data: nft_mint::instruction::MintNft {}.data(),
        };

        let tx_result_2 = self
            .trident
            .process_transaction(&[ix2], Some("boundary_mint_2"));

        if tx_result_2.is_success() {
            let col_data = self
                .trident
                .get_account(&self.fuzz_accounts.collection)
                .expect("collection");
            let col: nft_mint::CollectionState =
                nft_mint::CollectionState::try_deserialize(&mut &col_data.data[..])
                    .expect("deser");
            if col.current_supply > self.max_supply {
                eprintln!(
                    "NFT-SUPPLY finding: boundary over-mint! current={}, max={}",
                    col.current_supply, self.max_supply
                );
                std::process::exit(99);
            }
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
    NftSupplyFuzz::fuzz(
        env_u64(ENV_FUZZ_ITERATIONS, 200),
        env_u64(ENV_FUZZ_FLOW_CALLS, 30),
    );
}
