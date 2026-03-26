use anchor_lang::prelude::*;

declare_id!("NftMintDemoProgramXXXXXXXXXXXXXXXXXXXXXXXXX1");

/// ============================================================================
/// NFT Minting Program — Solana Design Pattern
/// ============================================================================
/// A simplified NFT collection manager:
///   1. create_collection  — authority creates a collection with max supply
///   2. mint_nft           — mint a new NFT from the collection (pays mint_price)
///   3. transfer_nft       — transfer ownership of an NFT between holders
///   4. burn_nft           — owner destroys their NFT, reducing current supply
///
/// Security considerations addressed:
///   - Signer checks: only collection authority can create; owner must sign transfers
///   - Owner checks: NFT metadata must be owned by this program
///   - Checked arithmetic: supply counters, price payments
///   - Supply cap enforcement: cannot mint beyond max_supply
///   - Duplicate mint prevention: token_id uniqueness via sequential counter
/// ============================================================================

#[program]
pub mod nft_mint {
    use super::*;

    /// Create a new NFT collection. The signer becomes the collection authority.
    pub fn create_collection(
        ctx: Context<CreateCollection>,
        name: [u8; 32],
        max_supply: u64,
        mint_price: u64,
    ) -> Result<()> {
        require!(max_supply > 0, NftError::ZeroSupply);

        let collection = &mut ctx.accounts.collection;
        collection.authority = ctx.accounts.authority.key();
        collection.name = name;
        collection.max_supply = max_supply;
        collection.current_supply = 0;
        collection.next_token_id = 1;
        collection.mint_price = mint_price;
        collection.is_active = true;

        Ok(())
    }

    /// Mint a new NFT from the collection. The minter pays mint_price to the
    /// collection authority's treasury and receives a new NftMetadata account.
    pub fn mint_nft(ctx: Context<MintNft>) -> Result<()> {
        let collection = &mut ctx.accounts.collection;
        require!(collection.is_active, NftError::CollectionNotActive);
        require!(
            collection.current_supply < collection.max_supply,
            NftError::MaxSupplyReached
        );

        let mint_price = collection.mint_price;

        // Payment: minter pays treasury
        if mint_price > 0 {
            let minter_balance = &mut ctx.accounts.minter_balance;
            let treasury = &mut ctx.accounts.treasury;

            minter_balance.amount = minter_balance
                .amount
                .checked_sub(mint_price)
                .ok_or(NftError::InsufficientFunds)?;
            treasury.amount = treasury
                .amount
                .checked_add(mint_price)
                .ok_or(NftError::ArithmeticOverflow)?;
        }

        // Assign NFT metadata
        let nft = &mut ctx.accounts.nft_metadata;
        nft.collection = collection.key();
        nft.token_id = collection.next_token_id;
        nft.owner = ctx.accounts.minter.key();
        nft.is_burned = false;

        // Update collection counters
        collection.current_supply = collection
            .current_supply
            .checked_add(1)
            .ok_or(NftError::ArithmeticOverflow)?;
        collection.next_token_id = collection
            .next_token_id
            .checked_add(1)
            .ok_or(NftError::ArithmeticOverflow)?;

        Ok(())
    }

    /// Transfer an NFT to a new owner. Only the current owner can transfer.
    pub fn transfer_nft(ctx: Context<TransferNft>, new_owner: Pubkey) -> Result<()> {
        let nft = &mut ctx.accounts.nft_metadata;
        require!(!nft.is_burned, NftError::NftBurned);

        // Signer must be current owner
        require_keys_eq!(
            ctx.accounts.owner.key(),
            nft.owner,
            NftError::Unauthorized
        );

        nft.owner = new_owner;
        Ok(())
    }

    /// Burn an NFT. Only the current owner can burn. Decrements collection supply.
    pub fn burn_nft(ctx: Context<BurnNft>) -> Result<()> {
        let nft = &mut ctx.accounts.nft_metadata;
        require!(!nft.is_burned, NftError::NftBurned);

        // Signer must be current owner
        require_keys_eq!(
            ctx.accounts.owner.key(),
            nft.owner,
            NftError::Unauthorized
        );

        nft.is_burned = true;

        let collection = &mut ctx.accounts.collection;
        collection.current_supply = collection
            .current_supply
            .checked_sub(1)
            .ok_or(NftError::ArithmeticOverflow)?;

        Ok(())
    }
}

// === Account Contexts ===

#[derive(Accounts)]
pub struct CreateCollection<'info> {
    #[account(init, payer = authority, space = 8 + CollectionState::SIZE)]
    pub collection: Account<'info, CollectionState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MintNft<'info> {
    #[account(mut)]
    pub collection: Account<'info, CollectionState>,
    #[account(init, payer = minter, space = 8 + NftMetadata::SIZE)]
    pub nft_metadata: Account<'info, NftMetadata>,
    #[account(mut)]
    pub minter: Signer<'info>,
    #[account(mut)]
    pub minter_balance: Account<'info, TokenBalance>,
    #[account(mut)]
    pub treasury: Account<'info, TokenBalance>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferNft<'info> {
    #[account(mut)]
    pub nft_metadata: Account<'info, NftMetadata>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct BurnNft<'info> {
    #[account(mut)]
    pub nft_metadata: Account<'info, NftMetadata>,
    #[account(mut)]
    pub collection: Account<'info, CollectionState>,
    pub owner: Signer<'info>,
}

// === Data Accounts ===

#[account]
pub struct CollectionState {
    pub authority: Pubkey,         // 32
    pub name: [u8; 32],           // 32
    pub max_supply: u64,          // 8
    pub current_supply: u64,      // 8
    pub next_token_id: u64,       // 8
    pub mint_price: u64,          // 8
    pub is_active: bool,          // 1
}

impl CollectionState {
    pub const SIZE: usize = 32 + 32 + 8 + 8 + 8 + 8 + 1;
}

#[account]
pub struct NftMetadata {
    pub collection: Pubkey,        // 32
    pub token_id: u64,            // 8
    pub owner: Pubkey,            // 32
    pub is_burned: bool,          // 1
}

impl NftMetadata {
    pub const SIZE: usize = 32 + 8 + 32 + 1;
}

#[account]
pub struct TokenBalance {
    pub amount: u64,
}

// === Errors ===

#[error_code]
pub enum NftError {
    #[msg("Max supply must be greater than zero.")]
    ZeroSupply,
    #[msg("Collection is not active.")]
    CollectionNotActive,
    #[msg("Maximum supply has been reached.")]
    MaxSupplyReached,
    #[msg("Insufficient funds for minting.")]
    InsufficientFunds,
    #[msg("Arithmetic overflow.")]
    ArithmeticOverflow,
    #[msg("Caller is not authorized.")]
    Unauthorized,
    #[msg("NFT has already been burned.")]
    NftBurned,
}
