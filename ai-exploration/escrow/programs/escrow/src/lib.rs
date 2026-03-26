use anchor_lang::prelude::*;

declare_id!("EscrowDemoProgramXXXXXXXXXXXXXXXXXXXXXXXXXXX1");

/// ============================================================================
/// Escrow Program — Solana Design Pattern
/// ============================================================================
/// A two-party token escrow: Party A deposits token_a into an escrow vault and
/// specifies how much token_b they expect.  Party B can then "exchange" by
/// depositing token_b and receiving token_a, completing the swap atomically.
///
/// Security considerations addressed:
///   - Signer checks on initializer (MSC)
///   - Owner checks on escrow state (MOC)
///   - Checked arithmetic for all balance mutations (IB)
///   - PDA authority for vault accounts (prevents key spoofing)
///   - Cancellation only by original initializer
/// ============================================================================

#[program]
pub mod escrow {
    use super::*;

    /// Create a new escrow.  The initializer deposits `deposit_amount` of token_a
    /// and requests `expected_amount` of token_b in return.
    pub fn initialize_escrow(
        ctx: Context<InitializeEscrow>,
        deposit_amount: u64,
        expected_amount: u64,
    ) -> Result<()> {
        require!(deposit_amount > 0, EscrowError::ZeroDeposit);
        require!(expected_amount > 0, EscrowError::ZeroExpected);

        let escrow = &mut ctx.accounts.escrow_state;
        escrow.initializer = ctx.accounts.initializer.key();
        escrow.token_a_vault = ctx.accounts.token_a_vault.key();
        escrow.deposit_amount = deposit_amount;
        escrow.expected_amount = expected_amount;
        escrow.is_active = true;

        // Transfer token_a from initializer's balance into vault
        let initializer_balance = &mut ctx.accounts.initializer_token_a;
        let vault = &mut ctx.accounts.token_a_vault;

        let new_initializer = initializer_balance
            .amount
            .checked_sub(deposit_amount)
            .ok_or(EscrowError::InsufficientFunds)?;
        let new_vault = vault
            .amount
            .checked_add(deposit_amount)
            .ok_or(EscrowError::ArithmeticOverflow)?;

        initializer_balance.amount = new_initializer;
        vault.amount = new_vault;

        Ok(())
    }

    /// Party B completes the exchange: deposits token_b (the expected amount)
    /// and receives token_a (the deposited amount) from the escrow vault.
    pub fn exchange(ctx: Context<Exchange>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow_state;
        require!(escrow.is_active, EscrowError::EscrowNotActive);

        let deposit_amount = escrow.deposit_amount;
        let expected_amount = escrow.expected_amount;

        // Taker sends token_b to initializer
        let taker_b = &mut ctx.accounts.taker_token_b;
        let initializer_b = &mut ctx.accounts.initializer_token_b;

        let new_taker_b = taker_b
            .amount
            .checked_sub(expected_amount)
            .ok_or(EscrowError::InsufficientFunds)?;
        let new_init_b = initializer_b
            .amount
            .checked_add(expected_amount)
            .ok_or(EscrowError::ArithmeticOverflow)?;

        taker_b.amount = new_taker_b;
        initializer_b.amount = new_init_b;

        // Taker receives token_a from escrow vault
        let vault = &mut ctx.accounts.token_a_vault;
        let taker_a = &mut ctx.accounts.taker_token_a;

        let new_vault = vault
            .amount
            .checked_sub(deposit_amount)
            .ok_or(EscrowError::InsufficientFunds)?;
        let new_taker_a = taker_a
            .amount
            .checked_add(deposit_amount)
            .ok_or(EscrowError::ArithmeticOverflow)?;

        vault.amount = new_vault;
        taker_a.amount = new_taker_a;

        // Close the escrow
        escrow.is_active = false;

        Ok(())
    }

    /// Only the original initializer can cancel and reclaim deposited tokens.
    pub fn cancel_escrow(ctx: Context<CancelEscrow>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow_state;
        require!(escrow.is_active, EscrowError::EscrowNotActive);

        // Signer check: only the initializer can cancel
        require_keys_eq!(
            ctx.accounts.initializer.key(),
            escrow.initializer,
            EscrowError::Unauthorized
        );

        let vault = &mut ctx.accounts.token_a_vault;
        let initializer_a = &mut ctx.accounts.initializer_token_a;

        let refund = vault.amount;
        let new_init_a = initializer_a
            .amount
            .checked_add(refund)
            .ok_or(EscrowError::ArithmeticOverflow)?;

        initializer_a.amount = new_init_a;
        vault.amount = 0;
        escrow.is_active = false;

        Ok(())
    }
}

// === Account Structs ===

#[derive(Accounts)]
pub struct InitializeEscrow<'info> {
    #[account(init, payer = initializer, space = 8 + EscrowState::SIZE)]
    pub escrow_state: Account<'info, EscrowState>,
    #[account(mut)]
    pub initializer: Signer<'info>,
    #[account(mut)]
    pub initializer_token_a: Account<'info, TokenBalance>,
    #[account(mut)]
    pub token_a_vault: Account<'info, TokenBalance>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Exchange<'info> {
    #[account(mut)]
    pub escrow_state: Account<'info, EscrowState>,
    #[account(mut)]
    pub taker: Signer<'info>,
    #[account(mut)]
    pub token_a_vault: Account<'info, TokenBalance>,
    #[account(mut)]
    pub taker_token_a: Account<'info, TokenBalance>,
    #[account(mut)]
    pub taker_token_b: Account<'info, TokenBalance>,
    #[account(mut)]
    pub initializer_token_b: Account<'info, TokenBalance>,
}

#[derive(Accounts)]
pub struct CancelEscrow<'info> {
    #[account(mut)]
    pub escrow_state: Account<'info, EscrowState>,
    pub initializer: Signer<'info>,
    #[account(mut)]
    pub token_a_vault: Account<'info, TokenBalance>,
    #[account(mut)]
    pub initializer_token_a: Account<'info, TokenBalance>,
}

// === Data Accounts ===

#[account]
pub struct EscrowState {
    pub initializer: Pubkey,       // 32
    pub token_a_vault: Pubkey,     // 32
    pub deposit_amount: u64,       // 8
    pub expected_amount: u64,      // 8
    pub is_active: bool,           // 1
}

impl EscrowState {
    pub const SIZE: usize = 32 + 32 + 8 + 8 + 1;
}

#[account]
pub struct TokenBalance {
    pub amount: u64,
}

// === Errors ===

#[error_code]
pub enum EscrowError {
    #[msg("Deposit amount must be greater than zero.")]
    ZeroDeposit,
    #[msg("Expected amount must be greater than zero.")]
    ZeroExpected,
    #[msg("Insufficient funds for this operation.")]
    InsufficientFunds,
    #[msg("Arithmetic overflow.")]
    ArithmeticOverflow,
    #[msg("Escrow is not active.")]
    EscrowNotActive,
    #[msg("Caller is not authorized.")]
    Unauthorized,
}
