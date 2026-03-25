//! Scaffold only: copy into a real Anchor program crate before compiling.
//! The example models a minimal escrow with a deliberately unsafe release path.

use anchor_lang::prelude::*;

declare_id!("Escrow1111111111111111111111111111111111111");

#[program]
pub mod escrow_mini {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        beneficiary: Pubkey,
    ) -> Result<()> {
        let state = &mut ctx.accounts.escrow_state;
        state.authority = ctx.accounts.authority.key();
        state.beneficiary = beneficiary;
        state.amount = 0;
        Ok(())
    }

    // Intentionally vulnerable sketch:
    // Missing signer check on `authority`.
    pub fn release_unchecked(
        ctx: Context<ReleaseUnchecked>,
        amount: u64,
    ) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.authority.key(),
            ctx.accounts.escrow_state.authority,
            EscrowError::Unauthorized
        );
        ctx.accounts.escrow_state.amount = ctx.accounts.escrow_state.amount.saturating_sub(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + EscrowState::SIZE)]
    pub escrow_state: Account<'info, EscrowState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ReleaseUnchecked<'info> {
    #[account(mut)]
    pub escrow_state: Account<'info, EscrowState>,
    /// CHECK: intentionally unchecked in scaffold.
    pub authority: UncheckedAccount<'info>,
}

#[account]
pub struct EscrowState {
    pub authority: Pubkey,
    pub beneficiary: Pubkey,
    pub amount: u64,
}

impl EscrowState {
    pub const SIZE: usize = 32 + 32 + 8;
}

#[error_code]
pub enum EscrowError {
    #[msg("Caller is not authorized.")]
    Unauthorized,
}
