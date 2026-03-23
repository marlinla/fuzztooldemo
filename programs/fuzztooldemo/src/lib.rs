use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke;

declare_id!("DbKQRFejQdTXuvd8NDNVX8uXYNXWNHVnxJi3JyEJhXbN");

#[program]
pub mod fuzztooldemo {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        trusted_cpi_program: Pubkey,
        trusted_clock_key: Pubkey,
    ) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.trusted_cpi_program = trusted_cpi_program;
        state.trusted_clock_key = trusted_clock_key;
        state.secret = 0;
        state.counter = 0;
        Ok(())
    }

    // Missing signer check: only key equality is checked, not signature.
    pub fn msc_set_secret(ctx: Context<MscSetSecret>, new_secret: u64) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.authority.key(),
            ctx.accounts.state.authority,
            DemoError::Unauthorized
        );
        ctx.accounts.state.secret = new_secret;
        Ok(())
    }

    // Minimal missing signer check demo for fuzzing bootstrap.
    pub fn msc_minimal(ctx: Context<MscMinimal>, marker: u8) -> Result<()> {
        let mut data = ctx.accounts.target.try_borrow_mut_data()?;
        if !data.is_empty() {
            data[0] = marker;
        }
        Ok(())
    }

    // Missing owner check: trusts data from an arbitrary account.
    pub fn moc_set_secret(ctx: Context<MocSetSecret>, new_secret: u64) -> Result<()> {
        let policy_data = ctx.accounts.policy_account.try_borrow_data()?;
        require!(
            !policy_data.is_empty() && policy_data[0] == 1,
            DemoError::PolicyNotTrusted
        );
        ctx.accounts.state.secret = new_secret;
        Ok(())
    }

    // Arbitrary CPI: no check that callee_program matches trusted_cpi_program.
    pub fn acpi_call(ctx: Context<AcpiCall>, payload: Vec<u8>) -> Result<()> {
        let ix = Instruction {
            program_id: ctx.accounts.callee_program.key(),
            accounts: vec![],
            data: payload,
        };
        invoke(&ix, &[ctx.accounts.callee_program.to_account_info()])?;
        Ok(())
    }

    // Missing key check: uses a clock-like account without validating pubkey.
    pub fn mkc_gate(ctx: Context<MkcGate>, min_slot: u64) -> Result<()> {
        let raw = ctx.accounts.clock_like.try_borrow_data()?;
        require!(raw.len() >= 8, DemoError::BadClockData);
        let mut slot_bytes = [0u8; 8];
        slot_bytes.copy_from_slice(&raw[0..8]);
        let provided_slot = u64::from_le_bytes(slot_bytes);
        require!(provided_slot >= min_slot, DemoError::SlotTooLow);

        ctx.accounts.state.counter = ctx.accounts.state.counter.saturating_add(1);
        Ok(())
    }

    // Integer bug: wrapping math can underflow/overflow.
    pub fn ib_transfer(ctx: Context<IbTransfer>, amount: u64) -> Result<()> {
        ctx.accounts.from_vault.amount = ctx.accounts.from_vault.amount.wrapping_sub(amount);
        ctx.accounts.to_vault.amount = ctx.accounts.to_vault.amount.wrapping_add(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + DemoState::SIZE)]
    pub state: Account<'info, DemoState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MscSetSecret<'info> {
    #[account(mut)]
    pub state: Account<'info, DemoState>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub authority: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MscMinimal<'info> {
    /// CHECK: Intentionally unchecked writable account for minimal demo.
    #[account(mut)]
    pub target: UncheckedAccount<'info>,
    /// CHECK: Intentionally unchecked and no signer requirement.
    pub authority: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MocSetSecret<'info> {
    #[account(mut)]
    pub state: Account<'info, DemoState>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub policy_account: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AcpiCall<'info> {
    #[account(mut)]
    pub state: Account<'info, DemoState>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub callee_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MkcGate<'info> {
    #[account(mut)]
    pub state: Account<'info, DemoState>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub clock_like: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct IbTransfer<'info> {
    pub state: Account<'info, DemoState>,
    #[account(mut)]
    pub from_vault: Account<'info, VaultBalance>,
    #[account(mut)]
    pub to_vault: Account<'info, VaultBalance>,
}

#[account]
pub struct DemoState {
    pub authority: Pubkey,
    pub trusted_cpi_program: Pubkey,
    pub trusted_clock_key: Pubkey,
    pub secret: u64,
    pub counter: u64,
}

impl DemoState {
    pub const SIZE: usize = 32 + 32 + 32 + 8 + 8;
}

#[account]
pub struct VaultBalance {
    pub amount: u64,
}

#[error_code]
pub enum DemoError {
    #[msg("Caller is not authorized.")]
    Unauthorized,
    #[msg("Policy account did not contain trusted marker.")]
    PolicyNotTrusted,
    #[msg("Clock-like account data was malformed.")]
    BadClockData,
    #[msg("Clock-like slot was below the required minimum.")]
    SlotTooLow,
}
