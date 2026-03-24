use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
#[cfg(target_os = "solana")]
use anchor_lang::solana_program::program::invoke;

declare_id!("DbKQRFejQdTXuvd8NDNVX8uXYNXWNHVnxJi3JyEJhXbN");

#[program]
pub mod fuzztooldemo {
    use super::*;

    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        trusted_plugin_program: Pubkey,
        trusted_clock_key: Pubkey,
    ) -> Result<()> {
        let state = &mut ctx.accounts.vault_state;
        state.authority = ctx.accounts.authority.key();
        state.trusted_plugin_program = trusted_plugin_program;
        state.trusted_clock_key = trusted_clock_key;
        state.withdraw_limit = 1_000_000;
        state.secret = 0;
        state.payout_count = 0;
        Ok(())
    }

    // Missing signer check: only key equality is checked, not signature.
    pub fn msc_update_withdraw_limit(
        ctx: Context<MscUpdateWithdrawLimit>,
        new_limit: u64,
    ) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.authority.key(),
            ctx.accounts.vault_state.authority,
            VaultDemoError::Unauthorized
        );
        ctx.accounts.vault_state.withdraw_limit = new_limit;
        Ok(())
    }

    // Missing owner check: trusts data from an arbitrary policy account.
    pub fn moc_update_policy_secret(
        ctx: Context<MocUpdatePolicySecret>,
        new_secret: u64,
    ) -> Result<()> {
        let policy_data = ctx.accounts.policy_account.try_borrow_data()?;
        require!(
            !policy_data.is_empty() && policy_data[0] == 1,
            VaultDemoError::PolicyNotTrusted
        );
        ctx.accounts.vault_state.secret = new_secret;
        Ok(())
    }

    // Arbitrary CPI in plugin payout: no check that plugin_program matches trusted_plugin_program.
    pub fn acpi_plugin_payout(
        ctx: Context<AcpiPluginPayout>,
        amount: u64,
        payload: Vec<u8>,
    ) -> Result<()> {
        ctx.accounts.treasury_vault.amount = ctx
            .accounts
            .treasury_vault
            .amount
            .saturating_sub(amount);
        let ix = Instruction {
            program_id: ctx.accounts.plugin_program.key(),
            accounts: vec![],
            data: payload,
        };
        #[cfg(target_os = "solana")]
        {
            invoke(&ix, &[ctx.accounts.plugin_program.to_account_info()])?;
            ctx.accounts.vault_state.payout_count =
                ctx.accounts.vault_state.payout_count.saturating_add(1);
            Ok(())
        }
        #[cfg(not(target_os = "solana"))]
        {
            // solana-program-test runs the program on the host; solana-invoke would panic here.
            let _ = ix;
            err!(VaultDemoError::CpiUnavailableOffChain)
        }
    }

    // Missing key check: uses a clock-like account without validating pubkey.
    pub fn mkc_clock_gate(ctx: Context<MkcClockGate>, min_slot: u64) -> Result<()> {
        let raw = ctx.accounts.clock_like.try_borrow_data()?;
        require!(raw.len() >= 8, VaultDemoError::BadClockData);
        let mut slot_bytes = [0u8; 8];
        slot_bytes.copy_from_slice(&raw[0..8]);
        let provided_slot = u64::from_le_bytes(slot_bytes);
        require!(provided_slot >= min_slot, VaultDemoError::SlotTooLow);

        ctx.accounts.vault_state.payout_count =
            ctx.accounts.vault_state.payout_count.saturating_add(1);
        Ok(())
    }

    // Integer bug in vault transfer: wrapping math can underflow/overflow.
    pub fn ib_internal_transfer(ctx: Context<IbInternalTransfer>, amount: u64) -> Result<()> {
        ctx.accounts.from_vault.amount = ctx.accounts.from_vault.amount.wrapping_sub(amount);
        ctx.accounts.to_vault.amount = ctx.accounts.to_vault.amount.wrapping_add(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(init, payer = payer, space = 8 + VaultState::SIZE)]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MscUpdateWithdrawLimit<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub authority: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MocUpdatePolicySecret<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub policy_account: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AcpiPluginPayout<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub treasury_vault: Account<'info, VaultBalance>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub plugin_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MkcClockGate<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    /// CHECK: Intentionally unchecked for vulnerability demo.
    pub clock_like: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct IbInternalTransfer<'info> {
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub from_vault: Account<'info, VaultBalance>,
    #[account(mut)]
    pub to_vault: Account<'info, VaultBalance>,
}

#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub trusted_plugin_program: Pubkey,
    pub trusted_clock_key: Pubkey,
    pub withdraw_limit: u64,
    pub secret: u64,
    pub payout_count: u64,
}

impl VaultState {
    pub const SIZE: usize = 32 + 32 + 32 + 8 + 8 + 8;
}

#[account]
pub struct VaultBalance {
    pub amount: u64,
}

#[error_code]
pub enum VaultDemoError {
    #[msg("Caller is not authorized.")]
    Unauthorized,
    #[msg("Policy account did not contain trusted marker.")]
    PolicyNotTrusted,
    #[msg("Clock-like account data was malformed.")]
    BadClockData,
    #[msg("Clock-like slot was below the required minimum.")]
    SlotTooLow,
    #[msg("CPI is only executable on-chain; host test runtimes cannot invoke.")]
    CpiUnavailableOffChain,
}
