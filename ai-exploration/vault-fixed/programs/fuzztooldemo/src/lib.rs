use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
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

    // ── FIX (MSC) ───────────────────────────────────────────────
    // BEFORE: authority was `UncheckedAccount` — only key equality was checked,
    //         but the runtime never verified that the account actually signed.
    // AFTER:  authority is `Signer<'info>` — Anchor enforces that the account
    //         signed the transaction at deserialization time.
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

    // ── FIX (MOC) ───────────────────────────────────────────────
    // BEFORE: policy_account was accepted without verifying its owner program,
    //         so an attacker could pass an account they own with faked data.
    // AFTER:  We check that policy_account.owner == this program's ID before
    //         trusting its data.
    pub fn moc_update_policy_secret(
        ctx: Context<MocUpdatePolicySecret>,
        new_secret: u64,
    ) -> Result<()> {
        // FIX: Verify the policy account is actually owned by this program
        require_keys_eq!(
            *ctx.accounts.policy_account.owner,
            crate::id(),
            VaultDemoError::PolicyNotTrusted
        );
        let policy_data = ctx.accounts.policy_account.try_borrow_data()?;
        require!(
            policy_data.len() >= 33 && policy_data[0] == 1,
            VaultDemoError::PolicyNotTrusted
        );
        let referenced_vault = read_policy_vault_key(&policy_data)?;
        require_keys_eq!(
            referenced_vault,
            ctx.accounts.treasury_vault.key(),
            VaultDemoError::PolicyTargetMismatch
        );
        ctx.accounts.treasury_vault.amount = ctx.accounts.treasury_vault.amount.saturating_sub(1);
        ctx.accounts.vault_state.secret = new_secret;
        Ok(())
    }

    // ── FIX (ACPI) ──────────────────────────────────────────────
    // BEFORE: Any program could be invoked via CPI without checking it
    //         matches the trusted_plugin_program stored in vault state.
    // AFTER:  We enforce that plugin_program.key() == vault_state.trusted_plugin_program
    //         before allowing the CPI call.
    pub fn acpi_plugin_payout(
        ctx: Context<AcpiPluginPayout>,
        amount: u64,
        payload: Vec<u8>,
    ) -> Result<()> {
        // FIX: Validate the plugin program matches the trusted one
        require_keys_eq!(
            ctx.accounts.plugin_program.key(),
            ctx.accounts.vault_state.trusted_plugin_program,
            VaultDemoError::Unauthorized
        );
        ctx.accounts.treasury_vault.amount = ctx
            .accounts
            .treasury_vault
            .amount
            .saturating_sub(amount);
        let ix = Instruction {
            program_id: ctx.accounts.plugin_program.key(),
            accounts: vec![AccountMeta::new(ctx.accounts.treasury_vault.key(), false)],
            data: payload,
        };
        #[cfg(target_os = "solana")]
        {
            invoke(
                &ix,
                &[
                    ctx.accounts.plugin_program.to_account_info(),
                    ctx.accounts.treasury_vault.to_account_info(),
                ],
            )?;
            ctx.accounts.vault_state.payout_count =
                ctx.accounts.vault_state.payout_count.saturating_add(1);
            Ok(())
        }
        #[cfg(not(target_os = "solana"))]
        {
            let _ = ix;
            err!(VaultDemoError::CpiUnavailableOffChain)
        }
    }

    // ── FIX (MKC) ───────────────────────────────────────────────
    // BEFORE: The clock_like account's public key was never validated against
    //         the trusted_clock_key stored in vault state.
    // AFTER:  We enforce clock_like.key() == vault_state.trusted_clock_key
    //         before reading any data from the account.
    pub fn mkc_clock_gate(ctx: Context<MkcClockGate>, min_slot: u64) -> Result<()> {
        let expected_clock_key = ctx.accounts.vault_state.trusted_clock_key;
        let provided_clock_key = ctx.accounts.clock_like.key();
        // FIX: Enforce the key check before trusting the account data
        require_keys_eq!(
            provided_clock_key,
            expected_clock_key,
            VaultDemoError::BadClockData
        );
        let provided_slot = load_slot_sysvar_like(&ctx.accounts.clock_like.to_account_info())?;
        require!(provided_slot >= min_slot, VaultDemoError::SlotTooLow);

        ctx.accounts.vault_state.payout_count =
            ctx.accounts.vault_state.payout_count.saturating_add(1);
        Ok(())
    }

    // ── FIX (IB) ────────────────────────────────────────────────
    // BEFORE: wrapping_sub/wrapping_add allowed silent underflow/overflow
    //         of lamport balances.
    // AFTER:  checked_sub/checked_add return None on overflow, and we
    //         propagate an error instead of silently wrapping.
    pub fn ib_lamport_transfer(ctx: Context<IbLamportTransfer>, amount: u64) -> Result<()> {
        let from_before = ctx.accounts.from_wallet.lamports();
        let to_before = ctx.accounts.to_wallet.lamports();
        // FIX: Use checked arithmetic instead of wrapping
        let from_after = from_before
            .checked_sub(amount)
            .ok_or(VaultDemoError::ArithmeticUnderflow)?;
        let to_after = to_before
            .checked_add(amount)
            .ok_or(VaultDemoError::ArithmeticOverflow)?;
        **ctx.accounts.from_wallet.try_borrow_mut_lamports()? = from_after;
        **ctx.accounts.to_wallet.try_borrow_mut_lamports()? = to_after;
        Ok(())
    }
}

// Keep the public helper for compatibility with tests that reference it directly.
pub fn ib_wrap_lamports(from_before: u64, to_before: u64, amount: u64) -> (u64, u64) {
    (
        from_before.wrapping_sub(amount),
        to_before.wrapping_add(amount),
    )
}

fn load_slot_sysvar_like(clock_like: &AccountInfo) -> Result<u64> {
    let raw = clock_like.try_borrow_data()?;
    require!(raw.len() >= 8, VaultDemoError::BadClockData);
    let mut slot_bytes = [0u8; 8];
    slot_bytes.copy_from_slice(&raw[0..8]);
    Ok(u64::from_le_bytes(slot_bytes))
}

fn read_policy_vault_key(policy_data: &[u8]) -> Result<Pubkey> {
    require!(policy_data.len() >= 33, VaultDemoError::PolicyNotTrusted);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&policy_data[1..33]);
    Ok(Pubkey::new_from_array(key_bytes))
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
    // FIX: Changed from UncheckedAccount to Signer
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct MocUpdatePolicySecret<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub treasury_vault: Account<'info, VaultBalance>,
    /// CHECK: Owner is validated in instruction body (FIX: added owner check).
    pub policy_account: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AcpiPluginPayout<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub treasury_vault: Account<'info, VaultBalance>,
    /// CHECK: Key is validated against trusted_plugin_program in instruction body.
    pub plugin_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MkcClockGate<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    /// CHECK: Key is validated against trusted_clock_key in instruction body.
    pub clock_like: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct IbLamportTransfer<'info> {
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    /// CHECK: Intentionally unchecked — same as vulnerable version.
    pub from_wallet: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: Intentionally unchecked — same as vulnerable version.
    pub to_wallet: UncheckedAccount<'info>,
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
    #[msg("Policy account did not target the provided treasury account.")]
    PolicyTargetMismatch,
    #[msg("Clock-like account data was malformed.")]
    BadClockData,
    #[msg("Clock-like slot was below the required minimum.")]
    SlotTooLow,
    #[msg("CPI is only executable on-chain; host test runtimes cannot invoke.")]
    CpiUnavailableOffChain,
    #[msg("Arithmetic underflow detected.")]
    ArithmeticUnderflow,
    #[msg("Arithmetic overflow detected.")]
    ArithmeticOverflow,
}
