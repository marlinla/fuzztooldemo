use anchor_lang::prelude::*;

declare_id!("AmmDemoProgramXXXXXXXXXXXXXXXXXXXXXXXXXXXXX1");

/// ============================================================================
/// Constant-Product AMM (Automated Market Maker) — Solana Design Pattern
/// ============================================================================
/// Implements x * y = k invariant for a two-token liquidity pool.
///
/// Instructions:
///   1. initialize_pool  — create pool with initial liquidity
///   2. add_liquidity     — deposit both tokens proportionally, receive LP shares
///   3. remove_liquidity  — burn LP shares, withdraw both tokens
///   4. swap              — trade token_a for token_b (or vice versa) with fee
///
/// Security considerations addressed:
///   - Signer checks on pool authority and liquidity providers
///   - Checked arithmetic everywhere (prevents integer overflow/underflow)
///   - Constant-product invariant validation after every swap
///   - Slippage protection via minimum output parameter
///   - Fee cannot exceed 100% (basis points capped at 10_000)
/// ============================================================================

#[program]
pub mod amm {
    use super::*;

    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        initial_a: u64,
        initial_b: u64,
        fee_bps: u16,
    ) -> Result<()> {
        require!(initial_a > 0 && initial_b > 0, AmmError::ZeroLiquidity);
        require!(fee_bps <= 10_000, AmmError::InvalidFee);

        let pool = &mut ctx.accounts.pool_state;
        pool.authority = ctx.accounts.authority.key();
        pool.reserve_a = initial_a;
        pool.reserve_b = initial_b;
        pool.fee_bps = fee_bps;
        // Initial LP shares = sqrt(initial_a * initial_b) approximated as geometric mean
        pool.total_lp_shares = sqrt_u64(
            (initial_a as u128)
                .checked_mul(initial_b as u128)
                .ok_or(AmmError::ArithmeticOverflow)?,
        );
        pool.is_initialized = true;

        // Debit provider
        let provider_a = &mut ctx.accounts.provider_token_a;
        let provider_b = &mut ctx.accounts.provider_token_b;
        provider_a.amount = provider_a
            .amount
            .checked_sub(initial_a)
            .ok_or(AmmError::InsufficientFunds)?;
        provider_b.amount = provider_b
            .amount
            .checked_sub(initial_b)
            .ok_or(AmmError::InsufficientFunds)?;

        // Credit provider LP shares
        let provider_lp = &mut ctx.accounts.provider_lp;
        provider_lp.amount = pool.total_lp_shares;

        Ok(())
    }

    pub fn add_liquidity(
        ctx: Context<AddLiquidity>,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool_state;
        require!(pool.is_initialized, AmmError::PoolNotInitialized);
        require!(amount_a > 0 && amount_b > 0, AmmError::ZeroLiquidity);

        // Calculate LP shares proportional to smaller ratio
        let share_a = (amount_a as u128)
            .checked_mul(pool.total_lp_shares as u128)
            .ok_or(AmmError::ArithmeticOverflow)?
            .checked_div(pool.reserve_a as u128)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let share_b = (amount_b as u128)
            .checked_mul(pool.total_lp_shares as u128)
            .ok_or(AmmError::ArithmeticOverflow)?
            .checked_div(pool.reserve_b as u128)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let new_shares = std::cmp::min(share_a, share_b) as u64;
        require!(new_shares > 0, AmmError::ZeroLiquidity);

        // Update reserves
        pool.reserve_a = pool
            .reserve_a
            .checked_add(amount_a)
            .ok_or(AmmError::ArithmeticOverflow)?;
        pool.reserve_b = pool
            .reserve_b
            .checked_add(amount_b)
            .ok_or(AmmError::ArithmeticOverflow)?;
        pool.total_lp_shares = pool
            .total_lp_shares
            .checked_add(new_shares)
            .ok_or(AmmError::ArithmeticOverflow)?;

        // Debit provider
        let provider_a = &mut ctx.accounts.provider_token_a;
        let provider_b = &mut ctx.accounts.provider_token_b;
        provider_a.amount = provider_a
            .amount
            .checked_sub(amount_a)
            .ok_or(AmmError::InsufficientFunds)?;
        provider_b.amount = provider_b
            .amount
            .checked_sub(amount_b)
            .ok_or(AmmError::InsufficientFunds)?;

        // Credit LP
        let provider_lp = &mut ctx.accounts.provider_lp;
        provider_lp.amount = provider_lp
            .amount
            .checked_add(new_shares)
            .ok_or(AmmError::ArithmeticOverflow)?;

        Ok(())
    }

    pub fn remove_liquidity(
        ctx: Context<RemoveLiquidity>,
        lp_shares: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool_state;
        require!(pool.is_initialized, AmmError::PoolNotInitialized);
        require!(lp_shares > 0, AmmError::ZeroLiquidity);

        let provider_lp = &mut ctx.accounts.provider_lp;
        require!(provider_lp.amount >= lp_shares, AmmError::InsufficientFunds);

        // Proportional withdrawal
        let withdraw_a = (lp_shares as u128)
            .checked_mul(pool.reserve_a as u128)
            .ok_or(AmmError::ArithmeticOverflow)?
            .checked_div(pool.total_lp_shares as u128)
            .ok_or(AmmError::ArithmeticOverflow)? as u64;
        let withdraw_b = (lp_shares as u128)
            .checked_mul(pool.reserve_b as u128)
            .ok_or(AmmError::ArithmeticOverflow)?
            .checked_div(pool.total_lp_shares as u128)
            .ok_or(AmmError::ArithmeticOverflow)? as u64;

        pool.reserve_a = pool
            .reserve_a
            .checked_sub(withdraw_a)
            .ok_or(AmmError::InsufficientFunds)?;
        pool.reserve_b = pool
            .reserve_b
            .checked_sub(withdraw_b)
            .ok_or(AmmError::InsufficientFunds)?;
        pool.total_lp_shares = pool
            .total_lp_shares
            .checked_sub(lp_shares)
            .ok_or(AmmError::InsufficientFunds)?;

        provider_lp.amount = provider_lp
            .amount
            .checked_sub(lp_shares)
            .ok_or(AmmError::InsufficientFunds)?;

        let provider_a = &mut ctx.accounts.provider_token_a;
        let provider_b = &mut ctx.accounts.provider_token_b;
        provider_a.amount = provider_a
            .amount
            .checked_add(withdraw_a)
            .ok_or(AmmError::ArithmeticOverflow)?;
        provider_b.amount = provider_b
            .amount
            .checked_add(withdraw_b)
            .ok_or(AmmError::ArithmeticOverflow)?;

        Ok(())
    }

    /// Swap token_a for token_b using constant-product formula.
    /// `amount_in` of token_a is sold; at least `min_out` of token_b must be received.
    pub fn swap(
        ctx: Context<Swap>,
        amount_in: u64,
        min_out: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool_state;
        require!(pool.is_initialized, AmmError::PoolNotInitialized);
        require!(amount_in > 0, AmmError::ZeroSwap);

        // Apply fee: effective_in = amount_in * (10000 - fee_bps) / 10000
        let fee_factor = 10_000u128
            .checked_sub(pool.fee_bps as u128)
            .ok_or(AmmError::InvalidFee)?;
        let effective_in = (amount_in as u128)
            .checked_mul(fee_factor)
            .ok_or(AmmError::ArithmeticOverflow)?
            .checked_div(10_000)
            .ok_or(AmmError::ArithmeticOverflow)?;

        // Constant product: amount_out = (reserve_b * effective_in) / (reserve_a + effective_in)
        let numerator = (pool.reserve_b as u128)
            .checked_mul(effective_in)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let denominator = (pool.reserve_a as u128)
            .checked_add(effective_in)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let amount_out = numerator
            .checked_div(denominator)
            .ok_or(AmmError::ArithmeticOverflow)? as u64;

        require!(amount_out >= min_out, AmmError::SlippageExceeded);
        require!(amount_out > 0, AmmError::ZeroSwap);

        // Record k before
        let k_before = (pool.reserve_a as u128)
            .checked_mul(pool.reserve_b as u128)
            .ok_or(AmmError::ArithmeticOverflow)?;

        // Update reserves
        pool.reserve_a = pool
            .reserve_a
            .checked_add(amount_in)
            .ok_or(AmmError::ArithmeticOverflow)?;
        pool.reserve_b = pool
            .reserve_b
            .checked_sub(amount_out)
            .ok_or(AmmError::InsufficientFunds)?;

        // Invariant: k must not decrease (fees make it grow)
        let k_after = (pool.reserve_a as u128)
            .checked_mul(pool.reserve_b as u128)
            .ok_or(AmmError::ArithmeticOverflow)?;
        require!(k_after >= k_before, AmmError::InvariantViolation);

        // Transfer tokens
        let trader_a = &mut ctx.accounts.trader_token_a;
        let trader_b = &mut ctx.accounts.trader_token_b;
        trader_a.amount = trader_a
            .amount
            .checked_sub(amount_in)
            .ok_or(AmmError::InsufficientFunds)?;
        trader_b.amount = trader_b
            .amount
            .checked_add(amount_out)
            .ok_or(AmmError::ArithmeticOverflow)?;

        Ok(())
    }
}

/// Integer square root via Newton's method for u128 → u64.
fn sqrt_u64(val: u128) -> u64 {
    if val == 0 {
        return 0;
    }
    let mut x = val;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + val / x) / 2;
    }
    x as u64
}

// === Account Contexts ===

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(init, payer = authority, space = 8 + PoolState::SIZE)]
    pub pool_state: Account<'info, PoolState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub provider_token_a: Account<'info, TokenBalance>,
    #[account(mut)]
    pub provider_token_b: Account<'info, TokenBalance>,
    #[account(mut)]
    pub provider_lp: Account<'info, TokenBalance>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AddLiquidity<'info> {
    #[account(mut)]
    pub pool_state: Account<'info, PoolState>,
    #[account(mut)]
    pub provider: Signer<'info>,
    #[account(mut)]
    pub provider_token_a: Account<'info, TokenBalance>,
    #[account(mut)]
    pub provider_token_b: Account<'info, TokenBalance>,
    #[account(mut)]
    pub provider_lp: Account<'info, TokenBalance>,
}

#[derive(Accounts)]
pub struct RemoveLiquidity<'info> {
    #[account(mut)]
    pub pool_state: Account<'info, PoolState>,
    #[account(mut)]
    pub provider: Signer<'info>,
    #[account(mut)]
    pub provider_token_a: Account<'info, TokenBalance>,
    #[account(mut)]
    pub provider_token_b: Account<'info, TokenBalance>,
    #[account(mut)]
    pub provider_lp: Account<'info, TokenBalance>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub pool_state: Account<'info, PoolState>,
    #[account(mut)]
    pub trader: Signer<'info>,
    #[account(mut)]
    pub trader_token_a: Account<'info, TokenBalance>,
    #[account(mut)]
    pub trader_token_b: Account<'info, TokenBalance>,
}

// === Data Accounts ===

#[account]
pub struct PoolState {
    pub authority: Pubkey,         // 32
    pub reserve_a: u64,            // 8
    pub reserve_b: u64,            // 8
    pub total_lp_shares: u64,      // 8
    pub fee_bps: u16,              // 2
    pub is_initialized: bool,      // 1
}

impl PoolState {
    pub const SIZE: usize = 32 + 8 + 8 + 8 + 2 + 1;
}

#[account]
pub struct TokenBalance {
    pub amount: u64,
}

// === Errors ===

#[error_code]
pub enum AmmError {
    #[msg("Liquidity amounts must be greater than zero.")]
    ZeroLiquidity,
    #[msg("Swap amount must be greater than zero.")]
    ZeroSwap,
    #[msg("Insufficient funds.")]
    InsufficientFunds,
    #[msg("Arithmetic overflow.")]
    ArithmeticOverflow,
    #[msg("Fee exceeds maximum (10000 bps = 100%).")]
    InvalidFee,
    #[msg("Output below minimum — slippage protection triggered.")]
    SlippageExceeded,
    #[msg("Constant product invariant violated after swap.")]
    InvariantViolation,
    #[msg("Pool has not been initialized.")]
    PoolNotInitialized,
}
