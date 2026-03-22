use anchor_lang::prelude::*;

declare_id!("DbKQRFejQdTXuvd8NDNVX8uXYNXWNHVnxJi3JyEJhXbN");

#[program]
pub mod fuzztooldemo {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
