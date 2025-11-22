use anchor_lang::prelude::*;

use crate::state::Ledger;

declare_id!("J3zRkAgCWjpXnKUr6teTdS2nLTGA3ZhEUi6gBvi5ZhdY");

pub mod state;

#[program]
pub mod rayguard_program {
    use super::*;

    pub fn create_ledger(ctx: Context<CreateLedger>, seed: u16) -> Result<()> {
        ctx.accounts.create_ledger(&ctx.bumps)
    }
}

#[derive(Accounts)]
#[instruction(seed: u16)]
pub struct CreateLedger<'info> {
    #[account(
        init,
        payer = authority,
        space = Ledger::DISCRIMINATOR.len() + Ledger::INIT_SPACE,
        seeds = [b"state", seed.to_le_bytes().as_ref()],
        bump
    )]
    pub ledger: Account<'info, Ledger>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

impl<'info> CreateLedger<'info> {
    pub fn create_ledger(&mut self, bumps: &CreateLedgerBumps) -> Result<()> {
        self.ledger.set_inner(Ledger {
            authority: self.authority.key(),
            last_hash: [0; 32],
            count: 0,
            bump: bumps.ledger,
        });

        Ok(())
    }
}
