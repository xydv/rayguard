use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

use crate::state::{Ledger, Log};

declare_id!("J3zRkAgCWjpXnKUr6teTdS2nLTGA3ZhEUi6gBvi5ZhdY");

pub mod state;

#[program]
pub mod rayguard_program {
    use super::*;

    pub fn create_ledger(ctx: Context<CreateLedger>, seed: u16) -> Result<()> {
        ctx.accounts.create_ledger(seed, &ctx.bumps)
    }

    pub fn add_log(ctx: Context<AddLog>, args: AddLogArgs) -> Result<()> {
        ctx.accounts.add_log(args, &ctx.bumps)
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
    pub fn create_ledger(&mut self, seed: u16, bumps: &CreateLedgerBumps) -> Result<()> {
        self.ledger.set_inner(Ledger {
            authority: self.authority.key(),
            last_hash: [0u8; 32],
            count: 0,
            bump: bumps.ledger,
        });

        msg!("new ledger initialized with seed {}", seed);

        Ok(())
    }
}

#[derive(Clone, Debug, AnchorSerialize, AnchorDeserialize)]
pub struct AddLogArgs {
    pub ip_address: String,
    pub threat_type: String,
    pub action_taken: String,
}

#[derive(Accounts)]
pub struct AddLog<'info> {
    #[account(mut)]
    pub ledger: Account<'info, Ledger>,

    #[account(
        init,
        payer = authority,
        space = Log::DISCRIMINATOR.len() + Log::INIT_SPACE,
        seeds = [
            b"log",
            ledger.key().as_ref(),
            ledger.count.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub log: Account<'info, Log>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

impl<'info> AddLog<'info> {
    pub fn add_log(&mut self, args: AddLogArgs, bumps: &AddLogBumps) -> Result<()> {
        let timestamp = Clock::get()?.unix_timestamp;

        let data_string = format!(
            "{}{}{}{}",
            args.ip_address, args.threat_type, args.action_taken, timestamp
        );

        let current_hash = hash(data_string.as_bytes()).to_bytes();

        self.log.set_inner(Log {
            timestamp,
            ip_address: args.ip_address,
            threat_type: args.threat_type,
            action_taken: args.action_taken,
            previous_hash: self.ledger.last_hash,
            current_hash,
            bump: bumps.log,
        });

        self.ledger.last_hash = current_hash;
        self.ledger.count += 1; // use checked_add later

        Ok(())
    }
}
