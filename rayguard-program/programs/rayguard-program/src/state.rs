use anchor_lang::prelude::*;

#[account]
#[derive(InitSpace)]
pub struct Ledger {
    pub authority: Pubkey,
    pub last_hash: [u8; 32],
    pub count: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Log {
    pub timestamp: i64,
    #[max_len(100)]
    pub ip_address: String,
    #[max_len(100)]
    pub threat_type: String,
    #[max_len(100)]
    pub action_taken: String,
    pub previous_hash: [u8; 32],
    pub current_hash: [u8; 32],
    pub bump: u8,
}
