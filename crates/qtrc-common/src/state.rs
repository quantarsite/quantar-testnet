//! Chain state — accounts and validator set.

use crate::block::{Block, BlockHash};
use crate::tx::{Transaction, TxError, TX_FEE};
use qtrc_crypto::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-account state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountState {
    /// Balance in micro-QTR
    pub balance: u64,
    /// Next expected nonce
    pub nonce:   u64,
}

/// Registered validator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub stake:   u64,
}

/// Full chain state — everything needed to validate the next block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub height:     u64,
    pub block_hash: BlockHash,
    pub accounts:   HashMap<String, AccountState>, // key = address hex
    pub validators: Vec<ValidatorInfo>,
    /// First block height that charges `TX_FEE`. A chain created before
    /// fees existed keeps its old blocks valid by activating them later.
    #[serde(default = "fees_from_genesis")]
    pub fee_from_height: u64,
    /// Total micro-QTR burned in fees so far
    #[serde(default)]
    pub burned: u64,
}

fn fees_from_genesis() -> u64 {
    1
}

impl ChainState {
    pub fn account(&self, addr: &Address) -> AccountState {
        self.accounts
            .get(&addr.as_hex())
            .cloned()
            .unwrap_or_default()
    }

    /// Fee charged for a transaction included at block `height`.
    pub fn fee_at(&self, height: u64) -> u64 {
        if height >= self.fee_from_height { TX_FEE } else { 0 }
    }

    /// Apply a single verified transaction as part of block `self.height + 1`.
    /// The sender pays `amount + fee`; the fee is burned.
    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<(), TxError> {
        let fee = self.fee_at(self.height + 1);
        let from_state = self
            .accounts
            .entry(tx.from.as_hex())
            .or_insert_with(AccountState::default);

        // Nonce check
        if tx.nonce != from_state.nonce {
            return Err(TxError::InvalidNonce {
                expected: from_state.nonce,
                got:      tx.nonce,
            });
        }
        // Balance check: amount plus the protocol fee
        let need = tx.amount.checked_add(fee).ok_or(TxError::InsufficientBalance {
            need: u64::MAX,
            have: from_state.balance,
        })?;
        if from_state.balance < need {
            return Err(TxError::InsufficientBalance {
                need,
                have: from_state.balance,
            });
        }

        from_state.balance -= need;
        from_state.nonce   += 1;
        self.burned = self.burned.saturating_add(fee);

        let to_state = self
            .accounts
            .entry(tx.to.as_hex())
            .or_insert_with(AccountState::default);
        to_state.balance += tx.amount;

        Ok(())
    }

    /// Apply a full block to produce the next state.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), TxError> {
        for tx in &block.transactions {
            self.apply_tx(tx)?;
        }
        self.height     = block.header.height;
        self.block_hash = block.hash();
        Ok(())
    }
}
