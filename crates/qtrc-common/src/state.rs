//! Chain state — accounts and validator set.

use crate::block::{Block, BlockHash};
use crate::tx::{Transaction, TxError};
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
}

impl ChainState {
    pub fn account(&self, addr: &Address) -> AccountState {
        self.accounts
            .get(&addr.as_hex())
            .cloned()
            .unwrap_or_default()
    }

    /// Apply a single verified transaction.
    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<(), TxError> {
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
        // Balance check
        if from_state.balance < tx.amount {
            return Err(TxError::InsufficientBalance {
                need: tx.amount,
                have: from_state.balance,
            });
        }

        from_state.balance -= tx.amount;
        from_state.nonce   += 1;

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
