//! # qtrc-chain — Chain indexing and persistence
//!
//! Wraps sled to provide:
//! - Block storage by height and hash
//! - Transaction index by hash
//! - Account state snapshots

use anyhow::Result;
use qtrc_common::{
    block::{Block, BlockHash},
    state::ChainState,
    tx::{Transaction, TxHash},
};
use sled::Db;

const BLOCKS_TREE:    &str = "blocks_by_height";
const HASH_IDX_TREE:  &str = "blocks_by_hash";
const TX_IDX_TREE:    &str = "transactions";
const STATE_TREE:     &str = "chain_state";

pub struct ChainDb {
    db: Db,
}

impl ChainDb {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(ChainDb { db })
    }

    // -----------------------------------------------------------------------
    // Blocks
    // -----------------------------------------------------------------------

    pub fn put_block(&self, block: &Block) -> Result<()> {
        let height_key = block.header.height.to_le_bytes();
        let hash_key   = block.hash().0;
        let value      = serde_json::to_vec(block)?;

        self.db
            .open_tree(BLOCKS_TREE)?
            .insert(height_key, value.clone())?;

        self.db
            .open_tree(HASH_IDX_TREE)?
            .insert(hash_key, value)?;

        // Index each transaction
        let tx_tree = self.db.open_tree(TX_IDX_TREE)?;
        for tx in &block.transactions {
            let tx_val = serde_json::to_vec(tx)?;
            tx_tree.insert(tx.hash().0, tx_val)?;
        }

        Ok(())
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let key = height.to_le_bytes();
        match self.db.open_tree(BLOCKS_TREE)?.get(key)? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None    => Ok(None),
        }
    }

    pub fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>> {
        match self.db.open_tree(HASH_IDX_TREE)?.get(hash.0)? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None    => Ok(None),
        }
    }

    pub fn latest_height(&self) -> Result<u64> {
        match self.db.open_tree(BLOCKS_TREE)?.last()? {
            Some((k, _)) => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&k);
                Ok(u64::from_le_bytes(buf))
            }
            None => Ok(0),
        }
    }

    // -----------------------------------------------------------------------
    // Transactions
    // -----------------------------------------------------------------------

    pub fn get_tx(&self, hash: &TxHash) -> Result<Option<Transaction>> {
        match self.db.open_tree(TX_IDX_TREE)?.get(hash.0)? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None    => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // State snapshots
    // -----------------------------------------------------------------------

    pub fn save_state(&self, state: &ChainState) -> Result<()> {
        let key   = state.height.to_le_bytes();
        let value = serde_json::to_vec(state)?;
        self.db.open_tree(STATE_TREE)?.insert(key, value)?;
        Ok(())
    }

    pub fn load_latest_state(&self) -> Result<Option<ChainState>> {
        match self.db.open_tree(STATE_TREE)?.last()? {
            Some((_, v)) => Ok(Some(serde_json::from_slice(&v)?)),
            None         => Ok(None),
        }
    }
}
