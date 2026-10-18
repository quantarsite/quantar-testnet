//! Persistent block storage backed by sled.
//!
//! Layout:
//!   tree "blocks": height (u64 big-endian) -> JSON block
//!   tree "meta":   "genesis" -> JSON genesis config this chain was started with
//!
//! Heights are stored big-endian so sled's byte ordering is numeric order.
//! (Little-endian keys, as in v1, sort 256 before 255 and break `last()`.)

use anyhow::{bail, Context, Result};
use qtrc_common::{block::Block, genesis::Genesis};
use qtrc_consensus::BlockSink;
use sled::{Db, Tree};

const GENESIS_KEY: &[u8] = b"genesis";

pub struct BlockStore {
    db:     Db,
    blocks: Tree,
    meta:   Tree,
}

impl BlockStore {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(format!("{path}/chain"))
            .with_context(|| format!("cannot open chain store in {path}"))?;
        let blocks = db.open_tree("blocks")?;
        let meta = db.open_tree("meta")?;
        Ok(BlockStore { db, blocks, meta })
    }

    /// Genesis this data directory was created with, if any.
    pub fn genesis(&self) -> Result<Option<Genesis>> {
        match self.meta.get(GENESIS_KEY)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Record the genesis of a brand new data directory.
    pub fn save_genesis(&self, genesis: &Genesis) -> Result<()> {
        self.meta.insert(GENESIS_KEY, serde_json::to_vec(genesis)?)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn put_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height;
        if let Some(last) = self.latest_height()? {
            if height != last + 1 {
                bail!("refusing to store block {height}: last stored block is {last}");
            }
        } else if height != 1 {
            bail!("refusing to store block {height}: store is empty, expected block 1");
        }
        self.blocks.insert(height.to_be_bytes(), serde_json::to_vec(block)?)?;
        // Durable before the node reports the block as committed.
        self.db.flush()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        match self.blocks.get(height.to_be_bytes())? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn latest_height(&self) -> Result<Option<u64>> {
        match self.blocks.last()? {
            Some((key, _)) => {
                let buf: [u8; 8] = key.as_ref().try_into().context("corrupt block key")?;
                Ok(Some(u64::from_be_bytes(buf)))
            }
            None => Ok(None),
        }
    }

    /// All stored blocks in height order.
    pub fn blocks(&self) -> impl Iterator<Item = Result<Block>> + '_ {
        self.blocks.iter().map(|item| {
            let (_, bytes) = item?;
            Ok(serde_json::from_slice(&bytes)?)
        })
    }
}

impl BlockSink for BlockStore {
    fn persist(&self, block: &Block) -> std::result::Result<(), String> {
        self.put_block(block).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_endian_keys_keep_numeric_order() {
        // 255 vs 256 is exactly where little-endian ordering breaks.
        assert!(255u64.to_be_bytes() < 256u64.to_be_bytes());
        assert!(255u64.to_le_bytes() > 256u64.to_le_bytes());
    }
}
