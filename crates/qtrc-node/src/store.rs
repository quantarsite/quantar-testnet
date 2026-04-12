//! Persistent block storage backed by sled.

use anyhow::Result;
use qtrc_common::block::Block;
use sled::Db;

pub struct BlockStore {
    db: Db,
}

impl BlockStore {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(format!("{path}/blocks"))?;
        Ok(BlockStore { db })
    }

    pub fn put_block(&self, block: &Block) -> Result<()> {
        let key   = block.header.height.to_le_bytes();
        let value = serde_json::to_vec(block)?;
        self.db.insert(key, value)?;
        Ok(())
    }

    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        let key = height.to_le_bytes();
        match self.db.get(key)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn latest_height(&self) -> Result<Option<u64>> {
        match self.db.last()? {
            Some((key, _)) => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&key);
                Ok(Some(u64::from_le_bytes(buf)))
            }
            None => Ok(None),
        }
    }
}
