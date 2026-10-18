//! Persistent block storage backed by sled.
//!
//! Layout:
//!   tree "blocks": height (u64 big-endian) -> 0x01 || bincode(block)
//!                  (blocks written before v2.0.1 are JSON and still read)
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
        self.blocks.insert(height.to_be_bytes(), encode_block(block)?)?;
        // Durable before the node reports the block as committed. If the
        // flush fails, take the block back out so disk and memory agree.
        if let Err(e) = self.db.flush() {
            let _ = self.blocks.remove(height.to_be_bytes());
            bail!("could not flush block {height} to disk: {e}");
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        match self.blocks.get(height.to_be_bytes())? {
            Some(bytes) => Ok(Some(decode_block(&bytes)?)),
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
            decode_block(&bytes)
        })
    }
}

/// Format tag for bincode-encoded blocks.
const BINCODE_V1: u8 = 0x01;

/// Binary encoding: about 4x smaller than JSON, which writes every
/// signature byte as a decimal number (a tx was ~132 KB in JSON).
fn encode_block(block: &Block) -> Result<Vec<u8>> {
    let mut out = vec![BINCODE_V1];
    out.extend(bincode::serialize(block)?);
    Ok(out)
}

fn decode_block(bytes: &[u8]) -> Result<Block> {
    match bytes.first() {
        Some(&BINCODE_V1) => Ok(bincode::deserialize(&bytes[1..])?),
        Some(b'{') => Ok(serde_json::from_slice(bytes)?), // written by v2.0.0
        _ => bail!("unknown block encoding"),
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

    fn sample_block() -> Block {
        use qtrc_common::genesis::{Genesis, MICRO_QTR};
        use qtrc_common::tx::Transaction;
        use qtrc_consensus::ConsensusEngine;
        use qtrc_crypto::HydraXKeypair;
        let faucet = HydraXKeypair::generate();
        let to = HydraXKeypair::generate().address();
        let g = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
        let engine = ConsensusEngine::new(g.initial_state(), HydraXKeypair::generate());
        let payload = Transaction::signing_payload(&faucet.address(), &to, MICRO_QTR, 0);
        engine
            .submit_tx(Transaction {
                from: faucet.address(),
                to,
                amount: MICRO_QTR,
                nonce: 0,
                timestamp: 0,
                signature: faucet.sign(&payload),
            })
            .unwrap();
        engine.propose_block().unwrap()
    }

    #[test]
    fn binary_blocks_roundtrip_and_old_json_blocks_still_read() {
        let block = sample_block();
        let bin = encode_block(&block).unwrap();
        let json = serde_json::to_vec(&block).unwrap();
        assert_eq!(decode_block(&bin).unwrap().hash(), block.hash());
        assert_eq!(decode_block(&json).unwrap().hash(), block.hash(), "blocos da v2.0.0");
        assert!(bin.len() * 3 < json.len(), "binario {} vs json {}", bin.len(), json.len());
    }

    #[test]
    fn store_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("qtrc-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let block = sample_block();
        {
            let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
            s.put_block(&block).unwrap();
        }
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        let all: Vec<Block> = s.blocks().collect::<Result<_>>().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].hash(), block.hash());
        assert_eq!(s.latest_height().unwrap(), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn big_endian_keys_keep_numeric_order() {
        // 255 vs 256 is exactly where little-endian ordering breaks.
        assert!(255u64.to_be_bytes() < 256u64.to_be_bytes());
        assert!(255u64.to_le_bytes() > 256u64.to_le_bytes());
    }
}
