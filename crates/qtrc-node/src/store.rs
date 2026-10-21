//! Persistent block storage backed by sled.
//!
//! Layout:
//!   tree "blocks": height (u64 big-endian) -> 0x02 || bincode(block)
//!                  (0x01 = bincode without the tx `data` field, written
//!                  before Sentinel; JSON = written by v2.0.0; both still read)
//!   tree "meta":   "genesis" -> JSON genesis config this chain was started with
//!
//! Heights are stored big-endian so sled's byte ordering is numeric order.
//! (Little-endian keys, as in v1, sort 256 before 255 and break `last()`.)

use anyhow::{bail, Context, Result};
use qtrc_common::{block::Block, genesis::Genesis};
use qtrc_consensus::BlockSink;
use sled::{Db, Tree};

const GENESIS_KEY: &[u8] = b"genesis";
const FEE_FROM_KEY: &[u8] = b"fee_from_height";
const SENTINEL_FROM_KEY: &[u8] = b"sentinel_from_height";

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

    /// First height that charges the protocol fee, fixed once per data dir.
    ///
    /// A new chain charges fees from block 1. A chain that already has
    /// blocks from before fees existed starts charging at the next block,
    /// so its stored blocks still replay to the same state.
    pub fn fee_from_height(&self) -> Result<u64> {
        self.activation_height(FEE_FROM_KEY)
    }

    /// First height that accepts Sentinel operations, fixed once per data
    /// dir: block 1 on a new chain, the next block on a chain that already
    /// has blocks, so stored history replays unchanged.
    pub fn sentinel_from_height(&self) -> Result<u64> {
        self.activation_height(SENTINEL_FROM_KEY)
    }

    fn activation_height(&self, key: &[u8]) -> Result<u64> {
        if let Some(v) = self.meta.get(key)? {
            let buf: [u8; 8] = v.as_ref().try_into().context("corrupt activation height")?;
            return Ok(u64::from_be_bytes(buf));
        }
        let from = self.latest_height()?.map_or(1, |h| h + 1);
        self.meta.insert(key, &from.to_be_bytes())?;
        self.db.flush()?;
        Ok(from)
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

/// Format tags for bincode-encoded blocks.
const BINCODE_V1: u8 = 0x01;
const BINCODE_V2: u8 = 0x02;

/// Binary encoding: about 4x smaller than JSON, which writes every
/// signature byte as a decimal number (a tx was ~132 KB in JSON).
fn encode_block(block: &Block) -> Result<Vec<u8>> {
    let mut out = vec![BINCODE_V2];
    out.extend(bincode::serialize(block)?);
    Ok(out)
}

fn decode_block(bytes: &[u8]) -> Result<Block> {
    match bytes.first() {
        Some(&BINCODE_V2) => Ok(bincode::deserialize(&bytes[1..])?),
        Some(&BINCODE_V1) => Ok(bincode::deserialize::<v1::Block>(&bytes[1..])?.into()),
        Some(b'{') => Ok(serde_json::from_slice(bytes)?), // written by v2.0.0
        _ => bail!("unknown block encoding"),
    }
}

/// Block layout before transactions had a `data` field. bincode is not
/// self-describing, so these blocks need their own field-for-field type.
mod v1 {
    use qtrc_common::block::{BlockHeader, ValidatorSig};
    use qtrc_crypto::{Address, HydraXSignature};
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct Transaction {
        from:      Address,
        to:        Address,
        amount:    u64,
        nonce:     u64,
        timestamp: i64,
        signature: HydraXSignature,
    }

    #[derive(Deserialize)]
    pub struct Block {
        header:         BlockHeader,
        transactions:   Vec<Transaction>,
        validator_sigs: Vec<ValidatorSig>,
    }

    impl From<Block> for qtrc_common::block::Block {
        fn from(b: Block) -> Self {
            Self {
                header: b.header,
                transactions: b
                    .transactions
                    .into_iter()
                    .map(|t| qtrc_common::tx::Transaction {
                        from: t.from,
                        to: t.to,
                        amount: t.amount,
                        nonce: t.nonce,
                        timestamp: t.timestamp,
                        signature: t.signature,
                        data: Vec::new(),
                    })
                    .collect(),
                validator_sigs: b.validator_sigs,
            }
        }
    }

    /// Encoder for tests: the exact bytes a pre-Sentinel node wrote.
    #[cfg(test)]
    pub fn encode(block: &qtrc_common::block::Block) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Tx<'a> {
            from: &'a Address,
            to: &'a Address,
            amount: u64,
            nonce: u64,
            timestamp: i64,
            signature: &'a HydraXSignature,
        }
        #[derive(serde::Serialize)]
        struct B<'a> {
            header: &'a BlockHeader,
            transactions: Vec<Tx<'a>>,
            validator_sigs: &'a Vec<ValidatorSig>,
        }
        let b = B {
            header: &block.header,
            transactions: block
                .transactions
                .iter()
                .map(|t| Tx {
                    from: &t.from,
                    to: &t.to,
                    amount: t.amount,
                    nonce: t.nonce,
                    timestamp: t.timestamp,
                    signature: &t.signature,
                })
                .collect(),
            validator_sigs: &block.validator_sigs,
        };
        let mut out = vec![super::BINCODE_V1];
        out.extend(bincode::serialize(&b).unwrap());
        out
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
                data: vec![],
            })
            .unwrap();
        engine.propose_block().unwrap()
    }

    #[test]
    fn pre_sentinel_bincode_blocks_still_read() {
        let block = sample_block();
        let old = v1::encode(&block);
        let back = decode_block(&old).unwrap();
        assert_eq!(back.hash(), block.hash());
        assert_eq!(back.header.merkle_root, block.header.merkle_root);
        assert!(back.verify_transactions());
        // New blocks use the new tag.
        assert_eq!(encode_block(&block).unwrap()[0], BINCODE_V2);
    }

    /// A block written by the pre-Sentinel node (generated with the code on
    /// `main`, the format the live testnet has on disk) must decode with
    /// the same merkle root and valid HYDRA-X signatures.
    #[test]
    fn block_written_by_previous_release_still_verifies() {
        let bytes = include_bytes!("../tests/fixtures/block_v1_main.bin");
        assert_eq!(bytes[0], BINCODE_V1);
        let block = decode_block(bytes).unwrap();
        assert!(!block.transactions.is_empty());
        assert!(block.transactions.iter().all(|t| t.data.is_empty()));
        assert_eq!(Block::compute_merkle_root(&block.transactions), block.header.merkle_root);
        assert!(block.verify_transactions(), "HYDRA-X signatures still verify");
        // Re-encoding as v2 and back is lossless.
        let again = decode_block(&encode_block(&block).unwrap()).unwrap();
        assert_eq!(again.hash(), block.hash());
        assert_eq!(v1::encode(&block).as_slice(), bytes.as_slice(), "our v1 encoder matches the real one");
    }

    #[test]
    fn sentinel_activation_follows_existing_blocks() {
        let dir = std::env::temp_dir().join(format!("qtrc-sentinel-act-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        s.put_block(&sample_block()).unwrap();
        assert_eq!(s.sentinel_from_height().unwrap(), 2);
        assert_eq!(s.sentinel_from_height().unwrap(), 2, "fixed once written");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
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
        // Pasta que já tinha blocos: a taxa começa no bloco seguinte, e fica fixa.
        assert_eq!(s.fee_from_height().unwrap(), 2);
        drop(s);
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        assert_eq!(s.fee_from_height().unwrap(), 2, "valor gravado, nao recalculado");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_chain_charges_fees_from_block_one() {
        let dir = std::env::temp_dir().join(format!("qtrc-fee-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        assert_eq!(s.fee_from_height().unwrap(), 1);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn big_endian_keys_keep_numeric_order() {
        // 255 vs 256 is exactly where little-endian ordering breaks.
        assert!(255u64.to_be_bytes() < 256u64.to_be_bytes());
        assert!(255u64.to_le_bytes() > 256u64.to_le_bytes());
    }
}
