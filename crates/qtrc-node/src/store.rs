//! Persistent block storage backed by sled.
//!
//! Layout:
//!   tree "blocks": height (u64 big-endian) -> 0x02 || bincode(block)
//!                  (0x01 = bincode without the tx `data` field, written
//!                  before Sentinel; JSON = written by v2.0.0; both still read)
//!   tree "meta":   "genesis" -> JSON genesis config this chain was started with
//!
//!   file "chain.marker" next to the sled dir: written when the genesis is
//!                  saved, then raised after every stored block. sled can
//!                  lose files and open as an empty database; the marker
//!                  lives outside it so that case is refused instead of
//!                  being mistaken for a new data directory.
//!
//! Heights are stored big-endian so sled's byte ordering is numeric order.
//! (Little-endian keys, as in v1, sort 256 before 255 and break `last()`.)

use anyhow::{bail, Context, Result};
use qtrc_common::{block::Block, genesis::Genesis};
use qtrc_consensus::BlockSink;
use sled::{Db, Tree};
use std::path::{Path, PathBuf};

const GENESIS_KEY: &[u8] = b"genesis";
const FEE_FROM_KEY: &[u8] = b"fee_from_height";
const SENTINEL_FROM_KEY: &[u8] = b"sentinel_from_height";
const STATE_ROOT_FROM_KEY: &[u8] = b"state_root_from_height";
const WITNESS_ROOT_FROM_KEY: &[u8] = b"witness_root_from_height";
const RECOVERY_V3_FROM_KEY: &[u8] = b"recovery_v3_from_height";
const MARKER_FILE: &str = "chain.marker";
const MARKER_HEADER: &str = "quantar chain store v1";

pub struct BlockStore {
    db:     Db,
    blocks: Tree,
    meta:   Tree,
    marker: PathBuf,
}

impl BlockStore {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(format!("{path}/chain"))
            .with_context(|| format!("cannot open chain store in {path}"))?;
        let blocks = db.open_tree("blocks")?;
        let meta = db.open_tree("meta")?;
        let store = BlockStore { db, blocks, meta, marker: Path::new(path).join(MARKER_FILE) };
        store.check_marker(path)?;
        Ok(store)
    }

    /// Refuse a store that holds less than this data dir is known to have
    /// committed. Data dirs from before the marker get one on first open.
    fn check_marker(&self, path: &str) -> Result<()> {
        let has_genesis = self.meta.get(GENESIS_KEY)?.is_some();
        let latest = self.latest_height()?.unwrap_or(0);
        match self.read_marker()? {
            Some(committed) => {
                if !has_genesis {
                    bail!(
                        "{path} holds a chain that reached block {committed}, but its database \
                         opened without a genesis: the sled files are damaged or incomplete. \
                         Refusing to start a new chain over it. Restore the data dir from a backup."
                    );
                }
                if latest < committed {
                    bail!(
                        "{path} committed up to block {committed}, but its database ends at \
                         block {latest}: blocks are missing. Restore the data dir from a backup."
                    );
                }
                Ok(())
            }
            None if has_genesis => self.write_marker(latest),
            None => Ok(()),
        }
    }

    fn read_marker(&self) -> Result<Option<u64>> {
        let text = match std::fs::read_to_string(&self.marker) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", self.marker.display())),
        };
        let mut lines = text.lines();
        let height = (lines.next() == Some(MARKER_HEADER))
            .then(|| lines.next()?.strip_prefix("height=")?.parse::<u64>().ok())
            .flatten();
        match height {
            Some(h) => Ok(Some(h)),
            None => bail!("{} is corrupt; restore the data dir from a backup", self.marker.display()),
        }
    }

    /// Atomic replace: write a temp file, sync it, rename over the marker.
    fn write_marker(&self, height: u64) -> Result<()> {
        use std::io::Write;
        let tmp = self.marker.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        writeln!(f, "{MARKER_HEADER}\nheight={height}")?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.marker)
            .with_context(|| format!("cannot write {}", self.marker.display()))?;
        Ok(())
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
        self.write_marker(self.latest_height()?.unwrap_or(0))
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

    /// First height whose header carries the state root, fixed once per
    /// data dir like the fee and Sentinel activations.
    ///
    /// If the stored height already has a block and that block has no root,
    /// an older binary ran on this data dir after the activation was recorded
    /// (rolled back before the first root was mined). Move the activation
    /// past those blocks so they replay instead of failing.
    pub fn state_root_from_height(&self) -> Result<u64> {
        let from = self.activation_height(STATE_ROOT_FROM_KEY)?;
        let Some(latest) = self.latest_height()? else { return Ok(from) };
        if from > latest {
            return Ok(from);
        }
        match self.get_block(from)? {
            Some(b) if b.header.state_root.is_none() => {
                let moved = latest + 1;
                self.meta.insert(STATE_ROOT_FROM_KEY, &moved.to_be_bytes())?;
                self.db.flush()?;
                Ok(moved)
            }
            _ => Ok(from),
        }
    }

    /// First height whose header carries the witness root, fixed once per
    /// data dir like the others (chains without fixed parameters).
    pub fn witness_root_from_height(&self) -> Result<u64> {
        self.activation_height(WITNESS_ROOT_FROM_KEY)
    }

    /// First height whose Sentinel recoveries are verified over the full
    /// message (v3), fixed once per data dir like the others.
    pub fn recovery_v3_from_height(&self) -> Result<u64> {
        self.activation_height(RECOVERY_V3_FROM_KEY)
    }

    /// Use a known network's fixed activation heights. A data dir that
    /// recorded different ones followed other rules: refuse it rather than
    /// replay its blocks under the wrong ones.
    pub fn pin_activations(&self, a: &qtrc_common::chain::Activations) -> Result<()> {
        for (key, fixed) in [
            (FEE_FROM_KEY, a.fee),
            (SENTINEL_FROM_KEY, a.sentinel),
            (STATE_ROOT_FROM_KEY, a.state_root),
            (WITNESS_ROOT_FROM_KEY, a.witness_root),
            (RECOVERY_V3_FROM_KEY, a.recovery_v3),
        ] {
            if let Some(v) = self.meta.get(key)? {
                let buf: [u8; 8] = v.as_ref().try_into().context("corrupt activation height")?;
                let recorded = u64::from_be_bytes(buf);
                // A height recorded past the last block was never used.
                let used = self.latest_height()?.is_some_and(|l| recorded <= l || fixed <= l);
                if recorded != fixed && used {
                    bail!(
                        "this data dir activated {} at block {recorded}, but the network fixes it at {fixed}. \
                         Restore a backup or sync a new data dir.",
                        String::from_utf8_lossy(key)
                    );
                }
            }
            self.meta.insert(key, &fixed.to_be_bytes())?;
        }
        self.db.flush()?;
        Ok(())
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
        // The block is durable in sled; the marker may only trail it. A
        // crash before this line leaves the marker one block behind, which
        // the open check accepts.
        if self.marker.exists() {
            self.write_marker(height)?;
        }
        Ok(())
    }

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
const BINCODE_V3: u8 = 0x03;
const BINCODE_V4: u8 = 0x04;
const BINCODE_V5: u8 = 0x05;

/// Binary encoding: about 4x smaller than JSON, which writes every
/// signature byte as a decimal number (a tx was ~132 KB in JSON).
///
/// The oldest format that can represent a block is used, so older releases
/// keep reading this data dir for as long as possible:
/// 0x01 no Sentinel data and no state root (any release),
/// 0x02 Sentinel data, no state root (v2.1+),
/// 0x03 state root in the header (v2.3+),
/// 0x04 witness root, and the state root if any, in the header (v2.4+),
/// 0x05 as 0x04 plus the commit proof of a block the validators voted on.
pub(crate) fn encode_block(block: &Block) -> Result<Vec<u8>> {
    if block.commit.is_some() {
        return wire::encode_v5(block);
    }
    if block.header.witness_root.is_some() {
        return wire::encode_v4(block);
    }
    if block.header.state_root.is_some() {
        return wire::encode_v3(block);
    }
    if block.transactions.iter().all(|t| t.data.is_empty()) {
        return v1::encode(block);
    }
    wire::encode_v2(block)
}

pub(crate) fn decode_block(bytes: &[u8]) -> Result<Block> {
    match bytes.first() {
        Some(&BINCODE_V5) => Ok(bincode::deserialize::<wire::BlockV5>(&bytes[1..])?.into()),
        Some(&BINCODE_V4) => Ok(bincode::deserialize::<wire::BlockV4>(&bytes[1..])?.into()),
        Some(&BINCODE_V3) => Ok(bincode::deserialize::<wire::BlockV3>(&bytes[1..])?.into()),
        Some(&BINCODE_V2) => Ok(bincode::deserialize::<wire::BlockV2>(&bytes[1..])?.into()),
        Some(&BINCODE_V1) => Ok(bincode::deserialize::<v1::Block>(&bytes[1..])?.into()),
        Some(b'{') => Ok(serde_json::from_slice(bytes)?), // written by v2.0.0
        _ => bail!("unknown block encoding"),
    }
}

/// Field-for-field layouts of the stored formats. bincode is not
/// self-describing, so each format has its own fixed type, independent of
/// how `BlockHeader` evolves.
mod wire {
    use qtrc_common::block::{Block, BlockHash, BlockHeader, ValidatorSig};
    use qtrc_common::tx::{Transaction, TxHash};
    use qtrc_crypto::Address;
    use serde::{Deserialize, Serialize};

    /// Header as stored before state roots (formats 0x01 and 0x02).
    #[derive(Serialize, Deserialize)]
    pub struct HeaderV1 {
        pub height:      u64,
        pub prev_hash:   BlockHash,
        pub merkle_root: TxHash,
        pub timestamp:   i64,
        pub proposer:    Address,
    }

    impl HeaderV1 {
        pub fn of(h: &BlockHeader) -> Self {
            Self {
                height: h.height,
                prev_hash: h.prev_hash.clone(),
                merkle_root: h.merkle_root.clone(),
                timestamp: h.timestamp,
                proposer: h.proposer.clone(),
            }
        }
        pub fn into_header(self, state_root: Option<[u8; 32]>, witness_root: Option<[u8; 32]>) -> BlockHeader {
            BlockHeader {
                height: self.height,
                prev_hash: self.prev_hash,
                merkle_root: self.merkle_root,
                timestamp: self.timestamp,
                proposer: self.proposer,
                state_root,
                witness_root,
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct BlockV2 {
        header:         HeaderV1,
        transactions:   Vec<Transaction>,
        validator_sigs: Vec<ValidatorSig>,
    }

    impl From<BlockV2> for Block {
        fn from(b: BlockV2) -> Self {
            Block { header: b.header.into_header(None, None), transactions: b.transactions, validator_sigs: b.validator_sigs, commit: None }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct BlockV3 {
        header:         HeaderV1,
        state_root:     [u8; 32],
        transactions:   Vec<Transaction>,
        validator_sigs: Vec<ValidatorSig>,
    }

    impl From<BlockV3> for Block {
        fn from(b: BlockV3) -> Self {
            Block {
                header: b.header.into_header(Some(b.state_root), None),
                transactions: b.transactions,
                validator_sigs: b.validator_sigs,
                commit: None,
            }
        }
    }

    pub fn encode_v2(block: &Block) -> anyhow::Result<Vec<u8>> {
        let b = BlockV2 {
            header: HeaderV1::of(&block.header),
            transactions: block.transactions.clone(),
            validator_sigs: block.validator_sigs.clone(),
        };
        let mut out = vec![super::BINCODE_V2];
        out.extend(bincode::serialize(&b)?);
        Ok(out)
    }

    #[derive(Serialize, Deserialize)]
    pub struct BlockV4 {
        header:         HeaderV1,
        state_root:     Option<[u8; 32]>,
        witness_root:   [u8; 32],
        transactions:   Vec<Transaction>,
        validator_sigs: Vec<ValidatorSig>,
    }

    impl From<BlockV4> for Block {
        fn from(b: BlockV4) -> Self {
            Block {
                header: b.header.into_header(b.state_root, Some(b.witness_root)),
                transactions: b.transactions,
                validator_sigs: b.validator_sigs,
                commit: None,
            }
        }
    }

    pub fn encode_v4(block: &Block) -> anyhow::Result<Vec<u8>> {
        let Some(witness_root) = block.header.witness_root else {
            anyhow::bail!("format 0x04 needs a witness root");
        };
        let b = BlockV4 {
            header: HeaderV1::of(&block.header),
            state_root: block.header.state_root,
            witness_root,
            transactions: block.transactions.clone(),
            validator_sigs: block.validator_sigs.clone(),
        };
        let mut out = vec![super::BINCODE_V4];
        out.extend(bincode::serialize(&b)?);
        Ok(out)
    }

    #[derive(Serialize, Deserialize)]
    pub struct BlockV5 {
        header:         HeaderV1,
        state_root:     Option<[u8; 32]>,
        witness_root:   Option<[u8; 32]>,
        transactions:   Vec<Transaction>,
        validator_sigs: Vec<ValidatorSig>,
        commit:         qtrc_common::block::CommitProof,
    }

    impl From<BlockV5> for Block {
        fn from(b: BlockV5) -> Self {
            Block {
                header: b.header.into_header(b.state_root, b.witness_root),
                transactions: b.transactions,
                validator_sigs: b.validator_sigs,
                commit: Some(b.commit),
            }
        }
    }

    pub fn encode_v5(block: &Block) -> anyhow::Result<Vec<u8>> {
        let Some(commit) = block.commit.clone() else {
            anyhow::bail!("format 0x05 needs a commit proof");
        };
        let b = BlockV5 {
            header: HeaderV1::of(&block.header),
            state_root: block.header.state_root,
            witness_root: block.header.witness_root,
            transactions: block.transactions.clone(),
            validator_sigs: block.validator_sigs.clone(),
            commit,
        };
        let mut out = vec![super::BINCODE_V5];
        out.extend(bincode::serialize(&b)?);
        Ok(out)
    }

    pub fn encode_v3(block: &Block) -> anyhow::Result<Vec<u8>> {
        let root = block.header.state_root.ok_or_else(|| anyhow::anyhow!("format 0x03 needs a state root"))?;
        let b = BlockV3 {
            header: HeaderV1::of(&block.header),
            state_root: root,
            transactions: block.transactions.clone(),
            validator_sigs: block.validator_sigs.clone(),
        };
        let mut out = vec![super::BINCODE_V3];
        out.extend(bincode::serialize(&b)?);
        Ok(out)
    }
}

/// Block layout before transactions had a `data` field.
mod v1 {
    use super::wire::HeaderV1;
    use qtrc_common::block::ValidatorSig;
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
        header:         HeaderV1,
        transactions:   Vec<Transaction>,
        validator_sigs: Vec<ValidatorSig>,
    }

    impl From<Block> for qtrc_common::block::Block {
        fn from(b: Block) -> Self {
            Self {
                header: b.header.into_header(None, None),
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
                commit: None,
            }
        }
    }

    /// The exact bytes a pre-Sentinel node writes. Only valid for blocks
    /// whose transactions all have empty `data` and no state root.
    pub fn encode(block: &qtrc_common::block::Block) -> anyhow::Result<Vec<u8>> {
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
            header: HeaderV1,
            transactions: Vec<Tx<'a>>,
            validator_sigs: &'a Vec<ValidatorSig>,
        }
        let b = B {
            header: HeaderV1::of(&block.header),
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
        out.extend(bincode::serialize(&b)?);
        Ok(out)
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

    /// A block as the previous releases made it: no state root.
    fn sample_block() -> Block {
        sample_block_with(false)
    }

    fn sample_block_with(state_root: bool) -> Block {
        use qtrc_common::genesis::{Genesis, MICRO_QTR};
        use qtrc_common::tx::Transaction;
        use qtrc_consensus::ConsensusEngine;
        use qtrc_crypto::HydraXKeypair;
        let faucet = HydraXKeypair::generate();
        let to = HydraXKeypair::generate().address();
        let g = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
        let mut st = g.initial_state();
        // Witness roots have their own test; these blocks are v1/v2/v3.
        st.witness_root_from_height = u64::MAX;
        if !state_root {
            st.state_root_from_height = u64::MAX;
        }
        let engine = ConsensusEngine::new(st, HydraXKeypair::generate());
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

    /// A Sentinel-era block (format 0x02) written by the release on `main`,
    /// the format the live node has on disk since v2.1. The fixture's data
    /// was set after signing, so only the layout is checked: it must decode
    /// and re-encode to the exact same bytes.
    #[test]
    fn a_block_with_a_commit_proof_round_trips_as_format_5() {
        let mut b = sample_block_with(true);
        let sig = b.validator_sigs[0].clone();
        b.commit = Some(qtrc_common::block::CommitProof { round: 2, precommits: vec![sig.clone(), sig] });
        let bytes = encode_block(&b).unwrap();
        assert_eq!(bytes[0], BINCODE_V5);
        let back = decode_block(&bytes).unwrap();
        assert_eq!(back.commit, b.commit);
        assert_eq!(back.hash(), b.hash());
        // Without a proof, the old format is still used.
        b.commit = None;
        assert_ne!(encode_block(&b).unwrap()[0], BINCODE_V5);
    }

    #[test]
    fn sentinel_era_v2_block_from_previous_release_still_reads() {
        let bytes = include_bytes!("../tests/fixtures/block_v2_main.bin");
        assert_eq!(bytes[0], BINCODE_V2);
        let block = decode_block(bytes).unwrap();
        assert_eq!(block.transactions[0].data, b"QSN1-fixture-data");
        assert!(block.header.state_root.is_none());
        assert_eq!(wire::encode_v2(&block).unwrap().as_slice(), bytes.as_slice());
        assert_eq!(encode_block(&block).unwrap().as_slice(), bytes.as_slice());
    }

    /// Regression U1: new binary records the activation, operator rolls back
    /// before any root is mined, the old binary adds blocks without roots,
    /// then the new binary returns. The activation must move past them.
    #[test]
    fn rollback_before_first_root_does_not_brick_the_node() {
        let dir = std::env::temp_dir().join(format!("qtrc-u1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        assert_eq!(s.state_root_from_height().unwrap(), 1, "new binary on an empty dir");
        s.put_block(&sample_block()).unwrap(); // old binary mines block 1 without a root
        assert_eq!(s.state_root_from_height().unwrap(), 2, "activation moved past it");
        assert_eq!(s.state_root_from_height().unwrap(), 2, "and stays there");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_root_blocks_use_v3_and_roundtrip() {
        let block = sample_block_with(true);
        assert!(block.header.state_root.is_some());
        let enc = encode_block(&block).unwrap();
        assert_eq!(enc[0], BINCODE_V3);
        let back = decode_block(&enc).unwrap();
        assert_eq!(back.header.state_root, block.header.state_root);
        assert_eq!(back.hash(), block.hash());
        assert!(back.verify_transactions());
        // The root is part of the signed header: dropping it changes the hash.
        let mut stripped = block.clone();
        stripped.header.state_root = None;
        assert_ne!(stripped.hash(), block.hash());
    }

    #[test]
    fn pre_sentinel_bincode_blocks_still_read() {
        let block = sample_block();
        let old = v1::encode(&block).unwrap();
        let back = decode_block(&old).unwrap();
        assert_eq!(back.hash(), block.hash());
        assert_eq!(back.header.merkle_root, block.header.merkle_root);
        assert!(back.verify_transactions());
        // Plain blocks stay readable by the previous release.
        assert_eq!(encode_block(&block).unwrap(), old);
        // A block with a Sentinel operation uses the new tag.
        let mut with_op = block.clone();
        with_op.transactions[0].data = b"QSN1x".to_vec();
        let enc = encode_block(&with_op).unwrap();
        assert_eq!(enc[0], BINCODE_V2);
        assert_eq!(decode_block(&enc).unwrap().transactions[0].data, b"QSN1x");
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
        assert_eq!(v1::encode(&block).unwrap().as_slice(), bytes.as_slice(), "our v1 encoder matches the real one");
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

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("qtrc-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Adversarial finding F1: deleting sled's snapshot made the store open
    /// empty and the node started a new chain over the old data dir.
    #[test]
    fn lost_sled_snapshot_is_refused_not_mistaken_for_a_new_chain() {
        let dir = tmp_dir("snaploss");
        let path = dir.to_str().unwrap();
        {
            let s = BlockStore::open(path).unwrap();
            s.save_genesis(&Genesis::testnet_with_faucet(None)).unwrap();
            s.put_block(&sample_block()).unwrap();
        }
        assert!(BlockStore::open(path).is_ok(), "healthy reopen");
        // With blob-sized values (real HYDRA-X blocks), losing snap.* after a
        // reopen makes sled open with no trees at all. That outcome is
        // reproduced directly here, since which files sled needs varies.
        std::fs::remove_dir_all(dir.join("chain")).unwrap();
        let err = BlockStore::open(path).err().expect("damaged store must not open").to_string();
        assert!(err.contains("Refusing to start a new chain"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_blocks_are_refused() {
        let dir = tmp_dir("missing");
        let path = dir.to_str().unwrap();
        {
            let s = BlockStore::open(path).unwrap();
            s.save_genesis(&Genesis::testnet_with_faucet(None)).unwrap();
            s.put_block(&sample_block()).unwrap();
        }
        std::fs::write(dir.join(MARKER_FILE), format!("{MARKER_HEADER}\nheight=5\n")).unwrap();
        let err = BlockStore::open(path).err().expect("must refuse").to_string();
        assert!(err.contains("blocks are missing"), "{err}");
        std::fs::write(dir.join(MARKER_FILE), "garbage").unwrap();
        assert!(BlockStore::open(path).err().unwrap().to_string().contains("corrupt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The live data dir has a genesis and blocks but no marker yet: the
    /// first open of the new binary adopts it at its current height.
    #[test]
    fn existing_data_dir_gets_a_marker_on_first_open() {
        let dir = tmp_dir("adopt");
        let path = dir.to_str().unwrap();
        {
            let s = BlockStore::open(path).unwrap();
            s.save_genesis(&Genesis::testnet_with_faucet(None)).unwrap();
            s.put_block(&sample_block()).unwrap();
        }
        std::fs::remove_file(dir.join(MARKER_FILE)).unwrap();
        let s = BlockStore::open(path).unwrap();
        assert_eq!(s.read_marker().unwrap(), Some(1));
        drop(s);
        // A fresh directory stays markerless until it has a genesis.
        let fresh = tmp_dir("fresh");
        let s = BlockStore::open(fresh.to_str().unwrap()).unwrap();
        assert_eq!(s.read_marker().unwrap(), None);
        s.save_genesis(&Genesis::testnet_with_faucet(None)).unwrap();
        assert_eq!(s.read_marker().unwrap(), Some(0));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&fresh);
    }

    #[test]
    fn witness_root_blocks_use_v4_and_roundtrip() {
        let mut block = sample_block_with(true);
        block.header.witness_root = Some(Block::compute_witness_root(&block.transactions));
        let bytes = encode_block(&block).unwrap();
        assert_eq!(bytes[0], BINCODE_V4);
        let back = decode_block(&bytes).unwrap();
        assert_eq!(back.hash(), block.hash());
        assert_eq!(back.header.witness_root, block.header.witness_root);
        // A witness root without a state root still has a format.
        block.header.state_root = None;
        let back = decode_block(&encode_block(&block).unwrap()).unwrap();
        assert_eq!(back.hash(), block.hash());
    }

    /// The live data dir recorded fee 5, Sentinel 6, state root 15 and no
    /// witness height: pinning keeps them and adds the fixed one.
    #[test]
    fn pinning_accepts_the_live_dir_and_refuses_other_rules() {
        use qtrc_common::chain::Activations;
        let dir = tmp_dir("pin");
        let path = dir.to_str().unwrap();
        let fixed = Activations { fee: 2, sentinel: 2, state_root: 2, witness_root: 5, recovery_v3: 7 };
        {
            let s = BlockStore::open(path).unwrap();
            s.save_genesis(&Genesis::testnet_with_faucet(None)).unwrap();
            s.put_block(&sample_block()).unwrap();
            // Recorded by earlier releases: next block after the one stored.
            assert_eq!(s.fee_from_height().unwrap(), 2);
            assert_eq!(s.sentinel_from_height().unwrap(), 2);
            assert_eq!(s.state_root_from_height().unwrap(), 2);
            s.pin_activations(&fixed).unwrap();
            assert_eq!(s.witness_root_from_height().unwrap(), 5);
            assert_eq!(s.recovery_v3_from_height().unwrap(), 7);
            // A rule recorded at block 1, already used, disagrees: refuse.
            let other = Activations { fee: 1, ..fixed };
            let err = s.pin_activations(&other).unwrap_err().to_string();
            assert!(err.contains("fee_from_height"), "{err}");
        }
        let _ = std::fs::remove_dir_all(&dir);
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
