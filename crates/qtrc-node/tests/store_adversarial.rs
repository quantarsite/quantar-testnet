//! Adversarial tests for the sled block store, compiled against the real
//! `src/store.rs` (included by path, the node is a binary crate).
//!
//! Tests prefixed `finding_` assert the behaviour the node SHOULD have and
//! fail on v2.3.0. They are `#[ignore]`d so the suite stays green; run them
//! with `cargo test -p qtrc-node --test store_adversarial -- --ignored`.

#[allow(dead_code)]
#[path = "../src/store.rs"]
mod store;

use qtrc_common::block::{Block, BlockHash, BlockHeader, ValidatorSig};
use qtrc_common::tx::{Transaction, TxHash};
use qtrc_crypto::{Address, HydraXKeypair, HydraXSignature};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use store::BlockStore;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn b32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        b
    }
}

fn sig() -> &'static HydraXSignature {
    static S: OnceLock<HydraXSignature> = OnceLock::new();
    S.get_or_init(|| HydraXKeypair::generate().sign(b"store"))
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qtrc-adv-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Random block of one of the three formats: 1 = plain, 2 = data, 3 = root.
fn random_block(rng: &mut Rng, height: u64, format: u8) -> Block {
    let ntx = (rng.next() % 4) as usize + usize::from(format == 2);
    let transactions = (0..ntx)
        .map(|i| Transaction {
            from: Address(rng.b32()),
            to: Address(rng.b32()),
            amount: rng.next(),
            nonce: rng.next(),
            timestamp: rng.next() as i64,
            signature: sig().clone(),
            data: if format == 2 && i == 0 { (0..1 + rng.next() % 300).map(|_| rng.next() as u8).collect() } else { vec![] },
        })
        .collect::<Vec<_>>();
    Block {
        header: BlockHeader {
            height,
            prev_hash: BlockHash(rng.b32()),
            merkle_root: TxHash(rng.b32()),
            timestamp: rng.next() as i64,
            proposer: Address(rng.b32()),
            state_root: (format == 3).then(|| rng.b32()),
        },
        transactions,
        validator_sigs: vec![ValidatorSig { validator: Address(rng.b32()), signature: sig().clone() }],
    }
}

fn json(b: &Block) -> Vec<u8> {
    serde_json::to_vec(b).unwrap()
}

#[test]
fn every_format_roundtrips_field_for_field() {
    let dir = tmp("roundtrip");
    let mut rng = Rng(0xABCDEF);
    let mut written = Vec::new();
    {
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        for h in 1..=60u64 {
            let fmt = (rng.next() % 3) as u8 + 1;
            let b = random_block(&mut rng, h, fmt);
            s.put_block(&b).unwrap();
            written.push(b);
        }
        // Gaps and repeats are refused
        assert!(s.put_block(&random_block(&mut rng, 62, 1)).is_err());
        assert!(s.put_block(&random_block(&mut rng, 60, 1)).is_err());
    }
    // Legacy v2.0.0 JSON block written straight into sled
    let legacy = random_block(&mut rng, 61, 1);
    {
        let db = sled::open(dir.join("chain")).unwrap();
        db.open_tree("blocks").unwrap().insert(61u64.to_be_bytes(), json(&legacy)).unwrap();
        db.flush().unwrap();
    }
    written.push(legacy);
    let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
    let all: Vec<Block> = s.blocks().collect::<anyhow::Result<_>>().unwrap();
    assert_eq!(all.len(), written.len());
    for (a, b) in all.iter().zip(&written) {
        assert_eq!(json(a), json(b), "block {} changed through the store", b.header.height);
        assert_eq!(a.hash(), b.hash());
    }
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupted_block_values_error_out_and_never_panic() {
    let dir = tmp("garbage");
    let mut rng = Rng(42);
    let good = {
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        let b = random_block(&mut rng, 1, 3);
        s.put_block(&b).unwrap();
        b
    };
    let enc = {
        let db = sled::open(dir.join("chain")).unwrap();
        db.open_tree("blocks").unwrap().get(1u64.to_be_bytes()).unwrap().unwrap().to_vec()
    };
    for i in 0..400u64 {
        let mut v = enc.clone();
        match i % 4 {
            0 => v.truncate((rng.next() % v.len() as u64) as usize),
            1 => {
                for _ in 0..1 + rng.next() % 8 {
                    let at = (rng.next() % v.len() as u64) as usize;
                    v[at] ^= 1 << (rng.next() % 8);
                }
            }
            2 => {
                // huge length prefix right after the tag + fixed header part
                let at = 1 + (rng.next() % 200) as usize;
                v[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            _ => v = (0..rng.next() % 64).map(|_| rng.next() as u8).collect(),
        }
        {
            let db = sled::open(dir.join("chain")).unwrap();
            db.open_tree("blocks").unwrap().insert(1u64.to_be_bytes(), v.clone()).unwrap();
            db.flush().unwrap();
        }
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.get_block(1)));
        let r = r.unwrap_or_else(|_| panic!("decode panicked (case {i})"));
        if let Ok(Some(b)) = r {
            // A flip that still decodes must change the block (and so its
            // hash or signatures), never come back identical silently.
            if json(&b) == json(&good) {
                assert_eq!(v, enc, "case {i}: different bytes decoded to the same block");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn snapshot_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir.join("chain"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("snap."))
        .collect()
}

/// FINDING: losing sled's `snap.*` file makes the store open EMPTY without
/// any error. `cmd_start` then treats the data dir as new, writes a fresh
/// genesis over it and starts mining a different chain from height 1 with
/// the same validator key (reproduced with the real binary as well).
#[test]
#[ignore = "FINDING: fails on v2.3.0 (silent chain reset after sled snapshot loss)"]
fn finding_store_with_lost_snapshot_must_not_look_new() {
    let dir = tmp("snaploss");
    let mut rng = Rng(7);
    {
        let s = BlockStore::open(dir.to_str().unwrap()).unwrap();
        let g = qtrc_common::genesis::Genesis::testnet_with_faucet(None);
        s.save_genesis(&g).unwrap();
        for h in 1..=30 {
            s.put_block(&random_block(&mut rng, h, 3)).unwrap();
        }
        assert_eq!(s.latest_height().unwrap(), Some(30));
    }
    let snaps = snapshot_files(&dir);
    assert!(!snaps.is_empty(), "sled wrote no snapshot");
    for p in snaps {
        std::fs::remove_file(p).unwrap();
    }
    // Desired: opening fails, or the existing chain is still visible.
    match BlockStore::open(dir.to_str().unwrap()) {
        Err(_) => {}
        Ok(s) => {
            let genesis = s.genesis().unwrap();
            let latest = s.latest_height().unwrap();
            assert!(
                genesis.is_some() || latest.is_some(),
                "data dir with 30 blocks opened as an empty store: the node would start a new chain on top of it"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// FINDING: the header (and so the block hash and the validator signature)
/// does not commit to transaction signatures or timestamps, because the tx
/// "merkle root" is built from tx IDs only. A stored block whose txs were
/// altered in those fields replays as the same block.
#[test]
#[ignore = "FINDING: fails on v2.3.0 (block commitment ignores tx timestamps/signatures)"]
fn finding_block_commitment_covers_every_stored_tx_byte() {
    let mut rng = Rng(9);
    let b = random_block(&mut rng, 1, 1);
    let mut t = b.clone();
    t.transactions[0].timestamp ^= 0x5555;
    t.transactions[0].signature = HydraXKeypair::generate().sign(b"other");
    // What commit_block checks: header.merkle_root == compute_merkle_root(txs)
    assert_ne!(
        Block::compute_merkle_root(&t.transactions),
        Block::compute_merkle_root(&b.transactions),
        "txs with a different timestamp and signature produce the same tx root, so a block's stored \
         contents can change without changing its hash or invalidating the validator signature"
    );
}
