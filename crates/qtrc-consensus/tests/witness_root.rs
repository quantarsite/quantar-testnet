//! Witness root (adversarial finding F6): from its activation the header
//! commits to every byte of every transaction, so a stored or relayed block
//! cannot change under the same header.

use qtrc_common::block::Block;
use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::state::ChainState;
use qtrc_common::tx::Transaction;
use qtrc_consensus::ConsensusEngine;
use qtrc_crypto::{Address, HydraXKeypair};

fn tx(kp: &HydraXKeypair, to: &Address, nonce: u64) -> Transaction {
    let from = kp.address();
    let p = Transaction::signing_payload(&from, to, MICRO_QTR, nonce);
    Transaction { from, to: to.clone(), amount: MICRO_QTR, nonce, timestamp: 0, signature: kp.sign(&p), data: vec![] }
}

struct Net {
    faucet: HydraXKeypair,
    key: Vec<u8>,
    start: ChainState,
    engine: ConsensusEngine,
    nonce: u64,
}

impl Net {
    fn new(witness_from: u64) -> Self {
        let faucet = HydraXKeypair::generate();
        let mut start = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state();
        start.witness_root_from_height = witness_from;
        let key = HydraXKeypair::generate().to_bytes().to_vec();
        let engine = ConsensusEngine::new(start.clone(), HydraXKeypair::from_bytes(&key).unwrap());
        Net { faucet, key, start, engine, nonce: 0 }
    }
    fn propose(&mut self) -> Block {
        let to = HydraXKeypair::generate().address();
        self.engine.submit_tx(tx(&self.faucet, &to, self.nonce)).unwrap();
        self.nonce += 1;
        self.engine.propose_block().unwrap()
    }
    fn resign(&self, mut b: Block) -> Block {
        let k = HydraXKeypair::from_bytes(&self.key).unwrap();
        b.validator_sigs[0].signature = k.sign(&b.header.signing_bytes());
        b
    }
}

#[test]
fn witness_root_appears_at_activation_and_replays() {
    let mut net = Net::new(2);
    let b1 = net.propose();
    assert!(b1.header.witness_root.is_none());
    net.engine.commit_block(b1.clone()).unwrap();
    let b2 = net.propose();
    assert_eq!(b2.header.witness_root, Some(Block::compute_witness_root(&b2.transactions)));
    net.engine.commit_block(b2.clone()).unwrap();

    let k = HydraXKeypair::from_bytes(&net.key).unwrap();
    let replica = ConsensusEngine::new(net.start.clone(), k);
    replica.replay_block(b1).unwrap();
    replica.replay_block(b2).unwrap();
}

#[test]
fn changing_a_signature_or_timestamp_breaks_the_block() {
    let mut net = Net::new(1);
    let b = net.propose();
    // Same tx ID, different bytes: a relay swaps in another valid signature
    // of the same payload (SLH-DSA and ML-DSA signing are randomized).
    let mut swapped = b.clone();
    let t = &b.transactions[0];
    swapped.transactions[0].signature = net.faucet.sign(&t.payload());
    assert_eq!(swapped.transactions[0].hash(), t.hash(), "tx ID does not cover the signature");
    assert_ne!(Block::compute_witness_root(&swapped.transactions), b.header.witness_root.unwrap());
    let err = net.engine.commit_block(swapped).unwrap_err().to_string();
    assert!(err.contains("witness root does not match"), "{err}");

    let mut retimed = b.clone();
    retimed.transactions[0].timestamp = 42;
    let err = net.engine.commit_block(retimed).unwrap_err().to_string();
    assert!(err.contains("witness root does not match"), "{err}");

    net.engine.commit_block(b).unwrap();
}

#[test]
fn missing_or_premature_witness_root_is_rejected() {
    let mut net = Net::new(1);
    let mut b = net.propose();
    b.header.witness_root = None;
    let err = net.engine.commit_block(net.resign(b)).unwrap_err().to_string();
    assert!(err.contains("missing its witness root"), "{err}");

    let mut early = Net::new(100);
    let mut b = early.propose();
    b.header.witness_root = Some(Block::compute_witness_root(&b.transactions));
    let err = early.engine.commit_block(early.resign(b)).unwrap_err().to_string();
    assert!(err.contains("before activation"), "{err}");
}
