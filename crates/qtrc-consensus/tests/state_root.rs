//! State root in block headers, end to end: activation height, replay,
//! rejection of wrong, missing or premature roots, and proofs that verify
//! against the validator-signed header.

use qtrc_common::block::Block;
use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::sentinel::SentinelOp;
use qtrc_common::state::ChainState;
use qtrc_common::tx::{Transaction, CHAIN_ID};
use qtrc_consensus::ConsensusEngine;
use qtrc_crypto::{Address, HydraXKeypair};

fn tx(kp: &HydraXKeypair, to: &Address, amount: u64, nonce: u64, data: Vec<u8>) -> Transaction {
    let from = kp.address();
    let payload = Transaction::signing_payload_with_data(&from, to, amount, nonce, &data);
    Transaction { from, to: to.clone(), amount, nonce, timestamp: 0, signature: kp.sign(&payload), data }
}

struct Net {
    node_key: Vec<u8>,
    faucet: HydraXKeypair,
    start: ChainState,
    engine: ConsensusEngine,
    nonce: u64,
}

impl Net {
    fn new(root_from: u64) -> Self {
        let faucet = HydraXKeypair::generate();
        let mut start = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state();
        start.state_root_from_height = root_from;
        let node_key = HydraXKeypair::generate().to_bytes().to_vec();
        let engine = ConsensusEngine::new(start.clone(), HydraXKeypair::from_bytes(&node_key).unwrap());
        Net { node_key, faucet, start, engine, nonce: 0 }
    }

    fn key(&self) -> HydraXKeypair {
        HydraXKeypair::from_bytes(&self.node_key).unwrap()
    }

    /// Propose (without committing) a block paying `to`.
    fn propose(&mut self, to: &Address) -> Block {
        let t = tx(&self.faucet, to, MICRO_QTR, self.nonce, vec![]);
        self.nonce += 1;
        self.engine.submit_tx(t).unwrap();
        self.engine.propose_block().unwrap()
    }

    fn mine(&mut self, to: &Address) -> Block {
        let b = self.propose(to);
        self.engine.commit_block(b.clone()).unwrap();
        b
    }

    /// Re-sign a modified header with the proposer's key.
    fn resign(&self, mut b: Block) -> Block {
        b.validator_sigs[0].signature = self.key().sign(&b.header.signing_bytes());
        b
    }
}

#[test]
fn root_appears_at_activation_and_replays_identically() {
    let mut net = Net::new(3);
    let user = HydraXKeypair::generate().address();
    let blocks: Vec<Block> = (0..4).map(|_| net.mine(&user)).collect();
    assert!(blocks[0].header.state_root.is_none());
    assert!(blocks[1].header.state_root.is_none());
    assert!(blocks[2].header.state_root.is_some());
    assert_eq!(blocks[3].header.state_root, Some(net.engine.state.read().state_root()));

    let replica = ConsensusEngine::new(net.start.clone(), net.key());
    for b in blocks {
        replica.replay_block(b).unwrap();
    }
    assert_eq!(replica.state.read().state_root(), net.engine.state.read().state_root());
}

#[test]
fn wrong_missing_or_premature_roots_are_rejected() {
    let mut net = Net::new(1);
    let user = HydraXKeypair::generate().address();

    let mut b = net.propose(&user);
    b.header.state_root = Some([7u8; 32]);
    let err = net.engine.commit_block(net.resign(b)).unwrap_err().to_string();
    assert!(err.contains("does not match"), "{err}");

    let mut b = net.propose(&user);
    b.header.state_root = None;
    let err = net.engine.commit_block(net.resign(b)).unwrap_err().to_string();
    assert!(err.contains("missing"), "{err}");

    // Before activation a root is refused too.
    let mut early = Net::new(100);
    let mut b = early.propose(&user);
    b.header.state_root = Some(early.engine.state.read().state_root());
    let err = early.engine.commit_block(early.resign(b)).unwrap_err().to_string();
    assert!(err.contains("before activation"), "{err}");
}

#[test]
fn proof_verifies_against_the_signed_header() {
    let mut net = Net::new(1);
    let user = HydraXKeypair::generate().address();
    net.mine(&user);
    net.mine(&user);

    let (header, sigs, proof) = net.engine.state_proof(&user).unwrap();
    let proof = proof.unwrap();
    let sig = &sigs[0];
    assert_eq!(sig.signature.signer_address(), header.proposer);
    sig.signature.verify(&header.signing_bytes()).unwrap();
    let root = header.state_root.unwrap();
    assert!(proof.verify(&root));
    assert_eq!(proof.leaf.balance, 2 * MICRO_QTR);

    // A lying node cannot change the balance without breaking the proof.
    let mut lie = proof.clone();
    lie.leaf.balance = 1_000 * MICRO_QTR;
    assert!(!lie.verify(&root));

    // Empty accounts have no proof.
    let nobody = HydraXKeypair::generate().address();
    assert!(net.engine.state_proof(&nobody).unwrap().2.is_none());
}

#[test]
fn sentinel_vault_is_committed_in_the_root() {
    let mut net = Net::new(1);
    let owner = HydraXKeypair::generate();
    let t = tx(&net.faucet, &owner.address(), 50 * MICRO_QTR, net.nonce, vec![]);
    net.nonce += 1;
    net.engine.submit_tx(t).unwrap();
    let b = net.engine.propose_block().unwrap();
    net.engine.commit_block(b).unwrap();

    let before = net.engine.state_proof(&owner.address()).unwrap().2.unwrap();
    assert!(before.leaf.vault_hash.is_none());

    let rec = HydraXKeypair::generate();
    let cold = HydraXKeypair::generate().address();
    let c = qtrc_sentinel::recovery_commitment(CHAIN_ID.as_bytes(), &owner.address(), &rec.address(), &cold, &[1u8; 32]);
    let op = SentinelOp::SetGuardian { commitment: c, delay_blocks: 10, allowance_per_window: 0 };
    net.engine.submit_tx(tx(&owner, &owner.address(), 0, 0, op.encode())).unwrap();
    let b = net.engine.propose_block().unwrap();
    net.engine.commit_block(b).unwrap();

    let (header, _, after) = net.engine.state_proof(&owner.address()).unwrap();
    let after = after.unwrap();
    assert!(after.leaf.vault_hash.is_some());
    assert!(after.verify(&header.state_root.unwrap()));
}

#[test]
fn proofs_wait_for_activation() {
    let mut net = Net::new(100);
    let user = HydraXKeypair::generate().address();
    net.mine(&user);
    let err = net.engine.state_proof(&user).unwrap_err().to_string();
    assert!(err.contains("state roots start at block 100"), "{err}");
}
