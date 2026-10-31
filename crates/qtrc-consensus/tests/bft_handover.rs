//! The switch of a running chain from one validator to several voting:
//! before `bft_from_height` only the earlier validator may make blocks, and
//! alone; from it on every block needs a commit proof, so that validator
//! can no longer make one by itself. This is how quantar-testnet-2 moves
//! from its single validator to the four servers.

use qtrc_common::block::Block;
use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::state::{ChainState, ValidatorInfo};
use qtrc_common::tx::Transaction;
use qtrc_consensus::{ConsensusEngine, ConsensusError};
use qtrc_crypto::HydraXKeypair;

const BFT_FROM: u64 = 3;

struct Setup {
    faucet: HydraXKeypair,
    keys:   Vec<HydraXKeypair>,
    start:  ChainState,
}

fn info(k: &HydraXKeypair) -> ValidatorInfo {
    ValidatorInfo { address: k.address(), stake: 1 }
}

fn setup() -> Setup {
    let faucet = HydraXKeypair::generate();
    let keys: Vec<_> = (0..4).map(|_| HydraXKeypair::generate()).collect();
    let mut start = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state();
    start.validators = keys.iter().map(info).collect();
    start.pre_bft_validators = vec![info(&keys[0])];
    start.bft_from_height = BFT_FROM;
    Setup { faucet, keys, start }
}

fn engine(state: &ChainState, k: &HydraXKeypair) -> ConsensusEngine {
    ConsensusEngine::new(state.clone(), HydraXKeypair::from_bytes(&k.to_bytes()).unwrap())
}

fn transfer(from: &HydraXKeypair, nonce: u64) -> Transaction {
    let to = HydraXKeypair::generate().address();
    let p = Transaction::signing_payload(&from.address(), &to, MICRO_QTR, nonce);
    Transaction { from: from.address(), to, amount: MICRO_QTR, nonce, timestamp: 0, signature: from.sign(&p), data: vec![] }
}

/// `maker` builds the next block alone, carrying one transfer.
fn solo_block(maker: &ConsensusEngine, s: &Setup, nonce: u64) -> Result<Block, ConsensusError> {
    maker.submit_tx(transfer(&s.faucet, nonce))?;
    maker.propose_block()
}

#[test]
fn only_the_earlier_validator_makes_blocks_before_the_switch() {
    let s = setup();
    let v0 = engine(&s.start, &s.keys[0]);
    let v1 = engine(&s.start, &s.keys[1]);

    // A voting validator cannot make a pre-switch block: refused when it
    // tries, and refused by everyone else if it forges one anyway.
    assert!(matches!(solo_block(&v1, &s, 0), Err(ConsensusError::NotProposer { .. })));
    let mut thinks_its_turn = s.start.clone();
    thinks_its_turn.pre_bft_validators = vec![info(&s.keys[1])];
    let rogue = engine(&thinks_its_turn, &s.keys[1]);
    let forged = solo_block(&rogue, &s, 0).unwrap();
    let err = v1.commit_block(forged.clone()).unwrap_err().to_string();
    assert!(err.contains("not the expected proposer"), "refused for the wrong reason: {err}");
    assert!(v0.commit_block(forged).is_err());

    // The earlier validator's blocks are taken by everyone, without votes.
    for (h, nonce) in (1..BFT_FROM).zip(0u64..) {
        let b = solo_block(&v0, &s, nonce).unwrap();
        assert_eq!(b.header.height, h);
        assert!(b.commit.is_none());
        v0.commit_block(b.clone()).unwrap();
        v1.commit_block(b).unwrap();
    }
    assert_eq!(v1.state.read().height, BFT_FROM - 1);
}

#[test]
fn the_earlier_validator_cannot_go_on_alone_after_the_switch() {
    let s = setup();
    let v0 = engine(&s.start, &s.keys[0]);
    let v2 = engine(&s.start, &s.keys[2]);
    for nonce in 0..BFT_FROM - 1 {
        let b = solo_block(&v0, &s, nonce).unwrap();
        v0.commit_block(b.clone()).unwrap();
        v2.commit_block(b).unwrap();
    }

    // At the switch height a block without a commit proof is not final,
    // even when the old validator made it, and even if its node still ran
    // the old rules.
    let unvoted = solo_block(&v0, &s, BFT_FROM - 1).unwrap();
    assert_eq!(unvoted.header.height, BFT_FROM);
    assert!(v2.commit_block(unvoted.clone()).is_err(), "solo block at the switch height");
    assert!(v0.commit_block(unvoted).is_err());

    let mut old_rules = v0.state.read().clone();
    old_rules.bft_from_height = u64::MAX;
    let stale = engine(&old_rules, &s.keys[0]);
    let solo = solo_block(&stale, &s, BFT_FROM - 1).unwrap();
    assert!(matches!(v2.commit_block(solo), Err(ConsensusError::InsufficientSigs { .. })));
    assert_eq!(v2.state.read().height, BFT_FROM - 1, "nothing was committed past the switch");

    // Before the switch, the earlier validator is still the only one
    // expected; from it on, the round decides who proposes.
    assert_eq!(v2.proposer_at(1), Some(s.keys[0].address()));
    assert_eq!(v2.proposer_at(BFT_FROM - 1), Some(s.keys[0].address()));
}

#[test]
fn a_chain_without_an_earlier_set_is_unchanged() {
    // bft_from_height 1 and no earlier set: the devnet case, all four
    // vote from the first block.
    let s = setup();
    let mut st = s.start.clone();
    st.pre_bft_validators.clear();
    st.bft_from_height = 1;
    let v = engine(&st, &s.keys[0]);
    let set: Vec<_> = st.validators.iter().map(|v| v.address.clone()).collect();
    for h in 1..8 {
        assert_eq!(v.proposer_at(h), Some(set[(h as usize) % 4].clone()));
    }
    // A chain that never votes keeps its single validator.
    let mut solo = Genesis::testnet_with_faucet(Some(&s.faucet.address().as_hex())).initial_state();
    solo.validators = vec![info(&s.keys[0])];
    let v = engine(&solo, &s.keys[0]);
    let b = solo_block(&v, &s, 0).unwrap();
    v.commit_block(b).unwrap();
}
