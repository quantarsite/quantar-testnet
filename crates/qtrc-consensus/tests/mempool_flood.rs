//! Mempool under flood (adversarial findings F2, F4, F5): a recovery still
//! gets in and goes first, and refusing junk costs the same however full
//! the queue is.

use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::sentinel::SentinelOp;
use qtrc_common::tx::{Transaction, TxHash, CHAIN_ID};
use qtrc_consensus::mempool::Entry;
use qtrc_consensus::{ConsensusEngine, MAX_MEMPOOL};
use qtrc_crypto::{Address, HydraXKeypair};
use qtrc_sentinel::{recovery_commitment, recovery_message};
use std::time::{Duration, Instant};

fn tx(kp: &HydraXKeypair, to: &Address, amount: u64, nonce: u64, data: Vec<u8>) -> Transaction {
    let from = kp.address();
    let payload = Transaction::signing_payload_with_data(&from, to, amount, nonce, &data);
    Transaction { from, to: to.clone(), amount, nonce, timestamp: 0, signature: kp.sign(&payload), data }
}

struct Setup {
    engine: ConsensusEngine,
    owner: HydraXKeypair,
    recover_tx: Transaction,
}

/// A funded, guarded account and a recovery signed by a rescuer.
fn setup() -> Setup {
    let faucet = HydraXKeypair::generate();
    let g = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(g.initial_state(), HydraXKeypair::generate());
    let owner = HydraXKeypair::generate();
    let rescuer = HydraXKeypair::generate();
    let rec = HydraXKeypair::generate();
    let cold = HydraXKeypair::generate().address();
    let salt = [5u8; 32];
    engine.submit_tx(tx(&faucet, &owner.address(), 100 * MICRO_QTR, 0, vec![])).unwrap();
    engine.submit_tx(tx(&faucet, &rescuer.address(), MICRO_QTR, 1, vec![])).unwrap();
    let b = engine.propose_block().unwrap();
    engine.commit_block(b).unwrap();
    let c = recovery_commitment(CHAIN_ID.as_bytes(), &owner.address(), &rec.address(), &cold, &salt);
    let op = SentinelOp::SetGuardian { commitment: c, delay_blocks: 10, allowance_per_window: MICRO_QTR };
    engine.submit_tx(tx(&owner, &owner.address(), 0, 0, op.encode())).unwrap();
    let b = engine.propose_block().unwrap();
    engine.commit_block(b).unwrap();
    let proof = rec.sign(&recovery_message(CHAIN_ID.as_bytes(), &owner.address(), &c, 0));
    let data = SentinelOp::Recover { cold_dest: cold, salt, proof: Box::new(proof) }.encode();
    let recover_tx = tx(&rescuer, &owner.address(), 0, 0, data);
    Setup { engine, owner, recover_tx }
}

/// MAX_MEMPOOL distinct ordinary entries (contents don't matter for the
/// admission checks being tested; signing 5,000 real txs takes an hour).
fn flood(e: &ConsensusEngine, like: &Transaction) {
    e.mempool.write().force_fill((0..MAX_MEMPOOL as u64).map(|i| {
        let mut en = Entry::new(like.clone(), false);
        en.hash = TxHash([0xEE; 32]);
        en.hash.0[..8].copy_from_slice(&i.to_be_bytes());
        en
    }));
}

#[test]
fn recovery_is_admitted_and_goes_first_when_the_mempool_is_flooded() {
    let s = setup();
    let filler = tx(&s.owner, &s.owner.address(), 1, 999, vec![]);
    flood(&s.engine, &filler);
    let busy = s.engine.submit_tx(tx(&s.owner, &s.owner.address(), 1, 1, vec![]));
    assert!(busy.is_err(), "ordinary tx must be refused when full");

    let id = s.engine.submit_tx(s.recover_tx.clone()).expect("recovery refused while flooded");

    // The recovery is at the front of the next block, ahead of 5,000 txs.
    let picked = s.engine.mempool.write().take_for_block(1);
    assert_eq!(picked[0].hash, id);
}

/// With 5,000 entries queued, junk is still refused for its own reason
/// (bad nonce), never "mempool full", and the queue is left untouched.
#[test]
fn junk_is_refused_on_its_own_merits_with_a_full_mempool() {
    let s = setup();
    let mut junk = s.recover_tx.clone();
    junk.nonce = 12_345;
    flood(&s.engine, &s.recover_tx);
    let before = s.engine.mempool.read().len();
    let err = s.engine.submit_tx(junk).unwrap_err().to_string();
    assert!(err.contains("invalid nonce"), "{err}");
    assert_eq!(s.engine.mempool.read().len(), before);
}

/// Timing of the same refusal, empty vs full mempool. A measurement: CI
/// runners are too noisy for a wall-clock assertion, so it is opt-in.
/// `cargo test --release -p qtrc-consensus --test mempool_flood -- --ignored --nocapture`
#[test]
#[ignore = "measurement"]
fn refusing_junk_costs_the_same_with_a_full_mempool() {
    let s = setup();
    let mut junk = s.recover_tx.clone();
    junk.nonce = 12_345;
    // Best of several rounds, so a busy CI runner does not decide the test.
    let measure = |e: &ConsensusEngine| {
        (0..5)
            .map(|_| {
                let t = Instant::now();
                for _ in 0..20 {
                    assert!(e.submit_tx(junk.clone()).is_err());
                }
                t.elapsed() / 20
            })
            .min()
            .unwrap()
    };
    let empty = measure(&s.engine);
    flood(&s.engine, &s.recover_tx);
    let full = measure(&s.engine);
    eprintln!("junk submit: empty {empty:?}, full {full:?}");
    // Before the index, a full mempool made this about 4,000x slower.
    assert!(full < empty * 10 + Duration::from_millis(2), "junk submit went from {empty:?} to {full:?}");
}
