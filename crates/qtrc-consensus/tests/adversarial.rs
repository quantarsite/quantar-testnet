//! Adversarial engine tests: concurrency, admission under a full mempool,
//! and cost measurements for attacker-controlled work.
//!
//! `finding_*` tests assert what SHOULD happen and fail on v2.3.0; they are
//! `#[ignore]`d. `dos_*` tests are measurements (ignored, print timings).
//! Run: `cargo test --release -p qtrc-consensus --test adversarial -- --ignored --nocapture`

use qtrc_common::block::Block;
use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::sentinel::SentinelOp;
use qtrc_common::tx::{Transaction, CHAIN_ID};
use qtrc_consensus::{ConsensusEngine, ConsensusError, MAX_MEMPOOL};
use qtrc_crypto::{Address, HydraXKeypair};
use qtrc_sentinel::{recovery_commitment, recovery_message};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn tx(kp: &HydraXKeypair, to: &Address, amount: u64, nonce: u64, data: Vec<u8>) -> Transaction {
    let from = kp.address();
    let payload = Transaction::signing_payload_with_data(&from, to, amount, nonce, &data);
    Transaction { from, to: to.clone(), amount, nonce, timestamp: 0, signature: kp.sign(&payload), data }
}

/// Sign many txs in parallel (SLH-DSA signing is ~0.7 s each).
/// (signer, to, amount, nonce, data)
type Job = (Arc<HydraXKeypair>, Address, u64, u64, Vec<u8>);

fn sign_all(jobs: Vec<Job>) -> Vec<Transaction> {
    let n = std::thread::available_parallelism().map_or(2, |n| n.get());
    let jobs = Arc::new(std::sync::Mutex::new(jobs.into_iter().enumerate().collect::<Vec<_>>()));
    let out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hs: Vec<_> = (0..n)
        .map(|_| {
            let (jobs, out) = (jobs.clone(), out.clone());
            std::thread::spawn(move || loop {
                let Some((i, (kp, to, amount, nonce, data))) = jobs.lock().unwrap().pop() else { return };
                let t = tx(&kp, &to, amount, nonce, data);
                out.lock().unwrap().push((i, t));
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let mut v = Arc::try_unwrap(out).ok().unwrap().into_inner().unwrap();
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, t)| t).collect()
}

fn engine_with_faucet() -> (Arc<ConsensusEngine>, Arc<HydraXKeypair>, HydraXKeypair) {
    let faucet = Arc::new(HydraXKeypair::generate());
    let g = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let validator = HydraXKeypair::generate();
    let vaddr = HydraXKeypair::from_bytes(&validator.to_bytes()).unwrap();
    (Arc::new(ConsensusEngine::new(g.initial_state(), validator)), faucet, vaddr)
}

/// Many threads submit (valid, replayed, out-of-order) and ask for proofs
/// while blocks are produced. No panic, no deadlock, and every proof must
/// verify against the state root of the header it was served with, and
/// that header must carry a valid validator signature.
#[test]
fn concurrent_submit_and_proof_never_disagree() {
    let (engine, faucet, validator) = engine_with_faucet();
    let users: Vec<Address> = (0..6).map(|_| HydraXKeypair::generate().address()).collect();
    let jobs = (0..24u64).map(|n| (faucet.clone(), users[(n % 6) as usize].clone(), MICRO_QTR + n, n, vec![])).collect();
    let txs = Arc::new(sign_all(jobs));

    let stop = Arc::new(AtomicBool::new(false));
    let proofs_ok = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();

    // Submitters: in order, plus replays and duplicates from other threads
    for t in 0..4 {
        let (e, txs, stop) = (engine.clone(), txs.clone(), stop.clone());
        handles.push(std::thread::spawn(move || {
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let k = (i + t) % txs.len();
                match e.submit_tx(txs[k].clone()) {
                    Ok(_) | Err(ConsensusError::InvalidTx(_)) | Err(ConsensusError::Busy(_)) => {}
                    Err(other) => panic!("unexpected submit error: {other}"),
                }
                i += 1;
            }
        }));
    }
    // Provers
    for t in 0..4 {
        let (e, users, stop, ok) = (engine.clone(), users.clone(), stop.clone(), proofs_ok.clone());
        let faucet_addr = faucet.address();
        let vaddr = validator.address();
        handles.push(std::thread::spawn(move || {
            let mut last_h = 0;
            let mut i = t;
            while !stop.load(Ordering::Relaxed) {
                let who = if i % 7 == 0 { faucet_addr.clone() } else { users[i % users.len()].clone() };
                i += 1;
                let Ok((header, sigs, proof)) = e.state_proof(&who) else { continue };
                assert!(header.height >= last_h, "header went backwards");
                last_h = header.height;
                let root = header.state_root.expect("root active from block 1");
                if let Some(p) = proof {
                    assert!(p.verify(&root), "proof does not match the header it was served with (h={})", header.height);
                    assert_eq!(p.leaf.address, who);
                }
                if i % 25 == 0 {
                    let s = sigs.iter().find(|s| s.validator == vaddr).expect("validator sig");
                    s.signature.verify(&header.signing_bytes()).expect("header signature");
                }
                ok.fetch_add(1, Ordering::Relaxed);
                let _ = e.next_nonce(&who);
            }
        }));
    }
    // Producer
    let deadline = Instant::now() + Duration::from_secs(240);
    let mut blocks = 0;
    while engine.state.read().account(&faucet.address()).nonce < 24 {
        assert!(Instant::now() < deadline, "no progress: possible deadlock");
        match engine.propose_block() {
            Ok(b) => {
                engine.commit_block(b).expect("own block must commit");
                blocks += 1;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("worker thread panicked");
    }
    let st = engine.state.read();
    let total: u64 = st.accounts.values().map(|a| a.balance).sum::<u64>() + st.burned;
    assert_eq!(total, 10_000_000 * MICRO_QTR, "supply");
    assert!(engine.mempool.read().is_empty());
    assert!(proofs_ok.load(Ordering::Relaxed) > 100, "too few proofs exercised");
    eprintln!("blocks {blocks}, proofs checked {}", proofs_ok.load(Ordering::Relaxed));
}

struct GuardedSetup {
    engine: Arc<ConsensusEngine>,
    owner: HydraXKeypair,
    recover_tx: Transaction,
}

/// A funded, guarded account and a ready recovery tx sent by a rescuer.
fn guarded_setup() -> GuardedSetup {
    let (engine, faucet, _) = engine_with_faucet();
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
    GuardedSetup { engine, owner, recover_tx }
}

/// FINDING: there is no reserved room for Sentinel recoveries. Once the
/// mempool holds MAX_MEMPOOL transactions (from anyone, e.g. a thief who
/// holds the main key and wants the time lock to run out) the recovery is
/// refused with "mempool full", and selection is FIFO with no priority, so
/// even an admitted recovery waits behind up to MAX_MEMPOOL/500 blocks.
#[test]
#[ignore = "FINDING: fails on v2.3.0 (recovery refused when the mempool is full)"]
fn finding_recovery_is_admitted_even_when_mempool_is_full() {
    let s = guarded_setup();
    // Simulate a flood: the queue is a pub field, fill it with copies of a
    // plain tx (contents do not matter for the size check).
    let filler = tx(&s.owner, &s.owner.address(), 1, 999, vec![]);
    s.engine.mempool.write().extend(std::iter::repeat_n(filler, MAX_MEMPOOL));
    let r = s.engine.submit_tx(s.recover_tx.clone());
    assert!(r.is_ok(), "recovery refused while the mempool is flooded: {r:?}");
}

// ---------------------------------------------------------------------------
// Cost measurements (attacker-controlled work)
// ---------------------------------------------------------------------------

fn time<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let r = f();
    eprintln!("{label}: {:?}", t.elapsed());
    r
}

/// An unauthenticated junk tx (wrong nonce, garbage signature) still makes
/// the node hash every tx in the mempool under the global submit lock,
/// before the nonce check (`is_pending`). With recovery-sized txs queued
/// this is tens of milliseconds per request.
#[test]
#[ignore = "measurement"]
fn dos_cost_of_a_junk_submit_vs_mempool_contents() {
    let s = guarded_setup();
    let junk = {
        let mut j = s.recover_tx.clone();
        j.nonce = 12345; // wrong nonce: refused, but only after is_pending()
        j.signature.slh_dsa_sig[0] ^= 1;
        j
    };
    for (label, filler, n) in [
        ("plain txs", tx(&s.owner, &s.owner.address(), 1, 999, vec![]), MAX_MEMPOOL),
        ("recovery-sized txs", s.recover_tx.clone(), MAX_MEMPOOL),
    ] {
        s.engine.mempool.write().clear();
        s.engine.mempool.write().extend(std::iter::repeat_n(filler.clone(), n));
        let reps = 20;
        let t = Instant::now();
        for _ in 0..reps {
            assert!(s.engine.submit_tx(junk.clone()).is_err());
        }
        eprintln!(
            "junk submit with {n} {label} in the mempool ({} B data each): {:?} per request (submit_lock held)",
            filler.data.len(),
            t.elapsed() / reps
        );
    }
    s.engine.mempool.write().clear();
    let t = Instant::now();
    for _ in 0..20 {
        assert!(s.engine.submit_tx(junk.clone()).is_err());
    }
    eprintln!("junk submit, empty mempool: {:?}", t.elapsed() / 20);
}

/// Time to propose + commit a full block, and to replay it.
#[test]
#[ignore = "measurement"]
fn dos_cost_full_block_commit_and_replay() {
    let (engine, faucet, validator) = engine_with_faucet();
    let n = 16u64; // per-sender cap; signing dominates setup, scale to 500 txs
    let to = HydraXKeypair::generate().address();
    let jobs = (0..n).map(|i| (faucet.clone(), to.clone(), 1, i, vec![])).collect();
    let txs = time("sign 16 txs (parallel)", || sign_all(jobs));
    let t = Instant::now();
    for x in &txs {
        engine.submit_tx(x.clone()).unwrap();
    }
    eprintln!("submit_tx (verify) per tx: {:?}", t.elapsed() / n as u32);
    let b: Block = time("propose 16-tx block (incl. block signature)", || engine.propose_block().unwrap());
    let bytes = serde_json::to_vec(&b).unwrap().len();
    time("commit 16-tx block (re-verifies every tx)", || engine.commit_block(b.clone()).unwrap());
    let replay = ConsensusEngine::new(
        Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state(),
        validator,
    );
    time("replay of the same block (restart)", || replay.replay_block(b).unwrap());
    eprintln!("block JSON size: {bytes} B for {n} txs");
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).map(|l| l.split_whitespace().nth(1).unwrap().parse().unwrap()))
        .unwrap_or(0)
}

/// Resident memory of a full mempool (MAX_MEMPOOL txs). Only the qtrc Vec
/// is filled here; hx-mempool keeps a second copy of both signatures
/// (SigEntry, ~34.5 KB) and of `data` (PooledTx) for every admitted tx.
#[test]
#[ignore = "measurement"]
fn dos_mempool_memory_when_full() {
    let s = guarded_setup();
    for (label, filler) in [("plain", tx(&s.owner, &s.owner.address(), 1, 999, vec![])), ("recovery", s.recover_tx.clone())] {
        s.engine.mempool.write().clear();
        let before = rss_kib();
        s.engine.mempool.write().extend((0..MAX_MEMPOOL).map(|_| filler.clone()));
        let after = rss_kib();
        eprintln!(
            "{MAX_MEMPOOL} {label} txs: +{} MiB in the qtrc mempool alone (~{} KiB/tx); with hx-mempool copies add ~{} MiB",
            (after - before) / 1024,
            (after - before) / MAX_MEMPOOL as u64,
            (MAX_MEMPOOL as u64 * (34_515 + filler.data.len() as u64)) / 1_048_576
        );
    }
}

/// FINDING: `submit_tx` hashes every queued tx (`is_pending`, BLAKE3 over
/// the full payload including `data`) under the global submit lock, before
/// the nonce, balance or signature checks. A request that needs no key and
/// no funds therefore costs O(mempool bytes). Desired: refusing junk costs
/// about the same whatever the mempool holds.
#[test]
#[ignore = "FINDING: fails on v2.3.0 (junk submit cost scales with mempool contents)"]
fn finding_junk_submit_cost_is_independent_of_mempool_contents() {
    let s = guarded_setup();
    let mut junk = s.recover_tx.clone();
    junk.nonce = 12345;
    let measure = |e: &ConsensusEngine| {
        let t = Instant::now();
        for _ in 0..10 {
            assert!(e.submit_tx(junk.clone()).is_err());
        }
        t.elapsed() / 10
    };
    let empty = measure(&s.engine);
    s.engine.mempool.write().extend(std::iter::repeat_n(s.recover_tx.clone(), MAX_MEMPOOL));
    let full = measure(&s.engine);
    eprintln!("junk submit: empty mempool {empty:?}, full mempool {full:?}");
    assert!(full < empty * 50 + Duration::from_millis(1), "junk submit went from {empty:?} to {full:?} with a full mempool");
}
