//! Adversarial property tests (randomized, deterministic seeds, no extra
//! dependencies). Every failure prints the seed so it can be replayed.
//!
//! * state root is independent of insertion order
//! * every account proves in random trees of 0..300 leaves
//! * tampered proofs never verify
//! * tx JSON / bincode roundtrip keeps payload and ID
//! * SentinelOp::decode never panics and is canonical
//! * Vault::canonical_encoding is injective on random vaults
//! * ChainState::apply_tx never panics, conserves supply, keeps every vault
//!   consistent, and leaves the state untouched when it returns Err

use qtrc_common::genesis::Genesis;
use qtrc_common::sentinel::SentinelOp;
use qtrc_common::state::{AccountState, ChainState};
use qtrc_common::state_root::Proof;
use qtrc_common::tx::{Transaction, CHAIN_ID};
use qtrc_crypto::{Address, HydraXKeypair, HydraXSignature};
use qtrc_sentinel::{recovery_commitment, recovery_message, Policy, RecoveryProof, Vault};
use std::collections::{BTreeMap, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Tiny deterministic PRNG (xorshift64*)
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        b
    }
    fn addr(&mut self) -> Address {
        Address(self.bytes32())
    }
    /// Amounts biased toward edge values.
    fn amount(&mut self, around: u64) -> u64 {
        match self.below(10) {
            0 => 0,
            1 => u64::MAX,
            2 => around,
            3 => around.saturating_add(1),
            4 => around.saturating_sub(1),
            5 => 1,
            _ => self.below(around.saturating_add(2)),
        }
    }
}

/// One real HYDRA-X signature reused as filler: `apply_tx` does not verify
/// transaction signatures (block commit does), so any value works there.
fn filler_sig() -> &'static HydraXSignature {
    static SIG: OnceLock<HydraXSignature> = OnceLock::new();
    SIG.get_or_init(|| HydraXKeypair::generate().sign(b"filler"))
}

fn mk_tx(from: &Address, to: &Address, amount: u64, nonce: u64, data: Vec<u8>) -> Transaction {
    Transaction {
        from: from.clone(),
        to: to.clone(),
        amount,
        nonce,
        timestamp: 0,
        signature: filler_sig().clone(),
        data,
    }
}

// ---------------------------------------------------------------------------
// State root
// ---------------------------------------------------------------------------

fn random_state(rng: &mut Rng, n: usize) -> (ChainState, Vec<Address>) {
    let mut st = Genesis::testnet_with_faucet(None).initial_state();
    let mut addrs = Vec::new();
    for _ in 0..n {
        let a = rng.addr();
        // Never empty: balance or nonce non-zero
        let bal = rng.below(1_000_000_000) + 1;
        st.accounts.insert(a.as_hex(), AccountState { balance: bal, nonce: rng.below(5) });
        addrs.push(a);
    }
    st.burned = rng.below(1 << 40);
    (st, addrs)
}

#[test]
fn state_root_is_independent_of_insertion_order() {
    for seed in 0..60u64 {
        let mut rng = Rng::new(seed);
        let n = rng.below(120) as usize;
        let (st, _) = random_state(&mut rng, n);
        let root = st.state_root();
        let mut entries: Vec<(String, AccountState)> = st.accounts.clone().into_iter().collect();
        for round in 0..4 {
            // Fisher-Yates with the seeded rng
            for i in (1..entries.len()).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                entries.swap(i, j);
            }
            let mut st2 = st.clone();
            st2.accounts = HashMap::new();
            for (k, v) in &entries {
                st2.accounts.insert(k.clone(), v.clone());
            }
            // Empty accounts sprinkled in must not matter either
            if round % 2 == 1 {
                st2.accounts.insert(rng.addr().as_hex(), AccountState::default());
            }
            assert_eq!(st2.state_root(), root, "seed {seed} round {round}");
        }
    }
}

#[test]
fn every_account_proves_in_random_trees_0_to_300() {
    for n in 0..=300usize {
        let mut rng = Rng::new(1_000 + n as u64);
        let (st, addrs) = random_state(&mut rng, n);
        let tree = st.state_tree();
        let root = tree.root();
        assert_eq!(root, st.state_root(), "n={n}");
        for a in &addrs {
            let p = tree.proof(a).unwrap_or_else(|| panic!("n={n}: no proof for a non-empty account"));
            assert!(p.verify(&root), "n={n} addr={}", a.as_hex());
            assert_eq!(p.count, n as u64);
        }
        // An address that is not in the tree has no proof
        assert!(tree.proof(&rng.addr()).is_none(), "n={n}");
    }
}

fn mutate_proof(rng: &mut Rng, p: &mut Proof) -> &'static str {
    loop {
        match rng.below(12) {
            0 => { p.leaf.balance = p.leaf.balance.wrapping_add(1 + rng.below(1000)); return "balance"; }
            1 => { p.leaf.nonce = p.leaf.nonce.wrapping_add(1 + rng.below(3)); return "nonce"; }
            2 => { p.leaf.address.0[rng.below(32) as usize] ^= 1 << rng.below(8); return "address"; }
            3 => { p.leaf.vault_hash = Some(rng.bytes32()); return "vault_hash added"; }
            4 => { p.index = p.index.wrapping_add(1 + rng.below(p.count.max(1))); return "index"; }
            5 => { p.count = p.count.wrapping_add(1 + rng.below(3)); return "count+"; }
            6 if p.count > 1 => { p.count -= 1; return "count-"; }
            7 => { p.burned = p.burned.wrapping_add(1 + rng.below(1000)); return "burned"; }
            8 if !p.siblings.is_empty() => {
                let i = rng.below(p.siblings.len() as u64) as usize;
                p.siblings[i][rng.below(32) as usize] ^= 1 << rng.below(8);
                return "sibling bit";
            }
            9 => { let at = rng.below(p.siblings.len() as u64 + 1) as usize; p.siblings.insert(at, rng.bytes32()); return "extra sibling"; }
            10 if !p.siblings.is_empty() => { let i = rng.below(p.siblings.len() as u64) as usize; p.siblings.remove(i); return "dropped sibling"; }
            11 if p.siblings.len() > 1 && p.siblings[0] != p.siblings[1] => { p.siblings.swap(0, 1); return "swapped siblings"; }
            _ => {}
        }
    }
}

#[test]
fn tampered_proofs_never_verify() {
    let mut checked = 0;
    for seed in 0..150u64 {
        let mut rng = Rng::new(50_000 + seed);
        let n = 1 + rng.below(200) as usize;
        let (st, addrs) = random_state(&mut rng, n);
        let tree = st.state_tree();
        let root = tree.root();
        for _ in 0..20 {
            let a = &addrs[rng.below(addrs.len() as u64) as usize];
            let good = tree.proof(a).unwrap();
            let mut bad = good.clone();
            let what = mutate_proof(&mut rng, &mut bad);
            if bad == good {
                continue;
            }
            assert!(!bad.verify(&root), "seed {seed}: tampered proof ({what}) still verifies");
            // Must never panic either, whatever the shape
            let _ = bad.root();
            checked += 1;
        }
        // A valid proof for another state does not verify against this root
        let mut other = st.clone();
        other.burned += 1;
        assert!(!tree.proof(&addrs[0]).unwrap().verify(&other.state_root()));
    }
    assert!(checked > 2_500, "only {checked} tampered proofs checked");
}

#[test]
fn hostile_proof_shapes_do_not_panic() {
    // What a malicious node could send to `qtrc-wallet proof`.
    let mut rng = Rng::new(7);
    let (st, addrs) = random_state(&mut rng, 5);
    let base = st.state_tree().proof(&addrs[0]).unwrap();
    for (index, count) in [(0, 0), (u64::MAX, u64::MAX), (u64::MAX - 1, u64::MAX), (0, u64::MAX), (1, 1), (5, 3)] {
        let mut p = base.clone();
        p.index = index;
        p.count = count;
        p.siblings = (0..70).map(|_| rng.bytes32()).collect();
        assert!(p.root().is_none() || !p.verify(&st.state_root()));
    }
}

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

#[test]
fn tx_json_and_bincode_roundtrip_keep_payload_and_id() {
    for seed in 0..300u64 {
        let mut rng = Rng::new(9_000 + seed);
        let len = match rng.below(4) { 0 => 0, 1 => rng.below(64), 2 => 48 * 1024, _ => rng.below(48 * 1024) } as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let mut tx = mk_tx(&rng.addr(), &rng.addr(), rng.amount(1 << 50), rng.amount(1 << 20), data);
        tx.timestamp = rng.next() as i64;
        let id = tx.hash();
        let payload = tx.payload();

        let js = serde_json::to_vec(&tx).unwrap();
        let back: Transaction = serde_json::from_slice(&js).unwrap();
        assert_eq!(back.payload(), payload, "seed {seed} json");
        assert_eq!(back.hash(), id);
        assert_eq!(back.timestamp, tx.timestamp);
        assert_eq!(serde_json::to_vec(&back).unwrap(), js);

        let bin = bincode::serialize(&tx).unwrap();
        let back: Transaction = bincode::deserialize(&bin).unwrap();
        assert_eq!(back.payload(), payload, "seed {seed} bincode");
        assert_eq!(bincode::serialize(&back).unwrap(), bin);
    }
}

#[test]
fn sentinel_decode_never_panics_and_is_canonical() {
    let mut rng = Rng::new(31337);
    let real = [
        SentinelOp::Finalize { id: 7 }.encode(),
        SentinelOp::RotateGuardian { commitment: [9; 32] }.encode(),
        SentinelOp::SetGuardian { commitment: [1; 32], delay_blocks: 10, allowance_per_window: 5 }.encode(),
        SentinelOp::UpdatePolicy { delay_blocks: 10, allowance_per_window: 5 }.encode(),
    ];
    for i in 0..20_000u64 {
        let mut d = match rng.below(3) {
            0 => {
                let mut d = b"QSN1".to_vec();
                d.extend((0..rng.below(200)).map(|_| rng.next() as u8));
                d
            }
            1 => {
                let mut d = real[rng.below(real.len() as u64) as usize].clone();
                let at = 4 + rng.below(d.len() as u64 - 4) as usize;
                d[at] ^= 1 << rng.below(8);
                d
            }
            _ => {
                let mut d = real[rng.below(real.len() as u64) as usize].clone();
                d.truncate(rng.below(d.len() as u64) as usize);
                d
            }
        };
        // Huge length prefixes for the Recover proof vectors
        if i % 97 == 0 {
            d = b"QSN1".to_vec();
            d.extend(3u32.to_le_bytes());
            d.extend([0u8; 64]);
            d.extend(u64::MAX.to_le_bytes());
        }
        let r = catch_unwind(|| SentinelOp::decode(&d));
        let r = r.unwrap_or_else(|_| panic!("decode panicked on {:?}", d));
        if let Ok(op) = r {
            assert_eq!(op.encode(), d, "accepted a non-canonical encoding");
        }
    }
}

// ---------------------------------------------------------------------------
// Vault canonical encoding injectivity
// ---------------------------------------------------------------------------

/// Fast stand-in for a recovery signature: signer + SHA3-free tag.
#[derive(Clone)]
struct Mock {
    signer: Address,
    tag: Vec<u8>,
}
impl RecoveryProof for Mock {
    fn signer(&self) -> Address {
        self.signer.clone()
    }
    fn verify(&self, msg: &[u8]) -> bool {
        self.tag == msg
    }
}

fn random_vault(rng: &mut Rng) -> Vault {
    let me = Address([rng.below(3) as u8; 32]);
    let rec = Address([0xEE; 32]);
    let cold = Address([0xC0 + rng.below(2) as u8; 32]);
    let salt = [rng.below(2) as u8; 32];
    let c = recovery_commitment(CHAIN_ID.as_bytes(), &me, &rec, &cold, &salt);
    let commitment = if rng.below(5) == 0 { None } else { Some(c) };
    let policy = Policy::new(10 + rng.below(3), rng.below(300)).unwrap();
    let mut v = Vault::new(me.clone(), rng.below(2_000), commitment, policy);
    let mut h = rng.below(50);
    for _ in 0..rng.below(25) {
        h += rng.below(6);
        let to = Address([rng.below(4) as u8 + 0x10; 32]);
        match rng.below(7) {
            0 | 1 => { let _ = v.transfer(h, to, rng.below(400)); }
            2 => { let _ = v.charge_fee(rng.below(30)); }
            3 => { let _ = v.credit(rng.below(300)); }
            4 => {
                let ids: Vec<u64> = v.pending().iter().map(|p| p.id).collect();
                if !ids.is_empty() {
                    let _ = v.finalize(h, ids[rng.below(ids.len() as u64) as usize]);
                }
            }
            5 => { let _ = v.request_rotation(h, [rng.below(3) as u8; 32]); }
            _ => {
                if rng.below(4) == 0 {
                    if let Some(cm) = v.commitment().copied() {
                        let msg = recovery_message(CHAIN_ID.as_bytes(), &me, &cm, v.epoch());
                        let _ = v.recover(CHAIN_ID.as_bytes(), &cold, &salt, &Mock { signer: rec.clone(), tag: msg.to_vec() });
                    }
                }
            }
        }
        v.validate().expect("vault invariant broken by public API");
    }
    v
}

#[test]
fn vault_canonical_encoding_is_injective() {
    let mut rng = Rng::new(424242);
    let mut by_enc: HashMap<Vec<u8>, String> = HashMap::new();
    let mut by_json: HashMap<String, Vec<u8>> = HashMap::new();
    for i in 0..20_000 {
        let v = random_vault(&mut rng);
        let enc = v.canonical_encoding();
        let json = serde_json::to_string(&v).unwrap();
        if let Some(prev) = by_enc.get(&enc) {
            assert_eq!(prev, &json, "iteration {i}: two different vaults share a canonical encoding");
        }
        if let Some(prev) = by_json.get(&json) {
            assert_eq!(prev, &enc, "iteration {i}: same vault, two encodings");
        }
        by_enc.insert(enc.clone(), json.clone());
        by_json.insert(json, enc);
    }
    assert!(by_enc.len() > 5_000, "only {} distinct vaults generated", by_enc.len());
}

// ---------------------------------------------------------------------------
// apply_tx fuzz: no panics, supply conserved, failed tx leaves no trace
// ---------------------------------------------------------------------------

struct Recovery {
    account: Address,
    rec: Address,
    cold: Address,
    salt: [u8; 32],
    /// real HYDRA-X recovery signature for epoch 0
    proof: HydraXSignature,
}

/// A few accounts with real recovery keys, signed once (SLH-DSA is slow).
fn recoveries(accts: &[Address]) -> Vec<Recovery> {
    let keys: Vec<HydraXKeypair> = (0..2).map(|_| HydraXKeypair::generate()).collect();
    accts
        .iter()
        .take(2)
        .zip(keys.iter())
        .map(|(a, k)| {
            let cold = accts[accts.len() - 1].clone();
            let salt = [3u8; 32];
            let c = recovery_commitment(CHAIN_ID.as_bytes(), a, &k.address(), &cold, &salt);
            let proof = k.sign(&recovery_message(CHAIN_ID.as_bytes(), a, &c, 0));
            Recovery { account: a.clone(), rec: k.address(), cold, salt, proof }
        })
        .collect()
}

fn total(st: &ChainState) -> u128 {
    st.accounts.values().map(|a| u128::from(a.balance)).sum::<u128>() + u128::from(st.burned)
}

fn fingerprint(st: &ChainState) -> (u64, u64, BTreeMap<String, AccountState>, BTreeMap<String, Vec<u8>>) {
    // Empty accounts left behind by a failed tx would not change the root,
    // but they are still state: compare the full maps.
    (
        st.height,
        st.burned,
        st.accounts.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        st.vaults.iter().map(|(k, v)| (k.clone(), v.canonical_encoding())).collect(),
    )
}

fn check_invariants(st: &ChainState, genesis_total: u128, ctx: &str) {
    assert_eq!(total(st), genesis_total, "{ctx}: supply not conserved");
    for (k, v) in &st.vaults {
        v.validate().unwrap_or_else(|e| panic!("{ctx}: vault {k} invalid: {e}"));
        let acct = st.accounts.get(k).map_or(0, |a| a.balance);
        assert_eq!(acct, v.balance(), "{ctx}: account balance does not mirror vault {k}");
    }
}

/// One random transaction against `st` (sometimes advancing the height):
/// transfers with edge amounts, every Sentinel op with valid and hostile
/// parameters, and junk data.
fn random_tx(rng: &mut Rng, st: &mut ChainState, accts: &[Address], recs: &[Recovery]) -> Transaction {
    if rng.below(4) == 0 {
        st.height += 1 + rng.below(4); // time passes (blocks)
    }
    let from = accts[rng.below(accts.len() as u64) as usize].clone();
    let to = if rng.below(3) == 0 { from.clone() } else { accts[rng.below(accts.len() as u64) as usize].clone() };
    let bal = st.account(&from).balance;
    let nonce = match rng.below(10) {
        0 => rng.next(),
        1 => st.account(&from).nonce.wrapping_add(1),
        _ => st.account(&from).nonce,
    };
    let (amount, data) = match rng.below(10) {
        0..=3 => (rng.amount(bal), vec![]),
        4 => {
            // SetGuardian: valid or hostile params, commitment of a known recovery when possible
            let c = recs
                .iter()
                .find(|r| r.account == from)
                .map(|r| recovery_commitment(CHAIN_ID.as_bytes(), &r.account, &r.rec, &r.cold, &r.salt))
                .unwrap_or_else(|| rng.bytes32());
            let delay = match rng.below(4) { 0 => 0, 1 => u64::MAX, 2 => 10_000_001, _ => 10 + rng.below(5) };
            (0, SentinelOp::SetGuardian { commitment: c, delay_blocks: delay, allowance_per_window: rng.amount(bal) }.encode())
        }
        5 => (0, SentinelOp::RotateGuardian { commitment: rng.bytes32() }.encode()),
        6 => (rng.amount(1), SentinelOp::Finalize { id: rng.below(6) }.encode()),
        7 => {
            let r = &recs[rng.below(recs.len() as u64) as usize];
            let cold = if rng.below(5) == 0 { rng.addr() } else { r.cold.clone() };
            let salt = if rng.below(5) == 0 { rng.bytes32() } else { r.salt };
            (0, SentinelOp::Recover { cold_dest: cold, salt, proof: Box::new(r.proof.clone()) }.encode())
        }
        8 => {
            // UpdatePolicy: tighten, loosen, mixed or out of range
            let delay = match rng.below(4) { 0 => 0, 1 => u64::MAX, 2 => 10_000_001, _ => 10 + rng.below(5) };
            (0, SentinelOp::UpdatePolicy { delay_blocks: delay, allowance_per_window: rng.amount(bal) }.encode())
        }
        _ => {
            let mut d = b"QSN1".to_vec();
            d.extend((0..rng.below(64)).map(|_| rng.next() as u8));
            (0, d)
        }
    };
    // Recover targets the guarded account in `to`
    let to = if data.len() > 1000 { recs[rng.below(recs.len() as u64) as usize].account.clone() } else { to };
    mk_tx(&from, &to, amount, nonce, data)
}

#[test]
fn apply_tx_fuzz_never_panics_conserves_supply_and_rolls_back() {
    let mut rng = Rng::new(0xC0FFEE);
    let accts: Vec<Address> = (0..7).map(|_| rng.addr()).collect();
    let recs = recoveries(&accts);
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    let mut recovered = 0u64;
    let mut vaults_made = 0u64;
    for seed in 0..120u64 {
        let mut rng = Rng::new(seed);
        let mut st = Genesis::testnet_with_faucet(Some(&accts[0].as_hex())).initial_state();
        for a in &accts[1..] {
            st.accounts.insert(a.as_hex(), AccountState { balance: rng.below(5_000_000_000), nonce: 0 });
        }
        let genesis_total = total(&st);
        for step in 0..250 {
            let tx = random_tx(&mut rng, &mut st, &accts, &recs);
            let from = tx.from.clone();
            let before = fingerprint(&st);
            let ctx = format!("seed {seed} step {step}");
            let res = catch_unwind(AssertUnwindSafe(|| st.apply_tx(&tx)))
                .unwrap_or_else(|_| panic!("{ctx}: apply_tx panicked on {tx:?}"));
            match res {
                Ok(()) => {
                    accepted += 1;
                    let rec_now = st.vaults.values().filter(|v| v.is_recovered()).count() as u64;
                    let rec_before = before.3.len() as u64; // vault count before
                    if tx.data.len() > 1000 && rec_now > 0 { recovered += 1; }
                    if st.vaults.len() as u64 > rec_before { vaults_made += 1; }
                    assert_eq!(st.account(&from).nonce, before.2.get(&from.as_hex()).map_or(0, |a| a.nonce) + 1, "{ctx}: nonce");
                }
                Err(_) => {
                    rejected += 1;
                    assert!(fingerprint(&st) == before, "{ctx}: failed tx changed the state");
                }
            }
            check_invariants(&st, genesis_total, &ctx);
        }
    }
    assert!(accepted > 3_000 && rejected > 3_000, "accepted {accepted} rejected {rejected}");
    assert!(vaults_made > 50 && recovered > 5, "coverage: vaults {vaults_made}, recover txs after a recovery {recovered}");
    eprintln!("apply fuzz: accepted {accepted} rejected {rejected} vaults {vaults_made} recover-path {recovered}");
}

/// Same transactions, same block boundaries: same root, every time.
#[test]
fn apply_is_deterministic_across_replays() {
    let mut rng = Rng::new(99);
    let accts: Vec<Address> = (0..5).map(|_| rng.addr()).collect();
    let mut log: Vec<(u64, Transaction)> = Vec::new();
    let mut st = Genesis::testnet_with_faucet(Some(&accts[0].as_hex())).initial_state();
    for _ in 0..400 {
        if rng.below(3) == 0 {
            st.height += 1;
        }
        let from = accts[rng.below(5) as usize].clone();
        let to = accts[rng.below(5) as usize].clone();
        let tx = mk_tx(&from, &to, rng.amount(st.account(&from).balance), st.account(&from).nonce, vec![]);
        if st.apply_tx(&tx).is_ok() {
            log.push((st.height, tx));
        }
    }
    let root = st.state_root();
    for _ in 0..3 {
        let mut r = Genesis::testnet_with_faucet(Some(&accts[0].as_hex())).initial_state();
        for (h, tx) in &log {
            r.height = *h;
            r.apply_tx(tx).expect("replay of an accepted tx failed");
        }
        assert_eq!(r.state_root(), root);
    }
}

/// Per-block work that grows with the number of accounts: the proposer
/// and the committer each clone the whole ChainState, and the state tree
/// is rebuilt from scratch (sort + hash every account) for every block.
/// Accounts cost an attacker one fee each (0.01 QTR), and a 0-amount
/// transfer to a fresh address leaves an empty map entry that is cloned
/// forever but never committed in the root.
#[test]
#[ignore = "measurement"]
fn dos_per_block_state_cost_vs_account_count() {
    for n in [10_000usize, 100_000, 1_000_000] {
        let mut rng = Rng::new(n as u64);
        let (st, _) = random_state(&mut rng, n);
        let t = std::time::Instant::now();
        let c1 = st.clone();
        let c2 = st.clone();
        let clones = t.elapsed();
        let t = std::time::Instant::now();
        let tree = c1.state_tree();
        let build = t.elapsed();
        std::hint::black_box((&c2, tree.root()));
        // A 0-amount transfer to a fresh address: what remains in the map
        let mut s = st.clone();
        let from = s.accounts.keys().next().cloned().map(|k| Address::from_hex(&k).unwrap()).unwrap();
        let before = s.accounts.len();
        let fresh = rng.addr();
        s.apply_tx(&mk_tx(&from, &fresh, 0, s.account(&from).nonce, vec![])).unwrap();
        eprintln!(
            "{n} accounts: 2 state clones {clones:?}, tree build {build:?}; 0-amount tx to a new address grows the map by {} (empty entry kept: {})",
            s.accounts.len() - before,
            s.accounts.get(&fresh.as_hex()).is_some_and(|a| a.balance == 0 && a.nonce == 0)
        );
    }
}

/// The node keeps the state tree between blocks and only updates the
/// accounts each block touched. That must give exactly the tree a full
/// rebuild gives: same root, same proofs, after every block, across
/// thousands of random transactions (transfers, every Sentinel op, junk).
#[test]
fn incremental_state_tree_matches_full_rebuild() {
    let mut rng = Rng::new(0x5EED);
    let accts: Vec<Address> = (0..7).map(|_| rng.addr()).collect();
    let recs = recoveries(&accts);
    let mut blocks = 0u64;
    let mut reshaped = 0u64;
    for seed in 0..60u64 {
        let mut rng = Rng::new(seed ^ 0xABCD);
        let mut st = Genesis::testnet_with_faucet(Some(&accts[0].as_hex())).initial_state();
        for a in &accts[1..4] {
            st.accounts.insert(a.as_hex(), AccountState { balance: rng.below(5_000_000_000), nonce: 0 });
        }
        let mut tree = st.state_tree();
        st.take_touched();
        for block in 0..40 {
            for _ in 0..rng.below(12) {
                let tx = random_tx(&mut rng, &mut st, &accts, &recs);
                let _ = st.apply_tx(&tx);
            }
            let before = tree.len();
            let touched = st.take_touched();
            tree = tree.updated(&st, &touched);
            let full = st.state_tree();
            let ctx = format!("seed {seed} block {block}");
            assert_eq!(tree.root(), full.root(), "{ctx}: root differs from a full rebuild");
            for a in &accts {
                assert_eq!(tree.proof(a), full.proof(a), "{ctx}: proof differs");
            }
            reshaped += u64::from(tree.len() != before);
            blocks += 1;
        }
    }
    assert!(reshaped > 20, "coverage: accounts appeared in only {reshaped} of {blocks} blocks");
}

/// An account that becomes empty leaves the tree; the incremental path
/// must remove it exactly like a rebuild does.
#[test]
fn incremental_state_tree_handles_removed_and_untouched_accounts() {
    let mut rng = Rng::new(7);
    let (mut st, addrs) = random_state(&mut rng, 40);
    let tree = st.state_tree();
    let gone = addrs[5].as_hex();
    st.accounts.insert(gone.clone(), AccountState::default());
    let changed = addrs[9].as_hex();
    st.accounts.get_mut(&changed).unwrap().balance += 1;
    let touched = [gone, changed, Address([0xAB; 32]).as_hex(), "not-hex".to_string()].into_iter().collect();
    let inc = tree.updated(&st, &touched);
    assert_eq!(inc.root(), st.state_tree().root());
    assert_eq!(inc.len(), 39);
    // Nothing touched: same tree.
    assert_eq!(inc.updated(&st, &Default::default()).root(), inc.root());
}

/// Cost of one block's tree update vs a full rebuild (prints timings).
/// `cargo test --release -p qtrc-common --test adversarial_props -- --ignored tree_update_cost --nocapture`
#[test]
#[ignore = "measurement"]
fn tree_update_cost() {
    use std::time::Instant;
    for n in [10_000usize, 100_000, 1_000_000] {
        let mut rng = Rng::new(n as u64);
        let (mut st, addrs) = random_state(&mut rng, n);
        let t = Instant::now();
        let tree = st.state_tree();
        let full = t.elapsed();
        // 500 balance changes, no new account.
        let touched: std::collections::BTreeSet<String> =
            (0..500).map(|i| addrs[(i * 7919) % n].as_hex()).collect();
        for k in &touched {
            st.accounts.get_mut(k).unwrap().balance += 1;
        }
        let t = Instant::now();
        let same_shape = tree.updated(&st, &touched);
        let upd = t.elapsed();
        // Same, plus one new account (positions shift).
        let fresh = rng.addr().as_hex();
        st.accounts.insert(fresh.clone(), AccountState { balance: 1, nonce: 0 });
        let mut touched2 = touched.clone();
        touched2.insert(fresh);
        let t = Instant::now();
        let reshaped = tree.updated(&st, &touched2);
        let resh = t.elapsed();
        assert_eq!(reshaped.root(), st.state_tree().root());
        drop(same_shape);
        eprintln!("n={n:>9}: full rebuild {full:?}, 500 updates {upd:?}, 500 updates + 1 new account {resh:?}");
    }
}
