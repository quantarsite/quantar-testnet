//! Sentinel wired into consensus, end to end, with real HYDRA-X keys:
//! mempool admission, block application, recovery, forwarding, activation
//! height and replay.

use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::sentinel::SentinelOp;
use qtrc_common::state::ChainState;
use qtrc_common::tx::{Transaction, CHAIN_ID, TX_FEE};
use qtrc_consensus::ConsensusEngine;
use qtrc_crypto::{Address, HydraXKeypair};
use qtrc_sentinel::{recovery_commitment, recovery_message};

const DELAY: u64 = 10;
const ALLOWANCE: u64 = 50 * MICRO_QTR;
const SALT: [u8; 32] = [7u8; 32];

fn tx(kp: &HydraXKeypair, to: &Address, amount: u64, nonce: u64, data: Vec<u8>) -> Transaction {
    let from = kp.address();
    let payload = Transaction::signing_payload_with_data(&from, to, amount, nonce, &data);
    Transaction { from, to: to.clone(), amount, nonce, timestamp: 0, signature: kp.sign(&payload), data }
}

struct Net {
    engine: ConsensusEngine,
    faucet: HydraXKeypair,
    faucet_nonce: u64,
    sink: Address,
}

impl Net {
    fn new(mutate: impl FnOnce(&mut ChainState)) -> Self {
        let faucet = HydraXKeypair::generate();
        let g = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
        let mut st = g.initial_state();
        mutate(&mut st);
        Net {
            engine: ConsensusEngine::new(st, HydraXKeypair::generate()),
            faucet,
            faucet_nonce: 0,
            sink: HydraXKeypair::generate().address(),
        }
    }

    fn submit(&self, t: Transaction) -> Result<(), String> {
        self.engine.submit_tx(t).map(|_| ()).map_err(|e| e.to_string())
    }

    /// Propose and commit one block with whatever is in the mempool.
    fn mine(&self) -> Result<qtrc_common::block::Block, String> {
        let b = self.engine.propose_block().map_err(|e| e.to_string())?;
        self.engine.commit_block(b.clone()).map_err(|e| e.to_string())?;
        Ok(b)
    }

    fn fund(&mut self, to: &Address, qtr: u64) {
        let t = tx(&self.faucet, to, qtr * MICRO_QTR, self.faucet_nonce, vec![]);
        self.faucet_nonce += 1;
        self.submit(t).unwrap();
    }

    /// Mine `n` blocks of filler so the height advances.
    fn advance(&mut self, n: u64) {
        for _ in 0..n {
            let sink = self.sink.clone();
            self.fund(&sink, 1);
            self.mine().unwrap();
        }
    }

    fn height(&self) -> u64 {
        self.engine.state.read().height
    }
    fn balance(&self, a: &Address) -> u64 {
        self.engine.state.read().account(a).balance
    }
    fn nonce(&self, a: &Address) -> u64 {
        self.engine.next_nonce(a)
    }
}

struct Guarded {
    owner: HydraXKeypair,
    recovery: HydraXKeypair,
    cold: Address,
    commitment: [u8; 32],
}

/// Fund an owner with `qtr` and set up its guardian.
fn guarded(net: &mut Net, qtr: u64) -> Guarded {
    let owner = HydraXKeypair::generate();
    let recovery = HydraXKeypair::generate();
    let cold = HydraXKeypair::generate().address();
    net.fund(&owner.address(), qtr);
    net.mine().unwrap();
    let commitment = recovery_commitment(CHAIN_ID.as_bytes(), &owner.address(), &recovery.address(), &cold, &SALT);
    let op = SentinelOp::SetGuardian { commitment, delay_blocks: DELAY, allowance_per_window: ALLOWANCE };
    net.submit(tx(&owner, &owner.address(), 0, net.nonce(&owner.address()), op.encode())).unwrap();
    net.mine().unwrap();
    assert!(net.engine.state.read().vault(&owner.address()).is_some());
    Guarded { owner, recovery, cold, commitment }
}

fn recover_op(g: &Guarded, epoch: u64) -> Vec<u8> {
    let msg = recovery_message(CHAIN_ID.as_bytes(), &g.owner.address(), &g.commitment, epoch);
    SentinelOp::Recover { cold_dest: g.cold.clone(), salt: SALT, proof: Box::new(g.recovery.sign(&msg)) }.encode()
}

#[test]
fn stolen_key_drain_is_stopped_by_recovery() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 1_000);
    let owner = g.owner.address();
    let thief = HydraXKeypair::generate().address();
    let after_setup = net.balance(&owner);
    assert_eq!(after_setup, 1_000 * MICRO_QTR - TX_FEE);

    // Thief with the main key: allowance leaves, the rest is queued.
    net.submit(tx(&g.owner, &thief, 30 * MICRO_QTR, net.nonce(&owner), vec![])).unwrap();
    net.submit(tx(&g.owner, &thief, 900 * MICRO_QTR, net.nonce(&owner), vec![])).unwrap();
    net.mine().unwrap();
    assert_eq!(net.balance(&thief), 30 * MICRO_QTR, "only the allowance left");
    let v = net.engine.state.read().vault(&owner).cloned().unwrap();
    assert_eq!(v.reserved(), 900 * MICRO_QTR);
    assert_eq!(v.pending().len(), 1);

    // Admission refuses to spend locked funds.
    let err = net.submit(tx(&g.owner, &thief, 100 * MICRO_QTR, net.nonce(&owner), vec![])).unwrap_err();
    assert!(err.contains("insufficient balance"), "{err}");

    // A rescuer (any funded account) submits the recovery and pays the fee,
    // even though the guarded account has nothing unlocked for fees.
    let rescuer = HydraXKeypair::generate();
    net.fund(&rescuer.address(), 1);
    net.mine().unwrap();
    net.submit(tx(&rescuer, &owner, 0, 0, recover_op(&g, 0))).unwrap();
    net.mine().unwrap();

    let expected = after_setup - 30 * MICRO_QTR - 2 * TX_FEE;
    assert_eq!(net.balance(&g.cold), expected, "everything else reached cold storage");
    assert_eq!(net.balance(&owner), 0);
    assert_eq!(net.balance(&thief), 30 * MICRO_QTR, "queued 900 never left");
    assert_eq!(net.balance(&rescuer.address()), MICRO_QTR - TX_FEE);

    // Later deposits to the recovered account are forwarded.
    net.fund(&owner, 5);
    net.mine().unwrap();
    assert_eq!(net.balance(&g.cold), expected + 5 * MICRO_QTR);
    assert_eq!(net.balance(&owner), 0);

    // The thief cannot finalize the cancelled transfer.
    net.submit(tx(&rescuer, &owner, 0, 1, SentinelOp::Finalize { id: 0 }.encode())).unwrap();
    assert!(net.mine().is_err(), "invalid finalize is dropped, block has nothing else");
}

#[test]
fn queued_transfer_settles_after_delay_and_anyone_can_finalize() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 1_000);
    let owner = g.owner.address();
    let shop = HydraXKeypair::generate().address();

    net.submit(tx(&g.owner, &shop, 400 * MICRO_QTR, net.nonce(&owner), vec![])).unwrap();
    net.mine().unwrap();
    let queued_at = net.height();
    assert_eq!(net.balance(&shop), 0);

    // Too early: the finalize is dropped.
    let stranger = HydraXKeypair::generate();
    net.fund(&stranger.address(), 1);
    net.mine().unwrap();
    net.submit(tx(&stranger, &owner, 0, 0, SentinelOp::Finalize { id: 0 }.encode())).unwrap();
    assert!(net.mine().is_err());

    while net.height() + 1 < queued_at + DELAY {
        net.advance(1);
    }
    net.submit(tx(&stranger, &owner, 0, 0, SentinelOp::Finalize { id: 0 }.encode())).unwrap();
    net.mine().unwrap();
    assert_eq!(net.balance(&shop), 400 * MICRO_QTR);
    assert_eq!(net.engine.state.read().vault(&owner).unwrap().reserved(), 0);
}

#[test]
fn incoming_payments_to_a_guarded_account_are_held() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 100);
    let owner = g.owner.address();
    let before = net.balance(&owner);
    net.fund(&owner, 25);
    net.mine().unwrap();
    let st = net.engine.state.read();
    assert_eq!(st.account(&owner).balance, before + 25 * MICRO_QTR);
    assert_eq!(st.vault(&owner).unwrap().balance(), before + 25 * MICRO_QTR, "account mirrors vault");
}

#[test]
fn invalid_operations_are_refused() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 100);
    let owner = g.owner.address();
    let other = HydraXKeypair::generate().address();

    // Garbage payload, value on an operation, guardian op aimed elsewhere.
    assert!(net.submit(tx(&g.owner, &owner, 0, net.nonce(&owner), b"QSN1junk".to_vec())).is_err());
    let rot = SentinelOp::RotateGuardian { commitment: [1; 32] }.encode();
    assert!(net.submit(tx(&g.owner, &owner, 5, net.nonce(&owner), rot.clone())).is_err());
    assert!(net.submit(tx(&g.owner, &other, 0, net.nonce(&owner), rot)).is_err());

    // Second SetGuardian on the same account is dropped at apply.
    let again = SentinelOp::SetGuardian { commitment: [2; 32], delay_blocks: DELAY, allowance_per_window: 0 };
    net.submit(tx(&g.owner, &owner, 0, net.nonce(&owner), again.encode())).unwrap();
    assert!(net.mine().is_err());

    // Recovery into the account itself, and with a forged destination.
    let mut bad = recover_op(&g, 0);
    if let Ok(SentinelOp::Recover { proof, salt, .. }) = SentinelOp::decode(&bad) {
        bad = SentinelOp::Recover { cold_dest: other.clone(), salt, proof }.encode();
    }
    let r = HydraXKeypair::generate();
    net.fund(&r.address(), 1);
    net.mine().unwrap();
    net.submit(tx(&r, &owner, 0, 0, bad)).unwrap();
    assert!(net.mine().is_err(), "redirected recovery must fail");
    assert!(net.engine.state.read().vault(&owner).unwrap().commitment().is_some());
}

#[test]
fn sentinel_activates_at_height_and_replays_identically() {
    let node_key = HydraXKeypair::generate().to_bytes();
    let faucet = HydraXKeypair::generate();
    let g = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let mut st = g.initial_state();
    st.sentinel_from_height = 3;

    let a = ConsensusEngine::new(st.clone(), HydraXKeypair::from_bytes(&node_key).unwrap());
    let recovery = HydraXKeypair::generate();
    let cold = HydraXKeypair::generate().address();
    let me = faucet.address();
    let c = recovery_commitment(CHAIN_ID.as_bytes(), &me, &recovery.address(), &cold, &SALT);
    let op = SentinelOp::SetGuardian { commitment: c, delay_blocks: DELAY, allowance_per_window: ALLOWANCE }.encode();

    // Block 1: refused at admission.
    let err = a.submit_tx(tx(&faucet, &me, 0, 0, op.clone())).unwrap_err().to_string();
    assert!(err.contains("not active"), "{err}");

    let filler = HydraXKeypair::generate().address();
    let mut blocks = vec![];
    for n in 0..2 {
        a.submit_tx(tx(&faucet, &filler, MICRO_QTR, n, vec![])).unwrap();
        let b = a.propose_block().unwrap();
        a.commit_block(b.clone()).unwrap();
        blocks.push(b);
    }
    // Block 3: accepted.
    a.submit_tx(tx(&faucet, &me, 0, 2, op)).unwrap();
    let b = a.propose_block().unwrap();
    a.commit_block(b.clone()).unwrap();
    blocks.push(b);
    assert!(a.state.read().vault(&me).is_some());

    let replica = ConsensusEngine::new(st, HydraXKeypair::from_bytes(&node_key).unwrap());
    for b in blocks {
        replica.replay_block(b).unwrap();
    }
    let (sa, sb) = (a.state.read(), replica.state.read());
    assert_eq!(serde_json::to_value(&sa.vaults).unwrap(), serde_json::to_value(&sb.vaults).unwrap());
    assert_eq!(sa.account(&me), sb.account(&me));
    assert_eq!(sa.burned, sb.burned);
}

#[test]
fn failed_operation_leaves_state_untouched() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 100);
    let owner = g.owner.address();
    let r = HydraXKeypair::generate();
    net.fund(&r.address(), 1);
    net.mine().unwrap();
    let before = serde_json::to_value(&*net.engine.state.read()).unwrap();
    // Recovery with a valid signature for the wrong epoch: the submitter's
    // fee and nonce are applied first, then the op fails. Nothing may stick.
    let mut scratch = net.engine.state.read().clone();
    let t = tx(&r, &owner, 0, 0, recover_op(&g, 5));
    assert!(scratch.apply_tx(&t).is_err());
    assert_eq!(serde_json::to_value(&scratch).unwrap(), before);
}
