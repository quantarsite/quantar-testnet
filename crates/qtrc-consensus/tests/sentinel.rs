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
    assert!(err.contains("insufficient"), "{err}");

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

    // The cancelled transfer cannot be finalized: refused at admission.
    assert!(net.submit(tx(&rescuer, &owner, 0, 1, SentinelOp::Finalize { id: 0 }.encode())).is_err());
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

    // Too early: included, pays the fee, changes nothing else.
    let stranger = HydraXKeypair::generate();
    net.fund(&stranger.address(), 1);
    net.mine().unwrap();
    net.submit(tx(&stranger, &owner, 0, 0, SentinelOp::Finalize { id: 0 }.encode())).unwrap();
    net.mine().unwrap();
    assert_eq!(net.balance(&shop), 0);
    assert_eq!(net.balance(&stranger.address()), MICRO_QTR - TX_FEE, "a failed operation still pays");

    while net.height() + 1 < queued_at + DELAY {
        net.advance(1);
    }
    net.submit(tx(&stranger, &owner, 0, 1, SentinelOp::Finalize { id: 0 }.encode())).unwrap();
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

    // Operations that could not apply are refused at admission.
    let again = SentinelOp::SetGuardian { commitment: [2; 32], delay_blocks: DELAY, allowance_per_window: 0 };
    assert!(net.submit(tx(&g.owner, &owner, 0, net.nonce(&owner), again.encode())).is_err());
    let bad_policy = SentinelOp::SetGuardian { commitment: [2; 32], delay_blocks: 0, allowance_per_window: 0 };
    let fresh = HydraXKeypair::generate();
    net.fund(&fresh.address(), 1);
    net.mine().unwrap();
    assert!(net.submit(tx(&fresh, &fresh.address(), 0, 0, bad_policy.encode())).is_err());
    let no_vault = SentinelOp::RotateGuardian { commitment: [3; 32] };
    assert!(net.submit(tx(&fresh, &fresh.address(), 0, 0, no_vault.encode())).is_err());
    assert!(net.submit(tx(&fresh, &other, 0, 0, SentinelOp::Finalize { id: 0 }.encode())).is_err());

    // Recovery into the account itself, and with a forged destination.
    let mut bad = recover_op(&g, 0);
    if let Ok(SentinelOp::Recover { proof, salt, .. }) = SentinelOp::decode(&bad) {
        bad = SentinelOp::Recover { cold_dest: other.clone(), salt, proof }.encode();
    }
    let r = HydraXKeypair::generate();
    net.fund(&r.address(), 1);
    net.mine().unwrap();
    assert!(net.submit(tx(&r, &owner, 0, 0, bad)).is_err(), "redirected recovery is refused");
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
fn failed_operation_pays_and_rolls_back_its_effects() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 100);
    let owner = g.owner.address();
    let r = HydraXKeypair::generate();
    net.fund(&r.address(), 1);
    net.mine().unwrap();
    let before = net.engine.state.read().clone();
    // Valid signature for the wrong epoch: fee and nonce are charged, the
    // recovery itself has no effect.
    let mut st = before.clone();
    let t = tx(&r, &owner, 0, 0, recover_op(&g, 5));
    st.apply_tx(&t).unwrap();
    assert_eq!(st.account(&r.address()).balance, MICRO_QTR - TX_FEE);
    assert_eq!(st.account(&r.address()).nonce, 1);
    assert_eq!(st.burned, before.burned + TX_FEE);
    assert_eq!(
        serde_json::to_value(&st.vaults).unwrap(),
        serde_json::to_value(&before.vaults).unwrap(),
        "vault untouched"
    );
    assert_eq!(st.account(&owner), before.account(&owner));
    // The same tx cannot be replayed (nonce consumed).
    assert!(st.apply_tx(&t).is_err());
}

/// Regression D1: an operation that passes admission but fails in the
/// block is not free. Two finalizes of the same id in one block: the
/// second fails and still pays.
#[test]
fn racing_operations_pay_even_when_they_lose() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 1_000);
    let owner = g.owner.address();
    let shop = HydraXKeypair::generate().address();
    net.submit(tx(&g.owner, &shop, 400 * MICRO_QTR, net.nonce(&owner), vec![])).unwrap();
    net.mine().unwrap();
    let unlock = net.height() + DELAY;
    let (a, b) = (HydraXKeypair::generate(), HydraXKeypair::generate());
    net.fund(&a.address(), 1);
    net.fund(&b.address(), 1);
    net.mine().unwrap();
    while net.height() + 1 < unlock {
        net.advance(1);
    }
    net.submit(tx(&a, &owner, 0, 0, SentinelOp::Finalize { id: 0 }.encode())).unwrap();
    net.submit(tx(&b, &owner, 0, 0, SentinelOp::Finalize { id: 0 }.encode())).unwrap();
    let block = net.mine().unwrap();
    assert_eq!(block.transactions.len(), 2, "the losing finalize is included");
    assert_eq!(net.balance(&shop), 400 * MICRO_QTR, "paid once");
    assert_eq!(net.balance(&b.address()), MICRO_QTR - TX_FEE, "the loser paid its fee");
}

/// Regression A1: the guarded account can submit its own recovery even when
/// a thief has locked every unlocked micro-QTR; the fee comes out of the
/// recovered amount.
#[test]
fn self_recovery_works_with_nothing_unlocked() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 1_000);
    let owner = g.owner.address();
    let thief = HydraXKeypair::generate().address();
    let avail = net.engine.state.read().spendable(&owner);
    // Thief: spend the allowance, then queue everything else.
    net.submit(tx(&g.owner, &thief, ALLOWANCE, net.nonce(&owner), vec![])).unwrap();
    net.submit(tx(&g.owner, &thief, avail - ALLOWANCE - 2 * TX_FEE, net.nonce(&owner), vec![])).unwrap();
    net.mine().unwrap();
    assert_eq!(net.engine.state.read().spendable(&owner), 0);
    let total = net.balance(&owner);

    net.submit(tx(&g.owner, &owner, 0, net.nonce(&owner), recover_op(&g, 0))).unwrap();
    net.mine().unwrap();
    assert_eq!(net.balance(&g.cold), total - TX_FEE);
    assert_eq!(net.balance(&thief), ALLOWANCE);
}

/// Regression M2: forwarding never grows into a chain.
#[test]
fn forwarding_is_compressed_to_one_hop() {
    let mut net = Net::new(|_| {});
    // B is a guarded account whose own cold address is C.
    let b = guarded(&mut net, 10);
    let rescuer = HydraXKeypair::generate();
    net.fund(&rescuer.address(), 1);
    net.mine().unwrap();

    // A2 is guarded with B as its cold address. A2 recovers into B
    // (allowed: B is active), then B recovers into C.
    let a2 = HydraXKeypair::generate();
    let rec2 = HydraXKeypair::generate();
    net.fund(&a2.address(), 10);
    net.mine().unwrap();
    let c2 = recovery_commitment(CHAIN_ID.as_bytes(), &a2.address(), &rec2.address(), &b.owner.address(), &SALT);
    let set = SentinelOp::SetGuardian { commitment: c2, delay_blocks: DELAY, allowance_per_window: 0 };
    net.submit(tx(&a2, &a2.address(), 0, 0, set.encode())).unwrap();
    net.mine().unwrap();
    let msg = recovery_message(CHAIN_ID.as_bytes(), &a2.address(), &c2, 0);
    let rec_a2 = SentinelOp::Recover { cold_dest: b.owner.address(), salt: SALT, proof: Box::new(rec2.sign(&msg)) };
    net.submit(tx(&rescuer, &a2.address(), 0, 0, rec_a2.encode())).unwrap();
    net.mine().unwrap();
    net.submit(tx(&rescuer, &b.owner.address(), 0, 1, recover_op(&b, 0))).unwrap();
    net.mine().unwrap();

    let st = net.engine.state.read();
    assert_eq!(st.vault(&a2.address()).unwrap().recovered_to(), Some(&b.cold), "A2 now points straight at C");
    drop(st);
    let before = net.balance(&b.cold);
    net.fund(&a2.address(), 3);
    net.mine().unwrap();
    assert_eq!(net.balance(&b.cold), before + 3 * MICRO_QTR);
}

#[test]
fn oversized_data_is_refused() {
    let net = Net::new(|_| {});
    let me = net.faucet.address();
    let mut big = qtrc_common::sentinel::MAGIC.to_vec();
    big.resize(qtrc_common::state::MAX_DATA_LEN + 1, 0);
    let err = net.submit(tx(&net.faucet, &me, 0, 0, big)).unwrap_err();
    assert!(err.contains("larger than"), "{err}");
}

/// Regression N1 (1, 2): plain transfers a vault would refuse are refused
/// at admission, and if one slips into a block anyway (state changed in
/// between) it is included and pays.
#[test]
fn guarded_plain_transfers_are_never_free() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 5_000);
    let owner = g.owner.address();
    let sink = HydraXKeypair::generate().address();
    // Zero amount: refused at admission.
    assert!(net.submit(tx(&g.owner, &sink, 0, net.nonce(&owner), vec![])).is_err());

    // Applied directly (as if admitted earlier): included, fee charged.
    let mut st = net.engine.state.read().clone();
    let before = st.account(&owner);
    st.apply_tx(&tx(&g.owner, &sink, 0, before.nonce, vec![])).unwrap();
    assert_eq!(st.account(&owner).nonce, before.nonce + 1);
    assert_eq!(st.account(&owner).balance, before.balance - TX_FEE);

    // Full queue: refused at admission.
    let mut st = net.engine.state.read().clone();
    let mut n = st.account(&owner).nonce;
    for _ in 0..qtrc_sentinel::MAX_PENDING {
        st.apply_tx(&tx(&g.owner, &sink, ALLOWANCE + 1, n, vec![])).unwrap();
        n += 1;
    }
    let pending = st.vault(&owner).unwrap().pending().len();
    assert_eq!(pending, qtrc_sentinel::MAX_PENDING);
    let t = tx(&g.owner, &sink, ALLOWANCE + 1, n, vec![]);
    assert!(st.check_guarded_transfer(&t, TX_FEE).is_err());
    let bal = st.account(&owner).balance;
    st.apply_tx(&t).unwrap();
    assert_eq!(st.account(&owner).balance, bal - TX_FEE, "refused by the vault but paid");
    assert_eq!(st.vault(&owner).unwrap().pending().len(), pending);
}

/// Regression N1 (3): a self-submitted recovery needs the fee in the vault.
#[test]
fn self_recovery_with_empty_vault_is_refused() {
    let mut net = Net::new(|_| {});
    let g = guarded(&mut net, 1);
    let owner = g.owner.address();
    // Empty the vault: allowance covers everything that is left.
    let all = net.engine.state.read().spendable(&owner) - TX_FEE;
    net.submit(tx(&g.owner, &HydraXKeypair::generate().address(), all, net.nonce(&owner), vec![])).unwrap();
    net.mine().unwrap();
    assert_eq!(net.balance(&owner), 0);
    let err = net.submit(tx(&g.owner, &owner, 0, net.nonce(&owner), recover_op(&g, 0))).unwrap_err();
    assert!(err.contains("insufficient"), "{err}");
    let mut st = net.engine.state.read().clone();
    assert!(st.apply_tx(&tx(&g.owner, &owner, 0, net.nonce(&owner), recover_op(&g, 0))).is_err());
}

/// Recoveries above MAX_RECOVERS_PER_BLOCK wait for the next block, along
/// with later txs from the same sender, without losing any.
#[test]
fn recoveries_are_capped_per_block_without_losing_txs() {
    use qtrc_consensus::MAX_RECOVERS_PER_BLOCK;
    let mut net = Net::new(|_| {});
    let n = MAX_RECOVERS_PER_BLOCK + 1;
    let owners: Vec<(HydraXKeypair, HydraXKeypair, Address)> = (0..n)
        .map(|_| (HydraXKeypair::generate(), HydraXKeypair::generate(), HydraXKeypair::generate().address()))
        .collect();
    // Three rescuers: the per-sender pending limit is 16.
    let rescuers: Vec<HydraXKeypair> = (0..3).map(|_| HydraXKeypair::generate()).collect();
    for (i, (o, _, _)) in owners.iter().enumerate() {
        net.fund(&o.address(), 1);
        if i % 15 == 14 {
            net.mine().unwrap();
        }
    }
    for r in &rescuers {
        net.fund(&r.address(), 10);
    }
    net.mine().unwrap();
    let mut commits = vec![];
    for (o, r, cold) in &owners {
        let c = recovery_commitment(CHAIN_ID.as_bytes(), &o.address(), &r.address(), cold, &SALT);
        let op = SentinelOp::SetGuardian { commitment: c, delay_blocks: DELAY, allowance_per_window: 0 };
        net.submit(tx(o, &o.address(), 0, 0, op.encode())).unwrap();
        commits.push(c);
    }
    net.mine().unwrap();
    // Rescuer i handles owners 16*i .. 16*i+15; the last one gets the
    // recovery over the cap.
    let mut nonces = [0u64; 3];
    for (i, ((o, r, cold), c)) in owners.iter().zip(&commits).enumerate() {
        let msg = recovery_message(CHAIN_ID.as_bytes(), &o.address(), c, 0);
        let op = SentinelOp::Recover { cold_dest: cold.clone(), salt: SALT, proof: Box::new(r.sign(&msg)) };
        let k = i / 16;
        net.submit(tx(&rescuers[k], &o.address(), 0, nonces[k], op.encode())).unwrap();
        nonces[k] += 1;
    }
    // A plain transfer from the last rescuer after its held recovery.
    let tail = HydraXKeypair::generate().address();
    let last = n / 16;
    net.submit(tx(&rescuers[last], &tail, MICRO_QTR, nonces[last], vec![])).unwrap();

    let first = net.mine().unwrap();
    assert_eq!(first.transactions.len(), MAX_RECOVERS_PER_BLOCK);
    let second = net.mine().unwrap();
    assert_eq!(second.transactions.len(), 2, "held recovery and the tx after it");
    for (_, _, cold) in &owners {
        assert!(net.balance(cold) > 0);
    }
    assert_eq!(net.balance(&tail), MICRO_QTR);
}
