//! # qtrc-consensus — Proof-of-Authority consensus
//!
//! Round-robin validator rotation. Every `BLOCK_TIME_SECS` seconds
//! the next validator in the registered set proposes a block.
//! A block is finalized when ≥ 2/3 of validators sign it.
//!
//! All block proposals and vote signatures are HYDRA-X AND-composed.

mod adapter;

use hx_mempool::{
    ingestion::{IngestionPipeline, IngestResult, PqCryptoVerifier},
    pool::TxPool,
    sig_cache::{HydraXSigCache, SigCacheConfig},
};
use parking_lot::{Mutex, RwLock};
use qtrc_common::state_root::StateTree;
use qtrc_common::{
    block::{Block, BlockHeader, ValidatorSig},
    state::ChainState,
    tx::{Transaction, TxHash},
};
use qtrc_crypto::{Address, HydraXKeypair};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Block time in seconds.
pub const BLOCK_TIME_SECS: u64 = 5;
/// Most transactions one block may carry.
pub const MAX_TXS_PER_BLOCK: usize = 500;
pub mod mempool;
pub use mempool::{Mempool, MAX_MEMPOOL, MAX_MEMPOOL_BYTES, RECOVERY_RESERVE};
/// Most transactions one sender may have waiting at once.
pub const MAX_PENDING_PER_SENDER: usize = 16;
/// Most Sentinel recoveries per block. Each carries a second HYDRA-X
/// signature (~37 KB); the rest wait for the next block.
pub const MAX_RECOVERS_PER_BLOCK: usize = 32;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Not the current proposer for height {height}")]
    NotProposer { height: u64 },
    #[error("Invalid block height: expected {expected}, got {got}")]
    WrongHeight { expected: u64, got: u64 },
    #[error("Block signature invalid: {0}")]
    InvalidSig(String),
    #[error("Insufficient validator signatures: need {need}, got {got}")]
    InsufficientSigs { need: usize, got: usize },
    #[error("Block transactions invalid: {0}")]
    InvalidTx(String),
    #[error("Block storage failed: {0}")]
    Storage(String),
    #[error("Node busy: {0}")]
    Busy(String),
}

/// A block that passed every check, and the state after it.
struct Checked {
    next: ChainState,
    tree: Option<Arc<StateTree>>,
}

/// The last committed block's header and signatures, with the state tree
/// its root was computed from (None before state-root activation). Proofs
/// are served from here, without touching the live state.
#[derive(Clone)]
struct LastBlock {
    header: BlockHeader,
    sigs:   Vec<ValidatorSig>,
    tree:   Option<Arc<StateTree>>,
    from:   u64,
}

/// Durable storage for committed blocks.
///
/// `commit_block` calls `persist` after the block is validated and applied to
/// a copy of the state, and before that copy replaces the live state. If
/// `persist` fails, the block is not committed, so the in-memory chain never
/// gets ahead of what is on disk.
pub trait BlockSink: Send + Sync {
    fn persist(&self, block: &Block) -> Result<(), String>;
}

/// The consensus engine — holds chain state, mempool, and ingestion pipeline.
pub struct ConsensusEngine {
    /// Current chain state (append-only, updated on commit)
    pub state:   Arc<RwLock<ChainState>>,
    /// Pending transactions: queued for the next block, or in flight in
    /// the block being built (they still count as pending until it commits
    /// or fails, so `next_nonce` never hands out a nonce already in use).
    pub mempool: Arc<RwLock<Mempool>>,
    /// This node's keypair (used when this node is the proposer)
    keypair:     Arc<HydraXKeypair>,
    /// This node's address
    pub address: Address,
    /// hx-mempool ingestion pipeline — parallel PQ-sig verification,
    /// deduplication, and two-tier signature cache.
    pipeline:    Arc<IngestionPipeline<PqCryptoVerifier>>,
    /// Where committed blocks are written (None = memory only, e.g. tests)
    sink:        Option<Arc<dyn BlockSink>>,
    /// hx-mempool pool and signature cache, pruned when txs leave the
    /// mempool so they never linger (and a dropped tx can be resubmitted)
    hx_pool:     Arc<TxPool>,
    sig_cache:   Arc<HydraXSigCache>,
    /// Header and signatures of the last committed block, kept together
    /// with the state they describe (both change under the state lock), so
    /// state proofs can be served with the header that signs their root.
    last_block:  RwLock<Option<LastBlock>>,
    /// State tree of the block this node last proposed, so committing its
    /// own block does not build the same tree twice.
    proposed_tree: Mutex<Option<Arc<StateTree>>>,
    /// Serializes the admission checks so two submits can't both pass them
    submit_lock: Mutex<()>,
    /// Cleared by the node when disk space runs low
    accepting:   AtomicBool,
    /// Height of the last committed block, for whoever wants to react to
    /// new blocks (e.g. announcing them to followers).
    commits:     tokio::sync::watch::Sender<u64>,
}

impl ConsensusEngine {
    pub fn new(state: ChainState, keypair: HydraXKeypair) -> Self {
        let address = keypair.address();

        let pool      = Arc::new(TxPool::new());
        let sig_cache = Arc::new(
            HydraXSigCache::new(SigCacheConfig::default(), Arc::clone(&pool))
                .expect("sig cache init failed"),
        );
        let pipeline = Arc::new(
            IngestionPipeline::new(
                Arc::clone(&pool),
                Arc::clone(&sig_cache),
                Arc::new(PqCryptoVerifier),
                0,
            )
            .expect("ingestion pipeline init failed"),
        );

        ConsensusEngine {
            state:   Arc::new(RwLock::new(state)),
            mempool: Arc::new(RwLock::new(Mempool::default())),
            keypair: Arc::new(keypair),
            address,
            pipeline,
            sink: None,
            hx_pool: pool,
            sig_cache,
            last_block: RwLock::new(None),
            proposed_tree: Mutex::new(None),
            submit_lock: Mutex::new(()),
            accepting: AtomicBool::new(true),
            commits: tokio::sync::watch::channel(0).0,
        }
    }

    /// Notified with the new height after every commit.
    pub fn subscribe_commits(&self) -> tokio::sync::watch::Receiver<u64> {
        self.commits.subscribe()
    }

    /// Header and signatures of the last committed block.
    pub fn tip(&self) -> Option<(BlockHeader, Vec<ValidatorSig>)> {
        self.last_block.read().as_ref().map(|l| (l.header.clone(), l.sigs.clone()))
    }

    /// Check a block header and its signatures without the block: the
    /// proposer must be the expected one for that height and its HYDRA-X
    /// signature over the header must verify. Used for block announcements,
    /// which carry no transactions.
    pub fn verify_header(&self, header: &BlockHeader, sigs: &[ValidatorSig]) -> Result<(), ConsensusError> {
        let bft = self.state.read().bft_active_at(header.height);
        let expected = if bft {
            // Who proposes depends on the consensus round, which the header
            // does not carry; the commit proof is what makes a block final.
            // Here the proposer only has to be a validator.
            if !self.state.read().validators.iter().any(|v| v.address == header.proposer) {
                return Err(ConsensusError::InvalidSig(format!("block proposer {} is not a validator", header.proposer)));
            }
            header.proposer.clone()
        } else {
            self.proposer_at(header.height).unwrap_or_else(|| self.address.clone())
        };
        if header.proposer != expected {
            return Err(ConsensusError::InvalidSig(format!(
                "block proposer {} is not the expected proposer {}",
                header.proposer, expected
            )));
        }
        let vs = sigs
            .iter()
            .find(|vs| vs.validator == expected)
            .ok_or_else(|| ConsensusError::InvalidSig("proposer signature not found".into()))?;
        // The key that signed must be the proposer's key, not just any key.
        if vs.signature.signer_address() != expected {
            return Err(ConsensusError::InvalidSig(
                "proposer signature was made by a different key".into(),
            ));
        }
        vs.signature
            .verify(&header.signing_bytes())
            .map_err(|e| ConsensusError::InvalidSig(e.to_string()))
    }

    /// Stop (false) or resume (true) accepting new transactions.
    pub fn set_accepting(&self, on: bool) {
        self.accepting.store(on, Ordering::SeqCst);
    }

    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::SeqCst)
    }

    /// Attach durable block storage.
    pub fn with_sink(mut self, sink: Arc<dyn BlockSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Return the validator that should propose at `height`.
    pub fn proposer_at(&self, height: u64) -> Option<Address> {
        let state = self.state.read();
        if state.validators.is_empty() {
            return None;
        }
        let idx = (height as usize) % state.validators.len();
        Some(state.validators[idx].address.clone())
    }

    /// Add a transaction to the mempool after pipeline validation.
    ///
    /// The hx-mempool `IngestionPipeline` performs:
    ///   1. Duplicate check (fast path against `TxPool`)
    ///   2. Address derivation: BLAKE3(ml_pk || slh_pk) == sender
    ///   3. Parallel ML-DSA-87 + SLH-DSA-256s verification via rayon
    ///   4. Signature caching in the two-tier hot/cold cache
    ///
    /// On `Accepted`, the transaction is also pushed to the `Vec` mempool
    /// so `propose_block()` can drain it into the next block.
    /// On `Duplicate`, the existing hash is returned without re-queuing.
    pub fn submit_tx(&self, tx: Transaction) -> Result<TxHash, ConsensusError> {
        if !self.is_accepting() {
            return Err(ConsensusError::Busy(
                "node is not accepting transactions right now (low disk space)".into(),
            ));
        }

        // Cheap admission checks first, so unfunded or out-of-order spam is
        // refused before it costs a full HYDRA-X verification.
        let _guard = self.submit_lock.lock();
        // One hash of the incoming tx; every lookup below is indexed, so
        // refusing junk costs the same however full the mempool is.
        let hash = tx.hash();
        if self.is_pending(&hash) {
            return Ok(hash);
        }
        let (pending_count, pending_out) = self.pending_for(&tx.from);
        let expected = self.state.read().account(&tx.from).nonce + pending_count as u64;
        if tx.nonce != expected {
            return Err(ConsensusError::InvalidTx(format!(
                "invalid nonce: expected {expected}, got {}",
                tx.nonce
            )));
        }
        let (balance, fee, recover) = {
            let st = self.state.read();
            let next = st.height + 1;
            // Sentinel operations get the same checks block application
            // runs, read-only, before they cost a HYDRA-X verification or a
            // mempool slot.
            let op = st.parse_op(&tx, next).map_err(|e| ConsensusError::InvalidTx(e.to_string()))?;
            let fee = st.fee_at(next);
            let mut deferred = false;
            let recover = matches!(op, Some(qtrc_common::sentinel::SentinelOp::Recover { .. }));
            match &op {
                // Recovery proofs are checked after the tx signature (below),
                // so a forged tx cannot make the node verify two signatures.
                Some(op @ qtrc_common::sentinel::SentinelOp::Recover { .. }) => {
                    deferred = ChainState::fee_from_recovery(op, &tx);
                }
                Some(op) => st.check_op(&tx, op).map_err(|e| ConsensusError::InvalidTx(e.to_string()))?,
                None => st.check_guarded_transfer(&tx, fee).map_err(|e| ConsensusError::InvalidTx(e.to_string()))?,
            }
            // A guarded account can only spend what is not reserved; its own
            // recovery pays the fee out of the whole (recovered) balance.
            let have = if deferred {
                st.vault(&tx.from).map_or(0, |v| v.balance())
            } else {
                st.spendable(&tx.from)
            };
            (have, fee, recover)
        };
        // Every pending tx and this one each pay the fee on top of the amount.
        let needed = pending_out
            .saturating_add(tx.amount)
            .saturating_add(fee.saturating_mul(pending_count as u64 + 1));
        if balance < needed {
            return Err(ConsensusError::InvalidTx(format!(
                "insufficient balance: have {balance} µQTR, pending txs plus this one (fee {fee} µQTR each) need {needed} µQTR"
            )));
        }
        if pending_count >= MAX_PENDING_PER_SENDER {
            return Err(ConsensusError::Busy(format!(
                "this account already has {MAX_PENDING_PER_SENDER} transactions waiting; try after the next block"
            )));
        }
        if let Err(full) = self.mempool.read().has_room(&tx, recover) {
            return Err(ConsensusError::Busy(match full {
                mempool::Full::RecoveryReserve => "too many recoveries waiting, try after the next block".into(),
                _ => "mempool full, try again shortly".into(),
            }));
        }

        let item = adapter::to_ingest_item(&tx)?;
        match self.pipeline.ingest_one(item) {
            IngestResult::Accepted { hash: h } => {
                // Recovery proof: checked only now that the tx signature is
                // known to be valid.
                if let Err(e) = self.check_recovery_op(&tx) {
                    self.forget(&[hash]);
                    return Err(e);
                }
                self.mempool.write().push(mempool::Entry::with_hash(tx, hash, recover));
                Ok(adapter::hx_hash_to_qtrc(h))
            }
            // Known to hx-mempool but not queued here (left over from a drop):
            // forget it and admit this copy, which just passed every check.
            IngestResult::Duplicate { hash: h } => {
                self.forget(std::slice::from_ref(&hash));
                match self.pipeline.ingest_one(adapter::to_ingest_item(&tx)?) {
                    IngestResult::Accepted { .. } => {
                        if let Err(e) = self.check_recovery_op(&tx) {
                            self.forget(&[hash]);
                            return Err(e);
                        }
                        self.mempool.write().push(mempool::Entry::with_hash(tx, hash, recover));
                        Ok(adapter::hx_hash_to_qtrc(h))
                    }
                    other => Err(ConsensusError::InvalidTx(format!(
                        "transaction could not be queued: {other:?}"
                    ))),
                }
            }
            IngestResult::Rejected { reason } => {
                Err(ConsensusError::InvalidTx(reason.to_string()))
            }
        }
    }

    fn check_recovery_op(&self, tx: &Transaction) -> Result<(), ConsensusError> {
        if tx.data.is_empty() {
            return Ok(());
        }
        let st = self.state.read();
        match qtrc_common::sentinel::SentinelOp::decode(&tx.data) {
            Ok(op @ qtrc_common::sentinel::SentinelOp::Recover { .. }) => {
                st.check_op(tx, &op).map_err(|e| ConsensusError::InvalidTx(e.to_string()))
            }
            _ => Ok(()),
        }
    }

    /// (count, total amount) of `addr`'s txs in the mempool or in flight.
    fn pending_for(&self, addr: &Address) -> (usize, u64) {
        self.mempool.read().pending_for(addr)
    }

    fn is_pending(&self, hash: &TxHash) -> bool {
        self.mempool.read().contains(hash)
    }

    /// Drop transactions from hx-mempool's pool and signature cache.
    fn forget(&self, hashes: &[TxHash]) {
        let raw: Vec<[u8; 32]> = hashes.iter().map(|h| h.0).collect();
        for h in &raw {
            self.hx_pool.remove(h);
        }
        self.sig_cache.on_block_finalized(&raw);
    }

    /// End the in-flight phase. `requeue` puts the txs back at the front of
    /// the mempool (the block failed); otherwise they are done (committed).
    /// Both locks are held together, so no submit ever sees a gap.
    fn release_inflight(&self, requeue: bool) {
        let done = self.mempool.write().finish_inflight(!requeue);
        if !done.is_empty() {
            self.forget(&done);
        }
    }

    /// Nonce the next transaction from `addr` must use: the on-chain nonce
    /// plus that sender's transactions still waiting in the mempool.
    pub fn next_nonce(&self, addr: &Address) -> u64 {
        let chain = self.state.read().account(addr).nonce;
        chain + self.pending_for(addr).0 as u64
    }

    /// Proof of `addr` against the last committed block, with that block's
    /// header and signatures. `Ok(None)` if the account is empty; error if
    /// state roots are not active yet.
    #[allow(clippy::type_complexity)]
    pub fn state_proof(
        &self,
        addr: &Address,
    ) -> Result<(BlockHeader, Vec<ValidatorSig>, Option<qtrc_common::state_root::Proof>), ConsensusError> {
        // Header, signatures and tree are swapped together at commit, so the
        // proof always matches the header it is served with. O(log n), no
        // state lock.
        let last = self.last_block.read().clone();
        let Some(last) = last else {
            return Err(ConsensusError::Busy("no block committed yet".into()));
        };
        let Some(tree) = last.tree else {
            return Err(ConsensusError::Busy(format!("state roots start at block {}", last.from)));
        };
        Ok((last.header, last.sigs, tree.proof(addr)))
    }

    /// Expose ingestion metrics for monitoring.
    pub fn pipeline_metrics(&self) -> &hx_mempool::metrics::IngestionMetrics {
        self.pipeline.metrics()
    }

    /// Propose a new block if this node is the current proposer.
    pub fn propose_block(&self) -> Result<Block, ConsensusError> {
        let next_height = {
            let state = self.state.read();
            state.height + 1
        };

        let proposer = self.proposer_at(next_height)
            .unwrap_or_else(|| self.address.clone());

        let bft = self.state.read().bft_active_at(next_height);
        {
            let state = self.state.read();
            // With BFT the consensus round decides who proposes.
            if !bft && proposer != self.address && !state.validators.is_empty() {
                return Err(ConsensusError::NotProposer { height: next_height });
            }
        }
        // With BFT our proposal from an earlier round may have lost; its
        // transactions go back to the queue and the new proposal takes them.
        if bft && !self.mempool.read().inflight_is_empty() {
            self.release_inflight(true);
        }

        // Take up to 500 pending txs and keep only those that apply, in order,
        // on top of the current state. An invalid tx (reused nonce, not
        // enough balance) is dropped here instead of poisoning the block:
        // since blocks apply all-or-nothing, one bad tx would otherwise make
        // every block fail and halt the chain.
        // Move candidates from the mempool to in-flight under both locks,
        // so they never stop counting as pending.
        // Senders with a Sentinel recovery waiting go first.
        let candidates = {
            let mut pool = self.mempool.write();
            if !pool.inflight_is_empty() {
                return Err(ConsensusError::Busy("a block is already being built".into()));
            }
            pool.take_for_block(MAX_TXS_PER_BLOCK)
        };
        let mut scratch = self.state.read().clone();
        let mut txs = Vec::with_capacity(candidates.len());
        let mut dropped = Vec::new();
        // Recoveries over the per-block cap wait for the next block, and so
        // does everything after them from the same sender (nonce order).
        let mut recovers = 0usize;
        let mut held: std::collections::HashSet<TxHash> = Default::default();
        let mut held_senders: std::collections::HashSet<Address> = Default::default();
        for e in candidates {
            if held_senders.contains(&e.tx.from) {
                held.insert(e.hash);
                continue;
            }
            if e.recover && recovers >= MAX_RECOVERS_PER_BLOCK {
                held_senders.insert(e.tx.from.clone());
                held.insert(e.hash);
                continue;
            }
            match scratch.apply_tx(&e.tx) {
                Ok(()) => {
                    recovers += usize::from(e.recover);
                    txs.push(e.tx);
                }
                Err(err) => {
                    warn!(tx = %e.hash, "dropping invalid tx from block: {err}");
                    dropped.push(e.hash);
                }
            }
        }
        if !dropped.is_empty() {
            self.mempool.write().drop_inflight(&dropped.iter().cloned().collect());
            self.forget(&dropped);
        }
        if !held.is_empty() {
            self.mempool.write().hold(&held);
        }
        if txs.is_empty() {
            self.release_inflight(false);
            return Err(ConsensusError::InvalidTx("no valid transactions to propose".into()));
        }

        let merkle_root = Block::compute_merkle_root(&txs);
        let prev_hash = {
            let state = self.state.read();
            state.block_hash.clone()
        };

        // `scratch` holds exactly the state after these transactions.
        let state_root = if scratch.state_root_active_at(next_height) {
            let touched = scratch.take_touched();
            let tree = Arc::new(self.next_tree(&scratch, &touched, next_height));
            let root = tree.root();
            *self.proposed_tree.lock() = Some(tree);
            Some(root)
        } else {
            None
        };

        let witness_root = scratch
            .witness_root_active_at(next_height)
            .then(|| Block::compute_witness_root(&txs));
        let header = BlockHeader {
            height:    next_height,
            prev_hash,
            merkle_root,
            timestamp: chrono::Utc::now().timestamp(),
            proposer:  self.address.clone(),
            state_root,
            witness_root,
        };

        let sig = self.keypair.sign(&header.signing_bytes());
        let validator_sig = ValidatorSig {
            validator: self.address.clone(),
            signature: sig,
        };

        let block = Block {
            header,
            transactions:   txs,
            validator_sigs: vec![validator_sig],
            commit:         None,
        };

        info!(
            height = next_height,
            txs    = block.transactions.len(),
            "📦 proposed block"
        );

        Ok(block)
    }

    /// Tree of `next`, a state that differs from the committed one only in
    /// `touched`: updated from the committed tree when there is one, built
    /// from scratch at activation.
    fn next_tree(&self, next: &ChainState, touched: &std::collections::BTreeSet<String>, height: u64) -> StateTree {
        let base = self
            .last_block
            .read()
            .as_ref()
            .filter(|l| l.header.height + 1 == height)
            .and_then(|l| l.tree.clone());
        match base {
            Some(t) => t.updated(next, touched),
            None => next.state_tree(),
        }
    }

    /// Commit a finalized block: validate, apply, persist, then publish.
    pub fn commit_block(&self, block: Block) -> Result<(), ConsensusError> {
        let own = {
            let inflight = self.mempool.read().inflight_hashes();
            !inflight.is_empty()
                && inflight.len() == block.transactions.len()
                && inflight.iter().zip(&block.transactions).all(|(a, b)| *a == b.hash())
        };
        let included: std::collections::HashSet<TxHash> =
            if own { Default::default() } else { block.transactions.iter().map(|t| t.hash()).collect() };
        let result = self.commit_inner(block, true);
        if own {
            // Our own proposal: on success the txs are done; on failure they
            // go back to the front of the mempool for the next attempt.
            self.release_inflight(result.is_err());
        } else if result.is_ok() {
            // Someone else's block (BFT, or a follower). Any proposal of ours
            // for this height lost: its txs go back to the queue. Then the
            // txs this block included leave the mempool for good.
            if !self.mempool.read().inflight_is_empty() {
                self.release_inflight(true);
            }
            let removed = self.mempool.write().remove(&included);
            if !removed.is_empty() {
                self.forget(&removed);
            }
        }
        result
    }

    /// Re-apply a block that is already on disk (node restart).
    /// Runs every check `commit_block` runs, but does not write it again.
    pub fn replay_block(&self, block: Block) -> Result<(), ConsensusError> {
        self.commit_inner(block, false)
    }

    /// Everything a block must satisfy except who decided it: it extends
    /// the tip, its roots match its transactions and the resulting state,
    /// every transaction and the proposer's header signature verify, and it
    /// applies. Returns the state after it, untouched live state.
    fn check(&self, block: &Block, own_tree: bool) -> Result<Checked, ConsensusError> {
        {
            let state    = self.state.read();
            let expected = state.height + 1;
            if block.header.height != expected {
                return Err(ConsensusError::WrongHeight {
                    expected,
                    got: block.header.height,
                });
            }
            if block.header.prev_hash != state.block_hash {
                return Err(ConsensusError::InvalidTx(
                    "block does not extend the current tip (prev_hash mismatch)".into(),
                ));
            }
        }

        if block.header.merkle_root != Block::compute_merkle_root(&block.transactions) {
            return Err(ConsensusError::InvalidTx(
                "merkle root does not match the block's transactions".into(),
            ));
        }
        // From its activation on, the header commits to every byte of every
        // transaction; before it, the field must be absent.
        let witness_expected = self
            .state
            .read()
            .witness_root_active_at(block.header.height)
            .then(|| Block::compute_witness_root(&block.transactions));
        if block.header.witness_root != witness_expected {
            return Err(ConsensusError::InvalidTx(match (&block.header.witness_root, &witness_expected) {
                (None, Some(_)) => "block is missing its witness root".into(),
                (Some(_), None) => "block carries a witness root before activation".into(),
                _ => "witness root does not match the block's transactions".into(),
            }));
        }

        if !block.verify_transactions() {
            return Err(ConsensusError::InvalidTx(
                "one or more transactions failed HYDRA-X verification".into(),
            ));
        }

        self.verify_proposer_sig(block)?;

        // Apply on a copy: a block either applies completely or not at all.
        // (Applying in place left earlier txs applied when a later one failed.)
        let mut next = self.state.read().clone();
        next.apply_block(block)
            .map_err(|e| ConsensusError::InvalidTx(e.to_string()))?;
        let touched = next.take_touched();

        // From the activation height on, the header must commit to exactly
        // the resulting state; before it, it must not carry a root at all.
        // Our own proposal's tree is reused when its root is the header's:
        // equal roots commit to the same leaves.
        let tree = next.state_root_active_at(block.header.height).then(|| {
            let mine = if own_tree { self.proposed_tree.lock().take() } else { None };
            match mine {
                Some(t) if Some(t.root()) == block.header.state_root => t,
                _ => Arc::new(self.next_tree(&next, &touched, block.header.height)),
            }
        });
        let expected_root = tree.as_ref().map(|t| t.root());
        if block.header.state_root != expected_root {
            return Err(ConsensusError::InvalidTx(match (&block.header.state_root, &expected_root) {
                (None, Some(_)) => "block is missing its state root".into(),
                (Some(_), None) => "block carries a state root before activation".into(),
                _ => "state root does not match the state after this block".into(),
            }));
        }

        Ok(Checked { next, tree })
    }

    fn commit_inner(&self, block: Block, persist: bool) -> Result<(), ConsensusError> {
        self.verify_finality(&block)?;
        let Checked { next, tree } = self.check(&block, true)?;

        if persist {
            if let Some(sink) = &self.sink {
                sink.persist(&block).map_err(ConsensusError::Storage)?;
            }
        }

        let mut state = self.state.write();
        if state.height + 1 != block.header.height {
            // Another commit won the race between our read and this write.
            return Err(ConsensusError::WrongHeight {
                expected: state.height + 1,
                got: block.header.height,
            });
        }
        *state = next;
        *self.last_block.write() = Some(LastBlock {
            header: block.header.clone(),
            sigs: block.validator_sigs.clone(),
            tree,
            from: state.state_root_from_height,
        });
        let height = state.height;
        drop(state);
        self.commits.send_replace(height);

        if persist {
            info!(
                height = block.header.height,
                hash   = %block.hash(),
                txs    = block.transactions.len(),
                "✅ block committed"
            );
        }

        Ok(())
    }

    /// The block must be proposed by the expected proposer and carry that
    /// proposer's HYDRA-X signature over the header. With no validator set
    /// (single-node testnet) the expected proposer is this node's own key.
    /// The validator set as the BFT consensus sees it (voting power = stake).
    pub fn bft_validator_set(&self) -> Result<qtrc_bft::ValidatorSet, ConsensusError> {
        let state = self.state.read();
        qtrc_bft::ValidatorSet::new(
            state
                .validators
                .iter()
                .map(|v| qtrc_bft::Validator { address: qtrc_bft::ValAddr::from(&v.address), power: v.stake })
                .collect(),
        )
        .map_err(ConsensusError::InvalidSig)
    }

    /// From the BFT activation height on, a block is final only with a
    /// commit proof: precommits for its header hash, at its height, from
    /// validators holding more than two thirds of the voting power. Before
    /// it, a block must not carry one.
    fn verify_finality(&self, block: &Block) -> Result<(), ConsensusError> {
        let bft = self.state.read().bft_active_at(block.header.height);
        match (&block.commit, bft) {
            (None, false) => Ok(()),
            (Some(_), false) => Err(ConsensusError::InvalidSig("commit proof before multi-validator activation".into())),
            (None, true) => Err(ConsensusError::InsufficientSigs { need: 1, got: 0 }),
            (Some(proof), true) => {
                use qtrc_bft::types as mc;
                let vs = self.bft_validator_set()?;
                let cert = mc::CommitCertificate::<qtrc_bft::Ctx> {
                    height: qtrc_bft::Height(block.header.height),
                    round: mc::Round::new(proof.round),
                    value_id: qtrc_bft::BlockId(block.hash().0),
                    commit_signatures: proof
                        .precommits
                        .iter()
                        .map(|p| mc::CommitSignature::new(qtrc_bft::ValAddr::from(&p.validator), qtrc_bft::Signature::from_hydrax(&p.signature)))
                        .collect(),
                };
                qtrc_bft::verify_commit(&cert, &vs).map_err(ConsensusError::InvalidSig)
            }
        }
    }

    /// Check a block another validator proposed, without committing it.
    /// The consensus votes for it only if this passes. It carries no commit
    /// proof yet: that is what the vote produces.
    pub fn check_proposal(&self, block: &Block) -> Result<(), ConsensusError> {
        if block.commit.is_some() {
            return Err(ConsensusError::InvalidTx("a proposal cannot carry a commit proof".into()));
        }
        self.check(block, false).map(|_| ())
    }

    fn verify_proposer_sig(&self, block: &Block) -> Result<(), ConsensusError> {
        self.verify_header(&block.header, &block.validator_sigs)
    }
}

// ---------------------------------------------------------------------------
// Block production loop
// ---------------------------------------------------------------------------

pub async fn run_block_producer(engine: Arc<ConsensusEngine>) {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(BLOCK_TIME_SECS));

    loop {
        interval.tick().await;

        // No empty blocks: each block carries a ~37 KB HYDRA-X signature, so
        // one empty block every 5 s would grow the disk by over 1 GB a day.
        if engine.mempool.read().is_empty() {
            continue;
        }

        // Signing and verifying take hundreds of milliseconds; keep that off
        // the async runtime so the RPC stays responsive.
        let e = engine.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            e.propose_block().and_then(|block| e.commit_block(block))
        })
        .await;

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(ConsensusError::NotProposer { .. })) => {
                debug!("not proposer this slot, waiting for block from peers");
            }
            Ok(Err(e)) => warn!("block production: {e}"),
            Err(e) => warn!("block production task failed: {e}"),
        }
    }
}
