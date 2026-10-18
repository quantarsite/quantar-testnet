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
/// Most transactions waiting in the mempool, across all senders.
pub const MAX_MEMPOOL: usize = 5_000;
/// Most transactions one sender may have waiting at once.
pub const MAX_PENDING_PER_SENDER: usize = 16;

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
    /// Pending transactions queued for the next block
    pub mempool: Arc<RwLock<Vec<Transaction>>>,
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
    /// Transactions taken out of the mempool for the block being built.
    /// They still count as pending until that block commits or fails, so
    /// `next_nonce` never hands out a nonce that is already in use.
    inflight:    RwLock<Vec<Transaction>>,
    /// Serializes the admission checks so two submits can't both pass them
    submit_lock: Mutex<()>,
    /// Cleared by the node when disk space runs low
    accepting:   AtomicBool,
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
            mempool: Arc::new(RwLock::new(Vec::new())),
            keypair: Arc::new(keypair),
            address,
            pipeline,
            sink: None,
            hx_pool: pool,
            sig_cache,
            inflight: RwLock::new(Vec::new()),
            submit_lock: Mutex::new(()),
            accepting: AtomicBool::new(true),
        }
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
        let hash = tx.hash();
        let (pending_count, pending_out) = self.pending_for(&tx.from);
        if self.is_pending(&hash) {
            return Ok(hash);
        }
        let expected = self.state.read().account(&tx.from).nonce + pending_count as u64;
        if tx.nonce != expected {
            return Err(ConsensusError::InvalidTx(format!(
                "invalid nonce: expected {expected}, got {}",
                tx.nonce
            )));
        }
        let balance = self.state.read().account(&tx.from).balance;
        let needed = pending_out.saturating_add(tx.amount);
        if balance < needed {
            return Err(ConsensusError::InvalidTx(format!(
                "insufficient balance: have {balance} µQTR, pending plus this tx need {needed} µQTR"
            )));
        }
        if pending_count >= MAX_PENDING_PER_SENDER {
            return Err(ConsensusError::Busy(format!(
                "this account already has {MAX_PENDING_PER_SENDER} transactions waiting; try after the next block"
            )));
        }
        if self.mempool.read().len() >= MAX_MEMPOOL {
            return Err(ConsensusError::Busy("mempool full, try again shortly".into()));
        }

        let item = adapter::to_ingest_item(&tx)?;
        match self.pipeline.ingest_one(item) {
            IngestResult::Accepted { hash: h } => {
                self.mempool.write().push(tx);
                Ok(adapter::hx_hash_to_qtrc(h))
            }
            // Known to hx-mempool but not queued here (left over from a drop):
            // forget it and admit this copy, which just passed every check.
            IngestResult::Duplicate { hash: h } => {
                self.forget(&[hash.clone()]);
                match self.pipeline.ingest_one(adapter::to_ingest_item(&tx)?) {
                    IngestResult::Accepted { .. } => {
                        self.mempool.write().push(tx);
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

    /// (count, total amount) of `addr`'s txs in the mempool or in flight.
    fn pending_for(&self, addr: &Address) -> (usize, u64) {
        let pool = self.mempool.read();
        let inflight = self.inflight.read();
        pool.iter()
            .chain(inflight.iter())
            .filter(|t| &t.from == addr)
            .fold((0, 0u64), |(n, sum), t| (n + 1, sum.saturating_add(t.amount)))
    }

    fn is_pending(&self, hash: &TxHash) -> bool {
        let pool = self.mempool.read();
        let inflight = self.inflight.read();
        pool.iter().chain(inflight.iter()).any(|t| &t.hash() == hash)
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
        let mut pool = self.mempool.write();
        let mut inflight = self.inflight.write();
        let txs = std::mem::take(&mut *inflight);
        if requeue {
            let rest = std::mem::take(&mut *pool);
            *pool = txs;
            pool.extend(rest);
        } else {
            drop(pool);
            drop(inflight);
            let hashes: Vec<TxHash> = txs.iter().map(|t| t.hash()).collect();
            self.forget(&hashes);
        }
    }

    /// Nonce the next transaction from `addr` must use: the on-chain nonce
    /// plus that sender's transactions still waiting in the mempool.
    pub fn next_nonce(&self, addr: &Address) -> u64 {
        let chain = self.state.read().account(addr).nonce;
        chain + self.pending_for(addr).0 as u64
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

        {
            let state = self.state.read();
            if proposer != self.address && !state.validators.is_empty() {
                return Err(ConsensusError::NotProposer { height: next_height });
            }
        }

        // Take up to 500 pending txs and keep only those that apply, in order,
        // on top of the current state. An invalid tx (reused nonce, not
        // enough balance) is dropped here instead of poisoning the block:
        // since blocks apply all-or-nothing, one bad tx would otherwise make
        // every block fail and halt the chain.
        // Move candidates from the mempool to in-flight under both locks,
        // so they never stop counting as pending.
        let candidates: Vec<Transaction> = {
            let mut pool = self.mempool.write();
            let mut inflight = self.inflight.write();
            if !inflight.is_empty() {
                return Err(ConsensusError::Busy("a block is already being built".into()));
            }
            let n = pool.len().min(MAX_TXS_PER_BLOCK);
            let c: Vec<Transaction> = pool.drain(..n).collect();
            *inflight = c.clone();
            c
        };
        let mut scratch = self.state.read().clone();
        let mut txs = Vec::with_capacity(candidates.len());
        let mut dropped = Vec::new();
        for tx in candidates {
            match scratch.apply_tx(&tx) {
                Ok(()) => txs.push(tx),
                Err(e) => {
                    warn!(tx = %tx.hash(), "dropping invalid tx from block: {e}");
                    dropped.push(tx.hash());
                }
            }
        }
        if !dropped.is_empty() {
            self.inflight.write().retain(|t| !dropped.contains(&t.hash()));
            self.forget(&dropped);
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

        let header = BlockHeader {
            height:    next_height,
            prev_hash,
            merkle_root,
            timestamp: chrono::Utc::now().timestamp(),
            proposer:  self.address.clone(),
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
        };

        info!(
            height = next_height,
            txs    = block.transactions.len(),
            "📦 proposed block"
        );

        Ok(block)
    }

    /// Commit a finalized block: validate, apply, persist, then publish.
    pub fn commit_block(&self, block: Block) -> Result<(), ConsensusError> {
        let own = {
            let inflight = self.inflight.read();
            !inflight.is_empty()
                && inflight.len() == block.transactions.len()
                && inflight.iter().zip(&block.transactions).all(|(a, b)| a.hash() == b.hash())
        };
        let result = self.commit_inner(block, true);
        if own {
            // Our own proposal: on success the txs are done; on failure they
            // go back to the front of the mempool for the next attempt.
            self.release_inflight(result.is_err());
        }
        result
    }

    /// Re-apply a block that is already on disk (node restart).
    /// Runs every check `commit_block` runs, but does not write it again.
    pub fn replay_block(&self, block: Block) -> Result<(), ConsensusError> {
        self.commit_inner(block, false)
    }

    fn commit_inner(&self, block: Block, persist: bool) -> Result<(), ConsensusError> {
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

        if !block.verify_transactions() {
            return Err(ConsensusError::InvalidTx(
                "one or more transactions failed HYDRA-X verification".into(),
            ));
        }

        self.verify_proposer_sig(&block)?;

        // Apply on a copy: a block either applies completely or not at all.
        // (Applying in place left earlier txs applied when a later one failed.)
        let mut next = self.state.read().clone();
        next.apply_block(&block)
            .map_err(|e| ConsensusError::InvalidTx(e.to_string()))?;

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
    fn verify_proposer_sig(&self, block: &Block) -> Result<(), ConsensusError> {
        let expected = self
            .proposer_at(block.header.height)
            .unwrap_or_else(|| self.address.clone());
        if block.header.proposer != expected {
            return Err(ConsensusError::InvalidSig(format!(
                "block proposer {} is not the expected proposer {}",
                block.header.proposer, expected
            )));
        }
        let header_bytes = block.header.signing_bytes();
        let vs = block
            .validator_sigs
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
            .verify(&header_bytes)
            .map_err(|e| ConsensusError::InvalidSig(e.to_string()))
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
